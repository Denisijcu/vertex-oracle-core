"""API y panel de operador de Vertex Oracle Core.

    uvicorn app.main:app --port 8000

Luego abre http://localhost:8000

Requiere en el entorno o en backend/.env:
    ORACLE_JWT_SECRET      minimo 32 caracteres
    ORACLE_OPERATOR        nombre del operador
    ORACLE_OPERATOR_HASH   hash argon2 de la clave
    ORACLE_COOKIE_SECURE   ponlo a 0 solo para desarrollo local sobre http

Genera secreto y hash con:
    python -m app.auth hash <tu-clave>
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

from fastapi import (
    Cookie,
    Depends,
    FastAPI,
    HTTPException,
    Response,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from mcp import StdioServerParameters
from pydantic import BaseModel, Field

from app.auth import (
    ACCESO_S,
    COOKIE,
    REFRESCO_S,
    AuthError,
    TokenStore,
    autenticar,
)
from app.hub import MissionHub
from oracle.manifest import ToolPinStore
from oracle.planner import ClaudePlanner, StubPlanner
from oracle.runner import MissionRunner
from oracle.sentinel import ClaudeSentinel, Sentinel

AQUI = Path(__file__).parent.parent
PANEL = Path(__file__).parent / "panel.html"
ESTATICOS = Path(__file__).parent / "static"

app = FastAPI(title="Vertex Oracle Core", version="0.1.0")
app.mount("/static", StaticFiles(directory=ESTATICOS), name="static")
hub = MissionHub(AQUI / "oracle_ledger.db")
tokens = TokenStore()
bearer = HTTPBearer(auto_error=False)

# La cookie de refresco solo viaja por HTTPS salvo que se diga lo contrario.
# En desarrollo local sobre http hay que poner ORACLE_COOKIE_SECURE=0.
COOKIE_SEGURA = os.getenv("ORACLE_COOKIE_SECURE", "1") != "0"


def _dotenv() -> None:
    env = AQUI / ".env"
    if not env.exists():
        return
    for line in env.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


_dotenv()


class NuevaMision(BaseModel):
    objective: str = Field(min_length=3, max_length=500)
    demo: bool = False          # True usa un plan fijo, sin gastar API


class DecisionEntrante(BaseModel):
    mission: str
    action: str
    reason: str = ""


def _factory(demo: bool, objective: str):
    """Devuelve runner_factory(ledger, approver) -> MissionRunner.

    OJO: el plan demo debe declarar el objetivo REAL. El runner compara el
    objetivo del plan con el de la mision y detiene todo si no coinciden
    (anclaje anti-drift). Un plan con un objetivo de relleno se aborta solo.
    """
    server = StdioServerParameters(
        command=sys.executable, args=["-m", "tools_server.echo_server"]
    )

    def build(ledger, approver):
        if demo:
            import json

            plan = json.dumps({"objective": objective, "steps": [
                {"tool": "recon", "args": {"target": "10.0.0.5"}, "rationale": "reconocer"},
                {"tool": "slow_scan", "args": {"target": "10.0.0.5", "seconds": 1.0},
                 "rationale": "escanear a fondo"}]})
            planner, sentinel = StubPlanner(plan), Sentinel()
        else:
            planner = ClaudePlanner()
            sentinel = Sentinel(ClaudeSentinel(), planner_model=planner._model)
        return MissionRunner(
            server, ledger, planner, server_id="local-echo",
            pins=ToolPinStore(AQUI / "tool_pins.json"),
            sentinel=sentinel, approver=approver,
        )

    return build


# --------------------------------------------------------------- seguridad

def operador(cred: HTTPAuthorizationCredentials | None = Depends(bearer)) -> str:
    """Dependencia: exige un JWT de acceso valido y devuelve el usuario."""
    if cred is None:
        raise HTTPException(401, "falta el token de acceso")
    try:
        return tokens.leer_acceso(cred.credentials)["sub"]
    except AuthError as exc:
        raise HTTPException(401, str(exc)) from exc


def _poner_cookie(resp: Response, refresco: str) -> None:
    resp.set_cookie(
        COOKIE, refresco,
        httponly=True,           # el JavaScript no la puede leer
        secure=COOKIE_SEGURA,
        samesite="strict",       # no viaja en peticiones de otros sitios
        max_age=REFRESCO_S,
        path="/api/auth",        # solo se envia a los endpoints que la usan
    )


class Credenciales(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=200)


@app.post("/api/auth/login")
async def login(c: Credenciales, resp: Response) -> dict:
    try:
        usuario = autenticar(c.username, c.password)
    except AuthError as exc:
        raise HTTPException(401, str(exc)) from exc
    acceso, _ = tokens.emitir_acceso(usuario)
    _poner_cookie(resp, tokens.emitir_refresco(usuario))
    return {"access_token": acceso, "expires_in": ACCESO_S, "user": usuario}


@app.post("/api/auth/refresh")
async def refrescar(resp: Response, oracle_refresh: str | None = Cookie(None)) -> dict:
    if not oracle_refresh:
        raise HTTPException(401, "no hay sesion")
    try:
        nuevo, usuario = tokens.rotar(oracle_refresh)
    except AuthError as exc:
        resp.delete_cookie(COOKIE, path="/api/auth")
        raise HTTPException(401, str(exc)) from exc
    acceso, _ = tokens.emitir_acceso(usuario)
    _poner_cookie(resp, nuevo)
    return {"access_token": acceso, "expires_in": ACCESO_S, "user": usuario}


@app.post("/api/auth/logout")
async def logout(
    resp: Response,
    cred: HTTPAuthorizationCredentials | None = Depends(bearer),
    oracle_refresh: str | None = Cookie(None),
) -> dict:
    if oracle_refresh:
        tokens.revocar_token(oracle_refresh)
    if cred:
        try:
            tokens.bloquear_jti(tokens.leer_acceso(cred.credentials)["jti"])
        except AuthError:
            pass
    resp.delete_cookie(COOKIE, path="/api/auth")
    tokens.purgar()
    return {"ok": True}


@app.get("/api/auth/me")
async def yo(usuario: str = Depends(operador)) -> dict:
    return {"user": usuario}


# ------------------------------------------------------------------ panel

@app.get("/", response_class=HTMLResponse)
async def panel() -> str:
    return PANEL.read_text(encoding="utf-8")


@app.get("/api/missions")
async def listar(usuario: str = Depends(operador)) -> dict:
    return {"missions": hub.snapshot(), "operators": hub.operators_online}


@app.post("/api/missions")
async def crear(m: NuevaMision, usuario: str = Depends(operador)) -> dict:
    if not m.demo and not os.getenv("ANTHROPIC_API_KEY"):
        raise HTTPException(400, "Falta ANTHROPIC_API_KEY. Usa el modo demo.")
    mid = await hub.start(m.objective, _factory(m.demo, m.objective))
    return {"mission": mid}


@app.post("/api/decisions")
async def decidir(d: DecisionEntrante, usuario: str = Depends(operador)) -> dict:
    # El operador que decide es el AUTENTICADO, no el que diga el cliente:
    # el ledger tiene que sellar quien decidio de verdad.
    if not hub.decide(d.mission, d.action, usuario, d.reason):
        raise HTTPException(404, "esa mision no esta esperando una decision")
    return {"ok": True}


@app.websocket("/ws/operator")
async def ws(sock: WebSocket, token: str = "") -> None:
    # El WebSocket tambien se autentica. Si no, cualquiera en la maquina
    # podria leer las misiones en vivo sin pasar por el login.
    try:
        tokens.leer_acceso(token)
    except AuthError:
        await sock.close(code=4401, reason="no autenticado")
        return
    await sock.accept()
    cola = hub.connect()
    await sock.send_json({"kind": "snapshot", "data": {"missions": hub.snapshot()}})
    try:
        while True:
            msg = await cola.get()
            await sock.send_json(msg)
    except WebSocketDisconnect:
        pass
    finally:
        hub.disconnect(cola)
