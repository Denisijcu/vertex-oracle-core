"""API y panel de operador de Vertex Oracle Core.

    uvicorn app.main:app --reload --port 8000

Luego abre http://localhost:8000

Sin autenticacion todavia: escucha SOLO en localhost a proposito. JWT/RTR es
lo siguiente, y hasta que exista, este servidor no se expone a la red.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from mcp import StdioServerParameters
from pydantic import BaseModel, Field

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
    operator: str = "operador"
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


@app.get("/", response_class=HTMLResponse)
async def panel() -> str:
    return PANEL.read_text(encoding="utf-8")


@app.get("/api/missions")
async def listar() -> dict:
    return {"missions": hub.snapshot(), "operators": hub.operators_online}


@app.post("/api/missions")
async def crear(m: NuevaMision) -> dict:
    if not m.demo and not os.getenv("ANTHROPIC_API_KEY"):
        raise HTTPException(400, "Falta ANTHROPIC_API_KEY. Usa el modo demo.")
    mid = await hub.start(m.objective, _factory(m.demo, m.objective))
    return {"mission": mid}


@app.post("/api/decisions")
async def decidir(d: DecisionEntrante) -> dict:
    if not hub.decide(d.mission, d.action, d.operator, d.reason):
        raise HTTPException(404, "esa mision no esta esperando una decision")
    return {"ok": True}


@app.websocket("/ws/operator")
async def ws(sock: WebSocket) -> None:
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
