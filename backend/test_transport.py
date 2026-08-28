"""Pruebas del transporte HITL: API HTTP autenticada, difusion en vivo y
politica de fallo cerrado.

Sin red externa y sin API de Anthropic: usa el modo demo.

Correr con:  python test_transport.py
"""
from __future__ import annotations

import asyncio
import os
import tempfile
from pathlib import Path

os.environ.setdefault("ORACLE_JWT_SECRET", "t" * 48)
os.environ.setdefault("ORACLE_OPERATOR", "denis")
os.environ.setdefault("ORACLE_COOKIE_SECURE", "0")

from app.auth import hash_password  # noqa: E402

os.environ.setdefault("ORACLE_OPERATOR_HASH", hash_password("clave-de-prueba"))

from fastapi.testclient import TestClient  # noqa: E402

from app.hub import MissionHub  # noqa: E402
from app.main import _factory, app  # noqa: E402


def _http() -> list[tuple[str, bool]]:
    c = TestClient(app)
    r = c.get("/")
    js = c.get("/static/panel.js")

    sin_token = c.get("/api/missions").status_code
    login = c.post("/api/auth/login",
                   json={"username": "denis", "password": "clave-de-prueba"})
    auth = {"Authorization": f"Bearer {login.json()['access_token']}"}

    return [
        ("el panel se sirve en la raiz", r.status_code == 200 and "Oracle Core" in r.text),
        ("el panel trae la pantalla de entrada", "Acceso de operador" in r.text),
        ("el panel carga su script", "/static/panel.js" in r.text),
        ("el script se sirve", js.status_code == 200),
        ("el script abre el WebSocket de operador", "ws/operator" in js.text),
        ("el token de acceso no se guarda en el navegador",
         not any(u in js.text for u in
                 ("localStorage.", "sessionStorage.", "localStorage[", "sessionStorage["))),
        ("sin token la API esta cerrada", sin_token == 401),
        ("el login devuelve acceso", login.status_code == 200),
        ("con token se listan misiones",
         c.get("/api/missions", headers=auth).status_code == 200),
        ("decidir sobre una mision inexistente da 404",
         c.post("/api/decisions", headers=auth,
                json={"mission": "nada", "action": "approve"}).status_code == 404),
        ("un objetivo vacio se rechaza",
         c.post("/api/missions", headers=auth,
                json={"objective": ""}).status_code == 422),
    ]


async def _vivo() -> list[tuple[str, bool]]:
    out: list[tuple[str, bool]] = []
    obj = "auditar 10.0.0.5"

    # --- con operador conectado: la mision corre entera ---
    hub = MissionHub(Path(tempfile.mkdtemp()) / "a.db")
    q = hub.connect()
    out.append(("un operador conectado cuenta como en linea", hub.operators_online == 1))

    mid = await hub.start(obj, _factory(True, obj))
    vistos, fin = [], None
    for _ in range(60):
        msg = await asyncio.wait_for(q.get(), timeout=25)
        vistos.append(msg["kind"])
        if msg["kind"] == "mission.ended":
            fin = msg["data"]
            break

    out += [
        ("se difunde el arranque de la mision", "mission.started" in vistos),
        ("las entradas del ledger llegan en vivo", vistos.count("ledger.entry") >= 5),
        ("se difunde el final", fin is not None),
        ("la mision demo termina exitosa", bool(fin) and fin["status"] == "exitosa"),
        ("el plan demo no dispara falso drift",
         bool(fin) and all(s["status"] == "ok" for s in fin["steps"])),
    ]

    snap = hub.snapshot()
    out += [
        ("la mision queda en el snapshot", len(snap) == 1 and snap[0]["id"] == mid),
        ("el snapshot trae la cadena completa", len(snap[0]["entries"]) >= 5),
        ("cada entrada lleva su hash de 64 hex",
         all(len(e["hash"]) == 64 for e in snap[0]["entries"])),
        ("la cadena incluye plan bloqueado y veredictos",
         {"plan.locked", "sentinel.verdict"} <= {e["kind"] for e in snap[0]["entries"]}),
    ]

    hub.disconnect(q)
    out.append(("al cerrar el panel no queda nadie en linea", hub.operators_online == 0))

    # --- FALLO CERRADO: sin nadie mirando, una intervencion aborta ---
    from app.hub import _HubApprover
    from oracle.hitl import ABORT, InterventionRequest

    hub2 = MissionHub(Path(tempfile.mkdtemp()) / "b.db")
    dec = await _HubApprover(hub2, "m1", 5).decide(
        InterventionRequest("m1", "sentinel_escalation", "prueba")
    )
    out.append(("sin operadores, la intervencion aborta",
                dec.action == ABORT and "fallo cerrado" in dec.reason))

    # --- con operador, la decision del panel llega al runner ---
    hub3 = MissionHub(Path(tempfile.mkdtemp()) / "c.db")
    hub3.connect()
    apr = _HubApprover(hub3, "m2", 5)
    hub3._approvers["m2"] = apr  # noqa: SLF001
    tarea = asyncio.create_task(
        apr.decide(InterventionRequest("m2", "tool_drift", "cambio una tool"))
    )
    await asyncio.sleep(0.05)
    enviado = hub3.decide("m2", "approve", "denis", "actualizacion legitima")
    d = await asyncio.wait_for(tarea, timeout=5)
    out += [
        ("la decision del panel se entrega", enviado),
        ("el runner la recibe con operador y motivo",
         d.action == "approve" and d.operator == "denis"),
    ]
    return out


async def main() -> int:
    resultados = _http() + await _vivo()
    fallos = sum(1 for _, ok in resultados if not ok)
    for n, ok in resultados:
        print(f"  [{'OK' if ok else 'XX'}] {n}")
    print(f"\n{len(resultados) - fallos}/{len(resultados)} casos correctos.")
    return 1 if fallos else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
