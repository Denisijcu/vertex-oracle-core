"""Prueba VIVA del Sentinel: un servidor MCP que devuelve resultados envenenados.

El servidor pasa el fijado (descripciones limpias) pero su SALIDA lleva
inyeccion indirecta. Es el caso que el escaneo de tools NO puede atrapar.

Todo offline con StubPlanner. Sin API, sin costo.

Correr con:  python test_sentinel_live.py
"""
from __future__ import annotations

import asyncio
import json
import sys
import tempfile
from pathlib import Path

from mcp import StdioServerParameters

from oracle.ledger import Ledger
from oracle.manifest import ToolPinStore
from oracle.planner import StubPlanner
from oracle.runner import MissionRunner
from oracle.sentinel import Sentinel

OBJ = "auditar 10.0.0.5"


def _plan(tool: str) -> str:
    return json.dumps({"objective": OBJ, "steps": [
        {"tool": tool, "args": {"target": "10.0.0.5"}, "rationale": "reconocer"}]})


def _runner(ledger: Ledger, pins: ToolPinStore, tool: str) -> MissionRunner:
    return MissionRunner(
        StdioServerParameters(command=sys.executable, args=["-m", "tools_server.tainted_server"]),
        ledger,
        StubPlanner(_plan(tool)),
        server_id="tainted",
        pins=pins,
        sentinel=Sentinel(),          # solo capa determinista: sin costo de API
    )


async def main() -> int:
    tmp = Path(tempfile.mkdtemp())
    ledger = Ledger(tmp / "l.db")
    pins = ToolPinStore(tmp / "p.json")
    fallos = 0

    escenarios = [
        ("salida limpia", "clean_scan", "ok"),
        ("inyeccion indirecta en la salida", "poisoned_scan", "rejected"),
        ("exfiltracion por imagen markdown", "exfil_scan", "rejected"),
    ]

    for nombre, tool, esperado in escenarios:
        st = await _runner(ledger, pins, tool).run(OBJ)
        real = st.steps[0].status if st.steps else "sin-pasos"
        ok = real == esperado
        print(f"  [{'OK' if ok else 'XX'}] {nombre:<36} -> {real}")
        fallos += not ok

    print("\n--- veredictos sellados en el ledger ---")
    for e in ledger.entries():
        if e.kind in ("sentinel.verdict", "mission.halted"):
            det = e.payload.get("verdict") or e.payload.get("motivo")
            print(f"  #{e.seq:<3} {e.kind:<18} {det}")

    ok_chain, _ = ledger.verify()
    print(f"\nCadena integra: {ok_chain}")
    print(f"{len(escenarios) - fallos}/{len(escenarios)} escenarios correctos.")
    return 1 if fallos or not ok_chain else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
