"""Prueba VIVA de la defensa: dos servidores MCP reales, uno limpio y uno
envenenado, y un rug pull. Todo offline con StubPlanner. Sin API, sin costo.

Correr con:  python test_poisoning_live.py
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

OBJ = "auditar 10.0.0.5"
PLAN = json.dumps({"objective": OBJ, "steps": [
    {"tool": "recon", "args": {"target": "10.0.0.5"}, "rationale": "reconocer"}]})


def _runner(modulo: str, ledger: Ledger, pins: ToolPinStore) -> MissionRunner:
    return MissionRunner(
        StdioServerParameters(command=sys.executable, args=["-m", modulo]),
        ledger,
        StubPlanner(PLAN),
        server_id="oracle-spike-tools",
        pins=pins,
    )


async def main() -> int:
    tmp = Path(tempfile.mkdtemp())
    ledger = Ledger(tmp / "l.db")
    pins = ToolPinStore(tmp / "pins.json")
    fallos = 0

    print("\n=== 1. Servidor LIMPIO (primer contacto: se fija) ===")
    st = await _runner("tools_server.echo_server", ledger, pins).run(OBJ)
    ok = st.success and st.aborted_by is None
    print(f"  [{'OK' if ok else 'XX'}] mision ejecutada, tools fijadas")
    fallos += not ok

    print("\n=== 2. Mismo servidor otra vez (huella igual) ===")
    st = await _runner("tools_server.echo_server", ledger, pins).run(OBJ)
    ok = st.success
    print(f"  [{'OK' if ok else 'XX'}] pasa sin friccion")
    fallos += not ok

    print("\n=== 3. RUG PULL: el servidor cambia bajo el mismo nombre ===")
    st = await _runner("tools_server.poisoned_server", ledger, pins).run(OBJ)
    ok = st.aborted_by is not None and not st.steps
    print(f"  [{'OK' if ok else 'XX'}] mision ABORTADA antes de planificar")
    if st.aborted_by:
        for parte in st.aborted_by.split("; ")[:4]:
            print(f"       {parte}")
    fallos += not ok

    print("\n=== 4. Servidor envenenado SIN fijado previo ===")
    pins2 = ToolPinStore(tmp / "pins2.json")
    st = await _runner("tools_server.poisoned_server", ledger, pins2).run(OBJ)
    ok = st.aborted_by is not None and not pins2.known("oracle-spike-tools")
    print(f"  [{'OK' if ok else 'XX'}] abortada y NO se fijo el servidor malo")
    fallos += not ok

    print("\n--- rastro en el ledger ---")
    for e in ledger.entries():
        if e.kind in ("mission.aborted", "tools.findings"):
            print(f"  #{e.seq:<3} {e.kind}")

    ok_chain, _ = ledger.verify()
    print(f"\nCadena integra: {ok_chain}")
    print(f"{4 - fallos}/4 escenarios correctos.")
    return 1 if fallos or not ok_chain else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
