"""Smoke test OFFLINE de Vertex Oracle Core. No usa API ni gasta un centavo.

Usa un plan fijo (StubPlanner) para ejercitar toda la maquinaria:
  1. Servidor MCP (spec 2026-07-28) por stdio.
  2. Descubrimiento de tools y validacion del plan contra sus esquemas.
  3. Ejecucion con reintentos.
  4. Ledger SHA-256 encadenado + deteccion de manipulacion.

Uso:  python spike.py
"""
from __future__ import annotations

import asyncio
import json
import sqlite3
import sys
from pathlib import Path

from mcp import StdioServerParameters

from oracle.ledger import Ledger
from oracle.planner import StubPlanner
from oracle.runner import MissionRunner

DB = Path(__file__).parent / "spike_ledger.db"
OBJETIVO = "auditar el objetivo 10.0.0.5"

PLAN_FIJO = json.dumps(
    {
        "objective": OBJETIVO,
        "steps": [
            {"tool": "recon", "args": {"target": "10.0.0.5"},
             "rationale": "reconocimiento inicial del objetivo"},
            {"tool": "slow_scan", "args": {"target": "10.0.0.5", "seconds": 1.0},
             "rationale": "escaneo profundo tras el reconocimiento"},
            {"tool": "flaky", "args": {"attempt_marker": "no"},
             "rationale": "paso que falla a proposito para probar reintentos"},
        ],
    }
)


async def main() -> int:
    for f in (DB, Path(str(DB) + "-wal"), Path(str(DB) + "-shm")):
        f.unlink(missing_ok=True)

    ledger = Ledger(DB)
    server = StdioServerParameters(
        command=sys.executable, args=["-m", "tools_server.echo_server"]
    )

    print(f"\n=== SMOKE TEST (offline) ===\nObjetivo: {OBJETIVO}\n")

    state = await MissionRunner(server, ledger, StubPlanner(PLAN_FIJO)).run(OBJETIVO)

    for i, s in enumerate(state.steps):
        icon = {"ok": "[OK]", "failed": "[XX]", "pending": "[--]"}[s.status]
        print(f"  {icon} paso {i}: {s.tool:<10} intentos={s.attempts}  {s.result or ''}")

    print("\n--- LEDGER ---")
    for e in ledger.entries(state.mission_id):
        print(f"  #{e.seq:<3} {e.kind:<18} {e.entry_hash[:16]}...")

    ok, _ = ledger.verify()
    print(f"\nCadena integra: {ok}")

    ledger.close()
    con = sqlite3.connect(DB)
    con.execute("UPDATE ledger SET payload='{\"tampered\":true}' WHERE seq=2")
    con.commit()
    con.close()

    ledger2 = Ledger(DB)
    ok2, bad2 = ledger2.verify()
    print(f"Tras manipular la fila 2 -> integra: {ok2}  (primera rota: seq {bad2})")
    ledger2.close()

    aprobado = ok and not ok2
    print("\nSMOKE TEST OK." if aprobado else "\nSMOKE TEST FALLIDO.")
    return 0 if aprobado else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
