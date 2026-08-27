"""FASE 1 - Oracle Core: ejecuta una mision desde un objetivo en lenguaje natural.

Uso:
    python mission.py "auditar el host 10.0.0.5 y hacerle un escaneo lento"
    python mission.py --verify            (solo verifica el ledger existente)

Requiere ANTHROPIC_API_KEY en el entorno o en un .env junto a este archivo.
"""
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

from mcp import StdioServerParameters

from oracle.ledger import Ledger
from oracle.planner import ClaudePlanner
from oracle.runner import MissionRunner

DB = Path(__file__).parent / "oracle_ledger.db"


def _load_dotenv() -> None:
    env = Path(__file__).parent / ".env"
    if not env.exists():
        return
    for line in env.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


async def main(argv: list[str]) -> int:
    _load_dotenv()
    ledger = Ledger(DB)

    if "--verify" in argv:
        ok, bad = ledger.verify()
        print(f"Cadena integra: {ok}" + ("" if ok else f"  (primera rota: seq {bad})"))
        return 0 if ok else 1

    if len(argv) < 2:
        print(__doc__)
        return 2

    objective = argv[1]
    server = StdioServerParameters(
        command=sys.executable, args=["-m", "tools_server.echo_server"]
    )

    print(f"\n=== OBJETIVO ===\n{objective}\n")
    print("Planificando...")

    state = await MissionRunner(server, ledger, ClaudePlanner()).run(objective)

    if not state.steps:
        print("\nEl plan fue RECHAZADO. Revisa el ledger:")
        for e in ledger.entries(state.mission_id):
            if e.kind == "plan.rejected":
                print(f"  {e.payload['error']}")
        return 1

    print(f"\n=== PLAN ({len(state.steps)} pasos) ===")
    for i, s in enumerate(state.steps):
        icon = {"ok": "[OK]", "failed": "[XX]", "pending": "[--]"}[s.status]
        print(f"  {icon} {i}: {s.tool:<12} {s.rationale}")
        if s.result:
            print(f"        -> {s.result}")

    print(f"\n--- LEDGER (mision {state.mission_id}) ---")
    for e in ledger.entries(state.mission_id):
        print(f"  #{e.seq:<3} {e.kind:<18} {e.entry_hash[:16]}...")

    ok, bad = ledger.verify()
    print(f"\nMision exitosa: {state.success}")
    if ok:
        print("Cadena integra: True")
    else:
        print(f"Cadena integra: FALSE -> la entrada #{bad} de este ledger fue ALTERADA.")
        print("   Esto es INDEPENDIENTE del resultado de la mision de arriba.")
        print("   Una cadena rota no se repara: se archiva el .db y se investiga")
        print("   quien lo toco. Para empezar limpio, borra el archivo .db.")
    return 0 if state.success and ok else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main(sys.argv)))
