"""Pruebas OFFLINE de la capa de validacion del plan. No usa red ni API key.

Verifica que la barrera rechaza lo que tiene que rechazar. Correr con:
    python test_planner.py
"""
from __future__ import annotations

import asyncio
import json
import sys

from oracle.plan import PlanError
from oracle.planner import StubPlanner

TOOLS = {
    "recon": {
        "type": "object",
        "properties": {"target": {"type": "string"}},
        "required": ["target"],
    },
    "slow_scan": {
        "type": "object",
        "properties": {"target": {"type": "string"}, "seconds": {"type": "number"}},
        "required": ["target"],
    },
}

OBJ = "auditar 10.0.0.5"

CASOS = [
    (
        "plan valido",
        json.dumps({"objective": OBJ, "steps": [
            {"tool": "recon", "args": {"target": "10.0.0.5"}, "rationale": "reconocer"}]}),
        None,
    ),
    (
        "tool inventada",
        json.dumps({"objective": OBJ, "steps": [
            {"tool": "exfiltrate", "args": {}, "rationale": "x"}]}),
        "no existe",
    ),
    (
        "falta arg requerido",
        json.dumps({"objective": OBJ, "steps": [
            {"tool": "recon", "args": {}, "rationale": "x"}]}),
        "args invalidos",
    ),
    (
        "tipo de arg incorrecto",
        json.dumps({"objective": OBJ, "steps": [
            {"tool": "slow_scan", "args": {"target": "h", "seconds": "rapido"},
             "rationale": "x"}]}),
        "args invalidos",
    ),
    (
        "JSON malformado",
        '{"objective": "x", "steps": [',
        "",
    ),
    (
        "sin pasos",
        json.dumps({"objective": OBJ, "steps": []}),
        "",
    ),
    (
        "envuelto en backticks",
        "```json\n" + json.dumps({"objective": OBJ, "steps": [
            {"tool": "recon", "args": {"target": "h"}, "rationale": "ok"}]}) + "\n```",
        None,
    ),
]


async def main() -> int:
    fallos = 0
    for nombre, payload, espera_error in CASOS:
        try:
            await StubPlanner(payload).plan(OBJ, TOOLS)
            ok = espera_error is None
            detalle = "aceptado"
        except (PlanError, Exception) as exc:  # noqa: BLE001
            ok = espera_error is not None and espera_error in str(exc)
            detalle = f"rechazado: {str(exc)[:70]}"
        print(f"  [{'OK' if ok else 'XX'}] {nombre:<26} {detalle}")
        fallos += not ok

    print(f"\n{len(CASOS) - fallos}/{len(CASOS)} casos correctos.")
    return 1 if fallos else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
