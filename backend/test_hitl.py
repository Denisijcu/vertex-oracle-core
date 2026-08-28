"""Pruebas OFFLINE del human-in-the-loop. Sin red, sin API.

Correr con:  python test_hitl.py
"""
from __future__ import annotations

import asyncio
import json
import sys
import tempfile
from pathlib import Path

from mcp import StdioServerParameters

from oracle.hitl import (
    ABORT,
    APPROVE,
    Decision,
    FailClosedApprover,
    InterventionRequest,
    OVERRIDE,
    QueuedApprover,
    RETRY,
)
from oracle.ledger import Ledger
from oracle.manifest import ToolPinStore
from oracle.planner import StubPlanner
from oracle.runner import MissionRunner
from oracle.sentinel import Sentinel

OBJ = "auditar 10.0.0.5"


def _req(options=(APPROVE, RETRY, ABORT)) -> InterventionRequest:
    return InterventionRequest("m1", "sentinel_escalation", "prueba", {}, options)


class Scripted:
    """Approver que responde con un guion fijo, en orden."""

    def __init__(self, *decisiones: Decision) -> None:
        self._d = list(decisiones)
        self.llamadas = 0

    async def decide(self, req: InterventionRequest) -> Decision:
        self.llamadas += 1
        return self._d.pop(0) if self._d else Decision(ABORT, "guion", "sin mas decisiones")


async def test_politica() -> list[tuple[str, bool]]:
    out = []

    d = await FailClosedApprover().decide(_req())
    out.append(("sin operador -> aborta", d.action == ABORT and not d.continues))

    q = QueuedApprover(timeout_s=0.15)
    d = await q.decide(_req())
    out.append(("operador no responde -> aborta", d.action == ABORT and d.timed_out))

    q = QueuedApprover(timeout_s=5)
    q.answer(Decision(APPROVE, "denis", "revisado a mano"))
    d = await q.decide(_req())
    out.append(("respuesta valida -> se respeta", d.action == APPROVE and d.operator == "denis"))

    q = QueuedApprover(timeout_s=5)
    q.answer(Decision(OVERRIDE, "denis", "x"))
    d = await q.decide(_req(options=(APPROVE, ABORT)))
    out.append(("decision fuera de opciones -> aborta", d.action == ABORT))

    out.append(("approve y override continuan",
                Decision(APPROVE).continues and Decision(OVERRIDE).continues))
    out.append(("retry y abort no continuan",
                not Decision(RETRY).continues and not Decision(ABORT).continues))
    return out


def _runner(ledger, pins, tool, approver, servidor="tainted", modulo="tools_server.tainted_server"):
    plan = json.dumps({"objective": OBJ, "steps": [
        {"tool": tool, "args": {"target": "10.0.0.5"}, "rationale": "r"}]})
    return MissionRunner(
        StdioServerParameters(command=sys.executable, args=["-m", modulo]),
        ledger, StubPlanner(plan), server_id=servidor, pins=pins,
        sentinel=Sentinel(), approver=approver,
    )


async def test_integracion() -> list[tuple[str, bool]]:
    out = []
    tmp = Path(tempfile.mkdtemp())

    # REJECT del Sentinel: bloqueo duro, el operador NI SIQUIERA se consulta.
    led = Ledger(tmp / "a.db")
    ap = Scripted(Decision(APPROVE, "denis", "dejalo pasar"))
    st = await _runner(led, ToolPinStore(tmp / "a.json"), "poisoned_scan", ap).run(OBJ)
    out.append(("REJECT no es negociable por el operador",
                st.steps[0].status == "rejected" and ap.llamadas == 0))

    # Rug pull: se fija limpio, luego cambia. El operador re-aprueba.
    pins = ToolPinStore(tmp / "b.json")
    led = Ledger(tmp / "b.db")
    await _runner(led, pins, "recon", Scripted(),
                  servidor="srv", modulo="tools_server.echo_server").run(OBJ)
    ap = Scripted(Decision(APPROVE, "denis", "actualizacion legitima"))
    st = await _runner(led, pins, "clean_scan", ap, servidor="srv").run(OBJ)
    out.append(("rug pull -> el operador re-aprueba",
                ap.llamadas == 1 and st.success))

    # Mismo rug pull, pero el operador aborta.
    pins2 = ToolPinStore(tmp / "c.json")
    led2 = Ledger(tmp / "c.db")
    await _runner(led2, pins2, "recon", Scripted(),
                  servidor="srv", modulo="tools_server.echo_server").run(OBJ)
    ap = Scripted(Decision(ABORT, "denis", "no reconozco ese cambio"))
    st = await _runner(led2, pins2, "clean_scan", ap, servidor="srv").run(OBJ)
    out.append(("rug pull -> el operador aborta", st.aborted_by is not None))

    # Servidor con INYECCION: nunca llega al operador.
    pins3 = ToolPinStore(tmp / "d.json")
    led3 = Ledger(tmp / "d.db")
    ap = Scripted(Decision(APPROVE, "denis", "confio"))
    st = await _runner(led3, pins3, "recon", ap,
                       servidor="p", modulo="tools_server.poisoned_server").run(OBJ)
    out.append(("inyeccion en descripciones no es re-aprobable",
                st.aborted_by is not None and ap.llamadas == 0))

    # Sin operador (default): un escalado termina en aborto.
    pins4 = ToolPinStore(tmp / "e.json")
    led4 = Ledger(tmp / "e.db")
    st = await _runner(led4, pins4, "recon", None,
                       servidor="q", modulo="tools_server.poisoned_server").run(OBJ)
    out.append(("default es fallo cerrado", st.aborted_by is not None))

    # El ledger guarda pregunta Y respuesta.
    kinds = [e.kind for e in Ledger(tmp / "b.db").entries()]
    out.append(("pregunta y decision quedan selladas",
                "hitl.requested" in kinds and "hitl.decision" in kinds
                and "tools.repinned" in kinds))
    return out


async def main() -> int:
    fallos = 0
    for titulo, casos in [
        ("politica de fallo cerrado", await test_politica()),
        ("integracion con el runner", await test_integracion()),
    ]:
        print(f"\n--- {titulo} ---")
        for nombre, ok in casos:
            print(f"  [{'OK' if ok else 'XX'}] {nombre}")
            fallos += not ok
    total = 6 + 6
    print(f"\n{total - fallos}/{total} casos correctos.")
    return 1 if fallos else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
