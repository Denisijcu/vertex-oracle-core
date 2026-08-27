"""Runner de misiones: Planner -> plan bloqueado -> Worker -> Ledger.

NOTA DE ARQUITECTURA
--------------------
El estado de la mision vive AQUI, en Oracle Core, no en la capa MCP.
La extension Tasks del protocolo (tasks/get, tasks/update, tasks/cancel) todavia
no esta implementada en el SDK de Python. Cuando salga, este es el unico modulo
que cambia.

ANTI-DRIFT
----------
El plan se BLOQUEA antes de ejecutar (plan-before-act). El Worker no lo
renegocia: no puede agregar pasos ni cambiar la tool de un paso a mitad de
camino. Cada paso reafirma el objetivo original antes de correr.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from mcp import Client, StdioServerParameters

from .ledger import Ledger
from .manifest import ToolPinStore
from .plan import Plan, PlanError

MAX_ATTEMPTS = 3        # reintentos por paso


@dataclass
class StepState:
    tool: str
    args: dict[str, Any]
    rationale: str
    result: Any = None
    attempts: int = 0
    status: str = "pending"         # pending | ok | failed


@dataclass
class MissionState:
    objective: str
    steps: list[StepState]
    mission_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    aborted_by: str | None = None

    @property
    def success(self) -> bool:
        return bool(self.steps) and all(s.status == "ok" for s in self.steps)


class MissionRunner:
    def __init__(
        self,
        server: StdioServerParameters,
        ledger: Ledger,
        planner,
        server_id: str = "default",
        pins: ToolPinStore | None = None,
    ) -> None:
        self._server = server
        self._ledger = ledger
        self._planner = planner
        self._server_id = server_id
        self._pins = pins or ToolPinStore()

    async def run(self, objective: str) -> MissionState:
        mission_id = uuid.uuid4().hex[:12]
        self._ledger.append(mission_id, "mission.start", {"objective": objective})

        async with Client(self._server) as client:
            declared = (await client.list_tools()).tools
            tools = {t.name: (t.input_schema or {"type": "object"}) for t in declared}
            self._ledger.append(mission_id, "tools.discovered", {"tools": sorted(tools)})

            # --- Defensa contra tool poisoning: se corre ANTES de planificar. ---
            scan = self._pins.verify_or_pin(self._server_id, declared)
            if scan.findings:
                self._ledger.append(
                    mission_id,
                    "tools.findings",
                    {"detalle": [f.__dict__ for f in scan.findings]},
                )
            if scan.blocked:
                self._ledger.append(
                    mission_id,
                    "mission.aborted",
                    {"motivo": "tool poisoning", "detalle": scan.summary()},
                )
                self._ledger.append(mission_id, "mission.end", {"success": False})
                st = MissionState(objective=objective, steps=[], mission_id=mission_id)
                st.aborted_by = scan.summary()
                return st

            try:
                plan: Plan = await self._planner.plan(objective, tools)
            except PlanError as exc:
                self._ledger.append(mission_id, "plan.rejected", {"error": str(exc)[:800]})
                self._ledger.append(mission_id, "mission.end", {"success": False})
                return MissionState(objective=objective, steps=[], mission_id=mission_id)

            # Plan bloqueado: a partir de aqui es inmutable y queda sellado.
            self._ledger.append(
                mission_id,
                "plan.locked",
                {"steps": [{"tool": s.tool, "args": s.args} for s in plan.steps]},
            )

            state = MissionState(
                objective=objective,
                steps=[StepState(s.tool, s.args, s.rationale) for s in plan.steps],
                mission_id=mission_id,
            )

            for idx, step in enumerate(state.steps):
                # Anclaje de objetivo: el objetivo del plan debe seguir siendo el original.
                if plan.objective.strip() != objective.strip():
                    self._ledger.append(
                        mission_id,
                        "drift.detected",
                        {"expected": objective, "got": plan.objective},
                    )
                    step.status = "failed"
                    break

                await self._run_step(client, mission_id, idx, step)
                if step.status == "failed":
                    break

        self._ledger.append(mission_id, "mission.end", {"success": state.success})
        return state

    async def _run_step(self, client: Client, mission_id: str, idx: int, step: StepState) -> None:
        while step.attempts < MAX_ATTEMPTS:
            step.attempts += 1
            self._ledger.append(
                mission_id,
                "step.start",
                {"step": idx, "tool": step.tool, "args": step.args, "attempt": step.attempts},
            )
            try:
                res = await client.call_tool(step.tool, step.args)
                if getattr(res, "is_error", False):
                    raise RuntimeError(_text_of(res))
                step.result = _text_of(res)
                step.status = "ok"
                self._ledger.append(
                    mission_id, "step.checkpoint", {"step": idx, "result": step.result}
                )
                return
            except Exception as exc:  # noqa: BLE001
                self._ledger.append(
                    mission_id,
                    "step.error",
                    {"step": idx, "attempt": step.attempts, "error": str(exc)[:400]},
                )
        step.status = "failed"


def _text_of(result: Any) -> str:
    parts = []
    for block in getattr(result, "content", []) or []:
        if getattr(block, "type", None) == "text":
            parts.append(block.text)
    return "\n".join(parts)
