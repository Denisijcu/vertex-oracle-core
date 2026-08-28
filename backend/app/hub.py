"""MissionHub: corre misiones y las transmite a los operadores conectados.

DECISION DE ALCANCE
-------------------
El transporte es asyncio en proceso, no Redis. Para una sola instancia del
orquestador, Redis no agrega nada: seria una dependencia mas que administrar
para mover mensajes entre corrutinas del mismo proceso.

Cuando haga falta escalar a varios workers, el punto de cambio es este archivo:
`QueuedApprover` ya es la costura, y el broker pasa a publicar en Redis en vez
de en colas locales. Nada mas cambia.

FALLO CERRADO, TAMBIEN AQUI
---------------------------
Si no hay operadores conectados cuando una mision pide intervencion, se aborta.
Un panel cerrado no es una aprobacion.
"""
from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from oracle.hitl import ABORT, Decision, InterventionRequest, QueuedApprover
from oracle.ledger import Entry, Ledger

HITL_TIMEOUT_S = 300.0


@dataclass
class MissionView:
    """Lo que el panel necesita saber de una mision."""

    id: str
    objective: str
    status: str = "corriendo"        # corriendo | exitosa | fallida | abortada
    steps: list[dict] = field(default_factory=list)
    entries: list[dict] = field(default_factory=list)
    pending: dict | None = None      # intervencion esperando respuesta


class MissionHub:
    def __init__(self, db_path: str | Path) -> None:
        self._db = str(db_path)
        self._clients: set[asyncio.Queue] = set()
        self._missions: dict[str, MissionView] = {}
        self._approvers: dict[str, QueuedApprover] = {}
        self._loop: asyncio.AbstractEventLoop | None = None

    # ------------------------------------------------------------ clientes

    def connect(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue()
        self._clients.add(q)
        return q

    def disconnect(self, q: asyncio.Queue) -> None:
        self._clients.discard(q)

    @property
    def operators_online(self) -> int:
        return len(self._clients)

    def broadcast(self, kind: str, data: dict) -> None:
        msg = {"kind": kind, "data": data}
        for q in list(self._clients):
            q.put_nowait(msg)

    def snapshot(self) -> list[dict]:
        return [self._as_dict(m) for m in self._missions.values()]

    @staticmethod
    def _as_dict(m: MissionView) -> dict:
        return {
            "id": m.id, "objective": m.objective, "status": m.status,
            "steps": m.steps, "entries": m.entries, "pending": m.pending,
        }

    # ------------------------------------------------------------ misiones

    async def start(self, objective: str, runner_factory) -> str:
        """Arranca una mision en segundo plano. `runner_factory(ledger, approver)`
        devuelve un MissionRunner ya configurado."""
        self._loop = asyncio.get_running_loop()
        mid = uuid.uuid4().hex[:12]
        view = MissionView(id=mid, objective=objective)
        self._missions[mid] = view

        approver = _HubApprover(self, mid, HITL_TIMEOUT_S)
        self._approvers[mid] = approver

        def on_append(e: Entry) -> None:
            fila = {
                "seq": e.seq, "kind": e.kind, "hash": e.entry_hash,
                "prev": e.prev_hash, "payload": e.payload, "ts": e.ts,
            }
            view.entries.append(fila)
            self.broadcast("ledger.entry", {"mission": mid, "entry": fila})

        ledger = Ledger(self._db, on_append=on_append)
        self.broadcast("mission.started", {"mission": mid, "objective": objective})

        asyncio.create_task(self._run(mid, view, runner_factory(ledger, approver)))
        return mid

    async def _run(self, mid: str, view: MissionView, runner) -> None:
        try:
            state = await runner.run(view.objective)
            view.steps = [
                {"tool": s.tool, "status": s.status, "verdict": s.verdict,
                 "rationale": s.rationale, "result": s.result}
                for s in state.steps
            ]
            if state.aborted_by:
                view.status = "abortada"
            else:
                view.status = "exitosa" if state.success else "fallida"
        except Exception as exc:  # noqa: BLE001
            view.status = "fallida"
            view.steps.append({"tool": "-", "status": "failed", "verdict": "",
                               "rationale": str(exc)[:200], "result": None})
        finally:
            view.pending = None
            self._approvers.pop(mid, None)
            self.broadcast("mission.ended",
                           {"mission": mid, "status": view.status, "steps": view.steps})

    # ------------------------------------------------------------ decisiones

    def decide(self, mission_id: str, action: str, operator: str, reason: str) -> bool:
        ap = self._approvers.get(mission_id)
        if ap is None:
            return False
        ap.answer(Decision(action=action, operator=operator or "operador", reason=reason))
        view = self._missions.get(mission_id)
        if view:
            view.pending = None
        self.broadcast("hitl.resolved", {"mission": mission_id, "accion": action})
        return True

    def _pending(self, mid: str, req: InterventionRequest) -> None:
        view = self._missions.get(mid)
        payload = {
            "mission": mid, "kind": req.kind, "summary": req.summary,
            "context": req.context, "options": list(req.options),
        }
        if view:
            view.pending = payload
        self.broadcast("hitl.requested", payload)


class _HubApprover(QueuedApprover):
    """QueuedApprover que avisa al panel y aborta si no hay nadie mirando."""

    def __init__(self, hub: MissionHub, mission_id: str, timeout_s: float) -> None:
        super().__init__(timeout_s=timeout_s)
        self._hub = hub
        self._mid = mission_id

    async def decide(self, req: InterventionRequest) -> Decision:
        if self._hub.operators_online == 0:
            self._hub.broadcast("hitl.unattended", {"mission": self._mid})
            return Decision(
                ABORT, "sistema",
                "no hay ningun operador conectado al panel; fallo cerrado",
            )
        self._hub._pending(self._mid, req)
        return await super().decide(req)
