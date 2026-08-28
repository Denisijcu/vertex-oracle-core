"""Human-in-the-loop: cuando el sistema no puede decidir solo.

PRINCIPIO RECTOR: FALLA CERRADO
-------------------------------
Si no hay operador disponible, o si el operador no responde a tiempo, la
mision se ABORTA. Nunca se auto-aprueba. Un HITL que aprueba solo cuando
nadie mira no es un control, es un adorno.

Es la misma regla del sandbox: ante la duda, no se degrada.

QUE SE ESCALA
-------------
- El Sentinel devolvio ESCALATE sobre el resultado de una tool.
- Un servidor MCP cambio su huella (rug pull) SIN patrones de inyeccion.
  Un servidor legitimo que se actualiza cae aqui y el operador puede
  re-aprobarlo. Uno con inyeccion en las descripciones NO llega: eso es
  bloqueo duro y no es negociable por nadie.

QUE NO SE ESCALA
----------------
Un veredicto REJECT del Sentinel y un servidor con inyeccion declarada.
Esos son bloqueos duros. Dejarlos aprobables convierte al operador en el
eslabon que el atacante ataca: basta con cansarlo a las 3 de la manana.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Protocol

# Decisiones que puede tomar el operador
APPROVE = "approve"       # continuar con el resultado tal cual
OVERRIDE = "override"     # continuar, pero con un resultado sustituido
RETRY = "retry"           # volver a intentar el paso
ABORT = "abort"           # detener la mision

# Motivos por los que se pide intervencion
SENTINEL_ESCALATION = "sentinel_escalation"
TOOL_DRIFT = "tool_drift"

DEFAULT_TIMEOUT_S = 300.0


@dataclass
class InterventionRequest:
    mission_id: str
    kind: str
    summary: str
    context: dict[str, Any] = field(default_factory=dict)
    options: tuple[str, ...] = (APPROVE, RETRY, ABORT)


@dataclass
class Decision:
    action: str = ABORT
    operator: str = "sistema"
    reason: str = ""
    override_result: str | None = None
    timed_out: bool = False

    @property
    def continues(self) -> bool:
        return self.action in (APPROVE, OVERRIDE)


class Approver(Protocol):
    async def decide(self, req: InterventionRequest) -> Decision: ...


class FailClosedApprover:
    """Sin operador conectado. Aborta siempre. Es el DEFAULT a proposito."""

    async def decide(self, req: InterventionRequest) -> Decision:
        return Decision(
            ABORT,
            operator="sistema",
            reason="no hay operador conectado; se aborta por politica de fallo cerrado",
        )


class QueuedApprover:
    """Recibe decisiones por una cola asincrona.

    Es la base sobre la que se monta cualquier transporte (Redis Pub/Sub,
    WebSocket, CLI). El transporte solo tiene que poner una Decision en la
    cola; la politica de tiempo y el fallo cerrado viven aqui.
    """

    def __init__(self, timeout_s: float = DEFAULT_TIMEOUT_S) -> None:
        self.timeout_s = timeout_s
        self.pending: asyncio.Queue[InterventionRequest] = asyncio.Queue()
        self._answers: asyncio.Queue[Decision] = asyncio.Queue()

    def answer(self, decision: Decision) -> None:
        """Lo llama el transporte cuando el operador responde."""
        self._answers.put_nowait(decision)

    async def decide(self, req: InterventionRequest) -> Decision:
        await self.pending.put(req)
        try:
            d = await asyncio.wait_for(self._answers.get(), timeout=self.timeout_s)
        except asyncio.TimeoutError:
            return Decision(
                ABORT,
                operator="sistema",
                reason=f"el operador no respondio en {self.timeout_s:.0f}s",
                timed_out=True,
            )
        if d.action not in req.options:
            # Una decision fuera de las opciones ofrecidas no se interpreta
            # con buena fe: se aborta.
            return Decision(
                ABORT,
                operator=d.operator,
                reason=f"decision '{d.action}' no estaba entre las opciones {req.options}",
            )
        return d


class CLIApprover:
    """Operador humano en la terminal. Util para correr misiones a mano."""

    def __init__(self, operator: str = "cli", timeout_s: float = DEFAULT_TIMEOUT_S) -> None:
        self.operator = operator
        self.timeout_s = timeout_s

    async def decide(self, req: InterventionRequest) -> Decision:
        print("\n" + "=" * 62)
        print(f"  INTERVENCION REQUERIDA  ({req.kind})")
        print("=" * 62)
        print(f"  Mision : {req.mission_id}")
        print(f"  Motivo : {req.summary}")
        for k, v in req.context.items():
            print(f"  {k:<8}: {str(v)[:300]}")
        print(f"\n  Opciones: {', '.join(req.options)}")

        try:
            raw = await asyncio.wait_for(
                asyncio.to_thread(input, "  Decision: "), timeout=self.timeout_s
            )
        except asyncio.TimeoutError:
            print("\n  Sin respuesta. Se aborta por politica de fallo cerrado.")
            return Decision(ABORT, self.operator, "timeout en la consola", timed_out=True)

        accion = raw.strip().lower()
        if accion not in req.options:
            return Decision(ABORT, self.operator, f"entrada no valida: {accion!r}")

        motivo = ""
        try:
            motivo = await asyncio.wait_for(
                asyncio.to_thread(input, "  Motivo (queda en el ledger): "), timeout=60.0
            )
        except asyncio.TimeoutError:
            pass
        return Decision(accion, self.operator, motivo.strip()[:300])
