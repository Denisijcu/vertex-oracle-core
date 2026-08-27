"""Planner: convierte un objetivo en lenguaje natural en un Plan validado.

Reglas no negociables:
  - La salida del LLM se valida con Pydantic v2 y contra el JSON Schema real
    de cada tool. Nada se ejecuta sin pasar por ahi.
  - Si el plan no valida, se le devuelve el error concreto al modelo y se
    reintenta hasta MAX_PLAN_ATTEMPTS. No se "arregla" el plan por nuestra cuenta.
  - El Planner solo ve las tools declaradas. No puede inventar capacidades.
"""
from __future__ import annotations

import json
import os
from typing import Protocol

from .plan import Plan, PlanError, validate_against_tools

MAX_PLAN_ATTEMPTS = 3
DEFAULT_MODEL = os.getenv("ORACLE_PLANNER_MODEL", "claude-sonnet-5")

SYSTEM = """Eres el Planner de un orquestador de agentes de autonomia prolongada.

Recibes un objetivo y el catalogo EXACTO de herramientas disponibles.
Devuelves un plan paso a paso para cumplirlo.

Reglas absolutas:
- Solo puedes usar herramientas del catalogo. No inventes nombres.
- Los argumentos deben cumplir el JSON Schema de cada herramienta.
- Cada paso lleva un "rationale" breve que lo ata al objetivo original.
- Si el objetivo no se puede cumplir con las herramientas dadas, devuelve
  un plan con un solo paso usando la herramienta mas cercana y explica la
  limitacion en el rationale.

Responde UNICAMENTE con un objeto JSON, sin markdown, sin backticks, sin
preambulo, con esta forma exacta:
{"objective": "<el objetivo recibido, literal>",
 "steps": [{"tool": "<nombre>", "args": {...}, "rationale": "<por que>"}]}"""


class Planner(Protocol):
    async def plan(self, objective: str, tools: dict[str, dict]) -> Plan: ...


def _strip_fences(text: str) -> str:
    t = text.strip()
    if t.startswith("```"):
        t = t.split("\n", 1)[-1]
        if t.rstrip().endswith("```"):
            t = t.rstrip()[:-3]
    return t.strip()


class ClaudePlanner:
    """Planner respaldado por la API de Anthropic."""

    def __init__(self, model: str = DEFAULT_MODEL, api_key: str | None = None) -> None:
        from anthropic import AsyncAnthropic

        key = api_key or os.getenv("ANTHROPIC_API_KEY")
        if not key:
            raise RuntimeError("Falta ANTHROPIC_API_KEY en el entorno o en .env")
        self._client = AsyncAnthropic(api_key=key)
        self._model = model
        self.last_error: str | None = None

    async def plan(self, objective: str, tools: dict[str, dict]) -> Plan:
        catalog = json.dumps(tools, indent=2, ensure_ascii=False)
        convo: list[dict] = [
            {
                "role": "user",
                "content": f"OBJETIVO:\n{objective}\n\nCATALOGO DE HERRAMIENTAS:\n{catalog}",
            }
        ]

        for attempt in range(1, MAX_PLAN_ATTEMPTS + 1):
            resp = await self._client.messages.create(
                model=self._model,
                max_tokens=2000,
                system=SYSTEM,
                messages=convo,
            )
            raw = "".join(b.text for b in resp.content if getattr(b, "type", None) == "text")

            try:
                candidate = Plan.model_validate_json(_strip_fences(raw))
                validate_against_tools(candidate, tools)
                self.last_error = None
                return candidate
            except Exception as exc:  # noqa: BLE001
                self.last_error = f"{type(exc).__name__}: {exc}"
                if attempt == MAX_PLAN_ATTEMPTS:
                    raise PlanError(
                        f"El Planner no produjo un plan valido en {MAX_PLAN_ATTEMPTS} intentos. "
                        f"Ultimo error: {self.last_error}"
                    ) from exc
                convo += [
                    {"role": "assistant", "content": raw},
                    {
                        "role": "user",
                        "content": (
                            f"Ese plan fue RECHAZADO: {self.last_error}\n"
                            "Corrigelo y responde de nuevo solo con el JSON."
                        ),
                    },
                ]

        raise PlanError("inalcanzable")  # pragma: no cover


class StubPlanner:
    """Planner de pruebas: devuelve un plan fijo. Sin red, para tests."""

    def __init__(self, payload: str) -> None:
        self._payload = payload

    async def plan(self, objective: str, tools: dict[str, dict]) -> Plan:
        candidate = Plan.model_validate_json(_strip_fences(self._payload))
        validate_against_tools(candidate, tools)
        return candidate
