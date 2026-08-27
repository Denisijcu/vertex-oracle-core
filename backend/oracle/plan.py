"""Contrato del plan: lo que el Planner produce y el Worker ejecuta.

El plan es un CONTRATO, no texto. Si no valida contra este esquema y contra
las tools realmente declaradas por el servidor MCP, se rechaza. Nunca se
ejecuta "lo que se pudo entender".
"""
from __future__ import annotations

from typing import Any

from jsonschema import Draft202012Validator
from jsonschema import ValidationError as JSONSchemaError
from pydantic import BaseModel, Field, field_validator

MAX_STEPS = 25


class PlanError(Exception):
    """El plan propuesto no es ejecutable. El mensaje se le devuelve al Planner."""


class PlannedStep(BaseModel):
    tool: str = Field(min_length=1)
    args: dict[str, Any] = Field(default_factory=dict)
    rationale: str = Field(min_length=1, max_length=500)

    @field_validator("tool")
    @classmethod
    def _clean(cls, v: str) -> str:
        return v.strip()


class Plan(BaseModel):
    objective: str = Field(min_length=1)
    steps: list[PlannedStep] = Field(min_length=1, max_length=MAX_STEPS)


def validate_against_tools(plan: Plan, tools: dict[str, dict]) -> None:
    """Verifica que cada paso use una tool declarada y args validos.

    `tools` es {nombre: input_schema} tal como lo declaro el servidor MCP.
    Lanza PlanError con un mensaje accionable para que el Planner reintente.
    """
    problems: list[str] = []

    for i, step in enumerate(plan.steps):
        if step.tool not in tools:
            problems.append(
                f"paso {i}: la tool '{step.tool}' no existe. "
                f"Disponibles: {sorted(tools)}"
            )
            continue
        try:
            Draft202012Validator(tools[step.tool]).validate(step.args)
        except JSONSchemaError as exc:
            path = ".".join(str(p) for p in exc.path) or "(raiz)"
            problems.append(f"paso {i} (tool '{step.tool}'): args invalidos en {path}: {exc.message}")

    if problems:
        raise PlanError("; ".join(problems))
