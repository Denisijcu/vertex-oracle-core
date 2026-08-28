"""Defensa contra tool poisoning en servidores MCP.

Dos capas independientes:

1. PINNING (fijado criptografico)
   La primera vez que se ve un servidor se toma la huella SHA-256 de cada tool
   (nombre + descripcion + esquema de entrada) y se guarda. En cada conexion
   posterior se recalcula y se compara. Si una tool cambio en silencio despues
   de haber sido aprobada, eso es un "rug pull" y la mision se aborta.

2. ESCANEO DE DESCRIPCIONES
   El Planner LEE las descripciones de las tools. Por lo tanto una descripcion
   es una superficie de inyeccion. Se buscan instrucciones dirigidas al modelo,
   señales de exfiltracion y caracteres invisibles.

LIMITACION HONESTA
------------------
La capa 2 es heuristica: es un cable trampa, no una garantia. Un atacante que
conozca los patrones los evade. La defensa fuerte es la capa 1 mas aprobacion
humana de tools nuevas. La capa 2 solo sube el costo del ataque trivial.
"""
from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

# Caracteres que no deberian aparecer NUNCA en la descripcion de una tool:
# invisibles (zero-width) y controles de direccion bidireccional.
_INVISIBLES = {
    "\u200b", "\u200c", "\u200d", "\ufeff", "\u2060",
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
    "\u2066", "\u2067", "\u2068", "\u2069",
}

# Instrucciones dirigidas al modelo, no al humano que lee la doc.
_PATRONES = [
    (r"\bignor(e|a|ar)\b.{0,30}\b(previous|anterior|instruc)", "instruccion de ignorar ordenes previas"),
    (r"\bdisregard\b.{0,30}\b(above|previous|prior)", "instruccion de descartar contexto"),
    (r"\b(do not|don't|no le|nunca)\b.{0,25}\b(tell|inform|mention|digas|menciones)\b", "instruccion de ocultar al usuario"),
    (r"<\s*(important|system|secret|admin)\s*>", "etiqueta pseudo-sistema en la descripcion"),
    (r"\b(before|antes de)\b.{0,25}\b(using|usar|calling|llamar)\b.{0,40}\b(read|lee|first|primero)\b", "precondicion inyectada"),
    (r"\b(\.ssh|id_rsa|\.env|passwd|credential|api[_ -]?key|token)\b", "referencia a material sensible"),
    (r"\b(curl|wget|exfiltrat|upload to|send to)\b", "señal de exfiltracion"),
    (r"data:[a-z/]+;base64,", "payload embebido en base64"),
]

MAX_DESC = 1500  # una descripcion legitima no necesita mas


@dataclass
class Finding:
    tool: str
    severity: str          # "block" | "warn"
    reason: str
    kind: str = "injection"   # "injection" | "drift"


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return any(f.severity == "block" for f in self.findings)

    @property
    def only_drift(self) -> bool:
        """True si lo unico que bloquea es un cambio de huella, sin inyeccion.

        Un servidor legitimo que se actualiza produce SOLO drift: el operador
        puede re-aprobarlo. Un servidor con patrones de inyeccion en sus
        descripciones NO es re-aprobable: eso es un bloqueo duro.
        """
        duros = [f for f in self.findings if f.severity == "block"]
        return bool(duros) and all(f.kind == "drift" for f in duros)

    def summary(self) -> str:
        return "; ".join(f"[{f.severity}] {f.tool}: {f.reason}" for f in self.findings)


def fingerprint(name: str, description: str | None, schema: dict | None) -> str:
    """Huella estable de una tool. Cambia si cambia CUALQUIER parte del contrato."""
    blob = json.dumps(
        {"name": name, "description": description or "", "schema": schema or {}},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def scan_description(name: str, description: str | None) -> list[Finding]:
    """Busca inyeccion en la descripcion de una tool."""
    out: list[Finding] = []
    desc = description or ""

    hallados = sorted({c for c in desc if c in _INVISIBLES})
    if hallados:
        nombres = ", ".join(f"U+{ord(c):04X}" for c in hallados)
        out.append(Finding(name, "block", f"caracteres invisibles en la descripcion ({nombres})"))

    if any(unicodedata.category(c) == "Cf" for c in desc):
        if not hallados:
            out.append(Finding(name, "warn", "caracteres de formato Unicode ocultos"))

    if len(desc) > MAX_DESC:
        out.append(Finding(name, "warn", f"descripcion anormalmente larga ({len(desc)} chars)"))

    bajo = desc.lower()
    for patron, motivo in _PATRONES:
        if re.search(patron, bajo, re.DOTALL):
            out.append(Finding(name, "block", motivo))

    return out


class ToolPinStore:
    """Guarda las huellas aprobadas por servidor en un JSON local."""

    def __init__(self, path: str | Path = "tool_pins.json") -> None:
        self.path = Path(path)
        self._data: dict[str, dict[str, str]] = {}
        if self.path.exists():
            self._data = json.loads(self.path.read_text(encoding="utf-8"))

    def _save(self) -> None:
        self.path.write_text(
            json.dumps(self._data, indent=2, sort_keys=True, ensure_ascii=False),
            encoding="utf-8",
        )

    def known(self, server: str) -> bool:
        return server in self._data

    def verify_or_pin(self, server: str, tools: Iterable[Any]) -> ScanResult:
        """Escanea y compara contra lo fijado. Si el servidor es nuevo, lo fija.

        `tools` son objetos con .name, .description y .input_schema.
        """
        result = ScanResult()
        actual: dict[str, str] = {}

        for t in tools:
            desc = getattr(t, "description", None)
            schema = getattr(t, "input_schema", None)
            result.findings.extend(scan_description(t.name, desc))
            actual[t.name] = fingerprint(t.name, desc, schema)

        if not self.known(server):
            # Primera vez: si el escaneo la bloquea, NO se fija nada.
            if not result.blocked:
                self._data[server] = actual
                self._save()
            return result

        fijado = self._data[server]
        for nombre, huella in actual.items():
            if nombre not in fijado:
                result.findings.append(
                    Finding(nombre, "block", "tool nueva no aprobada desde el ultimo fijado",
                            kind="drift")
                )
            elif fijado[nombre] != huella:
                result.findings.append(
                    Finding(
                        nombre,
                        "block",
                        f"RUG PULL: el contrato cambio tras ser aprobado "
                        f"({fijado[nombre][:12]}... -> {huella[:12]}...)",
                        kind="drift",
                    )
                )
        for nombre in fijado:
            if nombre not in actual:
                result.findings.append(
                    Finding(nombre, "warn", "tool aprobada que ya no se declara", kind="drift")
                )

        return result

    def repin(self, server: str, tools: Iterable[Any]) -> None:
        """Re-aprueba explicitamente un servidor. Accion deliberada del operador."""
        self._data[server] = {
            t.name: fingerprint(
                t.name, getattr(t, "description", None), getattr(t, "input_schema", None)
            )
            for t in tools
        }
        self._save()
