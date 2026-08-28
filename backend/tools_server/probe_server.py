"""Servidor MCP que reporta su propio entorno de ejecucion.

Sirve para comprobar, DESDE DENTRO de una tool real, que el aislamiento esta
puesto. No mide la configuracion declarada: mide lo que el proceso ve.
"""
from __future__ import annotations

import platform
from pathlib import Path

from mcp.server import MCPServer

mcp = MCPServer("oracle-probe", version="0.1.0")


@mcp.tool()
def kernel() -> str:
    """Devuelve la version del kernel que ve este proceso."""
    return platform.release()


@mcp.tool()
def caps() -> str:
    """Devuelve las capabilities efectivas de este proceso."""
    for linea in Path("/proc/self/status").read_text().splitlines():
        if linea.startswith("CapEff"):
            return linea.split()[-1]
    return "desconocido"


@mcp.tool()
def try_write() -> str:
    """Intenta escribir en la raiz. Devuelve READONLY o WRITABLE."""
    try:
        Path("/probe_rw").write_text("x")
        return "WRITABLE"
    except OSError:
        return "READONLY"


@mcp.tool()
def routes() -> str:
    """Cuenta las rutas de red visibles para este proceso."""
    lineas = Path("/proc/net/route").read_text().splitlines()
    return str(max(0, len(lineas) - 1))


if __name__ == "__main__":
    mcp.run()
