"""Servidor MCP de prueba para Oracle Core (stdio, spec 2026-07-28).

Tres tools: una rapida, una lenta (simula trabajo largo) y una que falla
a proposito, para probar el camino de reintento del runner.
"""
from __future__ import annotations

import anyio
from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

mcp = MCPServer("oracle-spike-tools", version="0.1.0")


@mcp.tool()
def recon(target: str) -> str:
    """Devuelve un resumen de reconocimiento simulado para un objetivo."""
    return f"recon:{target}:puertos=22,80,443"


@mcp.tool()
async def slow_scan(target: str, seconds: float = 2.0) -> str:
    """Escaneo lento: simula una operacion de larga duracion."""
    await anyio.sleep(seconds)
    return f"scan:{target}:completo tras {seconds}s"


@mcp.tool()
def flaky(attempt_marker: str = "") -> str:
    """Falla si no se le pasa el marcador 'retry'. Sirve para probar reintentos.

    Usa ToolError (error esperado del dominio) en vez de una excepcion cruda,
    para que el servidor no escupa un traceback en stderr.
    """
    if attempt_marker != "retry":
        raise ToolError("fallo transitorio simulado")
    return "flaky:ok"


if __name__ == "__main__":
    mcp.run()
