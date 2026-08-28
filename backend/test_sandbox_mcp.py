"""Prueba VIVA: misiones completas con el servidor MCP dentro de gVisor.

Esta es la que cierra la Fase 2b. Hasta ahora el sandbox existia y se
autoverificaba, pero las tools corrian como subproceso del orquestador, sin
aislamiento. Aqui el servidor MCP arranca DENTRO del contenedor.

REQUISITOS: Docker con runsc, y la imagen oracle-tools construida:
    docker build -t oracle-tools:latest -f Dockerfile.tools .

Si falta algo, la suite lo dice y se salta en vez de fingir que paso.

Correr con:  python test_sandbox_mcp.py
"""
from __future__ import annotations

import asyncio
import json
import shutil
import tempfile
from pathlib import Path

from mcp import Client

from oracle.ledger import Ledger
from oracle.manifest import ToolPinStore
from oracle.planner import StubPlanner
from oracle.runner import MissionRunner
from oracle.sandbox import DockerSandbox, SandboxUnavailable
from oracle.sentinel import Sentinel

AQUI = Path(__file__).parent.resolve()
IMAGEN = "oracle-tools:latest"
OBJ = "auditar 10.0.0.5"


async def _imagen_existe(sb: DockerSandbox) -> bool:
    code, out, _ = await sb._exec(["docker", "images", "-q", IMAGEN], timeout=20)
    return code == 0 and bool(out.strip())


async def main() -> int:
    if shutil.which("docker") is None:
        print("  [--] saltado: no hay docker en esta maquina")
        return 0

    sb = DockerSandbox()
    try:
        await sb.preflight()
    except SandboxUnavailable as exc:
        print(f"  [--] saltado: {str(exc)[:110]}")
        return 0

    if not await _imagen_existe(sb):
        print(f"  [--] saltado: falta la imagen {IMAGEN}")
        print(f"       construyela con: docker build -t {IMAGEN} -f Dockerfile.tools .")
        return 0

    fallos = 0
    resultados: list[tuple[str, bool]] = []

    def check(n: str, ok: bool) -> None:
        nonlocal fallos
        resultados.append((n, ok))
        fallos += not ok

    params = sb.mcp_stdio_params("tools_server.echo_server", str(AQUI), IMAGEN)

    # 1. El servidor MCP habla desde dentro del contenedor.
    async with Client(params) as c:
        tools = {t.name for t in (await c.list_tools()).tools}
        check("el servidor MCP responde desde el contenedor",
              {"recon", "slow_scan", "flaky"} <= tools)

        r = await c.call_tool("recon", {"target": "10.0.0.5"})
        texto = "".join(b.text for b in r.content if getattr(b, "type", None) == "text")
        check("una tool ejecuta y devuelve resultado", "puertos=22,80,443" in texto)

    # 2. El proceso que corre la tool ve el kernel de gVisor, no el del host.
    params_k = sb.mcp_stdio_params("tools_server.probe_server", str(AQUI), IMAGEN)
    async with Client(params_k) as c:
        r = await c.call_tool("kernel", {})
        kernel = "".join(b.text for b in r.content if getattr(b, "type", None) == "text")
        check(f"la tool corre bajo gVisor ({kernel.strip()})", "gvisor" in kernel.lower())

        r = await c.call_tool("caps", {})
        caps = "".join(b.text for b in r.content if getattr(b, "type", None) == "text")
        check("la tool corre sin capabilities", "0000000000000000" in caps)

        r = await c.call_tool("try_write", {})
        w = "".join(b.text for b in r.content if getattr(b, "type", None) == "text")
        check("la tool no puede escribir en el filesystem", "READONLY" in w)

        r = await c.call_tool("routes", {})
        rt = "".join(b.text for b in r.content if getattr(b, "type", None) == "text")
        check("la tool no tiene red", rt.strip() == "0")

    # 3. Una mision completa, de punta a punta, con todo el pipeline.
    tmp = Path(tempfile.mkdtemp())
    led = Ledger(tmp / "l.db")
    plan = json.dumps({"objective": OBJ, "steps": [
        {"tool": "recon", "args": {"target": "10.0.0.5"}, "rationale": "reconocer"},
        {"tool": "slow_scan", "args": {"target": "10.0.0.5", "seconds": 0.5},
         "rationale": "escanear"}]})
    st = await MissionRunner(
        params, led, StubPlanner(plan), server_id="sandboxed",
        pins=ToolPinStore(tmp / "p.json"), sentinel=Sentinel(),
    ).run(OBJ)
    check("mision completa con tools aisladas", st.success)
    check("el ledger queda integro", led.verify()[0])

    for n, ok in resultados:
        print(f"  [{'OK' if ok else 'XX'}] {n}")
    print(f"\n{len(resultados) - fallos}/{len(resultados)} casos correctos.")
    return 1 if fallos else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
