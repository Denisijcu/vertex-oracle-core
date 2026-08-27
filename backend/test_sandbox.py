"""Pruebas del modulo de sandbox.

Tiene DOS partes:
  - OFFLINE: construccion de banderas y logica de preflight con un docker
    falso. Corre en cualquier maquina, sin Docker.
  - VIVA: aislamiento real. Solo corre si hay Docker con runsc; si no, se
    salta y lo dice.

Correr con:  python test_sandbox.py
"""
from __future__ import annotations

import asyncio
import shutil

from oracle.sandbox import (
    DockerSandbox,
    IsolationReport,
    SandboxPolicy,
    SandboxUnavailable,
)


# ------------------------------------------------------------------ offline

def test_banderas() -> list[tuple[str, bool]]:
    args = SandboxPolicy().docker_args()
    linea = " ".join(args)
    return [
        ("runtime runsc forzado", "--runtime=runsc" in args),
        ("sin red", "--network=none" in args),
        ("cap-drop ALL", "--cap-drop ALL" in linea),
        ("solo lectura", "--read-only" in args),
        ("tmpfs noexec", "noexec" in linea),
        ("usuario no-root", "--user=65534:65534" in args),
        ("limite de pids", "--pids-limit=128" in args),
        ("limite de memoria", "--memory=512m" in args),
        ("no-new-privileges", "no-new-privileges" in linea),
        ("contenedor efimero", "--rm" in args),
    ]


class FakeSandbox(DockerSandbox):
    """Sustituye _exec para probar preflight sin Docker."""

    def __init__(self, runtimes_json: str, code: int = 0) -> None:
        # docker_bin="sh" solo para que el chequeo de PATH pase; _exec esta
        # sustituido, asi que nunca se ejecuta nada de verdad.
        super().__init__(docker_bin="sh")
        self._fake = (code, runtimes_json, "")

    async def _exec(self, cmd, timeout, stdin=""):  # type: ignore[override]
        return self._fake


async def test_preflight() -> list[tuple[str, bool]]:
    out: list[tuple[str, bool]] = []

    # runsc presente -> pasa
    s = FakeSandbox('{"runc":{},"runsc":{"path":"/usr/bin/runsc"}}')
    try:
        await s.preflight()
        out.append(("acepta cuando runsc existe", True))
    except SandboxUnavailable:
        out.append(("acepta cuando runsc existe", False))

    # runsc ausente -> DEBE lanzar, nunca degradar
    s = FakeSandbox('{"runc":{}}')
    try:
        await s.preflight()
        out.append(("RECHAZA si falta runsc", False))
    except SandboxUnavailable as exc:
        out.append(("RECHAZA si falta runsc", "NO se degrada" in str(exc)))

    # daemon caido -> lanza
    s = FakeSandbox("", code=1)
    try:
        await s.preflight()
        out.append(("rechaza si el daemon no responde", False))
    except SandboxUnavailable:
        out.append(("rechaza si el daemon no responde", True))

    return out


def test_reporte() -> list[tuple[str, bool]]:
    bueno = IsolationReport(
        kernel="4.19.0-gvisor", cap_eff="0000000000000000", routes=0, writable=False
    )
    bueno.checks = {
        "kernel_gvisor": True, "sin_capabilities": True,
        "sin_rutas_de_red": True, "solo_lectura": True,
    }
    malo = IsolationReport(kernel="6.6.87-microsoft-standard-WSL2")
    malo.checks = {"kernel_gvisor": False, "sin_capabilities": True,
                   "sin_rutas_de_red": True, "solo_lectura": True}
    vacio = IsolationReport()
    return [
        ("reporte bueno = aislado", bueno.isolated),
        ("kernel del host = NO aislado", not malo.isolated),
        ("sin checks = NO aislado", not vacio.isolated),
    ]


# --------------------------------------------------------------------- viva

async def test_vivo() -> list[tuple[str, bool]] | None:
    if shutil.which("docker") is None:
        return None
    s = DockerSandbox()
    try:
        await s.preflight()
    except SandboxUnavailable as exc:
        print(f"\n[!] Sandbox no disponible aqui: {str(exc)[:120]}")
        return None

    rep = await s.verify_isolation()
    print(f"\n  kernel visto por el contenedor : {rep.kernel}")
    print(f"  CapEff                         : {rep.cap_eff}")
    print(f"  rutas de red                   : {rep.routes}")
    print(f"  filesystem escribible          : {rep.writable}")
    return [(n, v) for n, v in sorted(rep.checks.items())]


async def main() -> int:
    fallos = 0

    for titulo, casos in [
        ("banderas de la politica", test_banderas()),
        ("preflight (docker falso)", await test_preflight()),
        ("reporte de aislamiento", test_reporte()),
    ]:
        print(f"\n--- {titulo} ---")
        for nombre, ok in casos:
            print(f"  [{'OK' if ok else 'XX'}] {nombre}")
            fallos += not ok

    print("\n--- aislamiento REAL (requiere docker + runsc) ---")
    vivo = await test_vivo()
    if vivo is None:
        print("  [--] saltado: no hay Docker con runsc en esta maquina")
    else:
        for nombre, ok in vivo:
            print(f"  [{'OK' if ok else 'XX'}] {nombre}")
            fallos += not ok

    print(f"\n{'TODO VERDE' if not fallos else f'{fallos} FALLOS'}")
    return 1 if fallos else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
