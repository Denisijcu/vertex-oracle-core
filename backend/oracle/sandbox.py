"""Ejecucion aislada de herramientas en contenedores efimeros con gVisor.

PRINCIPIO RECTOR
----------------
El runtime aislado es OBLIGATORIO, nunca opcional. Si `runsc` no esta
disponible, este modulo LANZA UNA EXCEPCION. Jamas cae a `runc` en silencio.

Esa degradacion silenciosa es el modo de fallo mas peligroso de todo el
sistema: no explota, no da error, y todo parece funcionar mientras el codigo
generado por un LLM corre compartiendo kernel con la maquina anfitriona.

FRONTERA DE RED
---------------
El contenedor corre con `--network none`, siempre. Las llamadas a servidores
MCP remotos salen del ORQUESTADOR, nunca desde dentro del sandbox. Si alguna
vez hace falta una excepcion aqui, ya se perdio el aislamiento.
"""
from __future__ import annotations

import asyncio
import json
import shutil
from dataclasses import dataclass, field


class SandboxUnavailable(RuntimeError):
    """El entorno no puede garantizar aislamiento. Nunca se degrada: se aborta."""


class SandboxTimeout(RuntimeError):
    """La ejecucion excedio el limite de tiempo y el contenedor fue destruido."""


@dataclass(frozen=True)
class SandboxPolicy:
    """Politica de aislamiento. Los defaults son los seguros."""

    image: str = "python:3.12-slim"
    runtime: str = "runsc"
    network: str = "none"
    read_only: bool = True
    drop_all_caps: bool = True
    no_new_privileges: bool = True
    user: str = "65534:65534"          # nobody:nogroup
    memory: str = "512m"
    cpus: str = "1.0"
    pids_limit: int = 128
    timeout_s: float = 30.0
    tmpfs: str = "/tmp:rw,noexec,nosuid,nodev,size=64m"

    def docker_args(self) -> list[str]:
        """Traduce la politica a banderas de `docker run`."""
        args = [
            "run", "--rm", "-i",
            f"--runtime={self.runtime}",
            f"--network={self.network}",
            f"--memory={self.memory}",
            f"--cpus={self.cpus}",
            f"--pids-limit={self.pids_limit}",
            f"--user={self.user}",
            "--security-opt", "no-new-privileges" if self.no_new_privileges else "seccomp=unconfined",
        ]
        if self.drop_all_caps:
            args += ["--cap-drop", "ALL"]
        if self.read_only:
            args += ["--read-only", "--tmpfs", self.tmpfs]
        return args


@dataclass
class SandboxResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out


@dataclass
class IsolationReport:
    """Resultado de la autoverificacion. Se sella en el ledger al arrancar."""

    kernel: str = ""
    cap_eff: str = ""
    routes: int = -1
    writable: bool = True
    checks: dict[str, bool] = field(default_factory=dict)

    @property
    def isolated(self) -> bool:
        return bool(self.checks) and all(self.checks.values())

    def summary(self) -> str:
        return "; ".join(
            f"{n}={'OK' if v else 'FALLA'}" for n, v in sorted(self.checks.items())
        )


class DockerSandbox:
    """Ejecuta comandos en contenedores efimeros bajo gVisor."""

    def __init__(self, policy: SandboxPolicy | None = None, docker_bin: str = "docker") -> None:
        self.policy = policy or SandboxPolicy()
        self._docker = docker_bin

    # ---------------------------------------------------------------- preflight

    async def preflight(self) -> None:
        """Verifica que el runtime aislado exista. Lanza si no. NO degrada."""
        if shutil.which(self._docker) is None:
            raise SandboxUnavailable(
                f"'{self._docker}' no esta en el PATH. Oracle Core no ejecuta "
                "herramientas sin sandbox."
            )

        code, out, err = await self._exec(
            [self._docker, "info", "--format", "{{json .Runtimes}}"], timeout=15.0
        )
        if code != 0:
            raise SandboxUnavailable(f"el daemon de Docker no responde: {err.strip()[:200]}")

        try:
            runtimes = json.loads(out or "{}")
        except json.JSONDecodeError as exc:
            raise SandboxUnavailable(f"no se pudo leer los runtimes de Docker: {exc}") from exc

        if self.policy.runtime not in runtimes:
            raise SandboxUnavailable(
                f"el runtime '{self.policy.runtime}' no esta registrado en Docker. "
                f"Disponibles: {sorted(runtimes)}. "
                "Instalalo con 'sudo runsc install && sudo systemctl restart docker'. "
                "Oracle Core NO se degrada a runc."
            )

    # ------------------------------------------------------- autoverificacion

    async def verify_isolation(self) -> IsolationReport:
        """Corre una sonda dentro del sandbox y comprueba el aislamiento real.

        No confia en la configuracion declarada: mide lo que el contenedor ve.
        """
        rep = IsolationReport()

        probe = (
            "uname -r; "
            "echo '::'; "
            "grep CapEff /proc/self/status | tr -d '\\t' ; "
            "echo '::'; "
            "tail -n +2 /proc/net/route | wc -l; "
            "echo '::'; "
            "touch /probe_rw 2>/dev/null && echo WRITABLE || echo READONLY"
        )
        res = await self.run(["/bin/sh", "-c", probe], image="ubuntu")

        partes = [p.strip() for p in res.stdout.split("::")]
        if len(partes) >= 4:
            rep.kernel = partes[0]
            rep.cap_eff = partes[1].replace("CapEff:", "").strip()
            rep.routes = int(partes[2] or -1)
            rep.writable = partes[3] == "WRITABLE"

        rep.checks = {
            "kernel_gvisor": "gvisor" in rep.kernel.lower(),
            "sin_capabilities": rep.cap_eff == "0000000000000000",
            "sin_rutas_de_red": rep.routes == 0,
            "solo_lectura": not rep.writable,
        }
        return rep

    # ------------------------------------------------------------------ run

    async def run(
        self,
        argv: list[str],
        stdin: str = "",
        image: str | None = None,
        timeout_s: float | None = None,
    ) -> SandboxResult:
        """Ejecuta argv dentro de un contenedor efimero. No hace preflight solo."""
        limite = timeout_s or self.policy.timeout_s
        cmd = [self._docker, *self.policy.docker_args(), image or self.policy.image, *argv]

        code, out, err = await self._exec(cmd, timeout=limite, stdin=stdin)
        if code is None:
            return SandboxResult(-1, out, err, timed_out=True)
        return SandboxResult(code, out, err)

    # -------------------------------------------------------------- interno

    async def _exec(
        self, cmd: list[str], timeout: float, stdin: str = ""
    ) -> tuple[int | None, str, str]:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            out, err = await asyncio.wait_for(
                proc.communicate(stdin.encode()), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return None, "", f"tiempo excedido tras {timeout}s"
        return proc.returncode, out.decode(errors="replace"), err.decode(errors="replace")
