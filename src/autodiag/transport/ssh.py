"""SSH transport: runs allowlisted commands on a database node as the oracle user."""

from __future__ import annotations

import shlex
import subprocess
import time
from collections.abc import Callable, Sequence
from pathlib import Path

from pydantic import BaseModel

from autodiag.core.models import Node
from autodiag.transport.allowlist import ALLOWLIST, build_command, remote_shell_line

__all__ = ["CommandResult", "SshTransport"]


class CommandResult(BaseModel):
    name: str
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str = ""
    truncated: bool = False
    timed_out: bool = False
    duration: float = 0.0

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


class SshTransport:
    """One node, key-based SSH, login shell on the remote side.

    ``runner`` and ``popen`` are injectable for tests (defaults: ``subprocess.run`` and
    ``subprocess.Popen``).
    """

    def __init__(
        self,
        node: Node,
        allowed_roots: Sequence[str],
        *,
        ssh_config: Path | None = None,
        connect_timeout: int = 10,
        default_timeout: int = 120,
        runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
        popen: Callable[..., object] = subprocess.Popen,
    ) -> None:
        self.node = node
        self.allowed_roots = list(allowed_roots)
        self.ssh_config = ssh_config
        self.connect_timeout = connect_timeout
        self.default_timeout = default_timeout
        self._runner = runner
        self._popen = popen

    # -- command construction -------------------------------------------------------
    def ssh_argv(self) -> list[str]:
        argv = [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            f"ConnectTimeout={self.connect_timeout}",
            "-o",
            "StrictHostKeyChecking=accept-new",
        ]
        if self.ssh_config is not None:
            argv += ["-F", str(self.ssh_config)]
        if self.node.ssh_alias is None and self.node.ssh_port != 22:
            argv += ["-p", str(self.node.ssh_port)]
        argv.append(self.node.ssh_target)
        return argv

    def remote_command(self, argv: Sequence[str]) -> str:
        exports: list[str] = []
        if self.node.oracle_home:
            exports.append(f"export ORACLE_HOME={shlex.quote(self.node.oracle_home)}")
            exports.append('export PATH="$ORACLE_HOME/bin:$PATH"')
        if self.node.instance:
            exports.append(f"export ORACLE_SID={shlex.quote(self.node.instance)}")
        script = "; ".join([*exports, remote_shell_line(argv)])
        return f"bash -lc {shlex.quote(script)}"

    # -- execution ------------------------------------------------------------------
    def run(
        self,
        name: str,
        params: dict[str, object],
        *,
        timeout: int | None = None,
        max_bytes: int | None = None,
    ) -> CommandResult:
        argv = build_command(name, params, allowed_roots=self.allowed_roots)
        spec = ALLOWLIST[name]
        timeout = timeout or spec.timeout or self.default_timeout
        cap = max_bytes or spec.max_bytes
        full = [*self.ssh_argv(), self.remote_command(argv)]
        started = time.monotonic()
        try:
            proc = self._runner(full, capture_output=True, timeout=timeout, check=False)
        except subprocess.TimeoutExpired as exc:
            out = exc.stdout or b""
            return CommandResult(
                name=name,
                argv=argv,
                returncode=124,
                stdout=_decode(out[:cap]),
                stderr=f"timed out after {timeout}s",
                truncated=len(out) > cap,
                timed_out=True,
                duration=time.monotonic() - started,
            )
        out: bytes = proc.stdout or b""
        return CommandResult(
            name=name,
            argv=argv,
            returncode=proc.returncode,
            stdout=_decode(out[:cap]),
            stderr=_decode((proc.stderr or b"")[:4096]),
            truncated=len(out) > cap,
            duration=time.monotonic() - started,
        )

    def fetch(
        self, path: str, dest: Path, *, max_bytes: int | None = None, timeout: int | None = None
    ) -> CommandResult:
        """Stream a remote file into ``dest`` (bounded by ``max_bytes``)."""
        argv = build_command("cat_file", {"path": path}, allowed_roots=self.allowed_roots)
        spec = ALLOWLIST["cat_file"]
        cap = max_bytes or spec.max_bytes
        full = [*self.ssh_argv(), self.remote_command(argv)]
        started = time.monotonic()
        dest.parent.mkdir(parents=True, exist_ok=True)
        proc = self._popen(full, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        written = 0
        truncated = False
        with dest.open("wb") as fh:
            while True:
                chunk = proc.stdout.read(1024 * 1024)  # type: ignore[attr-defined]
                if not chunk:
                    break
                if written + len(chunk) > cap:
                    fh.write(chunk[: cap - written])
                    written = cap
                    truncated = True
                    proc.kill()  # type: ignore[attr-defined]
                    break
                fh.write(chunk)
                written += len(chunk)
        rc = proc.wait(timeout=timeout or spec.timeout)  # type: ignore[attr-defined]
        return CommandResult(
            name="cat_file",
            argv=argv,
            returncode=0 if truncated else rc,
            stdout=str(dest),
            truncated=truncated,
            duration=time.monotonic() - started,
        )


def _decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")
