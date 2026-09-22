"""Shared plumbing for CLI commands: settings, inventory, sources, output helpers."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import typer
from pydantic import BaseModel

from autodiag.adr.source import AdrSource
from autodiag.case.store import CaseStore
from autodiag.core.models import Node, Target
from autodiag.core.settings import Settings, load_settings
from autodiag.core.targets import TargetInventory, load_targets
from autodiag.transport.ssh import SshTransport


def settings() -> Settings:
    return load_settings()


def inventory(s: Settings | None = None) -> TargetInventory:
    s = s or settings()
    return load_targets(s.targets_file)


def target(name: str, s: Settings | None = None) -> Target:
    try:
        return inventory(s).get(name)
    except KeyError:
        typer.echo(f"unknown target {name!r} (see 'autodiag targets list')", err=True)
        raise typer.Exit(code=1) from None


def transport_factory(s: Settings, t: Target) -> Callable[[Node], object]:
    """Builds the per-node transport; tests replace this to avoid the network."""
    return lambda node: SshTransport(
        node,
        t.allowed_roots,
        ssh_config=s.ssh_config,
        connect_timeout=s.ssh_connect_timeout,
        default_timeout=s.ssh_command_timeout,
    )


def source(t: Target, s: Settings | None = None) -> AdrSource:
    s = s or settings()
    return AdrSource(t, transport_factory=transport_factory(s, t), ssh_config=s.ssh_config)


def store(s: Settings | None = None) -> CaseStore:
    s = s or settings()
    return CaseStore(s.data_dir / "autodiag.db", artifacts_dir=s.data_dir / "cases")


def sql_runner(s: Settings, t: Target):
    """SQL*Net runner for a target, or None when it has no SQL*Net configuration."""
    if t.sqlnet is None:
        return None
    from autodiag.sql.runner import SqlRunner

    return SqlRunner(t.sqlnet, timeout=s.sql_timeout, diagnostics_pack=t.diagnostics_pack)


def context(s: Settings | None = None):
    """Full tool context (store, sources, SQL runners) using the same factories the CLI
    uses, so tests can substitute them."""
    from autodiag.mcp.server import AutoDiagContext

    s = s or settings()
    return AutoDiagContext(
        s,
        inventory(s),
        transport_factory=lambda t: transport_factory(s, t),
        runner_factory=lambda t: sql_runner(s, t),
    )


def pct(v: float) -> str:
    return f"{round(v * 100)}%"


def cache_dir(s: Settings, t: Target) -> Path:
    d = s.data_dir / "cache" / t.name
    d.mkdir(parents=True, exist_ok=True)
    return d


def emit(obj: Any, *, as_json: bool, lines: list[str] | None = None) -> None:
    if as_json:
        if isinstance(obj, BaseModel):
            typer.echo(obj.model_dump_json(indent=2))
        else:
            typer.echo(json.dumps(obj, indent=2, default=str))
        return
    for ln in lines or []:
        typer.echo(ln)


def table(rows: list[list[str]], headers: list[str]) -> list[str]:
    widths = [max(len(str(r[i])) for r in [headers, *rows]) for i in range(len(headers))]
    fmt = "  ".join("{:<" + str(w) + "}" for w in widths)
    out = [fmt.format(*headers), fmt.format(*["-" * w for w in widths])]
    out += [fmt.format(*[str(c) for c in r]) for r in rows]
    return out


def fmt_ts(ts) -> str:
    return ts.strftime("%Y-%m-%d %H:%M:%S%z") if ts else "-"


def us(v: int) -> str:
    return f"{v / 1e6:.3f}s"
