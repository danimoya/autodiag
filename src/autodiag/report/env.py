"""Capture the environment of a target: version, patches, parameters, instances, nodes."""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from autodiag.core.models import Node, Target

_PATCH_LINE = re.compile(r"^(\d+);(.+?)(?: \(\d+\))?\s*$")


def parse_opatch_lspatches(text: str) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for line in text.splitlines():
        m = _PATCH_LINE.match(line.strip())
        if m:
            out.append({"id": m.group(1), "description": m.group(2).strip()})
    return out


def capture_environment(
    target: Target,
    *,
    transport_factory: Callable[[Node], Any] | None,
    runner: Any | None,
) -> dict[str, Any]:
    env: dict[str, Any] = {
        "target": target.name,
        "platform": target.platform.value,
        "kind": target.kind.value,
        "db_unique_name": target.db_unique_name,
        "version_full": target.oracle_version,
        "patches": [],
        "sqlpatch": [],
        "nondefault_parameters": {},
        "instances": [],
        "nodes": [],
        "errors": [],
    }
    if runner is not None:
        for name, handler in (
            ("db_info", _db_info),
            ("sqlpatch_registry", _sqlpatch),
            ("params_nondefault", _params),
            ("rac_instances", _instances),
        ):
            try:
                handler(env, runner.run_named(name, {}, max_rows=500).as_dicts())
            except Exception as exc:  # noqa: BLE001 - every source is optional
                env["errors"].append(f"{name}: {exc}")
    else:
        env["errors"].append("no SQL*Net runner: version/patch registry/parameters not captured")
    if transport_factory is not None:
        for node in target.nodes:
            info: dict[str, Any] = {"host": node.host, "instance": node.instance}
            t = transport_factory(node)
            for cmd, key in (("hostname", "hostname"), ("uptime", "uptime")):
                try:
                    res = t.run(cmd, {})
                    info[key] = res.stdout.strip() if res.ok else f"error rc={res.returncode}"
                except Exception as exc:  # noqa: BLE001
                    info[key] = f"error: {exc}"
            if node.oracle_home:
                try:
                    res = t.run("opatch_lspatches", {"oracle_home": node.oracle_home})
                    patches = parse_opatch_lspatches(res.stdout) if res.ok else []
                    info["opatch"] = patches
                    if patches and not env["patches"]:
                        env["patches"] = [f"{p['id']} {p['description']}" for p in patches]
                except Exception as exc:  # noqa: BLE001
                    env["errors"].append(f"opatch on {node.host}: {exc}")
            env["nodes"].append(info)
    return env


def _db_info(env: dict[str, Any], rows: list[dict[str, Any]]) -> None:
    if rows:
        r = rows[0]
        env["version_full"] = r.get("VERSION_FULL") or env["version_full"]
        env["db_unique_name"] = r.get("DB_UNIQUE_NAME") or env["db_unique_name"]
        env["db_name"] = r.get("DB_NAME")
        env["database_role"] = r.get("DATABASE_ROLE")
        env["instance_name"] = r.get("INSTANCE_NAME")
        env["host_name"] = r.get("HOST_NAME")
        env["startup_time"] = str(r.get("STARTUP_TIME"))


def _sqlpatch(env: dict[str, Any], rows: list[dict[str, Any]]) -> None:
    env["sqlpatch"] = rows[:20]
    if rows and not env["patches"]:
        env["patches"] = [f"{r.get('PATCH_ID')} {r.get('DESCRIPTION')}" for r in rows[:10]]


def _params(env: dict[str, Any], rows: list[dict[str, Any]]) -> None:
    env["nondefault_parameters"] = {str(r.get("NAME")): str(r.get("VALUE")) for r in rows}


def _instances(env: dict[str, Any], rows: list[dict[str, Any]]) -> None:
    env["instances"] = rows
