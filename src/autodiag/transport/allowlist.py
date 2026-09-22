"""The closed set of commands AutoDiag may run on a database node over SSH.

Every command is a named template with typed, validated parameters. Nothing outside this
table can be executed by any interface (MCP tool, REST, CLI). Paths must sit under an
allowed root (the target's diagnostic destination, AHF repository, ...), ADR homes are
relative and clean, and free-text parameters are constrained to safe character sets or
passed as single quoted arguments.
"""

from __future__ import annotations

import posixpath
import re
import shlex
import string
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

__all__ = ["ALLOWLIST", "AllowlistError", "CommandSpec", "build_command", "remote_shell_line"]


class AllowlistError(ValueError):
    """Raised when a command name or parameter is not acceptable."""


Validator = Callable[[str, Any, Sequence[str]], str]

_ADR_HOME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_./-]*$")
_PROBLEM_KEY_RE = re.compile(r"^[A-Za-z0-9 _\[\]\-.:#/()*+,]+$")
_IDENT_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_FILE_GLOB_RE = re.compile(r"^[A-Za-z0-9_.*%-]+$")


def _v_int(name: str, value: Any, _roots: Sequence[str]) -> str:
    if isinstance(value, bool) or not isinstance(value, int):
        raise AllowlistError(f"parameter {name!r} must be an integer")
    if value < 0:
        raise AllowlistError(f"parameter {name!r} must be >= 0")
    return str(value)


def _v_adr_home(name: str, value: Any, _roots: Sequence[str]) -> str:
    s = str(value)
    if not s or not _ADR_HOME_RE.match(s) or ".." in s.split("/") or s.startswith("/"):
        raise AllowlistError(f"parameter {name!r} must be a clean relative ADR home")
    return s


def _v_path(name: str, value: Any, roots: Sequence[str]) -> str:
    s = str(value)
    if not s.startswith("/") or "\n" in s or "\x00" in s:
        raise AllowlistError(f"parameter {name!r} must be an absolute path")
    norm = posixpath.normpath(s)
    if ".." in s.split("/"):
        raise AllowlistError(f"parameter {name!r} must not contain '..'")
    for root in roots:
        r = posixpath.normpath(root)
        if norm == r or norm.startswith(r.rstrip("/") + "/"):
            return norm
    raise AllowlistError(f"parameter {name!r} is not under an allowed root")


def _v_problem_key(name: str, value: Any, _roots: Sequence[str]) -> str:
    s = str(value)
    if not s or not _PROBLEM_KEY_RE.match(s):
        raise AllowlistError(f"parameter {name!r} contains characters outside the safe set")
    return s


def _v_ident(name: str, value: Any, _roots: Sequence[str]) -> str:
    s = str(value)
    if not s or not _IDENT_RE.match(s):
        raise AllowlistError(f"parameter {name!r} must be an identifier")
    return s


def _v_file_glob(name: str, value: Any, _roots: Sequence[str]) -> str:
    s = str(value)
    if not s or not _FILE_GLOB_RE.match(s):
        raise AllowlistError(f"parameter {name!r} must be a simple file name pattern")
    return s


def _v_text(name: str, value: Any, _roots: Sequence[str]) -> str:
    s = str(value)
    if not s or "\n" in s or "\x00" in s:
        raise AllowlistError(f"parameter {name!r} must be a single line of text")
    return s


def _v_choice(*choices: str) -> Validator:
    def check(name: str, value: Any, _roots: Sequence[str]) -> str:
        s = str(value)
        if s not in choices:
            raise AllowlistError(f"parameter {name!r} must be one of {choices}")
        return s

    return check


@dataclass(frozen=True)
class CommandSpec:
    argv: tuple[str, ...]
    params: dict[str, Validator] = field(default_factory=dict)
    description: str = ""
    timeout: int = 60
    max_bytes: int = 4 * 1024 * 1024


def _adrci(script: str) -> tuple[str, ...]:
    return ("adrci", "exec=set home {adr_home}; " + script)


ALLOWLIST: dict[str, CommandSpec] = {
    "hostname": CommandSpec(("hostname",), description="Node host name", timeout=10),
    "uptime": CommandSpec(("uptime",), description="Node uptime and load", timeout=10),
    "adrci_show_homes": CommandSpec(
        ("adrci", "exec=show homes"), description="List ADR homes", timeout=60
    ),
    "adrci_show_problem": CommandSpec(
        _adrci('show problem -p "lastinc_time > systimestamp - {days}"'),
        {"adr_home": _v_adr_home, "days": _v_int},
        "Problems with incidents in the last N days",
    ),
    "adrci_show_incident": CommandSpec(
        _adrci("show incident -mode {mode} -p \"problem_key='{problem_key}'\""),
        {
            "adr_home": _v_adr_home,
            "problem_key": _v_problem_key,
            "mode": _v_choice("brief", "detail"),
        },
        "Incidents of one problem key",
    ),
    "adrci_show_incident_by_id": CommandSpec(
        _adrci('show incident -mode {mode} -p "incident_id={incident_id}"'),
        {"adr_home": _v_adr_home, "incident_id": _v_int, "mode": _v_choice("brief", "detail")},
        "One incident by id",
    ),
    "adrci_show_alert_tail": CommandSpec(
        _adrci("show alert -tail {lines}"),
        {"adr_home": _v_adr_home, "lines": _v_int},
        "Last N alert-log lines through adrci",
        timeout=120,
    ),
    "adrci_show_tracefile": CommandSpec(
        _adrci("show tracefile %{pattern}%"),
        {"adr_home": _v_adr_home, "pattern": _v_file_glob},
        "Trace files whose name contains a pattern",
    ),
    "adrci_ips_create_problem": CommandSpec(
        _adrci("ips create package problem {problem_id}"),
        {"adr_home": _v_adr_home, "problem_id": _v_int},
        "Create an IPS package for a problem",
        timeout=600,
    ),
    "adrci_ips_create_incident": CommandSpec(
        _adrci("ips create package incident {incident_id}"),
        {"adr_home": _v_adr_home, "incident_id": _v_int},
        "Create an IPS package for an incident",
        timeout=600,
    ),
    "adrci_ips_generate": CommandSpec(
        _adrci("ips generate package {package_id} in {dest}"),
        {"adr_home": _v_adr_home, "package_id": _v_int, "dest": _v_path},
        "Generate (zip) an IPS package into a directory",
        timeout=1800,
    ),
    "list_dir": CommandSpec(
        ("ls", "-la", "--time-style=+%Y-%m-%dT%H:%M:%S", "{path}"),
        {"path": _v_path},
        "List a directory under an allowed root",
    ),
    "stat_file": CommandSpec(
        ("stat", "-c", "%s %Y %F", "{path}"), {"path": _v_path}, "Size, mtime and type of a file"
    ),
    "read_range": CommandSpec(
        ("tail", "-c", "+{offset}", "{path}", "|", "head", "-c", "{length}"),
        {"path": _v_path, "offset": _v_int, "length": _v_int},
        "Read a byte range of a file",
    ),
    "grep_file": CommandSpec(
        ("grep", "-nF", "-C", "{context}", "-m", "{max_lines}", "--", "{pattern}", "{path}"),
        {"path": _v_path, "pattern": _v_text, "context": _v_int, "max_lines": _v_int},
        "Fixed-string grep with context, capped",
        timeout=120,
    ),
    "sha256": CommandSpec(
        ("sha256sum", "{path}"), {"path": _v_path}, "Checksum of a file", timeout=300
    ),
    "cat_file": CommandSpec(
        ("cat", "{path}"),
        {"path": _v_path},
        "Stream a whole file (to the artifact store)",
        timeout=600,
        max_bytes=512 * 1024 * 1024,
    ),
    "opatch_lspatches": CommandSpec(
        ("{oracle_home}/OPatch/opatch", "lspatches"),
        {"oracle_home": _v_path},
        "Installed interim patches",
        timeout=300,
    ),
    "tfactl_status": CommandSpec(("tfactl", "status"), description="AHF/TFA status", timeout=120),
    "tfactl_diagcollect": CommandSpec(
        ("tfactl", "diagcollect", "-from", "{from_ts}", "-to", "{to_ts}", "-noprompt", "-silent"),
        {"from_ts": _v_text, "to_ts": _v_text},
        "AHF diagnostic collection for a window",
        timeout=3600,
    ),
    "tfactl_analyze": CommandSpec(
        ("tfactl", "analyze", "-from", "{from_ts}", "-to", "{to_ts}"),
        {"from_ts": _v_text, "to_ts": _v_text},
        "AHF alert/trace analysis for a window",
        timeout=1800,
    ),
    "oswatcher_list": CommandSpec(
        ("ls", "-1", "{path}"), {"path": _v_path}, "List OSWatcher archive files", timeout=60
    ),
}

_PIPE_TOKENS = {"|"}


def build_command(
    name: str, params: dict[str, Any], *, allowed_roots: Sequence[str] = ()
) -> list[str]:
    """Return the argv for an allowlisted command with validated parameters.

    ``"|"`` elements are shell pipes (kept unquoted by :func:`remote_shell_line`).
    """
    spec = ALLOWLIST.get(name)
    if spec is None:
        raise AllowlistError(f"unknown command {name!r}")
    unexpected = set(params) - set(spec.params)
    if unexpected:
        raise AllowlistError(f"unexpected parameter(s) {sorted(unexpected)} for {name!r}")
    values: dict[str, str] = {}
    for pname, validator in spec.params.items():
        if pname not in params:
            raise AllowlistError(f"missing parameter {pname!r} for {name!r}")
        values[pname] = validator(pname, params[pname], allowed_roots)
    return [arg if arg in _PIPE_TOKENS else _render(arg, values) for arg in spec.argv]


def _render(template: str, values: dict[str, str]) -> str:
    out: list[str] = []
    for literal, fname, _spec, _conv in string.Formatter().parse(template):
        out.append(literal)
        if fname:
            out.append(values[fname])
    return "".join(out)


def remote_shell_line(argv: Sequence[str]) -> str:
    """Quote argv for the remote login shell; pipe tokens stay bare."""
    return " ".join("|" if a in _PIPE_TOKENS else shlex.quote(a) for a in argv)
