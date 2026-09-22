"""The ``autodiag`` MCP server: deterministic diagnostic tools for an AI agent.

Every tool returns a JSON object with ``evidence_id`` (recorded in the case store so
findings can cite it), ``truncated`` and ``next_offset``; output is capped and, for
targets with ``redact`` on, passed through the model-boundary redaction. Errors are
returned as ``{"error": ...}`` rather than raised, so the agent can react.
"""

from __future__ import annotations

import functools
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from fastmcp import FastMCP

from autodiag.adr.source import AdrSource, AdrSourceError
from autodiag.alertlog.stats import alert_stats
from autodiag.alertlog.text import parse_alert_text
from autodiag.alertlog.window import window
from autodiag.case.store import Case, CaseStore, CaseStoreError
from autodiag.core.models import Node, Target
from autodiag.core.redact import redact_for_llm
from autodiag.core.settings import Settings
from autodiag.core.targets import TargetInventory
from autodiag.diff.alertrate import compare_alert_rates as _compare_alert_rates
from autodiag.diff.callstack import compare_stacks, frame_frequency, stack_from_incident
from autodiag.diff.sqlprofile import compare_profiles
from autodiag.kb.lookup import kb_lookup as _kb_lookup
from autodiag.report.build import build_context
from autodiag.report.env import capture_environment as _capture_environment
from autodiag.report.render import render_report as _render_report
from autodiag.report.timeline import build_timeline
from autodiag.sql.catalog import load_catalog
from autodiag.sql.runner import SqlRunnerError
from autodiag.trace.incident import IncidentTrace
from autodiag.trace.models import TraceKind
from autodiag.trace.registry import parse_trace as _parse_trace
from autodiag.trace.sqltrace import parse_sqltrace
from autodiag.transport.allowlist import AllowlistError
from autodiag.transport.ssh import SshTransport

_TOOL_ERRORS = (
    KeyError,
    AllowlistError,
    AdrSourceError,
    CaseStoreError,
    SqlRunnerError,
    ValueError,
    OSError,
)


class AutoDiagContext:
    """Everything the tools need; factories are injectable for tests."""

    def __init__(
        self,
        settings: Settings,
        inventory: TargetInventory,
        *,
        transport_factory: Callable[[Target], Callable[[Node], Any]],
        runner_factory: Callable[[Target], Any | None],
        store: CaseStore | None = None,
    ) -> None:
        self.settings = settings
        self.inventory = inventory
        self.transport_factory = transport_factory
        self.runner_factory = runner_factory
        self.store = store or CaseStore(
            settings.data_dir / "autodiag.db", artifacts_dir=settings.data_dir / "cases"
        )
        self._sources: dict[str, AdrSource] = {}

    def target(self, name: str) -> Target:
        try:
            return self.inventory.get(name)
        except KeyError:
            raise KeyError(f"unknown target {name!r}; known: {self.inventory.names()}") from None

    def source(self, t: Target) -> AdrSource:
        if t.name not in self._sources:
            self._sources[t.name] = AdrSource(t, transport_factory=self.transport_factory(t))
        return self._sources[t.name]

    def runner(self, t: Target):
        return self.runner_factory(t)

    def cache_dir(self, t: Target) -> Path:
        d = self.settings.data_dir / "cache" / t.name
        d.mkdir(parents=True, exist_ok=True)
        return d

    def scratch_case(self, t: Target) -> Case:
        for c in self.store.list_cases(target=t.name, status="open"):
            if c.title == f"scratch: {t.name}":
                return c
        return self.store.open_case(
            t.name, f"scratch: {t.name}", notes="auto-created for ad-hoc tool calls"
        )

    def target_of_case(self, case_id: str) -> Target:
        return self.target(self.store.get_case(case_id).target)

    def target_of_artifact(self, artifact_id: str) -> Target:
        return self.target_of_case(self.store.get_artifact(artifact_id).case_id)


def default_context(settings: Settings, inventory: TargetInventory) -> AutoDiagContext:
    def transport_factory(t: Target) -> Callable[[Node], Any]:
        return lambda node: SshTransport(
            node,
            t.allowed_roots,
            ssh_config=settings.ssh_config,
            connect_timeout=settings.ssh_connect_timeout,
            default_timeout=settings.ssh_command_timeout,
        )

    def runner_factory(t: Target):
        if t.sqlnet is None:
            return None
        from autodiag.sql.runner import SqlRunner

        return SqlRunner(
            t.sqlnet, timeout=settings.sql_timeout, diagnostics_pack=t.diagnostics_pack
        )

    return AutoDiagContext(
        settings, inventory, transport_factory=transport_factory, runner_factory=runner_factory
    )


def _ts(value: str | datetime | None) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        dt = datetime.fromisoformat(str(value).replace(" ", "T", 1))
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _fmt(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def _redact_obj(obj: Any) -> Any:
    if isinstance(obj, str):
        return redact_for_llm(obj)
    if isinstance(obj, list):
        return [_redact_obj(x) for x in obj]
    if isinstance(obj, dict):
        return {
            k: (
                v
                if k
                in {"path", "trace_file", "owner_trace_file", "evidence_id", "artifact_id", "id"}
                else _redact_obj(v)
            )
            for k, v in obj.items()
        }
    return obj


def build_server(ctx: AutoDiagContext) -> FastMCP:
    mcp = FastMCP(
        "autodiag",
        instructions=(
            "Oracle Database diagnostics over ADR, trace files, alert logs and SQL*Net. "
            "Tools are deterministic; cite the evidence_id of tool results in findings. "
            "Outputs are capped: use offset/max_lines to page."
        ),
    )
    st = ctx.store
    s = ctx.settings
    hard_cap = s.tool_max_lines_hard_cap

    def cap(n: int | None, default: int | None = None) -> int:
        return max(1, min(n or default or s.tool_max_lines, hard_cap))

    def ok(
        payload: dict[str, Any],
        *,
        tool: str,
        params: dict[str, Any],
        summary: str,
        target: Target | None = None,
        case_id: str | None = None,
        artifact_id: str | None = None,
        truncated: bool = False,
        next_offset: int | None = None,
    ) -> dict[str, Any]:
        ev = st.record_evidence(tool, params, summary, case_id=case_id, artifact_id=artifact_id)
        out = {**payload, "evidence_id": ev.id, "truncated": truncated, "next_offset": next_offset}
        if target is not None and target.redact and s.redact_for_llm:
            out = _redact_obj(out)
        return out

    def guarded(fn: Callable[..., dict[str, Any]]) -> Callable[..., dict[str, Any]]:
        @functools.wraps(fn)
        def wrapper(*a: Any, **kw: Any) -> dict[str, Any]:
            try:
                return fn(*a, **kw)
            except _TOOL_ERRORS as exc:
                msg = exc.args[0] if exc.args and isinstance(exc.args[0], str) else str(exc)
                return {"error": msg, "error_type": type(exc).__name__}

        return wrapper

    def fetch_alert(t: Target) -> list:
        src = ctx.source(t)
        node, home = src.primary_ref()
        dest = ctx.cache_dir(t) / f"alert_{node.instance or 'db'}.log"
        src.fetch_file(node, src.alert_log_path(node, home), dest, max_bytes=64 * 1024 * 1024)
        return parse_alert_text(dest.read_text(errors="replace"))

    def artifact_text(artifact_id: str) -> str:
        return Path(st.get_artifact(artifact_id).path).read_text(errors="replace")

    def incident_doc(artifact_id: str) -> IncidentTrace:
        doc = _parse_trace(artifact_text(artifact_id))
        if not isinstance(doc, IncidentTrace):
            raise ValueError(
                f"artifact {artifact_id} is a {doc.kind.value} trace, not an incident trace"
            )
        return doc

    def trace_summary(doc) -> dict[str, Any]:
        out: dict[str, Any] = {
            "kind": doc.kind.value,
            "lines": doc.line_count,
            "version": doc.header.oracle_version,
            "instance": doc.header.instance_name,
            "session": f"{doc.header.session_id}.{doc.header.session_serial}",
            "module": doc.header.module,
            "container": doc.header.container_name or doc.header.container_id,
            "first_ts": _fmt(doc.timestamps[0]) if doc.timestamps else None,
            "sections": [{"kind": x.kind, "line": x.start_line} for x in doc.sections[:30]],
            "ora_lines": doc.ora_lines[:10],
        }
        if hasattr(doc, "summary_lines"):
            out["summary"] = doc.summary_lines()
        if isinstance(doc, IncidentTrace):
            out.update(
                {
                    "incident_id": doc.incident_id,
                    "problem_key": doc.problem_key,
                    "error_line": doc.error_line,
                    "error_args": doc.error_args,
                    "first_app_frame": doc.first_app_frame,
                    "sql_id": doc.sql_id,
                    "current_sql": doc.current_sql,
                    "plsql_top": doc.plsql_stack[0].name if doc.plsql_stack else None,
                    "context_frames": [
                        f"{c.func} [{c.component}]" + (" <-- signaling" if c.signaling else "")
                        for c in doc.context_frames[:25]
                    ],
                }
            )
        elif doc.kind is TraceKind.DEADLOCK:
            out.update(
                {
                    "classification": doc.classification,
                    "cycle": doc.cycle,
                    "sessions": [x.model_dump() for x in doc.sessions],
                    "rows_waited_on": [x.model_dump() for x in doc.rows_waited_on],
                }
            )
        elif doc.kind in (TraceKind.HANG, TraceKind.SYSTEMSTATE):
            out["chains"] = [
                {
                    "number": c.number,
                    "signature": c.signature,
                    "likely_cause": c.likely_cause,
                    "nodes": [
                        n.model_dump(exclude={"short_stack"}) | {"short_stack": n.short_stack[:12]}
                        for n in c.nodes
                    ],
                }
                for c in doc.chains
            ]
            if doc.systemstate:
                out["systemstate"] = {
                    "level": doc.systemstate.level,
                    "processes": len(doc.systemstate.processes),
                    "wait_histogram": doc.systemstate.wait_histogram,
                }
        elif doc.kind is TraceKind.OPTIMIZER:
            out.update(
                {
                    "sql_id": doc.sql_id,
                    "tables": [x.model_dump() for x in doc.table_stats],
                    "access_paths": [x.model_dump() for x in doc.access_paths],
                    "final_cost": doc.final_cost,
                    "join_orders": doc.join_orders,
                    "peeked_binds": doc.peeked_binds,
                }
            )
        elif doc.kind is TraceKind.SQLTRACE:
            out.update(
                {
                    "cursor_count": doc.cursor_count,
                    "totals": doc.totals.model_dump(),
                    "wall_seconds": doc.wall_seconds,
                }
            )
        return out

    def store_fetched(
        t: Target, node: Node, remote: str, case_id: str | None, kind: str
    ) -> tuple[Case, Any]:
        case = st.get_case(case_id) if case_id else ctx.scratch_case(t)
        dest = ctx.cache_dir(t) / Path(remote).name
        ctx.source(t).fetch_file(node, remote, dest)
        art = st.add_artifact(
            case.id,
            kind=kind,
            path=dest,
            origin={"source": "ssh", "node": node.host, "remote": remote},
        )
        return case, art

    # ---------------------------------------------------------------- targets / ADR
    @mcp.tool
    @guarded
    def list_targets() -> dict:
        """List the databases AutoDiag can diagnose (name, kind, platform, version, nodes)."""
        rows = [
            {
                "name": t.name,
                "kind": t.kind.value,
                "platform": t.platform.value,
                "version": t.oracle_version,
                "db_unique_name": t.db_unique_name,
                "nodes": [n.host for n in t.nodes],
                "sqlnet": t.sqlnet is not None,
            }
            for t in ctx.inventory.targets
        ]
        return ok({"targets": rows}, tool="list_targets", params={}, summary=f"{len(rows)} targets")

    @mcp.tool
    @guarded
    def list_problems(
        target: str, since_hours: int = 168, offset: int = 0, limit: int = 50
    ) -> dict:
        """ADR problems (grouped incidents) of a target with an incident in the last since_hours."""
        t = ctx.target(target)
        rows = ctx.source(t).list_problems(days=max(1, (since_hours + 23) // 24))
        st.upsert_problems(t.name, rows)
        page = rows[offset : offset + limit]
        out = [
            {
                "problem_id": p.problem_id,
                "problem_key": p.problem_key,
                "last_incident": p.last_incident,
                "last_time": _fmt(p.lastinc_time),
                "instance": p.instance,
                "node": p.node,
            }
            for p in page
        ]
        return ok(
            {"problems": out, "total": len(rows)},
            tool="list_problems",
            params={"target": target, "since_hours": since_hours},
            summary=f"{len(rows)} problems on {target}; newest: "
            + ", ".join(p.problem_key for p in rows[:3]),
            target=t,
            truncated=offset + limit < len(rows),
            next_offset=offset + limit if offset + limit < len(rows) else None,
        )

    @mcp.tool
    @guarded
    def list_incidents(
        target: str, problem_id: int | None = None, problem_key: str | None = None, limit: int = 50
    ) -> dict:
        """Incidents of one ADR problem (by problem_id, or by problem_key which is resolved first)."""
        t = ctx.target(target)
        rows = ctx.source(t).list_incidents(problem_id=problem_id, problem_key=problem_key)[:limit]
        st.upsert_incidents(t.name, rows)
        out = [
            {
                "incident_id": i.incident_id,
                "problem_key": i.problem_key,
                "problem_id": i.problem_id,
                "create_time": _fmt(i.create_time),
                "error": f"{i.error_facility}-{i.error_number}" if i.error_number else None,
                "error_args": i.error_args,
                "flood_controlled": i.flood_controlled,
                "instance": i.instance,
            }
            for i in rows
        ]
        return ok(
            {"incidents": out},
            tool="list_incidents",
            params={"target": target, "problem_id": problem_id, "problem_key": problem_key},
            summary=f"{len(out)} incidents",
            target=t,
        )

    @mcp.tool
    @guarded
    def get_incident(target: str, incident_id: int, case_id: str | None = None) -> dict:
        """Incident detail from adrci plus the parsed incident trace (fetched into the case as an artifact)."""
        t = ctx.target(target)
        src = ctx.source(t)
        inc = src.get_incident(incident_id)
        if inc is None:
            raise ValueError(f"incident {incident_id} not found on {target}")
        node = next((n for n in t.nodes if n.instance == inc.instance), t.nodes[0])
        payload: dict[str, Any] = {
            "incident": inc.model_dump(mode="json"),
            "artifact_id": None,
            "trace": None,
        }
        summary = f"incident {incident_id} {inc.problem_key}"
        case_ref = case_id
        if inc.trace_file:
            case, art = store_fetched(t, node, inc.trace_file, case_id, "incident_trace")
            case_ref = case.id
            doc = _parse_trace(artifact_text(art.id))
            payload["artifact_id"] = art.id
            payload["case_id"] = case.id
            payload["trace"] = trace_summary(doc)
            if hasattr(doc, "summary_lines"):
                summary = "; ".join(doc.summary_lines())
            if inc.problem_key and inc.problem_key not in case.problem_keys:
                st.update_case(case.id, problem_keys=[*case.problem_keys, inc.problem_key])
        return ok(
            payload,
            tool="get_incident",
            params={"target": target, "incident_id": incident_id},
            summary=summary,
            target=t,
            case_id=case_ref,
            artifact_id=payload["artifact_id"],
        )

    # ---------------------------------------------------------------- alert log
    @mcp.tool
    @guarded
    def alert_log_window(
        target: str,
        from_ts: str,
        to_ts: str,
        offset: int = 0,
        max_lines: int = 200,
        errors_only: bool = False,
    ) -> dict:
        """Alert-log entries between two ISO timestamps (paged). errors_only keeps ORA-/error entries."""
        t = ctx.target(target)
        recs = window(fetch_alert(t), _ts(from_ts), _ts(to_ts))
        if errors_only:
            recs = [r for r in recs if r.is_error]
        lines = [f"{_fmt(r.ts)} {ln}" for r in recs for ln in r.lines]
        n = cap(max_lines)
        page = lines[offset : offset + n]
        more = offset + n < len(lines)
        return ok(
            {
                "lines": page,
                "total_lines": len(lines),
                "records": len(recs),
                "ora_codes": sorted({c for r in recs for c in r.ora_codes}),
            },
            tool="alert_log_window",
            params={"target": target, "from_ts": from_ts, "to_ts": to_ts},
            summary=f"{len(recs)} alert entries {from_ts}..{to_ts}",
            target=t,
            truncated=more,
            next_offset=offset + n if more else None,
        )

    @mcp.tool
    @guarded
    def alert_log_grep(target: str, pattern: str, context: int = 3, max_lines: int = 200) -> dict:
        """Fixed-string grep of the alert log on the node with context lines (line numbers included)."""
        t = ctx.target(target)
        src = ctx.source(t)
        node, home = src.primary_ref()
        text = src.grep_file(
            node, src.alert_log_path(node, home), pattern, context=context, max_lines=cap(max_lines)
        )
        lines = text.splitlines()
        return ok(
            {
                "text": "\n".join(lines[:hard_cap]),
                "matches": sum(1 for ln in lines if ":" in ln and pattern in ln),
            },
            tool="alert_log_grep",
            params={"target": target, "pattern": pattern},
            summary=f"grep {pattern!r}: {len(lines)} lines",
            target=t,
            truncated=len(lines) > hard_cap,
        )

    @mcp.tool
    @guarded
    def alert_log_stats(target: str, hours: float = 24, top: int = 30) -> dict:
        """Alert-log statistics for the last N hours: ORA histogram, top signatures, per-hour counts, lifecycle events."""
        t = ctx.target(target)
        recs = fetch_alert(t)
        since = datetime.now(UTC) - timedelta(hours=hours)
        sel = window(recs, since, None)
        stats = alert_stats(sel, top=top)
        d = stats.model_dump(mode="json")
        d["per_hour"] = {str(k): v for k, v in stats.per_hour.items()}
        return ok(
            {"stats": d},
            tool="alert_log_stats",
            params={"target": target, "hours": hours},
            summary=f"{stats.record_count} entries, {stats.incident_count} incidents, ORA codes {stats.ora_counts}",
            target=t,
        )

    @mcp.tool
    @guarded
    def compare_alert_rates(
        target: str, from_a: str, to_a: str, from_b: str, to_b: str, top: int = 30
    ) -> dict:
        """Compare alert-log message rates between a baseline window (a) and an anomaly window (b)."""
        t = ctx.target(target)
        recs = fetch_alert(t)
        a = window(recs, _ts(from_a), _ts(to_a))
        b = window(recs, _ts(from_b), _ts(to_b))
        ha = max((_ts(to_a) - _ts(from_a)).total_seconds() / 3600, 1 / 60)
        hb = max((_ts(to_b) - _ts(from_b)).total_seconds() / 3600, 1 / 60)
        d = _compare_alert_rates(a, b, hours_a=ha, hours_b=hb, top=top)
        return ok(
            {"diff": d.model_dump(mode="json"), "summary": d.summary_lines()},
            tool="compare_alert_rates",
            params={"target": target, "a": [from_a, to_a], "b": [from_b, to_b]},
            summary="; ".join(d.summary_lines(5)),
            target=t,
        )

    # ---------------------------------------------------------------- traces
    @mcp.tool
    @guarded
    def parse_trace(
        artifact_id: str | None = None,
        target: str | None = None,
        path: str | None = None,
        case_id: str | None = None,
    ) -> dict:
        """Parse a trace file (by artifact_id, or fetch target+path first) and return its structured summary."""
        t: Target | None = None
        if artifact_id is None:
            if not (target and path):
                raise ValueError("give artifact_id, or target and path")
            t = ctx.target(target)
            case, art = store_fetched(t, t.nodes[0], path, case_id, "trace")
            artifact_id = art.id
        else:
            t = ctx.target_of_artifact(artifact_id)
        doc = _parse_trace(artifact_text(artifact_id))
        summ = trace_summary(doc)
        return ok(
            {"artifact_id": artifact_id, "trace": summ},
            tool="parse_trace",
            params={"artifact_id": artifact_id, "path": path},
            summary="; ".join(summ.get("summary", []))
            or f"{doc.kind.value} trace {doc.line_count} lines",
            target=t,
            artifact_id=artifact_id,
            case_id=st.get_artifact(artifact_id).case_id,
        )

    @mcp.tool
    @guarded
    def read_trace_lines(
        artifact_id: str, offset: int = 0, max_lines: int = 200, grep: str | None = None
    ) -> dict:
        """Raw lines of a stored trace/log artifact (paged; optional fixed-string filter)."""
        t = ctx.target_of_artifact(artifact_id)
        lines = artifact_text(artifact_id).splitlines()
        if grep:
            lines = [f"{i + 1}: {ln}" for i, ln in enumerate(lines) if grep in ln]
        n = cap(max_lines)
        page = lines[offset : offset + n]
        more = offset + n < len(lines)
        return ok(
            {"lines": page, "total_lines": len(lines)},
            tool="read_trace_lines",
            params={"artifact_id": artifact_id, "offset": offset, "grep": grep},
            summary=f"lines {offset}-{offset + len(page)} of {len(lines)}",
            target=t,
            artifact_id=artifact_id,
            truncated=more,
            next_offset=offset + n if more else None,
        )

    @mcp.tool
    @guarded
    def get_call_stack(artifact_id: str) -> dict:
        """Normalised kernel call stack of an incident trace (error-handling prelude removed), with components."""
        t = ctx.target_of_artifact(artifact_id)
        doc = incident_doc(artifact_id)
        n = stack_from_incident(doc)
        return ok(
            {
                "frames": n.frames,
                "prelude": n.prelude,
                "tail": n.tail,
                "source": n.source,
                "components": n.components,
                "first_app_frame": n.first_app_frame,
                "problem_key": doc.problem_key,
            },
            tool="get_call_stack",
            params={"artifact_id": artifact_id},
            summary=f"{doc.problem_key}: " + " <- ".join(n.frames[:8]),
            target=t,
            artifact_id=artifact_id,
        )

    @mcp.tool
    @guarded
    def sql_trace_profile(artifact_id: str, top: int = 20) -> dict:
        """tkprof-style profile of a 10046 trace artifact: totals, top cursors by elapsed, top waits."""
        t = ctx.target_of_artifact(artifact_id)
        prof = parse_sqltrace(artifact_text(artifact_id))
        cursors = [
            {
                "sql_id": c.sql_id,
                "dep": c.dep,
                "exec": c.exec.count,
                "fetch": c.fetch.count,
                "elapsed_us": c.elapsed_us,
                "cpu_us": c.total.cpu_us,
                "disk": c.total.disk,
                "query": c.total.query,
                "rows": c.total.rows,
                "plan_hashes": c.plan_hashes,
                "sql": c.sql_text[:300],
            }
            for c in prof.top_cursors(top)
        ]
        waits = [
            {"event": e, "count": w.count, "total_ela_us": w.total_ela_us}
            for e, w in prof.top_waits(10)
        ]
        return ok(
            {
                "profile": {
                    "cursor_count": prof.cursor_count,
                    "totals": prof.totals.model_dump(),
                    "wall_seconds": prof.wall_seconds,
                    "commits": prof.commits,
                    "rollbacks": prof.rollbacks,
                },
                "top_cursors": cursors,
                "top_waits": waits,
            },
            tool="sql_trace_profile",
            params={"artifact_id": artifact_id, "top": top},
            summary=f"{prof.cursor_count} cursors, elapsed {prof.totals.elapsed_us / 1e6:.3f}s, top {cursors[0]['sql_id'] if cursors else '-'}",
            target=t,
            artifact_id=artifact_id,
        )

    @mcp.tool
    @guarded
    def compare_call_stacks(left_artifact: str, right_artifact: str) -> dict:
        """Align the call stacks of two incident traces and report the divergence point and unique frames."""
        t = ctx.target_of_artifact(left_artifact)
        a, b = incident_doc(left_artifact), incident_doc(right_artifact)
        d = compare_stacks(stack_from_incident(a).frames, stack_from_incident(b).frames)
        return ok(
            {
                "diff": d.model_dump(),
                "left_problem_key": a.problem_key,
                "right_problem_key": b.problem_key,
            },
            tool="compare_call_stacks",
            params={"left": left_artifact, "right": right_artifact},
            summary="; ".join(d.notes),
            target=t,
            artifact_id=left_artifact,
        )

    @mcp.tool
    @guarded
    def stack_frequency(artifact_ids: list[str]) -> dict:
        """Share of incident traces containing each frame (signature frames appear in >= 80%)."""
        stacks = [stack_from_incident(incident_doc(a)).frames for a in artifact_ids]
        freq = frame_frequency(stacks)
        return ok(
            {"frames": [f.model_dump() for f in freq], "incidents": len(stacks)},
            tool="stack_frequency",
            params={"artifact_ids": artifact_ids},
            summary="signature frames: " + ", ".join(f.func for f in freq if f.signature)[:300],
        )

    @mcp.tool
    @guarded
    def compare_sql_profiles(left_artifact: str, right_artifact: str, top: int = 15) -> dict:
        """Compare two 10046 traces (normal vs anomaly) per sql_id: elapsed/IO deltas, plan changes, tags, hints."""
        t = ctx.target_of_artifact(left_artifact)
        d = compare_profiles(
            parse_sqltrace(artifact_text(left_artifact)),
            parse_sqltrace(artifact_text(right_artifact)),
            top=top,
        )
        return ok(
            {"diff": d.model_dump()},
            tool="compare_sql_profiles",
            params={"left": left_artifact, "right": right_artifact},
            summary=d.summary + "; " + "; ".join(d.explanation_hints[:2]),
            target=t,
            artifact_id=left_artifact,
        )

    # ---------------------------------------------------------------- knowledge / SQL
    @mcp.tool
    @guarded
    def kb_lookup(
        problem_key: str | None = None,
        frames: list[str] | None = None,
        alert_signature: str | None = None,
        wait_events: list[str] | None = None,
        platform: str | None = None,
    ) -> dict:
        """Knowledge-base guidance for a problem key, stack frames, an alert-log line or wait events."""
        hits = _kb_lookup(
            problem_key=problem_key,
            frames=frames,
            alert_signature=alert_signature,
            wait_events=wait_events,
            platform=platform or "generic",
        )
        return ok(
            {"hits": [h.model_dump() for h in hits]},
            tool="kb_lookup",
            params={"problem_key": problem_key, "frames": frames},
            summary=f"{len(hits)} KB hits" + (f" for {problem_key}" if problem_key else ""),
        )

    @mcp.tool
    @guarded
    def list_queries() -> dict:
        """Catalog of named read-only SQL queries usable with run_query (parameters and scope)."""
        qs = [
            {
                "name": q.name,
                "description": q.description,
                "scope": q.scope,
                "pack": q.pack,
                "params": {
                    k: f"{v.type}" + (f"={v.default}" if v.default is not None else "")
                    for k, v in q.params.items()
                },
            }
            for q in load_catalog().values()
        ]
        return ok({"queries": qs}, tool="list_queries", params={}, summary=f"{len(qs)} queries")

    @mcp.tool
    @guarded
    def run_query(
        target: str,
        name: str,
        params: dict | None = None,
        container: str | None = None,
        max_rows: int = 200,
    ) -> dict:
        """Run a catalog query over SQL*Net as the read-only diagnostic user (bind variables only)."""
        t = ctx.target(target)
        r = ctx.runner(t)
        if r is None:
            raise ValueError(f"target {target} has no SQL*Net configuration")
        res = r.run_named(name, params or {}, max_rows=min(max_rows, 500), container=container)
        rows = [
            [(v.isoformat() if isinstance(v, datetime) else v) for v in row] for row in res.rows
        ]
        return ok(
            {
                "columns": res.columns,
                "rows": rows,
                "elapsed_ms": res.elapsed_ms,
                "container": res.container,
            },
            tool="run_query",
            params={"target": target, "name": name, "params": params, "container": container},
            summary=f"{name}: {len(rows)} rows",
            target=t,
            truncated=res.truncated,
        )

    # ---------------------------------------------------------------- cases
    @mcp.tool
    @guarded
    def open_case(target: str, title: str, problem_keys: list[str] | None = None) -> dict:
        """Open a case for a target; artifacts, evidence, findings and reports attach to it."""
        t = ctx.target(target)
        c = st.open_case(t.name, title, problem_keys=problem_keys or [])
        return ok(
            {"case": c.model_dump(mode="json")},
            tool="open_case",
            params={"target": target, "title": title},
            summary=f"case {c.id} opened",
            case_id=c.id,
        )

    @mcp.tool
    @guarded
    def get_case(case_id: str) -> dict:
        """Case with its artifacts, evidence, findings and reports."""
        c = st.get_case(case_id)
        return ok(
            {
                "case": c.model_dump(mode="json"),
                "artifacts": [a.model_dump(mode="json") for a in st.list_artifacts(c.id)],
                "evidence": [e.model_dump(mode="json") for e in st.list_evidence(c.id)],
                "findings": [f.model_dump(mode="json") for f in st.list_findings(c.id)],
                "reports": [
                    {"id": r.id, "kind": r.kind, "rendered_at": _fmt(r.rendered_at)}
                    for r in st.list_reports(c.id)
                ],
            },
            tool="get_case",
            params={"case_id": case_id},
            summary=f"case {c.id}: {c.title}",
            case_id=c.id,
        )

    @mcp.tool
    @guarded
    def add_artifact_to_case(case_id: str, path: str, kind: str = "trace", label: str = "") -> dict:
        """Register a local file (already on this host) as a case artifact."""
        a = st.add_artifact(
            case_id,
            kind=kind,
            path=Path(path),
            origin={"source": "local", "path": path},
            label=label,
        )
        return ok(
            {"artifact": a.model_dump(mode="json")},
            tool="add_artifact_to_case",
            params={"case_id": case_id, "path": path},
            summary=f"artifact {a.id} ({kind})",
            case_id=case_id,
            artifact_id=a.id,
        )

    @mcp.tool
    @guarded
    def add_finding(
        case_id: str,
        kind: str,
        title: str,
        detail: str,
        confidence: float,
        evidence_ids: list[str],
        kb_refs: list[str] | None = None,
    ) -> dict:
        """Record a finding (root_cause | contributing | observation | action) citing evidence ids."""
        f = st.add_finding(
            case_id,
            kind=kind,
            title=title,
            detail=detail,
            confidence=confidence,
            evidence_ids=evidence_ids,
            kb_refs=kb_refs or [],
            author="agent",
        )
        return ok(
            {"finding": f.model_dump(mode="json")},
            tool="add_finding",
            params={"case_id": case_id, "kind": kind},
            summary=f"finding {f.id}: {title}",
            case_id=case_id,
        )

    @mcp.tool
    @guarded
    def set_baseline(target: str, kind: str, artifact_id: str, label: str = "") -> dict:
        """Mark an artifact as the 'normal' baseline of its kind for a target (for later comparisons)."""
        t = ctx.target(target)
        b = st.set_baseline(t.name, kind=kind, artifact_id=artifact_id, label=label)
        return ok(
            {"baseline": b.model_dump(mode="json")},
            tool="set_baseline",
            params={"target": target, "kind": kind},
            summary=f"baseline {b.id}",
            artifact_id=artifact_id,
        )

    @mcp.tool
    @guarded
    def list_baselines(target: str, kind: str | None = None) -> dict:
        """Baselines stored for a target."""
        t = ctx.target(target)
        rows = st.list_baselines(t.name, kind=kind)
        return ok(
            {"baselines": [b.model_dump(mode="json") for b in rows]},
            tool="list_baselines",
            params={"target": target},
            summary=f"{len(rows)} baselines",
        )

    # ---------------------------------------------------------------- reports / environment / timeline
    @mcp.tool
    @guarded
    def render_report(case_id: str, kind: str = "dba", capture_env: bool = False) -> dict:
        """Render the DBA report or the Service Request draft for a case (stored, returned as Markdown)."""
        c = st.get_case(case_id)
        t = ctx.target(c.target)
        rctx = build_context(
            st,
            case_id,
            target=t,
            transport_factory=ctx.transport_factory(t),
            runner=ctx.runner(t) if capture_env else None,
            capture_env=capture_env,
        )
        md = _render_report(kind, rctx)
        r = st.add_report(case_id, kind=kind, markdown=md)
        return ok(
            {"report_id": r.id, "kind": kind, "markdown": md},
            tool="render_report",
            params={"case_id": case_id, "kind": kind},
            summary=f"report {r.id} ({kind}) rendered",
            target=t,
            case_id=case_id,
        )

    @mcp.tool
    @guarded
    def capture_environment(target: str, case_id: str | None = None) -> dict:
        """Version, patches (opatch / registry), non-default parameters, instances and node facts."""
        t = ctx.target(target)
        env = _capture_environment(
            t, transport_factory=ctx.transport_factory(t), runner=ctx.runner(t)
        )
        return ok(
            {"environment": env},
            tool="capture_environment",
            params={"target": target},
            summary=f"version {env.get('version_full')}, {len(env.get('patches', []))} patches",
            target=t,
            case_id=case_id,
        )

    @mcp.tool
    @guarded
    def timeline(
        case_id: str | None = None,
        target: str | None = None,
        from_ts: str | None = None,
        to_ts: str | None = None,
        max_items: int = 200,
    ) -> dict:
        """Ordered timeline of alert-log errors and incidents for a case (its problem window) or a target window."""
        if case_id:
            c = st.get_case(case_id)
            t = ctx.target(c.target)
            rctx = build_context(st, case_id, target=t)
            incidents = rctx.incidents
            f, to = (_ts(from_ts) if from_ts else None), (_ts(to_ts) if to_ts else None)
            if not f and incidents:
                times = [i["create_time"] for i in incidents if i["create_time"]]
                if times:
                    f, to = min(times) - timedelta(minutes=30), max(times) + timedelta(minutes=30)
        elif target:
            t = ctx.target(target)
            incidents = []
            f, to = _ts(from_ts), _ts(to_ts)
        else:
            raise ValueError("give case_id or target")
        recs = window(fetch_alert(t), f, to) if (f or to) else []
        events = build_timeline(
            alert_records=recs, incidents=incidents, only_errors=True, max_items=cap(max_items, 200)
        )
        return ok(
            {
                "events": [e.model_dump(mode="json") for e in events],
                "from_ts": _fmt(f),
                "to_ts": _fmt(to),
            },
            tool="timeline",
            params={"case_id": case_id, "target": target},
            summary=f"{len(events)} timeline events",
            target=t,
            case_id=case_id,
        )

    # ---------------------------------------------------------------- jobs
    def run_job(job_id: str, fn: Callable[[CaseStore], dict[str, Any]]) -> None:
        def body() -> None:
            local = CaseStore(st.db_path, artifacts_dir=st.artifacts_dir)
            try:
                local.update_job(job_id, status="running")
                result = fn(local)
                local.update_job(job_id, status="done", result=result)
            except Exception as exc:  # noqa: BLE001 - the job record carries the error
                local.update_job(job_id, status="failed", error=f"{type(exc).__name__}: {exc}")
            finally:
                local.close()

        threading.Thread(target=body, name=f"autodiag-{job_id}", daemon=True).start()

    @mcp.tool
    @guarded
    def create_ips_package(
        target: str,
        problem_id: int | None = None,
        incident_id: int | None = None,
        case_id: str | None = None,
    ) -> dict:
        """Create and generate an ADRCI IPS package (zip) for a problem or incident; runs as a job, the zip is fetched into the case."""
        t = ctx.target(target)
        if problem_id is None and incident_id is None:
            raise ValueError("give problem_id or incident_id")
        job = st.create_job(
            "ips",
            {
                "target": target,
                "problem_id": problem_id,
                "incident_id": incident_id,
                "case_id": case_id,
            },
        )

        def work(local: CaseStore) -> dict[str, Any]:
            src = ctx.source(t)
            node, home = src.primary_ref()
            if problem_id is not None:
                out = src._run(
                    node, "adrci_ips_create_problem", {"adr_home": home, "problem_id": problem_id}
                )
            else:
                out = src._run(
                    node,
                    "adrci_ips_create_incident",
                    {"adr_home": home, "incident_id": incident_id},
                )
            import re

            m = re.search(r"Created package (\d+)", out)
            if not m:
                raise RuntimeError(f"ips create did not return a package id: {out[-300:]}")
            pkg = int(m.group(1))
            gen = src._run(
                node,
                "adrci_ips_generate",
                {"adr_home": home, "package_id": pkg, "dest": t.ips_dest},
            )
            zm = re.search(r"Generated package \d+ in file (\S+)", gen)
            if not zm:
                raise RuntimeError(f"ips generate did not return a file: {gen[-300:]}")
            remote_zip = zm.group(1).rstrip(",")
            case = local.get_case(case_id) if case_id else ctx.scratch_case(t)
            dest = ctx.cache_dir(t) / Path(remote_zip).name
            src.fetch_file(node, remote_zip, dest, max_bytes=2 * 1024 * 1024 * 1024)
            art = local.add_artifact(
                case.id,
                kind="ips_package",
                path=dest,
                origin={"source": "ssh", "node": node.host, "remote": remote_zip},
            )
            return {
                "package_id": pkg,
                "remote_zip": remote_zip,
                "artifact_id": art.id,
                "case_id": case.id,
            }

        run_job(job.id, work)
        return ok(
            {"job": job.model_dump(mode="json")},
            tool="create_ips_package",
            params=job.params,
            summary=f"IPS job {job.id} started",
        )

    @mcp.tool
    @guarded
    def collect_ahf(target: str, from_ts: str, to_ts: str, case_id: str | None = None) -> dict:
        """Run AHF 'tfactl diagcollect' for a time window on the target's first node (job); output is kept on the node."""
        t = ctx.target(target)
        job = st.create_job(
            "ahf", {"target": target, "from_ts": from_ts, "to_ts": to_ts, "case_id": case_id}
        )

        def work(local: CaseStore) -> dict[str, Any]:
            src = ctx.source(t)
            node = t.nodes[0]
            res = src.transport_for(node).run(
                "tfactl_diagcollect", {"from_ts": from_ts, "to_ts": to_ts}
            )
            if not res.ok:
                raise RuntimeError(
                    f"tfactl diagcollect failed rc={res.returncode}: {res.stderr[:300] or res.stdout[-300:]}"
                )
            return {"output_tail": res.stdout[-2000:]}

        run_job(job.id, work)
        return ok(
            {"job": job.model_dump(mode="json")},
            tool="collect_ahf",
            params=job.params,
            summary=f"AHF job {job.id} started",
        )

    @mcp.tool
    @guarded
    def job_status(job_id: str) -> dict:
        """Status and result of a background job (IPS packaging, AHF collection)."""
        j = st.get_job(job_id)
        return ok(
            {"job": j.model_dump(mode="json")},
            tool="job_status",
            params={"job_id": job_id},
            summary=f"job {j.id} {j.status}",
        )

    # ---------------------------------------------------------------- fixed playbook
    @mcp.tool
    @guarded
    def standard_triage(target: str, problem_key: str, case_id: str | None = None) -> dict:
        """Deterministic first pass for one problem key: incidents, newest incident trace summary, KB guidance,
        alert-log window around it, stack frequency across recent incidents. Opens a case if none is given."""
        t = ctx.target(target)
        src = ctx.source(t)
        case = (
            st.get_case(case_id)
            if case_id
            else st.open_case(t.name, f"triage: {problem_key}", problem_keys=[problem_key])
        )
        incs = src.list_incidents(problem_key=problem_key)
        st.upsert_incidents(t.name, incs)
        result: dict[str, Any] = {
            "target": target,
            "problem_key": problem_key,
            "case_id": case.id,
            "incidents": [
                {
                    "incident_id": i.incident_id,
                    "create_time": _fmt(i.create_time),
                    "instance": i.instance,
                }
                for i in incs[:20]
            ],
            "newest_incident": None,
            "kb_hits": [],
            "alert_window": None,
            "stack_frequency": None,
            "next_steps": [],
        }
        frames: list[str] = []
        artifacts: list[str] = []
        for i in incs[:5]:
            detail = src.get_incident(i.incident_id)  # the brief listing carries no trace path
            if detail is None or not detail.trace_file:
                continue
            node = next((n for n in t.nodes if n.instance == detail.instance), t.nodes[0])
            _, art = store_fetched(t, node, detail.trace_file, case.id, "incident_trace")
            artifacts.append(art.id)
            if result["newest_incident"] is None:
                doc = _parse_trace(artifact_text(art.id))
                result["newest_incident"] = {
                    "incident_id": i.incident_id,
                    "artifact_id": art.id,
                    "trace": trace_summary(doc),
                }
                if isinstance(doc, IncidentTrace):
                    frames = stack_from_incident(doc).frames
        result["kb_hits"] = [
            h.model_dump()
            for h in _kb_lookup(problem_key=problem_key, frames=frames, platform=t.platform.value)
        ]
        if incs and incs[0].create_time:
            f, to = (
                incs[0].create_time - timedelta(minutes=30),
                incs[0].create_time + timedelta(minutes=30),
            )
            recs = window(fetch_alert(t), f, to)
            errs = [r for r in recs if r.is_error]
            result["alert_window"] = {
                "from_ts": _fmt(f),
                "to_ts": _fmt(to),
                "records": len(recs),
                "errors": [r.lines[0][:200] for r in errs[:40]],
            }
        if len(artifacts) >= 2:
            stacks = []
            for a in artifacts:
                doc = _parse_trace(artifact_text(a))
                if isinstance(doc, IncidentTrace):
                    stacks.append(stack_from_incident(doc).frames)
            if len(stacks) >= 2:
                result["stack_frequency"] = [x.model_dump() for x in frame_frequency(stacks)][:40]
        result["next_steps"] = [
            "review newest_incident.trace.summary and the first application frame",
            "run_query ash_top_events_window / ash_top_sql_window around the incident time (if Diagnostics Pack)",
            "compare_call_stacks against an older incident or a baseline if the key recurs",
            "capture_environment and search My Oracle Support with the problem key and first frame",
            "add_finding with evidence ids, then render_report",
        ]
        return ok(
            result,
            tool="standard_triage",
            params={"target": target, "problem_key": problem_key},
            summary=f"triage {problem_key}: {len(incs)} incidents, {len(result['kb_hits'])} KB hits",
            target=t,
            case_id=case.id,
        )

    return mcp
