"""Deterministic collectors. Each builds a Dossier for one diagnosis mode: every item is
recorded as evidence in the case store first, so its id can be cited as proof later."""

from __future__ import annotations

import math
import re
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from autodiag.adr.source import AdrSourceError, IncidentRow, ProblemRow
from autodiag.alertlog.models import AlertRecord
from autodiag.alertlog.stats import alert_stats
from autodiag.alertlog.text import parse_alert_text
from autodiag.alertlog.window import window
from autodiag.core.models import Node, Platform, Target, TargetKind
from autodiag.diagnose.models import Dossier, DossierItem, Severity
from autodiag.diagnose.rules import KeptRecord, SweepResult, sweep
from autodiag.diff.alertrate import compare_alert_rates
from autodiag.diff.callstack import compare_stacks, frame_frequency, stack_from_incident
from autodiag.kb.lookup import kb_lookup
from autodiag.trace.incident import IncidentTrace
from autodiag.trace.registry import parse_trace

_CRITICAL_CODES = {600, 7445, 4031, 4030, 4036, 1578, 29740, 494, 257, 20}
_WARNING_CODES = {700, 60, 1555}
_KEY_CODE = re.compile(r"^ORA (\d+)")
ALERT_FETCH_MAX = 64 * 1024 * 1024


def problem_severity(problem_key: str) -> Severity:
    m = _KEY_CODE.match(problem_key or "")
    code = int(m.group(1)) if m else -1
    if code in _CRITICAL_CODES:
        return Severity.CRITICAL
    if code in _WARNING_CODES:
        return Severity.WARNING
    return Severity.WARNING


def _label(node: Node) -> str:
    return node.instance or node.host


def _json_safe(obj: Any) -> Any:
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, dict):
        return {k: _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, list | tuple):
        return [_json_safe(v) for v in obj]
    return obj


def _cell(v: Any) -> str:
    s = "" if v is None else str(v)
    return s if len(s) <= 48 else s[:45] + "..."


def rows_text(columns: list[str], rows: list[list[Any]], *, max_rows: int = 10) -> str:
    lines = [" | ".join(columns)]
    for r in rows[:max_rows]:
        lines.append(" | ".join(_cell(v) for v in r))
    if len(rows) > max_rows:
        lines.append(f"... {len(rows) - max_rows} more rows")
    if not rows:
        lines.append("(no rows)")
    return "\n".join(lines)


class Collector:
    """Shared plumbing for the three modes: evidence recording, alert logs, ADR, SQL."""

    def __init__(self, ctx: Any, target: Target, *, case_id: str) -> None:
        self.ctx = ctx
        self.t = target
        self.case_id = case_id
        self.st = ctx.store
        self.src = ctx.source(target)
        self.now = datetime.now(UTC).replace(microsecond=0)
        self._alert_cache: dict[str, list[AlertRecord]] = {}
        self._runner: Any = None
        self._runner_tried = False

    # -- dossier -----------------------------------------------------------------------
    def new_dossier(self, mode: str, scope: dict[str, Any]) -> Dossier:
        return Dossier(
            mode=mode,
            target=self.t.name,
            target_kind=self.t.kind.value,
            platform=self.t.platform.value,
            oracle_version=self.t.oracle_version,
            scope=scope,
            generated_at=self.now,
            nodes=[f"{_label(n)}@{n.host}" for n in self.t.nodes],
            case_id=self.case_id,
        )

    def add(
        self,
        d: Dossier,
        *,
        kind: str,
        severity: Severity,
        title: str,
        text: str,
        category: str = "",
        ts: datetime | None = None,
        node: str | None = None,
        refs: dict[str, Any] | None = None,
        count: int = 1,
        artifact_id: str | None = None,
        line_from: int | None = None,
    ) -> DossierItem:
        refs = _json_safe(refs or {})
        ev = self.st.record_evidence(
            f"diagnose.{kind}",
            refs,
            title[:200],
            case_id=self.case_id,
            artifact_id=artifact_id,
            line_from=line_from,
        )
        item = DossierItem(
            id=ev.id,
            kind=kind,
            severity_hint=severity,
            category=category,
            ts=ts,
            node=node,
            title=title[:200],
            text=text.strip()[:4000],
            refs=refs,
            count=count,
        )
        d.items.append(item)
        return item

    # -- SQL*Net -----------------------------------------------------------------------
    def runner(self) -> Any:
        if not self._runner_tried:
            self._runner_tried = True
            try:
                self._runner = self.ctx.runner(self.t)
            except Exception:  # noqa: BLE001 - no runner is a normal state
                self._runner = None
        return self._runner

    def query_into(
        self,
        d: Dossier,
        name: str,
        params: dict[str, Any] | None = None,
        *,
        title: str,
        severity: Severity | None = None,
        judge: Any = None,
        max_rows: int = 10,
        note: str = "",
        node: str | None = None,
    ) -> list[dict[str, Any]] | None:
        runner = self.runner()
        if runner is None:
            return None
        try:
            res = runner.run_named(name, params or {}, max_rows=max(max_rows, 50))
        except Exception as exc:  # noqa: BLE001 - one failed query must not stop the sweep
            d.errors.append(f"query {name}: {str(exc)[:200]}")
            return None
        rows = res.as_dicts()
        sev, verdict = severity or Severity.INFO, ""
        if judge is not None:
            sev, verdict = judge(rows)
        text = rows_text(res.columns, res.rows, max_rows=max_rows)
        if verdict:
            text = verdict + "\n" + text
        if note:
            text += "\n" + note
        self.add(
            d,
            kind="query",
            severity=sev,
            category="live",
            title=title,
            text=text,
            ts=self.now,
            node=node,
            refs={"query": name, "params": params or {}, "rows": len(res.rows)},
        )
        return rows

    # -- alert log ---------------------------------------------------------------------
    def alert_records(self, node: Node, home: str) -> list[AlertRecord]:
        key = node.ssh_target + ":" + home
        if key not in self._alert_cache:
            dest = self.ctx.cache_dir(self.t) / f"alert_{node.instance or 'db'}.log"
            self.src.fetch_file(
                node, self.src.alert_log_path(node, home), dest, max_bytes=ALERT_FETCH_MAX
            )
            self._alert_cache[key] = parse_alert_text(dest.read_text(errors="replace"))
        return self._alert_cache[key]

    def sweep_into(
        self,
        d: Dossier,
        records: list[AlertRecord],
        *,
        previous: list[AlertRecord] | None,
        node: str | None,
        max_items: int = 40,
        label: str = "",
    ) -> SweepResult:
        res = sweep(records, previous=previous, node=node)
        kept = sorted(
            res.kept,
            key=lambda k: (
                {Severity.CRITICAL: 0, Severity.WARNING: 1}.get(k.cls.severity, 2),
                -(k.record.ts.timestamp() if k.record.ts else 0),
            ),
        )
        shown = 0
        info_lines: list[str] = []
        for k in kept:
            r = k.record
            if k.cls.severity is Severity.INFO:
                info_lines.append(
                    f"{r.ts:%m-%d %H:%M:%S} "
                    if r.ts
                    else ""
                    + f"{(r.lines[0] if r.lines else '')[:150]}"
                    + (f" (x{k.duplicates + 1})" if k.duplicates else "")
                )
                continue
            if shown >= max_items:
                info_lines.append(
                    f"[not shown, {k.cls.severity.value}] {(r.lines[0] if r.lines else '')[:150]}"
                )
                continue
            shown += 1
            text = "\n".join(r.lines[:12])
            if len(r.lines) > 12:
                text += f"\n... {len(r.lines) - 12} more lines"
            self.add(
                d,
                kind="alert",
                severity=k.cls.severity,
                category=k.cls.category,
                title=(r.lines[0] if r.lines else "alert entry")[:160],
                text=text,
                ts=r.ts,
                node=node,
                refs={
                    "source_line": r.source_line,
                    "incident_id": r.incident_id,
                    "problem_key": r.problem_key,
                    "trace_file": r.trace_file,
                    "signature": r.signature,
                    "ora_codes": r.ora_codes,
                    "con_name": r.con_name,
                },
                count=k.duplicates + 1,
                line_from=r.source_line,
            )
        if info_lines:
            self.add(
                d,
                kind="alert_group",
                severity=Severity.INFO,
                category="info",
                title=f"Informational alert-log entries{label} ({len(info_lines)} signatures)",
                text="\n".join(info_lines[:25])
                + (f"\n... {len(info_lines) - 25} more" if len(info_lines) > 25 else ""),
                ts=records[-1].ts if records else None,
                node=node,
                count=len(info_lines),
            )
        for b in res.bursts[:8]:
            self.add(
                d,
                kind="alert_burst",
                severity=b.severity,
                category="burst",
                title=f"Burst: {b.count} entries of one message{label} "
                f"(previous window {b.previous_count})",
                text=f"{b.example}\ncount {b.count} vs {b.previous_count} "
                f"in the previous window (x{b.ratio})"
                + (
                    f"\nfirst {b.first_ts:%Y-%m-%d %H:%M:%S} last {b.last_ts:%Y-%m-%d %H:%M:%S}"
                    if b.first_ts and b.last_ts
                    else ""
                ),
                ts=b.last_ts,
                node=node,
                refs={"signature": b.signature, "count": b.count, "previous": b.previous_count},
                count=b.count,
            )
        d.noise.extend(res.noise)
        st = d.stats
        st["records_seen"] = st.get("records_seen", 0) + res.records_seen
        st["records_kept"] = st.get("records_kept", 0) + res.records_kept
        st["suppressed"] = st.get("suppressed", 0) + res.suppressed
        return res

    def alert_window_into(
        self,
        d: Dossier,
        node: Node,
        home: str,
        *,
        since: datetime,
        until: datetime,
        label: str = "",
        with_context: bool = True,
    ) -> list[KeptRecord]:
        recs = self.alert_records(node, home)
        cur = window(recs, since, until)
        prev = window(recs, since - (until - since), since)
        res = self.sweep_into(d, cur, previous=prev, node=_label(node), label=label)
        if with_context:
            lc = alert_stats(cur, top=5).lifecycle_events
            if lc:
                self.add(
                    d,
                    kind="lifecycle",
                    severity=Severity.INFO,
                    category="lifecycle",
                    title=f"Instance lifecycle and configuration events{label} ({len(lc)})",
                    text="\n".join(
                        f"{e.ts:%Y-%m-%d %H:%M:%S} {e.text[:150]}" if e.ts else e.text[:150]
                        for e in lc[-12:]
                    ),
                    ts=lc[-1].ts,
                    node=_label(node),
                )
            if prev:
                hours = max((until - since).total_seconds() / 3600, 1 / 60)
                rd = compare_alert_rates(prev, cur, hours_a=hours, hours_b=hours)
                self.add(
                    d,
                    kind="alert_rate",
                    severity=Severity.INFO,
                    category="rate",
                    title=f"Message-rate change vs the previous {hours:.0f}h{label}",
                    text="\n".join(rd.summary_lines(top=6)),
                    ts=until,
                    node=_label(node),
                )
        return res.kept

    def correlate(self, d: Dossier, kept_by_node: dict[str, list[KeptRecord]]) -> None:
        """RAC: the same non-info message on several nodes close in time, or on one only."""
        if len(kept_by_node) < 2:
            return
        by_sig: dict[str, dict[str, list[datetime]]] = defaultdict(lambda: defaultdict(list))
        example: dict[str, str] = {}
        for node, kept in kept_by_node.items():
            for k in kept:
                if k.cls.severity is Severity.INFO or not k.record.ts:
                    continue
                sig = k.record.signature or k.record.lines[0][:120]
                by_sig[sig][node].append(k.record.ts)
                example.setdefault(sig, k.record.lines[0][:150] if k.record.lines else sig)
        made = 0
        for sig, nodes in by_sig.items():
            if made >= 10:
                break
            if len(nodes) >= 2:
                stamps = [(n, t) for n, ts in nodes.items() for t in ts]
                gap = min(
                    abs((a[1] - b[1]).total_seconds())
                    for a in stamps
                    for b in stamps
                    if a[0] != b[0]
                )
                simultaneous = gap <= 120
                self.add(
                    d,
                    kind="correlation",
                    severity=Severity.WARNING if simultaneous else Severity.INFO,
                    category="rac",
                    title=(
                        f"Same message on {len(nodes)} nodes within {gap:.0f}s"
                        if simultaneous
                        else f"Same message on {len(nodes)} nodes, {gap / 60:.0f} min apart"
                    ),
                    text=example[sig]
                    + "\n"
                    + "\n".join(
                        f"{n}: {len(ts)}x, first {min(ts):%Y-%m-%d %H:%M:%S}"
                        for n, ts in nodes.items()
                    ),
                    ts=max(t for ts in nodes.values() for t in ts),
                    refs={"signature": sig, "nodes": list(nodes)},
                )
                made += 1
            else:
                ((node, ts),) = nodes.items()
                if len(ts) >= 3:
                    self.add(
                        d,
                        kind="correlation",
                        severity=Severity.INFO,
                        category="rac",
                        title=f"Only on {node}: {len(ts)}x {example[sig][:80]}",
                        text=example[sig]
                        + f"\nseen {len(ts)} times on {node} only; other nodes: none",
                        ts=max(ts),
                        node=node,
                        refs={"signature": sig, "nodes": [node]},
                    )
                    made += 1

    # -- ADR -----------------------------------------------------------------------------
    def problems_into(self, d: Dossier, *, days: int, max_items: int = 20) -> list[ProblemRow]:
        try:
            rows = self.src.list_problems(days=days)
        except AdrSourceError as exc:
            d.errors.append(f"adrci problems: {exc}")
            return []
        self.st.upsert_problems(self.t.name, rows)
        by_key: dict[str, list[ProblemRow]] = defaultdict(list)
        for p in rows:
            by_key[p.problem_key].append(p)
        for key, group in list(by_key.items())[:max_items]:
            nodes = sorted({p.instance or p.node for p in group})
            last = max((p.lastinc_time for p in group if p.lastinc_time), default=None)
            text = "\n".join(
                f"problem {p.problem_id} on {p.instance or p.node}: "
                f"last incident {p.last_incident or '-'}"
                + (f" at {p.lastinc_time:%Y-%m-%d %H:%M:%S}" if p.lastinc_time else "")
                for p in group
            )
            if len(nodes) > 1:
                text += f"\nsame problem key on {len(nodes)} instances: {', '.join(nodes)}"
            self.add(
                d,
                kind="problem",
                severity=problem_severity(key),
                category="adr",
                title=f"ADR problem {key}"
                + (f" on {len(nodes)} instances" if len(nodes) > 1 else ""),
                text=text,
                ts=last,
                node=nodes[0] if len(nodes) == 1 else None,
                refs={
                    "problem_key": key,
                    "problem_ids": [p.problem_id for p in group],
                    "days": days,
                },
                count=len(group),
            )
        return rows

    def incident_into(
        self, d: Dossier, inc: IncidentRow
    ) -> tuple[DossierItem | None, IncidentTrace | None]:
        detail = self.src.get_incident(inc.incident_id) if not inc.trace_file else inc
        if detail is None or not detail.trace_file:
            d.errors.append(f"incident {inc.incident_id}: no trace file known")
            return None, None
        node = next((n for n in self.t.nodes if n.instance == detail.instance), self.t.nodes[0])
        dest = self.ctx.cache_dir(self.t) / Path(detail.trace_file).name
        try:
            self.src.fetch_file(node, detail.trace_file, dest)
        except AdrSourceError as exc:
            d.errors.append(f"incident {inc.incident_id}: {exc}")
            return None, None
        art = self.st.add_artifact(
            self.case_id,
            kind="incident_trace",
            path=dest,
            origin={
                "source": "ssh",
                "node": node.host,
                "remote": detail.trace_file,
                "incident_id": inc.incident_id,
            },
        )
        doc = parse_trace(dest.read_text(errors="replace"))
        lines = (
            list(doc.summary_lines())
            if hasattr(doc, "summary_lines")
            else [f"{doc.kind.value} trace"]
        )
        if isinstance(doc, IncidentTrace):
            if doc.current_sql:
                lines.append(f"current SQL text: {doc.current_sql[:300]}")
            frames = [
                f"{c.func} [{c.component}]" + (" <-- signaling" if c.signaling else "")
                for c in doc.context_frames[:12]
            ]
            if frames:
                lines.append("call stack, innermost first: " + " <- ".join(frames))
            if doc.header.module:
                lines.append(f"module: {doc.header.module}")
        lines.append(f"trace file: {detail.trace_file} ({doc.line_count} lines)")
        item = self.add(
            d,
            kind="incident",
            severity=problem_severity(detail.problem_key),
            category="adr",
            title=f"Incident {inc.incident_id} {detail.problem_key}",
            text="\n".join(lines),
            ts=detail.create_time,
            node=_label(node),
            refs={
                "incident_id": inc.incident_id,
                "problem_key": detail.problem_key,
                "trace_file": detail.trace_file,
                "artifact_id": art.id,
                "flood_controlled": detail.flood_controlled,
            },
            artifact_id=art.id,
        )
        return item, (doc if isinstance(doc, IncidentTrace) else None)

    def kb_into(
        self,
        d: Dossier,
        *,
        problem_key: str | None = None,
        frames: list[str] | None = None,
        signatures: list[str] | None = None,
        max_hits: int = 4,
    ) -> None:
        hits = []
        if problem_key or frames:
            hits += kb_lookup(
                problem_key=problem_key, frames=frames, platform=self.t.platform.value
            )
        for sig in signatures or []:
            hits += [h for h in kb_lookup(alert_signature=sig) if h.kind == "alert"]
        seen: set[str] = set()
        for h in hits:
            if h.kind in {"component", "exadata_check"} or h.ref in seen or len(seen) >= max_hits:
                continue
            seen.add(h.ref)
            parts = [h.meaning] if h.meaning else []
            if h.typical_causes:
                parts.append("typical causes: " + "; ".join(h.typical_causes))
            if h.checks:
                parts.append("checks: " + "; ".join(h.checks))
            if h.actions:
                parts.append("actions: " + "; ".join(h.actions))
            if h.mos_search:
                parts.append(f"My Oracle Support search: {h.mos_search}")
            self.add(
                d,
                kind="kb",
                severity=Severity.INFO,
                category="kb",
                title=f"Knowledge base: {h.title}",
                text="\n".join(parts),
                refs={"kb_kind": h.kind, "ref": h.ref, "kb_severity": h.severity},
            )

    def env_into(self, d: Dossier) -> None:
        runner = self.runner()
        if runner is None:
            return
        parts: list[str] = []
        try:
            info = runner.run_named("db_info", {}, max_rows=5).as_dicts()
            if info:
                parts.append(", ".join(f"{k.lower()}={v}" for k, v in info[0].items()))
        except Exception as exc:  # noqa: BLE001
            d.errors.append(f"query db_info: {str(exc)[:200]}")
        try:
            res = runner.run_named("sqlpatch_registry", {}, max_rows=5)
            if res.rows:
                parts.append("latest SQL patches:\n" + rows_text(res.columns, res.rows, max_rows=5))
        except Exception as exc:  # noqa: BLE001
            d.errors.append(f"query sqlpatch_registry: {str(exc)[:200]}")
        if parts:
            self.add(
                d,
                kind="env",
                severity=Severity.INFO,
                category="env",
                title="Database identity, version and patch level",
                text="\n".join(parts),
                ts=self.now,
            )


# ------------------------------------------------------------------------------ modes


def _ash_params(center: datetime, minutes: int) -> dict[str, str]:
    f, t = center - timedelta(minutes=minutes), center + timedelta(minutes=minutes)
    return {
        "from_ts": f.strftime("%Y-%m-%d %H:%M:%S"),
        "to_ts": t.strftime("%Y-%m-%d %H:%M:%S"),
        "top": 10,
    }


def collect_problem(
    ctx: Any,
    target: Target,
    *,
    case_id: str,
    problem_key: str | None = None,
    incident_id: int | None = None,
    max_incidents: int = 5,
    window_minutes: int = 30,
) -> Dossier:
    c = Collector(ctx, target, case_id=case_id)
    src = c.src
    if incident_id is not None and problem_key is None:
        inc = src.get_incident(incident_id)
        if inc is None:
            raise AdrSourceError(f"incident {incident_id} not found on {target.name}")
        problem_key = inc.problem_key
    if not problem_key:
        raise AdrSourceError("problem_key or incident_id is required")
    d = c.new_dossier("problem", {"problem_key": problem_key, "incident_id": incident_id})
    incs = src.list_incidents(problem_key=problem_key)
    c.st.upsert_incidents(target.name, incs)
    stamped = [i.create_time for i in incs if i.create_time]
    first, last = (min(stamped), max(stamped)) if stamped else (None, None)
    nodes = sorted({i.instance or i.node for i in incs})
    c.add(
        d,
        kind="problem",
        severity=problem_severity(problem_key),
        category="adr",
        title=f"{problem_key}: {len(incs)} incident(s)"
        + (f" on {len(nodes)} instances" if len(nodes) > 1 else ""),
        text=(
            f"incidents: {', '.join(str(i.incident_id) for i in incs[:20])}"
            + (
                f"\nfirst {first:%Y-%m-%d %H:%M:%S}, last {last:%Y-%m-%d %H:%M:%S}"
                if first and last
                else ""
            )
            + (f"\ninstances: {', '.join(nodes)}" if nodes else "")
            + (
                "\nsome incidents are flood-controlled (ADR suppressed repeats)"
                if any(i.flood_controlled for i in incs)
                else ""
            )
        ),
        ts=last,
        refs={"problem_key": problem_key, "incident_ids": [i.incident_id for i in incs[:50]]},
        count=len(incs),
    )
    chosen = incs[:max_incidents]
    if len(incs) > max_incidents:
        chosen = [*incs[: max_incidents - 1], incs[-1]]  # newest ones plus the oldest
    if incident_id is not None and incident_id not in {i.incident_id for i in chosen}:
        chosen = [i for i in incs if i.incident_id == incident_id] + chosen[:-1]
    docs: list[tuple[IncidentRow, IncidentTrace]] = []
    for inc in chosen:
        _, doc = c.incident_into(d, inc)
        if doc is not None:
            docs.append((inc, doc))
    frames: list[str] = []
    if docs:
        frames = stack_from_incident(docs[0][1]).frames
    if len(docs) >= 2:
        stacks = [stack_from_incident(doc).frames for _, doc in docs]
        freq = frame_frequency(stacks)
        sig = [f for f in freq if f.signature]
        c.add(
            d,
            kind="stack_frequency",
            severity=Severity.INFO,
            category="stack",
            title=f"Call-stack consistency across {len(stacks)} incidents: "
            f"{len(sig)} signature frames",
            text=(
                (
                    "identical code path in every incident: "
                    if sig and all(f.share == 1.0 for f in sig)
                    else "shared frames: "
                )
                + ", ".join(f"{f.func} ({f.count}/{len(stacks)})" for f in freq[:15])
            ),
            refs={"incidents": [i.incident_id for i, _ in docs]},
        )
        newest, oldest = docs[0], docs[-1]
        diff = compare_stacks(
            stack_from_incident(newest[1]).frames, stack_from_incident(oldest[1]).frames
        )
        c.add(
            d,
            kind="stack_diff",
            severity=Severity.INFO if diff.similarity >= 0.9 else Severity.WARNING,
            category="stack",
            title=f"Newest vs oldest incident stack: similarity {diff.similarity}",
            text=(
                f"incident {newest[0].incident_id} vs {oldest[0].incident_id}: "
                f"similarity {diff.similarity}, divergence index {diff.divergence_index}, "
                f"first app frame {diff.left_first_app_frame} vs "
                f"{diff.right_first_app_frame}\n"
                + "\n".join(diff.notes[:4])
                + (
                    f"\nonly in newest: {', '.join(diff.unique_left[:8])}"
                    if diff.unique_left
                    else ""
                )
                + (
                    f"\nonly in oldest: {', '.join(diff.unique_right[:8])}"
                    if diff.unique_right
                    else ""
                )
            ),
            refs={"left": newest[0].incident_id, "right": oldest[0].incident_id},
        )
    c.kb_into(d, problem_key=problem_key, frames=frames)
    # alert log around the newest incident, per node that had one
    if last is not None:
        seen_nodes: set[str] = set()
        kept_by_node: dict[str, list[KeptRecord]] = {}
        for inc in incs[:3]:
            node = next((n for n in target.nodes if n.instance == inc.instance), target.nodes[0])
            if node.ssh_target in seen_nodes or not inc.create_time:
                continue
            seen_nodes.add(node.ssh_target)
            home = next((h for n, h in src.refs() if n.ssh_target == node.ssh_target), None)
            if home is None:
                continue
            try:
                kept_by_node[_label(node)] = c.alert_window_into(
                    d,
                    node,
                    home,
                    since=inc.create_time - timedelta(minutes=window_minutes),
                    until=inc.create_time + timedelta(minutes=window_minutes),
                    label=f" around incident {inc.incident_id}",
                    with_context=False,
                )
            except AdrSourceError as exc:
                d.errors.append(f"alert log on {node.host}: {exc}")
        c.correlate(d, kept_by_node)
    # live context
    if c.runner() is not None:
        c.env_into(d)
        if last is not None and target.diagnostics_pack:
            c.query_into(
                d,
                "ash_top_events_window",
                _ash_params(last, 15),
                title="ASH top events ±15 min around the newest incident",
                note="window given in UTC as recorded by ADR; ASH sample_time is in database time",
            )
    d.stats["incidents"] = len(incs)
    d.stats["traces_parsed"] = len(docs)
    return d


def collect_alert(
    ctx: Any,
    target: Target,
    *,
    case_id: str,
    hours: float = 24.0,
    since: datetime | None = None,
    until: datetime | None = None,
) -> Dossier:
    c = Collector(ctx, target, case_id=case_id)
    until = until or c.now
    since = since or until - timedelta(hours=hours)
    d = c.new_dossier("alert", {"since": since.isoformat(), "until": until.isoformat()})
    _alert_sweep(c, d, since=since, until=until)
    days = max(1, math.ceil((until - since).total_seconds() / 86400) + 1)
    c.problems_into(d, days=days, max_items=15)
    return d


def _alert_sweep(c: Collector, d: Dossier, *, since: datetime, until: datetime) -> None:
    kept_by_node: dict[str, list[KeptRecord]] = {}
    try:
        refs = c.src.refs()
    except AdrSourceError as exc:
        d.errors.append(f"adr homes: {exc}")
        refs = []
    for node, home in refs:
        label = f" on {_label(node)}" if len(refs) > 1 else ""
        try:
            kept_by_node[_label(node)] = c.alert_window_into(
                d, node, home, since=since, until=until, label=label
            )
        except AdrSourceError as exc:
            d.errors.append(f"alert log on {node.host}: {exc}")
    c.correlate(d, kept_by_node)
    sigs: list[str] = []
    for kept in kept_by_node.values():
        for k in kept:
            if k.cls.severity is not Severity.INFO and k.record.lines:
                line = k.record.lines[0]
                if line not in sigs:
                    sigs.append(line)
    c.kb_into(d, signatures=sigs[:6], max_hits=5)


def collect_instance(
    ctx: Any,
    target: Target,
    *,
    case_id: str,
    days: int = 7,
    hours: float = 24.0,
    live: bool | None = None,
) -> Dossier:
    c = Collector(ctx, target, case_id=case_id)
    use_live = (target.sqlnet is not None) if live is None else live
    d = c.new_dossier("instance", {"days": days, "hours": hours, "live": use_live})
    c.problems_into(d, days=days)
    _alert_sweep(c, d, since=c.now - timedelta(hours=hours), until=c.now)
    if use_live:
        if c.runner() is None:
            d.errors.append("live checks requested but the target has no SQL*Net configuration")
        else:
            c.env_into(d)
            rac = target.kind is TargetKind.RAC

            def judge_instances(rows: list[dict[str, Any]]) -> tuple[Severity, str]:
                bad = [r for r in rows if str(r.get("STATUS", "")).upper() != "OPEN"]
                return (
                    (Severity.CRITICAL, f"{len(bad)} instance(s) not OPEN")
                    if bad
                    else (Severity.INFO, f"{len(rows)} instance(s) OPEN")
                )

            def judge_pdbs(rows: list[dict[str, Any]]) -> tuple[Severity, str]:
                bad = [
                    r
                    for r in rows
                    if r.get("NAME") != "PDB$SEED"
                    and not str(r.get("OPEN_MODE", "")).upper().startswith("READ")
                ]
                return (
                    (Severity.WARNING, f"{len(bad)} PDB(s) not open")
                    if bad
                    else (Severity.INFO, "all PDBs open")
                )

            def judge_blocking(rows: list[dict[str, Any]]) -> tuple[Severity, str]:
                return (
                    (Severity.WARNING, f"{len(rows)} session(s) blocked right now")
                    if rows
                    else (Severity.INFO, "no blocked sessions right now")
                )

            c.query_into(
                d,
                "rac_instances",
                title="Instances and status (GV$INSTANCE)",
                judge=judge_instances,
            )
            c.query_into(d, "pdbs", title="Pluggable databases and open mode", judge=judge_pdbs)
            c.query_into(
                d,
                "rac_blocking_now" if rac else "blocking_tree_now",
                title="Blocked sessions right now",
                judge=judge_blocking,
            )
            c.query_into(
                d, "system_events_top", {"top": 10}, title="Top wait events since instance start"
            )
            if target.diagnostics_pack:
                c.query_into(
                    d,
                    "ash_top_events_window",
                    _ash_params(c.now - timedelta(minutes=30), 30),
                    title="ASH top events, last 60 minutes",
                    note="window in UTC; ASH sample_time is in database time",
                )
            if rac:
                c.query_into(
                    d,
                    "rac_gc_events",
                    title="Global cache / cluster waits per instance",
                    max_rows=12,
                )
            if target.platform is Platform.EXACC:
                c.query_into(
                    d, "exa_cell_events", title="Exadata cell and smart-scan waits", max_rows=10
                )
    return d


__all__ = ["Collector", "collect_alert", "collect_instance", "collect_problem", "problem_severity"]
