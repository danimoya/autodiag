"""Interval-based, instance-scoped performance evidence without ASH/AWR."""

import time
from typing import Any

from autodiag.diagnose.collect import Collector
from autodiag.diagnose.models import Severity


def counter_deltas(before: list[dict], after: list[dict], elapsed: float) -> tuple:
    """Reject restarts, counter resets and incomplete pairs instead of inventing rates."""
    if elapsed <= 0:
        raise ValueError("sample interval must be positive")
    keys = ("INST_ID", "STARTUP_TIME", "CATEGORY", "METRIC")
    old = {tuple(row[k] for k in keys): float(row["VALUE"]) for row in before}
    startups = {row["INST_ID"]: row["STARTUP_TIME"] for row in before}
    deltas, omitted = [], {"new": 0, "reset": 0, "restart": 0}
    for row in after:
        key = tuple(row[k] for k in keys)
        previous = old.get(key)
        value = float(row["VALUE"])
        if row["INST_ID"] in startups and startups[row["INST_ID"]] != row["STARTUP_TIME"]:
            omitted["restart"] += 1
            continue
        if previous is None:
            omitted["new"] += 1
            continue
        if value < previous:
            omitted["reset"] += 1
            continue
        delta = value - previous
        if delta == 0:
            continue
        rate = delta / elapsed
        if row["CATEGORY"] in {"time_us", "wait_us"}:
            rate /= 1e6
        deltas.append({**row, "DELTA": delta, "PER_SECOND": rate})
    return deltas, omitted


def collect_performance(
    ctx: Any, target, *, case_id: str, instance_id: int = 0, sample_seconds: float = 5.0
):
    if target.component != "rdbms":
        raise ValueError("performance diagnosis requires a database target")
    if not 1 <= sample_seconds <= 60 or instance_id < 0:
        raise ValueError("sample_seconds must be 1..60 and instance_id must be >= 0")
    c = Collector(ctx, target, case_id=case_id)
    d = c.new_dossier("performance", {"instance_id": instance_id, "sample_seconds": sample_seconds})
    runner = c.runner()
    if runner is None:
        d.errors.append("Performance collection requires configured read-only SQL*Net access")
        return d
    params = {"instance_id": instance_id}
    try:
        first = runner.run_named("performance_counters", params, max_rows=10000)
        started = time.monotonic()
        time.sleep(sample_seconds)
        second = runner.run_named("performance_counters", params, max_rows=10000)
        elapsed = time.monotonic() - started
        if first.truncated or second.truncated:
            raise ValueError("counter snapshot truncated; select one --instance-id")
        if not first.rows or not second.rows:
            raise ValueError("no counters returned; verify instance ID and CDB-root access")
        deltas, omitted = counter_deltas(first.as_dicts(), second.as_dicts(), elapsed)
        d.stats.update(
            elapsed_seconds=elapsed,
            omitted_counters=sum(omitted.values()),
            new_counters=omitted["new"],
            reset_counters=omitted["reset"],
            restart_counters=omitted["restart"],
        )
        if omitted["reset"] or omitted["restart"]:
            d.errors.append(
                f"Counter interval invalidated: {omitted['reset']} reset, "
                f"{omitted['restart']} affected by instance restart"
            )
        for inst in sorted({r["INST_ID"] for r in second.as_dicts()}):
            rows = [r for r in deltas if r["INST_ID"] == inst]
            for category in ("time_us", "wait_us", "stat_count", "wait_count"):
                selected = sorted(
                    [r for r in rows if r["CATEGORY"] == category], key=lambda r: -r["PER_SECOND"]
                )
                lines = [f"Measured interval: {elapsed:.3f} seconds; instance_id={inst}."]
                for row in selected[:10]:
                    unit = "count/s"
                    if category in {"time_us", "wait_us"}:
                        unit = "seconds/s"
                    elif row["METRIC"].endswith("bytes") or row["METRIC"] == "redo size":
                        unit = "bytes/s"
                    lines.append(
                        f"{row['METRIC']} | delta={row['DELTA']:.3f} | "
                        f"{row['PER_SECOND']:.3f} {unit}"
                    )
                if not selected:
                    lines.append("No positive valid deltas; this does not establish health.")
                if len(selected) > 10:
                    lines.append(f"Top 10 of {len(selected)} changing counters shown.")
                c.add(
                    d,
                    kind="performance_interval",
                    severity=Severity.INFO,
                    title=f"Instance {inst}: sampled {category}",
                    text="\n".join(lines),
                    node=str(inst),
                    refs={"instance_id": inst, "elapsed_seconds": elapsed},
                )
    except Exception as exc:  # continue gathering independent evidence
        d.errors.append(f"performance counters: {str(exc)[:200]}")
    c.query_into(
        d,
        "performance_sessions",
        params,
        title="Active sessions and blockers now",
        max_rows=30,
        note="Point-in-time sample; waiting sessions are not proof of cause.",
    )
    c.query_into(
        d,
        "performance_sql",
        params,
        title="Top SQL by cursor-lifetime elapsed time",
        max_rows=15,
        note="Cumulative since cursor load, NOT the measured interval. "
        "Do not attribute a current slowdown from these totals alone.",
    )
    return d
