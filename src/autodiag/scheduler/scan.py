"""Periodic scan of all targets for new ADR problems (LLM-free)."""

from __future__ import annotations

import threading
import time
from datetime import UTC, datetime

from pydantic import BaseModel, Field

from autodiag.core.models import Target
from autodiag.mcp.server import AutoDiagContext
from autodiag.scheduler.notify import notify


class ScanResult(BaseModel):
    target: str
    started_at: datetime
    finished_at: datetime | None = None
    problem_count: int = 0
    new_problem_ids: list[int] = Field(default_factory=list)
    new_problem_keys: list[str] = Field(default_factory=list)
    error: str | None = None


def scan_target(ctx: AutoDiagContext, target: Target, *, days: int = 7) -> ScanResult:
    res = ScanResult(target=target.name, started_at=datetime.now(UTC).replace(microsecond=0))
    scan_id = ctx.store.start_scan(target.name, res.started_at)
    try:
        problems = ctx.source(target).list_problems(days=days)
        new_ids = ctx.store.upsert_problems(target.name, problems)
        res.problem_count = len(problems)
        res.new_problem_ids = new_ids
        res.new_problem_keys = [p.problem_key for p in problems if p.problem_id in new_ids]
    except Exception as exc:  # noqa: BLE001 - an unreachable target must not stop the scan
        res.error = f"{type(exc).__name__}: {exc}"
    res.finished_at = datetime.now(UTC).replace(microsecond=0)
    summary = res.error or (
        f"{res.problem_count} problems, {len(res.new_problem_ids)} new"
        + (": " + ", ".join(res.new_problem_keys) if res.new_problem_keys else "")
    )
    ctx.store.finish_scan(scan_id, res.finished_at, res.new_problem_ids, summary)
    return res


def scan_all(ctx: AutoDiagContext, *, days: int = 7) -> list[ScanResult]:
    results = [scan_target(ctx, t, days=days) for t in ctx.inventory.targets]
    for r in results:
        if r.new_problem_keys:
            notify(ctx.settings, f"[{r.target}] new ADR problems: " + ", ".join(r.new_problem_keys))
        elif r.error:
            notify(ctx.settings, f"[{r.target}] scan failed: {r.error}")
    return results


class Scheduler:
    """Background thread: scan every ``interval_minutes`` and purge old cases daily."""

    def __init__(self, ctx: AutoDiagContext) -> None:
        self.ctx = ctx
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if not self.ctx.settings.scan_enabled:
            return
        self._thread = threading.Thread(target=self._loop, name="autodiag-scheduler", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        from autodiag.case.retention import purge

        last_purge = 0.0
        while not self._stop.is_set():
            try:
                scan_all(self.ctx)
                if time.monotonic() - last_purge > 86400:
                    purge(self.ctx.store, days=self.ctx.settings.retention_days)
                    last_purge = time.monotonic()
            except Exception as exc:  # noqa: BLE001
                notify(self.ctx.settings, f"scheduler error: {type(exc).__name__}: {exc}")
            self._stop.wait(max(60, self.ctx.settings.scan_interval_minutes * 60))
