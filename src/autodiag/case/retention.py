"""Delete closed cases (and their artifact files) that have not changed for N days."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from pydantic import BaseModel

from autodiag.case.store import CaseStore


class PurgeResult(BaseModel):
    cases_deleted: int = 0
    files_deleted: int = 0


def purge(store: CaseStore, *, days: int) -> PurgeResult:
    cutoff = datetime.now(UTC) - timedelta(days=days)
    result = PurgeResult()
    for case in store.list_cases(status="closed"):
        if case.updated_at and case.updated_at > cutoff:
            continue
        for art in store.list_artifacts(case.id):
            p = Path(art.path)
            if p.is_file() and store.artifacts_dir in p.parents:
                p.unlink()
                result.files_deleted += 1
        store.delete_case(case.id)
        result.cases_deleted += 1
    return result
