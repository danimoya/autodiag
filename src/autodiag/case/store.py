"""SQLite-backed case store: cases, artifacts, evidence, findings, baselines, reports,
jobs and problem snapshots. One file under the data directory; artifacts copied next to it."""

from __future__ import annotations

import hashlib
import json
import secrets
import shutil
import sqlite3
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from autodiag.adr.adrci import AdrIncident, AdrProblem

FINDING_KINDS = {"root_cause", "contributing", "observation", "action"}
REPORT_KINDS = {"dba", "sr"}
CASE_STATUSES = {"open", "closed"}


class CaseStoreError(RuntimeError):
    pass


class Case(BaseModel):
    id: str
    target: str
    title: str
    status: str = "open"
    problem_keys: list[str] = Field(default_factory=list)
    window_from: datetime | None = None
    window_to: datetime | None = None
    notes: str = ""
    created_at: datetime
    updated_at: datetime


class Artifact(BaseModel):
    id: str
    case_id: str
    kind: str
    path: str
    sha256: str
    size: int
    origin: dict[str, Any] = Field(default_factory=dict)
    label: str = ""
    created_at: datetime


class Evidence(BaseModel):
    id: str
    case_id: str | None = None
    tool: str
    params: dict[str, Any] = Field(default_factory=dict)
    summary: str = ""
    artifact_id: str | None = None
    line_from: int | None = None
    line_to: int | None = None
    created_at: datetime


class Finding(BaseModel):
    id: str
    case_id: str
    kind: str
    title: str
    detail: str = ""
    confidence: float = 0.5
    evidence_ids: list[str] = Field(default_factory=list)
    kb_refs: list[str] = Field(default_factory=list)
    author: str = "agent"
    status: str = "proposed"
    created_at: datetime
    updated_at: datetime


class Baseline(BaseModel):
    id: str
    target: str
    kind: str
    artifact_id: str
    label: str = ""
    created_at: datetime


class Report(BaseModel):
    id: str
    case_id: str
    kind: str
    markdown: str
    ips_artifact_id: str | None = None
    rendered_at: datetime


class Job(BaseModel):
    id: str
    kind: str
    status: str = "queued"
    params: dict[str, Any] = Field(default_factory=dict)
    result: dict[str, Any] = Field(default_factory=dict)
    error: str = ""
    created_at: datetime
    updated_at: datetime


class ScanRow(BaseModel):
    id: str
    target: str
    started_at: datetime
    finished_at: datetime | None = None
    new_problems: list[int] = Field(default_factory=list)
    summary: str = ""


class ProblemRow(BaseModel):
    target: str
    problem_id: int
    problem_key: str
    adr_home: str = ""
    first_incident: int | None = None
    last_incident: int | None = None
    lastinc_time: datetime | None = None
    first_seen_at: datetime
    last_seen_at: datetime


def _now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def _dt(s: str | None) -> datetime | None:
    return datetime.fromisoformat(s) if s else None


def _id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(5)}"


class CaseStore:
    def __init__(self, db_path: Path, *, artifacts_dir: Path | None = None) -> None:
        self.db_path = Path(db_path)
        self.artifacts_dir = artifacts_dir or self.db_path.parent / "cases"
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.db_path, isolation_level=None, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._migrate()

    def close(self) -> None:
        self._conn.close()

    def _migrate(self) -> None:
        schema = resources.files("autodiag.case").joinpath("schema/001_init.sql").read_text()
        self._conn.executescript(schema)
        cur = self._conn.execute("SELECT version FROM schema_version")
        if cur.fetchone() is None:
            self._conn.execute("INSERT INTO schema_version(version) VALUES (1)")

    # -- cases -----------------------------------------------------------------------
    def open_case(
        self,
        target: str,
        title: str,
        *,
        problem_keys: list[str] | None = None,
        window_from: datetime | None = None,
        window_to: datetime | None = None,
        notes: str = "",
    ) -> Case:
        now = _now()
        case = Case(
            id=_id("case"),
            target=target,
            title=title,
            problem_keys=problem_keys or [],
            window_from=window_from,
            window_to=window_to,
            notes=notes,
            created_at=now,
            updated_at=now,
        )
        self._conn.execute(
            "INSERT INTO cases(id,target,title,status,problem_keys,window_from,window_to,notes,"
            "created_at,updated_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                case.id,
                target,
                title,
                case.status,
                json.dumps(case.problem_keys),
                _iso(window_from),
                _iso(window_to),
                notes,
                _iso(now),
                _iso(now),
            ),
        )
        (self.artifacts_dir / case.id).mkdir(parents=True, exist_ok=True)
        return case

    def get_case(self, case_id: str) -> Case:
        row = self._conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        if row is None:
            raise CaseStoreError(f"unknown case {case_id!r}")
        return self._case(row)

    def list_cases(self, *, target: str | None = None, status: str | None = None) -> list[Case]:
        sql, args = "SELECT * FROM cases WHERE 1=1", []
        if target:
            sql, args = sql + " AND target=?", [*args, target]
        if status:
            sql, args = sql + " AND status=?", [*args, status]
        return [self._case(r) for r in self._conn.execute(sql + " ORDER BY created_at DESC", args)]

    def close_case(self, case_id: str) -> None:
        self.get_case(case_id)
        self._conn.execute(
            "UPDATE cases SET status='closed', updated_at=? WHERE id=?", (_iso(_now()), case_id)
        )

    def update_case(self, case_id: str, **fields: Any) -> Case:
        allowed = {"title", "status", "notes", "problem_keys", "window_from", "window_to"}
        bad = set(fields) - allowed
        if bad:
            raise CaseStoreError(f"cannot update {sorted(bad)}")
        if "status" in fields and fields["status"] not in CASE_STATUSES:
            raise CaseStoreError("bad status")
        sets, args = [], []
        for k, v in fields.items():
            sets.append(f"{k}=?")
            args.append(
                json.dumps(v) if k == "problem_keys" else (_iso(v) if k.startswith("window") else v)
            )
        args += [_iso(_now()), case_id]
        self._conn.execute(f"UPDATE cases SET {', '.join(sets)}, updated_at=? WHERE id=?", args)
        return self.get_case(case_id)

    def _case(self, r: sqlite3.Row) -> Case:
        return Case(
            id=r["id"],
            target=r["target"],
            title=r["title"],
            status=r["status"],
            problem_keys=json.loads(r["problem_keys"]),
            window_from=_dt(r["window_from"]),
            window_to=_dt(r["window_to"]),
            notes=r["notes"],
            created_at=_dt(r["created_at"]),
            updated_at=_dt(r["updated_at"]),
        )

    # -- artifacts ---------------------------------------------------------------------
    def add_artifact(
        self,
        case_id: str,
        *,
        kind: str,
        path: Path,
        origin: dict[str, Any],
        label: str = "",
        copy: bool = True,
    ) -> Artifact:
        self.get_case(case_id)
        path = Path(path)
        if not path.is_file():
            raise CaseStoreError(f"artifact file not found: {path}")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        existing = self._conn.execute(
            "SELECT * FROM artifacts WHERE case_id=? AND sha256=?", (case_id, digest)
        ).fetchone()
        if existing:
            return self._artifact(existing)
        dest = path
        if copy:
            dest = self.artifacts_dir / case_id / path.name
            if dest.exists() and dest.resolve() != path.resolve():
                dest = self.artifacts_dir / case_id / f"{digest[:8]}_{path.name}"
            if dest.resolve() != path.resolve():
                shutil.copy2(path, dest)
        now = _now()
        art = Artifact(
            id=_id("art"),
            case_id=case_id,
            kind=kind,
            path=str(dest),
            sha256=digest,
            size=path.stat().st_size,
            origin=origin,
            label=label,
            created_at=now,
        )
        self._conn.execute(
            "INSERT INTO artifacts(id,case_id,kind,path,sha256,size,origin,label,created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (
                art.id,
                case_id,
                kind,
                art.path,
                digest,
                art.size,
                json.dumps(origin),
                label,
                _iso(now),
            ),
        )
        return art

    def get_artifact(self, artifact_id: str) -> Artifact:
        row = self._conn.execute("SELECT * FROM artifacts WHERE id=?", (artifact_id,)).fetchone()
        if row is None:
            raise CaseStoreError(f"unknown artifact {artifact_id!r}")
        return self._artifact(row)

    def list_artifacts(self, case_id: str) -> list[Artifact]:
        rows = self._conn.execute(
            "SELECT * FROM artifacts WHERE case_id=? ORDER BY created_at", (case_id,)
        )
        return [self._artifact(r) for r in rows]

    def _artifact(self, r: sqlite3.Row) -> Artifact:
        return Artifact(
            id=r["id"],
            case_id=r["case_id"],
            kind=r["kind"],
            path=r["path"],
            sha256=r["sha256"],
            size=r["size"],
            origin=json.loads(r["origin"]),
            label=r["label"],
            created_at=_dt(r["created_at"]),
        )

    # -- evidence & findings -------------------------------------------------------------
    def record_evidence(
        self,
        tool: str,
        params: dict[str, Any],
        summary: str,
        *,
        case_id: str | None = None,
        artifact_id: str | None = None,
        line_from: int | None = None,
        line_to: int | None = None,
    ) -> Evidence:
        now = _now()
        ev = Evidence(
            id=_id("ev"),
            case_id=case_id,
            tool=tool,
            params=params,
            summary=summary[:2000],
            artifact_id=artifact_id,
            line_from=line_from,
            line_to=line_to,
            created_at=now,
        )
        self._conn.execute(
            "INSERT INTO evidence(id,case_id,tool,params,summary,artifact_id,line_from,line_to,"
            "created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (
                ev.id,
                case_id,
                tool,
                json.dumps(params, default=str),
                ev.summary,
                artifact_id,
                line_from,
                line_to,
                _iso(now),
            ),
        )
        return ev

    def get_evidence(self, evidence_id: str) -> Evidence:
        row = self._conn.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone()
        if row is None:
            raise CaseStoreError(f"unknown evidence {evidence_id!r}")
        return Evidence(
            id=row["id"],
            case_id=row["case_id"],
            tool=row["tool"],
            params=json.loads(row["params"]),
            summary=row["summary"],
            artifact_id=row["artifact_id"],
            line_from=row["line_from"],
            line_to=row["line_to"],
            created_at=_dt(row["created_at"]),
        )

    def list_evidence(self, case_id: str) -> list[Evidence]:
        ids = [
            r["id"]
            for r in self._conn.execute(
                "SELECT id FROM evidence WHERE case_id=? ORDER BY created_at", (case_id,)
            )
        ]
        return [self.get_evidence(i) for i in ids]

    def add_finding(
        self,
        case_id: str,
        *,
        kind: str,
        title: str,
        detail: str,
        confidence: float,
        evidence_ids: list[str],
        kb_refs: list[str] | None = None,
        author: str = "agent",
    ) -> Finding:
        self.get_case(case_id)
        if kind not in FINDING_KINDS:
            raise CaseStoreError(f"finding kind must be one of {sorted(FINDING_KINDS)}")
        if not evidence_ids:
            raise CaseStoreError("a finding needs at least one evidence id")
        for ev in evidence_ids:
            if self._conn.execute("SELECT 1 FROM evidence WHERE id=?", (ev,)).fetchone() is None:
                raise CaseStoreError(f"unknown evidence id {ev!r}")
        now = _now()
        f = Finding(
            id=_id("fnd"),
            case_id=case_id,
            kind=kind,
            title=title,
            detail=detail,
            confidence=max(0.0, min(1.0, confidence)),
            evidence_ids=evidence_ids,
            kb_refs=kb_refs or [],
            author=author,
            created_at=now,
            updated_at=now,
        )
        self._conn.execute(
            "INSERT INTO findings(id,case_id,kind,title,detail,confidence,evidence,kb_refs,"
            "author,status,created_at,updated_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                f.id,
                case_id,
                kind,
                title,
                detail,
                f.confidence,
                json.dumps(evidence_ids),
                json.dumps(f.kb_refs),
                author,
                f.status,
                _iso(now),
                _iso(now),
            ),
        )
        return f

    def get_finding(self, finding_id: str) -> Finding:
        row = self._conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
        if row is None:
            raise CaseStoreError(f"unknown finding {finding_id!r}")
        return self._finding(row)

    def list_findings(self, case_id: str) -> list[Finding]:
        rows = self._conn.execute(
            "SELECT * FROM findings WHERE case_id=? ORDER BY created_at", (case_id,)
        )
        return [self._finding(r) for r in rows]

    def update_finding(self, finding_id: str, **fields: Any) -> Finding:
        allowed = {"title", "detail", "confidence", "status", "kind", "kb_refs"}
        bad = set(fields) - allowed
        if bad:
            raise CaseStoreError(f"cannot update {sorted(bad)}")
        if "kind" in fields and fields["kind"] not in FINDING_KINDS:
            raise CaseStoreError("bad finding kind")
        sets, args = [], []
        for k, v in fields.items():
            sets.append(f"{k}=?")
            args.append(json.dumps(v) if k == "kb_refs" else v)
        args += [_iso(_now()), finding_id]
        self._conn.execute(f"UPDATE findings SET {', '.join(sets)}, updated_at=? WHERE id=?", args)
        return self.get_finding(finding_id)

    def _finding(self, r: sqlite3.Row) -> Finding:
        return Finding(
            id=r["id"],
            case_id=r["case_id"],
            kind=r["kind"],
            title=r["title"],
            detail=r["detail"],
            confidence=r["confidence"],
            evidence_ids=json.loads(r["evidence"]),
            kb_refs=json.loads(r["kb_refs"]),
            author=r["author"],
            status=r["status"],
            created_at=_dt(r["created_at"]),
            updated_at=_dt(r["updated_at"]),
        )

    # -- baselines ---------------------------------------------------------------------
    def set_baseline(
        self, target: str, *, kind: str, artifact_id: str, label: str = ""
    ) -> Baseline:
        self.get_artifact(artifact_id)
        now = _now()
        b = Baseline(
            id=_id("bl"),
            target=target,
            kind=kind,
            artifact_id=artifact_id,
            label=label,
            created_at=now,
        )
        self._conn.execute(
            "INSERT INTO baselines(id,target,kind,artifact_id,label,created_at)"
            " VALUES (?,?,?,?,?,?)",
            (b.id, target, kind, artifact_id, label, _iso(now)),
        )
        return b

    def list_baselines(self, target: str, *, kind: str | None = None) -> list[Baseline]:
        sql, args = "SELECT * FROM baselines WHERE target=?", [target]
        if kind:
            sql, args = sql + " AND kind=?", [*args, kind]
        return [
            Baseline(
                id=r["id"],
                target=r["target"],
                kind=r["kind"],
                artifact_id=r["artifact_id"],
                label=r["label"],
                created_at=_dt(r["created_at"]),
            )
            for r in self._conn.execute(sql + " ORDER BY created_at DESC", args)
        ]

    # -- reports -----------------------------------------------------------------------
    def add_report(
        self, case_id: str, *, kind: str, markdown: str, ips_artifact_id: str | None = None
    ) -> Report:
        self.get_case(case_id)
        if kind not in REPORT_KINDS:
            raise CaseStoreError(f"report kind must be one of {sorted(REPORT_KINDS)}")
        now = _now()
        r = Report(
            id=_id("rep"),
            case_id=case_id,
            kind=kind,
            markdown=markdown,
            ips_artifact_id=ips_artifact_id,
            rendered_at=now,
        )
        self._conn.execute(
            "INSERT INTO reports(id,case_id,kind,markdown,ips_artifact_id,rendered_at)"
            " VALUES (?,?,?,?,?,?)",
            (r.id, case_id, kind, markdown, ips_artifact_id, _iso(now)),
        )
        return r

    def get_report(self, report_id: str) -> Report:
        row = self._conn.execute("SELECT * FROM reports WHERE id=?", (report_id,)).fetchone()
        if row is None:
            raise CaseStoreError(f"unknown report {report_id!r}")
        return self._report(row)

    def list_reports(self, case_id: str) -> list[Report]:
        return [
            self._report(r)
            for r in self._conn.execute(
                "SELECT * FROM reports WHERE case_id=? ORDER BY rendered_at DESC", (case_id,)
            )
        ]

    def _report(self, r: sqlite3.Row) -> Report:
        return Report(
            id=r["id"],
            case_id=r["case_id"],
            kind=r["kind"],
            markdown=r["markdown"],
            ips_artifact_id=r["ips_artifact_id"],
            rendered_at=_dt(r["rendered_at"]),
        )

    # -- jobs --------------------------------------------------------------------------
    def create_job(self, kind: str, params: dict[str, Any]) -> Job:
        now = _now()
        j = Job(id=_id("job"), kind=kind, params=params, created_at=now, updated_at=now)
        self._conn.execute(
            "INSERT INTO jobs(id,kind,status,params,result,error,created_at,updated_at)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (j.id, kind, j.status, json.dumps(params, default=str), "{}", "", _iso(now), _iso(now)),
        )
        return j

    def update_job(
        self,
        job_id: str,
        *,
        status: str | None = None,
        result: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> Job:
        sets, args = [], []
        if status is not None:
            sets.append("status=?")
            args.append(status)
        if result is not None:
            sets.append("result=?")
            args.append(json.dumps(result, default=str))
        if error is not None:
            sets.append("error=?")
            args.append(error)
        args += [_iso(_now()), job_id]
        self._conn.execute(f"UPDATE jobs SET {', '.join(sets)}, updated_at=? WHERE id=?", args)
        return self.get_job(job_id)

    def get_job(self, job_id: str) -> Job:
        r = self._conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        if r is None:
            raise CaseStoreError(f"unknown job {job_id!r}")
        return Job(
            id=r["id"],
            kind=r["kind"],
            status=r["status"],
            params=json.loads(r["params"]),
            result=json.loads(r["result"]),
            error=r["error"],
            created_at=_dt(r["created_at"]),
            updated_at=_dt(r["updated_at"]),
        )

    # -- scans --------------------------------------------------------------------------
    def start_scan(self, target: str, started_at: datetime) -> str:
        sid = _id("scan")
        self._conn.execute(
            "INSERT INTO scans(id,target,started_at) VALUES (?,?,?)",
            (sid, target, _iso(started_at)),
        )
        return sid

    def finish_scan(
        self, scan_id: str, finished_at: datetime, new_problems: list[int], summary: str
    ) -> None:
        self._conn.execute(
            "UPDATE scans SET finished_at=?, new_problems=?, summary=? WHERE id=?",
            (_iso(finished_at), json.dumps(new_problems), summary, scan_id),
        )

    def list_scans(self, target: str | None = None, *, limit: int = 50) -> list[ScanRow]:
        sql, args = "SELECT * FROM scans", []
        if target:
            sql, args = sql + " WHERE target=?", [target]
        rows = self._conn.execute(sql + " ORDER BY started_at DESC LIMIT ?", [*args, limit])
        return [
            ScanRow(
                id=r["id"],
                target=r["target"],
                started_at=_dt(r["started_at"]),
                finished_at=_dt(r["finished_at"]),
                new_problems=json.loads(r["new_problems"]),
                summary=r["summary"],
            )
            for r in rows
        ]

    def delete_case(self, case_id: str) -> None:
        """Remove a case and everything attached to it (files are the caller's job)."""
        for table in ("reports", "findings", "evidence", "baselines"):
            col = "case_id" if table != "baselines" else None
            if col:
                self._conn.execute(f"DELETE FROM {table} WHERE case_id=?", (case_id,))
        self._conn.execute(
            "DELETE FROM baselines WHERE artifact_id IN (SELECT id FROM artifacts WHERE case_id=?)",
            (case_id,),
        )
        self._conn.execute("DELETE FROM artifacts WHERE case_id=?", (case_id,))
        self._conn.execute("DELETE FROM cases WHERE id=?", (case_id,))

    # -- problem / incident snapshots ------------------------------------------------------
    def upsert_problems(self, target: str, problems: list[AdrProblem]) -> list[int]:
        """Store the current problem list; return the ids that were not known before."""
        now = _iso(_now())
        new: list[int] = []
        for p in problems:
            known = self._conn.execute(
                "SELECT 1 FROM problems WHERE target=? AND problem_id=?", (target, p.problem_id)
            ).fetchone()
            if known:
                self._conn.execute(
                    "UPDATE problems SET problem_key=?, last_incident=?, lastinc_time=?,"
                    "last_seen_at=? WHERE target=? AND problem_id=?",
                    (
                        p.problem_key,
                        p.last_incident,
                        _iso(p.lastinc_time),
                        now,
                        target,
                        p.problem_id,
                    ),
                )
            else:
                new.append(p.problem_id)
                self._conn.execute(
                    "INSERT INTO problems(target,problem_id,problem_key,adr_home,"
                    "first_incident,last_incident,"
                    "lastinc_time,first_seen_at,last_seen_at)"
                    " VALUES (?,?,?,?,?,?,?,?,?)",
                    (
                        target,
                        p.problem_id,
                        p.problem_key,
                        p.adr_home,
                        None,
                        p.last_incident,
                        _iso(p.lastinc_time),
                        now,
                        now,
                    ),
                )
        return new

    def list_problems(self, target: str) -> list[ProblemRow]:
        rows = self._conn.execute(
            "SELECT * FROM problems WHERE target=? ORDER BY lastinc_time DESC", (target,)
        )
        return [
            ProblemRow(
                target=r["target"],
                problem_id=r["problem_id"],
                problem_key=r["problem_key"],
                adr_home=r["adr_home"],
                first_incident=r["first_incident"],
                last_incident=r["last_incident"],
                lastinc_time=_dt(r["lastinc_time"]),
                first_seen_at=_dt(r["first_seen_at"]),
                last_seen_at=_dt(r["last_seen_at"]),
            )
            for r in rows
        ]

    def upsert_incidents(self, target: str, incidents: list[AdrIncident]) -> int:
        now = _iso(_now())
        n = 0
        for i in incidents:
            self._conn.execute(
                "INSERT INTO incidents(target,incident_id,problem_id,problem_key,"
                "create_time,trace_file,"
                "seen_at) VALUES (?,?,?,?,?,?,?)"
                " ON CONFLICT(target,incident_id) DO UPDATE SET problem_key=excluded.problem_key,"
                "trace_file=excluded.trace_file, seen_at=excluded.seen_at",
                (
                    target,
                    i.incident_id,
                    i.problem_id,
                    i.problem_key,
                    _iso(i.create_time),
                    i.trace_file,
                    now,
                ),
            )
            n += 1
        return n
