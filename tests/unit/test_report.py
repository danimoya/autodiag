from datetime import UTC, datetime
from pathlib import Path

from autodiag.alertlog.text import parse_alert_text
from autodiag.report.render import ReportContext, render_report
from autodiag.report.timeline import TimelineEvent, build_timeline


def _ctx() -> ReportContext:
    now = datetime(2026, 9, 22, 12, 30, tzinfo=UTC)
    return ReportContext(
        case={
            "id": "case_1",
            "title": "ORA-7445 in busy loop",
            "target": "testbed",
            "status": "open",
            "problem_keys": ["ORA 7445 [qeilbk1]"],
            "window_from": now,
            "window_to": now,
            "created_at": now,
        },
        target={
            "name": "testbed",
            "platform": "exacc",
            "kind": "rac",
            "oracle_version": "19c",
            "db_unique_name": "PRODDB_FRA",
            "nodes": ["dbnode01.example.internal"],
        },
        environment={
            "version_full": "19.0.0.0.0",
            "patches": ["36582781 Database Release Update 19.24"],
            "nondefault_parameters": {"sga_target": "8G"},
        },
        problems=[
            {
                "problem_id": 2,
                "problem_key": "ORA 7445 [qeilbk1]",
                "incident_count": 2,
                "first_incident_time": now,
                "last_incident_time": now,
            }
        ],
        incidents=[
            {
                "incident_id": 8275,
                "problem_key": "ORA 7445 [qeilbk1]",
                "create_time": now,
                "trace_file": "/u02/diag/x_i8275.trc",
                "first_app_frame": "qeilbk1",
                "sql_id": "2cbq3fnthp7ut",
            }
        ],
        findings=[
            {
                "id": "fnd_1",
                "kind": "root_cause",
                "title": "Index lookup crash",
                "detail": "SIGSEGV in qeilbk1",
                "confidence": 0.7,
                "evidence_ids": ["ev_1"],
                "kb_refs": ["ora7445:^(qer|qei|qks|qkn)"],
                "status": "proposed",
            }
        ],
        evidence=[
            {
                "id": "ev_1",
                "tool": "parse_trace",
                "summary": "ORA 7445 [qeilbk1] (incident 8275)",
                "artifact_id": "art_1",
                "line_from": 41,
                "line_to": 99,
            }
        ],
        artifacts=[
            {
                "id": "art_1",
                "kind": "trace",
                "path": "/data/cases/case_1/x_i8275.trc",
                "sha256": "ab" * 32,
                "size": 12345,
            }
        ],
        timeline=[
            TimelineEvent(
                ts=now, source="incident", text="ORA 7445 [qeilbk1] incident 8275", ref="8275"
            )
        ],
        kb_hits=[
            {
                "kind": "ora7445",
                "title": "Crash in the SQL execution engine",
                "mos_search": "ORA-7445 qer",
                "checks": ["current SQL and plan"],
                "actions": ["search MOS"],
            }
        ],
        stack_notes=["stacks diverge at frame 0: 'qeilbk1' vs 'kdxbrs1'"],
        profile_summary=None,
        generated_at=now,
    )


def test_dba_report_sections() -> None:
    md = render_report("dba", _ctx())
    for section in [
        "# AutoDiag report",
        "## Summary",
        "## Evidence",
        "## Likely cause",
        "## Suggested actions",
        "## Timeline",
        "## Environment",
    ]:
        assert section in md, section
    assert "ORA 7445 [qeilbk1]" in md and "qeilbk1" in md and "ev_1" in md
    assert "Database Release Update 19.24" in md
    assert "70%" in md


def test_sr_report_sections() -> None:
    md = render_report("sr", _ctx())
    for section in [
        "# Service Request",
        "## Problem statement",
        "## Environment",
        "## Incidents",
        "## Diagnostic files",
        "## Analysis so far",
        "## Business impact",
    ]:
        assert section in md, section
    assert "PRODDB_FRA" in md and "19.0.0.0.0" in md and "sha256" in md.lower()
    assert "<fill in>" in md  # explicit placeholders for the DBA to complete


def test_timeline_merges_and_sorts(fixtures_dir: Path) -> None:
    recs = parse_alert_text((fixtures_dir / "23ai/alertlog/alert_excerpt.log").read_text())
    t = datetime(2026, 9, 22, 12, 5, tzinfo=UTC)
    inc = [{"incident_id": 1, "problem_key": "ORA 600 [x]", "create_time": t}]
    ash = [
        {
            "sample_time": datetime(2026, 9, 22, 12, 3, tzinfo=UTC),
            "event": "enq: TX - row lock contention",
            "samples": 12,
        }
    ]
    tl = build_timeline(
        alert_records=recs, incidents=inc, ash_rows=ash, only_errors=True, max_items=50
    )
    assert [e.ts for e in tl] == sorted(e.ts for e in tl)
    assert any(e.source == "incident" for e in tl) and any(e.source == "ash" for e in tl)
    assert all(e.source != "alert" or e.is_error for e in tl)
    assert len(tl) <= 50
