from pathlib import Path

import pytest

from autodiag.core.settings import load_settings
from autodiag.core.targets import load_targets
from autodiag.mcp.server import AutoDiagContext, build_server
from autodiag.sql.runner import QueryResult

TR = Path("tests/fixtures/23ai/traces")


class FakeRunner:
    def __init__(self):
        self.calls = []

    def run_named(self, name, params=None, *, max_rows=200, container=None):
        from autodiag.sql.catalog import load_catalog
        from autodiag.sql.runner import SqlRunnerError

        if name not in load_catalog():
            raise SqlRunnerError(f"unknown query {name!r}")
        self.calls.append((name, params, container))
        if name == "db_info":
            return QueryResult(
                name=name, columns=["DB_NAME", "VERSION_FULL"], rows=[["FREE", "23.26.3.0.0"]]
            )
        return QueryResult(
            name=name,
            columns=["A", "B"],
            rows=[[i, f"row {i}"] for i in range(max_rows + 1)][: max_rows + 1],
            truncated=True,
        )


@pytest.fixture
def ctx(tmp_path: Path, fixtures_dir: Path, fake_transport_factory, monkeypatch) -> AutoDiagContext:
    monkeypatch.setenv("AUTODIAG_CONFIG", str(tmp_path / "none.toml"))
    monkeypatch.setenv("AUTODIAG_DATA_DIR", str(tmp_path / "data"))
    s = load_settings(env_file=None)
    inv = load_targets(fixtures_dir / "config" / "targets.yaml")
    return AutoDiagContext(
        settings=s,
        inventory=inv,
        transport_factory=lambda t: fake_transport_factory,
        runner_factory=lambda t: FakeRunner(),
    )


@pytest.fixture
def server(ctx):
    return build_server(ctx)


async def call(server, tool_name: str, **kwargs):
    tool = await server.get_tool(tool_name)
    return tool.fn(**kwargs)


async def test_tool_inventory(server) -> None:
    tools = await server.list_tools()
    names = {t.name for t in tools}
    for n in [
        "list_targets",
        "list_problems",
        "list_incidents",
        "get_incident",
        "alert_log_window",
        "alert_log_grep",
        "alert_log_stats",
        "parse_trace",
        "read_trace_lines",
        "get_call_stack",
        "sql_trace_profile",
        "compare_call_stacks",
        "stack_frequency",
        "compare_sql_profiles",
        "compare_alert_rates",
        "kb_lookup",
        "list_queries",
        "run_query",
        "open_case",
        "get_case",
        "add_artifact_to_case",
        "add_finding",
        "set_baseline",
        "list_baselines",
        "render_report",
        "capture_environment",
        "timeline",
        "create_ips_package",
        "collect_ahf",
        "job_status",
        "standard_triage",
    ]:
        assert n in names, n
    for t in tools:
        assert t.description, t.name


async def test_targets_problems_incidents(server) -> None:
    r = await call(server, "list_targets")
    assert [t["name"] for t in r["targets"]] == ["testbed", "prod-rac"] and r[
        "evidence_id"
    ].startswith("ev_")
    r = await call(server, "list_problems", target="testbed", since_hours=48)
    assert r["problems"][0]["problem_key"].startswith("ORA 7445") and r["truncated"] is False
    r = await call(server, "list_incidents", target="testbed", problem_id=1)
    assert [i["incident_id"] for i in r["incidents"]] == [8881, 8880, 8873]
    r = await call(server, "get_incident", target="testbed", incident_id=8873)
    assert r["incident"]["problem_key"] == "ORA 600 [autodiag_test]"
    assert r["artifact_id"].startswith("art_") and r["trace"]["kind"] == "incident"
    assert r["trace"]["first_app_frame"] == "qeilbk1"


async def test_unknown_target_is_an_error_dict(server) -> None:
    r = await call(server, "list_problems", target="nope")
    assert r["error"].startswith("unknown target")


async def test_alert_tools(server) -> None:
    r = await call(server, "alert_log_grep", target="testbed", pattern="ORA-00060", context=1)
    assert "ORA-00060" in r["text"] and r["evidence_id"]
    r = await call(server, "alert_log_stats", target="testbed", hours=100000)
    assert r["stats"]["ora_counts"]["60"] == 2 or r["stats"]["ora_counts"][60] == 2
    r = await call(
        server,
        "alert_log_window",
        target="testbed",
        from_ts="2026-09-22T12:00:00+00:00",
        to_ts="2026-09-22T12:11:00+00:00",
        max_lines=3,
    )
    assert r["truncated"] is True and r["next_offset"] == 3 and len(r["lines"]) == 3


async def test_trace_tools_and_diffs(server, ctx) -> None:
    case = await call(server, "open_case", target="testbed", title="t")
    cid = case["case"]["id"]
    a = await call(
        server,
        "add_artifact_to_case",
        case_id=cid,
        path=str(TR / "incident_ora7445.trc"),
        kind="trace",
    )
    b = await call(
        server,
        "add_artifact_to_case",
        case_id=cid,
        path=str(TR / "incident_ora7445_b.trc"),
        kind="trace",
    )
    p = await call(server, "parse_trace", artifact_id=a["artifact"]["id"])
    assert p["trace"]["kind"] == "incident" and p["trace"]["problem_key"] == "ORA 7445 [qeilbk1]"
    lines = await call(
        server, "read_trace_lines", artifact_id=a["artifact"]["id"], offset=40, max_lines=5
    )
    assert len(lines["lines"]) == 5 and lines["next_offset"] == 45
    stack = await call(server, "get_call_stack", artifact_id=a["artifact"]["id"])
    assert stack["frames"][0] == "qeilbk1" and stack["source"] == "incident_context"
    d = await call(
        server,
        "compare_call_stacks",
        left_artifact=a["artifact"]["id"],
        right_artifact=b["artifact"]["id"],
    )
    assert d["diff"]["divergence_index"] == 0 and d["diff"]["right_first_app_frame"] == "kdxbrs1"
    f = await call(
        server, "stack_frequency", artifact_ids=[a["artifact"]["id"], b["artifact"]["id"]]
    )
    assert any(x["func"] == "qeilbk1" and x["share"] == 1.0 for x in f["frames"])
    n = await call(
        server,
        "add_artifact_to_case",
        case_id=cid,
        path=str(TR / "AUTODIAG_NORMAL.trc"),
        kind="sqltrace",
    )
    an = await call(
        server,
        "add_artifact_to_case",
        case_id=cid,
        path=str(TR / "AUTODIAG_ANOMALY.trc"),
        kind="sqltrace",
    )
    prof = await call(server, "sql_trace_profile", artifact_id=n["artifact"]["id"], top=3)
    assert prof["profile"]["cursor_count"] == 24 and len(prof["top_cursors"]) == 3
    pd = await call(
        server,
        "compare_sql_profiles",
        left_artifact=n["artifact"]["id"],
        right_artifact=an["artifact"]["id"],
        top=5,
    )
    assert any("PLAN_CHANGE" in it["tags"] for it in pd["diff"]["items"])
    assert pd["diff"]["explanation_hints"]


async def test_case_findings_and_report(server) -> None:
    case = await call(
        server, "open_case", target="testbed", title="ORA-7445", problem_keys=["ORA 7445 [qeilbk1]"]
    )
    cid = case["case"]["id"]
    inc = await call(server, "get_incident", target="testbed", incident_id=8873, case_id=cid)
    f = await call(
        server,
        "add_finding",
        case_id=cid,
        kind="root_cause",
        title="crash in qeilbk1",
        detail="SIGSEGV in index lookup",
        confidence=0.6,
        evidence_ids=[inc["evidence_id"]],
    )
    assert f["finding"]["id"].startswith("fnd_")
    bad = await call(
        server,
        "add_finding",
        case_id=cid,
        kind="root_cause",
        title="x",
        detail="y",
        confidence=0.5,
        evidence_ids=[],
    )
    assert "error" in bad
    got = await call(server, "get_case", case_id=cid)
    assert got["findings"][0]["title"] == "crash in qeilbk1" and got["artifacts"]
    rep = await call(server, "render_report", case_id=cid, kind="dba")
    assert rep["markdown"].startswith("# AutoDiag report") and "crash in qeilbk1" in rep["markdown"]
    tl = await call(server, "timeline", case_id=cid)
    assert tl["events"] and tl["events"][0]["source"] == "incident"


async def test_kb_queries_env(server) -> None:
    r = await call(server, "kb_lookup", problem_key="ORA 600 [4194]")
    assert r["hits"][0]["title"].startswith("Undo record mismatch")
    q = await call(server, "list_queries")
    assert any(x["name"] == "diag_problems" for x in q["queries"])
    res = await call(server, "run_query", target="testbed", name="db_info", params={})
    assert res["columns"] == ["DB_NAME", "VERSION_FULL"] and res["rows"][0][0] == "FREE"
    bad = await call(server, "run_query", target="testbed", name="drop_it", params={})
    assert "error" in bad
    env = await call(server, "capture_environment", target="testbed")
    assert env["environment"]["version_full"] == "23.26.3.0.0"


async def test_output_caps_and_redaction(server) -> None:
    case = await call(server, "open_case", target="testbed", title="t")
    a = await call(
        server,
        "add_artifact_to_case",
        case_id=case["case"]["id"],
        path=str(TR / "AUTODIAG_NORMAL.trc"),
        kind="sqltrace",
    )
    lines = await call(
        server, "read_trace_lines", artifact_id=a["artifact"]["id"], offset=0, max_lines=5000
    )
    assert len(lines["lines"]) <= 1000 and lines["truncated"] is True  # hard cap
    binds = await call(
        server,
        "read_trace_lines",
        artifact_id=a["artifact"]["id"],
        offset=0,
        max_lines=1000,
        grep="value=",
    )
    assert binds["lines"] and all(
        "value=<redacted>" in ln or "value=" not in ln for ln in binds["lines"]
    )


async def test_standard_triage_and_jobs(server) -> None:
    r = await call(
        server, "standard_triage", target="testbed", problem_key="ORA 600 [autodiag_test]"
    )
    assert (
        r["problem_key"] == "ORA 600 [autodiag_test]"
        and r["incidents"]
        and r["newest_incident"]["trace"]["kind"] == "incident"
    )
    assert r["kb_hits"] and r["alert_window"] is not None and r["case_id"].startswith("case_")
    j = await call(
        server,
        "collect_ahf",
        target="testbed",
        from_ts="2026-09-22 11:00:00",
        to_ts="2026-09-22 12:00:00",
    )
    assert j["job"]["id"].startswith("job_")
    st = await call(server, "job_status", job_id=j["job"]["id"])
    assert st["job"]["status"] in {"queued", "running", "done", "failed"}
