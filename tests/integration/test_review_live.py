"""Read-only review regression checks reusable against any configured testbed DB."""

import json

import pytest
from typer.testing import CliRunner

from autodiag.cli import common
from autodiag.cli.main import app
from autodiag.mcp.server import build_server
from autodiag.sql.runner import SqlRunner

pytestmark = pytest.mark.integration


def test_live_alert_grep_no_match_and_real_path(testbed_source):
    for node, home in testbed_source.refs():
        path = testbed_source.alert_log_path(node, home)
        assert testbed_source.grep_file(node, path, "AUTODIAG_ABSENT_98f65eaa8") == ""
        # A matching read distinguishes an accessible empty result from a bad path.
        assert testbed_source.grep_file(node, path, "2026", max_lines=1)


@pytest.mark.parametrize(
    "query", ["performance_counters", "performance_sessions", "performance_sql"]
)
def test_live_performance_catalog_binds(testbed_source, query):
    target = testbed_source.target
    assert target.sqlnet and target.sqlnet.password(), "Live validation requires SQL credentials"
    runner = SqlRunner(target.sqlnet, diagnostics_pack=False)
    all_rows = runner.run_named(query, {"instance_id": 0}, max_rows=10000)
    assert "INST_ID" in all_rows.columns
    if query != "performance_counters":
        limited = runner.run_named(query, {"instance_id": 0, "top": 1})
        assert len(limited.rows) <= 1
    instances = runner.run_named("rac_instances").as_dicts()
    for instance in instances:
        inst = instance["INST_ID"]
        result = runner.run_named(query, {"instance_id": inst}, max_rows=10000)
        assert all(row["INST_ID"] == inst for row in result.as_dicts())


def test_live_cli_performance(testbed_source):
    runner = SqlRunner(testbed_source.target.sqlnet, diagnostics_pack=False)
    ids = [0] + [r["INST_ID"] for r in runner.run_named("rac_instances").as_dicts()]
    for inst in ids:
        result = CliRunner().invoke(
            app,
            [
                "diagnose",
                "performance",
                "--target",
                "testbed",
                "--sample-seconds",
                "1",
                "--instance-id",
                str(inst),
                "--no-assess",
                "--json",
            ],
        )
        assert result.exit_code == 0, result.output
        diagnosis = json.loads(result.output)
        assert diagnosis["dossier"]["mode"] == "performance"
        assert diagnosis["dossier"]["scope"]["instance_id"] == inst
        assert not diagnosis["dossier"]["errors"], diagnosis["dossier"]["errors"]
        assert diagnosis["assessment"]["model"] == "rules"


async def test_live_mcp_performance(testbed_source):
    ctx = common.context()
    try:
        server = build_server(ctx)
        tool = await server.get_tool("diagnose_performance")
        runner = SqlRunner(testbed_source.target.sqlnet, diagnostics_pack=False)
        inst = max(r["INST_ID"] for r in runner.run_named("rac_instances").as_dicts())
        result = tool.fn(target="testbed", sample_seconds=1, instance_id=inst, assess=False)
        assert result["mode"] == "performance", result
        assert not result["errors"], result["errors"]
        assert result["scope"]["instance_id"] == inst
        assert result["assessment"]["model"] == "rules"
    finally:
        ctx.store.close()
