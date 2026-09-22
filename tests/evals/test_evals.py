"""Golden scenarios: deterministic checks through the MCP tools (always run) and an
optional headless OpenCode run (``-m llm``) that must mention the expected keywords."""

from pathlib import Path

import pytest
import yaml

from autodiag.core.settings import load_settings
from autodiag.core.targets import load_targets
from autodiag.mcp.server import AutoDiagContext, build_server

SCENARIOS = Path(__file__).parent / "scenarios"


def load(name: str) -> dict:
    return yaml.safe_load((SCENARIOS / f"{name}.yaml").read_text())


@pytest.fixture
def server(tmp_path: Path, fixtures_dir: Path, fake_transport_factory, monkeypatch):
    monkeypatch.setenv("AUTODIAG_CONFIG", str(tmp_path / "none.toml"))
    monkeypatch.setenv("AUTODIAG_DATA_DIR", str(tmp_path / "data"))
    s = load_settings(env_file=None)
    inv = load_targets(fixtures_dir / "config" / "targets.yaml")
    return build_server(
        AutoDiagContext(
            s,
            inv,
            transport_factory=lambda t: fake_transport_factory,
            runner_factory=lambda t: None,
        )
    )


async def call(server, name, **kw):
    return (await server.get_tool(name)).fn(**kw)


async def test_scenario_ora7445(server) -> None:
    sc = load("ora7445_busy_loop")
    case = await call(server, "open_case", target="testbed", title=sc["name"])
    cid = case["case"]["id"]
    a = await call(
        server, "add_artifact_to_case", case_id=cid, path=sc["inputs"]["incident_artifact"]
    )
    b = await call(
        server, "add_artifact_to_case", case_id=cid, path=sc["inputs"]["second_incident_artifact"]
    )
    t = await call(server, "parse_trace", artifact_id=a["artifact"]["id"])
    assert t["trace"]["problem_key"] == sc["expect"]["problem_key"]
    assert t["trace"]["first_app_frame"] == sc["expect"]["first_app_frame"]
    stack = await call(server, "get_call_stack", artifact_id=a["artifact"]["id"])
    kb = await call(
        server, "kb_lookup", problem_key=t["trace"]["problem_key"], frames=stack["frames"][:5]
    )
    assert kb["hits"][0]["kind"] == sc["expect"]["kb_kind"]
    assert any(sc["expect"]["component_contains"] in h["title"].lower() for h in kb["hits"])
    d = await call(
        server,
        "compare_call_stacks",
        left_artifact=a["artifact"]["id"],
        right_artifact=b["artifact"]["id"],
    )
    assert d["diff"]["divergence_index"] == sc["expect"]["divergence_index"]


async def test_scenario_sqltrace(server) -> None:
    sc = load("sqltrace_plan_change")
    cid = (await call(server, "open_case", target="testbed", title=sc["name"]))["case"]["id"]
    n = await call(
        server,
        "add_artifact_to_case",
        case_id=cid,
        path=sc["inputs"]["normal_artifact"],
        kind="sqltrace",
    )
    a = await call(
        server,
        "add_artifact_to_case",
        case_id=cid,
        path=sc["inputs"]["anomaly_artifact"],
        kind="sqltrace",
    )
    d = await call(
        server,
        "compare_sql_profiles",
        left_artifact=n["artifact"]["id"],
        right_artifact=a["artifact"]["id"],
    )
    flagged = [it for it in d["diff"]["items"] if sc["expect"]["tag"] in it["tags"]]
    assert flagged and any(
        sc["expect"]["cursor_text_contains"] in it["sql_text"].upper() for it in flagged
    )
    assert any(sc["expect"]["hint_contains"] in h for h in d["diff"]["explanation_hints"])


async def test_scenario_deadlock(server) -> None:
    sc = load("deadlock_row_lock")
    cid = (await call(server, "open_case", target="testbed", title=sc["name"]))["case"]["id"]
    a = await call(server, "add_artifact_to_case", case_id=cid, path=sc["inputs"]["artifact"])
    t = await call(server, "parse_trace", artifact_id=a["artifact"]["id"])
    assert sc["expect"]["classification_contains"] in t["trace"]["classification"]
    assert t["trace"]["cycle"] == sc["expect"]["cycle"]


@pytest.mark.llm
@pytest.mark.parametrize("name", ["ora7445_busy_loop"])
def test_headless_agent_mentions_expected_keywords(name: str, tmp_path: Path) -> None:
    """Runs OpenCode headless with the autodiag-triage agent against the live testbed."""
    import json
    import shutil
    import subprocess

    exe = shutil.which("opencode")
    if not exe:
        pytest.skip("opencode not installed")
    sc = load(name)
    prompt = (
        f"Target testbed: triage the problem key {sc['expect']['problem_key']} "
        "with standard_triage, "
        "then give the answer in the skill's format. Keep it under 300 words."
    )
    proc = subprocess.run(
        [exe, "run", "--agent", "autodiag-triage", "--format", "json", prompt],
        capture_output=True,
        text=True,
        timeout=900,
        cwd=tmp_path,
    )
    texts = []
    for line in proc.stdout.splitlines():
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        part = ev.get("part") or {}
        if part.get("type") == "text":
            texts.append(part.get("text", ""))
    answer = "\n".join(texts)
    missing = [k for k in sc["expect"]["answer_keywords"] if k.lower() not in answer.lower()]
    assert not missing, f"answer lacks {missing}:\n{answer[:1500]}"
