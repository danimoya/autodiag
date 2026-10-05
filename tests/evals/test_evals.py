"""Golden scenarios: deterministic checks through the MCP tools (always run) and an
optional headless OpenCode run (``-m llm``) that must mention the expected keywords."""

import re
from pathlib import Path

import pytest
import yaml

from autodiag.core.settings import load_settings
from autodiag.core.targets import load_targets
from autodiag.mcp.server import AutoDiagContext, build_server

SCENARIOS = Path(__file__).parent / "scenarios"


def load(name: str) -> dict:
    return yaml.safe_load((SCENARIOS / f"{name}.yaml").read_text())


def live_expectation(expect: dict, fault_log: Path | None) -> dict:
    """Keep fixture expectations unless a fresh fault run supplies the live frame."""
    if fault_log is None:
        return expect
    matches = re.findall(
        r'^AUTODIAG_FAULT name=ora7445 problem_key="(ORA 7445 \[([^\]]+)\])" '
        r"incident_ids=\[([0-9 ]+)\].* status=ok$",
        fault_log.read_text(),
        re.MULTILINE,
    )
    assert matches, "fault log has no successful ORA-7445 proof"
    key, frame, ids = matches[-1]
    return {
        **expect,
        "problem_key": key,
        "live_incident_ids": [int(i) for i in ids.split()],
        "answer_keywords": [
            frame if k == expect["first_app_frame"] else k for k in expect["answer_keywords"]
        ],
    }


def test_live_expectation_uses_fresh_frame_without_changing_other_checks(tmp_path):
    expect = load("ora7445_busy_loop")["expect"]
    log = tmp_path / "faults.log"
    log.write_text(
        'AUTODIAG_FAULT name=ora7445 problem_key="ORA 7445 [kcbrls]" '
        "incident_ids=[12] traces=[/diag/incident.trc] status=ok\n"
    )
    live = live_expectation(expect, log)
    assert live["problem_key"] == "ORA 7445 [kcbrls]"
    assert live["answer_keywords"] == ["kcbrls", "SIGSEGV", "PKG_ORDERS.BUSY_LOOP"]
    assert expect["first_app_frame"] == "qeilbk1"
    assert live_expectation(expect, None) is expect


def test_live_expectation_rejects_unproven_fault(tmp_path):
    log = tmp_path / "faults.log"
    log.write_text(
        'AUTODIAG_FAULT name=ora7445 problem_key="ORA 7445 [kcbrls]" '
        "incident_ids=[] traces=[] status=MISSING\n"
    )
    with pytest.raises(AssertionError, match="no successful"):
        live_expectation(load("ora7445_busy_loop")["expect"], log)


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
    import os
    import shutil
    import subprocess

    exe = shutil.which("opencode")
    if not exe:
        pytest.skip("opencode not installed")
    sc = load(name)
    fault_log = os.environ.get("AUTODIAG_EVAL_FAULT_LOG")
    expect = live_expectation(sc["expect"], Path(fault_log) if fault_log else None)
    prompt = (
        f"Target testbed: triage the problem key {expect['problem_key']} "
        "with standard_triage, "
        "then give the answer in the skill's format. Keep it under 300 words."
    )
    command = [exe, "run", "--agent", "autodiag-triage", "--format", "json"]
    model = os.environ.get("AUTODIAG_EVAL_OPENCODE_MODEL")
    if model:
        command += ["--model", model]
    proc = subprocess.run(
        [*command, prompt],
        capture_output=True,
        text=True,
        timeout=900,
        cwd=tmp_path,
    )
    texts = []
    errors = []
    triage_outputs = []
    for line in proc.stdout.splitlines():
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if ev.get("type") == "error":
            errors.append(ev.get("error", {}).get("name", "unknown error"))
        part = ev.get("part") or {}
        if part.get("type") == "tool" and "standard_triage" in part.get("tool", ""):
            state = part.get("state") or {}
            if state.get("status") == "completed":
                output = state.get("output", "")
                triage_outputs.append(output if isinstance(output, str) else json.dumps(output))
        if part.get("type") == "text":
            texts.append(part.get("text", ""))
    answer = "\n".join(texts)
    assert proc.returncode == 0 and not errors, (
        f"OpenCode exited {proc.returncode}; error events: {errors}. "
        "Check the client logs and 'opencode models'; set AUTODIAG_EVAL_OPENCODE_MODEL "
        "to override a stale default model."
    )
    if fault_log:
        version = os.environ.get("AUTODIAG_EVAL_EXPECT_VERSION_PREFIX", "")
        assert any(
            expect["problem_key"] in output
            and any(str(i) in output for i in expect["live_incident_ids"])
            and '"artifact_id"' in output
            and version in output
            for output in triage_outputs
        ), (
            "No completed standard_triage tool result matches the fresh incident "
            "and expected version"
        )
    missing = [k for k in expect["answer_keywords"] if k.lower() not in answer.lower()]
    assert not missing, f"answer lacks {missing}:\n{answer[:1500]}"


async def test_scenario_ora600_repeat(server) -> None:
    sc = load("ora600_repeat")
    cid = (await call(server, "open_case", target="testbed", title=sc["name"]))["case"]["id"]
    ids = [
        (await call(server, "add_artifact_to_case", case_id=cid, path=p))["artifact"]["id"]
        for p in sc["inputs"]["artifacts"]
    ]
    t = await call(server, "parse_trace", artifact_id=ids[0])
    assert t["trace"]["problem_key"] == sc["expect"]["problem_key"]
    assert t["trace"]["first_app_frame"] == sc["expect"]["signaling_frame"]
    f = await call(server, "stack_frequency", artifact_ids=ids)
    sig = next(x for x in f["frames"] if x["func"] == sc["expect"]["signaling_frame"])
    assert sig["share"] == sc["expect"]["signature_share"] and sig["signature"]
    kb = await call(server, "kb_lookup", problem_key=t["trace"]["problem_key"])
    assert kb["hits"][0]["kind"] == sc["expect"]["kb_kind"]


@pytest.mark.llm
def test_model_assessment_is_grounded_on_live_testbed() -> None:
    """The configured Ollama model must produce a verified assessment of the repeated
    ORA-600 on the testbed: proofs quoted from the dossier, the recurrence recognised."""
    from autodiag.cli import common
    from autodiag.diagnose.engine import default_assessor, diagnose

    ctx = common.context()
    assessor = default_assessor(ctx.settings)
    if assessor.client.available_url() is None:
        pytest.skip("no Ollama endpoint reachable")
    d = diagnose(
        ctx,
        mode="problem",
        target="testbed",
        problem_key="ORA 600 [autodiag_repeat]",
        assessor=assessor,
    )
    a = d.assessment
    assert a.model != "rules", a.notes
    assert a.proofs_verified >= 1 and a.proofs_verified / max(a.proofs_total, 1) >= 0.6
    assert a.concerns and a.concerns[0].proven
    text = (a.headline + " " + " ".join(c.title + c.assessment for c in a.concerns)).lower()
    assert "autodiag_repeat" in text or "ora-00600" in text or "ora-600" in text
