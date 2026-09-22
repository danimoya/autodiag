from pathlib import Path

import pytest

from autodiag.diff.callstack import (
    compare_stacks,
    frame_frequency,
    normalize_stack,
    stack_from_incident,
)
from autodiag.kb.loader import component_of
from autodiag.trace.incident import parse_incident


@pytest.fixture
def incidents(fixtures_dir: Path):
    a = parse_incident((fixtures_dir / "23ai/traces/incident_ora7445.trc").read_text())
    b = parse_incident((fixtures_dir / "23ai/traces/incident_ora7445_b.trc").read_text())
    return a, b


def test_normalize_strips_prelude_and_tail() -> None:
    raw = [
        "ksedst1",
        "ksedst",
        "dbkedDefDump",
        "ksedmp",
        "ssexhd",
        "__sighandler",
        "kglic0",
        "kksParseCursor",
        "opiodr",
        "opidrv",
        "sou2o",
        "opimai_real",
        "main",
    ]
    n = normalize_stack(raw)
    assert n.frames == ["kglic0", "kksParseCursor"]
    assert n.prelude == ["ksedst1", "ksedst", "dbkedDefDump", "ksedmp", "ssexhd", "__sighandler"]
    assert n.tail == ["opiodr", "opidrv", "sou2o", "opimai_real", "main"]
    assert normalize_stack(["kglic0()+12", "kksParseCursor()+7"]).frames == [
        "kglic0",
        "kksParseCursor",
    ]


def test_identical_stacks() -> None:
    d = compare_stacks(["a", "b", "c"], ["a", "b", "c"])
    assert d.similarity == 1.0 and d.divergence_index is None
    assert d.unique_left == [] and d.unique_right == []
    assert all(f.op == "equal" for f in d.aligned)


def test_divergence_index_and_unique_frames() -> None:
    d = compare_stacks(["a", "b", "c", "d", "z"], ["a", "b", "x", "y", "d", "z"])
    assert d.divergence_index == 2
    assert d.common_prefix == 2 and d.common_suffix == 2
    assert d.unique_left == ["c"] and d.unique_right == ["x", "y"]
    assert 0 < d.similarity < 1


def test_stack_from_incident_prefers_context_frames(incidents) -> None:
    a, b = incidents
    sa, sb = stack_from_incident(a), stack_from_incident(b)
    assert sa.source == "incident_context"
    assert sa.prelude[0] == "dbgexExplicitEndInc" and sa.frames[0] == "qeilbk1"
    assert "qeilbk1" in sa.frames and "kdxbrs1" in sb.frames
    assert sa.components["qerixtFetch"] == "SQL_Execution"


def test_compare_real_incidents(incidents) -> None:
    a, b = incidents
    d = compare_stacks(stack_from_incident(a).frames, stack_from_incident(b).frames)
    assert d.left_first_app_frame == "qeilbk1" and d.right_first_app_frame == "kdxbrs1"
    assert d.divergence_index == 0
    # the second crash happened one level deeper in the same index path, so the first
    # stack is a suffix of the second: the divergent frame is only on the right
    assert d.unique_left == [] and "kdxbrs1" in d.unique_right
    assert d.similarity < 1.0
    assert any("diverge" in n.lower() for n in d.notes)
    assert d.left_component == "row source: index" and d.right_component.startswith("index block")


def test_frame_frequency_and_signature() -> None:
    stacks = [
        ["p", "a", "b", "c"],
        ["p", "a", "b", "d"],
        ["p", "a", "x", "c"],
        ["p", "a", "b", "c"],
    ]
    freq = frame_frequency(stacks)
    by = {f.func: f for f in freq}
    assert by["a"].share == 1.0 and by["b"].share == 0.75 and by["x"].share == 0.25
    sig = [f.func for f in freq if f.signature]
    assert sig == ["p", "a"]  # share >= 0.8, in first-seen order


def test_component_lookup_longest_prefix() -> None:
    assert component_of("kglic0") == "library cache iterator"
    assert component_of("kglLock") == "library cache"
    assert component_of("kdxbrs1") == "index block layer (B-tree)"
    assert component_of("__sighandler") is None or isinstance(component_of("__sighandler"), str)
    assert component_of("zzz_unknown") is None
