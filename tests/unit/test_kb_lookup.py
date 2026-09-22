from autodiag.kb.lookup import kb_lookup


def test_ora600_specific_and_generic() -> None:
    hits = kb_lookup(problem_key="ORA 600 [4194]")
    assert hits[0].title == "Undo record mismatch while applying undo" and hits[0].kind == "ora600"
    assert hits[0].severity == "critical" and hits[0].mos_search
    assert any(h.kind == "ora600_generic" for h in hits)
    unknown = kb_lookup(problem_key="ORA 600 [zzzz]")
    assert unknown and unknown[0].kind == "ora600_generic"
    assert all("note" not in (h.mos_search or "").lower() for h in unknown)


def test_ora7445_by_function() -> None:
    hits = kb_lookup(problem_key="ORA 7445 [kdxbrs1]")
    assert hits[0].kind == "ora7445" and "index" in hits[0].title.lower()
    hits2 = kb_lookup(problem_key="ORA 7445 [qeilbk1]", frames=["qeilbk1", "qeilsr", "qerixtFetch"])
    assert hits2[0].title.startswith("Crash in the SQL execution engine")
    assert any(h.kind == "ora7445_generic" for h in hits2)


def test_frames_add_component_hints() -> None:
    hits = kb_lookup(frames=["kglic0", "kglLock", "opiodr"])
    comp = [h for h in hits if h.kind == "component"]
    assert comp and "library cache" in comp[0].title


def test_alert_signatures_and_wait_events() -> None:
    hits = kb_lookup(alert_signature="FREEPDB1(3):ORA-00060: Deadlock detected. See Note 60.1")
    assert hits[0].kind == "alert" and hits[0].title == "Deadlock detected"
    hits = kb_lookup(
        wait_events=["enq: TX - row lock contention", "cell single block physical read", "nope"]
    )
    kinds = [h.kind for h in hits]
    assert kinds.count("wait_event") == 2
    assert any("Exadata" in h.meaning for h in hits)


def test_exadata_checks_only_for_exacc() -> None:
    assert not [h for h in kb_lookup(problem_key="ORA 600 [x]") if h.kind == "exadata_check"]
    hits = kb_lookup(problem_key="ORA 600 [x]", platform="exacc")
    assert [h for h in hits if h.kind == "exadata_check"]
