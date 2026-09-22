from pathlib import Path

import pytest

from autodiag.trace.callstack import parse_call_stack_trace, parse_short_stack
from autodiag.trace.header import parse_header
from autodiag.trace.incident import parse_incident
from autodiag.trace.models import TraceKind


@pytest.fixture
def incident_text(fixtures_dir: Path) -> str:
    return (fixtures_dir / "23ai/traces/incident_ora7445.trc").read_text()


def test_header(incident_text: str) -> None:
    h = parse_header(incident_text.splitlines())
    assert h.trace_file.endswith("incdir_8275/FREE_ora_1753_i8275.trc")
    assert h.oracle_version == "23.26.3.0.0"
    assert h.build_label == "RDBMS_23.26.3.0.0DBRU_LINUX.X64_260704"
    assert h.oracle_home == "/opt/oracle/product/26ai/dbhomeFree"
    assert h.node_name == "oradb-test"
    assert h.instance_name == "FREE"
    assert h.db_unique_name == "FREE"
    assert h.oracle_pid == 33 and h.ospid == 1753
    assert h.image == "oracle@oradb-test"
    assert h.session_id == 178 and h.session_serial == 56539
    assert h.service_name == "freepdb1" and h.module == "SQL*Plus" and h.container_id == 3
    assert h.client_ip == "127.0.0.1"
    assert h.first_ts is not None and h.first_ts.isoformat().startswith("2026-09-22T11:49:52")


def test_call_stack_trace_handles_wrapped_frames(incident_text: str) -> None:
    lines = incident_text.splitlines()
    start = next(i for i, ln in enumerate(lines) if ln.startswith("----- Call Stack Trace -----"))
    stack = parse_call_stack_trace(lines, start)
    funcs = [f.func for f in stack.frames]
    assert funcs[:4] == ["ksedst1", "ksedst", "dbkedDefDump", "ksedmp"]
    assert stack.frames[2].offset == 26900  # wrapped: "dbkedDefDump()+2690" + "0"
    assert stack.frames[0].call_type == "call" and stack.frames[0].entry == "kgdsdst"
    assert "sslssSynchHdlr" in funcs and stack.frames[funcs.index("sslssSynchHdlr")].offset == 471
    assert stack.frames[0].raw.startswith("ksedst1()+95")


def test_short_stack() -> None:
    frames = parse_short_stack(
        "ksedsts<-ksdxfstk<-ksdxcb<-sspuser<-__sighandler()<-semtimedop<-sskgpwwait<-ksliwat"
    )
    assert frames[:3] == ["ksedsts", "ksdxfstk", "ksdxcb"]
    assert "__sighandler" in frames and "ksliwat" in frames
    assert parse_short_stack("ksedsts()+409<-ksdxfstk()+520<-ksudss_opt()+338")[1] == "ksdxfstk"


def test_parse_incident(incident_text: str) -> None:
    inc = parse_incident(incident_text)
    assert inc.kind is TraceKind.INCIDENT
    assert inc.incident_id == 8275
    assert inc.problem_key == "ORA 7445 [qeilbk1]"
    assert inc.error_line.startswith("ORA-07445: exception encountered: core dump [qeilbk1()+1746]")
    assert inc.error_code == 7445
    assert inc.error_args[:2] == ["qeilbk1()+1746", "SIGSEGV"]
    assert inc.exception is not None
    assert inc.exception.signal == "SIGSEGV" and inc.exception.function == "qeilbk1"
    assert inc.exception.pc == "0x19518052"
    assert inc.current_sql == "SELECT COUNT(*) FROM CUSTOMERS WHERE CUSTOMER_ID BETWEEN 1 AND 100"
    assert inc.sql_id == "2cbq3fnthp7ut"
    assert inc.plsql_stack[0].name == "package body AUTODIAG_TEST.PKG_ORDERS.BUSY_LOOP"
    assert inc.plsql_stack[0].line == 54
    assert inc.call_stack is not None and inc.call_stack.frames[0].func == "ksedst1"
    assert inc.continued_from == "/opt/oracle/diag/rdbms/free/FREE/trace/FREE_ora_1753.trc"
    # compact context frames from the Incident Context Dump
    ctx = inc.context_frames
    assert [c.func for c in ctx[:3]] == [
        "dbgexExplicitEndInc",
        "dbgeEndDDEInvocationImpl",
        "ssexhd",
    ]
    sig = next(c for c in ctx if c.signaling)
    assert sig.func == "qeilbk1" and sig.index == 6
    assert next(c for c in ctx if c.func == "qerixtFetch").component == "SQL_Execution"
    assert inc.first_app_frame == "qeilbk1"
    assert inc.summary_lines()[0].startswith("ORA 7445 [qeilbk1]")
