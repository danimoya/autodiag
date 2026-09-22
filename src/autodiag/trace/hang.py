"""``hanganalyze`` and ``systemstate`` dumps (often in one trace file)."""

from __future__ import annotations

import re
from collections import Counter

from pydantic import BaseModel, Field

from autodiag.trace.callstack import parse_short_stack
from autodiag.trace.header import parse_header, parse_timestamp_marker
from autodiag.trace.models import Section, TraceBase, TraceKind

_INSTANCES = re.compile(r"^\s+instances \(db_name\.oracle_sid\):\s+(\S+)")
_LIKELY = re.compile(r"^\s+\[(\w)\] Chain (\d+) Signature: (.+)$")
_CHAIN_HDR = re.compile(r"^Chain (\d+):\s*$")
_CHAIN_SIG = re.compile(r"^Chain (\d+) Signature: (.+)$")
_CHAIN_HASH = re.compile(r"^Chain (\d+) Signature Hash: (0x\w+)")
_SESSION_START = re.compile(r"^\s*(?:=> )?Oracle session identified by:")
_KV = re.compile(r"^\s+([a-z][a-z #_]*?):\s+(.+?)\s*$")
_WAITING = re.compile(r"^\s+(?:is|which is) waiting for '(.+?)'")
_NOT_WAITING = re.compile(r"^\s+(?:is|which is) not in a wait")
_BLOCKED_BY = re.compile(r"^\s+and is blocked by")
_NODE_STATE = re.compile(
    r"^\[(\d+)\]/(\d+)/(\d+)/(\d+)/(0x\w+)/(\d+)/(\w+)/\((0x\w+)\)/\{(\d+)\}(?:/\[([\d,]+)\])?"
)
_SS_HDR = re.compile(r"^SYSTEM STATE \(level=(\d+)(, with short stacks)?\)")
_SUMMARY_ROW = re.compile(
    r"^\s+(\d+): (\S+) ospid (\S+) sid (\d+) ser (\d+)(?:, waiting for '(.+?)')?"
)
_PROCESS_HDR = re.compile(r"^PROCESS (\d+):\s*(\S*)")
_OSPID = re.compile(r"^\s+ospid: (\d+)")
_SESSION = re.compile(r"^\s+\(session\) sid: (\d+) ser: (\d+)")
_WAIT_STACK = re.compile(r"^\s+0: waiting for '(.+?)'")
_SHORT_STACK = re.compile(r"^\s+Short stack dump: (.+)$")


class ChainNode(BaseModel):
    instance: int | None = None
    os_id: int | None = None
    process_id: int | None = None
    program: str | None = None
    session_id: int | None = None
    serial: int | None = None
    module: str | None = None
    pdb: str | None = None
    wait_event: str | None = None
    time_in_wait_s: float | None = None
    blocking_sessions: int = 0
    blocked_by_os_id: int | None = None
    sql_id: str | None = None
    current_sql: str | None = None
    short_stack: list[str] = Field(default_factory=list)
    is_blocked: bool = False


class Chain(BaseModel):
    number: int
    signature: str | None = None
    signature_hash: str | None = None
    likely_cause: bool = False
    nodes: list[ChainNode] = Field(default_factory=list)

    @property
    def final_blocker(self) -> ChainNode | None:
        return self.nodes[-1] if self.nodes else None


class NodeState(BaseModel):
    node: int
    cnode: int
    sid: int
    serial: int
    session_addr: str
    ospid: int
    state: str
    wait_hash: str
    time_in_wait_ms: int
    adjacent: list[int] = Field(default_factory=list)


class ProcessSummary(BaseModel):
    pid: int
    name: str
    ospid: str
    sid: int
    serial: int
    wait_event: str | None = None


class ProcessState(BaseModel):
    pid: int
    name: str
    ospid: int | None = None
    sid: int | None = None
    serial: int | None = None
    wait_event: str | None = None
    short_stack: list[str] = Field(default_factory=list)
    start_line: int = 0


class SystemState(BaseModel):
    level: int
    with_short_stacks: bool = False
    process_summary: list[ProcessSummary] = Field(default_factory=list)
    processes: list[ProcessState] = Field(default_factory=list)
    wait_histogram: dict[str, int] = Field(default_factory=dict)


class HangTrace(TraceBase):
    kind: TraceKind = TraceKind.HANG
    instances: str | None = None
    chains: list[Chain] = Field(default_factory=list)
    nodes_state: list[NodeState] = Field(default_factory=list)
    systemstate: SystemState | None = None


def parse_hang(text: str) -> HangTrace:
    lines = text.splitlines()
    doc = HangTrace(header=parse_header(lines), line_count=len(lines))
    sections: list[Section] = []
    likely: dict[int, str] = {}
    chain: Chain | None = None
    node: ChainNode | None = None
    in_session_block = False
    in_wait_block = False
    ss: SystemState | None = None
    proc: ProcessState | None = None
    for i, line in enumerate(lines):
        ts = parse_timestamp_marker(line)
        if ts:
            doc.timestamps.append(ts)
        if line.startswith("HANG ANALYSIS:"):
            sections.append(
                Section(kind="hang_analysis", title=line, start_line=i + 1, end_line=i + 1)
            )
            continue
        m = _INSTANCES.match(line)
        if m:
            doc.instances = m.group(1)
            continue
        m = _LIKELY.match(line)
        if m:
            likely[int(m.group(2))] = m.group(3)
            continue
        m = _CHAIN_HDR.match(line)
        if m:
            chain = Chain(number=int(m.group(1)), likely_cause=int(m.group(1)) in likely)
            doc.chains.append(chain)
            node = None
            continue
        if chain is not None:
            if _SESSION_START.match(line):
                node = ChainNode(
                    is_blocked=line.lstrip().startswith("=>") is False and bool(chain.nodes)
                )
                chain.nodes.append(node)
                in_session_block, in_wait_block = True, False
                continue
            if node is not None:
                wm = _WAITING.match(line)
                if wm:
                    node.wait_event = wm.group(1)
                    in_session_block, in_wait_block = False, True
                    continue
                if _NOT_WAITING.match(line):
                    node.wait_event = None
                    in_session_block, in_wait_block = False, True
                    continue
                if _BLOCKED_BY.match(line):
                    node.is_blocked = True
                    in_wait_block = False
                    continue
                kv = _KV.match(line)
                if kv and (in_session_block or in_wait_block):
                    _apply_kv(node, kv.group(1).strip(), kv.group(2))
            sm = _CHAIN_SIG.match(line)
            if sm and int(sm.group(1)) == chain.number:
                chain.signature = sm.group(2).strip()
                continue
            hm = _CHAIN_HASH.match(line)
            if hm and int(hm.group(1)) == chain.number:
                chain.signature_hash = hm.group(2)
                chain = None
                node = None
                continue
        m = _NODE_STATE.match(line)
        if m and not any(n.node == int(m.group(1)) for n in doc.nodes_state):
            doc.nodes_state.append(
                NodeState(
                    node=int(m.group(1)),
                    cnode=int(m.group(2)),
                    sid=int(m.group(3)),
                    serial=int(m.group(4)),
                    session_addr=m.group(5),
                    ospid=int(m.group(6)),
                    state=m.group(7),
                    wait_hash=m.group(8),
                    time_in_wait_ms=int(m.group(9)),
                    adjacent=[int(x) for x in m.group(10).split(",")] if m.group(10) else [],
                )
            )
            continue
        m = _SS_HDR.match(line)
        if m:
            ss = SystemState(level=int(m.group(1)), with_short_stacks=bool(m.group(2)))
            doc.systemstate = ss
            sections.append(
                Section(kind="systemstate", title=line, start_line=i + 1, end_line=i + 1)
            )
            continue
        if ss is not None:
            sm = _SUMMARY_ROW.match(line)
            if sm and proc is None:
                ss.process_summary.append(
                    ProcessSummary(
                        pid=int(sm.group(1)),
                        name=sm.group(2),
                        ospid=sm.group(3),
                        sid=int(sm.group(4)),
                        serial=int(sm.group(5)),
                        wait_event=sm.group(6),
                    )
                )
                continue
            pm = _PROCESS_HDR.match(line)
            if pm:
                proc = ProcessState(pid=int(pm.group(1)), name=pm.group(2), start_line=i + 1)
                ss.processes.append(proc)
                continue
            if proc is not None:
                if (om := _OSPID.match(line)) and proc.ospid is None:
                    proc.ospid = int(om.group(1))
                elif (sm2 := _SESSION.match(line)) and proc.sid is None:
                    proc.sid, proc.serial = int(sm2.group(1)), int(sm2.group(2))
                elif (wm := _WAIT_STACK.match(line)) and proc.wait_event is None:
                    proc.wait_event = wm.group(1)
                elif (ssm := _SHORT_STACK.match(line)) and not proc.short_stack:
                    proc.short_stack = parse_short_stack(ssm.group(1))
    if ss is not None:
        ss.wait_histogram = dict(Counter(p.wait_event for p in ss.process_summary if p.wait_event))
    doc.sections = sections
    return doc


def _apply_kv(node: ChainNode, key: str, value: str) -> None:
    if key == "instance":
        node.instance = _lead_int(value)
    elif key == "os id":
        node.os_id = _lead_int(value)
    elif key == "process id":
        node.process_id = _lead_int(value)
        parts = [p.strip() for p in value.split(",")]
        node.program = parts[1] if len(parts) > 1 else None
    elif key == "session id":
        node.session_id = _lead_int(value)
    elif key == "session serial #":
        node.serial = _lead_int(value)
    elif key == "module name":
        m = re.search(r"\((.*)\)", value)
        node.module = m.group(1) if m else value
    elif key == "pdb id":
        m = re.search(r"\((.*)\)", value)
        node.pdb = m.group(1) if m else value
    elif key == "time in wait":
        m = re.match(r"([\d.]+) sec", value)
        node.time_in_wait_s = float(m.group(1)) if m else None
    elif key == "blocking":
        node.blocking_sessions = _lead_int(value) or 0
    elif key == "immediate blockers":
        m = re.search(r"os id: (\d+)", value)
        node.blocked_by_os_id = int(m.group(1)) if m else None
    elif key == "current sql_id":
        m = re.search(r"\((\w+)\)", value)
        node.sql_id = m.group(1) if m else value
    elif key == "current sql":
        node.current_sql = value
    elif key == "short stack":
        node.short_stack = parse_short_stack(value)


def _lead_int(value: str) -> int | None:
    m = re.match(r"(\d+)", value.strip())
    return int(m.group(1)) if m else None
