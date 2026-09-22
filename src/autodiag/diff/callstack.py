"""Kernel call-stack comparison: normalise, align, find the divergence, frame frequency."""

from __future__ import annotations

import re
from collections import Counter
from difflib import SequenceMatcher

from pydantic import BaseModel, Field

from autodiag.kb.loader import component_of
from autodiag.trace.incident import IncidentTrace

PRELUDE_FUNCS = frozenset(
    {
        "ksedst1",
        "ksedst",
        "dbkedDefDump",
        "ksedmp",
        "dbgexPhaseII",
        "dbgexProcessError",
        "dbgeExecuteForError",
        "dbgePostErrorKGE",
        "dbkePostKGE_kgsf",
        "kgeade",
        "kgerelv",
        "kgerev",
        "kgeasnmierr",
        "kgesinv",
        "kgesin",
        "kgesinva",
        "kgeasi",
        "ksfdmp",
        "dbgexExplicitEndInc",
        "dbgeEndDDEInvocationImpl",
        "ssexhd",
        "sslssSynchHdlr",
        "sslsshandler",
        "__sighandler",
        "__restore_rt",
        "skgesigOSErr",
        "skgesig_sigactionHandler",
        "ksdxfstk",
        "ksdxcb",
        "sspuser",
        "ksedsts",
        "kgdsdst",
        "dbgeEndDDEInvocation",
    }
)
TAIL_FUNCS = frozenset(
    {
        "main",
        "__libc_start_main",
        "__libc_start_call_main",
        "_start",
        "ssthrdmain",
        "opimai_real",
        "sou2o",
        "opidrv",
        "opiodr",
        "opiino",
        "opitsk",
        "ttcpip",
        "opiosq0",
        "kpoal8",
        "opirip",
        "ksbrdp_int",
        "ksbrdp",
    }
)
_FUNC = re.compile(r"^([A-Za-z_][\w.$]*)")


class NormalizedStack(BaseModel):
    frames: list[str]
    prelude: list[str] = Field(default_factory=list)
    tail: list[str] = Field(default_factory=list)
    source: str = "unknown"
    components: dict[str, str] = Field(default_factory=dict)

    @property
    def first_app_frame(self) -> str | None:
        return self.frames[0] if self.frames else None


class AlignedFrame(BaseModel):
    op: str  # equal | replace | delete | insert
    left: str | None = None
    right: str | None = None


class FrameFrequency(BaseModel):
    func: str
    count: int
    share: float
    signature: bool


class StackDiff(BaseModel):
    left: list[str]
    right: list[str]
    aligned: list[AlignedFrame]
    similarity: float
    common_prefix: int
    common_suffix: int
    divergence_index: int | None
    unique_left: list[str]
    unique_right: list[str]
    left_first_app_frame: str | None = None
    right_first_app_frame: str | None = None
    left_component: str | None = None
    right_component: str | None = None
    notes: list[str] = Field(default_factory=list)


def _clean(func: str) -> str:
    m = _FUNC.match(func.strip())
    return m.group(1) if m else func.strip()


def normalize_stack(funcs: list[str], *, source: str = "unknown") -> NormalizedStack:
    frames = [_clean(f) for f in funcs if f and f.strip() and f.strip() != "<unavailable>"]
    prelude: list[str] = []
    while frames and frames[0] in PRELUDE_FUNCS:
        prelude.append(frames.pop(0))
    tail: list[str] = []
    while frames and frames[-1] in TAIL_FUNCS:
        tail.insert(0, frames.pop())
    return NormalizedStack(frames=frames, prelude=prelude, tail=tail, source=source)


def stack_from_incident(inc: IncidentTrace) -> NormalizedStack:
    """Prefer the compact incident-context frames (they carry components); else the full
    Call Stack Trace."""
    if inc.context_frames:
        n = normalize_stack([c.func for c in inc.context_frames], source="incident_context")
        n.components = {c.func: c.component for c in inc.context_frames if c.component}
        return n
    if inc.call_stack:
        return normalize_stack(inc.call_stack.funcs, source="call_stack_trace")
    return NormalizedStack(frames=[], source="none")


def compare_stacks(left: list[str], right: list[str]) -> StackDiff:
    ln = normalize_stack(left)
    rn = normalize_stack(right)
    a, b = ln.frames, rn.frames
    sm = SequenceMatcher(None, a, b, autojunk=False)
    aligned: list[AlignedFrame] = []
    divergence: int | None = None
    for op, i1, i2, j1, j2 in sm.get_opcodes():
        if op == "equal":
            aligned.extend(
                AlignedFrame(op=op, left=a[k], right=b[k - i1 + j1]) for k in range(i1, i2)
            )
            continue
        if divergence is None:
            divergence = i1
        if op == "replace":
            n = max(i2 - i1, j2 - j1)
            for k in range(n):
                aligned.append(
                    AlignedFrame(
                        op=op,
                        left=a[i1 + k] if i1 + k < i2 else None,
                        right=b[j1 + k] if j1 + k < j2 else None,
                    )
                )
        elif op == "delete":
            aligned.extend(AlignedFrame(op=op, left=a[k]) for k in range(i1, i2))
        elif op == "insert":
            aligned.extend(AlignedFrame(op=op, right=b[k]) for k in range(j1, j2))
    prefix = 0
    while prefix < min(len(a), len(b)) and a[prefix] == b[prefix]:
        prefix += 1
    suffix = 0
    while suffix < min(len(a), len(b)) - prefix and a[-1 - suffix] == b[-1 - suffix]:
        suffix += 1
    set_b, set_a = set(b), set(a)
    unique_left = [f for f in a if f not in set_b]
    unique_right = [f for f in b if f not in set_a]
    lc = component_of(a[0]) if a else None
    rc = component_of(b[0]) if b else None
    notes: list[str] = []
    if divergence is None:
        notes.append("stacks are identical after removing the error-handling prelude")
    else:
        where = f"frame {divergence}"
        if a[:1] == b[:1]:
            notes.append(f"same first application frame {a[0]!r}; stacks diverge at {where}")
        else:
            notes.append(
                f"stacks diverge at {where}: {a[divergence] if divergence < len(a) else '-'!r} "
                f"vs {b[divergence] if divergence < len(b) else '-'!r}"
            )
        if lc and rc and lc != rc:
            notes.append(f"innermost frames belong to different components: {lc!r} vs {rc!r}")
        if suffix:
            notes.append(f"{suffix} outermost frame(s) are shared (same call path into the kernel)")
    return StackDiff(
        left=a,
        right=b,
        aligned=aligned,
        similarity=round(sm.ratio(), 4),
        common_prefix=prefix,
        common_suffix=suffix,
        divergence_index=divergence,
        unique_left=unique_left,
        unique_right=unique_right,
        left_first_app_frame=a[0] if a else None,
        right_first_app_frame=b[0] if b else None,
        left_component=lc,
        right_component=rc,
        notes=notes,
    )


def frame_frequency(
    stacks: list[list[str]], *, signature_share: float = 0.8
) -> list[FrameFrequency]:
    """Share of stacks (of one problem key) that contain each frame, in first-seen order."""
    if not stacks:
        return []
    order: list[str] = []
    counts: Counter[str] = Counter()
    for st in stacks:
        seen = set()
        for f in normalize_stack(st).frames:
            if f in seen:
                continue
            seen.add(f)
            counts[f] += 1
            if f not in order:
                order.append(f)
    n = len(stacks)
    return [
        FrameFrequency(
            func=f, count=counts[f], share=counts[f] / n, signature=counts[f] / n >= signature_share
        )
        for f in order
    ]
