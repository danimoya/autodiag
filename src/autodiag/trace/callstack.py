"""Kernel call stacks: the ``Call Stack Trace`` table, short stacks and context frames."""

from __future__ import annotations

import re
from collections.abc import Sequence

from autodiag.trace.models import CallStack, ContextFrame, Frame

_FRAME = re.compile(r"^(\S+?)\(\)(?:\+(\d+))?\s+(call|signal|ptr_call|jump)\s+(\S+?)\(\)")
_FRAME_NOENTRY = re.compile(r"^(\S+?)\(\)(?:\+(\d+))?\s+(call|signal|ptr_call|jump)\s+")
_CONTINUATION = re.compile(r"^(\S{1,20})\s{2,}\S")  # wrapped tail of the previous location
_BARE_CONT = re.compile(r"^(\S{1,20})\s*$")
_SHORT_FRAME = re.compile(r"([A-Za-z_][\w.$]*)(?:\(\))?(?:\+\d+)?")
_CTX = re.compile(r"^\[(\d+)\]: (\S+) \[([^\]]*)\](\s*<-- Signaling)?")
END_MARKER = "----- End of Call Stack Trace -----"


def parse_call_stack_trace(lines: Sequence[str], start: int) -> CallStack:
    """Parse the table that begins at ``lines[start]`` (the ``----- Call Stack Trace -----``
    header). Long ``func()+offset`` locations wrap to the next line; those continuation
    lines are glued back onto the previous frame."""
    frames: list[Frame] = []
    end = start
    i = start + 1
    # skip the three header lines (calling/location/------)
    while i < len(lines) and not lines[i].startswith("---"):
        i += 1
    i += 1
    while i < len(lines):
        line = lines[i]
        if line.startswith(END_MARKER) or line.startswith("----- End of Call Stack"):
            end = i
            break
        if line.startswith("----- ") or line.startswith("[TOC"):
            end = i
            break
        if line and not line[0].isspace():
            m = _FRAME.match(line) or _FRAME_NOENTRY.match(line)
            if m:
                frames.append(
                    Frame(
                        func=m.group(1),
                        offset=int(m.group(2)) if m.group(2) else None,
                        call_type=m.group(3),
                        entry=m.group(4) if m.re is _FRAME else None,
                        raw=line.strip(),
                    )
                )
            elif frames:
                cm = _CONTINUATION.match(line) or _BARE_CONT.match(line)
                if cm:
                    _glue(frames[-1], cm.group(1))
        i += 1
    return CallStack(frames=frames, start_line=start + 1, end_line=end + 1)


def _glue(frame: Frame, tail: str) -> None:
    """Append the wrapped characters to the previous frame's ``func()+offset``."""
    loc = frame.raw.split()[0] + tail
    frame.raw = loc + frame.raw[len(frame.raw.split()[0]) :]
    m = re.match(r"^(\S+?)\(\)(?:\+(\d+))?$", loc)
    if m:
        frame.func = m.group(1)
        frame.offset = int(m.group(2)) if m.group(2) else frame.offset


def parse_short_stack(text: str) -> list[str]:
    """``ksedsts()+409<-ksdxfstk()+520<-...`` or ``ksedsts<-ksdxfstk<-...`` → function names."""
    out: list[str] = []
    for part in text.strip().split("<-"):
        part = part.strip()
        if not part:
            continue
        m = _SHORT_FRAME.match(part)
        if m:
            out.append(m.group(1))
    return out


def parse_context_frames(lines: Sequence[str], start: int) -> list[ContextFrame]:
    """``[NN]: func [component]`` lines following ``----- Incident Context Dump -----``."""
    frames: list[ContextFrame] = []
    for line in lines[start:]:
        m = _CTX.match(line)
        if m:
            frames.append(
                ContextFrame(
                    index=int(m.group(1)),
                    func=m.group(2),
                    component=m.group(3),
                    signaling=bool(m.group(4)),
                )
            )
        elif frames:
            break
    return frames
