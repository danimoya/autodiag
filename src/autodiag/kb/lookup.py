"""Knowledge-base lookup: problem keys, kernel frames, alert signatures, wait events."""

from __future__ import annotations

import re

from pydantic import BaseModel, Field

from autodiag.kb.loader import component_of, load_yaml

_KEY = re.compile(r"^(ORA) (\d+)(?: \[(.*?)\])?")


class KbHit(BaseModel):
    # ora600 | ora600_generic | ora7445 | ora7445_generic | component | alert | wait_event
    # | exadata_check
    kind: str
    ref: str
    title: str
    meaning: str = ""
    typical_causes: list[str] = Field(default_factory=list)
    checks: list[str] = Field(default_factory=list)
    actions: list[str] = Field(default_factory=list)
    severity: str = ""
    mos_search: str | None = None

    def as_text(self) -> str:
        parts = [f"[{self.kind}] {self.title}"]
        if self.meaning:
            parts.append(f"  {self.meaning}")
        for label, items in (
            ("causes", self.typical_causes),
            ("checks", self.checks),
            ("actions", self.actions),
        ):
            if items:
                parts.append(f"  {label}: " + "; ".join(items))
        if self.mos_search:
            parts.append(f"  search My Oracle Support for: {self.mos_search}")
        return "\n".join(parts)


def _entry_hit(kind: str, ref: str, e: dict) -> KbHit:
    return KbHit(
        kind=kind,
        ref=ref,
        title=e.get("title", ""),
        meaning=e.get("meaning", ""),
        typical_causes=e.get("typical_causes", []),
        checks=e.get("checks", []),
        actions=e.get("actions", []),
        severity=e.get("severity", ""),
        mos_search=e.get("mos_search"),
    )


def kb_lookup(
    *,
    problem_key: str | None = None,
    frames: list[str] | None = None,
    alert_signature: str | None = None,
    wait_events: list[str] | None = None,
    platform: str = "generic",
) -> list[KbHit]:
    hits: list[KbHit] = []
    if problem_key:
        hits += _problem_key_hits(problem_key)
    if frames:
        seen: set[str] = set()
        for f in frames[:8]:
            comp = component_of(f)
            if comp and comp not in seen:
                seen.add(comp)
                hits.append(
                    KbHit(
                        kind="component",
                        ref=f,
                        title=f"{comp} ({f})",
                        meaning=f"frame {f} belongs to the {comp} layer",
                    )
                )
    if alert_signature:
        for e in load_yaml("alertlog_signatures.yaml").get("entries", []):
            if re.search(e["pattern"], alert_signature):
                hits.append(_entry_hit("alert", e["pattern"], e))
                break
    if wait_events:
        events = load_yaml("wait_events.yaml").get("events", {})
        for ev in wait_events:
            e = events.get(ev)
            if e:
                hits.append(
                    KbHit(
                        kind="wait_event",
                        ref=ev,
                        title=ev,
                        meaning=e.get("meaning", ""),
                        checks=e.get("checks", []),
                    )
                )
    if platform == "exacc":
        for c in load_yaml("exadata.yaml").get("checks", []):
            hits.append(
                KbHit(
                    kind="exadata_check",
                    ref=c["id"],
                    title=c["title"],
                    meaning=c.get("interpret", ""),
                    checks=[c.get("how", "")],
                )
            )
    return hits


def _problem_key_hits(problem_key: str) -> list[KbHit]:
    m = _KEY.match(problem_key.strip())
    if not m:
        return []
    number, arg = int(m.group(2)), (m.group(3) or "")
    out: list[KbHit] = []
    if number == 600:
        kb = load_yaml("ora600.yaml")
        for e in kb.get("entries", []):
            if problem_key.startswith(e["match"]):
                out.append(_entry_hit("ora600", e["match"], e))
                break
        out.append(_entry_hit("ora600_generic", "ORA-600", kb.get("generic", {})))
    elif number == 7445:
        kb = load_yaml("ora7445.yaml")
        func = re.match(r"([A-Za-z_][\w]*)", arg)
        fname = func.group(1) if func else ""
        for e in kb.get("entries", []):
            if fname and re.search(e["match_func"], fname):
                out.append(_entry_hit("ora7445", e["match_func"], e))
                break
        comp = component_of(fname) if fname else None
        if comp:
            out.append(
                KbHit(
                    kind="component",
                    ref=fname,
                    title=f"{comp} ({fname})",
                    meaning=f"signaling function {fname} belongs to the {comp} layer",
                )
            )
        out.append(_entry_hit("ora7445_generic", "ORA-7445", kb.get("generic", {})))
    else:
        sig = f"ORA-{number:05d}"
        for e in load_yaml("alertlog_signatures.yaml").get("entries", []):
            if re.search(e["pattern"], sig):
                out.append(_entry_hit("alert", e["pattern"], e))
                break
    return out
