"""Text and Markdown rendering of a Diagnosis for the CLI, the web UI and reports."""

from __future__ import annotations

from autodiag.diagnose.models import Diagnosis


def _ts(dt) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S") if dt else "-"


def diagnosis_lines(d: Diagnosis, *, dossier: bool = False) -> list[str]:
    a, ds = d.assessment, d.dossier
    counts = ds.counts()
    scope = ", ".join(f"{k}={v}" for k, v in ds.scope.items() if v is not None)
    out = [
        f"== {ds.target} | {ds.mode} | {scope} | {_ts(ds.generated_at)} UTC",
        f"   model {a.model}"
        + (f", proofs {a.proofs_verified}/{a.proofs_total} verified" if a.proofs_total else "")
        + f", confidence {a.confidence:.0%}"
        + (f", {a.elapsed_ms / 1000:.0f}s" if a.elapsed_ms else "")
        + (f", case {d.case_id}" if d.case_id else ""),
        "",
        f"{a.severity.value.upper()}: {a.headline}",
        "",
    ]
    if a.concerns:
        out.append("Concerns:")
        for i, c in enumerate(a.concerns, 1):
            out.append(f" {i}. [{c.severity.value}/{c.kind}] {c.title}")
            if c.assessment:
                out.append(f"    {c.assessment}")
            for p in c.proofs:
                mark = "proof" if p.verified else "UNVERIFIED"
                out.append(f'    {mark} {p.evidence_id}: "{p.quote}"')
            for n in c.next_checks:
                out.append(f"    next: {n}")
    else:
        out.append("Concerns: none proven.")
    if a.dismissed:
        out.append("")
        out.append(f"Dismissed ({len(a.dismissed)}):")
        out += [f" - {x.what}: {x.reason}" for x in a.dismissed]
    if a.actions:
        out.append("")
        out.append("Suggested actions:")
        out += [f" - {x}" for x in a.actions]
    if a.open_questions:
        out.append("")
        out.append("Open questions:")
        out += [f" - {x}" for x in a.open_questions]
    out.append("")
    out.append(
        f"Evidence considered: {len(ds.items)} items ({counts['critical']} critical, "
        f"{counts['warning']} warning, {counts['info']} info); noise suppressed: "
        f"{counts['noise_records']} entries in {counts['noise_signatures']} signatures"
        + (
            f"; alert records seen {ds.stats.get('records_seen')}"
            if ds.stats.get("records_seen")
            else ""
        )
    )
    if ds.noise:
        top = ", ".join(f"{g.signature[:60]} x{g.count}" for g in ds.noise[:4])
        out.append(f"   top noise: {top}")
    if ds.errors:
        out.append("Collector errors: " + " | ".join(ds.errors[:6]))
    if a.notes:
        out.append("Notes: " + " | ".join(a.notes))
    if d.finding_ids:
        out.append(f"Findings recorded: {', '.join(d.finding_ids)}")
    if dossier:
        out.append("")
        out.append("Dossier items:")
        for it in ds.sorted_items():
            out.append(
                f"--- [{it.id}] {it.kind} | {it.severity_hint.value} | "
                f"{_ts(it.ts)} | {it.node or '-'}"
            )
            out.append(f"title: {it.title}")
            out += ["  " + ln for ln in it.text.splitlines()[:20]]
    return out


def diagnosis_markdown(d: Diagnosis) -> str:
    a, ds = d.assessment, d.dossier
    counts = ds.counts()
    scope = ", ".join(f"{k}={v}" for k, v in ds.scope.items() if v is not None)
    md = [
        f"# Diagnosis: {ds.target} ({ds.mode})",
        "",
        f"Scope {scope}; generated {_ts(ds.generated_at)} UTC; model `{a.model}`"
        + (f"; proofs {a.proofs_verified}/{a.proofs_total} verified" if a.proofs_total else "")
        + f"; confidence {a.confidence:.0%}.",
        "",
        f"## {a.severity.value.upper()}: {a.headline}",
        "",
        "## Concerns",
    ]
    for c in a.concerns:
        md.append(f"- **[{c.severity.value}/{c.kind}] {c.title}** {c.assessment}")
        for p in c.proofs:
            md.append(
                f'  - {"proof" if p.verified else "unverified"} `{p.evidence_id}`: "{p.quote}"'
            )
        for n in c.next_checks:
            md.append(f"  - next: {n}")
    if not a.concerns:
        md.append("- none proven")
    md += ["", "## Dismissed"] + [f"- {x.what}: {x.reason}" for x in a.dismissed] or ["- none"]
    md += ["", "## Suggested actions"] + ([f"- {x}" for x in a.actions] or ["- none"])
    md += ["", "## Open questions"] + ([f"- {x}" for x in a.open_questions] or ["- none"])
    md += [
        "",
        "## Evidence considered",
        f"{len(ds.items)} items ({counts['critical']} critical, {counts['warning']} warning, "
        f"{counts['info']} info); {counts['noise_records']} routine entries in "
        f"{counts['noise_signatures']} signatures suppressed.",
        "",
        "| id | kind | hint | time | node | title |",
        "|---|---|---|---|---|---|",
    ]
    md += [
        f"| `{it.id}` | {it.kind} | {it.severity_hint.value} | {_ts(it.ts)} | "
        f"{it.node or '-'} | {it.title} |"
        for it in ds.sorted_items()
    ]
    if ds.noise:
        md += ["", "### Suppressed noise"] + [
            f"- {g.signature[:100]} x{g.count}" for g in ds.noise[:15]
        ]
    if ds.errors:
        md += ["", "### Collector errors"] + [f"- {e}" for e in ds.errors]
    if a.notes:
        md += ["", "### Notes"] + [f"- {n}" for n in a.notes]
    return "\n".join(md) + "\n"
