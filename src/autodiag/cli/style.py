"""ANSI styling for the diagnosis text. Colours are added here and dropped by click when
the output is not a terminal, so pipes and files receive plain text."""

from __future__ import annotations

import re

import typer

SEVERITY_COLOR = {"critical": "red", "warning": "yellow", "info": "cyan", "noise": "bright_black"}

_HEADLINE = re.compile(r"^(CRITICAL|WARNING|INFO|NOISE):")
_CONCERN = re.compile(r"^( \d+\. )\[(critical|warning|info|noise)/(\w+)\] (.*)$")
_PROOF = re.compile(r"^(\s+)(proof|UNVERIFIED) (\S+): (.*)$")
_NEXT = re.compile(r"^(\s+)next: (.*)$")
_SECTION = re.compile(
    r"^(Concerns|Dismissed \(\d+\)|Suggested actions|Open questions|Evidence considered"
    r"|Dossier items|Concerns: none proven\.)"
)
_DIM_PREFIXES = ("   model ", "   top noise:", "Notes:", "Findings recorded:", "--- [")


def colorize_lines(lines: list[str]) -> list[str]:
    """Style the lines of ``diagnosis_lines`` for a terminal."""
    out: list[str] = []
    section = ""
    for line in lines:
        m = _SECTION.match(line)
        if m:
            section = m.group(1)
        out.append(_colorize(line, section))
    return out


def _colorize(line: str, section: str) -> str:
    if line.startswith("== "):
        return typer.style(line, bold=True)
    if line.startswith(_DIM_PREFIXES):
        return typer.style(line, dim=True)
    if line.startswith("Collector errors:"):
        return typer.style(line, fg="red")
    m = _HEADLINE.match(line)
    if m:
        color = SEVERITY_COLOR[m.group(1).lower()]
        return typer.style(m.group(0), fg=color, bold=True) + line[m.end() :]
    m = _CONCERN.match(line)
    if m:
        num, sev, kind, title = m.groups()
        return (
            num
            + typer.style(f"[{sev}/{kind}]", fg=SEVERITY_COLOR[sev])
            + " "
            + typer.style(title, bold=True)
        )
    m = _PROOF.match(line)
    if m:
        indent, mark, ev, quote = m.groups()
        return (
            indent
            + typer.style(mark, fg="green" if mark == "proof" else "red", bold=True)
            + " "
            + typer.style(ev, fg="magenta")
            + ": "
            + quote
        )
    m = _NEXT.match(line)
    if m:
        return m.group(1) + typer.style("next:", fg="cyan") + " " + m.group(2)
    if _SECTION.match(line):
        return typer.style(line, bold=True)
    if section.startswith("Dismissed") and line.startswith(" - "):
        return typer.style(line, dim=True)
    if line.startswith("title: "):
        return typer.style(line, bold=True)
    return line


__all__ = ["colorize_lines"]
