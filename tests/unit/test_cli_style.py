"""Terminal styling of the diagnosis text."""

import re

from autodiag.cli.style import colorize_lines

ANSI = re.compile(r"\x1b\[[0-9;]*m")


def test_severity_headline_and_proofs_are_styled() -> None:
    lines = [
        "== testbed | problem | problem_key=ORA 600 [x] | 2026-01-01 00:00:00 UTC",
        "CRITICAL: something bad",
        "Concerns:",
        " 1. [critical/root_cause] Recurring ORA-00600",
        '    proof ev_1: "ORA-00600: internal error"',
        '    UNVERIFIED ev_2: "not there"',
        "    next: check the trace",
        "Dismissed (1):",
        " - JIT: pid <n> x3: routine",
        "plain line",
    ]
    out = colorize_lines(lines)
    assert "\x1b[31m" in out[1] and out[1].endswith("something bad")  # red headline
    assert "\x1b[32m" in out[4] and "\x1b[31m" in out[5]  # green proof, red unverified
    assert "\x1b[2m" in out[8]  # dismissed items are dim
    assert out[9] == "plain line"
    assert [ANSI.sub("", ln) for ln in out] == lines  # styling never changes the text


def test_headline_severity_colors_differ() -> None:
    crit, warn, info = colorize_lines(["CRITICAL: a", "WARNING: b", "INFO: c"])
    assert "\x1b[31m" in crit and "\x1b[33m" in warn and "\x1b[36m" in info
