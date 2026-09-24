"""The repository must not contain environment-specific identifiers.

Real hosts, addresses and home directories live only in git-ignored local config. The
forbidden words are assembled from fragments so this test does not trip itself.
"""

import re
import shutil
import subprocess
from pathlib import Path

_PARTS = [
    "".join(["g", "p", "c"]),
    r"100\.64\.",
    "".join(["ola", "res"]),
    "".join(["dm", "26"]),
]
FORBIDDEN = re.compile("|".join(_PARTS), re.IGNORECASE)
SKIP_PREFIXES = (".venv/", "data/")


def _listed_files(root: Path) -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    return [root / p for p in out if not p.startswith(SKIP_PREFIXES)]


def _is_binary(path: Path) -> bool:
    """Same rule as ``grep -I``: a NUL byte in the first block marks a binary file."""
    with path.open("rb") as fh:
        return b"\0" in fh.read(8192)


def test_no_environment_identifiers_in_repo(repo_root: Path) -> None:
    offenders: list[str] = []
    for path in _listed_files(repo_root):
        if not path.is_file() or _is_binary(path):
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for lineno, line in enumerate(text.splitlines(), 1):
            if FORBIDDEN.search(line):
                offenders.append(f"{path.relative_to(repo_root)}:{lineno}: {line.strip()[:80]}")
    assert not offenders, "environment-specific identifiers found:\n" + "\n".join(offenders)


def _run_hygiene(tmp_repo: Path) -> int:
    return subprocess.run(
        [str(tmp_repo / "scripts" / "hygiene.sh")], cwd=tmp_repo, capture_output=True
    ).returncode


def test_hygiene_script_detects_offending_file(tmp_path: Path, repo_root: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    (tmp_path / "scripts").mkdir()
    shutil.copy(repo_root / "scripts" / "hygiene.sh", tmp_path / "scripts" / "hygiene.sh")
    (tmp_path / "clean.txt").write_text("host: dbnode01.example.internal\n")
    assert _run_hygiene(tmp_path) == 0
    (tmp_path / "bad.txt").write_text("host: " + "".join(["ola", "res", "1"]) + "\n")
    assert _run_hygiene(tmp_path) == 1
