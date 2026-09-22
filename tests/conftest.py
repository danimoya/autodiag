from pathlib import Path

import pytest

from autodiag.core.models import Node
from autodiag.transport.ssh import CommandResult

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture
def fixtures_dir() -> Path:
    return REPO_ROOT / "tests" / "fixtures"


class FakeTransport:
    """Answers allowlisted commands from adrci fixture files; records calls."""

    FILES = {
        "adrci_show_homes": "show_homes.txt",
        "adrci_show_problem": "show_problem.txt",
        "adrci_show_incident": "show_incident_brief.txt",
        "adrci_show_incident_by_id": "show_incident_detail.txt",
    }

    def __init__(self, node: Node, adrci_dir: Path) -> None:
        self.node = node
        self.dir = adrci_dir
        self.calls: list[tuple[str, dict]] = []

    def run(self, name, params, **kw):
        self.calls.append((name, params))
        if name in self.FILES:
            out = (self.dir / self.FILES[name]).read_text()
        elif name == "grep_file":
            out = f"12:ORA-00060: Deadlock detected. More info in file {params['path']}.\n"
        else:
            out = ""
        return CommandResult(name=name, argv=[name], returncode=0, stdout=out)

    def fetch(self, path, dest, **kw):
        dest.parent.mkdir(parents=True, exist_ok=True)
        src = REPO_ROOT / "tests/fixtures/23ai/alertlog/alert_excerpt.log"
        dest.write_text(src.read_text() if path.endswith(".log") else "fetched:" + path)
        return CommandResult(name="cat_file", argv=["cat", path], returncode=0, stdout=str(dest))


@pytest.fixture
def fake_transport_factory(fixtures_dir: Path):
    adrci_dir = fixtures_dir / "23ai" / "adrci"
    return lambda node: FakeTransport(node, adrci_dir)
