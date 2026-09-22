"""The reference docs must name every tool, route, SSH command and catalog query."""

from pathlib import Path

from autodiag.core.settings import load_settings
from autodiag.core.targets import load_targets
from autodiag.mcp.server import AutoDiagContext, build_server
from autodiag.sql.catalog import load_catalog
from autodiag.transport.allowlist import ALLOWLIST
from autodiag.web.app import create_app

DOCS = Path(__file__).resolve().parents[2] / "docs"
_SKIP_ROUTES = {"/api/openapi.json", "/api/docs", "/docs/oauth2-redirect", "/redoc"}


def _ctx(tmp_path, fixtures_dir, fake_transport_factory, monkeypatch) -> AutoDiagContext:
    monkeypatch.setenv("AUTODIAG_CONFIG", str(tmp_path / "none.toml"))
    monkeypatch.setenv("AUTODIAG_DATA_DIR", str(tmp_path / "data"))
    s = load_settings(env_file=None)
    inv = load_targets(fixtures_dir / "config" / "targets.yaml")
    return AutoDiagContext(
        s, inv, transport_factory=lambda t: fake_transport_factory, runner_factory=lambda t: None
    )


async def test_every_mcp_tool_and_query_is_in_mcp_doc(
    tmp_path, fixtures_dir, fake_transport_factory, monkeypatch
) -> None:
    doc = (DOCS / "mcp.md").read_text()
    server = build_server(_ctx(tmp_path, fixtures_dir, fake_transport_factory, monkeypatch))
    names = {t.name for t in await server.list_tools()}
    missing = sorted(n for n in names if f"`{n}`" not in doc)
    assert not missing, f"tools missing from docs/mcp.md: {missing}"
    missing_q = sorted(q for q in load_catalog() if f"`{q}`" not in doc)
    assert not missing_q, f"queries missing from docs/mcp.md: {missing_q}"


def test_every_route_is_in_gui_doc(tmp_path, fixtures_dir, fake_transport_factory, monkeypatch):
    doc = (DOCS / "gui.md").read_text()
    app = create_app(_ctx(tmp_path, fixtures_dir, fake_transport_factory, monkeypatch))
    paths = {r.path for r in app.routes if getattr(r, "path", None)} - _SKIP_ROUTES
    missing = sorted(p for p in paths if p not in doc)
    assert not missing, f"routes missing from docs/gui.md: {missing}"


def test_every_ssh_command_is_in_safety_doc() -> None:
    doc = (DOCS / "safety.md").read_text()
    missing = sorted(n for n in ALLOWLIST if f"`{n}`" not in doc)
    assert not missing, f"allowlist commands missing from docs/safety.md: {missing}"


def test_readme_links_every_doc() -> None:
    readme = (Path(__file__).resolve().parents[2] / "README.md").read_text()
    missing = sorted(p.name for p in DOCS.glob("*.md") if f"docs/{p.name}" not in readme)
    assert not missing, f"docs not linked from README: {missing}"
