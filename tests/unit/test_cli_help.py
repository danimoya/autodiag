"""Every CLI command answers -h and is documented in docs/cli.md."""

from pathlib import Path

from typer.testing import CliRunner

from autodiag.cli.main import app

DOC = Path(__file__).resolve().parents[2] / "docs" / "cli.md"


def _commands() -> list[tuple[str, ...]]:
    out: list[tuple[str, ...]] = []
    for group in app.registered_groups:
        sub = group.typer_instance
        assert sub is not None
        if not sub.registered_commands:
            out.append((group.name,))
        for cmd in sub.registered_commands:
            out.append((group.name, cmd.name))
    return out


def test_every_command_is_documented() -> None:
    doc = DOC.read_text()
    names = ["autodiag " + " ".join(parts) for parts in _commands()]
    missing = [n for n in names if n not in doc]
    assert not missing, f"undocumented commands: {missing}"


def test_dash_h_works_at_every_level() -> None:
    runner = CliRunner()
    for parts in [(), *_commands()]:
        result = runner.invoke(app, [*parts, "-h"])
        assert result.exit_code == 0, f"{parts}: {result.output}"
        assert "Usage" in result.output, parts


def test_every_command_has_a_description() -> None:
    for group in app.registered_groups:
        sub = group.typer_instance
        assert sub is not None
        for cmd in sub.registered_commands:
            assert cmd.callback is not None
            assert (cmd.callback.__doc__ or "").strip(), f"{group.name} {cmd.name} has no help"
