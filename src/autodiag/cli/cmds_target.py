import typer

from autodiag.cli import common
from autodiag.core.targets import remove_target

app = typer.Typer(help="Target inventory (databases AutoDiag may reach).")


@app.command("remove")
def remove_target_command(
    name: str = typer.Argument(..., help="Target name to remove from the inventory."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation."),
    as_json: bool = typer.Option(False, "--json", help="Emit JSON instead of text."),
) -> None:
    """Remove a target, keeping a backup of the inventory and existing case data."""
    settings = common.settings()
    common.target(name, settings)
    if not yes:
        typer.confirm(f"Remove target {name!r} from {settings.targets_file}?", abort=True)
    try:
        backup = remove_target(settings.targets_file, name)
    except (OSError, ValueError, KeyError, RuntimeError) as exc:
        typer.echo(f"Could not remove target: {exc}", err=True)
        raise typer.Exit(code=1) from None
    common.emit(
        {"removed": name, "backup": str(backup)},
        as_json=as_json,
        lines=[
            f"Removed target {name!r}. Inventory backup: {backup}",
            "Restart running AutoDiag services to reload the inventory.",
        ],
    )


@app.command("list")
def list_targets(
    as_json: bool = typer.Option(False, "--json", help="Emit JSON instead of a table."),
) -> None:
    """List the configured targets (from the targets file)."""
    inv = common.inventory()
    rows = [
        [
            t.name,
            t.kind.value,
            t.platform.value,
            t.oracle_version or "-",
            ", ".join(n.host for n in t.nodes),
            "yes" if t.sqlnet else "no",
        ]
        for t in inv.targets
    ]
    common.emit(
        inv,
        as_json=as_json,
        lines=common.table(rows, ["name", "kind", "platform", "version", "nodes", "sqlnet"]),
    )


@app.command("show")
def show_target(
    name: str = typer.Argument(..., help="Target name."),
    as_json: bool = typer.Option(False, "--json", help="Emit JSON instead of text."),
) -> None:
    """Show one target: nodes, SSH aliases, ADR base and homes, allowed roots."""
    t = common.target(name)
    lines = [f"{t.name}: {t.kind.value} on {t.platform.value}, version {t.oracle_version or '-'}"]
    lines += [f"  node {n.host} ssh={n.ssh_target} instance={n.instance or '-'}" for n in t.nodes]
    lines += [f"  adr_base={t.adr_base} homes={t.adr_homes}", f"  allowed roots={t.allowed_roots}"]
    common.emit(t, as_json=as_json, lines=lines)
