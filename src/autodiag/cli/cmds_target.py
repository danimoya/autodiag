import typer

from autodiag.cli import common

app = typer.Typer(help="Target inventory (databases AutoDiag may reach).")


@app.command("list")
def list_targets(as_json: bool = typer.Option(False, "--json")) -> None:
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
def show_target(name: str, as_json: bool = typer.Option(False, "--json")) -> None:
    t = common.target(name)
    lines = [f"{t.name}: {t.kind.value} on {t.platform.value}, version {t.oracle_version or '-'}"]
    lines += [f"  node {n.host} ssh={n.ssh_target} instance={n.instance or '-'}" for n in t.nodes]
    lines += [f"  adr_base={t.adr_base} homes={t.adr_homes}", f"  allowed roots={t.allowed_roots}"]
    common.emit(t, as_json=as_json, lines=lines)
