import typer

from autodiag.cli import common
from autodiag.mcp.server import default_context
from autodiag.web.app import create_app

app = typer.Typer(help="Run the web UI + REST API + MCP endpoint in one process.")


@app.callback(invoke_without_command=True)
def serve(
    host: str = typer.Option(None, "--host", help="Bind address (default: listen_host)."),
    port: int = typer.Option(None, "--port", help="Port (default: listen_port)."),
) -> None:
    """Serve the UI, /api/v1 and /mcp (loopback by default)."""
    import uvicorn

    s = common.settings()
    ctx = default_context(s, common.inventory(s))
    uvicorn.run(
        create_app(ctx), host=host or s.listen_host, port=port or s.listen_port, log_level="info"
    )
