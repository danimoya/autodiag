import typer

from autodiag.cli import common
from autodiag.mcp.server import build_server, default_context

app = typer.Typer(help="Run the MCP server (stdio for a local agent, HTTP for the shared service).")


def _server():
    s = common.settings()
    return build_server(default_context(s, common.inventory(s))), s


@app.command("stdio")
def stdio() -> None:
    """Serve MCP over stdio (what OpenCode's local MCP configuration launches)."""
    server, _ = _server()
    server.run(transport="stdio", show_banner=False)


@app.command("http")
def http(
    host: str = typer.Option(None, "--host", help="Bind address (default: listen_host)."),
    port: int = typer.Option(None, "--port", help="Port (default: listen_port)."),
) -> None:
    """Serve MCP over streamable HTTP at /mcp (bearer token from AUTODIAG_MCP_TOKEN when set)."""
    server, s = _server()
    server.run(
        transport="http",
        host=host or s.listen_host,
        port=port or s.listen_port,
        path="/mcp",
        show_banner=False,
    )


@app.command("selftest")
def selftest() -> None:
    """List the tools and call list_targets."""
    import asyncio

    server, _ = _server()

    async def go() -> None:
        tools = await server.list_tools()
        typer.echo(f"{len(tools)} tools: " + ", ".join(sorted(t.name for t in tools)))
        tool = await server.get_tool("list_targets")
        typer.echo(str(tool.fn()))

    asyncio.run(go())
