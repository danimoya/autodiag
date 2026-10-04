from types import SimpleNamespace

import pytest
from fastmcp import FastMCP
from starlette.testclient import TestClient

from autodiag.cli import cmds_serve


@pytest.mark.parametrize("token", [None, "test-only-secret"])
def test_standalone_http_uses_shared_authentication(monkeypatch, token):
    captured = {}

    class Server:
        def run(self, **kw):
            captured.update(kw)

    settings = SimpleNamespace(mcp_token=token, listen_host="127.0.0.1", listen_port=8790)
    monkeypatch.setattr(cmds_serve, "_server", lambda: (Server(), settings))
    cmds_serve.http(host=None, port=None)
    server = FastMCP("auth-test")
    app = server.http_app(
        path="/mcp", middleware=captured["middleware"], stateless_http=True, json_response=True
    )
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1"},
        },
    }
    headers = {"Accept": "application/json, text/event-stream"}
    with TestClient(app) as client:
        if token:
            for value in (None, "Bearer wrong"):
                h = {**headers, **({"Authorization": value} if value else {})}
                assert client.post("/mcp", json=body, headers=h).status_code == 401
        h = {**headers, **({"Authorization": f"Bearer {token}"} if token else {})}
        response = client.post("/mcp", json=body, headers=h)
        assert response.status_code == 200
        assert "result" in response.json()
