"""Shared bearer authentication for the combined service and standalone MCP HTTP."""

from secrets import compare_digest

from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse


class BearerMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, token: str | None) -> None:
        super().__init__(app)
        self.token = token

    async def dispatch(self, request, call_next):
        path = request.url.path
        protected = path in {"/api", "/mcp"} or path.startswith(("/api/", "/mcp/"))
        if self.token and protected:
            actual = request.headers.get("authorization", "").encode()
            expected = f"Bearer {self.token}".encode()
            if not compare_digest(actual, expected):
                return JSONResponse({"error": "unauthorized"}, status_code=401)
        return await call_next(request)


def http_middleware(token: str | None) -> list[Middleware]:
    return [Middleware(BearerMiddleware, token=token)]
