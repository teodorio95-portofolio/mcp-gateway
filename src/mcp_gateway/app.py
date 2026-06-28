"""The gateway as a real MCP server over Streamable HTTP.

A client (Claude Code, Cline, an agent) connects to POST /mcp with a Bearer API
key, exactly as it would to any MCP server. The gateway authenticates the key to
a client, then runs every `tools/list` / `tools/call` through the security
pipeline (`GatewayCore`) before proxying to the upstream MCP server.

The MCP protocol itself is handled by the SDK's low-level `Server` +
`StreamableHTTPSessionManager` — we don't hand-roll JSON-RPC/SSE. Per-request
auth is done in an ASGI shim that resolves the key and stashes the client in a
context var the tool handlers read.
"""

from __future__ import annotations

import contextlib
from contextvars import ContextVar

import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route
from starlette.types import Receive, Scope, Send

from .config import Settings, load_settings
from .gateway import GatewayCore, GatewayError
from .policy import Client, Policy, load_policy
from .upstream import MockUpstream, StdioUpstream, Upstream

# The client resolved from the Bearer key for the in-flight request. Set by the
# ASGI auth shim, read by the MCP tool handlers (same task -> context propagates).
_current_client: ContextVar[Client | None] = ContextVar("current_client", default=None)


def _build_upstream(settings: Settings) -> Upstream:
    """Pick the upstream from config: a real stdio server, or the in-process mock."""
    if settings.upstream_kind == "mock":
        return MockUpstream()
    return StdioUpstream(settings.upstream_cmd)


def _authenticate(policy: Policy, authorization: str | None) -> Client | None:
    token = None
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
    return policy.client_for_key(token)


def create_app(settings: Settings | None = None, upstream: Upstream | None = None) -> Starlette:
    settings = settings or load_settings()
    policy = load_policy(settings.policy_path)
    upstream = upstream or _build_upstream(settings)
    core = GatewayCore(settings, upstream)

    server: Server = Server("mcp-gateway")

    @server.list_tools()
    async def _list_tools() -> list[types.Tool]:
        client = _current_client.get()
        assert client is not None  # the auth shim guarantees this
        tools = await core.list_tools(client)
        return [
            types.Tool(name=t.name, description=t.description, inputSchema=t.input_schema)
            for t in tools
        ]

    @server.call_tool()
    async def _call_tool(name: str, arguments: dict) -> list[types.ContentBlock]:
        client = _current_client.get()
        assert client is not None
        try:
            text = await core.call_tool(client, name, arguments or {})
        except GatewayError as exc:
            # Surfaced to the client as an MCP tool error (isError=true).
            raise ValueError(str(exc)) from exc
        return [types.TextContent(type="text", text=text)]

    session_manager = StreamableHTTPSessionManager(app=server, stateless=True, json_response=True)

    async def mcp_endpoint(scope: Scope, receive: Receive, send: Send) -> None:
        client = _authenticate(policy, Request(scope, receive).headers.get("authorization"))
        if client is None:
            await JSONResponse({"error": "invalid or missing API key"}, status_code=401)(
                scope, receive, send
            )
            return
        token = _current_client.set(client)
        try:
            await session_manager.handle_request(scope, receive, send)
        finally:
            _current_client.reset(token)

    async def healthz(_request: Request) -> JSONResponse:
        return JSONResponse({"status": "ok"})

    @contextlib.asynccontextmanager
    async def lifespan(_app: Starlette):
        if isinstance(upstream, StdioUpstream):
            await upstream.connect()
        try:
            async with session_manager.run():
                yield
        finally:
            if isinstance(upstream, StdioUpstream):
                await upstream.aclose()

    app = Starlette(
        routes=[Route("/healthz", healthz, methods=["GET"]), Mount("/mcp", app=mcp_endpoint)],
        lifespan=lifespan,
    )
    app.state.core = core
    return app


def main() -> None:
    """Console entrypoint: serve the gateway with uvicorn."""
    import uvicorn

    uvicorn.run(create_app(), host="127.0.0.1", port=8080)
