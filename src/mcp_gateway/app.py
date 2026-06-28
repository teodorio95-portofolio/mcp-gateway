"""The gateway HTTP app (FastAPI).

A client speaks MCP-style JSON-RPC to POST /mcp with a Bearer API key. For every
request the gateway runs the security pipeline:

    1. auth        — Bearer key -> client (default-deny on unknown key)
    2. allow-list  — tools/list is filtered; tools/call is refused if not allowed
    3. scan args   — block tool arguments that look like prompt injection
    4. upstream    — forward the call to the protected MCP server
    5. scan result — redact secrets from the result before returning it
    6. audit       — append a JSONL record of the decision

This is the skeleton slice: a `MockUpstream`, a pattern-based scanner, and a
simplified JSON-RPC surface. Real llm-guard scanning, the stdio upstream to
project #6, and full MCP streamable-HTTP compliance land in follow-up PRs.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request

from . import audit
from .config import Settings, load_settings
from .policy import Client, Policy, load_policy
from .scanner import ScanResult, scan_input, scan_output
from .upstream import MockUpstream, StdioUpstream, Tool, Upstream


def _build_upstream(settings: Settings) -> Upstream:
    """Pick the upstream from config: a real stdio server, or the in-process mock."""
    if settings.upstream_kind == "mock":
        return MockUpstream()
    return StdioUpstream(settings.upstream_cmd)


def _jsonrpc_result(req_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _jsonrpc_error(req_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def create_app(settings: Settings | None = None, upstream: Upstream | None = None) -> FastAPI:
    settings = settings or load_settings()
    policy: Policy = load_policy(settings.policy_path)
    upstream = upstream or _build_upstream(settings)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        # A real stdio upstream is spawned once and reused for the app's lifetime.
        if isinstance(upstream, StdioUpstream):
            await upstream.connect()
        try:
            yield
        finally:
            if isinstance(upstream, StdioUpstream):
                await upstream.aclose()

    app = FastAPI(title="mcp-gateway", version="0.1.0", lifespan=lifespan)
    app.state.settings = settings
    app.state.policy = policy
    app.state.upstream = upstream

    def authenticate(authorization: str | None) -> Client:
        token = None
        if authorization and authorization.lower().startswith("bearer "):
            token = authorization[7:].strip()
        client = policy.client_for_key(token)
        if client is None:
            raise HTTPException(status_code=401, detail="invalid or missing API key")
        return client

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/mcp")
    async def mcp(
        request: Request, authorization: str | None = Header(default=None)
    ) -> dict[str, Any]:
        client = authenticate(authorization)
        body = await request.json()
        req_id = body.get("id")
        method = body.get("method")
        params = body.get("params") or {}

        if method == "initialize":
            return _jsonrpc_result(
                req_id, {"serverInfo": {"name": "mcp-gateway", "version": "0.1.0"}}
            )

        if method == "tools/list":
            tools: list[Tool] = await upstream.list_tools()
            visible: list[dict[str, str]] = []
            for t in tools:
                if not client.allows(t.name):
                    continue  # allow-list: hide tools the client can't use
                # Tool poisoning: a hidden instruction in the description.
                desc_scan = scan_input(t.description)
                if settings.guardrails and not desc_scan.allowed:
                    audit.record(
                        settings.audit_path,
                        client=client.name,
                        tool=t.name,
                        action="list",
                        verdict="hidden",
                        reasons=desc_scan.reasons,
                    )
                    continue
                visible.append({"name": t.name, "description": t.description})
            return _jsonrpc_result(req_id, {"tools": visible})

        if method == "tools/call":
            name = params.get("name", "")
            arguments = params.get("arguments") or {}

            if not client.allows(name):
                audit.record(
                    settings.audit_path,
                    client=client.name,
                    tool=name,
                    action="call",
                    verdict="denied",
                    reasons=["tool not in allow-list"],
                )
                return _jsonrpc_error(req_id, -32601, f"tool {name!r} not permitted")

            if settings.guardrails:
                arg_scan = scan_input(" ".join(str(v) for v in arguments.values()))
                if not arg_scan.allowed:
                    audit.record(
                        settings.audit_path,
                        client=client.name,
                        tool=name,
                        action="call",
                        verdict="blocked",
                        reasons=arg_scan.reasons,
                    )
                    return _jsonrpc_error(req_id, -32602, "arguments blocked by guardrail")

            raw = await upstream.call_tool(name, arguments)
            out = scan_output(raw) if settings.guardrails else ScanResult(True, raw, [])
            audit.record(
                settings.audit_path,
                client=client.name,
                tool=name,
                action="call",
                verdict="sanitized" if out.reasons else "allowed",
                reasons=out.reasons,
            )
            return _jsonrpc_result(req_id, {"content": [{"type": "text", "text": out.sanitized}]})

        return _jsonrpc_error(req_id, -32601, f"method {method!r} not supported")

    return app


def main() -> None:
    """Console entrypoint: serve the gateway with uvicorn."""
    import uvicorn

    uvicorn.run(create_app(), host="127.0.0.1", port=8080)
