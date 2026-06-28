"""End-to-end: a real MCP client connects over Streamable HTTP with a Bearer key.

Proves the gateway is a drop-in MCP server (what Claude Code / Cline would do),
not just a curl target. Runs the app under uvicorn in a thread and drives it with
the SDK's streamable_http_client. Uses MockUpstream, so no project #6 needed.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
import threading
import time
from pathlib import Path

import pytest
import uvicorn
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

from mcp_gateway.app import create_app
from mcp_gateway.config import Settings
from mcp_gateway.upstream import MockUpstream

_ROOT = Path(__file__).resolve().parents[1]


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture
def server_url(tmp_path):
    settings = Settings(
        policy_path=_ROOT / "policy.yaml",
        audit_path=tmp_path / "audit.jsonl",
        upstream_kind="mock",
        upstream_cmd=[],
        guardrails=True,
    )
    app = create_app(settings=settings, upstream=MockUpstream())
    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(100):  # wait for startup (max ~10s)
        if server.started:
            break
        time.sleep(0.1)
    yield f"http://127.0.0.1:{port}/mcp"
    server.should_exit = True
    thread.join(timeout=5)


@contextlib.asynccontextmanager
async def _connect(url: str, key: str):
    """A real MCP client session authenticated with a Bearer key."""
    headers = {"Authorization": f"Bearer {key}"}
    async with streamablehttp_client(url, headers=headers) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            yield session


def test_real_client_sees_allowlisted_tools(server_url):
    async def go():
        async with _connect(server_url, "dev-analyst-key") as session:
            return {t.name for t in (await session.list_tools()).tools}

    names = asyncio.run(go())
    # analyst's list is filtered to its allow-list; the privileged tool is hidden
    assert "trivy_fs_scan" in names and "lookup_invoice" not in names


def test_real_client_call_denied_and_redacted(server_url):
    async def go():
        # admin may call the poisoned tool; the secret is redacted in the result
        async with _connect(server_url, "dev-admin-key") as session:
            res = await session.call_tool("lookup_invoice", {})
            text = res.content[0].text
            assert "sk-LAB-1337" not in text and "[REDACTED]" in text

        # a least-privileged client is refused the tool entirely
        async with _connect(server_url, "dev-analyst-key") as session:
            denied = await session.call_tool("lookup_invoice", {})
            assert denied.isError

    asyncio.run(go())
