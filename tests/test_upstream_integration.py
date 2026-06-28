"""Live integration: the stdio upstream against project #6.

Skipped unless mcp-security-toolkit (#6) and uv are present locally, so the
fast unit suite still runs anywhere. Drives the async upstream with asyncio.run
so no pytest-async plugin is needed.
"""

from __future__ import annotations

import asyncio
import shutil
from pathlib import Path

import pytest

from mcp_gateway.upstream import StdioUpstream

_SIX = Path(__file__).resolve().parents[2] / "mcp-security-toolkit"

pytestmark = pytest.mark.skipif(
    not (_SIX / "pyproject.toml").exists() or shutil.which("uv") is None,
    reason="needs project #6 (mcp-security-toolkit) and uv installed",
)


def test_stdio_upstream_lists_real_tools_from_project_6():
    cmd = ["uv", "run", "--project", str(_SIX), "mcp-security-toolkit"]

    async def go() -> set[str]:
        up = StdioUpstream(cmd)
        await up.connect()
        try:
            return {t.name for t in await up.list_tools()}
        finally:
            await up.aclose()

    names = asyncio.run(go())
    # #6 exposes these scanner tools — the gateway now proxies the real server.
    assert {"trivy_fs_scan", "gitleaks_scan"} <= names
