"""Transport-agnostic gateway core: the security pipeline, with no HTTP/MCP in it.

`GatewayCore.list_tools` / `call_tool` apply auth-resolved policy, scanning and
audit around an upstream. The HTTP/MCP layer (app.py), the offline demo and the
unit tests all drive this same core, so the security logic is tested once and
reused everywhere.

Denials are raised as exceptions so the transport can map them to MCP/JSON-RPC
errors:
  - ToolNotAllowed — tool is not on the client's allow-list (confused deputy)
  - InputBlocked   — an argument tripped the injection scanner
"""

from __future__ import annotations

from dataclasses import dataclass

from . import audit
from .config import Settings
from .policy import Client
from .scanner import ScanResult, scan_input, scan_output
from .upstream import Tool, Upstream


class GatewayError(Exception):
    """Base for gateway refusals (mapped to MCP errors by the transport)."""


class ToolNotAllowed(GatewayError):
    pass


class InputBlocked(GatewayError):
    pass


@dataclass(frozen=True)
class GatewayCore:
    settings: Settings
    upstream: Upstream

    async def list_tools(self, client: Client) -> list[Tool]:
        """Upstream tools, filtered to the client's allow-list, poisoned ones hidden."""
        visible: list[Tool] = []
        for tool in await self.upstream.list_tools():
            if not client.allows(tool.name):
                continue
            if self.settings.guardrails and not scan_input(tool.description).allowed:
                audit.record(
                    self.settings.audit_path,
                    client=client.name,
                    tool=tool.name,
                    action="list",
                    verdict="hidden",
                    reasons=["poisoned description"],
                )
                continue
            visible.append(tool)
        return visible

    async def call_tool(self, client: Client, name: str, arguments: dict) -> str:
        """Enforce allow-list + arg scan, forward to upstream, redact the result, audit."""
        if not client.allows(name):
            audit.record(
                self.settings.audit_path,
                client=client.name,
                tool=name,
                action="call",
                verdict="denied",
                reasons=["tool not in allow-list"],
            )
            raise ToolNotAllowed(f"tool {name!r} not permitted")

        if self.settings.guardrails:
            arg_scan = scan_input(" ".join(str(v) for v in arguments.values()))
            if not arg_scan.allowed:
                audit.record(
                    self.settings.audit_path,
                    client=client.name,
                    tool=name,
                    action="call",
                    verdict="blocked",
                    reasons=arg_scan.reasons,
                )
                raise InputBlocked("arguments blocked by guardrail")

        raw = await self.upstream.call_tool(name, arguments)
        out = scan_output(raw) if self.settings.guardrails else ScanResult(True, raw, [])
        audit.record(
            self.settings.audit_path,
            client=client.name,
            tool=name,
            action="call",
            verdict="sanitized" if out.reasons else "allowed",
            reasons=out.reasons,
        )
        return out.sanitized
