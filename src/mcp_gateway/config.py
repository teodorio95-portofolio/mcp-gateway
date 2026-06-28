"""Runtime configuration, read from the environment (12-factor, no secrets in code).

Every value has a safe local default so `mcp-gateway` runs with zero setup.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

# Repo root (…/mcp-gateway), used to resolve default file locations.
_ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class Settings:
    """Resolved gateway settings."""

    policy_path: Path
    audit_path: Path
    # Which upstream to use: "stdio" spawns a real MCP server, "mock" uses the
    # in-process fake (handy for an HTTP demo without project #6 present).
    upstream_kind: str
    # Command the gateway spawns to reach the upstream MCP server (stdio).
    # Defaults to the sibling project #6 (mcp-security-toolkit) if present.
    upstream_cmd: list[str]
    # "on" enables argument/result scanning; "off" is the vulnerable baseline.
    guardrails: bool


def load_settings() -> Settings:
    policy = Path(os.environ.get("MCPGW_POLICY", _ROOT / "policy.yaml"))
    audit = Path(os.environ.get("MCPGW_AUDIT", _ROOT / "audit.jsonl"))
    upstream = os.environ.get(
        "MCPGW_UPSTREAM_CMD",
        # The gateway fronts project #6 by spawning it on stdio.
        "uv run --project ../mcp-security-toolkit mcp-security-toolkit",
    ).split()
    guardrails = os.environ.get("GUARDRAILS", "on").strip().lower() != "off"
    kind = os.environ.get("MCPGW_UPSTREAM", "stdio").strip().lower()
    return Settings(
        policy_path=policy,
        audit_path=audit,
        upstream_kind=kind,
        upstream_cmd=upstream,
        guardrails=guardrails,
    )
