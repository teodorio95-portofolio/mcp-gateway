"""Policy: the single source of truth mapping a client API key to the tools it
may call. Loaded from policy.yaml.

    clients:
      - name: analyst
        api_key: "dev-analyst-key"
        allow_tools: ["trivy_fs_scan", "gitleaks_scan"]
      - name: admin
        api_key: "dev-admin-key"
        allow_tools: ["*"]            # "*" = every tool the upstream exposes

Default-deny: an unknown key resolves to no client, and a client may only call
tools on its allow-list.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass(frozen=True)
class Client:
    name: str
    api_key: str
    allow_tools: tuple[str, ...] = field(default_factory=tuple)

    def allows(self, tool: str) -> bool:
        """True if this client may call `tool` (explicit allow-list, or "*")."""
        return "*" in self.allow_tools or tool in self.allow_tools


@dataclass(frozen=True)
class Policy:
    clients: tuple[Client, ...]

    def client_for_key(self, api_key: str | None) -> Client | None:
        """Resolve a bearer API key to a client, or None (default-deny)."""
        if not api_key:
            return None
        for c in self.clients:
            if c.api_key == api_key:
                return c
        return None


def load_policy(path: Path) -> Policy:
    data = yaml.safe_load(path.read_text()) or {}
    clients = tuple(
        Client(
            name=c["name"],
            api_key=c["api_key"],
            allow_tools=tuple(c.get("allow_tools", [])),
        )
        for c in data.get("clients", [])
    )
    return Policy(clients=clients)
