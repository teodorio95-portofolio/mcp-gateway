"""Content scanning for tool arguments and results.

The production scanner reuses llm-guard (the same defense as project #7) to catch
prompt injection in arguments and secrets/PII in results. llm-guard pulls a heavy
ML stack, so until the `guard` extra is wired in (follow-up PR) this module ships
a lightweight pattern fallback with the SAME interface — the gateway pipeline and
tests don't change when the real scanner lands.

    ScanResult(allowed=False, sanitized=..., reasons=[...])
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Obvious injection phrases an attacker plants in tool arguments or in a
# poisoned tool description/result (LLM01/LLM05). Not exhaustive — llm-guard's
# trained PromptInjection scanner replaces this.
_INJECTION = re.compile(
    r"ignore\s+(?:all|your|the|previous|prior)\b[\w\s,]*?\b(?:instructions|prompts)"
    r"|disregard\s+(?:the|all)\b[\w\s]*?\babove"
    r"|system\s+prompt"
    r"|exfiltrat|reveal\s+the\s+(?:secret|key|password|operations\s+key)",
    re.IGNORECASE,
)

# Secret-shaped tokens to redact from results before they reach the client.
_SECRET = re.compile(r"\bsk-[A-Za-z0-9_-]{6,}\b|\bghp_[A-Za-z0-9]{20,}\b")
_REDACTION = "[REDACTED]"


@dataclass(frozen=True)
class ScanResult:
    allowed: bool
    sanitized: str
    reasons: list[str] = field(default_factory=list)


def scan_input(text: str) -> ScanResult:
    """Block arguments that look like prompt injection (fail-closed)."""
    if _INJECTION.search(text or ""):
        return ScanResult(False, text, ["input: possible prompt injection"])
    return ScanResult(True, text, [])


def scan_output(text: str) -> ScanResult:
    """Redact secrets from a tool result; always allowed but possibly sanitized."""
    text = text or ""
    if _SECRET.search(text):
        return ScanResult(True, _SECRET.sub(_REDACTION, text), ["output: secret redacted"])
    return ScanResult(True, text, [])
