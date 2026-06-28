"""Content scanning for tool arguments and results — layered defense.

Two layers with the SAME interface (`scan_input` / `scan_output` -> `ScanResult`):

  1. an always-on **pattern backstop** (regex) — deterministic, zero-dependency,
     catches the obvious cases and gives a stable redaction token; and
  2. **llm-guard** (the same trained defense as project #7) when the optional
     `guard` extra is installed — a model that catches paraphrased / obfuscated
     prompt injection and PII the regex misses.

llm-guard pulls a heavy ML stack and downloads a model on first use, so it is
lazily loaded, only used when importable, and **fails open with a logged reason**
(the pattern backstop still applies). Install it with `uv sync --extra guard`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache

# Obvious injection phrases planted in tool arguments or a poisoned tool
# description/result (LLM01/LLM05). The backstop; llm-guard adds trained detection.
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


@lru_cache(maxsize=1)
def _llm_guard_available() -> bool:
    try:
        import llm_guard  # noqa: F401
    except Exception:
        return False
    return True


@lru_cache(maxsize=1)
def _input_scanner():
    from llm_guard.input_scanners import PromptInjection
    from llm_guard.input_scanners.prompt_injection import MatchType

    return PromptInjection(threshold=0.5, match_type=MatchType.FULL)


@lru_cache(maxsize=1)
def _output_scanner():
    from llm_guard.output_scanners import Sensitive

    return Sensitive(redact=True)


def scan_input(text: str) -> ScanResult:
    """Block arguments/descriptions that look like prompt injection.

    Blocked if EITHER the pattern backstop matches OR llm-guard flags it.
    """
    text = text or ""
    reasons: list[str] = []
    blocked = False

    if _INJECTION.search(text):
        blocked = True
        reasons.append("input: pattern injection match")

    if _llm_guard_available():
        try:
            _, is_valid, risk = _input_scanner().scan(text)
            if not is_valid:
                blocked = True
                reasons.append(f"input: llm-guard prompt_injection risk={risk:.2f}")
        except Exception as exc:  # model unavailable, etc. — fail open, but say so
            reasons.append(f"input: llm-guard skipped ({exc})")

    return ScanResult(not blocked, text, reasons)


def scan_output(text: str) -> ScanResult:
    """Redact secrets/PII from a tool result; always allowed, possibly sanitized."""
    text = text or ""
    sanitized = text
    reasons: list[str] = []

    # Always-on backstop: redact secret-shaped tokens with a stable marker.
    if _SECRET.search(sanitized):
        sanitized = _SECRET.sub(_REDACTION, sanitized)
        reasons.append("output: secret redacted (pattern)")

    if _llm_guard_available():
        try:
            scrubbed, is_valid, risk = _output_scanner().scan("", sanitized)
            if not is_valid:
                sanitized = scrubbed
                reasons.append(f"output: llm-guard sensitive risk={risk:.2f}")
        except Exception as exc:
            reasons.append(f"output: llm-guard skipped ({exc})")

    return ScanResult(True, sanitized, reasons)
