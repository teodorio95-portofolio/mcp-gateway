"""Policy loading + default-deny resolution."""

from __future__ import annotations

from pathlib import Path

from mcp_gateway.policy import load_policy

_POLICY = Path(__file__).resolve().parents[1] / "policy.yaml"


def test_unknown_key_is_denied():
    policy = load_policy(_POLICY)
    assert policy.client_for_key("nope") is None
    assert policy.client_for_key(None) is None


def test_known_keys_resolve():
    policy = load_policy(_POLICY)
    analyst = policy.client_for_key("dev-analyst-key")
    admin = policy.client_for_key("dev-admin-key")
    assert analyst is not None and admin is not None
    assert analyst.allows("trivy_fs_scan")
    assert not analyst.allows("lookup_invoice")  # not on allow-list
    assert admin.allows("lookup_invoice")  # admin has "*"
