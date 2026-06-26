"""Unit tests for AdminClient — mocked HTTP, no live server required."""
import http.client
import json
import ssl
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from pqctoday_kmip.admin import AdminClient, AdminError


# ── Fixture ──────────────────────────────────────────────────────────────────

@pytest.fixture
def client():
    return AdminClient(host="127.0.0.1", port=5697, insecure=True)


def _mock_response(status: int, body: object) -> MagicMock:
    resp = MagicMock()
    resp.status = status
    raw = json.dumps(body).encode() if not isinstance(body, (str, bytes)) else \
          body.encode() if isinstance(body, str) else body
    resp.read.return_value = raw
    return resp


def _patch_conn(resp: MagicMock):
    """Patch HTTPSConnection so _request() gets our canned response."""
    conn = MagicMock()
    conn.getresponse.return_value = resp
    return patch(
        "pqctoday_kmip.admin.http.client.HTTPSConnection",
        return_value=conn,
    )


# ── healthz / version ────────────────────────────────────────────────────────

def test_healthz_ok(client):
    with _patch_conn(_mock_response(200, {"status": "ok"})):
        result = client.healthz()
    assert result == {"status": "ok"}


def test_version_ok(client):
    with _patch_conn(_mock_response(200, {"version": "0.1.0", "git_sha": "abc123"})):
        result = client.version()
    assert result["version"] == "0.1.0"


def test_raises_on_4xx(client):
    with _patch_conn(_mock_response(503, {"detail": "unavailable"})):
        with pytest.raises(AdminError) as exc:
            client.healthz()
    assert exc.value.status == 503
    assert "unavailable" in str(exc.value)


# ── policy management ────────────────────────────────────────────────────────

def test_list_policies(client):
    with _patch_conn(_mock_response(200, {"policies": ["aead-only", "pqc", "training-permissive"]})):
        result = client.list_policies()
    assert result == ["aead-only", "pqc", "training-permissive"]


def test_get_policy(client):
    body = {"name": "aead-only", "yaml": "name: aead-only\n"}
    with _patch_conn(_mock_response(200, body)):
        result = client.get_policy("aead-only")
    assert result["name"] == "aead-only"


def test_get_active_none_on_404(client):
    with _patch_conn(_mock_response(404, {"detail": "no active policy"})):
        result = client.get_active()
    assert result is None


def test_get_active_returns_dict(client):
    body = {"name": "aead-only", "fingerprint": "abc"}
    with _patch_conn(_mock_response(200, body)):
        result = client.get_active()
    assert result["name"] == "aead-only"


def test_activate(client):
    body = {"activated": "aead-only"}
    with _patch_conn(_mock_response(200, body)):
        result = client.activate("aead-only")
    assert result["activated"] == "aead-only"


# ── validate / dry-run ───────────────────────────────────────────────────────

def test_validate_ok(client):
    body = {"valid": True, "fingerprint": "abc"}
    with _patch_conn(_mock_response(200, body)):
        result = client.validate("name: test\n")
    assert result["valid"] is True


def test_dry_run_allow(client):
    body = {"decision": "Allow", "policy": "pqc", "op": "Sign", "algorithm": "ML_DSA_65"}
    with _patch_conn(_mock_response(200, body)):
        result = client.dry_run("name: pqc\n", "Sign", algorithm="ML_DSA_65")
    assert result["decision"] == "Allow"


def test_dry_run_deny(client):
    body = {"decision": "Deny", "reason": "algorithm not in allowed list"}
    with _patch_conn(_mock_response(200, body)):
        result = client.dry_run("name: aead-only\n", "Sign", algorithm="RSA")
    assert result["decision"] == "Deny"


# ── audit ────────────────────────────────────────────────────────────────────

def test_get_audit_returns_events(client):
    events = [
        {"plane": "p1", "event": {"type": "PolicyActivated"}},
        {"plane": "p2", "event": {"type": "Create"}},
    ]
    with _patch_conn(_mock_response(200, {"events": events, "count": 2})):
        result = client.get_audit(limit=10)
    assert result["count"] == 2
    assert result["events"][0]["plane"] == "p1"


# ── AdminError formatting ────────────────────────────────────────────────────

def test_admin_error_detail_extracted():
    err = AdminError(422, json.dumps({"detail": "bad yaml"}))
    assert "bad yaml" in str(err)
    assert err.status == 422


def test_admin_error_plain_body():
    err = AdminError(500, "internal server error")
    assert "internal server error" in str(err)
