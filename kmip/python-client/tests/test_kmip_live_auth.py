"""Live-server tests for authentication and signature verification (RG-3).

Unlike the rest of this suite these are NOT mocked — they exist to cover
behaviour that only a real server can demonstrate:

  * §8.1.2 Username/Password credentials actually authenticating,
  * §3.3.4 client-certificate (mTLS) identity,
  * §6.1.63 SignatureVerify reporting a FORGED signature as a *successful*
    call carrying ``ValidityIndicator = Invalid``.

That last one is the reason this file exists. A client that reads the
result status instead of the indicator scores a forgery as passing, and a
mocked test cannot prove the real server does what the spec says.

Endpoint is configurable so the same tests can run against the sandbox
`pqc-kmip` container (the intended target) or a locally spawned server:

    KMIP_TEST_HOST=pqc-kmip KMIP_TEST_PORT=5696 \\
    KMIP_TEST_USER=... KMIP_TEST_PASS=... \\
    KMIP_TEST_CERTS=/admin-certs pytest tests/test_kmip_live_auth.py

They SKIP — never fail — when no server is reachable, so a normal unit run
is unaffected. A skip is not a pass: if these are meant to be covering the
auth path in CI, check they are actually running there.
"""
import os
import socket

import pytest

from pqctoday_kmip.kmip import KmipClient

HOST = os.environ.get("KMIP_TEST_HOST", "127.0.0.1")
PORT = int(os.environ.get("KMIP_TEST_PORT", "5696"))
USER = os.environ.get("KMIP_TEST_USER", "alice")
PASS = os.environ.get("KMIP_TEST_PASS", "pw")
CERTS = os.environ.get("KMIP_TEST_CERTS")  # dir holding client.crt/client.key


def _reachable() -> bool:
    try:
        with socket.create_connection((HOST, PORT), timeout=3):
            return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(
    not _reachable(),
    reason=f"no KMIP server reachable at {HOST}:{PORT} — set KMIP_TEST_HOST/PORT",
)


def _client(**kw) -> KmipClient:
    if CERTS:
        kw.setdefault("client_cert", os.path.join(CERTS, "client.crt"))
        kw.setdefault("client_key", os.path.join(CERTS, "client.key"))
    return KmipClient(host=HOST, port=PORT, insecure=True, timeout=20, **kw)


def _authed() -> KmipClient:
    return _client(username=USER, password=PASS)


# ── §8.1.2 credentials ──────────────────────────────────────────────────────

def test_correct_credentials_authenticate():
    assert _authed().locate().ok


def test_wrong_password_is_rejected():
    """The case that gives the others meaning — without it, 'success' could
    just be an auth path that waves everything through."""
    r = _client(username=USER, password="definitely-not-the-password").locate()
    assert not r.ok, "a wrong password must not authenticate"


def test_unknown_user_is_rejected():
    r = _client(username="nobody-by-that-name", password=PASS).locate()
    assert not r.ok, "an unknown user must not authenticate"


# ── §6.1.63 SignatureVerify ─────────────────────────────────────────────────

@pytest.fixture(scope="module")
def signing_pair():
    """An ML-DSA-65 pair usable for BOTH operations.

    Usage must be "Sign Verify": a Sign-only pair is refused by
    SignatureVerify with IncompatibleCryptographicUsageMask (mask 0x1 lacks
    bit 0x2), which is the server behaving correctly, not a client bug.
    """
    c = _authed()
    kp = c.create_key_pair("ML-DSA-65", "Sign Verify")
    assert kp.ok, f"key pair creation failed: {kp}"
    priv = kp.get("PrivateKeyUniqueIdentifier")
    pub = kp.get("PublicKeyUniqueIdentifier")
    assert c.activate(priv).ok and c.activate(pub).ok
    return c, priv, pub


def test_good_signature_is_valid(signing_pair):
    c, priv, pub = signing_pair
    data = b"pqctoday signature verify - good"
    sig = bytes.fromhex(c.sign(priv, data, "ML-DSA-65").get("SignatureData"))
    r = c.signature_verify(pub, data, sig, "ML-DSA-65")
    assert r.ok
    assert KmipClient.validity(r) == "Valid"


def test_forged_signature_reports_invalid_on_a_successful_call(signing_pair):
    """The trap, asserted directly.

    A forged signature is NOT a KMIP error: the call SUCCEEDS and the
    verdict lives in ValidityIndicator. Both halves are asserted here on
    purpose — if `r.ok` ever became False for a forgery the API contract
    would have changed, and if the verdict stopped being Invalid the engine
    would be broken. A client reading only `r.ok` passes a forgery.
    """
    c, priv, pub = signing_pair
    data = b"pqctoday signature verify - forged"
    sig = bytearray(bytes.fromhex(c.sign(priv, data, "ML-DSA-65").get("SignatureData")))
    sig[len(sig) // 2] ^= 0xFF

    r = c.signature_verify(pub, data, bytes(sig), "ML-DSA-65")
    assert r.ok, "a failed verification is not a KMIP error — the call must succeed"
    assert KmipClient.validity(r) == "Invalid", "a forged signature must not verify"


def test_signature_over_different_data_is_invalid(signing_pair):
    c, priv, pub = signing_pair
    sig = bytes.fromhex(c.sign(priv, b"the signed message", "ML-DSA-65").get("SignatureData"))
    r = c.signature_verify(pub, b"a completely different message", sig, "ML-DSA-65")
    assert r.ok
    assert KmipClient.validity(r) == "Invalid"


# ── §3.3.4 transport identity ───────────────────────────────────────────────

@pytest.mark.skipif(not CERTS, reason="KMIP_TEST_CERTS not set — no client cert available")
def test_client_certificate_alone_authenticates():
    """§3.3.4 accepts channel identity OR credentials. With a client cert
    present, no username/password should be required."""
    assert _client().locate().ok
