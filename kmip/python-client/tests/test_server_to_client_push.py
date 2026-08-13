"""Live proof of KMIP 3.0 §6.2 server-to-client push (Baseline item 10).

Not mocked, and it cannot be: what is under test is that a REAL server pushes a
REAL `Notify` down a channel whose roles were swapped, and that this client
answers it. A mock of either side would only prove the mock agrees with itself
— the same reason the §3.3.3 hybrid group is gated on OpenSSL rather than on a
self-round-trip.

Run against a server started with credentials, e.g.:

    ./target/release/pqctoday-kmip --store-memory --policy-dir policies \\
        --policy training-permissive \\
        --auth-user "alice:$(printf %s pw | shasum -a 256 | cut -d' ' -f1)"

    KMIP_TEST_HOST=127.0.0.1 KMIP_TEST_USER=alice KMIP_TEST_PASS=pw \\
        pytest tests/test_server_to_client_push.py

SKIPS — never silently passes — when no server is reachable. A skip is not a
pass; if this is meant to be covering the push path, check it actually ran.
"""
import os
import socket
import uuid

import pytest

from pqctoday_kmip.kmip import KmipClient, _leaf, _struct

HOST = os.environ.get("KMIP_TEST_HOST", "127.0.0.1")
PORT = int(os.environ.get("KMIP_TEST_PORT", "5696"))
USER = os.environ.get("KMIP_TEST_USER", "alice")
PASS = os.environ.get("KMIP_TEST_PASS", "pw")


def _reachable() -> bool:
    try:
        with socket.create_connection((HOST, PORT), timeout=1):
            return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(
    not _reachable(), reason=f"no KMIP server on {HOST}:{PORT}"
)


def _authed() -> KmipClient:
    return KmipClient(HOST, PORT, username=USER, password=PASS)


def _mutate_an_attribute(c: KmipClient, tag: str) -> str:
    """Create a key and change an attribute on it. Returns the UID."""
    created = c.create_symmetric("AES", 256, name=f"push-{tag}")
    assert created.ok, f"could not create a key to mutate: {created}"
    uid = created.get("UniqueIdentifier")
    changed = c.request(
        "SetAttribute",
        _leaf("UniqueIdentifier", "TextString", uid),
        _struct("NewAttribute", _leaf("ContactInformation", "TextString", f"ops-{tag}")),
    )
    assert changed.ok, f"SetAttribute failed: {changed}"
    return uid


def test_an_attribute_change_is_pushed_to_a_listening_client():
    """§6.2.2: the server notifies "of events that resulted in changes to
    attributes of an object", including "at least the Last Change Date"."""
    tag = uuid.uuid4().hex[:8]
    c = _authed()
    uid = _mutate_an_attribute(c, tag)

    messages = c.serve_as_endpoint()

    assert messages, "the attribute change produced no notification"
    notify = next((m for m in messages if m["uid"] == uid), None)
    assert notify is not None, f"no Notify named {uid}; got {messages}"
    assert notify["operation"] == "Notify", notify["operation"]
    assert notify["attributes"], "§6.2.2 requires at least Last Change Date"


def test_a_delivered_notification_is_not_delivered_twice():
    """Delivery consumes the queue. Re-delivering would make a client that
    reconnects re-process history it has already handled."""
    tag = uuid.uuid4().hex[:8]
    c = _authed()
    _mutate_an_attribute(c, tag)

    first = c.serve_as_endpoint()
    assert first, "expected at least one notification on the first listen"
    second = c.serve_as_endpoint()
    assert second == [], f"notifications were re-delivered: {second}"


def test_an_anonymous_client_cannot_take_the_server_role():
    """§6.1.61 hands the server the client role, after which it pushes managed
    object attributes down the channel. An unauthenticated peer has no identity
    to scope those notifications to, so the switch must be refused."""
    anon = KmipClient(HOST, PORT)  # no credentials
    with pytest.raises((PermissionError, ConnectionError, OSError)):
        anon.serve_as_endpoint()


def test_listening_with_nothing_queued_returns_cleanly():
    """A client that listens when nothing has changed must get an empty result,
    not a hang or an error — otherwise polling for changes is unusable."""
    c = _authed()
    c.serve_as_endpoint()  # drain anything this suite already queued
    assert c.serve_as_endpoint() == []
