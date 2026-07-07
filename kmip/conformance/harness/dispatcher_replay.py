#!/usr/bin/env python3
"""OASIS KMIP 3.0 dispatcher replay harness.

Drives every OASIS XML transcript through a running ``pqctoday-kmip``
server over TLS. For each test:

1. Parse the XML into alternating Request / Response message pairs.
2. For each Request:

   a. Resolve placeholders (``$NOW``, ``$UNIQUE_IDENTIFIER_n``,
      ``$KEY_HANDLE_n``, …) against bindings captured from prior
      responses in *this* test.
   b. Encode the resolved AST to TTLV via :mod:`oasis_codec`.
   c. Send raw bytes to the server, receive raw bytes back.
   d. Decode the response into an AST.

3. Compare the actual response to the expected response (modulo
   ``TimeStamp`` / ``ServerCorrelationValue`` which always differ; plus
   bind newly-introduced ``$UNIQUE_IDENTIFIER_n`` placeholders to
   whatever the actual response returned, so subsequent requests in
   this test see consistent values).

4. Report PASS / SKIP / FAIL per test plus an aggregate. Output is
   ``conformance/REPLAY_REPORT.md`` (+ JSON sidecar).

Why TLS / subprocess instead of an in-process dispatcher call?

The server's TLS path is the real production stack. An in-process test
that bypasses TLS + the wire codec is weaker — it can't catch e.g. a
codec/dispatcher integration regression. Subprocess + TLS is slower but
catches more.

Usage (from ``kmip/``):

.. code-block:: shell

    # Run on all 13 candidate tests (auto-classified):
    python3 conformance/harness/dispatcher_replay.py

    # Run on a single test:
    python3 conformance/harness/dispatcher_replay.py BL-M-1-30.xml
"""

from __future__ import annotations

import json
import os
import re
import socket
import ssl
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))

from conformance.harness.oasis_codec import (  # noqa: E402
    _norm,
    decode_one,
    encode_node,
    parse_transcript_xml,
    TtlvNode,
)

KMIP_ROOT = HERE.parent.parent
CORPUS_DIR = KMIP_ROOT / "conformance/oasis_corpus"
REPORT_DIR = KMIP_ROOT / "conformance"
SERVER_BINARY = KMIP_ROOT / "target/release/pqctoday-kmip"

# KMIP ops the dispatcher currently implements (`handle_payload` in
# `dispatcher/mod.rs` — the single source of truth; re-derive this set from
# there, not from memory, if the two ever look out of sync). Tests using any
# other op are auto-skipped with ``OP_UNSUPPORTED``.
IMPLEMENTED_OPS: set[str] = {
    "Create", "CreateKeyPair", "Get", "Locate",
    "Activate", "Revoke", "Destroy",
    "Encrypt", "Decrypt", "Sign", "SignatureVerify",
    "Query",
    # PR #81 (Group B + Interop): attribute read-side ops + test-framework
    # markers.
    "GetAttributes", "GetAttributeList",
    "Interop",
    # PR #82 (Group B wave 2): attribute mutation ops.
    "AddAttribute", "ModifyAttribute", "DeleteAttribute",
    "SetAttribute", "AdjustAttribute",
    # PR #83 (Group C): object import/export.
    "Register", "Import", "Export",
    # PR #84 (Group D + Group A leftover): lifecycle + protocol.
    "Deactivate", "Check", "Archive", "Recover", "Obliterate",
    "DiscoverVersions", "Ping",
    # PR #85 (Group E wave 1): keyed + keyless crypto.
    "MAC", "MACVerify", "Hash",
    # PR #86 (Group F): session / auth.
    "CreateCredential", "CreateGroup", "CreateUser",
    "Log", "Login", "Logout",
    # PR #87 (Group G): RNG + PKCS#11 passthrough — closes SKIP_OP universe.
    "RNGRetrieve", "RNGSeed", "PKCS_11",
    # KMIP 3.0 WD19 (PQC interop): ML-KEM encapsulation / decapsulation.
    "Encapsulate", "Decapsulate",
    # K19-K21 (baseline client-to-server + derive/rekey ops) — added when the
    # KMIP3.0 browser Commands tab work found this set was 7 ops stale
    # relative to the dispatcher; e2e-covered in
    # `kmip/tests/op_coverage_e2e.rs` (these ops aren't in the OASIS corpus,
    # so this harness never actually exercises them — see that file for
    # substantive-outcome coverage instead).
    "GetUsageAllocation", "GetConstraints", "SetDefaults", "SetEndpointRole",
    "DeriveKey", "ReKey", "ReKeyKeyPair",
}


# OASIS conformance tests that exercise cryptographic mechanisms the
# `softhsmrustv3` PKCS#11 backend does NOT implement by policy. These
# are not implementation gaps — the algorithms are deprecated and
# intentionally out of scope. See `kmip/DEPRECATED.md` for the full
# rationale + spec citations. Tests in this set surface as
# `SKIP_DEPRECATED` rather than `FAIL` and are removed from the
# headline pass-rate denominator.
_DEPRECATED_ALGO_TESTS: dict[str, str] = {
    # `KmipAlgorithm = DSA` (0x05). Classical DSA discrete-log signatures.
    "BL-M-12-30.xml": "DSA — deprecated (NIST SP 800-186 §5.4)",
    "BL-M-13-30.xml": "DSA — deprecated (NIST SP 800-186 §5.4)",
    # `KmipAlgorithm = 3DES / DES3` (0x02). Triple-DES.
    "SKFF-M-4-30.xml": "3DES — deprecated (NIST SP 800-131A r2 §1.2.1)",
    "SKFF-M-8-30.xml": "3DES — deprecated (NIST SP 800-131A r2 §1.2.1)",
    "SKFF-M-12-30.xml": "3DES — deprecated (NIST SP 800-131A r2 §1.2.1)",
    # `KmipAlgorithm = DES` (0x01) — single-DES. Not currently in any
    # mandatory OASIS test we replay, but listed for completeness so
    # the policy + skip-list stay together.
}


def is_deprecated_algo_test(name: str) -> str | None:
    return _DEPRECATED_ALGO_TESTS.get(name)


# OASIS conformance tests whose first request assumes Managed Object state
# left over from an earlier transcript in the same profile run. Our harness
# restarts ``pqctoday-kmip`` per test for hermetic isolation (see
# ``run_test`` / ``start_server``), so any cross-test state is intentionally
# wiped by default. The OASIS reference suite was authored against a
# long-lived server where the M-2 transcript's Register/Create persists
# into M-3.
#
# RESOLVED (2026-07-07, Honest-Maximum Phase 2.1): TL-M-3 and SASED-M-3 are
# NOT implementation gaps — the underlying stateful Locate filters
# (GroupLink, ApplicationSpecificInformation; see `locate.rs`) were already
# implemented, only untested end-to-end because this harness wiped the
# precondition state. They're now run as `_CHAINED_TEST_GROUPS` (below):
# the M-2 + M-3 pair shares one server instance and one `Bindings` object,
# exactly like a real long-lived server session, instead of getting a fresh
# server per test. This dict is kept (currently empty) as a documented
# escape hatch for any *future* corpus addition with the same shape, so a
# real gap doesn't get silently misclassified as FAIL without an
# explanation, or silently skipped without one either.
_PRECONDITION_TESTS: dict[str, str] = {}

# Test files that must run against ONE shared server + ONE shared
# `Bindings` object, in the given order, instead of each getting its own
# fresh server. Mirrors how the OASIS reference suite's transcripts were
# authored (against a single long-lived server across an entire profile
# run) for the specific pairs that depend on it — e.g. TL-M-3's
# Locate-by-ApplicationSpecificInformation targets the object TL-M-2
# created; SASED-M-3's Locate-by-GroupLink targets the SecretData
# SASED-M-2 registered. Every other test stays hermetic (fresh server).
#
# Both group members are still scored independently (PASS/FAIL per test);
# only the server process and placeholder bindings are shared. Verified
# safe to share bindings wholesale: the trailing member's placeholder
# names that overlap the leading member's (`$UNIQUE_IDENTIFIER_0` in both
# pairs) resolve to the SAME object in both transcripts, so
# `Bindings.bind()`'s re-bind-must-match-prior-value check never fires.
_CHAINED_TEST_GROUPS: list[list[str]] = [
    ["SASED-M-2-30.xml", "SASED-M-3-30.xml"],
    ["TL-M-2-30.xml", "TL-M-3-30.xml"],
]


def chained_group_for(name: str) -> list[str] | None:
    """Return the chain `name` belongs to, or None if it runs standalone."""
    for group in _CHAINED_TEST_GROUPS:
        if name in group:
            return group
    return None


def is_precondition_test(name: str) -> str | None:
    return _PRECONDITION_TESTS.get(name)


# OASIS conformance tests that pin a specific server policy choice from a
# set of MUTUALLY EXCLUSIVE conformant behaviors. RNGSeed is the canonical
# example: KMIP 3.0 §6.1.55 lets a conformant server (a) consume the full
# seed, (b) consume only N bytes and report DataLength=N, (c) ignore the
# seed entirely and report DataLength=0, or (d) deny the op outright with
# `PermissionDenied`. CS-RNG-O-1 exercises (a) — the server's default.
#
# RESOLVED (2026-07-07, Honest-Maximum Phase 2.2): the server now accepts
# `--rng-seed-mode <full|partial|ignore|deny>` (`bin/pqctoday-kmip.rs`,
# `ops/deps.rs::RngSeedMode`), so CS-RNG-O-{2,3,4} each get their own
# server instance started with the matching mode pinned via `extra_args`
# — see `_RNG_SEED_MODE_TESTS` and its use in `main()`. This dict is kept
# (currently empty) as a documented escape hatch for a *future* corpus
# addition that pins some other mutually-exclusive server choice we
# haven't built a selector for yet.
_POLICY_VARIANT_TESTS: dict[str, str] = {}


def is_policy_variant_test(name: str) -> str | None:
    return _POLICY_VARIANT_TESTS.get(name)


# Maps a CS-RNG-O-{2,3,4} transcript to the `--rng-seed-mode` value that
# makes it the server's active policy for that one run. CS-RNG-O-1 needs
# no entry — `full` is already the server's built-in default.
_RNG_SEED_MODE_TESTS: dict[str, str] = {
    "CS-RNG-O-2-30.xml": "partial",
    "CS-RNG-O-3-30.xml": "ignore",
    "CS-RNG-O-4-30.xml": "deny",
}


# ── Placeholder resolution ──────────────────────────────────────────────────


# Tags whose leaf value is volatile across runs even though the tag isn't
# in the §4.1.1 Variable Items table — auto-binding from these would
# bind a stale value into a later request. UID is bound via the
# positional ``$UNIQUE_IDENTIFIER_n`` mechanism, not by tag name.
_AUTO_BIND_SKIP = {
    "TimeStamp",
    "UniqueIdentifier",
    "ServerCorrelationValue",
    "ClientCorrelationValue",
    "CorrelationValue",  # streaming AEAD session token
}


def _tag_to_placeholder(tag: str) -> str | None:
    """``MACData`` → ``MAC_DATA``; ``KeyMaterial`` → ``KEY_MATERIAL``.

    OASIS test transcripts use this naming convention for placeholders
    like ``$MAC_DATA`` and ``$KEY_MATERIAL`` — the leaf value is printed
    literally in the response but referenced by upper-underscore name in
    later requests. Returns ``None`` for tags we never auto-bind.
    """
    if tag in _AUTO_BIND_SKIP:
        return None
    # Insert ``_`` at lowercase→uppercase boundaries AND at the boundary
    # of a run of uppercase followed by an uppercase+lowercase pair
    # (``MAC`` + ``Data`` → ``MAC_DATA``).
    s1 = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", tag)
    s2 = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s1)
    return s2.upper() if s2 else None


@dataclass
class Bindings:
    """Per-test ``$NAME`` → resolved value map.

    Built up as responses come back: the first time an expected response
    contains ``$UNIQUE_IDENTIFIER_0``, we bind it to whatever UID the
    actual response returned at the same tree position. Subsequent
    requests that reference ``$UNIQUE_IDENTIFIER_0`` get the bound value.

    ``$NOW`` is a special case — bound once at test start to the current
    timestamp so the request encodes a sensible value; the comparator
    skips TimeStamp comparison entirely so server clock skew never
    matters.
    """
    values: dict[str, Any] = field(default_factory=dict)
    # Tag-name auto-binds ($MAC_DATA et al.) — a RESOLUTION FALLBACK
    # only. Kept separate from `values` so an eager tag-name bind
    # never shadows the comparator's bind-on-first-use of an explicit
    # corpus placeholder (CS-BC-M-GCM-2 pair #111: the response's
    # $AUTHENTICATED_ENCRYPTION_TAG must bind THERE, not inherit the
    # tag value auto-harvested from pair #1).
    auto_values: dict[str, Any] = field(default_factory=dict)

    def bind(self, name: str, value: Any) -> None:
        if name in self.values and self.values[name] != value:
            raise ValueError(
                f"placeholder {name!r} re-bound: was {self.values[name]!r}, now {value!r}"
            )
        self.values[name] = value

    def resolve_tree(self, node: TtlvNode) -> TtlvNode:
        """Return a deep copy of ``node`` with every ``$NAME`` value
        replaced by the bound value. Unbound placeholders raise.
        """
        children = [self.resolve_tree(c) for c in node.children]
        value = node.value
        if isinstance(value, str) and value.startswith("$"):
            if value == "$NOW":
                value = str(int(time.time()))
            elif value.startswith("$NOW-") or value.startswith("$NOW+"):
                # `$NOW-3600` / `$NOW+86400` arithmetic — OASIS uses these
                # for ActivationDate / DeactivationDate sentinel values.
                try:
                    offset = int(value[4:])
                except ValueError:
                    raise ValueError(f"malformed NOW arithmetic {value!r}")
                value = str(int(time.time()) + offset)
            elif value in self.values:
                value = self.values[value]
            elif value in self.auto_values:
                # Tag-name auto-bind fallback (see `auto_values`).
                value = self.auto_values[value]
            else:
                raise ValueError(f"unresolved placeholder {value!r} on {node.tag_name}")
        return TtlvNode(
            tag_name=node.tag_name,
            ttlv_type=node.ttlv_type,
            value=value,
            children=children,
        )

    def harvest_from_response(self, expected: TtlvNode, actual: TtlvNode) -> None:
        """Walk expected & actual; whenever expected has a ``$NAME``
        value, bind ``NAME`` to actual's corresponding value. Also
        auto-binds ``$TAG_NAME`` (upper-underscore form of the tag) to
        the actual value at every leaf, so a later request can
        reference e.g. ``$MAC_DATA`` against the ``MACData`` leaf of an
        earlier response without an explicit placeholder in the XML.

        Skips TimeStamp and ServerCorrelationValue (always differ).
        Tolerant of structural mismatches — the comparator will flag
        those; this method's job is just to capture bindings.

        Container traversal is positional EXCEPT inside an `Attributes`
        Structure, where order is variable per §4.1.2 item 5. There we
        match children by tag-name so a placeholder $X attached to a
        specific attribute binds against THAT attribute's actual value
        rather than a positionally-aligned but semantically unrelated
        one.
        """
        if is_volatile_tag(expected.tag_name):
            return
        if isinstance(expected.value, str) and expected.value.startswith("$"):
            if expected.value not in ("$NOW",):
                try:
                    self.bind(expected.value, actual.value)
                except ValueError:
                    pass  # mismatch — comparator will catch it
        # Auto-bind by tag-name so later requests can reference values
        # without an explicit ``$NAME`` placeholder in the expected
        # response. KMIP OASIS transcripts use this convention for
        # MACData / KeyMaterial / Data fields where the spec value is
        # printed literally in the response but referenced as
        # ``$MAC_DATA`` / ``$KEY_MATERIAL`` / ``$DATA`` later. Only fires
        # at leaves (Structures have no value) and skips $NOW / volatile.
        if actual.value is not None and not (
            isinstance(expected.value, str) and expected.value == "$NOW"
        ):
            auto = _tag_to_placeholder(expected.tag_name)
            if auto:
                key = f"${auto}"
                if key not in self.auto_values:
                    # First-write wins. Stored in the FALLBACK map so an
                    # explicit corpus placeholder of the same name still
                    # binds on first use in the comparator.
                    self.auto_values[key] = actual.value
        # Container traversal.
        if _norm(expected.tag_name) == _norm("Attributes"):
            # Tag-name-aware: pair each expected child to the FIRST
            # actual child of the same tag name.
            actual_by_name: dict[str, list[TtlvNode]] = {}
            for c in actual.children:
                actual_by_name.setdefault(_norm(c.tag_name), []).append(c)
            for ec in expected.children:
                candidates = actual_by_name.get(_norm(ec.tag_name), [])
                if candidates:
                    ac = candidates.pop(0)
                    self.harvest_from_response(ec, ac)
        else:
            # Positional (default for spec-positional containers).
            for ec, ac in zip(expected.children, actual.children):
                self.harvest_from_response(ec, ac)


# ── Response comparison ────────────────────────────────────────────────────


def find_child(node: TtlvNode, tag: str) -> TtlvNode | None:
    for c in node.children:
        if c.tag_name == tag:
            return c
    return None


# Each entry below is grounded in a specific item in
# KMIP Profiles v3.0 §4.1 "Permitted Test Case Variations". The
# section enumerates which TTLV fields MAY differ between the test
# transcript's expected response and the server's actual output. Any
# variation not enumerated there SHALL be deemed non-conformant
# (§4.1 closing sentence) — so this set is the entire permitted list,
# nothing invented.
#
# Format: tag-name → spec citation. Codec citations point to PDF page
# numbers in `spec/oasis-kmip-3.0/kmip-profiles-v3.0.pdf`.
_VARIABLE_ITEM_TAGS: dict[str, str] = {
    # Envelope fields the main spec §6.4 marks as transient.
    _norm("TimeStamp"): "§4.1.1 item 6 — Time Stamp",
    _norm("ServerCorrelationValue"): "§4.1.1 item 18",
    _norm("ClientCorrelationValue"): "§4.1.1 item 19",
    # §4.1.1 item 5 — Asynchronous Correlation Value.
    _norm("AsynchronousCorrelationValue"): "§4.1.1 item 5",
    # §4.1.1 item 9 — DateTime attributes whose value isn't fixed by the
    # client request. Each sub-item enumerated explicitly in §4.1.1.9.a-o.
    _norm("ActivationDate"): "§4.1.1 item 9.a",
    _norm("ArchiveDate"): "§4.1.1 item 9.b",
    _norm("BuildDate"): "§4.1.1 item 9.c",
    _norm("CompromiseDate"): "§4.1.1 item 9.d",
    _norm("CompromiseOccurrenceDate"): "§4.1.1 item 9.e",
    _norm("DeactivationDate"): "§4.1.1 item 9.f",
    _norm("DestroyDate"): "§4.1.1 item 9.g",
    _norm("InitialDate"): "§4.1.1 item 9.h",
    _norm("LastChangeDate"): "§4.1.1 item 9.i",
    _norm("ProtectStopDate"): "§4.1.1 item 9.j",
    _norm("ProcessStartDate"): "§4.1.1 item 9.k",
    _norm("RotateDate"): "§4.1.1 item 9.l",
    _norm("SubmissionDate"): "§4.1.1 item 9.m",
    _norm("ValidityDate"): "§4.1.1 item 9.n",
    _norm("OriginalCreationDate"): "§4.1.1 item 9.o",
    # §4.1.1 item 10 — Digest Value for dynamically-generated objects.
    _norm("Digest"): "§4.1.1 item 10",
    # §4.1.1 item 11 — Key Format Type selected by the server.
    _norm("KeyFormatType"): "§4.1.1 item 11",
    # §4.1 Response Variations item 5 — Vendor Identification value.
    _norm("VendorIdentification"): "§4.1 Response Variations item 5",
    # §4.1.1 items 1-4 — UID family. These are placeholder-bound via
    # the existing $UNIQUE_IDENTIFIER_n mechanism rather than skipped
    # outright, but if a test expects a literal UID and we return our
    # urn:pqctoday:obj:<uuid> form they should compare equal because
    # the binding harvest captures the actual value.
}


def is_volatile_tag(tag: str) -> bool:
    """True iff this TTLV tag is enumerated in §4.1.1 as a Variable
    Item — values are permitted to differ between expected and actual.
    """
    return _norm(tag) in _VARIABLE_ITEM_TAGS


# A handful of §4.1.1 Variable Items are ALSO optional-presence per the
# main KMIP 3.0 spec §6.4 Message-Envelope rules — the server MAY emit
# them or omit them. Different OASIS XML fixtures pick one form or the
# other for the same op, so the comparator must tolerate presence/absence
# in BOTH directions: drop these tags from both sides before structural
# (child-count) comparison.
#
# Restricted on purpose: most Variable Items (e.g. ActivationDate) are
# value-variable but presence-mandatory when the attribute exists —
# silently dropping them would mask real dispatcher bugs.
_OPTIONAL_PRESENCE_TAGS: dict[str, str] = {
    _norm("ServerCorrelationValue"): "§8.2.2 — optional in ResponseHeader",
    _norm("ClientCorrelationValue"): "§8.1.2 — optional in RequestHeader",
    # KMIP 3.0 §6.1.42 — `PKCS_11OutputParameters` is optional on
    # responses where the underlying PKCS#11 function returns no
    # output buffer (`C_Initialize`, `C_Finalize`, etc.) and present
    # only for the few functions that do (`C_GetInfo`, `C_GetSlotInfo`,
    # `C_GetTokenInfo`, `C_GetMechanismInfo`, ...). Treating it as
    # optional-presence on both sides matches the spec's permissive
    # framing without forcing every server to emit a placeholder
    # byte string just to keep child-count parity.
    _norm("PKCS_11OutputParameters"): "PKCS#11 v3.2 §5 — optional per function",
    _norm("PKCS11OutputParameters"): "PKCS#11 v3.2 §5 — optional per function",
}


def is_optional_presence(tag: str) -> bool:
    return _norm(tag) in _OPTIONAL_PRESENCE_TAGS


# `kmip-profiles-v3.0` §4.1 Response Variations item 8 — "Server
# Information – the contents of the structure returned MAY vary…".
# The structure itself is positionally compared, but its interior is
# treated as opaque (only the presence of the tag is checked).
_OPAQUE_STRUCTURE_TAGS: dict[str, str] = {
    _norm("ServerInformation"): "§4.1 Response Variations item 8",
    # `kmip-profiles-v3.0` §4.1.1 item 10 — `Digest Value` is variable
    # for dynamically-generated managed objects (and the Hashing
    # Algorithm sub-field is variable per item 12.a). Presence of the
    # `Digest` Structure is required when the client asks for it, but
    # its interior bytes can vary.
    _norm("Digest"): "§4.1.1 item 10 + item 12",
    # `kmip-profiles-v3.0` §4.1 Response Variations item 6 — Random
    # Number Generator fields are all variable; treat the entire
    # structure as opaque.
    _norm("RandomNumberGenerator"): "§4.1 Response Variations item 6",
}


def is_opaque_structure(tag: str) -> bool:
    return _norm(tag) in _OPAQUE_STRUCTURE_TAGS


def compare_responses(
    expected: TtlvNode,
    actual: TtlvNode,
    bindings: Bindings,
    op_context: str | None = None,
) -> tuple[bool, str]:
    """Recursively compare two ResponseMessage ASTs modulo volatile tags
    and bound placeholders.

    Bind newly-introduced placeholders along the way so later messages
    in the test see them. Returns ``(ok, diagnostic)``.

    ``op_context`` is the Operation enum value of the enclosing
    ``BatchItem`` (e.g. "Query", "GetAttributes"). It selects spec-cited
    container-specific comparison rules per §4.1.1 items 15-16
    (Query) — every other comparison falls through to byte-exact KAT
    discipline (§4.1 closing sentence: variations not enumerated SHALL
    be deemed non-conformant).
    """
    # Tag names compare modulo whitespace/punctuation — spec table uses
    # "Response Message", XML uses "ResponseMessage". Both must normalise
    # to the same alphanumeric form.
    if _norm(expected.tag_name) != _norm(actual.tag_name):
        return False, f"tag {expected.tag_name!r} != {actual.tag_name!r}"
    if is_volatile_tag(expected.tag_name):
        return True, "skipped (volatile)"

    if expected.ttlv_type == "Structure":
        norm_tag = _norm(expected.tag_name)

        # §4.1 Response Variations item 8 — Server Information structure
        # contents may vary; presence of the tag is what counts.
        if is_opaque_structure(expected.tag_name):
            return True, "ok (opaque structure)"

        # §4.1.1 Response Variations item 3 — ResultMessage is optional;
        # also detect Operation child to set op_context for descendants.
        if norm_tag == _norm("BatchItem"):
            return _compare_batch_item(expected, actual, bindings)

        # §4.1.1 items 15-16 — Query ResponsePayload reports Operation /
        # ObjectType lists; server's set MAY be a superset of what the
        # OASIS test enumerates.
        if norm_tag == _norm("ResponsePayload") and op_context == "Query":
            return _compare_query_response_payload(expected, actual, bindings)

        # §4.1.1 item 20 (additional attributes server MAY include) +
        # §4.1.2 item 5 ("any permutation of the order of the required
        # entries is allowed"). Apply to every Attributes container —
        # bag semantics, expected ⊆ actual by tag-name.
        if norm_tag == _norm("Attributes"):
            return _compare_attributes_container(expected, actual, bindings)

        # §4.1.2 item 5 also applies to the GetAttributeList
        # `ResponsePayload` itself: it returns the UID + a series
        # of `AttributeReference` Enumerations whose ORDER is
        # explicitly variable per spec. Switch to bag semantics
        # for that op's payload (SKFF-M-9/-10/-11 exercise it).
        if (
            norm_tag == _norm("ResponsePayload")
            and op_context == "GetAttributeList"
        ):
            return _compare_attribute_reference_list(expected, actual, bindings)

        # Default: positional child compare. KMIP message structures are
        # positional per the main spec §6 unless §4.1 grants a variation
        # — see the carve-outs above. Drop optional-presence tags
        # (ServerCorrelationValue, ClientCorrelationValue) from both
        # sides first so emit/omit asymmetry doesn't fail the count.
        exp_children = [c for c in expected.children
                        if not is_optional_presence(c.tag_name)]
        act_children = [c for c in actual.children
                        if not is_optional_presence(c.tag_name)]
        if len(exp_children) != len(act_children):
            return False, (
                f"{expected.tag_name}: child count {len(exp_children)} "
                f"!= {len(act_children)}"
            )
        for ec, ac in zip(exp_children, act_children):
            ok, why = compare_responses(ec, ac, bindings, op_context)
            if not ok:
                return False, f"{expected.tag_name}/{why}"
        return True, "ok"

    # Leaf — resolve expected value if it's a placeholder; for newly seen
    # placeholders, bind and accept.
    ev = expected.value
    av = actual.value
    if isinstance(ev, str) and ev.startswith("$"):
        if ev == "$NOW":
            return True, "ok (skipped $NOW)"
        if ev in bindings.values:
            ev = bindings.values[ev]
        else:
            bindings.bind(ev, av)
            return True, f"ok (bound {expected.value} = {av!r})"
    if _values_equal(expected.ttlv_type, ev, av, expected.tag_name):
        return True, "ok"
    return False, f"{expected.tag_name}: expected {ev!r} got {av!r}"


def _compare_batch_item(
    expected: TtlvNode,
    actual: TtlvNode,
    bindings: Bindings,
) -> tuple[bool, str]:
    """KMIP Profiles v3.0 §4.1.1 Response Variations item 3 — the
    ``Result Message`` element is optional in a BatchItem; servers MAY
    omit it even on failures. Drop it from both sides before positional
    compare. Also derive op_context from the Operation child so the
    ResponsePayload comparison knows which §4.1 carve-outs to apply.
    """
    op_enum = find_child(expected, "Operation")
    op_context: str | None = None
    if op_enum is not None:
        if isinstance(op_enum.value, str):
            op_context = op_enum.value
        elif isinstance(op_enum.value, int):
            # Decoded actual side gives codepoint; look up the name.
            from conformance.harness.oasis_codec import table
            for _name, members in table().enum_name_to_value.items():
                if _norm(_name) != _norm("Operation"):
                    continue
                for k, v in members.items():
                    if v == op_enum.value:
                        op_context = k
                        break

    rm = _norm("ResultMessage")
    exp_children = [c for c in expected.children if _norm(c.tag_name) != rm]
    act_children = [c for c in actual.children if _norm(c.tag_name) != rm]
    if len(exp_children) != len(act_children):
        return False, (
            f"BatchItem: child count {len(exp_children)} != {len(act_children)} "
            f"(after dropping optional ResultMessage per §4.1.1 item 3)"
        )
    for ec, ac in zip(exp_children, act_children):
        ok, why = compare_responses(ec, ac, bindings, op_context)
        if not ok:
            return False, f"BatchItem/{why}"
    return True, "ok"


def _compare_attributes_container(
    expected: TtlvNode,
    actual: TtlvNode,
    bindings: Bindings,
) -> tuple[bool, str]:
    """KMIP Profiles v3.0 §4.1.1 item 20 + §4.1.2 item 5.

    Item 20 — *Additional attributes MAY be returned by the server*.
    Item 5 — *any permutation of the order of the required entries is
    allowed.*

    Bag semantics: every expected child must find a matching actual
    child (by tag-name + deep-equal value). The actual side MAY include
    extra attributes; expected must be a subset. Order is irrelevant.
    Within a matched pair, descendant comparison still follows §4.1
    rules (volatile tags skipped, etc.).
    """
    # Build a name → list-of-nodes index of actual children. We pop
    # matched candidates as we go so a duplicated expected attribute
    # demands a duplicated actual.
    actual_by_name: dict[str, list[TtlvNode]] = {}
    for c in actual.children:
        actual_by_name.setdefault(_norm(c.tag_name), []).append(c)

    for ec in expected.children:
        candidates = actual_by_name.get(_norm(ec.tag_name), [])
        if not candidates:
            return False, (
                f"Attributes: missing expected attribute {ec.tag_name!r} "
                f"(§4.1.1 item 20 permits server *extras* — not omissions)"
            )
        matched_idx: int | None = None
        for idx, ac in enumerate(candidates):
            ok, _why = compare_responses(ec, ac, bindings)
            if ok:
                matched_idx = idx
                break
        if matched_idx is None:
            return False, (
                f"Attributes: no actual {ec.tag_name!r} matches expected value"
            )
        candidates.pop(matched_idx)
    return True, "ok"


def _compare_attribute_reference_list(
    expected: TtlvNode,
    actual: TtlvNode,
    bindings: Bindings,
) -> tuple[bool, str]:
    """KMIP Profiles v3.0 §4.1.2 item 5 — GetAttributeList ResponsePayload
    returns the UniqueIdentifier + an unordered list of AttributeReference
    Enumerations naming every attribute on the object.

    Implementation: separate UniqueIdentifier (positional, mandatory first
    child) from the AttributeReference bag. The expected bag must be a
    subset of the actual bag (server MAY include extras per §4.1.1 item 20).
    """
    # Split UniqueIdentifier (positional) from the AttributeReference bag.
    def split(node: TtlvNode):
        uid = None
        refs = []
        for c in node.children:
            if _norm(c.tag_name) == _norm("UniqueIdentifier"):
                uid = c
            elif _norm(c.tag_name) == _norm("AttributeReference"):
                refs.append(c)
        return uid, refs

    e_uid, e_refs = split(expected)
    a_uid, a_refs = split(actual)
    if e_uid is not None and a_uid is None:
        return False, "ResponsePayload: missing UniqueIdentifier"
    if e_uid is not None and a_uid is not None:
        ok, why = compare_responses(e_uid, a_uid, bindings, "GetAttributeList")
        if not ok:
            return False, f"ResponsePayload/{why}"

    # Each AttributeReference has TWO valid wire shapes (KMIP 3.0 §11 "the
    # enumerable Tag" + our own encoder, `wire.rs::attribute_reference_frame`):
    #   1. A spec tag-name -> a leaf Enumeration (`.value` = the tag codepoint).
    #   2. A custom/vendor attribute name (no codepoint) -> a Structure
    #      carrying an `AttributeName` TextString child (optionally also a
    #      `VendorIdentification` sibling, which our encoder omits and the
    #      OASIS corpus includes — tolerated: only AttributeName identifies
    #      the reference, VendorIdentification is not part of its identity
    #      for this comparison).
    # A prior version of this comparator only understood shape 1 — any
    # shape-2 (Structure) reference had `.value is None` and always failed
    # to match, misreporting a real custom-vendor-attribute round trip
    # (KMIP 3.0's own client-set generic `Attribute{VendorIdentification,
    # AttributeName,AttributeValue}` mechanism) as a server gap.
    def identity(ref: TtlvNode) -> tuple[str, Any]:
        if ref.value is not None:
            # Shape 1: already a resolved Enumeration value (int) or a
            # symbolic placeholder string handled below by the caller.
            return ("enum", ref.value)
        for c in ref.children:
            if _norm(c.tag_name) == _norm("AttributeName"):
                return ("name", c.value)
        return ("unknown", None)

    from conformance.harness.oasis_codec import table
    actual_identities = {identity(a) for a in a_refs}
    for er in e_refs:
        ev = er.value
        if isinstance(ev, str):
            # Shape 1 with a symbolic tag name (not yet resolved to a
            # codepoint) — resolve via the tag table, same as before.
            ec = table().tag_name_to_code.get(_norm(ev))
            want = ("enum", ec) if ec is not None else ("unknown", None)
        elif ev is not None:
            want = ("enum", ev)
        else:
            want = identity(er)  # Shape 2: Structure{AttributeName}
        ok = want in actual_identities
        if not ok:
            return False, (
                f"ResponsePayload/AttributeReference: expected {want!r} not "
                f"present in actual list (§4.1.2 item 5 — order variable, "
                f"omissions are non-conformant)"
            )
    return True, "ok"


def _compare_query_response_payload(
    expected: TtlvNode,
    actual: TtlvNode,
    bindings: Bindings,
) -> tuple[bool, str]:
    """KMIP Profiles v3.0 §4.1.1 items 15-16.

    Item 15 — *Operation Types returned in the Query response MAY be a
    superset.*
    Item 16 — *Object Types returned in the Query response MAY be a
    superset.*

    Set-superset semantics on those two tag-name lists; every other
    child compares positionally as a normal structure.
    """
    superset_tags = {_norm("Operation"), _norm("ObjectType")}

    actual_by_name: dict[str, list[TtlvNode]] = {}
    for c in actual.children:
        actual_by_name.setdefault(_norm(c.tag_name), []).append(c)
    expected_by_name: dict[str, list[TtlvNode]] = {}
    for c in expected.children:
        expected_by_name.setdefault(_norm(c.tag_name), []).append(c)

    for list_tag in superset_tags:
        exp_items = expected_by_name.get(list_tag, [])
        if not exp_items:
            continue
        act_items = actual_by_name.get(list_tag, [])
        act_values = [a.value for a in act_items]
        missing = []
        for e in exp_items:
            if not any(_enum_match(e.value, av) for av in act_values):
                missing.append(e.value)
        if missing:
            return False, (
                f"Query ResponsePayload {list_tag}: actual lacks expected "
                f"{missing!r} (§4.1.1 items 15-16 permit *supersets* — "
                f"not subsets)"
            )

    # Compare the remaining non-list children positionally.
    other_expected = [c for c in expected.children
                      if _norm(c.tag_name) not in superset_tags]
    other_actual = [c for c in actual.children
                    if _norm(c.tag_name) not in superset_tags]
    if len(other_expected) != len(other_actual):
        return False, (
            f"Query ResponsePayload: non-list child count "
            f"{len(other_expected)} != {len(other_actual)}"
        )
    for ec, ac in zip(other_expected, other_actual):
        ok, why = compare_responses(ec, ac, bindings, "Query")
        if not ok:
            return False, f"Query ResponsePayload/{why}"
    return True, "ok"


def _enum_match(expected: Any, actual: Any) -> bool:
    """True iff two enum leaf values match — accounts for the
    string-name (XML) vs codepoint (decoded actual) skew."""
    if expected == actual:
        return True
    if isinstance(expected, str) and isinstance(actual, int):
        from conformance.harness.oasis_codec import table
        norm_exp = _norm(expected)
        for _name, members in table().enum_name_to_value.items():
            if members.get(norm_exp) == actual:
                return True
        return False
    if isinstance(expected, int) and isinstance(actual, str):
        return _enum_match(actual, expected)
    # Integer codepoints from XML can be hex strings — try parse.
    try:
        return int(str(expected), 0) == int(actual)
    except (ValueError, TypeError):
        return False


def _values_equal(
    ttlv_type: str,
    expected: Any,
    actual: Any,
    tag_name: str | None = None,
) -> bool:
    """Compare leaf values modulo the str/int/hex skew between XML (always
    strings) and decoded bytes (typed). Enum values are looked up by name.

    `tag_name` enables named-bit-flag resolution for KMIP 3.0 §5.4.1.6.4
    "Integer — Special case for Masks" (CryptographicUsageMask /
    ProtectionStorageMask): the XML carries `value="Sign Verify"` as the
    space-separated flag names; the wire encodes them as the bitwise OR.
    """
    if expected == actual:
        return True
    # XML always gives us strings; the decoder gives us typed values.
    # Coerce to a canonical form for the comparison.
    if ttlv_type in ("Integer", "LongInteger", "DateTime", "DateTimeExtended", "Interval"):
        try:
            return int(str(expected), 0) == int(actual)
        except (ValueError, TypeError):
            pass
        # KMIP 3.0 §5.4.1.6.4 — named bit-flag mask. Resolve flag names
        # → bitwise OR before comparing. Only `CryptographicUsageMask`
        # and `ProtectionStorageMask` carry named flags per the spec.
        if tag_name is not None:
            from conformance.harness.oasis_codec import NAMED_INTEGER_MASKS
            # NAMED_INTEGER_MASKS keys are the spec-canonical CamelCase
            # tag names; the AST carries the same form (XML element name).
            mask = NAMED_INTEGER_MASKS.get(tag_name)
            if mask is not None and isinstance(expected, str):
                acc = 0
                for flag in str(expected).split():
                    if flag not in mask:
                        return False
                    acc |= mask[flag]
                try:
                    return acc == int(actual)
                except (ValueError, TypeError):
                    return False
        return False
    if ttlv_type == "Boolean":
        return str(expected).lower() in ("true", "1") and bool(actual) is True or \
               str(expected).lower() in ("false", "0") and bool(actual) is False
    if ttlv_type == "Enumeration":
        # Expected is the human-readable name (e.g. "Query"); actual is the
        # 32-bit codepoint. Look up the codepoint via the tag table.
        if isinstance(expected, str) and isinstance(actual, int):
            # Vendor-extension codepoints come through as a hex literal
            # (e.g. `0x80123456`); compare directly to the decoded int.
            try:
                if int(expected, 0) == actual:
                    return True
            except (ValueError, TypeError):
                pass
            # AttributeReference is a special case — expected is a tag name.
            from conformance.harness.oasis_codec import table
            tag_norm = _norm(expected)
            tag_code = table().tag_name_to_code.get(tag_norm)
            if tag_code is not None and tag_code == actual:
                return True
            # Otherwise it's a normal enum member name; iterate all enum
            # tables looking for a match. (We don't know which enum table
            # to use from leaf context — comparator could be enhanced to
            # carry tag context if this gets slow.)
            for _name, members in table().enum_name_to_value.items():
                v = members.get(tag_norm)
                if v == actual:
                    return True
            return False
        return expected == actual
    if ttlv_type == "ByteString":
        # Both should be hex strings (encoder + decoder).
        return str(expected).lower() == str(actual).lower()
    if ttlv_type == "TextString":
        return str(expected) == str(actual)
    return expected == actual


# ── Server + TLS client ────────────────────────────────────────────────────


@dataclass
class Server:
    proc: subprocess.Popen
    host: str
    port: int

    def stop(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def start_server(port: int = 9999, extra_args: list[str] | None = None) -> Server:
    """Spawn ``pqctoday-kmip`` with volatile store + self-signed TLS.

    Caller is responsible for ``Server.stop()`` — even on test failures —
    so we don't leak listeners across runs. ``extra_args`` lets a caller
    pin a server-operator-choice flag for one run — e.g. ``--rng-seed-mode``
    (see ``_RNG_SEED_MODE_TESTS`` below) — without touching every other
    test's default config.
    """
    if not SERVER_BINARY.exists():
        raise SystemExit(
            f"server binary missing: {SERVER_BINARY}\n"
            f"run `cargo build --release --bin pqctoday-kmip` first"
        )
    proc = subprocess.Popen(
        [str(SERVER_BINARY), "--listen", f"127.0.0.1:{port}", "--store-memory", *(extra_args or [])],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
    )
    # Poll port until it's accepting; bail after 5 s.
    deadline = time.time() + 5.0
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return Server(proc=proc, host="127.0.0.1", port=port)
        except (ConnectionRefusedError, OSError):
            time.sleep(0.1)
    proc.terminate()
    out, err = proc.communicate(timeout=1)
    raise SystemExit(
        f"server didn't open port {port} within 5 s\n"
        f"stdout: {out[:500]!r}\n"
        f"stderr: {err[:500]!r}"
    )


def send_request(srv: Server, request_bytes: bytes, timeout: float = 5.0) -> bytes:
    """Open one TLS connection, send the request, read the response.

    The server expects one TTLV ``RequestMessage`` per connection per
    KMIP 3.0 §6 (no batching of independent requests). We accept the
    self-signed cert without verification — testing the wire path, not
    PKI.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection((srv.host, srv.port), timeout=timeout)
    sock = ctx.wrap_socket(raw, server_hostname=srv.host)
    try:
        sock.sendall(request_bytes)
        # Read until the socket closes (server closes after one response).
        chunks: list[bytes] = []
        sock.settimeout(timeout)
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        sock.close()


# ── Test classification ────────────────────────────────────────────────────


def operations_used(transcript: list[TtlvNode]) -> set[str]:
    """Collect every Operation enum value the transcript invokes (request
    side only — response Operation tags mirror)."""
    ops: set[str] = set()

    def walk(n: TtlvNode) -> None:
        if n.tag_name == "Operation" and n.ttlv_type == "Enumeration":
            ops.add(str(n.value))
        for c in n.children:
            walk(c)

    for msg in transcript:
        if _norm(msg.tag_name) == "RequestMessage":
            walk(msg)
    return ops


@dataclass
class TestResult:
    name: str
    status: str  # PASS / FAIL / SKIP_OP / SKIP_PARSE / SKIP_DEPRECATED / ERROR
    detail: str = ""
    ops_used: list[str] = field(default_factory=list)


def run_test(srv: Server, xml_path: Path, bindings: "Bindings | None" = None) -> TestResult:
    """Run one transcript. `bindings` lets a `_CHAINED_TEST_GROUPS` member
    reuse the placeholder state a prior group member harvested (e.g. the
    UID an M-2 Register/Create bound, for an M-3 Locate to reference) —
    the default (`None`) gives every standalone test its own fresh state,
    unchanged from before chained groups existed.
    """
    name = xml_path.name
    # Policy: deprecated mechanisms (DES, 3DES, classical DSA) are
    # out of scope for the softhsmrustv3 backend. See
    # `kmip/DEPRECATED.md` for the full rationale + spec citations.
    if (reason := is_deprecated_algo_test(name)) is not None:
        return TestResult(name=name, status="SKIP_DEPRECATED", detail=reason)
    if (reason := is_precondition_test(name)) is not None:
        return TestResult(name=name, status="SKIP_PRECONDITION", detail=reason)
    if (reason := is_policy_variant_test(name)) is not None:
        return TestResult(name=name, status="SKIP_POLICY_VARIANT", detail=reason)
    try:
        transcript = parse_transcript_xml(xml_path)
    except Exception as e:
        return TestResult(name=name, status="SKIP_PARSE", detail=f"XML parse: {e}")

    ops = operations_used(transcript)
    unsupported = ops - IMPLEMENTED_OPS
    if unsupported:
        return TestResult(
            name=name,
            status="SKIP_OP",
            detail=f"unsupported ops: {sorted(unsupported)}",
            ops_used=sorted(ops),
        )

    if bindings is None:
        bindings = Bindings()
    # Process Request / Response pairs in order.
    if len(transcript) % 2 != 0:
        return TestResult(name=name, status="SKIP_PARSE", detail="odd message count")

    for i in range(0, len(transcript), 2):
        req = transcript[i]
        expected_rsp = transcript[i + 1]
        if _norm(req.tag_name) != "RequestMessage" or _norm(expected_rsp.tag_name) != "ResponseMessage":
            return TestResult(
                name=name,
                status="SKIP_PARSE",
                detail=f"msg #{i//2}: not a Req/Resp pair "
                       f"({req.tag_name}/{expected_rsp.tag_name})",
            )
        # Resolve placeholders in the request.
        try:
            resolved_req = bindings.resolve_tree(req)
            req_bytes = encode_node(resolved_req)
        except Exception as e:
            return TestResult(
                name=name,
                status="ERROR",
                detail=f"msg #{i//2}: encode request: {type(e).__name__}: {e}",
                ops_used=sorted(ops),
            )

        try:
            resp_bytes = send_request(srv, req_bytes)
        except Exception as e:
            return TestResult(
                name=name,
                status="ERROR",
                detail=f"msg #{i//2}: transport: {type(e).__name__}: {e}",
                ops_used=sorted(ops),
            )

        if not resp_bytes:
            return TestResult(
                name=name,
                status="FAIL",
                detail=f"msg #{i//2}: server returned 0 bytes — likely rejected the request",
                ops_used=sorted(ops),
            )

        try:
            actual_rsp, _consumed = decode_one(resp_bytes)
        except Exception as e:
            return TestResult(
                name=name,
                status="FAIL",
                detail=f"msg #{i//2}: decode response: {type(e).__name__}: {e}",
                ops_used=sorted(ops),
            )

        bindings.harvest_from_response(expected_rsp, actual_rsp)
        ok, why = compare_responses(expected_rsp, actual_rsp, bindings)
        if not ok:
            return TestResult(
                name=name,
                status="FAIL",
                detail=f"msg #{i//2}: response mismatch: {why}",
                ops_used=sorted(ops),
            )

    return TestResult(name=name, status="PASS", detail="", ops_used=sorted(ops))


# ── Reporting ──────────────────────────────────────────────────────────────


def write_report(results: list[TestResult], path: Path) -> None:
    n_pass = sum(1 for r in results if r.status == "PASS")
    n_fail = sum(1 for r in results if r.status == "FAIL")
    n_skip_op = sum(1 for r in results if r.status == "SKIP_OP")
    n_skip_parse = sum(1 for r in results if r.status == "SKIP_PARSE")
    n_skip_deprecated = sum(1 for r in results if r.status == "SKIP_DEPRECATED")
    n_skip_precondition = sum(1 for r in results if r.status == "SKIP_PRECONDITION")
    n_skip_policy_variant = sum(1 for r in results if r.status == "SKIP_POLICY_VARIANT")
    n_err = sum(1 for r in results if r.status == "ERROR")
    n_total = len(results)
    # Candidates = tests we can actually run and expect to pass:
    # excludes SKIP_PARSE (XML malformed), SKIP_OP (op not implemented),
    # SKIP_DEPRECATED (algorithm out-of-scope per policy),
    # SKIP_PRECONDITION (depends on inter-transcript state our hermetic
    # harness intentionally wipes), and SKIP_POLICY_VARIANT (mutually
    # exclusive policy choices — we pin one).
    n_candidates = (
        n_total - n_skip_op - n_skip_parse - n_skip_deprecated
        - n_skip_precondition - n_skip_policy_variant
    )

    md = []
    md.append("# OASIS KMIP 3.0 Dispatcher Replay Report\n")
    md.append(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n\n")
    md.append("## Aggregate\n\n")
    md.append(f"| Status | Count | % of total |")
    md.append(f"|---|---|---|")
    md.append(f"| **PASS** | {n_pass} | {100*n_pass/n_total:.1f}% |")
    md.append(f"| **FAIL** | {n_fail} | {100*n_fail/n_total:.1f}% |")
    md.append(f"| ERROR | {n_err} | {100*n_err/n_total:.1f}% |")
    md.append(f"| SKIP_OP (op not implemented) | {n_skip_op} | {100*n_skip_op/n_total:.1f}% |")
    md.append(f"| SKIP_DEPRECATED (DES / 3DES / DSA out of scope) | {n_skip_deprecated} | {100*n_skip_deprecated/n_total:.1f}% |")
    md.append(f"| SKIP_PRECONDITION (needs prior-transcript state) | {n_skip_precondition} | {100*n_skip_precondition/n_total:.1f}% |")
    md.append(f"| SKIP_POLICY_VARIANT (mutually-exclusive policy) | {n_skip_policy_variant} | {100*n_skip_policy_variant/n_total:.1f}% |")
    md.append(f"| SKIP_PARSE (XML malformed) | {n_skip_parse} | {100*n_skip_parse/n_total:.1f}% |")
    md.append(f"| **Total** | **{n_total}** | 100.0% |\n")
    md.append(f"\nOf the {n_candidates} tests that exercise only implemented + non-deprecated ops:")
    md.append(f"\n  - **{n_pass} pass ({100*n_pass/max(n_candidates,1):.0f}%)**")
    md.append(f"\n  - {n_fail} fail")
    md.append(f"\n  - {n_err} errored\n")
    if n_skip_deprecated:
        md.append(f"\n{n_skip_deprecated} test(s) skipped per the deprecated-mechanism policy ")
        md.append("(see `kmip/DEPRECATED.md`):")
        for r in results:
            if r.status == "SKIP_DEPRECATED":
                md.append(f"\n  - `{r.name}` — {r.detail}")
        md.append("\n")
    if n_skip_precondition:
        md.append(f"\n{n_skip_precondition} test(s) skipped — depend on inter-transcript state ")
        md.append("our hermetic per-test harness wipes:")
        for r in results:
            if r.status == "SKIP_PRECONDITION":
                md.append(f"\n  - `{r.name}` — {r.detail}")
        md.append("\n")
    if n_skip_policy_variant:
        md.append(f"\n{n_skip_policy_variant} test(s) skipped — pin a mutually-exclusive policy ")
        md.append("choice our server does not select:")
        for r in results:
            if r.status == "SKIP_POLICY_VARIANT":
                md.append(f"\n  - `{r.name}` — {r.detail}")
        md.append("\n")
    md.append("\n## Per-test breakdown\n\n")
    md.append("| Test | Status | Detail |")
    md.append("|---|---|---|")
    for r in sorted(results, key=lambda x: (x.status, x.name)):
        detail = r.detail.replace("|", "\\|")[:140]
        md.append(f"| `{r.name}` | {r.status} | {detail} |")

    path.write_text("\n".join(md) + "\n")
    # JSON sidecar for downstream tooling.
    json_path = path.with_suffix(".json")
    json_path.write_text(json.dumps(
        {
            "generated_at": int(time.time()),
            "summary": {
                "pass": n_pass, "fail": n_fail, "error": n_err,
                "skip_op": n_skip_op, "skip_parse": n_skip_parse,
                "skip_deprecated": n_skip_deprecated,
                "skip_precondition": n_skip_precondition,
                "skip_policy_variant": n_skip_policy_variant,
                "total": n_total, "candidates": n_candidates,
            },
            "tests": [
                {"name": r.name, "status": r.status, "detail": r.detail,
                 "ops_used": r.ops_used}
                for r in results
            ],
        },
        indent=2,
    ))


# ── Main ───────────────────────────────────────────────────────────────────


def main(argv: list[str]) -> int:
    target_name = argv[1] if len(argv) > 1 else None
    # ``KMIP_REPLAY_CORPUS`` points the harness at an alternate, flat corpus
    # directory (e.g. the OASIS 3.0 PQC interop set) instead of the built-in
    # mandatory/optional split. Used by the PQC replay gate.
    alt = os.environ.get("KMIP_REPLAY_CORPUS")
    if alt:
        paths = sorted(Path(alt).glob("*.xml"))
    else:
        paths = sorted(
            list((CORPUS_DIR / "mandatory").glob("*.xml")) +
            list((CORPUS_DIR / "optional").glob("*.xml"))
        )
    if target_name:
        paths = [p for p in paths if p.name == target_name]
        if not paths:
            print(f"no such test: {target_name!r}", file=sys.stderr)
            return 1

    # Restart the server fresh per test so the in-process MemoryStore
    # carries no state across tests. Without this, e.g. Locate by Name
    # leaks objects from prior runs and breaks placeholder bindings.
    # Cost: ~0.5 s startup × N tests; for the full corpus that's ~50 s.
    #
    # EXCEPTION: `_CHAINED_TEST_GROUPS` members share one server + one
    # `Bindings` across the group (see that constant's docstring) — the
    # OASIS transcripts in those specific pairs assume a single
    # long-lived server session, not hermetic per-test isolation.
    by_name = {p.name: p for p in paths}
    results: list[TestResult] = []
    consumed: set[str] = set()  # chain members already scored, skip in the main loop
    port_counter = 0

    def next_port() -> int:
        nonlocal port_counter
        port_counter += 1
        # See the per-test cycling comment above — same rationale.
        return 10000 + (port_counter % 5000)

    for i, path in enumerate(paths, 1):
        name = path.name
        if name in consumed:
            continue

        group = chained_group_for(name)
        # Only run as a chain if EVERY member is present in this invocation
        # (e.g. `target_name` filtering to a single file falls back to the
        # old standalone behavior — legitimately unresolvable without its
        # precondition, which is the correct debug-mode signal).
        if group is not None and all(g in by_name for g in group) and name == group[0]:
            srv = start_server(port=next_port())
            shared_bindings = Bindings()
            try:
                for member_name in group:
                    r = run_test(srv, by_name[member_name], bindings=shared_bindings)
                    results.append(r)
                    consumed.add(member_name)
                    print(f"  [{i:3d}/{len(paths)}] {r.status:12s}  {r.name}  {r.detail[:60]}  (chained)")
            finally:
                srv.stop()
            continue

        # Cycle the listen port per test. Re-binding a single fixed port
        # hundreds of times in quick succession exhausts TIME_WAIT slots on
        # some platforms (macOS), making `start_server` time out mid-run.
        # A rotating port over a wide range avoids the collision; the range
        # is bounded so it stays inside the ephemeral space.
        extra_args: list[str] = []
        if (mode := _RNG_SEED_MODE_TESTS.get(name)) is not None:
            extra_args = ["--rng-seed-mode", mode]
        srv = start_server(port=next_port(), extra_args=extra_args)
        try:
            r = run_test(srv, path)
        finally:
            srv.stop()
        results.append(r)
        tag = f"  (--rng-seed-mode={mode})" if extra_args else ""
        print(f"  [{i:3d}/{len(paths)}] {r.status:12s}  {r.name}  {r.detail[:60]}{tag}")

    out = REPORT_DIR / "REPLAY_REPORT.md"
    write_report(results, out)
    print(f"\nreport: {out}")
    print(f"        {out.with_suffix('.json')}")

    # Exit non-zero if any test FAILed or ERRORed. The replay is a
    # conformance GATE: a 92->89 Locate regression once shipped because
    # this harness always returned 0 and CI never ran it. Returning the
    # FAIL+ERROR count makes the process exit non-zero so CI fails loudly.
    n_fail = sum(1 for r in results if r.status == "FAIL")
    n_err = sum(1 for r in results if r.status == "ERROR")
    if n_fail or n_err:
        print(
            f"\nFAIL: {n_fail} test(s) failed, {n_err} errored — "
            f"see {out} for details",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
