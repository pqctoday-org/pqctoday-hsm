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

# 12 KMIP ops the dispatcher currently implements. Tests using any other
# op are auto-skipped with ``OP_UNSUPPORTED``.
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
}


# ── Placeholder resolution ──────────────────────────────────────────────────


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
            else:
                raise ValueError(f"unresolved placeholder {value!r} on {node.tag_name}")
        return TtlvNode(
            tag_name=node.tag_name,
            ttlv_type=node.ttlv_type,
            value=value,
            children=children,
        )

    def harvest_from_response(self, expected: TtlvNode, actual: TtlvNode) -> None:
        """Walk expected & actual in parallel; whenever expected has a
        ``$NAME`` value, bind ``NAME`` to actual's corresponding value.

        Skips TimeStamp and ServerCorrelationValue (always differ).
        Tolerant of structural mismatches — the comparator will flag
        those; this method's job is just to capture bindings.
        """
        if is_volatile_tag(expected.tag_name):
            return
        if isinstance(expected.value, str) and expected.value.startswith("$"):
            if expected.value not in ("$NOW",):
                try:
                    self.bind(expected.value, actual.value)
                except ValueError:
                    pass  # mismatch — comparator will catch it
        # Recurse pairwise as far as both trees go.
        for ec, ac in zip(expected.children, actual.children):
            self.harvest_from_response(ec, ac)


# ── Response comparison ────────────────────────────────────────────────────


def find_child(node: TtlvNode, tag: str) -> TtlvNode | None:
    for c in node.children:
        if c.tag_name == tag:
            return c
    return None


_VOLATILE_TAG_FORMS: set[str] = {
    _norm(t) for t in ("TimeStamp", "ServerCorrelationValue", "ClientCorrelationValue")
}


def is_volatile_tag(tag: str) -> bool:
    """Tags whose values vary run-to-run and aren't worth comparing
    semantically: server timestamps, server correlation tokens, etc."""
    return _norm(tag) in _VOLATILE_TAG_FORMS


def compare_responses(
    expected: TtlvNode,
    actual: TtlvNode,
    bindings: Bindings,
) -> tuple[bool, str]:
    """Recursively compare two ResponseMessage ASTs modulo volatile tags
    and bound placeholders.

    Bind newly-introduced placeholders along the way so later messages
    in the test see them. Returns ``(ok, diagnostic)``.
    """
    # Tag names compare modulo whitespace/punctuation — spec table uses
    # "Response Message", XML uses "ResponseMessage". Both must normalise
    # to the same alphanumeric form.
    if _norm(expected.tag_name) != _norm(actual.tag_name):
        return False, f"tag {expected.tag_name!r} != {actual.tag_name!r}"
    if is_volatile_tag(_norm(expected.tag_name)) or is_volatile_tag(expected.tag_name):
        return True, "skipped (volatile)"

    if expected.ttlv_type == "Structure":
        # Compare children in order; KMIP message structures are positional
        # except for attribute bags (which OASIS happens to order
        # consistently so we can keep this simple for v0.1).
        if len(expected.children) != len(actual.children):
            return False, (
                f"{expected.tag_name}: child count {len(expected.children)} "
                f"!= {len(actual.children)}"
            )
        for ec, ac in zip(expected.children, actual.children):
            ok, why = compare_responses(ec, ac, bindings)
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
    if _values_equal(expected.ttlv_type, ev, av):
        return True, "ok"
    return False, f"{expected.tag_name}: expected {ev!r} got {av!r}"


def _values_equal(ttlv_type: str, expected: Any, actual: Any) -> bool:
    """Compare leaf values modulo the str/int/hex skew between XML (always
    strings) and decoded bytes (typed). Enum values are looked up by name."""
    if expected == actual:
        return True
    # XML always gives us strings; the decoder gives us typed values.
    # Coerce to a canonical form for the comparison.
    if ttlv_type in ("Integer", "LongInteger", "DateTime", "DateTimeExtended", "Interval"):
        try:
            return int(str(expected), 0) == int(actual)
        except (ValueError, TypeError):
            return False
    if ttlv_type == "Boolean":
        return str(expected).lower() in ("true", "1") and bool(actual) is True or \
               str(expected).lower() in ("false", "0") and bool(actual) is False
    if ttlv_type == "Enumeration":
        # Expected is the human-readable name (e.g. "Query"); actual is the
        # 32-bit codepoint. Look up the codepoint via the tag table.
        if isinstance(expected, str) and isinstance(actual, int):
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


def start_server(port: int = 9999) -> Server:
    """Spawn ``pqctoday-kmip`` with volatile store + self-signed TLS.

    Caller is responsible for ``Server.stop()`` — even on test failures —
    so we don't leak listeners across runs.
    """
    if not SERVER_BINARY.exists():
        raise SystemExit(
            f"server binary missing: {SERVER_BINARY}\n"
            f"run `cargo build --release --bin pqctoday-kmip` first"
        )
    proc = subprocess.Popen(
        [str(SERVER_BINARY), "--listen", f"127.0.0.1:{port}", "--store-memory"],
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
    status: str  # PASS / FAIL / SKIP_OP / SKIP_PARSE / ERROR
    detail: str = ""
    ops_used: list[str] = field(default_factory=list)


def run_test(srv: Server, xml_path: Path) -> TestResult:
    name = xml_path.name
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
    n_err = sum(1 for r in results if r.status == "ERROR")
    n_total = len(results)
    n_candidates = n_total - n_skip_op - n_skip_parse

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
    md.append(f"| SKIP_PARSE (XML malformed) | {n_skip_parse} | {100*n_skip_parse/n_total:.1f}% |")
    md.append(f"| **Total** | **{n_total}** | 100.0% |\n")
    md.append(f"\nOf the {n_candidates} tests that exercise only implemented ops:")
    md.append(f"\n  - **{n_pass} pass ({100*n_pass/max(n_candidates,1):.0f}%)**")
    md.append(f"\n  - {n_fail} fail")
    md.append(f"\n  - {n_err} errored\n")
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
    results: list[TestResult] = []
    for i, path in enumerate(paths, 1):
        srv = start_server()
        try:
            r = run_test(srv, path)
        finally:
            srv.stop()
        results.append(r)
        print(f"  [{i:3d}/{len(paths)}] {r.status:12s}  {r.name}  {r.detail[:60]}")

    out = REPORT_DIR / "REPLAY_REPORT.md"
    write_report(results, out)
    print(f"\nreport: {out}")
    print(f"        {out.with_suffix('.json')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
