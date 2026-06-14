"""Sandbox-dev integration demo for the agile pqctoday-kmip server.

Drives a fixed sequence of KMIP operations against a RUNNING server, then
reads the server's audit log and prints the correlated three-plane trail
(p1 policy / p2 KMIP / p3 PKCS#11) for every request.

Two halves, exercised by identical client code:

  1. PQC happy-path — ML-DSA keygen + sign, ML-KEM keygen + encapsulate +
     decapsulate. Under any policy that allows them, each shows
     ALLOW -> KMIP Success -> the PKCS#11 engine call that ran.

  2. Encryption allow-vs-deny contrast — one AES key, encrypted once with
     GCM and once with CBC. Under the `aead-only` policy the GCM call is
     ALLOWED (full p1->p2->p3 trail) while the CBC call is DENIED at p1 with
     NO p3 engine call — the agility layer stopping it before the engine.

Run the server first, e.g.:

    cargo build --release --bin pqctoday-kmip
    ./target/release/pqctoday-kmip \
        --listen 127.0.0.1:5696 --store-memory \
        --policy-dir policies --policy aead-only \
        --audit-log /tmp/agility-audit.jsonl

then:

    python -m pykmip.demo --audit-log /tmp/agility-audit.jsonl

The client targets the running server; it does not launch or configure it.
"""
from __future__ import annotations

import argparse
import os
import time

from . import audit
from .client import KmipClient


def _step(label: str, result) -> None:
    status = "ok" if result.ok else f"DENIED/FAILED (reason={result.reason})"
    print(f"  · {label:<34} -> {status}")


def run_operations(c: KmipClient) -> None:
    print("\n=== 1. PQC happy-path ===")

    # ML-DSA: keygen -> activate -> sign
    kp = c.create_key_pair("ML_DSA_44", "Sign Verify")
    _step("CreateKeyPair ML-DSA-44", kp)
    priv = kp.get("PrivateKeyUniqueIdentifier")
    if kp.ok and priv:
        c.activate(priv)
        _step("Sign (ML-DSA-44)", c.sign(priv, b"agility demo message", "ML_DSA_44"))

    # ML-KEM: keygen -> activate -> encapsulate -> decapsulate
    kem = c.create_key_pair("ML_KEM_512", "KeyAgreement")
    _step("CreateKeyPair ML-KEM-512", kem)
    kpriv = kem.get("PrivateKeyUniqueIdentifier")
    kpub = kem.get("PublicKeyUniqueIdentifier")
    if kem.ok and kpub:
        c.activate(kpub)
        if kpriv:
            c.activate(kpriv)
        enc = c.encapsulate(kpub)
        _step("Encapsulate (ML-KEM-512)", enc)
        ct = enc.get("Data")
        if enc.ok and ct and kpriv:
            _step("Decapsulate (ML-KEM-512)", c.decapsulate(kpriv, bytes.fromhex(ct)))

    print("\n=== 2. Encryption allow-vs-deny contrast ===")
    aes = c.create_symmetric("AES", 256, name="agility-demo-aes")
    _step("Create AES-256", aes)
    aes_uid = aes.get("UniqueIdentifier")
    if aes.ok and aes_uid:
        c.activate(aes_uid)
        block = b"\x00" * 16
        _step("Encrypt AES-GCM (expect ALLOW)",
              c.encrypt(aes_uid, block, block_cipher_mode="GCM", iv=b"\x00" * 12))
        _step("Encrypt AES-CBC (expect DENY under aead-only)",
              c.encrypt(aes_uid, block, block_cipher_mode="CBC", iv=b"\x00" * 16))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Agile KMIP server sandbox-dev demo")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5696)
    ap.add_argument("--audit-log", help="server's --audit-log path; printed as a correlated 3-plane trail after the run")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args(argv)

    c = KmipClient(args.host, args.port)
    print(f"agile KMIP server @ {args.host}:{args.port}")
    run_operations(c)

    if args.audit_log:
        # Give the JSONL sink a moment to flush the last lines.
        time.sleep(0.2)
        print("\n=== three-plane audit trail (p1 policy / p2 kmip / p3 pkcs11) ===\n")
        if os.path.exists(args.audit_log):
            print(audit.format_log(args.audit_log, color=not args.no_color))
        else:
            print(f"  (audit log not found at {args.audit_log})")
    else:
        print("\n(pass --audit-log <path> to print the correlated three-plane trail)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
