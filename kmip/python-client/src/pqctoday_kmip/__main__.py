"""CLI entry point for pqctoday-kmip-client.

Usage::

    pqctoday-kmip demo [--host HOST] [--port PORT] [--audit-log PATH]
    pqctoday-kmip audit <log-path>
    pqctoday-kmip admin --ca CA --cert CERT --key KEY [--host HOST] [--port PORT] <subcommand>

Admin subcommands: healthz, version, list-policies, get-policy NAME,
                   active, activate NAME, validate YAML_FILE,
                   dry-run YAML_FILE --op OP [--algorithm ALG],
                   audit [--limit N], stream [--count N]

"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time


def _demo(args: argparse.Namespace) -> int:
    from .kmip import KmipClient
    from . import audit as _audit

    c = KmipClient(args.host, args.port)
    print(f"agile KMIP server @ {args.host}:{args.port}")

    def _step(label: str, result) -> None:
        status = "ok" if result.ok else f"DENIED/FAILED (reason={result.reason})"
        print(f"  · {label:<34} -> {status}")

    print("\n=== 1. PQC happy-path ===")
    kp = c.create_key_pair("ML_DSA_44", "Sign Verify")
    _step("CreateKeyPair ML-DSA-44", kp)
    priv = kp.get("PrivateKeyUniqueIdentifier")
    if kp.ok and priv:
        c.activate(priv)
        _step("Sign (ML-DSA-44)", c.sign(priv, b"agility demo message", "ML_DSA_44"))

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

    if args.audit_log:
        time.sleep(0.2)
        print("\n=== three-plane audit trail (p1 policy / p2 kmip / p3 pkcs11) ===\n")
        if os.path.exists(args.audit_log):
            print(_audit.format_log(args.audit_log, color=not args.no_color))
        else:
            print(f"  (audit log not found at {args.audit_log})")
    else:
        print("\n(pass --audit-log <path> to print the correlated three-plane trail)")
    return 0


def _audit_cmd(args: argparse.Namespace) -> int:
    from . import audit as _audit
    print(_audit.format_log(args.log_path, color=not args.no_color))
    return 0


def _admin_cmd(args: argparse.Namespace) -> int:
    from .admin import AdminClient, AdminError

    client = AdminClient(
        host=args.host,
        port=args.port,
        ca_cert=getattr(args, "ca", None),
        client_cert=getattr(args, "cert", None),
        client_key=getattr(args, "key", None),
        insecure=getattr(args, "insecure", False),
    )

    try:
        sub = args.admin_cmd
        if sub == "healthz":
            print(json.dumps(client.healthz(), indent=2))
        elif sub == "version":
            print(json.dumps(client.version(), indent=2))
        elif sub == "list-policies":
            for name in client.list_policies():
                print(name)
        elif sub == "get-policy":
            result = client.get_policy(args.name)
            print(result.get("yaml", ""))
        elif sub == "active":
            result = client.get_active()
            if result is None:
                print("(no policy active)")
            else:
                print(json.dumps(result, indent=2))
        elif sub == "activate":
            print(json.dumps(client.activate(args.name), indent=2))
        elif sub == "validate":
            yaml_text = open(args.yaml_file).read()
            print(json.dumps(client.validate(yaml_text), indent=2))
        elif sub == "dry-run":
            yaml_text = open(args.yaml_file).read()
            print(json.dumps(
                client.dry_run(yaml_text, args.op, algorithm=getattr(args, "algorithm", None)),
                indent=2,
            ))
        elif sub == "audit":
            result = client.get_audit(limit=getattr(args, "limit", 200))
            print(json.dumps(result, indent=2))
        elif sub == "stream":
            count = getattr(args, "count", 0)
            seen = 0
            try:
                for event in client.stream_audit():
                    print(json.dumps(event))
                    sys.stdout.flush()
                    seen += 1
                    if count and seen >= count:
                        break
            except KeyboardInterrupt:
                pass
        else:
            print(f"unknown admin subcommand: {sub}", file=sys.stderr)
            return 2
    except AdminError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="pqctoday-kmip",
        description="pqctoday KMIP 3.0 PQC key management client",
    )
    ap.add_argument("--no-color", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)

    # demo
    p_demo = sub.add_parser("demo", help="run PQC happy-path + allow-vs-deny demo")
    p_demo.add_argument("--host", default="127.0.0.1")
    p_demo.add_argument("--port", type=int, default=5696)
    p_demo.add_argument("--audit-log", metavar="PATH",
                        help="server audit log path; printed as correlated 3-plane trail")

    # audit
    p_audit = sub.add_parser("audit", help="print correlated audit trail from a JSONL log")
    p_audit.add_argument("log_path", metavar="LOG")

    # admin
    p_admin = sub.add_parser("admin", help="REST admin facade commands")
    p_admin.add_argument("--host", default="127.0.0.1")
    p_admin.add_argument("--port", type=int, default=5697)
    p_admin.add_argument("--ca", metavar="CA_CERT", help="CA certificate (PEM)")
    p_admin.add_argument("--cert", metavar="CLIENT_CERT", help="client certificate (PEM)")
    p_admin.add_argument("--key", metavar="CLIENT_KEY", help="client private key (PEM)")
    p_admin.add_argument("--insecure", action="store_true",
                         help="skip server cert verification (sandbox dev)")
    admin_sub = p_admin.add_subparsers(dest="admin_cmd", required=True)
    admin_sub.add_parser("healthz")
    admin_sub.add_parser("version")
    admin_sub.add_parser("list-policies")
    gp = admin_sub.add_parser("get-policy")
    gp.add_argument("name")
    admin_sub.add_parser("active")
    act = admin_sub.add_parser("activate")
    act.add_argument("name")
    val = admin_sub.add_parser("validate")
    val.add_argument("yaml_file")
    dr = admin_sub.add_parser("dry-run",
                               help="evaluate a policy YAML against one operation")
    dr.add_argument("yaml_file", metavar="YAML_FILE")
    dr.add_argument("--op", required=True, help="KMIP operation name, e.g. Sign")
    dr.add_argument("--algorithm", metavar="ALG",
                    help="CryptographicAlgorithm, e.g. ML_DSA_65")
    aud = admin_sub.add_parser("audit", help="recent audit events (ring buffer)")
    aud.add_argument("--limit", type=int, default=200)
    strm = admin_sub.add_parser("stream",
                                 help="tail live audit events via SSE (Ctrl-C to stop)")
    strm.add_argument("--count", type=int, default=0,
                      metavar="N", help="stop after N events (default: run forever)")

    args = ap.parse_args(argv)
    if args.cmd == "demo":
        return _demo(args)
    if args.cmd == "audit":
        return _audit_cmd(args)
    if args.cmd == "admin":
        return _admin_cmd(args)
    ap.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
