"""Correlate the agile KMIP server's audit log into per-request trails.

The server (run with `--audit-log <path>`) appends one JSON object per
line, each tagged with a `plane` and a `correlation_id` that is shared by
every event for one inbound request:

    p1 — Crypto-Agility engine  (PolicyDecided: allow / deny / rekey)
    p2 — KMIP dispatcher        (KmipResponseSent: op + result)
    p3 — PKCS#11 bridge         (Pkcs11Call: C_Sign / C_EncapsulateKey / …)

Grouping by `correlation_id` reconstructs, for each request, the full
three-plane story: what the policy decided, what KMIP did, and which
PKCS#11 engine calls (if any) actually ran. A *denied* request shows a p1
Deny and **no** p3 call — visible proof the agility layer stopped it before
the engine.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Optional

PLANE_LABEL = {"p1": "policy", "p2": "kmip", "p3": "pkcs11"}


@dataclass
class RequestTrail:
    correlation_id: str
    op: Optional[str] = None
    decision: Optional[str] = None  # "Allow" | "Deny" | "Rekey"
    decision_detail: str = ""
    kmip_result: Optional[str] = None  # "Success" | "OperationFailed: …"
    pkcs11_calls: list = field(default_factory=list)  # (function, mechanism, rv_name)
    policy_loaded: Optional[str] = None  # set for a PolicyActivated (startup) event
    events: list = field(default_factory=list)  # raw events in arrival order

    @property
    def is_request(self) -> bool:
        """True for a real KMIP request (has an op / decision / engine call);
        False for envelope events like the startup PolicyActivated."""
        return bool(self.op or self.decision or self.pkcs11_calls)


def load_events(path: str) -> list[dict]:
    """Read a JSONL audit log into a list of event dicts (order preserved)."""
    events = []
    with open(path, "r") as fh:
        for line in fh:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def group(events: list[dict]) -> list[RequestTrail]:
    """Group events by correlation_id into ordered RequestTrails (first-seen
    correlation order). Each trail summarises the p1/p2/p3 story."""
    trails: dict[str, RequestTrail] = {}
    order: list[str] = []
    for ev in events:
        cid = ev.get("correlation_id", "?")
        if cid not in trails:
            trails[cid] = RequestTrail(correlation_id=cid)
            order.append(cid)
        t = trails[cid]
        t.events.append(ev)
        payload = ev.get("event", {})
        etype = payload.get("type")
        if etype == "PolicyActivated":
            t.policy_loaded = payload.get("policy_name")
        elif etype == "PolicyDecided":
            t.op = t.op or payload.get("op")
            outcome = payload.get("outcome", {})
            t.decision = outcome.get("type")
            if t.decision == "Deny":
                t.decision_detail = outcome.get("reason", "")
            elif t.decision == "Rekey":
                t.decision_detail = f"-> {outcome.get('new_algorithm', '?')}"
            elif t.decision == "Allow" and outcome.get("algorithm_override"):
                t.decision_detail = f"override -> {outcome['algorithm_override']}"
        elif etype == "KmipResponseSent":
            t.op = payload.get("op", t.op)
            res = payload.get("result", {})
            if res.get("type") == "Success":
                t.kmip_result = "Success"
            else:
                t.kmip_result = f"OperationFailed: {res.get('reason', '')}"
        elif etype == "KmipRequestReceived":
            t.op = t.op or payload.get("op")
        elif etype == "Pkcs11Call":
            t.pkcs11_calls.append(
                (payload.get("function"), payload.get("mechanism"), payload.get("rv_name"))
            )
    return [trails[c] for c in order]


def format_trail(t: RequestTrail, *, color: bool = True) -> str:
    """One human-readable block for a single request trail."""
    def c(code: str, s: str) -> str:
        return f"\033[{code}m{s}\033[0m" if color else s

    if t.decision == "Allow":
        mark = c("32", "ALLOW")
    elif t.decision == "Deny":
        mark = c("31", "DENY")
    elif t.decision == "Rekey":
        mark = c("33", "REKEY")
    else:
        mark = c("90", "?")

    lines = [f"{mark}  {t.op or '?'}  ({t.correlation_id[:8]})"]
    detail = t.decision_detail
    lines.append(f"    p1 policy : {t.decision or '—'}" + (f"  {detail}" if detail else ""))
    lines.append(f"    p2 kmip   : {t.kmip_result or '—'}")
    if t.pkcs11_calls:
        for fn, mech, rv in t.pkcs11_calls:
            mech_s = f" [{mech}]" if mech else ""
            rv_s = "" if rv in (None, "CKR_OK") else c("31", f" {rv}")
            lines.append(f"    p3 pkcs11 : {fn}{mech_s}{rv_s}")
    else:
        none = c("90", "(no engine call)")
        lines.append(f"    p3 pkcs11 : {none}")
    return "\n".join(lines)


def format_log(path: str, *, color: bool = True) -> str:
    """Load, group, and format an entire audit log as correlated trails.

    Startup `PolicyActivated` envelope events render as a one-line banner;
    every real KMIP request renders as a three-plane block."""
    def c(code: str, s: str) -> str:
        return f"\033[{code}m{s}\033[0m" if color else s

    blocks = []
    for t in group(load_events(path)):
        if t.policy_loaded and not t.is_request:
            blocks.append(c("36", f"● policy active: {t.policy_loaded}"))
        elif t.is_request:
            blocks.append(format_trail(t, color=color))
    return "\n\n".join(blocks)


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("usage: python -m pykmip.audit <audit-log.jsonl>", file=sys.stderr)
        raise SystemExit(2)
    print(format_log(sys.argv[1]))
