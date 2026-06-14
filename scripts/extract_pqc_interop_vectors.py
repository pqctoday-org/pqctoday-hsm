#!/usr/bin/env python3
"""I0 extractor: parse the 1452 OASIS KMIP 3.0 PQC interop XML transcripts into
compact engine-level (input -> expected-output) vectors.

Each transcript is a KMIP request/response replay carrying CONCRETE deterministic
values. We strip the leading `#` annotation lines (not valid XML), wrap the
multiple top-level <RequestMessage>/<ResponseMessage> under the single <KMIP>
root, and pull the per-category fields by KMIP tag.

Categories:
  keygen  : Seed -> expected private-key Raw KeyMaterial (expanded sk) + public-key Raw
  siggen  : sk(Raw) + Data(msg) + ContextString + Deterministic -> expected SignatureData
  sigver  : pk(Raw) + Data(msg) + SignatureData + ContextString -> expected ValidityIndicator
  decap   : dk(Raw) + Data(ct) -> expected shared-secret (Get KeyMaterial)
  encap   : ek(Raw) + InputKeyMaterial(coins m) -> expected ct(Data) + ss(Get KeyMaterial)
"""
import glob, json, os, re, sys
import xml.etree.ElementTree as ET

SRC = sys.argv[1] if len(sys.argv) > 1 else "/tmp/kmip-pqc/kmip-3-0-pqc-tests"
OUT = sys.argv[2] if len(sys.argv) > 2 else "/tmp/pqc_interop_vectors.json"

def load(path):
    raw = open(path).read()
    lines = [l for l in raw.splitlines() if not l.lstrip().startswith("#")]
    body = "\n".join(lines)
    return ET.fromstring(body)

def family_of(name):
    # ML-DSA-44, ML-KEM-512, SLH-DSA-SHA2-128f
    m = re.match(r"(ML-DSA-\d+|ML-KEM-\d+|SLH-DSA-[A-Z0-9]+-\d+[fs])-", name)
    return m.group(1) if m else None

def text_val(el):
    return el.get("value")

def iter_payloads(root, op):
    """Yield RequestPayload elements for a given Operation value, paired with the
    following ResponsePayload (same batch order)."""
    # Collect request payloads and response payloads in document order.
    reqs, resps = [], []
    for msg in root:
        for bi in msg.findall("BatchItem"):
            o = bi.find("Operation")
            if o is None:
                continue
            if msg.tag == "RequestMessage":
                rp = bi.find("RequestPayload")
                reqs.append((o.get("value"), rp, bi))
            elif msg.tag == "ResponseMessage":
                rp = bi.find("ResponsePayload")
                resps.append((o.get("value"), rp, bi))
    return reqs, resps

def find_keymaterial(payload):
    """Return Raw KeyMaterial hex (KeyMaterial that is itself a ByteString)."""
    for km in payload.iter("KeyMaterial"):
        if km.get("type") == "ByteString":
            return km.get("value")
    return None

def extract(path):
    name = os.path.splitext(os.path.basename(path))[0]
    fam = family_of(name)
    root = load(path)
    reqs, resps = iter_payloads(root, None)
    rmap = {}  # index by operation occurrence

    if "keygen" in name:
        # CreateKeyPair req has Seed; subsequent Get(Raw) responses carry the
        # private-key (expanded sk) and public-key Raw KeyMaterial.
        seed = None
        for op, rp, bi in reqs:
            if op == "CreateKeyPair" and rp is not None:
                s = rp.find("Seed")
                if s is not None:
                    seed = s.get("value")
        sk_raw = pk_raw = None
        for op, rp, bi in resps:
            if op == "Get" and rp is not None:
                ot = rp.find("ObjectType")
                kb = rp.find(".//KeyBlock")
                if kb is None:
                    continue
                kft = kb.find("KeyFormatType")
                fmt = kft.get("value") if kft is not None else None
                otv = ot.get("value") if ot is not None else None
                if fmt == "Raw":
                    km = find_keymaterial(kb)
                    if otv == "PrivateKey":
                        sk_raw = km
                    elif otv == "PublicKey":
                        pk_raw = km
                elif fmt == "SeedPrivateKey" and otv == "PrivateKey" and sk_raw is None:
                    # ML-KEM (and ML-DSA) expose the expanded private key via the
                    # nested <Key> of a SeedPrivateKey KeyMaterial.
                    keyel = kb.find(".//KeyMaterial/Key")
                    if keyel is not None:
                        sk_raw = keyel.get("value")
        return {"family": fam, "category": "keygen", "name": name,
                "seed": seed, "sk": sk_raw, "pk": pk_raw}

    if "siggen" in name:
        sk_raw = None
        # private key registered Raw
        for op, rp, bi in reqs:
            if op == "Register" and rp is not None:
                ot = rp.find("ObjectType")
                if ot is not None and ot.get("value") == "PrivateKey":
                    kb = rp.find(".//KeyBlock")
                    kft = kb.find("KeyFormatType") if kb is not None else None
                    if kft is not None and kft.get("value") == "Raw":
                        sk_raw = find_keymaterial(kb)
        data = ctx = det = rnd = None
        internal = external_mu = False
        for op, rp, bi in reqs:
            if op == "Sign" and rp is not None:
                d = rp.find("Data")
                if d is not None:
                    data = d.get("value") or ""
                cp = rp.find("CryptographicParameters")
                if cp is not None:
                    de = cp.find("Deterministic")
                    det = (de is not None and de.get("value") == "true")
                    cs = cp.find("ContextString")
                    ctx = cs.get("value") if cs is not None else ""
                    it = cp.find("Internal")
                    internal = (it is not None and it.get("value") == "true")
                    em = cp.find("ExternalMu")
                    external_mu = (em is not None and em.get("value") == "true")
                    rn = cp.find("Random")
                    rnd = rn.get("value") if rn is not None else None
        sig = None
        for op, rp, bi in resps:
            if op == "Sign" and rp is not None:
                sd = rp.find("SignatureData")
                if sd is not None:
                    sig = sd.get("value")
        # external-mu: <Data> carries the 64-byte µ, not the message.
        # hedged (deterministic=false): <Random> carries the explicit signing
        # randomizer (ML-DSA rnd / SLH-DSA addrnd) needed for byte-exactness.
        return {"family": fam, "category": "siggen", "name": name,
                "sk": sk_raw, "msg": data or "", "context": ctx or "",
                "deterministic": bool(det), "internal": internal,
                "external_mu": external_mu, "random": rnd, "sig": sig}

    if "sigver" in name:
        pk_raw = None
        for op, rp, bi in reqs:
            if op == "Register" and rp is not None:
                ot = rp.find("ObjectType")
                if ot is not None and ot.get("value") == "PublicKey":
                    kb = rp.find(".//KeyBlock")
                    kft = kb.find("KeyFormatType") if kb is not None else None
                    if kft is not None and kft.get("value") == "Raw":
                        pk_raw = find_keymaterial(kb)
        data = sig = ctx = None
        internal = external_mu = False
        for op, rp, bi in reqs:
            if op == "SignatureVerify" and rp is not None:
                d = rp.find("Data")
                data = d.get("value") if d is not None else ""
                sd = rp.find("SignatureData")
                sig = sd.get("value") if sd is not None else None
                cp = rp.find("CryptographicParameters")
                if cp is not None:
                    cs = cp.find("ContextString")
                    ctx = cs.get("value") if cs is not None else ""
                    it = cp.find("Internal")
                    internal = (it is not None and it.get("value") == "true")
                    em = cp.find("ExternalMu")
                    external_mu = (em is not None and em.get("value") == "true")
        valid = None
        for op, rp, bi in resps:
            if op == "SignatureVerify" and rp is not None:
                vi = rp.find("ValidityIndicator")
                if vi is not None:
                    valid = (vi.get("value") == "Valid")
        return {"family": fam, "category": "sigver", "name": name,
                "pk": pk_raw, "msg": data or "", "context": ctx or "",
                "internal": internal, "external_mu": external_mu,
                "sig": sig, "valid": valid}

    if "decapsulation" in name:
        dk_raw = None
        for op, rp, bi in reqs:
            if op == "Register" and rp is not None:
                ot = rp.find("ObjectType")
                if ot is not None and ot.get("value") == "PrivateKey":
                    kb = rp.find(".//KeyBlock")
                    kft = kb.find("KeyFormatType") if kb is not None else None
                    if kft is not None and kft.get("value") == "Raw":
                        dk_raw = find_keymaterial(kb)
        ct = None
        for op, rp, bi in reqs:
            if op == "Decapsulate" and rp is not None:
                d = rp.find("Data")
                if d is not None:
                    ct = d.get("value")
        ss = None
        # shared secret comes back via Get on the SS object
        for op, rp, bi in resps:
            if op == "Get" and rp is not None:
                kb = rp.find(".//KeyBlock")
                if kb is not None:
                    km = find_keymaterial(kb)
                    if km is not None and len(km) == 64:  # 32-byte ss
                        ss = km
            if op == "Decapsulate" and rp is not None:
                # some encode ss directly in Decapsulate response Data
                d = rp.find("Data")
                if d is not None and ss is None:
                    ss = d.get("value")
        return {"family": fam, "category": "decap", "name": name,
                "dk": dk_raw, "ct": ct, "ss": ss}

    if "encapsulation" in name:
        ek_raw = None
        for op, rp, bi in reqs:
            if op == "Register" and rp is not None:
                ot = rp.find("ObjectType")
                if ot is not None and ot.get("value") == "PublicKey":
                    kb = rp.find(".//KeyBlock")
                    kft = kb.find("KeyFormatType") if kb is not None else None
                    if kft is not None and kft.get("value") == "Raw":
                        ek_raw = find_keymaterial(kb)
        coins = None
        for op, rp, bi in reqs:
            if op == "Encapsulate" and rp is not None:
                ikm = rp.find(".//InputKeyMaterial")
                if ikm is not None:
                    coins = ikm.get("value")
        ct = ss = None
        for op, rp, bi in resps:
            if op == "Encapsulate" and rp is not None:
                d = rp.find("Data")
                if d is not None:
                    ct = d.get("value")
            if op == "Get" and rp is not None:
                kb = rp.find(".//KeyBlock")
                if kb is not None:
                    km = find_keymaterial(kb)
                    if km is not None and len(km) == 64:
                        ss = km
        return {"family": fam, "category": "encap", "name": name,
                "ek": ek_raw, "coins": coins, "ct": ct, "ss": ss}

    return None

def main():
    out = {"provenance": {
        "source": "OASIS KMIP 3.0 PQC interop test set (kmip-3-0-pqc-tests-03.zip, 2025-02-26)",
        "url": "https://kmip-interop.org/test-xml/",
        "note": "Engine-level (input->expected-output) vectors extracted from the 1452 KMIP XML transcripts for softhsmrustv3 native byte-exact validation (I0).",
    }, "vectors": []}
    files = sorted(glob.glob(os.path.join(SRC, "*.xml")))
    n = 0
    incomplete = []
    for f in files:
        try:
            v = extract(f)
        except Exception as e:
            print(f"ERROR {f}: {e}", file=sys.stderr)
            continue
        if v is None:
            print(f"SKIP (unclassified) {f}", file=sys.stderr)
            continue
        out["vectors"].append(v)
        n += 1
    json.dump(out, open(OUT, "w"), separators=(",", ":"))
    print(f"extracted {n} vectors -> {OUT}")
    # summary
    from collections import Counter
    c = Counter((v["family"], v["category"]) for v in out["vectors"])
    for k in sorted(c):
        print(f"  {k[0]:24s} {k[1]:8s} {c[k]}")

if __name__ == "__main__":
    main()
