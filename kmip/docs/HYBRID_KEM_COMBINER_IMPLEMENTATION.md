# Hybrid-KEM combiner — REVISED implementation plan

**Date**: 2026-07-05 (revised after an adversarial review of the first draft).
Companion to `HYBRID_KEM_PKCS11_COMPLIANT_REBUILD_PLAN.md`. This revision
exists because the first draft had four real flaws — a self-defeating API, an
over-broad correctness claim, a glossed interop blind spot, and unverified
recipes stated as fact. Each is corrected below and called out explicitly, and
every load-bearing fact is now grounded in the actual code or a primary source
(no recited-from-memory recipes).

## Grounded facts (verified against the code, this revision)

- **The defect, precisely.** `kmip/src/ops/get.rs:139` returns
  `obj.key_material` in the clear when it is `Some`. `create_key_pair`'s
  hybrid branch stores the raw composite private key in `key_material`
  (`create_key_pair.rs` ~285). So `Get` on a hybrid private key returns the
  raw private key.
- **The fix shape is already the norm for every other key type.** For
  engine-backed keys, `key_material = None` and the material lives behind a
  `pkcs11_cka_id` → PKCS#11 object; `Get` then refuses it via the
  `CKA_SENSITIVE` gate (compliance-audit B-4). So making hybrid keys
  engine-backed reuses the existing, tested non-extractability path — no new
  Get logic.
- **`generate_ml_kem_keypair` sets `CKA_EXTRACTABLE=false`/`CKA_SENSITIVE=true`**
  (`keygen.rs:447-448`); `generate_ecdh_keypair` (P0) does the same. So real
  engine key objects are non-extractable by construction.
- **`ObjectRecord`** (`store/traits.rs:41`) has a SINGLE `pkcs11_cka_id:
  Vec<u8>` + `key_material: Option<Vec<u8>>`; sqlite persists both.
- **PKCS#11 v3.2** (published spec, extracted): no dedicated hybrid-KEM
  mechanism; the composable derive building blocks (all committed, 219 tests)
  are `CKM_CONCATENATE_BASE_AND_KEY` §6.43.3, `..._BASE_AND_DATA` §6.43.4,
  `CKM_SHA*_KEY_DERIVATION` §6.22/§6.29, `CKM_HKDF_DERIVE` §6.62 (+
  `CKF_HKDF_SALT_KEY`).
- **The three IANA TLS groups** (`draft-ietf-tls-ecdhe-mlkem`, order
  load-bearing): X25519MLKEM768 0x11EC (ML-KEM‖X25519, 64B), SecP256r1MLKEM768
  0x11EB (ECDH‖ML-KEM, 64B), SecP384r1MLKEM1024 0x11ED (ECDH‖ML-KEM, 80B).
  **All three are PURE CONCATENATION** — no hash, no KDF.

## Correction 1 (critical) — handle-based API, not bytes

The first draft's `native::hybrid::decapsulate(hybrid, dk: &[u8],
classical_secret: &[u8], ct)` took the private key AS BYTES. That forces the
caller to extract the private material — defeating the whole non-extractability
fix. **Corrected API passes HANDLES; `rust/` reads the values internally
(`get_object_value` works on non-extractable objects — it's an internal read,
not an export), so the private bytes never enter `kmip/`:**

```
native::hybrid::keygen(session, hybrid)
    -> Result<HybridKeyGen, CkRv>   // wire share + two NON-EXTRACTABLE handles
struct HybridKeyGen { public: Vec<u8>, mlkem_priv: u32, classical_priv: u32 }

native::hybrid::encapsulate(session, hybrid, peer_public: &[u8])
    -> Result<Encapsulated, CkRv>   // ciphertext + combined shared secret
    // encapsulation uses only the PEER's public + a fresh ephemeral; no
    // long-term private key involved, so no handle needed here.

native::hybrid::decapsulate(session, hybrid, mlkem_priv: u32,
                            classical_priv: u32, ct: &[u8])
    -> Result<Vec<u8>, CkRv>        // reads both handles' values in-HSM
```

Keygen builds the two component keys via `generate_ml_kem_keypair` +
`generate_ecdh_keypair`/a Montgomery keygen (non-extractable), returns their
handles. The composite wire share is assembled from the two public keys.

## Correction 2 (high) — scope the claim honestly

The first draft claimed the two shapes (Concat / DualPrf) express *all*
combiners. **False for n-ary keyed-PRF chains**: RFC 9370 (IKEv2) chains up to
7 key exchanges through an iterated keyed PRF — neither "concatenate n" nor "one
dual-PRF over 2." **Corrected scope:** the HSM provides the composable
*primitives* and *composes the two-component registered TLS combiners*; n-ary
keyed-PRF chaining is the calling protocol's orchestration (the IKE daemon
calls the KEM/PRF primitives and chains them itself), explicitly out of scope
for the HSM. The plan claims only what it delivers: the three pure-concat TLS
groups, plus a general two-input combiner executor.

## Correction 3 (high) — state the interop blind spot

A round-trip test (encap then decap agree) proves **self-consistency, not
interoperability**: a shared byte-ordering bug present in BOTH encap and decap
would still agree, passing green while being non-interoperable with
OpenSSL/BoringSSL. There is no published combined KAT to catch this (verified —
none at IETF/NIST/BoringSSL/Go). **Mitigations, stated plainly:**
1. Anchor each COMPONENT to its real KAT (ML-KEM ACVP already in-repo; X25519
   RFC 7748 §5.2 vectors — to add).
2. A structural test asserting the exact per-variant ordering (ML-KEM ss in
   bytes [0..32] for X25519MLKEM768; [32..64] for the SecP variants) — this is
   only as strong as the spec ordering I encoded, so it is cross-checked
   against the draft's "SS = concat(...)" text.
3. **Known residual risk, documented, not hidden:** true interop proof needs a
   handshake against a reference implementation (OpenSSL 3.5 X25519MLKEM768) —
   an integration test out of unit-test scope, flagged as a follow-on. The
   unit suite CANNOT prove interop; it proves the components are KAT-correct and
   the composition order matches my reading of the spec.

## Correction 4 (medium) — recipes now VERIFIED against primary sources

The first draft recited SSH/X-Wing recipes from memory (and got SSH's hash
wrong — said SHA-512). Both are now verified against their authoritative
sources, so they are stated as fact WITH the source, not dropped:

**SSH `mlkem768x25519-sha256`** — verified from the OpenSSH source vendored in
this repo (`openssh-pkcs11/build/openssh-src/kexmlkem768x25519.c` +
`kex.h:67`). The shared secret is:
```
SS = SHA-256( ss_mlkem ‖ ss_x25519 )      # ML-KEM shared secret first
```
The code builds `buf = enc.snd (ML-KEM ss) ‖ ECDH-shared-key`, then
`ssh_digest_buffer(kex->hash_alg=SHA-256, buf, hash)`. (My earlier "SHA-512"
was wrong — the method name literally ends `-sha256`.) As a recipe:
`Concat { finalize: [Digest(CKM_SHA256_KEY_DERIVATION)] }`,
components `[ss_mlkem, ss_x25519]`.

**X-Wing** — verified from `draft-connolly-cfrg-xwing-kem`:
```
SS = SHA3-256( ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ XWingLabel )
XWingLabel = 0x5c 2e 2f 2f 5e 5c   (6-byte ASCII "\.//^\")
```
where `ss_M` = ML-KEM-768 ss (first), `ss_X` = X25519 ss, `ct_X` = X25519
ephemeral public, `pk_X` = X25519 public key. **The ML-KEM ciphertext `ct_M`
is deliberately OMITTED** (X-Wing relies on ML-KEM-768's FO ciphertext-binding;
the draft states this explicitly). As a recipe:
`Concat { finalize: [ConcatData(ct_X ‖ pk_X ‖ XWingLabel), Digest(CKM_SHA3_256_KEY_DERIVATION)] }`,
components `[ss_M, ss_X]`.

**Crucial distinction (this is why "same primitives" ≠ "same combiner"):**
X-Wing and the TLS `X25519MLKEM768` group both pair ML-KEM-768 with X25519, but
use DIFFERENT combiners — X-Wing hashes with a transcript+label (SHA3-256), the
TLS group is PURE CONCATENATION (no hash). They are not interchangeable. Only
the three TLS groups ship in increment 3 (they have KMIP codepoints); SSH and
X-Wing are now verified recipes expressible in the executor and unit-tested at
the executor level, but not wired to a KMIP algorithm (no codepoint).

## Correction 5 (medium) — honest about the mechanism, and fix the litter

For the three PURE-CONCAT groups, routing the combine through
`CKM_CONCATENATE_BASE_AND_KEY` is **uniform machinery, not a security or
correctness gain** over an inline concat — `[a,b].concat()` yields identical
bytes. It earns its keep for (a) external PKCS#11 C_DeriveKey conformance and
(b) combiners that DO have a hash/KDF step. Decision: **use the executor** (so
pure-concat and future hash/KDF combiners share one code path and the composition
happens in the audited derive machinery), but:
- **Destroy the intermediate component/running handles** after extracting the
  final secret (the first draft leaked them — `register_derived_secret` makes
  them extractable and they accumulated per op). Add `native::destroy_object`
  use or mark them session-scoped and reap.
- Be precise: the intermediates are the KEM's own component secrets (parts of
  a value that gets released anyway), so the leak was hygiene, not disclosure —
  but it's fixed regardless.

## Correction 6 (low) — no invented codepoint

`SecP384r1MLKEM1024` has no WD19 KMIP `CryptographicAlgorithm` value (verified
— WD19 stops at 0x5D). The first draft said "use 0x8XXXXXXX" without a value.
**Corrected:** assign a clearly-marked VENDOR/EXTENSION codepoint in the
reserved range, documented as non-standard and pending OASIS assignment (same
posture as the composite-signature codepoints), with the exact value chosen and
recorded in `algos.rs` — not left as "some 0x8… value."

## The combiner executor (unchanged core, litter fixed)

```
pub enum Combiner {
    Concat { finalize: Vec<FinalizeStep> },          // n components concatenated, then finalize
    DualPrf { prf: u32, info: Vec<u8>, len: usize },  // HKDF-Extract(salt=ss1, IKM=ss2)
}
pub enum FinalizeStep { ConcatData(Vec<u8>), Digest(u32), Hkdf{prf,salt,info,len} }
run_combiner(session, components: &[&[u8]], combiner: &Combiner) -> Result<Vec<u8>, CkRv>
```
The 3 TLS groups use `Concat { finalize: [] }`. DualPrf and the finalize steps
are tested at the executor level (proving the mechanisms compose) but not wired
to a shipped algorithm.

## Increment 3 — ordered, grounded steps

3a. `native::hybrid` — three-variant crypto with the **handle-based** API
    (Correction 1); combine via `run_combiner`; intermediates destroyed
    (Correction 5). Tests: round-trip (self-consistency, per Correction 3),
    structural ordering, wrong-length rejection, and a NON-EXTRACTABILITY unit
    test (the decap handles' `CKA_EXTRACTABLE` is false).
3b. `ObjectRecord`: add `pkcs11_cka_id_secondary: Option<Vec<u8>>` (grounded in
    the real single-cka_id struct); hybrid objects set BOTH cka_ids,
    `key_material = None`. sqlite + memory backends updated.
3c. Rewire `create_key_pair` (two engine keys, no key_material), `encapsulate`
    (assemble share from the two public handles), `decapsulate` (pass the two
    private handles to `native::hybrid::decapsulate`), and confirm `get.rs`
    now refuses the hybrid private via the EXISTING CKA_SENSITIVE path (no new
    Get code — add a regression test).
3d. `Destroy`/`Locate` reconcile both handles.
3e. `SecP384r1MlKem1024` KmipAlgorithm (Correction 6 codepoint) +
    parse/mech mapping; `kmip/hybrid_kem.rs` → thin re-export of the native
    enum; remove `ml-kem`/`x25519-dalek`/`p256` from `kmip/Cargo.toml`.
3f. Tests: component KATs, structural, round-trip, non-extractability
    regression (`Get` on a hybrid private half returns no key material).
    Interop-vs-OpenSSL flagged as an out-of-scope follow-on (Correction 3).

## What this plan deliberately does NOT claim

- It does NOT claim unit tests prove interoperability (Correction 3).
- It does NOT claim to express every combiner — only the two-input shapes;
  n-ary keyed-PRF chains are the daemon's job (Correction 2).
- It does NOT ship SSH/X-Wing recipes (Correction 4).
