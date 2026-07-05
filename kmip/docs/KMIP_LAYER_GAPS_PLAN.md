# KMIP-layer algorithm gaps — implementation plan

**Date**: 2026-07-05. **Trigger**: the 2026-07-04 CACP policy-gap audit
(`docs/CACP_GUIDE.md` §4) found that several algorithm names the policy engine
recognizes as vocabulary (`Ed25519`, `X25519`, `X448`, `HSS`, `XMSS`, `LMS`,
`XMSS-MT`, `Ed448`) cannot actually be created through a real KMIP
`CreateKeyPair`/`Sign` request — the hub picker marks them "spec-only." This
plan is the result of tracing each one down to its actual implementation
status (or absence) in `rust/` (softhsmrustv3, the PKCS#11 engine) and `kmip/`
(the KMIP 3.0 protocol crate this session's audit operated on), so that
"spec-only" claims are accurate and the real, tractable gaps get fixed.

**Source-of-truth rule (unchanged, per project convention)**: every KMIP wire
value from `spec/oasis-kmip-3.0/kmip-spec-3.0-tags-enums.json` (verified: this
extract is from the pre-WD19 public-review snapshot, so it stops at
`SLH-DSA-SHAKE-256f` = `0x4a` — WD19's hybrid-KEM additions at `0x5c`/`0x5d`
are NOT in it and were verified separately against the vendored WD19 PDF).
Every `CKM_*`/`CKK_*` from `rust/src/constants.rs`.

**Terminology guard — DO NOT CONFLATE these four during implementation.**
Same underlying curve family, four unrelated purposes; a key generated for
one is never usable for another:

| Name | Curve form | Purpose | Key type | Keygen mech | Use mech | OID (RFC 8410) |
|---|---|---|---|---|---|---|
| Ed25519 | Edwards (Curve25519) | Sign (EdDSA) | `CKK_EC_EDWARDS` | `CKM_EC_EDWARDS_KEY_PAIR_GEN` | `CKM_EDDSA` | `1.3.101.112` |
| X25519  | Montgomery (Curve25519) | Key agreement | `CKK_EC_MONTGOMERY` | `CKM_EC_MONTGOMERY_KEY_PAIR_GEN` | `CKM_X25519` | `1.3.101.110` |
| Ed448   | Edwards (Curve448) | Sign (EdDSA) | `CKK_EC_EDWARDS` | not implemented | not implemented | `1.3.101.113` |
| X448    | Montgomery (Curve448) | Key agreement | `CKK_EC_MONTGOMERY` | `CKM_EC_MONTGOMERY_KEY_PAIR_GEN` | `CKM_X448` | `1.3.101.111` |

P1 below touches Ed25519 ONLY (Edwards/signing). P2 touches X25519/X448 ONLY
(Montgomery/key-agreement). Ed448 is out of scope entirely (row above, no
implementation to build on). The OIDs happen to sit in one sequential IANA
arc (110/111/112/113) — that is a numbering coincidence, not a relationship;
each value was verified independently against RFC 8410, not inferred from
the others.

**Explicitly out of scope for this plan** (per direction): FrodoKEM, Classic
McEliece — not implemented at any layer, no crypto crate dependency, skip.
Composite/hybrid signatures — already scoped as a separate, deferred
work package (see `CACP_GUIDE.md` §4); this plan does not revisit it.

---

## Findings — what's actually implemented where

| Algorithm | `rust/` (PKCS#11 engine) | `kmip/` (protocol layer) | Verdict |
|---|---|---|---|
| **Ed25519** | Full: keygen (`CKM_EC_EDWARDS_KEY_PAIR_GEN`, `ffi.rs:1877`), sign (`CKM_EDDSA`, `ffi.rs:3438`), verify (`ffi.rs:3765`) | No `KmipAlgorithm` variant; `parse_algorithm` doesn't recognize it | **Tractable — full round trip possible** |
| Ed448 | Not implemented — no crate dependency (`ed448-goldilocks` or similar), no keygen/sign path anywhere | Missing | Skip — needs a new crypto dependency, not just plumbing |
| X25519 (standalone key agreement) | Keygen full (`CKM_EC_MONTGOMERY_KEY_PAIR_GEN`, distinguishes X25519 from X448 via OID); DH derive full (`CKM_X25519`, `ffi.rs:5812`) | No `KmipAlgorithm` variant. **`DeriveKey`'s `Asymmetric Key` method is explicitly unimplemented** (`derive_key.rs` doc comment: "fail with Operation Not Supported ... this stack has no honest backing for them at the KMIP layer") | **Not a quick fix** — keygen exists, but the KMIP layer has no operation that actually performs Diffie-Hellman agreement. Creating the key pair alone would be inert. |
| X448 (standalone key agreement) | Same as X25519 (own `x448` crate, confirmed in `Cargo.toml`) | Same gap as X25519 | Same as X25519 |
| **Plain `Ecdh` (already an enum variant!)** | Keygen mechanism mapped (`(Ecdsa, KeyGen) \| (Ecdh, KeyGen) => CKM_EC_KEY_PAIR_GEN`) but **`native_generate_keypair`'s match has no `Ecdh =>` arm** — falls to the `_ => Err(OperationNotSupported)` catch-all (`create_key_pair.rs`) | Enum variant exists, wire codepoint `0x0e` correct, but unusable | **Real, standing bug** — every policy that allowlists `ECDH-P256`/`-P384`/`-P521` (bsi-tr-02102, fips-only, classical.yaml) is currently allowlisting an algorithm that fails at Plane 2 with `OperationNotSupported` if actually created. My 2026-07-04 policy fixes were policy-plane-correct but did not (and could not, from that vantage point) catch this Plane-2 gap, since the audit's engine matrix drove `Engine::evaluate` (Plane 1 policy decisions) directly, never the real `create_key_pair` dispatcher. |
| HSS / LMS / XMSS / XMSS-MT | **Keygen only** (`ffi.rs:2072` — `CKM_HSS_KEY_PAIR_GEN`, incl. the `levels=1` single-tree-LMS special case). **`Sign` has no arm for `CKM_HSS`/`CKM_XMSS`/`CKM_XMSSMT`** — falls to `_ => Err(CKR_MECHANISM_INVALID)` (`ffi.rs:3438` area) | Missing | Skip for this plan — signing state management (one-time-signature trees) is genuinely unimplemented, comparable in size to the composite-signature work, not a quick fix |

## Priority order

1. **P0 — fix the standing `Ecdh` keygen bug.** This is the most urgent: it's
   not a "spec-only, honestly labeled" gap like the others — it's a policy
   that currently *claims* ECDH is creatable and is wrong. Three policies
   reference it. Fix before anything else in this plan.
2. **P1 — add Ed25519 as a full first-class algorithm.** Complete round trip
   (Create → Activate → Sign → Verify) achievable with existing crypto; no new
   dependency, no new KMIP operation needed.
3. **P2 — (optional, larger) add ECDH/X25519/X448 Diffie-Hellman agreement.**
   Requires implementing `DeriveKey`'s `Asymmetric Key` method (or a
   dedicated `Agree`-style op) — a real KMIP operation this stack doesn't
   have today. Scope this as its own follow-on once P0/P1 land; don't bundle.

---

## P0 — `Ecdh` keygen

**Goal**: `CreateKeyPair:KeyAgreement` with `algorithm=ECDH-P256/-P384/-P521`
actually succeeds at Plane 2, matching what the policy layer already allows.

1. **`rust/src/native/keygen.rs`** — add `pub fn generate_ecdh_keypair(session,
   curve: EccCurve, cka_id, label) -> Result<(u32,u32), CkRv>`. Mirror
   `generate_ecdsa_keypair` exactly (same p256/p384/p521 crates, same
   `CKA_EC_POINT`/`CKA_PUBLIC_KEY_INFO` construction) but set
   `store_algo_family(..., ALGO_ECDH)` and the key-agreement usage attributes
   (`CKA_DERIVE=true`, `CKA_SIGN=false`) instead of the signing ones. Reuse
   `EccCurve` — no new curve enum needed (K-256/secp256k1 arm can be omitted;
   ECDH-K256 isn't referenced by any policy).
2. **`kmip/src/ops/create_key_pair.rs`** — add an `Ecdh => { let curve =
   ecdsa_curve_from_length(key_length)?; ("native::generate_ecdh_keypair",
   native::generate_ecdh_keypair(session, curve, cka_id, label)) }` arm to
   `native_generate_keypair`'s match (reuse `ecdsa_curve_from_length` — same
   256/384/521 → curve inference already used for `Ecdsa`).
3. **Tests**: unit test in `create_key_pair.rs` (or a new
   `create_key_pair_ecdh` test) creating an `ECDH-P256`/`-P384`/`-P521` key
   pair and asserting success + correct `CKA_DERIVE` usage mask; extend the
   existing engine-matrix-style coverage to confirm `CreateKeyPair:KeyAgreement`
   + `ECDH-P256` now returns `Allow` **and** the op actually succeeds (not just
   the policy decision).
4. No wire-codepoint change, no WASM facade change beyond a rebuild, no policy
   YAML change needed — this closes a gap under already-correct policies.

## P1 — Ed25519

**Goal**: `Ed25519` becomes a full `KmipAlgorithm` variant with working
`CreateKeyPair` → `Sign` → `SignatureVerify`.

1. **`kmip/src/kmip30/algos.rs`**:
   - Add `Ed25519,  // 0x37` to the enum (classical baseline section).
   - `to_wire_value`: `Ed25519 => 0x00000037` (verified against the spec
     extract above — this value predates WD19, it's in the base 3.0 enum).
   - `from_wire_value`: `0x00000037 => Ed25519`.
   - `canonical_name`: `Ed25519 => "Ed25519"`.
   - `to_pkcs11_mech`: `(Ed25519, KeyGen) => Some(CKM_EC_EDWARDS_KEY_PAIR_GEN)`,
     `(Ed25519, SignVerify) => Some(CKM_EDDSA)`.
   - Add to the exhaustive-match lists (`algorithm_is_quantum_safe` — classical,
     `false`; the enum-completeness test around line 397/406).
2. **`kmip/src/ops/create_key_pair.rs::parse_algorithm`** — add `"Ed25519" =>
   Ed25519` (exact match, no `-` suffix to split, same pattern as the hybrid
   KEM names).
3. **`rust/src/native/keygen.rs`** — add `pub fn generate_ed25519_keypair(...)`
   using `ed25519_dalek::SigningKey::generate` (same crate already used in
   `ffi.rs`), building `CKA_EC_POINT`/`CKA_PUBLIC_KEY_INFO` per RFC 8410 with
   OID `id-Ed25519 = 1.3.101.112` (verified directly against RFC 8410 —
   https://datatracker.ietf.org/doc/html/rfc8410 — not inferred from the
   adjacent X25519=110/X448=111 arc this codebase already uses in
   `ffi.rs:2026,2040`). DER: `06 03 2b 65 70`, matching the `06 03 2b 65 6e`/
   `6f` pattern already in `ffi.rs` for X25519/X448. Set `CKA_KEY_TYPE =
   CKK_EC_EDWARDS`, `CKA_SIGN=true`/`CKA_VERIFY=true`.
4. **`rust/src/native/sign.rs`** — add `pub fn sign_ed25519(sk_bytes, msg) ->
   Result<Vec<u8>, CkRv>` and `pub fn verify_ed25519(pk_bytes, msg, sig) ->
   Result<(), CkRv>`, delegating to `ed25519_dalek::Signer`/`Verifier` — pure
   Ed25519, no prehash variant (Ed25519ph) unless a policy needs it (none do
   currently; skip Ed25519ph for this pass).
5. **`kmip/src/ops/create_key_pair.rs::native_generate_keypair`** — add
   `Ed25519 => ("native::generate_ed25519_keypair",
   native::generate_ed25519_keypair(session, cka_id, label))`.
6. **`kmip/src/ops/sign.rs` / `signature_verify.rs`** — wire the
   `CKM_EDDSA` mechanism resolution/dispatch path (check how `Ecdsa`'s
   sign/verify currently resolves its mechanism from the stored key's
   algorithm + hash attribute; Ed25519 needs no hash attribute — EdDSA signs
   the raw message — so this is simpler than the ECDSA path, not more).
7. **`kmip/src/policy/rule.rs::ckm_name_to_code`** — add `"CKM_EDDSA" =>
   c::CKM_EDDSA` (currently absent from the policy engine's mechanism
   vocabulary — needed if any future policy wants to gate on it explicitly).
8. **Tests**: full round-trip unit test (Create → Activate → Sign → Verify)
   in `create_key_pair.rs`/`sign.rs`/`signature_verify.rs`; a KAT-style
   deterministic test if RFC 8032's Ed25519 test vectors are easy to vendor
   (check `kat/` directory conventions first — don't hand-roll if a fixture
   pattern already exists for other algorithms).
9. **Downstream** (after the Rust-side change lands and passes its own tests):
   rebuild WASM (`build-kmip-wasm.sh`), flip `Ed25519` from `runnable: false`
   to fully runnable in `kmipMeta.ts` (remove it from the "spec-only" bullet
   in `CACP_GUIDE.md` §3.1), and add positive Create/Sign/Verify scenarios to
   `policyScenarios.ts` for at least `cnsa-2.0` (Ed25519 is not CNSA-approved
   — should Deny) and `fips-only` (Ed25519 is FIPS 186-5-approved — should
   Allow, and now actually succeed end-to-end).

## P2 — ECDH / X25519 / X448 key agreement (separate follow-on, not this pass)

Needs an actual Diffie-Hellman **operation**, not just keygen:

- Implement `DeriveKey`'s `Asymmetric Key` method (§6.1.18.1 Table 304) —
  given a private key UID + a peer public value, perform ECDH/X25519/X448
  agreement and return the shared secret as a `Secret Data`/`Symmetric Key`
  object per the request's `object_type`. `rust/`'s `CKM_ECDH1_DERIVE` /
  `CKM_X25519` / `CKM_X448` derive paths (`ffi.rs:5812`) already do the raw
  crypto — this is dispatch + KMIP request/response shape work in
  `derive_key.rs`, not new crypto.
- For X25519/X448 keygen specifically: since KMIP's `CryptographicAlgorithm`
  enum has no distinct X25519/X448 value (confirmed: absent from the spec
  extract), the KMIP-correct representation is the **existing** `Ecdh`
  (`0x0e`) family value with curve selection via `CryptographicLength`
  (255-bit → X25519, 448-bit → X448) — the same pattern `Ecdsa` already uses
  for P-256/384/521. Do NOT invent new enum variants or extension codepoints
  for these; extend `ecdsa_curve_from_length`'s sibling for `Ecdh` to also
  recognize 255/448.
- Scope this only after P0/P1 are done and reviewed — it's materially larger
  (a new operation's request/response semantics, not just a keygen arm).
