# ML-DSA external-µ — vendor-extension scope (2026-08-26)

Companion to `docs/openssl-provider-coverage-audit-2026-08-25.md` (F36-6)
and `docs/openssl-provider-remediation-plan-phase6-2026-08-26.md`. This is
a **scope document, not an execution plan** — design and sequencing only,
written per explicit request, not yet approved for implementation.

## 1. Why this exists

F36-6 (coverage audit) originally called ML-DSA external-µ support "not
fixable... regardless of provider-side code." That was wrong. Verified
directly against sources, not memory:

- **PKCS#11 v3.2** (ratified OASIS Standard, `docs/refs/pkcs11-spec-v3.2-os.pdf`,
  03 June 2026 — the current, non-draft text): `CKM_ML_DSA` carries only
  `CK_SIGN_ADDITIONAL_CONTEXT` (hedge/context). No field anywhere in the
  spec carries a caller-supplied µ. Confirmed by full-text search, not a
  single hit for "mu" in the entire ratified document.
- **PKCS#11 v3.3** (in progress, not ratified, no date set): external-µ
  for ML-DSA is an active work item — [oasis-tcs/pkcs11#58](https://github.com/oasis-tcs/pkcs11/issues/58),
  discussed publicly at IETF 123 LAMPS by an OASIS PKCS#11 TC contributor
  ([slides](https://datatracker.ietf.org/meeting/123/materials/slides-123-lamps-falko-discussion-of-pkcs11-v32-proposal-00.pdf)),
  with the technical detail written up on IACR eprint
  ([2026/617](https://eprint.iacr.org/2026/617.pdf)): *"The upcoming PKCS#11
  version 3.2 will introduce ML-DSA in the pure and pre-hash variant.
  Providing external-µ as the input to the signature or verification
  function will be specified in version 3.3."*
- **Security standing**: external-µ is not a weakening. Per FIPS 204's own
  Sign_internal/Verify_internal (Algorithm 7/8, cited by NIST's own FAQ
  addendum) and confirmed in the eprint paper: unlike the pre-hash variant
  (which reverts to hash-then-sign security assumptions), external-µ
  *"preserves the security assumptions, as it is merely an implementation
  variant of the direct signing... variant of ML-DSA."* Computing µ in one
  module and signing in another is the same cryptographic operation split
  across a trust boundary, not a different, weaker one.
- **Industry precedent for a vendor-private stopgap**: Thales ships a
  proprietary PKCS#11 extension today for a closely related problem —
  retrieving short-message-representative material for XMSS/LMS
  ([`PQC_external_hash`](https://thalesdocs.com/gphsm/luna/7/docs/network/Content/sdk/extensions/pqc/PQC_external_hash.htm)).
  A vendor mechanism for this class of gap is an established pattern, not
  a novel risk.
- **Both engines' underlying crypto already has the primitive** — this is
  wiring, not new cryptography. OpenSSL's own default provider implements
  `OSSL_SIGNATURE_PARAM_MU` (`ml_dsa_sig.c`, confirmed live in the staged
  3.6.3 source), and the C++ engine's `OSSLMLDSA.cpp` already calls
  `EVP_PKEY-ML-DSA` directly — the same code path. The Rust engine's own
  `fips204-patched` crate has `ext_mu: Option<[u8; 64]>` threaded through
  its internal sign/verify functions (`ml_dsa.rs`) already, comment and
  all: *"ext_mu short-circuits this: the caller supplied µ directly."* It
  is not on the crate's public `Signer`/`Verifier` trait surface yet.

## 2. Scope

**In scope**: a vendor-private PKCS#11 mechanism, `CKM_PQCTODAY_ML_DSA_MU`,
usable for `C_Sign`/`C_Verify` against an existing `CKK_ML_DSA` key,
taking a caller-computed 64-byte µ (FIPS 204 Eq. 2) instead of a raw
message. Both engines. Provider wiring so an OpenSSL caller setting the
*standard* `OSSL_SIGNATURE_PARAM_MU=1` (no new OpenSSL-facing API —
that part is already standard) gets routed to this mechanism instead of
being rejected.

**Out of scope, deliberately**:
- `message-encoding=0` for arbitrary caller-supplied M′ under plain
  `CKM_ML_DSA` — no well-defined shape to accept (unlike µ, which is a
  fixed 64 bytes with one unambiguous meaning); stays rejected as today.
  `CKM_HASH_ML_DSA` already covers the one *standard*, well-shaped
  pre-hash case (separate, real gap — provider doesn't register it at
  all despite both engines implementing the mechanism family; not
  addressed here, candidate for a separate item if wanted).
- SLH-DSA's own external-hash story, or the Thales-style "retrieve
  hash-start material from the token" direction for XMSS/HSS — a
  different shape of problem, not requested here.
- Anything in `pkcs11t.h` itself. That header is kept byte-for-byte
  synced to the ratified spec per this project's own CLAUDE.md rule; a
  vendor mechanism belongs in `vendor_mechanisms.h` (C++) and the
  existing `CKM_PQCTODAY_*` block of `rust/src/constants.rs` (Rust),
  never in the canonical copy.

## 3. Mechanism design

`src/lib/vendor_mechanisms.h` currently allocates vendor mechanisms up
to `0x80000012` (`CKM_PQCTODAY_SPLIT_KEY`). Next free slot:

```c
// ── Vendor: ML-DSA external-µ signing (stopgap for PKCS#11 v3.3's own
// upcoming external-µ mechanism — oasis-tcs/pkcs11#58, not yet ratified)
// PQCTODAY-VENDOR-EXT-MU: remove this whole block, both engines' dispatch
// arms, and the provider's routing when this project adopts PKCS#11 v3.3
// natively. Search this exact tag project-wide to find every site.

#define CKM_PQCTODAY_ML_DSA_MU 0x80000013UL  /* vendor */

#define PQCTODAY_ML_DSA_MU_LEN 64  /* FIPS 204 Eq.(2): SHAKE256 output, fixed */

typedef struct CK_PQCTODAY_ML_DSA_MU_PARAMS {
    CK_HEDGE_TYPE hedgeVariant;              /* same semantics as CK_SIGN_ADDITIONAL_CONTEXT */
    CK_BYTE       mu[PQCTODAY_ML_DSA_MU_LEN]; /* caller-computed µ */
} CK_PQCTODAY_ML_DSA_MU_PARAMS;
```

No `pContext`/`ulContextLen` field: per FIPS 204 Eq. (1)–(2), the context
string is folded into `M′` *before* µ is derived (`µ = SHAKE256(tr ‖ M′,
512)`), and `Sign_internal`/`Verify_internal` (Algorithm 7/8) take no
separate context argument at all. Carrying a context field here would be
meaningless — the caller has already consumed it by the time µ exists.
Length is fixed at 64, not a `pMu`/`ulMuLen` pair — FIPS 204 defines no
other length, and a fixed-size field forecloses a whole class of
buffer-length mistakes for zero functional cost (same reasoning this
project already applied to `CK_HSS_KEY_PAIR_GEN_PARAMS`'s own fixed
`HSS_MAX_LEVELS` arrays).

Single mechanism for both directions (mirrors `CKM_ML_DSA`/`CKM_HASH_ML_DSA`
both being sign+verify): `C_Sign` treats `mu` as the value to sign
directly; `C_Verify` treats it as the value to check the signature
against, matching FIPS 204's own `verifyµ` (per the eprint paper's
notation).

## 4. Per-layer wiring

**C++ engine** (`src/lib/`):
- `vendor_mechanisms.h`: the block above.
- `SoftHSM.cpp` mechanism table / `SoftHSM_sign.cpp` dispatch: new case
  alongside the existing `HASH_MLDSA*` family, translating
  `CK_PQCTODAY_ML_DSA_MU_PARAMS` into a new field on the project-internal
  `MLDSA_SIGN_PARAMS` struct (`externalMu: bool` + `mu[64]`, parallel to
  the existing `preHash` field).
- `OSSLMLDSA.cpp` `sign()`/`verify()`: new branch parallel to the existing
  `useRawEncoding`/`preHash` branch (lines ~289–353 today) — set
  `OSSL_SIGNATURE_PARAM_MU=1` via `EVP_PKEY_CTX_set_params` instead of
  `MESSAGE_ENCODING=0`, pass the 64-byte `mu` as the `EVP_DigestSign`/
  `EVP_DigestVerify` data argument instead of the pre-hash-encoded buffer.
  Same shape as the code already there; OpenSSL does the actual crypto.
  Smallest-risk part of this whole item — reuses a working pattern in the
  same file, doesn't touch the pre-hash branch at all.

**Rust engine** (`rust/`):
- `constants.rs`: mirror `CKM_PQCTODAY_ML_DSA_MU = 0x8000_0013`, in the
  existing `CKM_PQCTODAY_*` block.
- `fips204-patched`: the crate is already a project-owned fork (patched
  once already, for Ph digest variants — see `Cargo.toml`'s own comment).
  `ext_mu` exists in `ml_dsa.rs`'s internal sign/verify functions but
  isn't on the public `Signer`/`Verifier` trait (`traits.rs`) — needs a
  new public entry point (e.g. `sign_with_mu`/`verify_with_mu`) that
  threads `ext_mu` through from outside the crate. This is the one place
  genuinely new code is needed, not just wiring — budget accordingly.
- `ffi.rs`/`crypto/handlers.rs`: new dispatch arm for
  `CKM_PQCTODAY_ML_DSA_MU`, calling the new crate entry point.

**Provider** (`src/vendor/pkcs11-provider/src/sig/mldsa.c`):
- Today: `p11prov_mldsa_set_ctx_params` explicitly rejects `mu != 0`
  (`CKR_ARGUMENTS_BAD "Unsupported 'mu' parameter"`) — correct, honest
  behavior for what the mechanism can do *today*, per F36-6's own
  original (if overstated) finding.
- Change: when `mu=1` is set, stop rejecting; at sign/verify time, read
  the caller's data buffer (which OpenSSL's own `ossl_ml_dsa_sign`-style
  `ctx->mu` convention already treats as the raw µ bytes, not a message
  to encode — confirmed against `ml_dsa_sig.c`), validate it is exactly
  `PQCTODAY_ML_DSA_MU_LEN` bytes (reject anything else loudly — same
  discipline as every other length check in this provider), build a
  `CK_PQCTODAY_ML_DSA_MU_PARAMS`, and call `C_Sign`/`C_Verify` with
  `CKM_PQCTODAY_ML_DSA_MU` instead of `CKM_ML_DSA`. `message-encoding`'s
  existing rejection (`!= 1`) is untouched — this item does not widen
  that.
- No change needed to what an OpenSSL caller sets — `OSSL_SIGNATURE_PARAM_MU`
  is already a standard OpenSSL param name; the vendor mechanism is purely
  an internal PKCS#11-side implementation detail of honoring it.

## 5. Removal path when v3.3 lands

Every site touched by this item carries the literal tag
`PQCTODAY-VENDOR-EXT-MU` in its comment (see §3's header block for the
exact string). When this project adopts ratified PKCS#11 v3.3:
`grep -rn PQCTODAY-VENDOR-EXT-MU` finds every touch point — the vendor
mechanism definition, both engines' dispatch arms, the crate's
`sign_with_mu`/`verify_with_mu` entry points, and the provider's routing
— for deletion or replacement with the native v3.3 mechanism/param
shape. The provider-side change is additive only (widens a rejection,
doesn't remove or restructure existing code), so removal is a clean
revert, not a re-design.

## 6. Test plan (when executed)

Mirrors this project's own house discipline (own arena, sabotage twins,
cross-implementation verify):
- New raw-PKCS#11 tool computing µ independently in software exactly per
  FIPS 204 Eq. (1)–(2) from a known message/context/public key, feeding
  it through `CKM_PQCTODAY_ML_DSA_MU`, and verifying the resulting
  signature two ways: (a) via the SAME mechanism's own `C_Verify` against
  the same µ, and (b) — the real proof — via OpenSSL's own native
  `EVP_PKEY-ML-DSA` verify against the ORIGINAL raw message, proving the
  µ-signed signature is byte-for-byte what a direct pure-ML-DSA signature
  of that message would have produced.
- Sabotage: flipped byte in µ must fail both verify paths; wrong-length
  µ must fail loudly at `set_ctx_params`/`C_Sign` time, not silently
  truncate or pad.
- Regression: full harness + C++ CTest + `cargo test --release` (Rust
  touched — crate change).

## 7. Effort estimate

| Component | Effort | Risk |
|---|---|---|
| `vendor_mechanisms.h` | XS | none — additive constant + struct |
| C++ engine wiring | S | low — mirrors existing pre-hash branch in the same file |
| Rust: `fips204-patched` public API extension | S–M | low-medium — new code, not just wiring, but the underlying primitive is already implemented and tested inside the crate |
| Rust: FFI/dispatch wiring | S | low |
| Provider (`sig/mldsa.c`) | S | low — narrows an existing rejection, doesn't restructure |
| Test tooling + harness cases | S–M | low |

Total: **effort M**, no component individually risky. Not scheduled;
this document scopes it for a future execution decision.
