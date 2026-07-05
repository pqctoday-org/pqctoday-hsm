# Hybrid KEM — PKCS#11 v3.2-compliant rebuild plan

**Date**: 2026-07-05. **Trigger**: two problems found while answering questions
about the existing `hybrid_kem.rs` design (not part of the original policy
audit): (1) it puts crypto crates directly in the `kmip/` protocol layer,
violating this project's own architecture boundary; (2) the private key
material is extractable via a plain KMIP `Get` — it never enters the PKCS#11
engine's protected object store at all. This plan rebuilds it to be
PKCS#11 v3.2-compliant and architecturally correct. **Not started — this is
the plan only**, queued behind P1 (Ed25519) in `KMIP_LAYER_GAPS_PLAN.md`.

## The two problems, precisely

1. **Crypto in the wrong layer.** `kmip/src/hybrid_kem.rs` calls `ml_kem`,
   `x25519-dalek`, `p256` directly. `kmip/Cargo.toml:175-176` lists them as
   real dependencies; `Cargo.toml:204`'s own comment admits they were "moved
   to `[dependencies]`" for this one file. All cryptography must live in
   `rust/` (softhsmrustv3) — `kmip/` calls it via plain functions only. No
   exceptions, no new crypto crate ever added to `kmip/Cargo.toml`.
2. **The private key is extractable.** `create_key_pair.rs` calls
   `hybrid_kem::keygen()` directly, gets back raw private-key bytes
   (`dk_mlkem ‖ x25519_secret`, or the P-256 equivalent), and stores them as
   opaque bytes in the KMIP store's own `ObjectRecord.key_material` field
   (`cka_id_priv`/`cka_id_pub` are left empty — no PKCS#11 object is ever
   allocated). `get.rs:139` reads `obj.key_material` directly to answer a
   `Get` request. There is no `CKA_SENSITIVE`/`CKA_EXTRACTABLE=false`
   protection anywhere, because this key never enters the PKCS#11 engine's
   protected object store. **A caller who asks for a hybrid KEM private key
   via `Get` receives the raw scalar.**

## What PKCS#11 v3.2 does and doesn't give you

Verified (not guessed): PKCS#11 v3.2 has **no dedicated hybrid-KEM
mechanism**. Checked two independent sources: the vendored draft
(`docs/refs/pkcs11-spec-v3.2-csd01.pdf` — the only "HYBRID" string in it is
`CKV_TYPE_HYBRID`, an unrelated token-hardware-type enum) and Mozilla's own
PKCS#11 v3.2 ML-KEM implementation tracking (bug 1965329), which confirms
v3.2 adds only standalone ML-KEM `C_EncapsulateKey`/`C_DecapsulateKey`, with
hybrid composition explicitly left to the caller to build from separate
mechanism calls. A v3.3 draft reference was found but its content could not
be verified (required authenticated access) — no claim is made about it.

What v3.2 **does** give you, already implemented and verified in this
engine, is every building block needed to compose a hybrid correctly without
ever exposing a private key:

| Building block | Mechanism | Status in `rust/` |
|---|---|---|
| ML-KEM keygen | `CKM_ML_KEM_KEY_PAIR_GEN` | ✅ implemented, non-extractable private key |
| ML-KEM encapsulate | `CKM_ML_KEM` via `C_EncapsulateKey` | ✅ implemented — **already returns a new secret-key *handle*** (`ffi.rs:2486-2578`, `allocate_handle_owned`), not raw bytes, correctly marked `CKA_EXTRACTABLE=true` (a shared secret is meant to be released — correct) |
| ML-KEM decapsulate | `CKM_ML_KEM` via `C_DecapsulateKey` | ✅ implemented, same handle-returning pattern |
| Montgomery-curve keygen (X25519/X448) | `CKM_EC_MONTGOMERY_KEY_PAIR_GEN` | ✅ implemented, non-extractable private key |
| Montgomery-curve keygen (P-256/384/521, ECDSA-shaped) | `CKM_EC_KEY_PAIR_GEN` | ✅ implemented via `generate_ecdsa_keypair`; **P0's new `generate_ecdh_keypair`** now also covers this with correct `ALGO_ECDH_P256` tagging |
| ECDH/X25519/X448 derive | `CKM_ECDH1_DERIVE` / `CKM_X25519` / `CKM_X448` | ✅ implemented at the raw `ffi.rs` C-ABI layer (`ffi.rs:5812+`), **already returns a new derived-key handle** — confirmed by tracing to `allocate_handle_owned`. **Missing: no `native::` Rust-idiomatic wrapper exists** — only the raw FFI path has it (needed, see below). |
| **Combine two secret handles into one** | **`CKM_CONCATENATE_BASE_AND_KEY` (`0x360`)** | ❌ **not implemented anywhere** in `rust/src/ffi.rs`/`constants.rs`. Confirmed present in the project's own `src/lib/pkcs11/pkcs11t.h` — a general-purpose, pre-PQC key-derivation mechanism (not hybrid-KEM-specific), exactly the primitive this design needs. **This is the one new mechanism to add.** |

So every piece exists except the final combine step. Building it is adding
one generic mechanism plus two Rust-idiomatic wrapper functions — not new
cryptography.

## Scope — which combiners this plan covers (2026-07-05 addendum)

Checked the full combiner landscape before finalizing scope, since "hybrid
KEM" spans more than the two variants already in `hybrid_kem.rs`:

- **TLS (`draft-ietf-tls-ecdhe-mlkem`) defines THREE named groups, not two:**
  `X25519MLKEM768` (ML-KEM-first) and `SecP256r1MLKEM768` (ECDH-first) are
  implemented; **`SecP384r1MLKEM1024`** (P-384 + ML-KEM-1024, ECDH-first,
  for high-security environments) is missing entirely — no `Hybrid` enum
  variant, no combiner logic. Same architecture as the other two (P-384
  keygen and ML-KEM-1024 keygen/encapsulate/decapsulate are both already
  implemented) — this rebuild adds it as a third `Hybrid` variant alongside
  the fix, not a separate effort.
- **VPN/IKEv2 (RFC 9370) is architecturally different, not a third
  combiner to add here.** IKEv2 has no fixed named pairs — it negotiates a
  *sequence* of up to 7 independent key exchanges (any registered KEM/DH,
  chained through an SP 800-56C-style KDF via `IKE_INTERMEDIATE`/
  `IKE_FOLLOWUP_KE`), and that sequencing/chaining logic lives in the VPN
  daemon, not an HSM. There is nothing analogous to `X25519MLKEM768` for a
  PKCS#11 engine to implement for IKEv2 — what a VPN daemon needs from this
  stack is the *individual* primitives (ML-KEM ✅, ECDH ✅ as of P0,
  standalone X25519/X448 *derive* ❌ — tracked as `KMIP_LAYER_GAPS_PLAN.md`
  P2, unrelated to this plan; FrodoKEM ❌ not implemented, explicitly out of
  scope per direction). **Not part of this rebuild** — flagging so "support
  hybrid key establishment" isn't assumed to include IKEv2 by osmosis.

`Hybrid` enum after this rebuild: `X25519MlKem768`, `SecP256r1MlKem768`,
`SecP384r1MlKem1024` (new). **Wire codepoint for the third: checked
exhaustively against the vendored WD19 draft — there isn't one.** WD19 only
defines `0x5c`/`0x5d` (the first two groups); `SecP384r1MLKEM1024` has no
assigned KMIP `CryptographicAlgorithm` value in any spec material vendored
in this repo. Same situation as the composite-signature work: use the
`8XXXXXXX` extension range (every KMIP enum reserves it) until/unless a
future KMIP revision assigns a real one — do not invent a value in the
`0x5e`-and-up range as if it were standard, and do not silently skip this
variant either; extension-codepoint it, matching the documented pattern
for the deferred composite-signature algorithms.

## Verified reference values (2026-07-05, from primary sources)

**`CKM_CONCATENATE_BASE_AND_KEY` semantics** (PKCS#11 v3.2 §6.43.3, extracted
verbatim from the published spec PDF): derives a generic-secret key whose
value is `base_key.CKA_VALUE ‖ parameter_key.CKA_VALUE`. Base = `C_DeriveKey`'s
`hBaseKey`; the appended key = the `CK_OBJECT_HANDLE` passed as the mechanism
parameter. Default output = generic secret, length = sum of the two values.
No KDF, no truncation — pure ordered concatenation. Value `0x360`, verified
against the vendored `pkcs11t.h`.

**The three IANA-registered TLS hybrid groups** (`draft-ietf-tls-ecdhe-mlkem`,
cross-checked vs the IANA TLS registry). Concatenation order is per-variant
and spec-mandated — reversing it is a non-interop bug:

| Group | IANA codepoint | base (first) ‖ param (second) | SS size |
|---|---|---|---|
| X25519MLKEM768 | 0x11EC (4588) | ML-KEM-768 ‖ X25519 | 64 B (32+32) |
| SecP256r1MLKEM768 | 0x11EB (4587) | ECDH-P256 ‖ ML-KEM-768 | 64 B (32+32) |
| SecP384r1MLKEM1024 | 0x11ED (4589) | ECDH-P384 ‖ ML-KEM-1024 | 80 B (48+32) |

So per variant: build the two component secret-key handles, then call
`C_DeriveKey(CKM_CONCATENATE_BASE_AND_KEY, hBaseKey = <first>, param = <second>)`.
X25519MLKEM768 → base = ML-KEM handle, param = X25519 handle. The two SecP
variants → base = ECDH handle, param = ML-KEM handle. (These TLS codepoints
are the key-agreement group IDs, NOT the KMIP `CryptographicAlgorithm`
codepoints — those remain WD19's `0x5c`/`0x5d`, with SecP384r1MLKEM1024
needing an extension codepoint per the scope note above.)

## Full composable-combiner architecture (2026-07-05 — scope: "full set")

**Decision**: build the general combiner pipeline, not just pure concatenation
for the three TLS groups. Verified that EVERY standardized/registered hybrid-
KEM combiner is expressible as a chain of standard PKCS#11 v3.2 `C_DeriveKey`
calls (concatenate, then optionally hash/KDF), each handle→handle, nothing
leaving the HSM. This is the load-bearing correctness claim; the taxonomy
that proves it:

| Combiner family | Formula | PKCS#11 v3.2 derive chain |
|---|---|---|
| Concatenation (TLS `ecdhe-mlkem`, the 3 named groups) | `ss₁ ‖ ss₂` | `CONCATENATE_BASE_AND_KEY` |
| Hash-of-concat (SSH `kexmlkem768x25519`) | `H(ss₁ ‖ ss₂)` | `CONCATENATE_BASE_AND_KEY` → `SHAx_KEY_DERIVATION` |
| KDF-of-concat (IKEv2 / RFC 9370 PRF+) | `KDF(ss₁ ‖ ss₂)` | `CONCATENATE_BASE_AND_KEY` → `HKDF_DERIVE` / `SP800_108_*` |
| Transcript-binding (X-Wing, Chempat) | `H(ss₁ ‖ ss₂ ‖ ct ‖ pk ‖ label)` | `CONCATENATE_BASE_AND_KEY` → `CONCATENATE_BASE_AND_DATA` → `SHA3_256_KEY_DERIVATION` |
| Keyed dual-PRF | `PRF(ss₁ ; ss₂ ‖ ctx)` | `HKDF_DERIVE` with salt-as-key (HKDF-Extract keys on the salt) |

No proposed combiner (NIST SP 800-227, ETSI, IETF `ecdhe-mlkem`, X-Wing,
Chempat, IKEv2 RFC 9370) needs anything outside this set — they were all
designed to reuse standard KDF/hash primitives so HSMs could compose them.

### PKCS#11 v3.2 building blocks — status in our engine

Verified against `rust/src/ffi.rs` `C_DeriveKey` dispatch (2026-07-05):

| Mechanism | Spec | Status | Action |
|---|---|---|---|
| `CKM_CONCATENATE_BASE_AND_KEY` | §6.43.3 | ❌ missing | **add** (universal step 1; value 0x360, functional spec quoted below) |
| `CKM_CONCATENATE_BASE_AND_DATA` | §6.43.4 | ❌ missing | **add** (append ct/pk/label; param `CK_KEY_DERIVATION_STRING_DATA`) |
| `CKM_SHA512_KEY_DERIVATION` / `CKM_SHA384_…` / `CKM_SHA256_…` | §6.22 | ❌ missing (the SHA code in `C_DeriveKey` today is HKDF's internal PRF selection only, not standalone digest-key-derivation) | **add** (`new_key.value = SHAx(base.value)`) |
| `CKM_SHA3_256_KEY_DERIVATION` / `CKM_SHA3_512_…` | §6.29 | ❌ missing | **add** (for SHA3-based combiners incl. X-Wing) |
| `CKM_HKDF_DERIVE` | §6.62 | ✅ present, but salt-as-DATA only | **extend**: add `CKF_HKDF_SALT_KEY` (salt as a key handle) for keyed dual-PRF combiners |
| `CKM_SP800_108_COUNTER_KDF` / `_FEEDBACK_KDF` | §6.x | ✅ present | none |

`CKM_CONCATENATE_BASE_AND_KEY` functional spec (§6.43.3, verbatim): derives a
secret key from `base_key.CKA_VALUE ‖ parameter_key.CKA_VALUE`; base =
`C_DeriveKey`'s `hBaseKey`, appended key = the `CK_OBJECT_HANDLE` parameter;
default output generic-secret, length = sum. Pure ordered concatenation.

### KMIP 3.0 + PKCS#11 v3.2 dual-compliance mapping

The rebuild must satisfy BOTH standards simultaneously; where each concern
lives:

| Concern | PKCS#11 v3.2 (rust/ engine) | KMIP 3.0 (kmip/ protocol) |
|---|---|---|
| Component keygen | `CKM_ML_KEM_KEY_PAIR_GEN`, `CKM_EC_MONTGOMERY_KEY_PAIR_GEN` (both implemented) | `CreateKeyPair` with the hybrid `CryptographicAlgorithm` (WD19 `0x5c`/`0x5d`; `SecP384r1MLKEM1024` needs an extension codepoint — no WD19 value, confirmed) |
| Encapsulate | `C_EncapsulateKey` (ML-KEM half) + `C_DeriveKey` ECDH (classical half) → two secret handles; then the combiner pipeline (`C_DeriveKey` chain) → one final handle | KMIP 3.0 WD19 `Encapsulate` op returns ciphertext + the final shared-secret value (only the combined secret is released — correct) |
| Decapsulate | mirror: `C_DecapsulateKey` + ECDH derive → combiner pipeline | KMIP 3.0 WD19 `Decapsulate` op |
| Non-extractable private keys | `CKA_SENSITIVE=true` / `CKA_EXTRACTABLE=false` on both component private keys — never leave the HSM | KMIP `Get` on the private object returns no key material (falls out naturally once the key is a real non-extractable PKCS#11 object, not raw `ObjectRecord.key_material`) |
| Combiner recipe (which chain, per named group + order) | n/a — engine just runs the mechanisms it's told | Lives in `kmip/` as declarative orchestration (legitimate KMIP-layer domain logic, like `ecdsa_curve_from_length`); NO crypto crate |

### The combiner pipeline abstraction

A named hybrid group is declared as an ordered list of derive steps — e.g.
`X25519MLKEM768 = [Concatenate{base: mlkem_ss, param: x25519_ss}]`;
`SSH-style = [Concatenate{…}, DigestDerive{SHA512}]`;
`X-Wing = [Concatenate{base, param}, ConcatData{ct‖pk‖label}, DigestDerive{SHA3-256}]`.
The `kmip/` layer holds these recipes (data, not code); a small executor walks
the list calling the matching `native::` derive wrapper for each step against
the running handle. Adding a future combiner = adding a recipe entry, no new
crypto. All recipe steps are standard PKCS#11 v3.2 mechanisms, so the pipeline
is conformant by construction.

## Design

### `rust/` changes (all the new code; no crypto crate touches `kmip/`)

1. **`rust/src/ffi.rs`** — add a `CKM_CONCATENATE_BASE_AND_KEY` arm to the
   `C_DeriveKey` mechanism dispatch (same function that already handles
   `CKM_ECDH1_DERIVE`/`CKM_X25519`/`CKM_X448`/the KDF mechanisms). Parameter
   is a single `CK_OBJECT_HANDLE hSecondKey` (the mechanism's `pParameter`) —
   confirm the exact struct against the OASIS PKCS#11 v3.2 Current
   Mechanisms text before coding (the vendored header only has the numeric
   constant, not the parameter shape — don't guess it, look it up). Logic:
   read `CKA_VALUE` off both the base key (`h_base_key`, the `C_DeriveKey`
   argument) and the second key (`hSecondKey`), concatenate in that order,
   register as a new secret-key object via `allocate_handle_owned` — same
   pattern every other derive arm already uses.
2. **`rust/src/native/` — new wrapper functions** (mirroring the
   `generate_ecdh_keypair` pattern from P0, i.e. typed args in, `Result<u32,
   CkRv>` or `Result<(u32,u32), CkRv>` out, no raw FFI marshalling exposed
   to callers):
   - `derive_montgomery(session, priv_handle, peer_public: &[u8]) ->
     Result<u32, CkRv>` — wraps `CKM_X25519`/`CKM_X448`/`CKM_ECDH1_DERIVE`
     dispatch (currently only reachable via the raw C-ABI `p_mechanism`
     pointer marshalling; needs a clean typed entry point, same gap P0 found
     for keygen).
   - `concatenate_keys(session, base_handle, second_handle) ->
     Result<u32, CkRv>` — wraps the new `CKM_CONCATENATE_BASE_AND_KEY` arm.
   - `get_key_value(session, handle) -> Option<Vec<u8>>` if no equivalent
     already exists for extracting a `CKA_EXTRACTABLE=true` secret's raw
     bytes (check `get_object_value` in `state.rs` first — likely already
     sufficient, reused as-is).
3. **Tests in `rust/`** (mirroring P0's test depth): unit tests proving
   `concatenate_keys` produces `base_value ‖ second_value` in the correct
   order for both orderings the two hybrid variants need; a test proving
   the source key handles are untouched/still non-extractable after
   concatenation; a test proving `derive_montgomery` matches the existing
   raw-FFI `CKM_X25519`/`CKM_X448` dispatch (parity test, same pattern as
   the existing `native::parity` test module).

### `kmip/` changes (orchestration only — zero new crypto crate dependency)

4. **`kmip/src/hybrid_kem.rs`** — rewritten to contain **zero cryptography**.
   It becomes pure orchestration: which two mechanisms to call, in which
   order, per hybrid variant (this ordering knowledge — "ML-KEM-first for
   X25519MLKEM768, ECDHE-first for SecP256r1MLKEM768" — is legitimate
   KMIP-layer domain logic, the same category as `ecdsa_curve_from_length`
   already living in `kmip/`). Every actual byte of crypto happens via calls
   into `rust/`'s `native::` module (existing `generate_ml_kem_keypair`,
   `generate_ecdh_keypair`/a new Montgomery-curve variant, `encapsulate`,
   `decapsulate`, plus the three new functions above).
5. **`kmip/Cargo.toml`** — remove `ml-kem`, `x25519-dalek`, `p256` from
   `[dependencies]` entirely once `hybrid_kem.rs` no longer imports them
   directly (they remain in `rust/Cargo.toml`, where they've always
   belonged).
6. **`ObjectRecord` schema** (`kmip/src/store/`) — gains a way to reference
   **two** underlying PKCS#11 handles/`cka_id`s for one KMIP object, instead
   of the current single `cka_id` + a separate raw `key_material` escape
   hatch. Smallest viable change: an optional second `cka_id` field
   (`cka_id_secondary: Option<Vec<u8>>`) rather than a new enum variant —
   keeps `Get`/`Locate`/`Destroy` mostly unchanged, they just need to know to
   act on both handles for a composite object.
7. **`create_key_pair.rs`** — the hybrid-KEM branch calls
   `native::generate_ml_kem_keypair` (existing) + `native::generate_ecdh_keypair`-
   style Montgomery keygen (existing/extended) to get two **real** handles;
   stores both `cka_id`s on one `ObjectRecord`; no more raw private bytes
   anywhere in the KMIP store.
8. **`encapsulate.rs`** — call the ML-KEM public handle's `C_EncapsulateKey`
   (via a `native::` wrapper, existing capability) to get ciphertext + a
   derived-secret handle; call `native::derive_montgomery` with an ephemeral
   Montgomery keypair against the peer's static public share to get the
   second derived-secret handle; call `native::concatenate_keys` in the
   variant-correct order; extract *only* the final combined secret's raw
   value (via `get_object_value` — this step is correct and expected, a
   shared secret is the KEM's legitimate release-to-caller output) to build
   the KMIP response. The intermediate derived-secret handles get destroyed
   after extraction (their material is not sensitive as such, but no reason
   to keep them token-resident).
9. **`decapsulate.rs`** — mirror: derive both component secrets via the
   two stored private handles, concatenate, extract, return. The private
   keys themselves are never read or extracted at any point in this path.
10. **`get.rs`** — for a composite object, must not be able to return
    anything resembling private key material — this falls out naturally
    once the private `cka_id`s point at real, non-extractable PKCS#11
    objects (the existing `Get` handler already refuses to return
    non-extractable key values for ordinary keys; verify this codepath is
    actually exercised for the composite case with a new regression test,
    not just assumed).

## Testing strategy — what a KAT can and can't prove here

Checked exhaustively before writing this: **no official numeric test vector
exists yet for the combined `X25519MLKEM768`/`SecP256r1MLKEM768` hybrid
outputs** — not in this repo, not from the IETF `draft-ietf-tls-ecdhe-mlkem`
authors, not from NIST ACVP, not from BoringSSL or Go's standard library
(checked all four). One local decoy to explicitly avoid: this repo vendors
OpenSSH's `kexmlkem768x25519.c` (`openssh-pkcs11/build/openssh-src/`) — it
implements a **different, SSH-specific hybrid combiner** (concatenates the
ML-KEM key and ECDH shared key, then **hashes** the concatenation via
`ssh_digest_buffer`) per SSH's own separate IETF draft. That is not the same
construction as the TLS draft's raw-concatenation combiner this engine
implements, and must never be used as a reference or "KAT" for it — that
would be validating against the wrong specification.

Given no combined KAT exists, correctness has to be established
compositionally:

1. **Component-level KAT, ML-KEM half**: reuse the existing, current
   `kmip/kat/ml-kem/ml-kem-acvp.json` (ACVP `encapDecap`/AFT vectors,
   ML-KEM-768) — the rebuilt keygen/encapsulate/decapsulate calls are the
   *same* already-KAT-verified `native::` functions this file already
   validates; no new component test needed there.
2. **Component-level KAT, X25519 half**: RFC 7748 §5.2/6.1 publishes
   official, stable test vectors for X25519 scalar multiplication — fetch
   and verify the exact hex values directly from the RFC (do not trust
   memorized hex) and add them as a new `rust/` unit test for
   `derive_montgomery`, parallel to how `ecdsa-p256-acvp.json` etc. are used
   for the other curves.
3. **Combiner correctness — structural, not numeric** (since no numeric
   answer exists to check against): a test that independently computes
   `expected = mlkem_ss ‖ x25519_ss` (or the reverse order for
   `SecP256r1MLKEM768`) from the two KAT-verified component outputs, and
   asserts the engine's `concatenate_keys` output matches byte-for-byte —
   this validates the ordering and concatenation logic precisely, using
   inputs whose individual correctness is already externally verified.
4. **End-to-end KMIP round trip**: `CreateKeyPair` → `Encapsulate` (party A)
   → `Decapsulate` (party B, using the ciphertext from step 2 and party A's
   static public share) → assert both parties derive the identical shared
   secret. This is the self-consistency check the *current* `hybrid_kem.rs`
   tests already do (`x25519_mlkem768_round_trips`) — keep it, but it proves
   internal consistency, not spec conformance; (1)-(3) above are what prove
   conformance.
5. **The security fix, proven, not assumed**: a new regression test —
   attempt `Get` on the private half of a freshly created hybrid keypair,
   assert it does **not** return the raw private scalar (either by
   asserting the underlying PKCS#11 handle is `CKA_EXTRACTABLE=false`
   directly, or by asserting the KMIP `Get` response's key material is
   absent/redacted for a non-extractable key, matching whatever the
   existing non-hybrid `Get` path already asserts for a private key).

## Sequencing

Do the `rust/` half first and get it fully tested in isolation (mirrors
exactly how P0 was done — the concatenate mechanism and the Montgomery
derive wrapper are self-contained, testable without touching `kmip/` at
all). Only then rewire `kmip/`'s `hybrid_kem.rs`/`create_key_pair.rs`/
`encapsulate.rs`/`decapsulate.rs`/`get.rs` and remove the crypto crates from
`kmip/Cargo.toml` in the same change that removes their last call site.
