# Expose X25519 / X448 through the standard KMIP `ECDH` + `RecommendedCurve` path

**Date**: 2026-07-05. **Status**: plan (not yet implemented).

Goal: let a KMIP client create and use X25519 / X448 keys the way KMIP 3.0
models them — `CryptographicAlgorithm = ECDH` with a `RecommendedCurve` — instead
of a bespoke algorithm. Every fact below is grounded in the OASIS KMIP 3.0 spec
extract in this repo or in the actual code, not inferred.

## 1. Spec basis (verified against `spec/oasis-kmip-3.0/kmip-spec-3.0-tags-enums.json`)

- **`Cryptographic Algorithm` enum** has **no standalone `X25519`/`X448`**:
  `ECDH = 0x0e`, `EC = 0x1a`, `ECDSA = 0x06`, `ECMQV = 0x0f`,
  `Ed25519 = 0x37`, `Ed448 = 0x38`.
- **`Recommended Curve` enum** carries the Montgomery curves:
  **`CURVE25519 = 0x45`**, **`CURVE448 = 0x46`** (alongside the NIST/Brainpool
  curves).
- **`Recommended Curve` attribute TTLV tag = `0x420075`**, item type
  **Enumeration**.

**Conclusion (matches the requested model):** an X25519 key =
`ECDH (0x0e)` + `RecommendedCurve = CURVE25519 (0x45)`; an X448 key =
`ECDH (0x0e)` + `RecommendedCurve = CURVE448 (0x46)`. `Ed25519`/`Ed448` stay
separate because they are *signature* schemes; X25519/X448 are *key agreement*
= ECDH over Curve25519/Curve448.

## 2. Current state / gap (verified in code)

- **Engine**: `native::generate_x25519_keypair` EXISTS (added this session,
  `CKK_EC_MONTGOMERY`, non-extractable). **`generate_x448_keypair` does NOT
  exist** — X448 keygen lives only in the FFI `CKM_EC_MONTGOMERY_KEY_PAIR_GEN`
  arm (`ffi.rs`, `x448` crate, 56-byte keys, `ALGO_ECDH_X448`,
  `build_x448_spki`, OID `1.3.101.111`). Same situation X25519 was in.
- **Engine derive**: the FFI already exposes `CKM_EC_MONTGOMERY_KEY_DERIVE`
  (X25519/X448 ECDH) and `CKM_ECDH1_DERIVE` (NIST) — key agreement is
  implemented at the engine layer.
- **KMIP algorithm map** (`kmip30/algos.rs`): `Ecdh = 0x0e` exists.
- **KMIP curve selection** (`ops/create_key_pair.rs::native_generate_keypair`,
  `Ecdh` arm): curve is inferred purely from `CryptographicLength` via
  `ecdsa_curve_from_length` (256→P-256, 384→P-384, 521→P-521). **No
  `RecommendedCurve` is parsed anywhere** — the code comment says so
  explicitly. `EccCurve` (`native/keygen.rs`) is `{P256,P384,P521,Secp256K1}`
  — no Montgomery variant.
- **KMIP attribute set** (`kmip30/attrs.rs::Attribute`): **no `RecommendedCurve`
  variant**. `extract_template` pulls only `(algorithm, length, usage)`.

So: creation of X25519/X448 through KMIP is impossible today, and length-based
inference cannot express it (X25519 is 255-bit — collides with P-256's 256).
`RecommendedCurve` is the required discriminator, exactly as the spec intends.

## 3. Design decisions

1. **Model X25519/X448 as `Ecdh` + `RecommendedCurve`, not new algorithms.**
   No new `KmipAlgorithm` variant. This keeps us spec-faithful and avoids the
   Ed25519-vs-X25519 confusion (they stay distinct: Ed* = signature algo, X* =
   ECDH curve).
2. **`RecommendedCurve` becomes a first-class typed attribute** carrying the raw
   enum codepoint (`u32`), tag `0x420075`, Enumeration on the wire. Raw
   codepoint (not a Rust enum) so unknown curves reach the handler and fail with
   a clean KMIP error rather than a decode error — same posture as
   `GetRequest.key_format_type`.
3. **Curve resolution precedence**: if `RecommendedCurve` is present, it wins;
   else fall back to the existing length-based NIST inference (back-compat — no
   existing ECDH test changes behaviour).
4. **Engine keeps all crypto**: X448 gets a native typed wrapper paralleling the
   FFI arm (like X25519), so the KMIP layer dispatches by handle with no crypto
   crate — consistent with the hybrid-KEM work.
5. **Non-extractable by default**: both wrappers set `CKA_SENSITIVE`/
   `!CKA_EXTRACTABLE` (as `generate_x25519_keypair` already does), so `Get`
   refuses the private key — same security posture as every other engine key.

## 4. Increments (each built + tested in the `pqc-rust` container before the next)

### 4a. Engine — `generate_x448_keypair` (native wrapper)
Mirror `generate_x25519_keypair` exactly, swapping in the X448 shape from the
FFI arm: `x448` crate, 56-byte scalar + 56-byte public, `ALGO_ECDH_X448`,
`CKK_EC_MONTGOMERY`, OID `06 03 2b 65 6f`, `build_x448_spki`, `CKA_EC_POINT`
DER-wrapped. Non-extractable. Test: lengths (56/56), family tag, key type,
non-extractable/sensitive.

### 4b. KMIP — `Attribute::CryptographicDomainParameters` structure + wire codec
**Compliance fix (KMIP 3.0 §4.16, verified from spec text):** the curve is NOT a
standalone attribute. `Recommended Curve (0x420075)` is a MEMBER of the
**`Cryptographic Domain Parameters` structure attribute (`0x420029`)**, together
with `Qlength (0x420073)`. That structure is the field §4.16 says "MAY need to be
specified in the Create Key Pair Request Payload" and it "Applies to … Public
Keys, Private Keys", "Initially set by Client" — exactly our use.

- Add `Attribute::CryptographicDomainParameters { qlength: Option<u32>,
  recommended_curve: Option<u32> }` to `kmip30/attrs.rs` (outer tag `0x420029`).
  Do NOT conflate with the existing `Cryptographic Parameters` attribute
  (`0x42002b`, RSA-OAEP padding etc.) already on `ObjectRecord`.
- TTLV codec: encode/decode a **Structure** at `0x420029` whose members are
  `Qlength` (`0x420073`, Integer) and `Recommended Curve` (`0x420075`,
  Enumeration). Both optional.
- Named constants for the curve enum values from the spec extract:
  `CURVE25519 = 0x45`, `CURVE448 = 0x46`, plus the NIST `P_256/384/521` values
  for round-trip — sourced, not guessed.

### 4c. KMIP — capture + plumb the curve
- `extract_template` reads `CryptographicDomainParameters.recommended_curve` and
  returns `recommended_curve: Option<u32>`.
- Thread it into `native_generate_keypair` (new param) alongside `key_length`.

### 4d. KMIP — ECDH curve dispatch
In the `Ecdh` arm of `native_generate_keypair`, resolve the curve:
- `RecommendedCurve == CURVE25519` → `native::generate_x25519_keypair`.
- `RecommendedCurve == CURVE448` → `native::generate_x448_keypair`.
- `RecommendedCurve` ∈ {P_256,P_384,P_521} → the matching `EccCurve` →
  `generate_ecdh_keypair`.
- absent → existing `ecdsa_curve_from_length` fallback.
Record the curve on the object (see §6 open item) so a later use can recover it.

### 4e. Tests (e2e vs a REAL engine session, like `hybrid_kem_e2e.rs`)
- `CreateKeyPair(ECDH, RecommendedCurve=CURVE25519)` → private record is
  `CKK_EC_MONTGOMERY`, 32-byte scalar, `ALGO_ECDH_X25519`, **Get refused**.
- Same for `CURVE448` → 56-byte, `ALGO_ECDH_X448`.
- Back-compat: `CreateKeyPair(ECDH, length=256)` still yields P-256.
- Attribute wire round-trip: encode→decode `RecommendedCurve(CURVE25519)` is
  stable.

### 4f. KMIP — ECDH key AGREEMENT via `DeriveKey` (decision: IN scope)

Wire the KMIP `DeriveKey` op to perform X25519/X448 (and NIST) ECDH agreement:
base = the stored ECDH private key (engine handle, non-extractable), peer public
supplied in the request → shared secret as a `SecretData`/`SymmetricKey` object.

- Engine: use the existing `CKM_EC_MONTGOMERY_KEY_DERIVE` (X25519/X448) /
  `CKM_ECDH1_DERIVE` (NIST) — both already implemented at the FFI layer. Add a
  typed `native::ecdh_agree(session, priv_handle, peer_public, mech) -> handle`
  wrapper if one is missing (verify first; the FFI arm exists at
  `ffi.rs` `CKM_ECDH1_DERIVE | CKM_EC_MONTGOMERY_KEY_DERIVE`).
- KMIP: in `ops/derive_key.rs`, handle **`DerivationMethod = Asymmetric Key
  (0x08)`** — verified against the spec `Derivation Method` enum
  (`PBKDF2/HASH/HMAC/ENCRYPT/NIST800-108-*/Asymmetric Key=0x08/HKDF=0x0a`); this
  is KMIP's method for asymmetric (ECDH) key agreement. Base object = the stored
  ECDH private key; the peer public arrives in the derivation parameters/data.
  Resolve the base private handle by `cka_id`, store the shared secret. Reuse
  the non-extractable-handle pattern (no private key in this layer).
- Tests: X25519 agree(A_priv, B_pub) == X25519 agree(B_priv, A_pub); same for
  X448; NIST P-256 unchanged.

## 5. Object model — follow the KMIP 3.0 standard (Cryptographic Domain Parameters)

The curve is carried and reported as part of the **`Cryptographic Domain
Parameters` structure attribute** (`0x420029`), per §4.16 — NOT a standalone
attribute:
- **Input**: `CryptographicDomainParameters { RecommendedCurve }` in the
  `CreateKeyPair` template (§4c).
- **Persist**: add `cryptographic_domain_parameters: Option<DomainParameters>`
  (`{ qlength, recommended_curve }`) to `ObjectRecord` (`#[serde(default)]`,
  mirrors `pkcs11_cka_id_secondary`). This is a NEW field, distinct from the
  existing `cryptographic_parameters` (`0x42002b`).
- **Report**: `GetAttributes`/`Get` return the `Cryptographic Domain Parameters`
  structure for EC/ECDH keys (Baseline) — the curve inside it, for NIST and
  Montgomery alike.
- **Wire**: round-trips as a Structure through the TTLV codec (§4b).

## 6. Deliberately out of scope

- Brainpool / other Recommended Curves beyond CURVE25519, CURVE448, and the NIST
  P-256/384/521 values needed for round-trip + back-compat.
- Legacy `CryptographicDomainParameters` (the older container that also carries a
  curve) — the standard modern surface is the `Recommended Curve` attribute;
  revisit only if a client sends the legacy form.

## 7. Build order (all decisions locked)

4a (engine X448) → 4b (attribute + codec) → 4c (extract + plumb) → 4d (keygen
dispatch) → §5 persist+report → 4e (keygen tests) → 4f (ECDH agreement +
tests). Each stage built and green in the `pqc-rust` container before the next.
