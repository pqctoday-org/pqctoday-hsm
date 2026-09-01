# CKM_HPKE — a Hybrid Public Key Encryption mechanism family for PKCS #11

**Status:** Draft specification proposal — NOT an OASIS work product, NOT
submitted. Intended shape: public feedback to the OASIS PKCS 11 TC
(github.com/oasis-tcs/pkcs11) under the OASIS Feedback License, subject to
explicit owner approval before submission (see companion plan,
`docs/proposal-plan-ckm-hpke-mechanism-2026-08-31.md`, §5 Phase 3).
**Author's working evidence:** a reference composition of every mechanism
below, built entirely from mechanisms PKCS #11 v3.2 already defines, is
implemented and tested (152 tests, 0 extraction of any secret intermediate)
in `pqctoday-hub`'s HPKE workshop
(`src/components/PKILearning/modules/HybridCrypto/services/hpkeService.ts`).
That composition is both the motivation for this proposal (an application
should not have to get a 12-call chain exactly right) and its validation (every
normative step below has already been dry-run against working code).
**Numbering:** every mechanism, key type, and attribute below is written
number-agnostic in the main text ("TBD by the TC on adoption"). §9 gives a
provisional vendor-range numbering for any interim implementation; that annex
is not part of the normative proposal.

## 1. Overview

PKCS #11 v3.2 (ratified 2026-06) defines no mechanism for HPKE (RFC 9180).
The v3.3 working draft's `CKM_COMP_KEM` (targeting
draft-ietf-lamps-pq-composite-kem) is adjacent but does not cover this case —
different working group, different combiner, and critically, `CKM_COMP_KEM`
is KEM-only: it has no notion of RFC 9180's KeySchedule, AEAD Seal/Open, or
Export API, all of which HPKE requires.

Every real deployment of HPKE against a v3.2-conformant token therefore
composes it from primitives: `CKM_ECDH1_DERIVE` / `CKM_ML_KEM` for the KEM
layer, `CKM_HKDF_DERIVE` for LabeledExtract/LabeledExpand, `CKM_AES_GCM` /
`CKM_CHACHA20_POLY1305` for Seal/Open, and — for the PQ/T hybrid KEM suites
draft-ietf-hpke-pq registers — `CKM_CONCATENATE_BASE_AND_KEY` /
`CKM_CONCATENATE_BASE_AND_DATA` / `CKM_SHA3_256_KEY_DERIVATION` for the CG
combiner. This works, and can be done with full key custody (every
intermediate secret stays a non-extractable key handle; see §7.1) — but it
takes on the order of 10-12 chained `C_DeriveKey`/`C_EncapsulateKey` calls per
message, each with a template an implementer must get exactly right. This
proposal defines a mechanism family that performs that composition inside
the token, the same argument `CKM_COMP_KEM`'s own working draft text makes
for its case.

### 1.1 Normative references

- **[RFC9180]** Barnes, R., Bhargavan, K., Lipp, B., and C. Wood, "Hybrid
  Public Key Encryption", RFC 9180, February 2022.
  <https://www.rfc-editor.org/rfc/rfc9180.html>
- **[HPKE-PQ]** draft-ietf-hpke-pq — post-quantum and PQ/T hybrid KEM
  registrations for HPKE. <https://datatracker.ietf.org/doc/draft-ietf-hpke-pq/>
- **[HYBRID-KEMS]** draft-irtf-cfrg-hybrid-kems — the generic combiner
  framework (§5.5, "CG": Combiner=C2PRI, traditional component=nominal
  Group) that [HPKE-PQ]'s PQ/T hybrid KEM IDs delegate to.
  <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hybrid-kems-12>
- **[CONCRETE-HYBRID-KEMS]** draft-irtf-cfrg-concrete-hybrid-kems §4 — the
  concrete instantiation of [HYBRID-KEMS] (labels, component order) that
  [HPKE-PQ]'s three registered hybrid KEM IDs use.
  <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-concrete-hybrid-kems-03>
- **[RFC5869]** Krawczyk, H. and P. Eronen, "HMAC-based Extract-and-Expand
  Key Derivation Function (HKDF)", RFC 5869, May 2010.
- **[PKCS11-BASE]** PKCS #11 Specification Version 3.2 (OASIS Standard,
  2026-06-03).
- **[COMP-KEM]** draft-ietf-lamps-pq-composite-kem — referenced only for
  contrast in §1 and §10; not a dependency of this proposal.

### 1.2 Relationship to CKM_COMP_KEM

`CKM_COMP_KEM` and `CKM_HPKE` are complementary, not competing, and MUST NOT
be treated as interchangeable:

| | CKM_COMP_KEM (v3.3 draft) | CKM_HPKE (this proposal) |
|---|---|---|
| Target spec | [COMP-KEM] (LAMPS WG, X.509-oriented) | [RFC9180] + [HPKE-PQ] + [HYBRID-KEMS] (CFRG/IRTF) |
| Scope | KEM only (Encaps/Decaps → shared secret) | Full protocol: KEM + KeySchedule + AEAD + Export |
| Combiner | Fixed SHA3-256, one KDF for every parameter set | Fixed SHA3-256 at the KEM-combiner layer (same shape); KDF selectable at the outer HPKE suite layer (§4) |
| Output | A shared secret key object | A ready-to-use AEAD key object (+ optional exporter key) |

Both combiners are, incidentally, the same *shape* —
`SHA3-256(ss_PQ ‖ ss_T ‖ ct_T ‖ ek_T ‖ Label)` — because both descend from the
same NIST SP 800-227 hybrid-combiner allowance (see §7.3). That similarity is
coincidental to their shared cryptographic ancestry, not a sign either
mechanism can stand in for the other.

## 2. Mechanisms vs. Functions

+--------------------------------------+---------------------------------------------------+
|                                      | Functions                                         |
|                                      +-----+-----+------+-----+-------+-----+-----+------+
| Mechanism                            | ENC | SIG | SIGR |     | GENK  | WRP |     | ENCS |
|                                      |  &  |  &  |  &   | DIG |   &   |  &  | DRV |  &   |
|                                      | DEC | VER | VERR |     | GENKP | UWRP|     | DECS |
+======================================+:===:+:===:+:====:+:===:+:=====:+:===:+:===:+:====:+
| CKM_HPKE_KEM_KEY_PAIR_GEN            |     |     |      |     |   ✓   |     |     |      |
+--------------------------------------+-----+-----+------+-----+-------+-----+-----+------+
| CKM_HPKE                             |     |     |      |     |       |     |     |  ✓   |
+--------------------------------------+-----+-----+------+-----+-------+-----+-----+------+
table: HPKE Mechanisms vs. Functions

`CKM_HPKE` is used with `C_EncapsulateKey` (sender role) and
`C_DecapsulateKey` (recipient role). One call performs the KEM step (and, for
hybrid KEM IDs, the [HYBRID-KEMS] combiner) *and* the full [RFC9180] §5.1
KeySchedule, returning a ready-to-use AEAD key object. Existing
`CKM_AES_GCM` / `CKM_CHACHA20_POLY1305` mechanisms then perform Seal/Open —
no new AEAD mechanism is defined here.

## 3. Definitions

Key type: **CKK_HPKE_KEM** for `CK_KEY_TYPE`, used in `CKA_KEY_TYPE` for all
HPKE KEM key objects.

Mechanisms:

- CKM_HPKE_KEM_KEY_PAIR_GEN
- CKM_HPKE

**CK_HPKE_KEM_PARAMETER_SET_TYPE** identifies the KEM suite:

```c
typedef CK_ULONG CK_HPKE_KEM_PARAMETER_SET_TYPE;
```

Parameter set types (values = the corresponding `kem_id` from [RFC9180] §7.1
/ [HPKE-PQ] §8.1 — this registry is deliberately NOT reinvented; a
`CK_HPKE_KEM_PARAMETER_SET_TYPE` value equals the wire `kem_id` it names):

- CKP_HPKE_KEM_DHKEM_P256_HKDF_SHA256   (0x0010)
- CKP_HPKE_KEM_DHKEM_P384_HKDF_SHA384   (0x0011)
- CKP_HPKE_KEM_DHKEM_P521_HKDF_SHA512   (0x0012)
- CKP_HPKE_KEM_DHKEM_X25519_HKDF_SHA256 (0x0020)
- CKP_HPKE_KEM_DHKEM_X448_HKDF_SHA512   (0x0021)
- CKP_HPKE_KEM_MLKEM768_P256            (0x0050)
- CKP_HPKE_KEM_MLKEM1024_P384           (0x0051)
- CKP_HPKE_KEM_MLKEM768_X25519          (0x647a)

**CK_HPKE_KDF_TYPE** / **CK_HPKE_AEAD_TYPE** — likewise equal to the wire
`kdf_id` / `aead_id` values from [RFC9180] §7.2/§7.3:

- CKD_HPKE_HKDF_SHA256 (0x0001), CKD_HPKE_HKDF_SHA384 (0x0002),
  CKD_HPKE_HKDF_SHA512 (0x0003)
- CKZ_HPKE_AEAD_128_GCM (0x0001), CKZ_HPKE_AEAD_256_GCM (0x0002),
  CKZ_HPKE_AEAD_CHACHA20POLY1305 (0x0003), CKZ_HPKE_AEAD_EXPORT_ONLY (0xFFFF)

**CK_HPKE_MODE_TYPE**: CKZ_HPKE_MODE_BASE (0x00), CKZ_HPKE_MODE_PSK (0x01),
CKZ_HPKE_MODE_AUTH (0x02), CKZ_HPKE_MODE_AUTH_PSK (0x03) — [RFC9180] §5.1.

## 4. CK_HPKE_PARAMS

**CK_HPKE_PARAMS** is the parameter structure for `CKM_HPKE`:

```c
typedef struct CK_HPKE_PARAMS {
    CK_HPKE_KEM_PARAMETER_SET_TYPE kemId;
    CK_HPKE_KDF_TYPE                kdfId;
    CK_HPKE_AEAD_TYPE               aeadId;
    CK_HPKE_MODE_TYPE               mode;
    CK_OBJECT_HANDLE                hPsk;          /* PSK, PSK/AuthPSK modes; CK_INVALID_HANDLE otherwise */
    CK_BYTE_PTR                     pPskId;
    CK_ULONG                        ulPskIdLen;
    CK_BYTE_PTR                     pInfo;
    CK_ULONG                        ulInfoLen;
    CK_OBJECT_HANDLE                hSenderStaticKey; /* Auth/AuthPSK, sender (Encap) side only */
    CK_BYTE_PTR                     pSenderPk;        /* Auth/AuthPSK, recipient (Decap) side only */
    CK_ULONG                        ulSenderPkLen;
    CK_BYTE_PTR                     pBaseNonce;       /* out, Nn bytes — see §7.1 for why this is bytes, not a handle */
    CK_ULONG                        ulBaseNonceLen;
    CK_DERIVED_KEY_PTR              pExporterKey;     /* OPTIONAL — a second key object for exporter_secret, or NULL */
} CK_HPKE_PARAMS;
```

The fields have the following meanings:

_kemId, kdfId, aeadId, mode_
: select the HPKE ciphersuite and mode exactly as [RFC9180] §5.1 defines
  them. `aeadId = CKZ_HPKE_AEAD_EXPORT_ONLY` selects "export-only" mode
  ([RFC9180] §5.1.2): no AEAD key is derived, and `phKey` (the function's
  returned handle) refers to the exporter key instead — `pExporterKey` MUST
  be NULL in that case.

_hPsk, pPskId, ulPskIdLen_
: the PSK, supplied **as a key handle**, not raw bytes — a PSK is keying
  material and deserves the same custody as everything else derived in this
  call (precedent: [PKCS11-BASE] §6.62.3's `CKF_HKDF_SALT_KEY`, which already
  lets an HKDF salt be sourced from a key's `CKA_VALUE` rather than caller
  bytes). `pPskId`/`ulPskIdLen` are the (public) `psk_id` bytes. Both MUST be
  present together for PSK/AuthPSK modes and absent otherwise, matching
  [RFC9180] §5.1's own rule.

_pInfo, ulInfoLen_
: the (public) application `info` parameter — [RFC9180] §5.1.

_hSenderStaticKey / pSenderPk_
: Auth/AuthPSK modes only. On the sender (Encap) side, a handle to the
  sender's own static `CKK_HPKE_KEM` private key (used for AuthEncap). On the
  recipient (Decap) side, the sender's static public key bytes (used for
  AuthDecap) — public, so bytes are appropriate here, unlike `hPsk`.
  `CKR_MECHANISM_PARAM_INVALID` if either is supplied for a KEM ID whose
  [HPKE-PQ] table marks the Auth column "no" (every currently-registered
  hybrid KEM ID — none of them define AuthEncap/AuthDecap).

_enc_
: NOT a `CK_HPKE_PARAMS` field. `enc` — the KEM's public output — flows
  through `C_EncapsulateKey`/`C_DecapsulateKey`'s own built-in
  `pCiphertext`/`pulCiphertextLen` parameters, exactly like every other KEM
  mechanism this proposal composes from (`CKM_ML_KEM`, classical
  ECDH-as-KEM under §6.3.17): query-then-fill (`pCiphertext = NULL` sizes
  it) on Encap, a plain input buffer on Decap. An earlier draft of this
  proposal duplicated this as a `pEnc`/`pulEncLen` pair inside the params
  struct; removed for consistency with the rest of the mechanism table.

_pBaseNonce, ulBaseNonceLen_
: out-buffer, exactly `Nn` bytes for the selected AEAD (see §5). Not
  templated, not a key handle — `base_nonce` is not secret (see §7.1) and the
  caller needs it in the clear regardless, to compute
  `nonce = base_nonce XOR seq` per message.

_pExporterKey_
: OPTIONAL. If non-NULL, a `CK_DERIVED_KEY` (already defined by
  [PKCS11-BASE] §6.42 as `{ pTemplate, ulAttributeCount, phKey }`) whose
  template governs the second output key — [RFC9180]'s `exporter_secret`.
  This reuses `CK_SP800_108_KDF_PARAMS.pAdditionalDerivedKeys`'s existing
  precedent for "one mechanism call, two output keys" rather than defining a
  new mechanism. If NULL, no exporter key is produced (a caller not planning
  to use HPKE's Export() API pays nothing for it).

## 5. CKK_HPKE_KEM key objects

### 5.1 Why a uniform key type, including for non-hybrid suites

For hybrid KEM IDs, `C_DecapsulateKey`'s single `hKey` argument must resolve
to *two* component private keys (dk_PQ and dk_T) plus enough metadata (the
`kemId`) to run the right combiner — no existing single key object can carry
that. Rather than defining two code paths in this mechanism's semantics (a
bare `CKK_EC`/`CKK_EC_MONTGOMERY` key for classical DHKEM suites, a composite
object only for hybrids), `CKK_HPKE_KEM` is used uniformly for every suite.
This mirrors `CKM_COMP_KEM`'s own `CKK_COMP_KEM` precedent and keeps this
mechanism's semantics (§6) suite-agnostic.

### 5.2 Public key objects

(object class `CKO_PUBLIC_KEY`, key type `CKK_HPKE_KEM`)

| Attribute | Data Type | Meaning |
|---|---|---|
| CKA_PARAMETER_SET | CK_HPKE_KEM_PARAMETER_SET_TYPE | The KEM suite |
| CKA_VALUE | Byte array | `ek` — for classical suites, the raw DHKEM public key ([RFC9180] Table 2 encoding); for hybrid suites, `ek_PQ ‖ ek_T` ([HPKE-PQ]/[CONCRETE-HYBRID-KEMS], PQ component first) |

Sample template:

```c
CK_OBJECT_CLASS class = CKO_PUBLIC_KEY;
CK_KEY_TYPE keyType = CKK_HPKE_KEM;
CK_HPKE_KEM_PARAMETER_SET_TYPE param_set = CKP_HPKE_KEM_MLKEM768_X25519;
CK_BYTE value[] = {...};
CK_BBOOL true = CK_TRUE;
CK_ATTRIBUTE template[] = {
  {CKA_CLASS, &class, sizeof(class)},
  {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
  {CKA_TOKEN, &true, sizeof(true)},
  {CKA_ENCAPSULATE, &true, sizeof(true)},
  {CKA_PARAMETER_SET, &param_set, sizeof(param_set)},
  {CKA_VALUE, value, sizeof(value)}
};
```

### 5.3 Private key objects

(object class `CKO_PRIVATE_KEY`, key type `CKK_HPKE_KEM`)

| Attribute | Data Type | Meaning |
|---|---|---|
| CKA_PARAMETER_SET | CK_HPKE_KEM_PARAMETER_SET_TYPE | The KEM suite |
| CKA_VALUE | Byte array | `dk` — classical: the raw private scalar; hybrid: `dk_PQ ‖ dk_T` |
| CKA_SEED | Byte array | OPTIONAL, see §8 |

As with `CKM_COMP_KEM`'s private keys, `CKA_PARAMETER_SET` is not specified
in the private key's own template on `C_GenerateKeyPair` — it is inherited
from the public key template of the pair being generated.

### 5.4 Key pair generation

`CKM_HPKE_KEM_KEY_PAIR_GEN` — a `C_GenerateKeyPair` mechanism, section 3.1 of
this proposal's semantics. Takes `CK_HPKE_KEM_PARAMETER_SET_TYPE` from the
public key template (§5.2). For hybrid suites, generates BOTH component key
pairs internally (ML-KEM + the classical group) and packs them into the
single composite public/private key objects per §5.1 — the two components
never need to exist as separate objects/handles from the caller's
perspective, and, per §7.1, never need to exist outside the token at all.

## 6. Mechanism semantics

### 6.1 CKM_HPKE under C_EncapsulateKey (sender)

Given a recipient `CKK_HPKE_KEM` public key handle `hKey` and a
`CK_HPKE_PARAMS` structure:

1. Validate `mode` against `hPsk`/`pPskId` presence and against
   `hSenderStaticKey` presence, exactly as [RFC9180] §5.1's own validation
   (`gotPsk`/Auth-required checks).
2. Validate Auth/AuthPSK modes are not requested for a `kemId` whose
   [HPKE-PQ] table marks Auth "no" → `CKR_MECHANISM_PARAM_INVALID`.
3. Run Encap:
   - Classical (`kemId` ∈ [RFC9180] §7.1's DHKEM entries): [RFC9180] §4.1
     `Encap`/`AuthEncap` — `CKM_ECDH1_DERIVE` internally, then the DHKEM's
     own `ExtractAndExpand` (its *fixed* internal KDF per [RFC9180] Table 2,
     independent of the outer `kdfId`).
   - Hybrid (`kemId` ∈ [HPKE-PQ]'s registrations): ML-KEM encapsulation
     against `ek_PQ`, ephemeral-static Diffie-Hellman against `ek_T`, then
     the [HYBRID-KEMS] §5.5 CG combiner:
     `ss_H = SHA3-256(ss_PQ ‖ ss_T ‖ ct_T ‖ ek_T ‖ Label)`, `Label` per
     [CONCRETE-HYBRID-KEMS] §4 (Table 1 below).
   - Both cases: `ss_PQ`, `ss_T` (hybrid) or the raw DH output (classical),
     and the combined/extracted shared secret, MUST NOT be readable via
     `C_GetAttributeValue` at any point in this process — see §7.1.
   - Write `enc` to `C_EncapsulateKey`'s own `pCiphertext`/`pulCiphertextLen`
     (query-then-fill).
4. Run [RFC9180] §5.1 KeySchedule on the shared secret produced by step 3,
   `info` = `pInfo`, `psk`/`psk_id` from `hPsk`/`pPskId` (empty for
   Base/Auth). `secret = LabeledExtract(shared_secret, "secret", psk)` — note
   `shared_secret` plays the *salt* role here, which is what lets step 3's
   secret be consumed as a key handle via `CKF_HKDF_SALT_KEY`-style internal
   plumbing without ever being read out (§7.1).
5. `key = LabeledExpand(secret, "key", key_schedule_context, Nk)` — created
   directly as the `aeadId`-appropriate key type (`CKK_AES` for the two GCM
   AEAD IDs, `CKK_CHACHA20` for ChaCha20-Poly1305), returned as `*phKey`.
   Skipped entirely if `aeadId = CKZ_HPKE_AEAD_EXPORT_ONLY`.
6. `base_nonce = LabeledExpand(secret, "base_nonce", key_schedule_context,
   Nn)` — written to `pBaseNonce` (not templated; see §4).
7. If `pExporterKey != NULL`: `exporter_secret = LabeledExpand(secret, "exp",
   key_schedule_context, Nh)`, created per `pExporterKey->pTemplate`, handle
   returned via `*pExporterKey->phKey`. If `aeadId =
   CKZ_HPKE_AEAD_EXPORT_ONLY` and `pExporterKey = NULL`, this value is
   instead what `*phKey` returns.

### 6.2 CKM_HPKE under C_DecapsulateKey (recipient)

Mirrors §6.1: `hKey` is the recipient's `CKK_HPKE_KEM` private key;
`C_DecapsulateKey`'s own `pCiphertext`/`ulCiphertextLen` carry `enc` as an
input; Decap/AuthDecap/hybrid-Decap replace step 3; steps 4-7 are
identical. The combiner recomputation MUST produce the identical `ss_H` the
sender derived without either side's `ss_PQ`/`ss_T`/`ss_H` ever having
existed outside a token (either token — the property holds independently on
each side).

### Table 1 — Hybrid KEM combiner labels ([CONCRETE-HYBRID-KEMS] §4)

| kemId | Label (as used in the combiner) |
|---|---|
| CKP_HPKE_KEM_MLKEM768_P256 | ASCII `"MLKEM768-P256"` |
| CKP_HPKE_KEM_MLKEM1024_P384 | ASCII `"MLKEM1024-P384"` |
| CKP_HPKE_KEM_MLKEM768_X25519 | the 6 bytes `5c 2e 2f 2f 5e 5c` (not ASCII-representable cleanly — given in hex per [COMP-KEM]'s own transcription-safety practice for a similarly awkward label) |

### Table 2 — Suite sizes (author's verified values; cross-check against
[RFC9180] Table 2/5/6 and [HPKE-PQ] §8.1's KEM table before adoption — see
§8, V1)

| kemId | Nsecret | Nenc | Npk | Auth? |
|---|---|---|---|---|
| DHKEM_P256_HKDF_SHA256 | 32 | 65 | 65 | yes |
| DHKEM_P384_HKDF_SHA384 | 48 | 97 | 97 | yes |
| DHKEM_P521_HKDF_SHA512 | 64 | 133 | 133 | yes |
| DHKEM_X25519_HKDF_SHA256 | 32 | 32 | 32 | yes |
| DHKEM_X448_HKDF_SHA512 | 64 | 56 | 56 | yes |
| MLKEM768_P256 | 32 | 1153 | 1249 | no |
| MLKEM1024_P384 | 32 | 1665 | 1665 | no |
| MLKEM768_X25519 | 32 | 1120 | 1216 | no |

`Nk`/`Nn`/`Nt` (AEAD) and `Nh` (KDF) are exactly [RFC9180] §7.2/§7.3's
existing values — this proposal does not redefine them.

## 7. Attribute rules and security considerations

### 7.1 Key custody (the central design goal)

`ss_PQ`, `ss_T`, the combined shared secret, the extracted PRK, and `key`
(the returned AEAD key) MUST NOT be extractable by default and SHOULD be
rejected as templated-extractable unless the caller deliberately overrides
`CKA_EXTRACTABLE` — mirroring [PKCS11-BASE] §5.18.8's existing
`CKA_ALWAYS_SENSITIVE`/`CKA_NEVER_EXTRACTABLE` handling for encapsulated
keys. Exactly two values are intended to leave the token as plaintext,
because [RFC9180] itself hands them to the application:

- `base_nonce` — combined publicly with the sequence number; no different in
  sensitivity from an AEAD IV.
- The exporter key's value, *if and only if* the caller's `pExporterKey`
  template explicitly requests `CKA_EXTRACTABLE = CK_TRUE` — [RFC9180]'s own
  Export() API is defined to hand this value to the application; a caller
  that instead wants to keep using it in-token (e.g. as future HKDF input
  via `CKF_HKDF_SALT_KEY`) may simply not request extractability.

Everything else, at every step, stays a key handle from creation to
consumption.

### 7.2 Nonce/sequence-number management

This mechanism does not track message sequence numbers — the caller computes
`nonce = base_nonce XOR seq` and supplies it to `CKM_AES_GCM`/
`CKM_CHACHA20_POLY1305` exactly as it already does for those mechanisms
today. This is a deliberate non-goal (see companion plan §2, "Non-goals") —
inventing a stateful in-token sequence counter is a materially larger ask
(a new key/context object class) that this proposal does not make.

### 7.3 FIPS mapping

Per [HYBRID-KEMS]/[CONCRETE-HYBRID-KEMS]'s own analysis (mirrored in
[COMP-KEM] §10.1 for the sibling LAMPS construction), the hybrid combiner in
§6.1 maps onto NIST SP 800-227's hybrid key-combiner allowance,
`K <- KDM((S1,S2,...,St), OtherInput)`, with `ss_PQ, ss_T` in the first two
slots and `ct_T, ek_T, Label` as `OtherInput` — certifiable under SP 800-56Cr2
One-Step Key Derivation (`H(x) = hash(x)`) so long as at least one component
shared secret comes from an approved method.

## 8. Open items for TC discussion (recorded here, not resolved unilaterally)

- **Deterministic Encaps for test-vector reproduction.** [RFC9180]/
  [CONCRETE-HYBRID-KEMS] both publish byte-exact Appendix-A vectors that
  require forcing the ephemeral key and (for hybrid suites) seeding
  ML-KEM.Encaps. This proposal adds an OPTIONAL seeding hook, reusing the
  existing [PKCS11-BASE] `CKA_SEED` attribute (already defined for
  deterministic ML-DSA/ML-KEM key generation) rather than inventing a new
  one: if the recipient's `CKK_HPKE_KEM` public key object used in
  `C_EncapsulateKey` carries a token-visible `CKA_SEED`-tagged ephemeral
  override — mechanics TBD during drafting, candidates are (a) a
  `pEphemeralSeed`/`ulEphemeralSeedLen` pair added to `CK_HPKE_PARAMS`
  mirroring `CKA_SEED`'s existing `d ‖ z` convention for ML-KEM, or (b) a
  vendor/testing-only companion mechanism — Encap/Decap MUST reproduce the
  registered Appendix-A vectors exactly. Implementations MUST NOT use this
  hook outside test contexts; the normative text will carry an explicit
  warning to that effect (determinism defeats IND-CCA2 security guarantees
  for real traffic).
- Whether `pSenderPk`/`hSenderStaticKey` in Auth/AuthPSK modes should instead
  be unified as a single `hSenderStaticKey`-shaped field that also accepts a
  public-key-only object on the Decap side, rather than two differently-typed
  fields — a modest ABI simplification, deferred to drafting.

## 9. Provisional vendor-range numbering (non-normative; interim
implementation only)

If Phase 1 of the companion plan (Rust engine implementation) proceeds before
TC numbers are assigned, use the next free slots in this repo's existing
`CKM_VENDOR_DEFINED`/`CKK_VENDOR_DEFINED` ledger
(`pqctoday-hsm/rust/src/constants.rs`) at implementation time — confirmed
free as of this proposal's writing:

| Symbol | Provisional value |
|---|---|
| CKM_HPKE_KEM_KEY_PAIR_GEN | `CKM_VENDOR_DEFINED \| 0x0013` (0x8000_0013) |
| CKM_HPKE | `CKM_VENDOR_DEFINED \| 0x0014` (0x8000_0014) |
| CKK_HPKE_KEM | `CKK_VENDOR_DEFINED \| 0x0003` (0x8000_0003) |

`CK_HPKE_KEM_PARAMETER_SET_TYPE`/`CK_HPKE_KDF_TYPE`/`CK_HPKE_AEAD_TYPE`/
`CK_HPKE_MODE_TYPE` values are, by design (§3), the wire IDs from
[RFC9180]/[HPKE-PQ] themselves — no vendor allocation needed for those.

## 10. Appendix: implementer's evidence

The composed (non-native) equivalent of this entire mechanism family is
implemented and tested in `pqctoday-hub`:

- `HpkeService.ts` — `hybridEncap`/`hybridDecap`/`keyScheduleSecure`/
  `sealHandle`/`openHandle` (the non-extracting path this proposal's §6/§7.1
  are directly modeled on) and `dhkemEncap`/`dhkemDecap`/`dhkemAuthEncap`/
  `dhkemAuthDecap`/`keySchedule` (the classical, byte-exact-verified path).
- `hpkeService.test.ts` — 4 cases byte-exact against [RFC9180] Appendix A.3
  (all four modes, DHKEM-P256), 54 cases covering the full hybrid
  KEM × KDF × AEAD × mode cross-product with explicit non-extractability
  assertions (`toThrow()` on every attempted `C_GetAttributeValue` against
  `ss_PQ`/`ss_T`/`ss_H`/the AEAD key).

152/152 passing as of 2026-08-31, against the Rust engine
(`pqctoday-hsm/rust`, `softhsmrustv3` — release build via
`build-wasm-bundle.sh`).
