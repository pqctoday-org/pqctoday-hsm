use wasm_bindgen::prelude::*;

// ── PKCS#11 Return Values ────────────────────────────────────────────────────

pub const CKR_OK: u32 = 0x0000_0000;
pub const CKR_HOST_MEMORY: u32 = 0x0000_0002;
// PKCS#11 v3.2 §5.6 — Cryptoki library lifecycle.
pub const CKR_CRYPTOKI_NOT_INITIALIZED: u32 = 0x0000_0190;
pub const CKR_CRYPTOKI_ALREADY_INITIALIZED: u32 = 0x0000_0191;
pub const CKR_GENERAL_ERROR: u32 = 0x0000_0005;
pub const CKR_FUNCTION_FAILED: u32 = 0x0000_0006;
pub const CKR_ARGUMENTS_BAD: u32 = 0x0000_0007;
pub const CKR_DATA_INVALID: u32 = 0x0000_0020;
/// PKCS#11 v3.2 §6.16 — `CKR_DATA_LEN_RANGE`. Input plaintext length
/// invalid for the mechanism (e.g. AES-ECB requires a non-zero
/// multiple of 16 bytes).
pub const CKR_DATA_LEN_RANGE: u32 = 0x0000_0021;
/// PKCS#11 v3.2 §6.16 — `CKR_ENCRYPTED_DATA_LEN_RANGE`. Ciphertext
/// length invalid for the mechanism (decrypt side counterpart of
/// `CKR_DATA_LEN_RANGE`).
pub const CKR_ENCRYPTED_DATA_LEN_RANGE: u32 = 0x0000_0041;
pub const CKR_KEY_TYPE_INCONSISTENT: u32 = 0x0000_0063;
pub const CKR_MECHANISM_INVALID: u32 = 0x0000_0070;
pub const CKR_MECHANISM_PARAM_INVALID: u32 = 0x0000_0071;
pub const CKR_OBJECT_HANDLE_INVALID: u32 = 0x0000_0082;
pub const CKR_OPERATION_NOT_INITIALIZED: u32 = 0x0000_0091;
pub const CKR_SIGNATURE_INVALID: u32 = 0x0000_00C0;
pub const CKR_TEMPLATE_INCOMPLETE: u32 = 0x0000_00D0;
pub const CKR_TEMPLATE_INCONSISTENT: u32 = 0x0000_00D1;
pub const CKR_KEY_NOT_WRAPPABLE: u32 = 0x0000_0069; // PKCS#11 v3.2 — CKA_WRAP_WITH_TRUSTED policy violation
/// PKCS#11 v3.2 §5.1.6 (Table 6) — "This parameter set is not supported by
/// this token." Narrower than `CKR_ATTRIBUTE_VALUE_INVALID`: for an
/// unrecognized `CKA_PARAMETER_SET` value on a PQC keygen template.
pub const CKR_PARAMETER_SET_NOT_SUPPORTED: u32 = 0x0000_0209;
/// PKCS#11 v3.2 §6.3 — "an invalid or unsupported representation of the EC
/// domain parameters". Distinct from [`CKR_CURVE_NOT_SUPPORTED`]: the bytes
/// could not be decoded at all (W1, 2026-08-13).
pub const CKR_DOMAIN_PARAMS_INVALID: u32 = 0x0000_0130;
/// PKCS#11 v3.2 §6.3 — the CKA_EC_PARAMS decoded cleanly and names a curve
/// this token does not implement (W1/W2/C2, 2026-08-13).
pub const CKR_CURVE_NOT_SUPPORTED: u32 = 0x0000_0140;
/// PKCS#11 v3.2 §5.2 — returned by the NULL-mechanism cancel form of a
/// `C_*Init` function when the active operation cannot be cancelled (C2).
pub const CKR_OPERATION_CANCEL_FAILED: u32 = 0x0000_0202;
/// Vendor error (CKR_VENDOR_DEFINED | 1) — a persisted engine snapshot was
/// written under a superseded serialisation format. Deliberately NOT
/// migrated in place: the pre-S4 layout stored stateful HBS key state under
/// client-writable vendor attribute ids, so silently reinterpreting such a
/// key would present a rewound one-time-signature key as a fresh one. See
/// `state_snapshot::SNAPSHOT_MAGIC` (remediation item S4, 2026-08-13).
pub const CKR_PQCTODAY_SNAPSHOT_FORMAT_UNSUPPORTED: u32 = 0x8000_0001;
pub const CKR_KEY_UNEXTRACTABLE: u32 = 0x0000_006A;
pub const CKR_KEY_FUNCTION_NOT_PERMITTED: u32 = 0x0000_0068;
pub const CKR_KEY_HANDLE_INVALID: u32 = 0x0000_0060;
pub const CKR_SIGNATURE_LEN_RANGE: u32 = 0x0000_00C1;
pub const CKR_ATTRIBUTE_READ_ONLY: u32 = 0x0000_0010;
pub const CKR_ATTRIBUTE_SENSITIVE: u32 = 0x0000_0011;
pub const CKR_ATTRIBUTE_VALUE_INVALID: u32 = 0x0000_0013;
pub const CKR_ACTION_PROHIBITED: u32 = 0x0000_001B;
pub const CKR_SESSION_PARALLEL_NOT_SUPPORTED: u32 = 0x0000_00B4;
pub const CKR_TOKEN_NOT_RECOGNIZED: u32 = 0x0000_00E1;
pub const CKR_TOKEN_WRITE_PROTECTED: u32 = 0x0000_00E2;
pub const CKR_ATTRIBUTE_TYPE_INVALID: u32 = 0x0000_0012; // PKCS#11 §11.7 — attribute not present on object
pub const CKR_BUFFER_TOO_SMALL: u32 = 0x0000_0150;
pub const CKR_ENCRYPTED_DATA_INVALID: u32 = 0x0000_0040;
pub const CKR_KEY_SIZE_RANGE: u32 = 0x0000_0062;
pub const CKR_OPERATION_ACTIVE: u32 = 0x0000_0090;
// PKCS#11 v3.2 §5.18 wrap/unwrap return codes (values from pkcs11t.h).
pub const CKR_UNWRAPPING_KEY_HANDLE_INVALID: u32 = 0x0000_00F0;
pub const CKR_WRAPPED_KEY_INVALID: u32 = 0x0000_0110;
pub const CKR_WRAPPED_KEY_LEN_RANGE: u32 = 0x0000_0112;
pub const CKR_WRAPPING_KEY_HANDLE_INVALID: u32 = 0x0000_0113;

// ── PKCS#11 Attribute Types ──────────────────────────────────────────────────

pub const CKA_VALUE: u32 = 0x0000_0011;
pub const CKA_KEY_TYPE: u32 = 0x0000_0100;
pub const CKA_MODULUS: u32 = 0x0000_0120; // PKCS#11 v3.2 §2.1.2 — RSA modulus (big-endian)
pub const CKA_MODULUS_BITS: u32 = 0x0000_0121;
pub const CKA_PUBLIC_EXPONENT: u32 = 0x0000_0122; // PKCS#11 v3.2 §2.1.2 — RSA public exponent
pub const CKA_VALUE_LEN: u32 = 0x0000_0161;
pub const CKA_EC_PARAMS: u32 = 0x0000_0180;
pub const CKA_EC_POINT: u32 = 0x0000_0181;
// PQCToday vendor attrs (CKA_VENDOR_DEFINED | 0x1021/0x1022). Formerly bare
// 0x1021/0x1022, which squat OASIS-reserved space — see pkcs11t.h vendor
// extensions section. Legacy bare values still accepted (CKA_BIP32_*_LEGACY).
pub const CKA_BIP32_CHAIN_CODE: u32 = 0x8000_1021;
pub const CKA_BIP32_CHILD_INDEX: u32 = 0x8000_1022;
// Deprecated aliases — accepted on read paths for in-the-wild JS callers.
pub const CKA_BIP32_CHAIN_CODE_LEGACY: u32 = 0x0000_1021;
pub const CKA_BIP32_CHILD_INDEX_LEGACY: u32 = 0x0000_1022;
pub const CKA_PUBLIC_KEY_INFO: u32 = 0x0000_0129; // PKCS#11 v3.2 — DER SubjectPublicKeyInfo
pub const CKA_PARAMETER_SET: u32 = 0x0000_061d;
// PKCS#11 v3.2 — deterministic keygen seed (ξ for ML-DSA, d‖z for ML-KEM).
// Wired: native::keygen + ffi consume CKA_SEED for FIPS 203/204 deterministic
// keygen (ML-KEM KeyGen_internal(d,z); ML-DSA KeyGen from ξ).
pub const CKA_SEED: u32 = 0x0000_0637;

// ── PKCS#11 Object Classes ────────────────────────────────────────────────────

/// PKCS#11 v3.2 §4.6 — certificate objects. X.509 (`CKC_X_509`) only in
/// this engine; WTLS/X.509-attribute-certificate types are recognized (to
/// reject cleanly) but not implemented — no consumer in this workspace and
/// no KMIP 3.0 counterpart.
/// PKCS#11 v3.2 §4.5 — a generic data object (raw CKA_VALUE, no key
/// semantics). The CKM_HKDF_DATA derive result lands here (§2.43).
pub const CKO_DATA: u32 = 0x0000_0000;
pub const CKO_CERTIFICATE: u32 = 0x0000_0001;
pub const CKO_PUBLIC_KEY: u32 = 0x0000_0002;
pub const CKO_PRIVATE_KEY: u32 = 0x0000_0003;
pub const CKO_SECRET_KEY: u32 = 0x0000_0004;
/// PKCS#11 v3.2 §4.7 — trust objects bind trusted usages (`CKA_TRUST_*`
/// below) to individual certificates, keyed by `CKA_ISSUER` +
/// `CKA_SERIAL_NUMBER`. Read/write, general-purpose object storage — no
/// key-specific validation applies (state::validate_create_template already
/// falls through to `Ok(())` for any non-key class).
pub const CKO_TRUST: u32 = 0x0000_000b;
/// PKCS#11 Profiles v3.2 §3 — a token exposes one `CKO_PROFILE` object per
/// conformance profile it supports, each with a fixed `CKA_PROFILE_ID`.
/// Token-resident, public, read-only (state::init_profile_objects) — never
/// client-created (validate_create_template rejects it explicitly).
pub const CKO_PROFILE: u32 = 0x0000_0009;

/// PKCS#11 Profiles v3.2 §3 Table 1 — identifies which conformance profile
/// a `CKO_PROFILE` object represents. Read-only, set once at object creation.
pub const CKA_PROFILE_ID: u32 = 0x0000_0601;

// ── PKCS#11 Profiles v3.2 §3 Table 1 — CK_PROFILE_ID values ──────────────────

pub const CKP_INVALID_ID: u32 = 0x0000_0000;
pub const CKP_BASELINE_PROVIDER: u32 = 0x0000_0001;
pub const CKP_EXTENDED_PROVIDER: u32 = 0x0000_0002;
pub const CKP_AUTHENTICATION_TOKEN: u32 = 0x0000_0003;
pub const CKP_PUBLIC_CERTIFICATES_TOKEN: u32 = 0x0000_0004;
pub const CKP_COMPLETE_PROVIDER: u32 = 0x0000_0005;
pub const CKP_HKDF_TLS_TOKEN: u32 = 0x0000_0006;

// ── PKCS#11 v3.2 §4.7 — CK_TRUST values ──────────────────────────────────────

pub const CKT_TRUST_UNKNOWN: u32 = 0x0000_0000;
pub const CKT_TRUSTED: u32 = 0x0000_0001;
pub const CKT_TRUST_ANCHOR: u32 = 0x0000_0002;
pub const CKT_NOT_TRUSTED: u32 = 0x0000_0003;
pub const CKT_TRUST_MUST_VERIFY_TRUST: u32 = 0x0000_0004;

// ── PKCS#11 v3.2 §4.6.3 Table 20 — CK_CERTIFICATE_TYPE values ────────────────
// Only CKC_X_509 is accepted by this engine's template validation; the
// others are defined so an unsupported request can be recognized and
// rejected with CKR_ATTRIBUTE_VALUE_INVALID rather than falling through as
// an unrecognized raw integer.

pub const CKC_X_509: u32 = 0x0000_0000;
pub const CKC_X_509_ATTR_CERT: u32 = 0x0000_0001;
pub const CKC_WTLS: u32 = 0x0000_0002;

// ── PKCS#11 v3.2 §4.6.2 Table 19 — CK_CERTIFICATE_CATEGORY values ────────────

pub const CK_CERTIFICATE_CATEGORY_UNSPECIFIED: u32 = 0x0000_0000;
pub const CK_CERTIFICATE_CATEGORY_TOKEN_USER: u32 = 0x0000_0001;
pub const CK_CERTIFICATE_CATEGORY_AUTHORITY: u32 = 0x0000_0002;
pub const CK_CERTIFICATE_CATEGORY_OTHER_ENTITY: u32 = 0x0000_0003;

// ── PKCS#11 Key Types (CKK_*) ────────────────────────────────────────────────

pub const CKK_RSA: u32 = 0x0000_0000;
pub const CKK_EC: u32 = 0x0000_0003; // ECDSA (P-256, P-384)
pub const CKK_GENERIC_SECRET: u32 = 0x0000_0010;
pub const CKK_AES: u32 = 0x0000_001f;
pub const CKK_EC_EDWARDS: u32 = 0x0000_0040; // EdDSA (Ed25519)
pub const CKK_EC_MONTGOMERY: u32 = 0x0000_0041; // X25519 (PKCS#11 v3.2 §6.7)
pub const CKK_ML_KEM: u32 = 0x0000_0049;
pub const CKK_ML_DSA: u32 = 0x0000_004a;
pub const CKK_SLH_DSA: u32 = 0x0000_004b;
// Stateful hash-based signature key types (PKCS#11 v3.2 §6.14)
pub const CKK_HSS: u32 = 0x0000_0046; // HSS/LMS multi-level (standard)
pub const CKK_XMSS: u32 = 0x0000_0047; // XMSS single-tree (standard)
pub const CKK_XMSSMT: u32 = 0x0000_0048; // XMSS^MT multi-tree (standard)
// Vendor: single-level LMS (not in PKCS#11 v3.2 standard; same numeric space as CKK is separate from CKM)

// Vendor key types — FrodoKEM / Classic McEliece (BSI TR-02102-1 recommended KEMs,
// not NIST-standardized, no PKCS#11 v3.2 standard codepoint exists for either).
// Allocated at CKK_VENDOR_DEFINED (0x8000_0000) | n per
// pqctoday-priv/docs/platform/data/pkcs11-vendor-mech-allocation.md §1.4 — the
// first genuinely vendor-compliant allocation in this project (the earlier
// 0x4030-0x404F block sat below CKK_VENDOR_DEFINED and was retired).
pub const CKK_PQCTODAY_FRODOKEM: u32 = 0x8000_0001;
pub const CKK_PQCTODAY_CLASSIC_MCELIECE: u32 = 0x8000_0002;

// ── PKCS#11 Semantic Attribute Types ─────────────────────────────────────────

pub const CKA_CLASS: u32 = 0x0000_0000;
pub const CKA_TOKEN: u32 = 0x0000_0001;
pub const CKA_PRIVATE: u32 = 0x0000_0002;
// T6 — client-modifiable storage attrs (PKCS#11 v3.2 §4.5/§4.6 data objects).
pub const CKA_APPLICATION: u32 = 0x0000_0010;
pub const CKA_OBJECT_ID: u32 = 0x0000_0012;
// PKCS#11 v3.2 §4.4.1 — token-generated unique object identifier (read-only,
// assigned by the engine at object creation; see state::allocate_handle).
// Canonical OASIS value 0x4 (the local header had drifted to 0x17).
pub const CKA_UNIQUE_ID: u32 = 0x0000_0004;
pub const CKA_SENSITIVE: u32 = 0x0000_0103;
pub const CKA_ENCRYPT: u32 = 0x0000_0104;
pub const CKA_DECRYPT: u32 = 0x0000_0105;
pub const CKA_WRAP: u32 = 0x0000_0106;
pub const CKA_UNWRAP: u32 = 0x0000_0107;
pub const CKA_SIGN: u32 = 0x0000_0108;
pub const CKA_SIGN_RECOVER: u32 = 0x0000_0109;
pub const CKA_VERIFY: u32 = 0x0000_010a;
pub const CKA_VERIFY_RECOVER: u32 = 0x0000_010b;
pub const CKA_DERIVE: u32 = 0x0000_010c;
pub const CKA_EXTRACTABLE: u32 = 0x0000_0162;
pub const CKA_LOCAL: u32 = 0x0000_0163;
pub const CKA_NEVER_EXTRACTABLE: u32 = 0x0000_0164;
pub const CKA_ALWAYS_SENSITIVE: u32 = 0x0000_0165;
pub const CKA_KEY_GEN_MECHANISM: u32 = 0x0000_0166;
pub const CKA_CHECK_VALUE: u32 = 0x0000_0090;
pub const CKA_ENCAPSULATE: u32 = 0x0000_0633;
pub const CKA_DECAPSULATE: u32 = 0x0000_0634;
pub const CKA_MODIFIABLE: u32 = 0x0000_0170; // PKCS#11 v3.2 — mandatory for all objects (default: TRUE)
pub const CKA_COPYABLE: u32 = 0x0000_0171; // PKCS#11 v3.2 — mandatory for all objects (default: TRUE)
pub const CKA_DESTROYABLE: u32 = 0x0000_0172; // PKCS#11 v3.2 — mandatory for all objects (default: TRUE)
pub const CKA_TRUSTED: u32 = 0x0000_0086; // PKCS#11 v3.2 — public/secret keys (default: FALSE)
pub const CKA_WRAP_WITH_TRUSTED: u32 = 0x0000_0210; // PKCS#11 v3.2 — private/secret keys (default: FALSE)
pub const CKA_ALWAYS_AUTHENTICATE: u32 = 0x0000_0202; // PKCS#11 v3.2 — private keys (default: FALSE)

// PKCS#11 v3.2 §4.6 Tables 19-20 — CKO_CERTIFICATE object attributes
// (X.509 only). CKA_VALUE/CKA_ID/CKA_LABEL/CKA_TRUSTED/CKA_CHECK_VALUE/
// CKA_PUBLIC_KEY_INFO already exist (constants.rs / native/keygen.rs);
// CKA_ISSUER/CKA_SERIAL_NUMBER/CKA_NAME_HASH_ALGORITHM already exist below
// (shared with CKO_TRUST, §4.7 Table 25).
pub const CKA_CERTIFICATE_TYPE: u32 = 0x0000_0080;
pub const CKA_CERTIFICATE_CATEGORY: u32 = 0x0000_0087;
pub const CKA_URL: u32 = 0x0000_0089;
pub const CKA_HASH_OF_SUBJECT_PUBLIC_KEY: u32 = 0x0000_008a;
pub const CKA_HASH_OF_ISSUER_PUBLIC_KEY: u32 = 0x0000_008b;
pub const CKA_SUBJECT: u32 = 0x0000_0101;
pub const CKA_START_DATE: u32 = 0x0000_0110;
pub const CKA_END_DATE: u32 = 0x0000_0111;

// PKCS#11 v3.2 §4.7 Table 25 — CKO_TRUST object attributes. CKA_ISSUER +
// CKA_SERIAL_NUMBER key the trust object to a certificate; the 7 CKA_TRUST_*
// attributes (type CK_TRUST) carry per-usage trust values; a missing
// CKA_TRUST_* is application-interpreted as CKT_TRUST_UNKNOWN (not
// engine-synthesized — consistent with how every other optional attribute
// on this engine surfaces as CK_UNAVAILABLE_INFORMATION when absent).
pub const CKA_ISSUER: u32 = 0x0000_0081;
pub const CKA_SERIAL_NUMBER: u32 = 0x0000_0082;
pub const CKA_HASH_OF_CERTIFICATE: u32 = 0x0000_0635;
pub const CKA_NAME_HASH_ALGORITHM: u32 = 0x0000_008c;
pub const CKA_TRUST_SERVER_AUTH: u32 = 0x0000_062c;
pub const CKA_TRUST_CLIENT_AUTH: u32 = 0x0000_062d;
pub const CKA_TRUST_CODE_SIGNING: u32 = 0x0000_062e;
pub const CKA_TRUST_EMAIL_PROTECTION: u32 = 0x0000_062f;
pub const CKA_TRUST_IPSEC_IKE: u32 = 0x0000_0630;
pub const CKA_TRUST_TIME_STAMPING: u32 = 0x0000_0631;
pub const CKA_TRUST_OCSP_SIGNING: u32 = 0x0000_0632;

/// PKCS#11 v3.2 §3.1/§4.8 Table 13 — marks an attribute whose value is an
/// array (here, of `CK_MECHANISM_TYPE`) rather than a scalar.
pub const CKF_ARRAY_ATTRIBUTE: u32 = 0x4000_0000;

// ── CK_MECHANISM_INFO.flags (values from the pinned canonical OASIS v3.2
//    pkcs11t.h, docs/refs/pkcs11t-canonical-v3.2.h:1298-1312) ───────────────
// PKCS#11 v3.2 §6.3.3 states three times that a library performing EC
// mechanisms "must set" the field-type, parameter-encoding and point-form
// flags on EACH EC mechanism. Remediation item C3, 2026-08-13.
pub const CKF_WRAP: u32 = 0x0002_0000;
pub const CKF_UNWRAP: u32 = 0x0004_0000;
/// The mechanism can be used with EC domain parameters over F_p.
pub const CKF_EC_F_P: u32 = 0x0010_0000;
/// F_2^m curves — this engine implements none, so it is never set.
pub const CKF_EC_F_2M: u32 = 0x0020_0000;
/// CKA_EC_PARAMS may be supplied as explicit `ECParameters`.
pub const CKF_EC_ECPARAMETERS: u32 = 0x0040_0000;
/// CKA_EC_PARAMS may be supplied as a named-curve OID.
pub const CKF_EC_OID: u32 = 0x0080_0000;
/// Uncompressed point form is accepted / produced.
pub const CKF_EC_UNCOMPRESS: u32 = 0x0100_0000;
/// Compressed point form is accepted / produced.
pub const CKF_EC_COMPRESS: u32 = 0x0200_0000;
/// CKA_EC_PARAMS may be supplied as a `PrintableString` curve name.
pub const CKF_EC_CURVENAME: u32 = 0x0400_0000;
/// PKCS#11 v3.2 §4.8 Table 13 — restricts a key to a caller-specified
/// mechanism whitelist; absent = unrestricted (the spec default). Stored as
/// a packed `CK_MECHANISM_TYPE[]` (u32 LE, matching this engine's existing
/// CK_ULONG-as-4-byte convention — see `check_mechanism_allowed` in ffi.rs).
pub const CKA_ALLOWED_MECHANISMS: u32 = CKF_ARRAY_ATTRIBUTE | 0x0000_0600;

/// PKCS#11 v3.2 §5.18.3 — "To partition the wrapping keys so they can only
/// wrap a subset of extractable keys the attribute CKA_WRAP_TEMPLATE can be
/// used on the wrapping key to specify an attribute set that will be compared
/// against the attributes of the key to be wrapped." Array attribute: the
/// caller supplies a `CK_ATTRIBUTE[]`, which the engine flattens into a
/// self-contained byte blob at absorb time (see
/// `crypto::handlers::flatten_attr_array` — the caller's pointers are
/// invalid the moment the call returns, so the raw struct bytes cannot be
/// stored). Remediation item S2, 2026-08-13.
pub const CKA_WRAP_TEMPLATE: u32 = CKF_ARRAY_ATTRIBUTE | 0x0000_0211;
/// §5.18.3 twin of [`CKA_WRAP_TEMPLATE`], applied to the key produced by
/// `C_UnwrapKey`; a caller template contradicting it is
/// `CKR_TEMPLATE_INCONSISTENT`.
pub const CKA_UNWRAP_TEMPLATE: u32 = CKF_ARRAY_ATTRIBUTE | 0x0000_0212;
/// §5.18.3 — the derive counterpart. Defined for completeness of the array
/// attribute family; not enforced by any derive path yet.
pub const CKA_DERIVE_TEMPLATE: u32 = CKF_ARRAY_ATTRIBUTE | 0x0000_0213;

// Private attribute: stores the parameter set on generated keys
pub const CKA_PRIV_PARAM_SET: u32 = 0xFFFF_0001;
// Private attribute: stores the algorithm family for polymorphic dispatch
pub const CKA_PRIV_ALGO_FAMILY: u32 = 0xFFFF_0002;
// Private attribute: handle of the session that created the object (u32 LE).
// 0 / absent = library scope (native/KMIP-registered objects). Session objects
// (CKA_TOKEN=FALSE) owned by a session are destroyed when it closes (§4.4).
pub const CKA_PRIV_OWNER_SESSION: u32 = 0xFFFF_0003;
// Private attribute: slot id of the token that owns the object (u32 LE).
// Stamped at creation (state::allocate_handle) from the creating session's
// slot; absent/legacy records default to slot 0 (the primary token). Object
// enumeration (C_FindObjects, native CKA_ID lookups) and handle visibility
// are scoped to the session's slot via this attribute (audit: multi-slot
// FindObjects scoping).
pub const CKA_PRIV_SLOT_ID: u32 = 0xFFFF_0004;
// ── Engine-private stateful-signature state (remediation item S4, 2026-08-13)
// These three lived at 0x8000_0101/0105/0106 — inside the vendor range that
// `state::attr_mutation_allowed` exempted from mutation policy wholesale, so
// a client could write the leaf index back to zero and rewind an XMSS/LMS
// one-time-signature key (reuse of a one-time key permits forgery). The
// v3.2 HSS/XMSS private-key tables put this state in the key's value
// attribute, which carries no modify-after-creation footnote and is
// therefore not modifiable; relocating it to a writable vendor attribute
// routed around that. They now live in the ENGINE-PRIVATE range, which
// `crypto::handlers::template_attr_is_skipped` strips from client templates
// and `state::attr_mutation_allowed` refuses outright. They remain READABLE
// (C_GetAttributeValue does not filter by id range), so the playground's
// remaining-signature display is unaffected.
//
// The ids MOVED rather than the policy alone changing, because genuine
// vendor attributes must keep their spec-sanctioned "outside Cryptoki's
// scope" mutability. `state_snapshot` bumps its format accordingly and
// REFUSES the old layout — see CKR_PQCTODAY_SNAPSHOT_FORMAT_UNSUPPORTED.
/// Raw serialised stateful private-key blob (HSS/LMS, XMSS, XMSS^MT).
pub const CKA_PRIV_STATEFUL_KEY_STATE: u32 = 0xFFFF_0005;
/// Current one-time-signature leaf index (u64, little-endian).
pub const CKA_PRIV_LEAF_INDEX: u32 = 0xFFFF_0006;
/// Remaining XMSS / XMSS^MT signature operations (CK_ULONG width, LE).
pub const CKA_PRIV_XMSS_KEYS_REMAINING: u32 = 0xFFFF_0007;

// ── PKCS#11 Mechanism Types ──────────────────────────────────────────────────

// RSA
pub const CKM_RSA_PKCS_KEY_PAIR_GEN: u32 = 0x0000_0000;
pub const CKM_RSA_PKCS_OAEP: u32 = 0x0000_0009;
pub const CKM_SHA256_RSA_PKCS: u32 = 0x0000_0040;
pub const CKM_SHA384_RSA_PKCS: u32 = 0x0000_0041;
pub const CKM_SHA512_RSA_PKCS: u32 = 0x0000_0042;
pub const CKM_SHA256_RSA_PKCS_PSS: u32 = 0x0000_0043;
pub const CKM_SHA384_RSA_PKCS_PSS: u32 = 0x0000_0044;
pub const CKM_SHA512_RSA_PKCS_PSS: u32 = 0x0000_0045;
// Raw RSA PKCS#1 v1.5 sign/verify/encrypt (caller supplies the data; no hash).
pub const CKM_RSA_PKCS: u32 = 0x0000_0001;
// Raw RSA, X.509-style — no padding at all (RSASP1/RSAVP1 directly on the
// caller's data as a big-endian integer). Added 2026-07-25 for
// C_SignRecover/C_VerifyRecover — this mechanism previously had zero
// plumbing anywhere in this engine (no regular Sign/Encrypt support either).
pub const CKM_RSA_X_509: u32 = 0x0000_0003;
// Raw RSA-PSS (caller supplies the pre-computed hash) — advertised in §6.4.
pub const CKM_RSA_PKCS_PSS: u32 = 0x0000_000D;
// RSA private-key CRT components (§2.1.3) — sensitive material, never extractable
// in clear from a sensitive key. CKA_PRIVATE_EXPONENT .. CKA_COEFFICIENT.
pub const CKA_PRIVATE_EXPONENT: u32 = 0x0000_0123;
pub const CKA_PRIME_1: u32 = 0x0000_0124;
pub const CKA_PRIME_2: u32 = 0x0000_0125;
pub const CKA_EXPONENT_1: u32 = 0x0000_0126;
pub const CKA_EXPONENT_2: u32 = 0x0000_0127;
pub const CKA_COEFFICIENT: u32 = 0x0000_0128;
// SHA3-384 RSA composite sign mechanisms (§6.4).
pub const CKM_SHA3_384_RSA_PKCS: u32 = 0x0000_0061;
pub const CKM_SHA3_384_RSA_PKCS_PSS: u32 = 0x0000_0064;

// PQC - KEM
pub const CKM_ML_KEM_KEY_PAIR_GEN: u32 = 0x0000_000F;
pub const CKM_ML_KEM: u32 = 0x0000_0017;

// Vendor KEMs — FrodoKEM / Classic McEliece (BSI TR-02102-1 §2.4.1/2.4.2
// recommended, NIST passed on both). No PKCS#11 v3.2 standard codepoint exists
// for either (confirmed against the normative pkcs11t.h and the OASIS CSD01
// spec text directly). Allocated at CKM_VENDOR_DEFINED (0x8000_0000) | n per
// pqctoday-priv/docs/platform/data/pkcs11-vendor-mech-allocation.md §1.4.
pub const CKM_PQCTODAY_FRODOKEM_KEY_PAIR_GEN: u32 = 0x8000_0001;
pub const CKM_PQCTODAY_FRODOKEM_ENCAPSULATE: u32 = 0x8000_0002;
pub const CKM_PQCTODAY_CLASSIC_MCELIECE_KEY_PAIR_GEN: u32 = 0x8000_0003;
pub const CKM_PQCTODAY_CLASSIC_MCELIECE_ENCAPSULATE: u32 = 0x8000_0004;

// PQC - DSA
pub const CKM_ML_DSA_KEY_PAIR_GEN: u32 = 0x0000_001C;
pub const CKM_ML_DSA: u32 = 0x0000_001D;
pub const CKM_HASH_ML_DSA: u32 = 0x0000_001F;
pub const CKM_SLH_DSA_KEY_PAIR_GEN: u32 = 0x0000_002D;
pub const CKM_SLH_DSA: u32 = 0x0000_002E;
pub const CKM_HASH_SLH_DSA: u32 = 0x0000_0034;

// CKH_ hedge/determinism constants (PKCS#11 v3.2 §7.3)
pub const CKH_DETERMINISTIC_REQUIRED: u32 = 0x0000_0002;

// SHA Digest
pub const CKM_SHA256: u32 = 0x0000_0250;
pub const CKM_SHA224: u32 = 0x0000_0255;
pub const CKM_SHA384: u32 = 0x0000_0260;
pub const CKM_SHA512: u32 = 0x0000_0270;
pub const CKM_SHA3_256: u32 = 0x0000_02B0;
pub const CKM_SHA3_224: u32 = 0x0000_02B5;
pub const CKM_SHA3_384: u32 = 0x0000_02C0;
pub const CKM_SHA3_512: u32 = 0x0000_02D0;
// RIPEMD-160 (historical) — digest + HMAC.
pub const CKM_RIPEMD160: u32 = 0x0000_0240;
pub const CKM_RIPEMD160_HMAC: u32 = 0x0000_0241;

// HMAC
pub const CKM_SHA256_HMAC: u32 = 0x0000_0251;
pub const CKM_SHA384_HMAC: u32 = 0x0000_0261;
pub const CKM_SHA512_HMAC: u32 = 0x0000_0271;
pub const CKM_SHA3_256_HMAC: u32 = 0x0000_02B1;
pub const CKM_SHA3_512_HMAC: u32 = 0x0000_02D1;
// HMAC general-length variants (§6.x — CK_MAC_GENERAL_PARAMS = ulMacLength)
pub const CKM_SHA256_HMAC_GENERAL: u32 = 0x0000_0252;
pub const CKM_SHA384_HMAC_GENERAL: u32 = 0x0000_0262;
pub const CKM_SHA512_HMAC_GENERAL: u32 = 0x0000_0272;
pub const CKM_SHA3_256_HMAC_GENERAL: u32 = 0x0000_02B2;
pub const CKM_SHA3_512_HMAC_GENERAL: u32 = 0x0000_02D2;

// MGF identifiers (CK_RSA_PKCS_MGF_TYPE)
pub const CKG_MGF1_SHA1: u32 = 0x0000_0001;
pub const CKG_MGF1_SHA256: u32 = 0x0000_0002;
pub const CKG_MGF1_SHA384: u32 = 0x0000_0003;
pub const CKG_MGF1_SHA512: u32 = 0x0000_0004;
pub const CKG_MGF1_SHA3_384: u32 = 0x0000_0008;
// OAEP source type
pub const CKZ_DATA_SPECIFIED: u32 = 0x0000_0001;
// SP 800-108 data-param types (beyond BYTE_ARRAY below)
pub const CK_SP800_108_ITERATION_VARIABLE: u32 = 0x0000_0001;
/// PKCS#11 v3.2 Table 197 — `CK_SP800_108_OPTIONAL_COUNTER`, aliased by the
/// spec as `CK_SP800_108_COUNTER`. Invalid for Counter Mode KDF (Table 199 —
/// the counter there is the mandatory ITERATION_VARIABLE); optional for
/// Feedback Mode KDF (Table 200).
pub const CK_SP800_108_OPTIONAL_COUNTER: u32 = 0x0000_0002;
pub const CK_SP800_108_COUNTER: u32 = CK_SP800_108_OPTIONAL_COUNTER;
pub const CK_SP800_108_DKM_LENGTH: u32 = 0x0000_0003;
/// PKCS#11 v3.2 Table 197 — identifies a symmetric key's `CKA_VALUE` to be
/// spliced into the constructed PRF input data at this position.
pub const CK_SP800_108_KEY_HANDLE: u32 = 0x0000_0005;
pub const CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS: u32 = 0x0000_0001;
/// PKCS#11 v3.2 Table 198 — DKM length is the sum of the lengths of all PRF
/// output segments produced by this KDF invocation (rounded up to a whole
/// number of PRF-output blocks), not just the derived key length(s).
pub const CK_SP800_108_DKM_LENGTH_SUM_OF_SEGMENTS: u32 = 0x0000_0002;

// KMAC
pub const CKM_KMAC_128: u32 = 0x8000_0100;
pub const CKM_KMAC_256: u32 = 0x8000_0101;

// Generic Secret
pub const CKM_GENERIC_SECRET_KEY_GEN: u32 = 0x0000_0350;
pub const CKM_UNAVAILABLE_INFORMATION: u32 = 0xFFFF_FFFF; // PKCS#11 v3.2 §4.3 — CKA_KEY_GEN_MECHANISM on imported keys

// Key Derivation Functions
pub const CKM_PKCS5_PBKD2: u32 = 0x0000_03b0;
pub const CKM_SP800_108_COUNTER_KDF: u32 = 0x0000_03ac;
pub const CKM_SP800_108_FEEDBACK_KDF: u32 = 0x0000_03ad;
pub const CKM_HKDF_DERIVE: u32 = 0x0000_402a;
/// PKCS#11 v3.2 §2.43 — same HKDF computation as CKM_HKDF_DERIVE, output as
/// a CKO_DATA object instead of a CKO_SECRET_KEY.
pub const CKM_HKDF_DATA: u32 = 0x0000_402b;
// Simple key-derivation mechanisms (PKCS#11 v3.2 §6.43 "Miscellaneous simple
// key derivation"). Values verified against the vendored pkcs11t.h. The
// composable building blocks for hybrid-KEM combiners (classical ‖ PQC),
// entirely in-HSM — v3.2 has no dedicated hybrid-KEM mechanism.
//   §6.43.3 — derived value = base.CKA_VALUE ‖ second_key.CKA_VALUE
//             (param: CK_OBJECT_HANDLE of the second key).
pub const CKM_CONCATENATE_BASE_AND_KEY: u32 = 0x0000_0360;
//   §6.43.4 — derived value = base.CKA_VALUE ‖ data
//             (param: CK_KEY_DERIVATION_STRING_DATA { pData, ulLen }).
//             For appending ciphertext/pubkey/label in transcript-binding
//             combiners (X-Wing, Chempat).
pub const CKM_CONCATENATE_BASE_AND_DATA: u32 = 0x0000_0362;

// Digest key-derivation (PKCS#11 v3.2 §6.22 SHA-2 / §6.29 SHA-3): derived
// value = SHAx(base.CKA_VALUE), left-truncated to CKA_VALUE_LEN when the
// template supplies one. The hash-second-step for concat-then-hash combiners
// (SSH, X-Wing). Values verified against pkcs11t.h.
pub const CKM_SHA256_KEY_DERIVATION: u32 = 0x0000_0393;
pub const CKM_SHA384_KEY_DERIVATION: u32 = 0x0000_0394;
pub const CKM_SHA512_KEY_DERIVATION: u32 = 0x0000_0395;
pub const CKM_SHA3_256_KEY_DERIVATION: u32 = 0x0000_0397;
pub const CKM_SHA3_384_KEY_DERIVATION: u32 = 0x0000_0399;
pub const CKM_SHA3_512_KEY_DERIVATION: u32 = 0x0000_039a;

// HKDF salt-as-key flag (pkcs11t.h) — complements the existing
// CKF_HKDF_SALT_DATA. Lets HKDF-Extract key on ANOTHER key's value (salt =
// key handle), i.e. HMAC(salt_key, base) — the keyed dual-PRF combiner form.
pub const CKF_HKDF_SALT_KEY: u32 = 0x0000_0004;
// PKCS#11 v3.2 §6.62.2 — "no salt is supplied". Used only to validate
// ulSaltType when bExtract is true (§6.62.3); the derive itself already
// treats any non-DATA/non-KEY value as "no salt" by construction.
pub const CKF_HKDF_SALT_NULL: u32 = 0x0000_0001;

// ML-DSA pre-hash mechanisms (PKCS#11 v3.2, pkcs11t.h §1221-1231)
pub const CKM_HASH_ML_DSA_SHA224: u32 = 0x0000_0023;
pub const CKM_HASH_ML_DSA_SHA256: u32 = 0x0000_0024;
pub const CKM_HASH_ML_DSA_SHA384: u32 = 0x0000_0025;
pub const CKM_HASH_ML_DSA_SHA512: u32 = 0x0000_0026;
pub const CKM_HASH_ML_DSA_SHA3_224: u32 = 0x0000_0027;
pub const CKM_HASH_ML_DSA_SHA3_256: u32 = 0x0000_0028;
pub const CKM_HASH_ML_DSA_SHA3_384: u32 = 0x0000_0029;
pub const CKM_HASH_ML_DSA_SHA3_512: u32 = 0x0000_002a;
pub const CKM_HASH_ML_DSA_SHAKE128: u32 = 0x0000_002b;
pub const CKM_HASH_ML_DSA_SHAKE256: u32 = 0x0000_002c;

// SLH-DSA pre-hash mechanisms (PKCS#11 v3.2, pkcs11t.h §1235-1245)
pub const CKM_HASH_SLH_DSA_SHA224: u32 = 0x0000_0036;
pub const CKM_HASH_SLH_DSA_SHA256: u32 = 0x0000_0037;
pub const CKM_HASH_SLH_DSA_SHA384: u32 = 0x0000_0038;
pub const CKM_HASH_SLH_DSA_SHA512: u32 = 0x0000_0039;
pub const CKM_HASH_SLH_DSA_SHA3_224: u32 = 0x0000_003a;
pub const CKM_HASH_SLH_DSA_SHA3_256: u32 = 0x0000_003b;
pub const CKM_HASH_SLH_DSA_SHA3_384: u32 = 0x0000_003c;
pub const CKM_HASH_SLH_DSA_SHA3_512: u32 = 0x0000_003d;
pub const CKM_HASH_SLH_DSA_SHAKE128: u32 = 0x0000_003e;
pub const CKM_HASH_SLH_DSA_SHAKE256: u32 = 0x0000_003f;

// PKCS#11 v3.2 §5.2.12 — X9.63 KDF with SHA3
pub const CKD_SHA3_256_KDF: u32 = 0x0000_000B; // PKCS#11 v3.2 §5.2.12 — SHA3-256 X9.63 KDF
pub const CKD_SHA3_512_KDF: u32 = 0x0000_000D; // PKCS#11 v3.2 §5.2.12 — SHA3-512 X9.63 KDF

// PBKDF2 PRF types
pub const CKP_PBKDF2_HMAC_SHA256: u32 = 0x04;
pub const CKP_PBKDF2_HMAC_SHA384: u32 = 0x05;
pub const CKP_PBKDF2_HMAC_SHA512: u32 = 0x06;

// HKDF salt types
pub const CKF_HKDF_SALT_DATA: u32 = 0x0000_0002;

// SP 800-108 data param types
pub const CK_SP800_108_BYTE_ARRAY: u32 = 0x0000_0004;

// EC
// ----- HD Derivation (BIP32 / SLIP10) -----
// PQCToday vendor mechanisms (CKM_VENDOR_DEFINED | 0x105B/0x105C). Formerly
// bare 0x105B/0x105C, which squat OASIS-reserved space — see pkcs11t.h
// vendor extensions section. Only the vendor codepoints are advertised;
// the legacy bare values are still ACCEPTED at C_DeriveKey dispatch as
// deprecated aliases for in-the-wild JS callers.
pub const CKM_BIP32_MASTER_DERIVE: u32 = 0x8000_105B;
pub const CKM_BIP32_CHILD_DERIVE: u32 = 0x8000_105C;
// Deprecated aliases — do NOT advertise; dispatch-accept only.
pub const CKM_BIP32_MASTER_DERIVE_LEGACY: u32 = 0x0000_105B;
pub const CKM_BIP32_CHILD_DERIVE_LEGACY: u32 = 0x0000_105C;
pub const CKF_BIP32_HARDENED: u32 = 0x8000_0000;

pub const CKM_EC_KEY_PAIR_GEN: u32 = 0x0000_1040;
pub const CKM_ECDSA: u32 = 0x0000_1041; // PKCS#11 v3.2 §6.3.12 — raw (pre-hashed), no parameter, single-part only, token truncates internally
pub const CKM_ECDSA_SHA256: u32 = 0x0000_1044;
pub const CKM_ECDSA_SHA384: u32 = 0x0000_1045;
pub const CKM_ECDSA_SHA512: u32 = 0x0000_1046;
// ECDSA with SHA-3 prehash (PKCS#11 v3.2 §6.3)
pub const CKM_ECDSA_SHA3_224: u32 = 0x0000_1047;
pub const CKM_ECDSA_SHA3_256: u32 = 0x0000_1048;
pub const CKM_ECDSA_SHA3_384: u32 = 0x0000_1049;
pub const CKM_ECDSA_SHA3_512: u32 = 0x0000_104a;
pub const CKM_ECDH1_DERIVE: u32 = 0x0000_1050;
pub const CKM_ECDH1_COFACTOR_DERIVE: u32 = 0x0000_1051;
pub const CKM_EC_EDWARDS_KEY_PAIR_GEN: u32 = 0x0000_1055;
pub const CKM_EC_MONTGOMERY_KEY_PAIR_GEN: u32 = 0x0000_1056; // PKCS#11 v3.2 §6.7 — X25519 keygen
pub const CKM_EDDSA: u32 = 0x0000_1057;
// Vendor alias: ECDH1_DERIVE for X25519 keys. Moved into the vendor-defined
// range (0x80000000+) — the former 0x1058 squatted unassigned spec-reserved
// space adjacent to CKM_EDDSA and risked a future OASIS collision.
pub const CKM_EC_MONTGOMERY_KEY_DERIVE: u32 = 0x8000_0011;
// G12 — Split Key secret sharing (KMIP 3.0 §6.1.12/§6.1.31, §13.1).
// PKCS#11 v3.2 has NO mechanism for this at all (verified directly
// against the spec text, not just the header — no Shamir / secret
// sharing / threshold-scheme / key-split concept anywhere in it), so
// this is a genuinely new vendor mechanism, not a gap-fill of an
// existing one. Covers all four KMIP 3.0 §11.54 Split Key Method
// Enumeration values (XOR, Prime Field, GF(2^16), GF(2^8)) — the
// specific method + parameters travel in a
// `CK_SPLIT_KEY_PARAMS`-style native argument, not separate mechanism
// codepoints, mirroring how CKM_HSS_KEY_PAIR_GEN carries its levels/
// param-set choice in one mechanism.
pub const CKM_PQCTODAY_SPLIT_KEY: u32 = 0x8000_0012;
// ML-DSA external-µ signing (remediation R34, 2026-08-26). Stopgap for
// PKCS#11 v3.3's own upcoming external-µ mechanism (oasis-tcs/pkcs11#58,
// not yet ratified) — see
// docs/openssl-provider-ml-dsa-external-mu-vendor-ext-2026-08-26.md.
// PQCTODAY-VENDOR-EXT-MU: remove when this project adopts v3.3 natively.
pub const CKM_PQCTODAY_ML_DSA_MU: u32 = 0x8000_0013;
pub const PQCTODAY_ML_DSA_MU_LEN: usize = 64;
// µ GENERATION (remediation R39, phase 8, 2026-08-26) — the PRODUCE half
// of external-µ (the mechanism above is the CONSUME half); a digest-type
// mechanism (C_Digest/C_DigestUpdate/C_DigestFinal). Same
// PQCTODAY-VENDOR-EXT-MU removal group as the mechanism above.
pub const CKM_PQCTODAY_ML_DSA_MU_GEN: u32 = 0x8000_0014;
// PKCS#11 v3.2 §6.7 dedicated Montgomery-curve DH mechanisms, in the
// CKM_VENDOR_DEFINED (0x80000000) range per the spec header:
// CKM_X25519 = CKM_VENDOR_DEFINED | 0x1058, CKM_X448 = | 0x1059.
pub const CKM_X25519: u32 = 0x8000_1058;
pub const CKM_X448: u32 = 0x8000_1059;
// AES-CMAC (PKCS#11 v3.2 §6.43) — also a valid SP 800-108 KBKDF PRF.
pub const CKM_AES_CMAC: u32 = 0x0000_108A;
// Ed25519ph (prehashed). This is the real PKCS#11 v3.2 mechanism value
// (pkcs11t.h: CKM_EDDSA_PH = 0x80001057); the engine also dispatches to it
// internally when CK_EDDSA_PARAMS.phFlag is set on a plain CKM_EDDSA op.
pub const CKM_EDDSA_PH: u32 = 0x8000_1057;

// AES
pub const CKM_AES_KEY_GEN: u32 = 0x0000_1080;
/// PKCS#11 v3.2 §6.10 — AES-ECB. No IV; plaintext MUST be a multiple
/// of 16 bytes (no padding); ciphertext same length.
pub const CKM_AES_ECB: u32     = 0x0000_1081;
/// PKCS#11 v3.2 §6.10 — AES-CBC. 16-byte IV; plaintext MUST be a
/// multiple of 16 bytes (no padding); use `CKM_AES_CBC_PAD` for
/// PKCS#7 padding.
pub const CKM_AES_CBC: u32     = 0x0000_1082;
pub const CKM_AES_CBC_PAD: u32 = 0x0000_1085;
pub const CKM_AES_CTR: u32 = 0x0000_1086;
pub const CKM_AES_GCM: u32 = 0x0000_1087;
pub const CKM_AES_KEY_WRAP: u32 = 0x0000_2109;
// RFC 5649 AES Key Wrap with Padding. Both names denote the same RFC 5649
// scheme; `_PAD` is the deprecated v2.40 name (was 0x1091), `_KWP` the v3.x
// name. Values per pkcs11t.h: PAD=0x210A, KWP=0x210B.
pub const CKM_AES_KEY_WRAP_PAD: u32 = 0x0000_210A;
pub const CKM_AES_KEY_WRAP_KWP: u32 = 0x0000_210B;

// ChaCha20 family — PKCS#11 v3.2 §6.20 (RFC 7539 / 8439 stream cipher
// + AEAD). Values verified against normative pkcs11t.h (NOT the vendor
// manifest, which had them wrong — collided with CKM_AES_XTS / CKM_TWOFISH_CBC).
/// `CKM_CHACHA20` — IETF ChaCha20 stream cipher. 32-byte key, 12-byte
/// nonce. Distinct from the older 8-byte-nonce variant.
pub const CKM_CHACHA20: u32 = 0x0000_1226;
pub const CKM_CHACHA20_KEY_GEN: u32 = 0x0000_1225;
// CKK_CHACHA20 key type (§6.20) — a 256-bit ChaCha20 stream-cipher key.
pub const CKK_CHACHA20: u32 = 0x0000_0033;
/// `CKM_CHACHA20_POLY1305` — IETF ChaCha20-Poly1305 AEAD (RFC 8439).
/// 32-byte key, 12-byte nonce, 16-byte tag.
pub const CKM_CHACHA20_POLY1305: u32 = 0x0000_4021;

// ── PKCS#11 Parameter Sets ──────────────────────────────────────────────────

pub const CKP_ML_KEM_512: u32 = 0x1;
pub const CKP_ML_KEM_768: u32 = 0x2;
pub const CKP_ML_KEM_1024: u32 = 0x3;

// FrodoKEM (BSI TR-02102-1 §2.4.1) — 6 standard variants; eFrodoKEM
// (ephemeral/one-time-use) intentionally not exposed, see the FrodoKEM/
// Classic-McEliece/HQC implementation plan Phase 0.8.
pub const CKP_FRODOKEM_640_AES: u32 = 0x1;
pub const CKP_FRODOKEM_640_SHAKE: u32 = 0x2;
pub const CKP_FRODOKEM_976_AES: u32 = 0x3;
pub const CKP_FRODOKEM_976_SHAKE: u32 = 0x4;
pub const CKP_FRODOKEM_1344_AES: u32 = 0x5;
pub const CKP_FRODOKEM_1344_SHAKE: u32 = 0x6;

// Classic McEliece (BSI TR-02102-1 §2.4.2) — scoped to mceliece6688128 (BSI's
// Category-5 pick) for this slice; the crate can only have one parameter-set
// feature compiled in at a time (see implementation plan Phase 0.5), so this
// is the only valid value today. Kept as an explicit CKP_* (not a bare
// literal) so CKA_PARAMETER_SET validation follows the same
// no-silent-default pattern as ML-KEM, and so adding 460896/8192128 later is
// additive, not a rename.
pub const CKP_CLASSIC_MCELIECE_6688128: u32 = 0x1;

pub const CKP_ML_DSA_44: u32 = 0x1;
pub const CKP_ML_DSA_65: u32 = 0x2;
pub const CKP_ML_DSA_87: u32 = 0x3;

pub const CKP_SLH_DSA_SHA2_128S: u32 = 0x01;
pub const CKP_SLH_DSA_SHAKE_128S: u32 = 0x02;
pub const CKP_SLH_DSA_SHA2_128F: u32 = 0x03;
pub const CKP_SLH_DSA_SHAKE_128F: u32 = 0x04;
pub const CKP_SLH_DSA_SHA2_192S: u32 = 0x05;
pub const CKP_SLH_DSA_SHAKE_192S: u32 = 0x06;
pub const CKP_SLH_DSA_SHA2_192F: u32 = 0x07;
pub const CKP_SLH_DSA_SHAKE_192F: u32 = 0x08;
pub const CKP_SLH_DSA_SHA2_256S: u32 = 0x09;
pub const CKP_SLH_DSA_SHAKE_256S: u32 = 0x0A;
pub const CKP_SLH_DSA_SHA2_256F: u32 = 0x0B;
pub const CKP_SLH_DSA_SHAKE_256F: u32 = 0x0C;

// ── PKCS#11 Session/Token Constants ─────────────────────────────────────────

pub const CKS_RO_PUBLIC_SESSION: u32 = 0;
pub const CKS_RO_USER_FUNCTIONS: u32 = 1;
pub const CKS_RW_PUBLIC_SESSION: u32 = 2;
pub const CKS_RW_USER_FUNCTIONS: u32 = 3;
pub const CKS_RW_SO_FUNCTIONS: u32 = 4;

pub const CKF_SERIAL_SESSION: u32 = 0x0000_0004;
pub const CKF_RW_SESSION: u32 = 0x0000_0002;
// PKCS#11 v3.2 §5.6 — async sessions. We do not support async, so the token
// never advertises CKF_ASYNC_SESSION_SUPPORTED and C_OpenSession rejects the
// CKF_ASYNC_SESSION request flag.
pub const CKF_ASYNC_SESSION: u32 = 0x0000_0008;

// PKCS#11 v3.2 §5.5 — CK_TOKEN_INFO.flags (pkcs11t.h "token information flags")
pub const CKF_RNG: u32 = 0x0000_0001;
pub const CKF_WRITE_PROTECTED: u32 = 0x0000_0002;
pub const CKF_LOGIN_REQUIRED: u32 = 0x0000_0004;
pub const CKF_USER_PIN_INITIALIZED: u32 = 0x0000_0008;
// PKCS#11 v3.2 pkcs11t.h — "If it is set, that means that *every* time the
// state of cryptographic operations of a session is successfully saved,
// all keys needed to continue those operations are stored in the state."
// Unconditionally true for a software-only token: no operation state is
// ever backed by external/removable key material this engine could fail
// to persist. The C++ engine (Token::getTokenInfo) sets this
// unconditionally for the same reason — this keeps the two engines at
// parity.
pub const CKF_RESTORE_KEY_NOT_NEEDED: u32 = 0x0000_0020;
pub const CKF_TOKEN_INITIALIZED: u32 = 0x0000_0400;
/// PKCS#11 v3.2 §4.2 — `CK_UNAVAILABLE_INFORMATION` is `(~0UL)`, i.e.
/// 0xFFFF_FFFF on this 32-bit (wasm) CK_ULONG ABI. Used by C_GetTokenInfo
/// for unbounded session limits and untracked memory counters.
pub const CK_UNAVAILABLE_INFORMATION: u32 = 0xFFFF_FFFF;
pub const CKR_SESSION_HANDLE_INVALID: u32 = 0x0000_00B3;
pub const CKR_SESSION_EXISTS: u32 = 0x0000_00B6;
pub const CKR_SESSION_READ_ONLY: u32 = 0x0000_00B5;
pub const CKR_SESSION_READ_ONLY_EXISTS: u32 = 0x0000_00B7;
pub const CKR_SESSION_READ_WRITE_SO_EXISTS: u32 = 0x0000_00B8;
// PKCS#11 v3.2 §5.6.1 — returned when CKF_ASYNC_SESSION is requested but the
// token does not support async sessions.
pub const CKR_SESSION_ASYNC_NOT_SUPPORTED: u32 = 0x0000_0205;
pub const CKR_USER_TYPE_INVALID: u32 = 0x0000_0103;
pub const CKR_USER_ANOTHER_ALREADY_LOGGED_IN: u32 = 0x0000_0104;
pub const CKR_USER_TOO_MANY_TYPES: u32 = 0x0000_0105;
pub const CKR_USER_NOT_LOGGED_IN: u32 = 0x0000_0101;
pub const CKR_USER_ALREADY_LOGGED_IN: u32 = 0x0000_0100;
pub const CKR_USER_PIN_NOT_INITIALIZED: u32 = 0x0000_0102;
pub const CKR_PIN_INCORRECT: u32 = 0x0000_00A0;
pub const CKR_PIN_INVALID: u32 = 0x0000_00A1;
pub const CKR_PIN_LEN_RANGE: u32 = 0x0000_00A2;
// T6 — C_SeedRandom: the engine's RNG is OS-backed and takes no external
// seeding (PKCS#11 v3.2 §5.14).
pub const CKR_RANDOM_SEED_NOT_SUPPORTED: u32 = 0x0000_0120;
pub const CKR_SLOT_ID_INVALID: u32 = 0x0000_0003;
pub const CKU_SO: u32 = 0;
pub const CKU_USER: u32 = 1;
pub const CKU_CONTEXT_SPECIFIC: u32 = 2;

// ── Mechanism Discovery ──────────────────────────────────────────────────────

pub const SUPPORTED_MECHS: &[u32] = &[
    // RSA
    CKM_RSA_PKCS_KEY_PAIR_GEN,
    CKM_RSA_PKCS_OAEP,
    CKM_SHA256_RSA_PKCS,
    CKM_SHA384_RSA_PKCS,
    CKM_SHA512_RSA_PKCS,
    CKM_SHA256_RSA_PKCS_PSS,
    CKM_SHA384_RSA_PKCS_PSS,
    CKM_SHA512_RSA_PKCS_PSS,
    CKM_RSA_PKCS,
    // CKM_RSA_X_509 — added 2026-07-25, advertised for sign-recover/
    // verify-recover ONLY (see its CKF_* flags in ffi.rs's mechanism_info).
    // Not CKF_SIGN/CKF_VERIFY/CKF_ENCRYPT/CKF_DECRYPT — those aren't
    // implemented for this mechanism, so they're deliberately not claimed.
    CKM_RSA_X_509,
    CKM_RSA_PKCS_PSS,
    CKM_SHA3_384_RSA_PKCS,
    CKM_SHA3_384_RSA_PKCS_PSS,
    // ML-KEM (FIPS 203)
    CKM_ML_KEM_KEY_PAIR_GEN,
    CKM_ML_KEM,
    // FrodoKEM / Classic McEliece (BSI TR-02102-1 — vendor mechanisms, see
    // pqctoday-priv/docs/platform/data/pkcs11-vendor-mech-allocation.md §1.4)
    CKM_PQCTODAY_FRODOKEM_KEY_PAIR_GEN,
    CKM_PQCTODAY_FRODOKEM_ENCAPSULATE,
    CKM_PQCTODAY_CLASSIC_MCELIECE_KEY_PAIR_GEN,
    CKM_PQCTODAY_CLASSIC_MCELIECE_ENCAPSULATE,
    // ML-DSA (FIPS 204) — pure + pre-hash.
    // GENERIC CKM_HASH_ML_DSA (0x1F) selects the pre-hash digest via
    // CK_HASH_SIGN_ADDITIONAL_CONTEXT.hash (ffi::remap_generic_hash_mech
    // parses it and remaps onto the matching hash-SPECIFIC mechanism below,
    // same pattern as the CKM_EDDSA -> CKM_EDDSA_PH phFlag remap).
    CKM_ML_DSA_KEY_PAIR_GEN,
    CKM_ML_DSA,
    CKM_HASH_ML_DSA,
    CKM_HASH_ML_DSA_SHA224,
    CKM_HASH_ML_DSA_SHA256,
    CKM_HASH_ML_DSA_SHA384,
    CKM_HASH_ML_DSA_SHA512,
    CKM_HASH_ML_DSA_SHA3_224,
    CKM_HASH_ML_DSA_SHA3_256,
    CKM_HASH_ML_DSA_SHA3_384,
    CKM_HASH_ML_DSA_SHA3_512,
    CKM_HASH_ML_DSA_SHAKE128,
    CKM_HASH_ML_DSA_SHAKE256,
    // ML-DSA external-µ (remediation R34) — PQCTODAY-VENDOR-EXT-MU.
    CKM_PQCTODAY_ML_DSA_MU,
    // ML-DSA external-µ GENERATION (remediation R39, phase 8) — the
    // produce half; a digest-family mechanism, not sign/verify.
    CKM_PQCTODAY_ML_DSA_MU_GEN,
    // SLH-DSA (FIPS 205) — pure + pre-hash.
    // Generic CKM_HASH_SLH_DSA (0x34) — same remap as CKM_HASH_ML_DSA above.
    CKM_SLH_DSA_KEY_PAIR_GEN,
    CKM_SLH_DSA,
    CKM_HASH_SLH_DSA,
    CKM_HASH_SLH_DSA_SHA224,
    CKM_HASH_SLH_DSA_SHA256,
    CKM_HASH_SLH_DSA_SHA384,
    CKM_HASH_SLH_DSA_SHA512,
    CKM_HASH_SLH_DSA_SHA3_224,
    CKM_HASH_SLH_DSA_SHA3_256,
    CKM_HASH_SLH_DSA_SHA3_384,
    CKM_HASH_SLH_DSA_SHA3_512,
    CKM_HASH_SLH_DSA_SHAKE128,
    CKM_HASH_SLH_DSA_SHAKE256,
    // Digests
    CKM_SHA256,
    CKM_SHA384,
    CKM_SHA512,
    CKM_SHA3_256,
    CKM_SHA3_512,
    CKM_RIPEMD160,
    // HMAC
    CKM_SHA256_HMAC,
    CKM_SHA384_HMAC,
    CKM_SHA512_HMAC,
    CKM_SHA3_256_HMAC,
    CKM_SHA3_512_HMAC,
    CKM_RIPEMD160_HMAC,
    CKM_SHA256_HMAC_GENERAL,
    CKM_SHA384_HMAC_GENERAL,
    CKM_SHA512_HMAC_GENERAL,
    CKM_SHA3_256_HMAC_GENERAL,
    CKM_SHA3_512_HMAC_GENERAL,
    // KMAC
    CKM_KMAC_128,
    CKM_KMAC_256,
    // Secret key generation
    CKM_GENERIC_SECRET_KEY_GEN,
    // EC / ECDSA / EdDSA
    CKM_EC_KEY_PAIR_GEN,
    CKM_ECDSA,
    CKM_ECDSA_SHA256,
    CKM_ECDSA_SHA384,
    CKM_ECDSA_SHA512,
    CKM_ECDSA_SHA3_224,
    CKM_ECDSA_SHA3_256,
    CKM_ECDSA_SHA3_384,
    CKM_ECDSA_SHA3_512,
    CKM_ECDH1_DERIVE,
    CKM_ECDH1_COFACTOR_DERIVE,
    CKM_EC_EDWARDS_KEY_PAIR_GEN,
    CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
    CKM_EC_MONTGOMERY_KEY_DERIVE,
    CKM_X25519,
    CKM_X448,
    CKM_EDDSA,
    CKM_EDDSA_PH,
    // AES
    CKM_AES_KEY_GEN,
    CKM_AES_ECB,
    CKM_AES_CBC,
    CKM_AES_CBC_PAD,
    CKM_AES_CTR,
    CKM_AES_GCM,
    CKM_AES_KEY_WRAP,
    CKM_AES_KEY_WRAP_KWP,
    CKM_AES_KEY_WRAP_PAD,
    // ChaCha20 stream cipher + ChaCha20-Poly1305 AEAD (S1 — were implemented
    // but not advertised; values verified against pkcs11t.h 0x1226 / 0x4021)
    CKM_CHACHA20,
    CKM_CHACHA20_KEY_GEN,
    CKM_CHACHA20_POLY1305,
    // Key derivation
    CKM_PKCS5_PBKD2,
    CKM_HKDF_DERIVE,
    CKM_HKDF_DATA,
    CKM_SP800_108_COUNTER_KDF,
    CKM_SP800_108_FEEDBACK_KDF,
    // Hybrid-KEM combiner building blocks — concatenate (key/data) + digest
    // key-derivation, all standard PKCS#11 v3.2 derive mechanisms composed
    // in-HSM (v3.2 has no dedicated hybrid-KEM mechanism). §6.43 / §6.22 / §6.29.
    CKM_CONCATENATE_BASE_AND_KEY,
    CKM_CONCATENATE_BASE_AND_DATA,
    CKM_SHA256_KEY_DERIVATION,
    CKM_SHA384_KEY_DERIVATION,
    CKM_SHA512_KEY_DERIVATION,
    CKM_SHA3_256_KEY_DERIVATION,
    CKM_SHA3_384_KEY_DERIVATION,
    CKM_SHA3_512_KEY_DERIVATION,
    // BIP32 HD derivation (C_DeriveKey master/child — pkcs11t.h 0x105B/0x105C)
    CKM_BIP32_MASTER_DERIVE,
    CKM_BIP32_CHILD_DERIVE,
    // Stateful hash-based signatures (G10)
    CKM_HSS_KEY_PAIR_GEN,
    CKM_HSS,
    CKM_XMSS_KEY_PAIR_GEN,
    CKM_XMSS,
    CKM_XMSSMT_KEY_PAIR_GEN,
    CKM_XMSSMT,
    // Keccak-256 digest (G11 — Rust engine only)
    CKM_KECCAK_256,
];

/// PKCS#11 v3.2 §5.5 — C_GetMechanismList. Gated on library initialization
/// (§5.4), validates the slot (CKR_SLOT_ID_INVALID, mirroring
/// C_GetTokenInfo) and the required `pulCount` out-param
/// (CKR_ARGUMENTS_BAD). NULL `pMechanismList` is the §5.2 size query.
#[wasm_bindgen(js_name = _C_GetMechanismList)]
pub fn C_GetMechanismList(slot_id: u32, p_mechanism_list: *mut u32, pul_count: *mut u32) -> u32 {
    // §5.4 init gate — the `require_init!` macro is textually scoped to
    // ffi.rs (declared after this module in lib.rs), so the check is
    // replicated here.
    if !crate::state::is_initialized() {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if pul_count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let valid_slot = crate::state::TOKEN_STORE.with(|ts| ts.borrow().contains_key(&slot_id));
    if !valid_slot {
        return CKR_SLOT_ID_INVALID;
    }
    unsafe {
        if p_mechanism_list.is_null() {
            *pul_count = SUPPORTED_MECHS.len() as u32;
        } else {
            let avail = *pul_count as usize;
            if avail < SUPPORTED_MECHS.len() {
                *pul_count = SUPPORTED_MECHS.len() as u32;
                return CKR_BUFFER_TOO_SMALL;
            }
            for (i, m) in SUPPORTED_MECHS.iter().enumerate() {
                *p_mechanism_list.add(i) = *m;
            }
            *pul_count = SUPPORTED_MECHS.len() as u32;
        }
    }
    CKR_OK
}

// C_*Update/C_*Final multi-part Sign/Verify/Encrypt/Decrypt/Digest flows are
// all genuinely implemented in ffi.rs (real per-session accumulator state,
// e.g. SIGN_MULTIPART_ACC), not stubbed. CKR_FUNCTION_NOT_SUPPORTED below
// remains the spec-legal answer for the handful of PKCS#11 v3.2 functions a
// compliant library may decline outright (§11.17) — it is not a marker for
// "multi-part isn't implemented."

pub const CKR_FUNCTION_NOT_SUPPORTED: u32 = 0x0000_0054;
pub const CKR_FUNCTION_NOT_PARALLEL: u32 = 0x0000_0051;
pub const CKR_NO_EVENT: u32 = 0x0000_0008;
/// C_WaitForSlotEvent non-blocking flag (pkcs11t.h).
pub const CKF_DONT_BLOCK: u32 = 0x0000_0001;
pub const CKR_KEY_EXHAUSTED: u32 = 0x0000_0203; // PKCS#11 v3.2 — stateful key has no remaining signatures

// ── Stateful Signature Mechanisms (G10) ─────────────────────────────────────

// HSS/LMS standard mechanisms (PKCS#11 v3.2 §6.14)
pub const CKM_HSS_KEY_PAIR_GEN: u32 = 0x0000_4032;
pub const CKM_HSS: u32 = 0x0000_4033;
// XMSS / XMSS-MT (PKCS#11 v3.2 §6.66 / §6.66)
pub const CKM_XMSS_KEY_PAIR_GEN: u32 = 0x0000_4034; // pkcs11t.h §1222
pub const CKM_XMSSMT_KEY_PAIR_GEN: u32 = 0x0000_4035; // pkcs11t.h §1222
pub const CKM_XMSS: u32 = 0x0000_4036; // pkcs11t.h §1225
pub const CKM_XMSSMT: u32 = 0x0000_4037; // pkcs11t.h §1224

// Vendor: Keccak-256 digest (G11 — Ethereum address derivation, Rust engine only)
pub const CKM_KECCAK_256: u32 = 0x8000_0010;

// ── Stateful Key Attributes (vendor, G10) ────────────────────────────────────
// Range: 0x80000102–0x80000107. These are pure PARAMETER-SET labels — inert
// data a client may legitimately set on an imported key. The three STATEFUL
// members that formerly shared this range (CKA_PRIV_STATEFUL_KEY_STATE,
// CKA_PRIV_LEAF_INDEX, CKA_PRIV_XMSS_KEYS_REMAINING) moved to the engine-private
// 0xFFFF_00xx range on 2026-08-13 — see remediation item S4 near
// CKA_PRIV_SLOT_ID. 0x8000_0101 and 0x8000_0105/0106 are now RETIRED and must
// not be reused: a pre-S4 serialised key carries state under those ids, and
// the snapshot format bump exists precisely so such a key fails loudly rather
// than being reinterpreted.
pub const CKA_LMS_PARAM_SET: u32 = 0x8000_0102; // CKP_LMS_SHA256_M32_H* value
pub const CKA_LMOTS_PARAM_SET: u32 = 0x8000_0103; // CKP_LMOTS_SHA256_N32_W* value
pub const CKA_XMSS_PARAM_SET: u32 = 0x8000_0104; // CKP_XMSS_* value
pub const CKA_XMSSMT_PARAM_SET: u32 = 0x8000_0107; // CKP_XMSSMT_* value (RFC 8391 OID)

// Official PKCS#11 v3.2 §6.14 HSS attributes (pkcs11t.h:636-638). Phase 5
// R25: CKA_HSS_LEVELS was previously missing and CKA_HSS_LMS_TYPE was
// misused locally to hold the level count instead of the actual LMS type —
// fixed to match the spec (and the C++ engine's own convention).
pub const CKA_HSS_LEVELS: u32 = 0x0000_0617;
pub const CKA_HSS_LMS_TYPE: u32 = 0x0000_0618;
pub const CKA_HSS_LMOTS_TYPE: u32 = 0x0000_0619;
pub const CKA_HSS_KEYS_REMAINING: u32 = 0x0000_061c;

// ── LMS / LMOTS Parameter Set Constants ─────────────────────────────────────
// Values match PKCS#11 v3.2 §6.14 table (tree-height based naming)
// NOTE: hbs-lms LmsAlgorithm enum uses RFC 8554 type IDs — use ckp_to_lms_algo() in lms.rs

// IANA "Leighton-Micali Signatures" registry (RFC 8554 + SP 800-208)
// https://www.iana.org/assignments/leighton-micali-signatures/
pub const CKP_LMS_SHA256_M32_H5: u32 = 0x05;
pub const CKP_LMS_SHA256_M32_H10: u32 = 0x06;
pub const CKP_LMS_SHA256_M32_H15: u32 = 0x07;
pub const CKP_LMS_SHA256_M32_H20: u32 = 0x08;
pub const CKP_LMS_SHA256_M32_H25: u32 = 0x09;
pub const CKP_LMS_SHA256_M24_H5: u32 = 0x0A;
pub const CKP_LMS_SHA256_M24_H10: u32 = 0x0B;
pub const CKP_LMS_SHA256_M24_H15: u32 = 0x0C;
pub const CKP_LMS_SHA256_M24_H20: u32 = 0x0D;
pub const CKP_LMS_SHA256_M24_H25: u32 = 0x0E;
pub const CKP_LMS_SHAKE_M32_H5: u32 = 0x0F;
pub const CKP_LMS_SHAKE_M32_H10: u32 = 0x10;
pub const CKP_LMS_SHAKE_M32_H15: u32 = 0x11;
pub const CKP_LMS_SHAKE_M32_H20: u32 = 0x12;
pub const CKP_LMS_SHAKE_M32_H25: u32 = 0x13;
pub const CKP_LMS_SHAKE_M24_H5: u32 = 0x14;
pub const CKP_LMS_SHAKE_M24_H10: u32 = 0x15;
pub const CKP_LMS_SHAKE_M24_H15: u32 = 0x16;
pub const CKP_LMS_SHAKE_M24_H20: u32 = 0x17;
pub const CKP_LMS_SHAKE_M24_H25: u32 = 0x18;

// IANA "LM-OTS Signatures" registry (RFC 8554 + SP 800-208)
pub const CKP_LMOTS_SHA256_N32_W1: u32 = 0x01;
pub const CKP_LMOTS_SHA256_N32_W2: u32 = 0x02;
pub const CKP_LMOTS_SHA256_N32_W4: u32 = 0x03;
pub const CKP_LMOTS_SHA256_N32_W8: u32 = 0x04;
pub const CKP_LMOTS_SHA256_N24_W1: u32 = 0x05;
pub const CKP_LMOTS_SHA256_N24_W2: u32 = 0x06;
pub const CKP_LMOTS_SHA256_N24_W4: u32 = 0x07;
pub const CKP_LMOTS_SHA256_N24_W8: u32 = 0x08;
pub const CKP_LMOTS_SHAKE_N32_W1: u32 = 0x09;
pub const CKP_LMOTS_SHAKE_N32_W2: u32 = 0x0A;
pub const CKP_LMOTS_SHAKE_N32_W4: u32 = 0x0B;
pub const CKP_LMOTS_SHAKE_N32_W8: u32 = 0x0C;
pub const CKP_LMOTS_SHAKE_N24_W1: u32 = 0x0D;
pub const CKP_LMOTS_SHAKE_N24_W2: u32 = 0x0E;
pub const CKP_LMOTS_SHAKE_N24_W4: u32 = 0x0F;
pub const CKP_LMOTS_SHAKE_N24_W8: u32 = 0x10;

// ── XMSS Parameter Set Constants ─────────────────────────────────────────────

// Values are the RFC 8391 §8 / NIST SP 800-208 §5.3 (IANA "XMSS Signatures")
// numeric identifiers — the same numbering the C++ engine's
// xmss-reference params.c uses. N1 remediation 2026-08-13: the SHAKE
// (SHAKE128-based) sets moved from the engine's historical 0x11-0x13 to
// their standard 0x07-0x09 ids; 0x11-0x13 now denote the SHAKE256-based
// sets they stand for in the registry (previously those ids silently ran
// SHAKE128 — a numbering collision with the standard).
pub const CKP_XMSS_SHA2_10_256: u32 = 0x01;
pub const CKP_XMSS_SHA2_16_256: u32 = 0x02;
pub const CKP_XMSS_SHA2_20_256: u32 = 0x03;
pub const CKP_XMSS_SHAKE_10_256: u32 = 0x07; // XMSS-SHAKE_10_256 (SHAKE128)
pub const CKP_XMSS_SHAKE_16_256: u32 = 0x08; // XMSS-SHAKE_16_256 (SHAKE128)
pub const CKP_XMSS_SHAKE_20_256: u32 = 0x09; // XMSS-SHAKE_20_256 (SHAKE128)
pub const CKP_XMSS_SHAKE256_16_256: u32 = 0x11; // XMSS-SHAKE256_16_256
pub const CKP_XMSS_SHAKE256_20_256: u32 = 0x12; // XMSS-SHAKE256_20_256
pub const CKP_XMSS_SHAKE256_10_192: u32 = 0x13; // XMSS-SHAKE256_10_192

// ── XMSS-MT Parameter Set Constants (RFC 8391 OIDs, matching C++ xmssmt_parse_oid) ──────────────
// SHA2 / 256-bit (most common; selected subset for PKCS#11 v3.2 §6.66.6)
pub const CKP_XMSSMT_SHA2_20_2_256: u32 = 0x01; // XMSSMT-SHA2_20/2_256
pub const CKP_XMSSMT_SHA2_20_4_256: u32 = 0x02; // XMSSMT-SHA2_20/4_256
pub const CKP_XMSSMT_SHA2_40_2_256: u32 = 0x03; // XMSSMT-SHA2_40/2_256
pub const CKP_XMSSMT_SHA2_40_4_256: u32 = 0x04; // XMSSMT-SHA2_40/4_256
pub const CKP_XMSSMT_SHA2_40_8_256: u32 = 0x05; // XMSSMT-SHA2_40/8_256
pub const CKP_XMSSMT_SHA2_60_3_256: u32 = 0x06; // XMSSMT-SHA2_60/3_256
pub const CKP_XMSSMT_SHA2_60_6_256: u32 = 0x07; // XMSSMT-SHA2_60/6_256
pub const CKP_XMSSMT_SHA2_60_12_256: u32 = 0x08; // XMSSMT-SHA2_60/12_256
// SHA2 / 512-bit
pub const CKP_XMSSMT_SHA2_20_2_512: u32 = 0x09;
pub const CKP_XMSSMT_SHA2_20_4_512: u32 = 0x0a;
pub const CKP_XMSSMT_SHA2_40_2_512: u32 = 0x0b;
pub const CKP_XMSSMT_SHA2_40_4_512: u32 = 0x0c;
pub const CKP_XMSSMT_SHA2_40_8_512: u32 = 0x0d;
pub const CKP_XMSSMT_SHA2_60_3_512: u32 = 0x0e;
pub const CKP_XMSSMT_SHA2_60_6_512: u32 = 0x0f;
pub const CKP_XMSSMT_SHA2_60_12_512: u32 = 0x10;
// SHAKE-128 / 256-bit
pub const CKP_XMSSMT_SHAKE_20_2_256: u32 = 0x11;
pub const CKP_XMSSMT_SHAKE_20_4_256: u32 = 0x12;
pub const CKP_XMSSMT_SHAKE_40_2_256: u32 = 0x13;
pub const CKP_XMSSMT_SHAKE_40_4_256: u32 = 0x14;
pub const CKP_XMSSMT_SHAKE_40_8_256: u32 = 0x15;
pub const CKP_XMSSMT_SHAKE_60_3_256: u32 = 0x16;
pub const CKP_XMSSMT_SHAKE_60_6_256: u32 = 0x17;
pub const CKP_XMSSMT_SHAKE_60_12_256: u32 = 0x18;
// SHAKE-128 / 512-bit
pub const CKP_XMSSMT_SHAKE_20_2_512: u32 = 0x19;
pub const CKP_XMSSMT_SHAKE_20_4_512: u32 = 0x1a;
pub const CKP_XMSSMT_SHAKE_40_2_512: u32 = 0x1b;
pub const CKP_XMSSMT_SHAKE_40_4_512: u32 = 0x1c;
pub const CKP_XMSSMT_SHAKE_40_8_512: u32 = 0x1d;
pub const CKP_XMSSMT_SHAKE_60_3_512: u32 = 0x1e;
pub const CKP_XMSSMT_SHAKE_60_6_512: u32 = 0x1f;
pub const CKP_XMSSMT_SHAKE_60_12_512: u32 = 0x20;
