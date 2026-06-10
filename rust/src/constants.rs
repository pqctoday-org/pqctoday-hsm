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

// ── PKCS#11 Attribute Types ──────────────────────────────────────────────────

pub const CKA_VALUE: u32 = 0x0000_0011;
pub const CKA_KEY_TYPE: u32 = 0x0000_0100;
pub const CKA_MODULUS: u32 = 0x0000_0120; // PKCS#11 v3.2 §2.1.2 — RSA modulus (big-endian)
pub const CKA_MODULUS_BITS: u32 = 0x0000_0121;
pub const CKA_PUBLIC_EXPONENT: u32 = 0x0000_0122; // PKCS#11 v3.2 §2.1.2 — RSA public exponent
pub const CKA_VALUE_LEN: u32 = 0x0000_0161;
pub const CKA_EC_PARAMS: u32 = 0x0000_0180;
pub const CKA_EC_POINT: u32 = 0x0000_0181;
pub const CKA_BIP32_CHAIN_CODE: u32 = 0x0000_1021;
pub const CKA_BIP32_CHILD_INDEX: u32 = 0x0000_1022;
pub const CKA_PUBLIC_KEY_INFO: u32 = 0x0000_0129; // PKCS#11 v3.2 — DER SubjectPublicKeyInfo
pub const CKA_PARAMETER_SET: u32 = 0x0000_061d;
// PKCS#11 v3.2 — deterministic keygen seed (ξ for ML-DSA, d‖z for ML-KEM).
// NOTE: deterministic seeded keygen is not yet wired; see gap analysis R3.6.
pub const CKA_SEED: u32 = 0x0000_0637;

// ── PKCS#11 Object Classes ────────────────────────────────────────────────────

pub const CKO_PUBLIC_KEY: u32 = 0x0000_0002;
pub const CKO_PRIVATE_KEY: u32 = 0x0000_0003;
pub const CKO_SECRET_KEY: u32 = 0x0000_0004;

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

// ── PKCS#11 Semantic Attribute Types ─────────────────────────────────────────

pub const CKA_CLASS: u32 = 0x0000_0000;
pub const CKA_TOKEN: u32 = 0x0000_0001;
pub const CKA_PRIVATE: u32 = 0x0000_0002;
// PKCS#11 v3.2 §4.4.1 — token-generated unique object identifier (read-only,
// assigned by the engine at object creation; see state::allocate_handle).
pub const CKA_UNIQUE_ID: u32 = 0x0000_0017;
pub const CKA_SENSITIVE: u32 = 0x0000_0103;
pub const CKA_ENCRYPT: u32 = 0x0000_0104;
pub const CKA_DECRYPT: u32 = 0x0000_0105;
pub const CKA_WRAP: u32 = 0x0000_0106;
pub const CKA_UNWRAP: u32 = 0x0000_0107;
pub const CKA_SIGN: u32 = 0x0000_0108;
pub const CKA_VERIFY: u32 = 0x0000_010a;
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

// Private attribute: stores the parameter set on generated keys
pub const CKA_PRIV_PARAM_SET: u32 = 0xFFFF_0001;
// Private attribute: stores the algorithm family for polymorphic dispatch
pub const CKA_PRIV_ALGO_FAMILY: u32 = 0xFFFF_0002;
// Private attribute: handle of the session that created the object (u32 LE).
// 0 / absent = library scope (native/KMIP-registered objects). Session objects
// (CKA_TOKEN=FALSE) owned by a session are destroyed when it closes (§4.4).
pub const CKA_PRIV_OWNER_SESSION: u32 = 0xFFFF_0003;

// ── PKCS#11 Mechanism Types ──────────────────────────────────────────────────

// RSA
pub const CKM_RSA_PKCS_KEY_PAIR_GEN: u32 = 0x0000_0000;
pub const CKM_RSA_PKCS_OAEP: u32 = 0x0000_0009;
pub const CKM_SHA256_RSA_PKCS: u32 = 0x0000_0040;
pub const CKM_SHA256_RSA_PKCS_PSS: u32 = 0x0000_0043;

// PQC - KEM
pub const CKM_ML_KEM_KEY_PAIR_GEN: u32 = 0x0000_000F;
pub const CKM_ML_KEM: u32 = 0x0000_0017;

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
pub const CKM_SHA384: u32 = 0x0000_0260;
pub const CKM_SHA512: u32 = 0x0000_0270;
pub const CKM_SHA3_256: u32 = 0x0000_02B0;
pub const CKM_SHA3_512: u32 = 0x0000_02D0;

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
// OAEP source type
pub const CKZ_DATA_SPECIFIED: u32 = 0x0000_0001;
// SP 800-108 data-param types (beyond BYTE_ARRAY below)
pub const CK_SP800_108_ITERATION_VARIABLE: u32 = 0x0000_0001;
pub const CK_SP800_108_DKM_LENGTH: u32 = 0x0000_0003;
pub const CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS: u32 = 0x0000_0001;

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
pub const CKM_BIP32_MASTER_DERIVE: u32 = 0x0000_105B;
pub const CKM_BIP32_CHILD_DERIVE: u32 = 0x0000_105C;
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
/// `CKM_CHACHA20_POLY1305` — IETF ChaCha20-Poly1305 AEAD (RFC 8439).
/// 32-byte key, 12-byte nonce, 16-byte tag.
pub const CKM_CHACHA20_POLY1305: u32 = 0x0000_4021;

// ── PKCS#11 Parameter Sets ──────────────────────────────────────────────────

pub const CKP_ML_KEM_512: u32 = 0x1;
pub const CKP_ML_KEM_768: u32 = 0x2;
pub const CKP_ML_KEM_1024: u32 = 0x3;

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
pub const CKR_SESSION_HANDLE_INVALID: u32 = 0x0000_00B3;
pub const CKR_SESSION_EXISTS: u32 = 0x0000_00B6;
pub const CKR_SESSION_READ_ONLY: u32 = 0x0000_00B5;
pub const CKR_SESSION_READ_ONLY_EXISTS: u32 = 0x0000_00B7;
pub const CKR_SESSION_READ_WRITE_SO_EXISTS: u32 = 0x0000_00B8;
pub const CKR_USER_TYPE_INVALID: u32 = 0x0000_0103;
pub const CKR_USER_ANOTHER_ALREADY_LOGGED_IN: u32 = 0x0000_0104;
pub const CKR_USER_TOO_MANY_TYPES: u32 = 0x0000_0105;
pub const CKR_USER_NOT_LOGGED_IN: u32 = 0x0000_0101;
pub const CKR_USER_ALREADY_LOGGED_IN: u32 = 0x0000_0100;
pub const CKR_USER_PIN_NOT_INITIALIZED: u32 = 0x0000_0102;
pub const CKR_PIN_INCORRECT: u32 = 0x0000_00A0;
pub const CKR_PIN_INVALID: u32 = 0x0000_00A1;
pub const CKR_PIN_LEN_RANGE: u32 = 0x0000_00A2;
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
    CKM_SHA256_RSA_PKCS_PSS,
    // ML-KEM (FIPS 203)
    CKM_ML_KEM_KEY_PAIR_GEN,
    CKM_ML_KEM,
    // ML-DSA (FIPS 204) — pure + pre-hash
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
    // SLH-DSA (FIPS 205) — pure + pre-hash
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
    // HMAC
    CKM_SHA256_HMAC,
    CKM_SHA384_HMAC,
    CKM_SHA512_HMAC,
    CKM_SHA3_256_HMAC,
    CKM_SHA3_512_HMAC,
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
    CKM_CHACHA20_POLY1305,
    // Key derivation
    CKM_PKCS5_PBKD2,
    CKM_HKDF_DERIVE,
    CKM_SP800_108_COUNTER_KDF,
    CKM_SP800_108_FEEDBACK_KDF,
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

// ── Multi-part operation stubs (PKCS#11 v3.2 compliance) ────────────────────
// These return CKR_FUNCTION_NOT_SUPPORTED as the Rust engine only supports
// single-shot operations. DigestUpdate/DigestFinal are fully implemented above.

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
// Range: 0x80000101–0x80000106 (offset from CKM vendor range to avoid confusion)

pub const CKA_STATEFUL_KEY_STATE: u32 = 0x8000_0101; // raw serialised private key blob
pub const CKA_LMS_PARAM_SET: u32 = 0x8000_0102; // CKP_LMS_SHA256_M32_H* value
pub const CKA_LMOTS_PARAM_SET: u32 = 0x8000_0103; // CKP_LMOTS_SHA256_N32_W* value
pub const CKA_XMSS_PARAM_SET: u32 = 0x8000_0104; // CKP_XMSS_* value
pub const CKA_LEAF_INDEX: u32 = 0x8000_0105; // current leaf index (u64, little-endian)
pub const CKA_XMSS_KEYS_REMAINING: u32 = 0x8000_0106; // remaining XMSS signature operations (u32, LE)
pub const CKA_XMSSMT_PARAM_SET: u32 = 0x8000_0107; // CKP_XMSSMT_* value (RFC 8391 OID)

// Standard multi-level HSS level-type attribute (PKCS#11 v3.2 §6.14)
pub const CKA_HSS_LMS_TYPE: u32 = 0x0000_0618;
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

pub const CKP_XMSS_SHA2_10_256: u32 = 0x01;
pub const CKP_XMSS_SHA2_16_256: u32 = 0x02;
pub const CKP_XMSS_SHA2_20_256: u32 = 0x03;
pub const CKP_XMSS_SHAKE_10_256: u32 = 0x11;
pub const CKP_XMSS_SHAKE_16_256: u32 = 0x12;
pub const CKP_XMSS_SHAKE_20_256: u32 = 0x13;

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
