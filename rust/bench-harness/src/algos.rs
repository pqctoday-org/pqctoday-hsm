//! Algorithm definitions: which mechanism generates the key pair, which
//! mechanism signs/verifies/derives/encapsulates with it, and (per the
//! engine's own dispatch in `rust/src/ffi.rs` — verified against source
//! before writing each of these, never guessed) which template
//! attributes are actually required. Every mechanism value here is a
//! real, OASIS-assigned PKCS#11 v3.2 codepoint (cross-checked against
//! `rust/src/constants.rs`, which itself is checked against the spec's
//! `pkcs11t.h` per this repo's CLAUDE.md) — no vendor extensions.
//!
//! Two categories from plan §A5 are deliberately NOT here, both verified
//! against source before excluding (not assumed):
//! - **Composite/hybrid signatures** (e.g. ECDSA P-256 + ML-DSA-44): no
//!   single PKCS#11 mechanism exists for these in this engine — a caller
//!   genuinely issues two separate real sign operations. §A5 itself calls
//!   these "modeled, not native"; a harness-level composite measurement is
//!   a distinct, separately-scoped increment, not added here.
//! - **Hybrid/native KEMs** (X25519MLKEM768 etc.): `rust/src/native/hybrid.rs`
//!   confirms these exist ONLY through the KMIP server's own tenant/handle
//!   bookkeeping (`kmip/src/hybrid_kem.rs` and friends) — no
//!   `C_GenerateKeyPair`/`C_EncapsulateKey` dispatch arm reaches them.
//!   Unreachable from a pkcs11-direct harness; deferred to kmip mode (§P2).

use softhsmrustv3::constants::{
    CKM_EC_EDWARDS_KEY_PAIR_GEN, CKM_EC_KEY_PAIR_GEN, CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
    CKM_ECDSA_SHA256, CKM_ECDSA_SHA384, CKM_ECDSA_SHA512, CKM_EDDSA, CKM_ML_DSA,
    CKM_ML_DSA_KEY_PAIR_GEN, CKM_ML_KEM, CKM_ML_KEM_KEY_PAIR_GEN,
    CKM_AES_CBC, CKM_AES_GCM,
    CKM_RSA_PKCS_KEY_PAIR_GEN, CKM_RSA_PKCS_OAEP, CKM_SHA256, CKM_SHA384, CKM_SHA3_256,
    CKM_SHA3_512, CKM_SHA512, CKM_SHA256_RSA_PKCS_PSS, CKM_SHA384_RSA_PKCS_PSS,
    CKM_SHA512_RSA_PKCS_PSS, CKM_SLH_DSA,
    CKM_SLH_DSA_KEY_PAIR_GEN, CKP_ML_DSA_44, CKP_ML_DSA_65, CKP_ML_DSA_87, CKP_ML_KEM_1024,
    CKP_ML_KEM_512, CKP_ML_KEM_768,
    CKP_SLH_DSA_SHA2_128F, CKP_SLH_DSA_SHA2_128S, CKP_SLH_DSA_SHA2_192F, CKP_SLH_DSA_SHA2_192S,
    CKP_SLH_DSA_SHA2_256F, CKP_SLH_DSA_SHA2_256S,
    CKP_SLH_DSA_SHAKE_128F, CKP_SLH_DSA_SHAKE_128S, CKP_SLH_DSA_SHAKE_192F, CKP_SLH_DSA_SHAKE_192S,
    CKP_SLH_DSA_SHAKE_256F, CKP_SLH_DSA_SHAKE_256S,
};

/// How a keygen call's public-key template must be built for a given
/// algorithm. `None` — no attribute needed. `EcParamsOid` — CKA_EC_PARAMS
/// must carry this exact DER OID: for the Weierstrass curves, absent
/// defaults to P-256 (verified against `ffi.rs`'s curve-selection branch);
/// for the Edwards/Montgomery curves (Ed25519, X25519) the attribute is
/// REQUIRED — absent → `CKR_TEMPLATE_INCOMPLETE` — since the engine's
/// 2026-08-13 "W2" correctness fix (`ffi.rs` commit da449bc) made it read
/// `CKA_EC_PARAMS` instead of hardcoding Ed25519 (PKCS#11 v3.2 §6.3.10
/// requires this; a stale pre-08-13 build of this engine is the only way
/// `KeygenParam::None` ever worked for these two — found 2026-08-24
/// bisecting a keygen failure that reproduced only against a freshly-built
/// engine, never against an older cached one). `ParameterSet`
/// — CKA_PARAMETER_SET is REQUIRED (ML-DSA/ML-KEM/SLH-DSA; absent →
/// CKR_TEMPLATE_INCOMPLETE), and per `get_attr_ulong`'s implementation
/// (`crypto/handlers.rs`) the value must be readable as a plain 4-byte
/// `u32` regardless of this platform's 8-byte native `CK_ULONG` width —
/// `pkcs11::Engine::generate_key_pair_with_param` builds exactly that.
#[derive(Clone, Copy, Debug)]
pub enum KeygenParam {
    None,
    EcParamsOid(&'static [u8]),
    ParameterSet(u32),
    /// `CKA_MODULUS_BITS` (RSA keygen only) — read via the SAME
    /// `get_attr_ulong` convention as `ParameterSet` (confirmed against
    /// `ffi.rs`'s `CKM_RSA_PKCS_KEY_PAIR_GEN` dispatch before adding this:
    /// plain 4-byte `u32`, not native `CK_ULONG` width). No
    /// `CKA_PUBLIC_EXPONENT` needed — the engine generates and stores that
    /// itself.
    RsaModulusBits(u32),
}

/// DER OID bytes for the three NIST Weierstrass curves this harness uses,
/// byte-for-byte identical to what the engine's own SPKI builders emit
/// (`crypto/handlers.rs` — cited per-curve below), so `CKA_EC_PARAMS`
/// round-trips through exactly the bytes the engine already recognizes.
pub const P256_OID: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
pub const P384_OID: &[u8] = &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22];
pub const P521_OID: &[u8] = &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23];
/// 1.3.132.0.10 — secp256k1. NOT a NIST/FIPS curve: it is here because it is
/// what Bitcoin, Ethereum and most of the wider blockchain estate actually
/// sign with, so "what does migrating THAT cost" is a real question this
/// benchmark should be able to answer next to the P-curves.
///
/// Byte-identical to what the engine emits into `CKA_EC_PARAMS` for this curve
/// (`ffi.rs` stores `06 05 2b 81 04 00 0a` for `CURVE_K256`) and to what
/// `crypto/handlers.rs::decode_ec_params` accepts as INPUT — so EC_PARAMS
/// round-trips through exactly the bytes the engine already recognises,
/// the same property the P-curve OIDs above rely on.
pub const SECP256K1_OID: &[u8] = &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A];
/// id-Ed25519 (RFC 8032 / 1.3.101.112) — byte-identical to the OID
/// `ffi.rs`'s Edwards keygen arm itself emits into the public key's
/// `CKA_EC_PARAMS` (and, since the 2026-08-13 fix, requires as INPUT too).
pub const ED25519_OID: &[u8] = &[0x06, 0x03, 0x2B, 0x65, 0x70];
/// id-X25519 (RFC 8032 / 1.3.101.110) — same relationship to `ffi.rs`'s
/// Montgomery keygen arm as `ED25519_OID` above.
pub const X25519_OID: &[u8] = &[0x06, 0x03, 0x2B, 0x65, 0x6E];

/// One benchmarked signature algorithm.
#[derive(Clone, Copy, Debug)]
pub struct SignatureAlgo {
    pub name: &'static str,
    pub security_level: &'static str,
    pub keygen_mechanism: u32,
    pub keygen_param: KeygenParam,
    pub sign_mechanism: u32,
    /// Excluded unless `--include-slow` is passed (plan §A6 toggle).
    pub slow: bool,
}

pub const ED25519: SignatureAlgo = SignatureAlgo {
    name: "Ed25519", security_level: "L1",
    keygen_mechanism: CKM_EC_EDWARDS_KEY_PAIR_GEN, keygen_param: KeygenParam::EcParamsOid(ED25519_OID),
    sign_mechanism: CKM_EDDSA, slow: false,
};

/// ECDSA hash-then-sign, paired with each curve's natural digest (§6.3.12
/// hash-composite mechanisms — genuinely implemented, confirmed against
/// `ffi.rs`'s `handlers.rs` dispatch, not the raw pre-hashed `CKM_ECDSA`):
/// real sign-a-message semantics, matching every other algorithm here,
/// rather than "sign this already-hashed digest."
pub const ECDSA_P256: SignatureAlgo = SignatureAlgo {
    name: "ECDSA-P256", security_level: "L1",
    keygen_mechanism: CKM_EC_KEY_PAIR_GEN, keygen_param: KeygenParam::EcParamsOid(P256_OID),
    sign_mechanism: CKM_ECDSA_SHA256, slow: false,
};
/// secp256k1 ECDSA. Same 128-bit security class and the same
/// `CKM_ECDSA_SHA256` mechanism as P-256 — deliberately, so the pair is a
/// like-for-like read on the cost of the curve itself rather than of the hash.
pub const ECDSA_K256: SignatureAlgo = SignatureAlgo {
    name: "ECDSA-K256", security_level: "L1",
    keygen_mechanism: CKM_EC_KEY_PAIR_GEN, keygen_param: KeygenParam::EcParamsOid(SECP256K1_OID),
    sign_mechanism: CKM_ECDSA_SHA256, slow: false,
};
pub const ECDSA_P384: SignatureAlgo = SignatureAlgo {
    name: "ECDSA-P384", security_level: "L3",
    keygen_mechanism: CKM_EC_KEY_PAIR_GEN, keygen_param: KeygenParam::EcParamsOid(P384_OID),
    sign_mechanism: CKM_ECDSA_SHA384, slow: false,
};
pub const ECDSA_P521: SignatureAlgo = SignatureAlgo {
    name: "ECDSA-P521", security_level: "L5",
    keygen_mechanism: CKM_EC_KEY_PAIR_GEN, keygen_param: KeygenParam::EcParamsOid(P521_OID),
    sign_mechanism: CKM_ECDSA_SHA512, slow: false,
};

pub const ML_DSA_44: SignatureAlgo = SignatureAlgo {
    name: "ML-DSA-44", security_level: "L1",
    keygen_mechanism: CKM_ML_DSA_KEY_PAIR_GEN, keygen_param: KeygenParam::ParameterSet(CKP_ML_DSA_44),
    sign_mechanism: CKM_ML_DSA, slow: false,
};
pub const ML_DSA_65: SignatureAlgo = SignatureAlgo {
    name: "ML-DSA-65", security_level: "L3",
    keygen_mechanism: CKM_ML_DSA_KEY_PAIR_GEN, keygen_param: KeygenParam::ParameterSet(CKP_ML_DSA_65),
    sign_mechanism: CKM_ML_DSA, slow: false,
};
pub const ML_DSA_87: SignatureAlgo = SignatureAlgo {
    name: "ML-DSA-87", security_level: "L5",
    keygen_mechanism: CKM_ML_DSA_KEY_PAIR_GEN, keygen_param: KeygenParam::ParameterSet(CKP_ML_DSA_87),
    sign_mechanism: CKM_ML_DSA, slow: false,
};

/// Slow (§A6 toggle) — SLH-DSA sign is orders of magnitude more expensive
/// than every other signature algorithm here (a full hypertree + FORS
/// computation per signature, vs. a handful of field/lattice ops).
pub const SLH_DSA_128S: SignatureAlgo = SignatureAlgo {
    name: "SLH-DSA-SHA2-128s", security_level: "L1",
    keygen_mechanism: CKM_SLH_DSA_KEY_PAIR_GEN, keygen_param: KeygenParam::ParameterSet(CKP_SLH_DSA_SHA2_128S),
    sign_mechanism: CKM_SLH_DSA, slow: true,
};
pub const SLH_DSA_256S: SignatureAlgo = SignatureAlgo {
    name: "SLH-DSA-SHA2-256s", security_level: "L5",
    keygen_mechanism: CKM_SLH_DSA_KEY_PAIR_GEN, keygen_param: KeygenParam::ParameterSet(CKP_SLH_DSA_SHA2_256S),
    sign_mechanism: CKM_SLH_DSA, slow: true,
};

/// FIPS 205 completion: the other 10 of the standard's 12 parameter sets
/// ({SHA2,SHAKE} x {128,192,256} x {s,f}) — all 12 have real, non-stub
/// sign/verify/keygen dispatch in the engine (verified against
/// crypto/handlers.rs before adding these, not assumed). "s" (small
/// signature, slow sign) entries are marked `slow: true` to match the
/// existing 128s/256s convention; "f" (fast sign, larger signature) is
/// FIPS 205's own tradeoff specifically FOR faster signing, so those are
/// marked `slow: false` here — confirmed empirically via a timed run
/// (see hsm-perf-bench FIPS-gap plan Part A), not assumed from the name.
pub const SLH_DSA_SHAKE_128S: SignatureAlgo = SignatureAlgo {
    name: "SLH-DSA-SHAKE-128s", security_level: "L1",
    keygen_mechanism: CKM_SLH_DSA_KEY_PAIR_GEN, keygen_param: KeygenParam::ParameterSet(CKP_SLH_DSA_SHAKE_128S),
    sign_mechanism: CKM_SLH_DSA, slow: true,
};
pub const SLH_DSA_SHA2_128F: SignatureAlgo = SignatureAlgo {
    name: "SLH-DSA-SHA2-128f", security_level: "L1",
    keygen_mechanism: CKM_SLH_DSA_KEY_PAIR_GEN, keygen_param: KeygenParam::ParameterSet(CKP_SLH_DSA_SHA2_128F),
    sign_mechanism: CKM_SLH_DSA, slow: false,
};
pub const SLH_DSA_SHAKE_128F: SignatureAlgo = SignatureAlgo {
    name: "SLH-DSA-SHAKE-128f", security_level: "L1",
    keygen_mechanism: CKM_SLH_DSA_KEY_PAIR_GEN, keygen_param: KeygenParam::ParameterSet(CKP_SLH_DSA_SHAKE_128F),
    sign_mechanism: CKM_SLH_DSA, slow: false,
};
pub const SLH_DSA_SHA2_192S: SignatureAlgo = SignatureAlgo {
    name: "SLH-DSA-SHA2-192s", security_level: "L3",
    keygen_mechanism: CKM_SLH_DSA_KEY_PAIR_GEN, keygen_param: KeygenParam::ParameterSet(CKP_SLH_DSA_SHA2_192S),
    sign_mechanism: CKM_SLH_DSA, slow: true,
};
pub const SLH_DSA_SHAKE_192S: SignatureAlgo = SignatureAlgo {
    name: "SLH-DSA-SHAKE-192s", security_level: "L3",
    keygen_mechanism: CKM_SLH_DSA_KEY_PAIR_GEN, keygen_param: KeygenParam::ParameterSet(CKP_SLH_DSA_SHAKE_192S),
    sign_mechanism: CKM_SLH_DSA, slow: true,
};
pub const SLH_DSA_SHA2_192F: SignatureAlgo = SignatureAlgo {
    name: "SLH-DSA-SHA2-192f", security_level: "L3",
    keygen_mechanism: CKM_SLH_DSA_KEY_PAIR_GEN, keygen_param: KeygenParam::ParameterSet(CKP_SLH_DSA_SHA2_192F),
    sign_mechanism: CKM_SLH_DSA, slow: false,
};
pub const SLH_DSA_SHAKE_192F: SignatureAlgo = SignatureAlgo {
    name: "SLH-DSA-SHAKE-192f", security_level: "L3",
    keygen_mechanism: CKM_SLH_DSA_KEY_PAIR_GEN, keygen_param: KeygenParam::ParameterSet(CKP_SLH_DSA_SHAKE_192F),
    sign_mechanism: CKM_SLH_DSA, slow: false,
};
pub const SLH_DSA_SHAKE_256S: SignatureAlgo = SignatureAlgo {
    name: "SLH-DSA-SHAKE-256s", security_level: "L5",
    keygen_mechanism: CKM_SLH_DSA_KEY_PAIR_GEN, keygen_param: KeygenParam::ParameterSet(CKP_SLH_DSA_SHAKE_256S),
    sign_mechanism: CKM_SLH_DSA, slow: true,
};
pub const SLH_DSA_SHA2_256F: SignatureAlgo = SignatureAlgo {
    name: "SLH-DSA-SHA2-256f", security_level: "L5",
    keygen_mechanism: CKM_SLH_DSA_KEY_PAIR_GEN, keygen_param: KeygenParam::ParameterSet(CKP_SLH_DSA_SHA2_256F),
    sign_mechanism: CKM_SLH_DSA, slow: false,
};
pub const SLH_DSA_SHAKE_256F: SignatureAlgo = SignatureAlgo {
    name: "SLH-DSA-SHAKE-256f", security_level: "L5",
    keygen_mechanism: CKM_SLH_DSA_KEY_PAIR_GEN, keygen_param: KeygenParam::ParameterSet(CKP_SLH_DSA_SHAKE_256F),
    sign_mechanism: CKM_SLH_DSA, slow: false,
};

/// RSA-PSS signing — added per the hub's Transition Guide (RSA is the
/// classical algorithm referenced most). The hash-specific PSS mechanisms
/// REQUIRE a `CK_RSA_PKCS_PSS_PARAMS` (v3.2 §6.1.11); `pkcs11.rs::
/// sig_mechanism` supplies it (hashAlg/mgf matching the mechanism's digest,
/// sLen = digest length). This comment used to say the struct was optional
/// because the engine fell back to defaults when it was absent — true until
/// conformance decision E9/D6 (2026-09-25) made the engine enforce the spec,
/// at which point every RSA-PSS provisioning failed with rv=0x71. Key
/// sizes/levels match the hub guide's own RSA-PSS rows (2048->L1, 3072->L3,
/// 4096->L5).
pub const RSA_PSS_2048: SignatureAlgo = SignatureAlgo {
    name: "RSA-PSS-2048", security_level: "L1",
    keygen_mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN, keygen_param: KeygenParam::RsaModulusBits(2048),
    sign_mechanism: CKM_SHA256_RSA_PKCS_PSS, slow: false,
};
pub const RSA_PSS_3072: SignatureAlgo = SignatureAlgo {
    name: "RSA-PSS-3072", security_level: "L3",
    keygen_mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN, keygen_param: KeygenParam::RsaModulusBits(3072),
    sign_mechanism: CKM_SHA384_RSA_PKCS_PSS, slow: false,
};
pub const RSA_PSS_4096: SignatureAlgo = SignatureAlgo {
    name: "RSA-PSS-4096", security_level: "L5",
    keygen_mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN, keygen_param: KeygenParam::RsaModulusBits(4096),
    sign_mechanism: CKM_SHA512_RSA_PKCS_PSS, slow: false,
};

pub const SIGNATURE_ALGOS: &[SignatureAlgo] = &[
    ED25519, ECDSA_P256, ECDSA_K256, ECDSA_P384, ECDSA_P521,
    ML_DSA_44, ML_DSA_65, ML_DSA_87,
    SLH_DSA_128S, SLH_DSA_256S,
    SLH_DSA_SHAKE_128S, SLH_DSA_SHA2_128F, SLH_DSA_SHAKE_128F,
    SLH_DSA_SHA2_192S, SLH_DSA_SHAKE_192S, SLH_DSA_SHA2_192F, SLH_DSA_SHAKE_192F,
    SLH_DSA_SHAKE_256S, SLH_DSA_SHA2_256F, SLH_DSA_SHAKE_256F,
    RSA_PSS_2048, RSA_PSS_3072, RSA_PSS_4096,
];

/// One benchmarked key-agreement (ECDH-family) algorithm. Deriving is
/// always `CKM_ECDH1_DERIVE` (§6.7/§5.18.5) for every entry here — the
/// SAME generic derive mechanism for both Montgomery (X25519) and
/// Weierstrass (P-256/384/521) curves; the engine dispatches to the right
/// math internally from the base key's own stored algorithm family
/// (confirmed against `ffi.rs`'s single shared `C_DeriveKey` ECDH branch).
/// That mechanism is hardcoded inside `pkcs11::Engine::ecdh1_derive`
/// rather than carried as a field here, since no other value is valid.
#[derive(Clone, Copy, Debug)]
pub struct KeyAgreementAlgo {
    pub name: &'static str,
    pub security_level: &'static str,
    pub keygen_mechanism: u32,
    pub keygen_param: KeygenParam,
}

pub const X25519: KeyAgreementAlgo = KeyAgreementAlgo {
    name: "X25519", security_level: "L1",
    keygen_mechanism: CKM_EC_MONTGOMERY_KEY_PAIR_GEN, keygen_param: KeygenParam::EcParamsOid(X25519_OID),
};
pub const ECDH_P256: KeyAgreementAlgo = KeyAgreementAlgo {
    name: "ECDH-P256", security_level: "L1",
    keygen_mechanism: CKM_EC_KEY_PAIR_GEN, keygen_param: KeygenParam::EcParamsOid(P256_OID),
};
pub const ECDH_P384: KeyAgreementAlgo = KeyAgreementAlgo {
    name: "ECDH-P384", security_level: "L3",
    keygen_mechanism: CKM_EC_KEY_PAIR_GEN, keygen_param: KeygenParam::EcParamsOid(P384_OID),
};
pub const ECDH_P521: KeyAgreementAlgo = KeyAgreementAlgo {
    name: "ECDH-P521", security_level: "L5",
    keygen_mechanism: CKM_EC_KEY_PAIR_GEN, keygen_param: KeygenParam::EcParamsOid(P521_OID),
};

pub const KEY_AGREEMENT_ALGOS: &[KeyAgreementAlgo] = &[X25519, ECDH_P256, ECDH_P384, ECDH_P521];

/// One benchmarked KEM. `CKA_PARAMETER_SET` is a REQUIRED public-key-
/// template attribute for `CKM_ML_KEM_KEY_PAIR_GEN` (confirmed against
/// `ffi.rs`: absent → `CKR_TEMPLATE_INCOMPLETE`) — unlike Ed25519/X25519
/// this category never uses an empty template.
#[derive(Clone, Copy, Debug)]
pub struct KemAlgo {
    pub name: &'static str,
    pub security_level: &'static str,
    pub keygen_mechanism: u32,
    pub kem_mechanism: u32,
    pub parameter_set: u32,
}

pub const ML_KEM_512: KemAlgo = KemAlgo {
    name: "ML-KEM-512", security_level: "L1",
    keygen_mechanism: CKM_ML_KEM_KEY_PAIR_GEN, kem_mechanism: CKM_ML_KEM, parameter_set: CKP_ML_KEM_512,
};
pub const ML_KEM_768: KemAlgo = KemAlgo {
    name: "ML-KEM-768", security_level: "L3",
    keygen_mechanism: CKM_ML_KEM_KEY_PAIR_GEN, kem_mechanism: CKM_ML_KEM, parameter_set: CKP_ML_KEM_768,
};
pub const ML_KEM_1024: KemAlgo = KemAlgo {
    name: "ML-KEM-1024", security_level: "L5",
    keygen_mechanism: CKM_ML_KEM_KEY_PAIR_GEN, kem_mechanism: CKM_ML_KEM, parameter_set: CKP_ML_KEM_1024,
};

pub const KEM_ALGOS: &[KemAlgo] = &[ML_KEM_512, ML_KEM_768, ML_KEM_1024];

/// One benchmarked key-transport (RSA-OAEP) algorithm — `C_Encrypt`/
/// `C_Decrypt`, not a KEM's `C_EncapsulateKey`/`C_DecapsulateKey`, but
/// reported under the SAME `"key_establishment"` category as
/// `KeyAgreementAlgo`/`KemAlgo` above (main.rs already puts two
/// structurally different measurement patterns — derive vs encapsulate/
/// decapsulate — under that one label, differentiated only by `op`; this
/// is a third instance of that same pattern, not a new category).
///
/// `keygen_mechanism`/`keygen_param` here are a FALLBACK only:
/// `provision_tenant` reuses the matching `SignatureAlgo` entry named
/// `sig_algo_name`'s ALREADY-provisioned keypair when that algorithm was
/// also selected for this run (confirmed the engine's default RSA keygen
/// template already sets dual CKA_SIGN+CKA_DECRYPT on one keypair — no
/// redundant, and for RSA genuinely expensive, second keygen in the
/// common case). These fields only get used if a run selects an
/// `EncAlgo` WITHOUT its matching `SignatureAlgo` (e.g. `--algorithms
/// RSA-OAEP-2048` alone) — provisioning then falls back to an
/// independent keypair for just that case.
#[derive(Clone, Copy, Debug)]
pub struct EncAlgo {
    pub name: &'static str,
    pub security_level: &'static str,
    pub sig_algo_name: &'static str,
    pub keygen_mechanism: u32,
    pub keygen_param: KeygenParam,
    pub encrypt_mechanism: u32,
}

pub const RSA_OAEP_2048: EncAlgo = EncAlgo {
    name: "RSA-OAEP-2048", security_level: "L1", sig_algo_name: "RSA-PSS-2048",
    keygen_mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN, keygen_param: KeygenParam::RsaModulusBits(2048),
    encrypt_mechanism: CKM_RSA_PKCS_OAEP,
};
pub const RSA_OAEP_3072: EncAlgo = EncAlgo {
    name: "RSA-OAEP-3072", security_level: "L3", sig_algo_name: "RSA-PSS-3072",
    keygen_mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN, keygen_param: KeygenParam::RsaModulusBits(3072),
    encrypt_mechanism: CKM_RSA_PKCS_OAEP,
};
pub const RSA_OAEP_4096: EncAlgo = EncAlgo {
    name: "RSA-OAEP-4096", security_level: "L5", sig_algo_name: "RSA-PSS-4096",
    keygen_mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN, keygen_param: KeygenParam::RsaModulusBits(4096),
    encrypt_mechanism: CKM_RSA_PKCS_OAEP,
};

pub const ENC_ALGOS: &[EncAlgo] = &[RSA_OAEP_2048, RSA_OAEP_3072, RSA_OAEP_4096];

/// One benchmarked SYMMETRIC bulk-encryption point: an AES key size, a
/// mode, and the plaintext size it is measured at. The data size is part
/// of the algorithm identity here (`AES-256-GCM-1KB`, not `AES-256-GCM`)
/// on purpose — symmetric throughput is a function of message size in a
/// way an asymmetric operation's is not, and every consumer of this
/// harness's JSONL (the sandbox dashboard, `bench-results-table.py`)
/// keys a series by `algorithm` alone, so folding the size into the name
/// is what makes "64 B vs 1 KiB" two comparable rows rather than one
/// ambiguous one.
///
/// Mechanisms: CBC is the classical bulk mode and GCM is what TLS 1.3 and
/// the rest of the modern estate actually encrypt with; both are real,
/// non-stub dispatch arms in this engine (verified against `ffi.rs`'s
/// `C_EncryptInit`, which enforces each mode's parameter shape — see
/// `pkcs11.rs::sym_init`). 64 B and 1024 B are both exact multiples of
/// the 16-byte AES block, so raw `CKM_AES_CBC` (no padding) is valid at
/// both sizes and no padding cost is silently folded into the CBC rows.
///
/// `security_level` follows the same convention the classical asymmetric
/// entries above use (RSA-2048 → L1): AES-128 → L1, AES-256 → L5. Note
/// that unlike RSA, neither is expected to MOVE under a quantum threat
/// model — that is the point of measuring them next to the PQC rows.
#[derive(Clone, Copy, Debug)]
pub struct SymmetricAlgo {
    pub name: &'static str,
    pub security_level: &'static str,
    /// Key length in BYTES (16 = AES-128, 32 = AES-256) — the
    /// `CKA_VALUE_LEN` the engine requires for `CKM_AES_KEY_GEN`.
    pub key_bytes: u32,
    pub encrypt_mechanism: u32,
    /// Plaintext bytes per measured operation.
    pub data_len: usize,
    /// IV/nonce length in bytes: 16 for CBC (the mode's block-sized IV),
    /// 12 for GCM (SP 800-38D's recommended nonce length).
    pub iv_len: usize,
}

macro_rules! aes_point {
    ($konst:ident, $name:literal, $level:literal, $key_bytes:expr, $mech:expr, $data_len:expr, $iv_len:expr) => {
        pub const $konst: SymmetricAlgo = SymmetricAlgo {
            name: $name, security_level: $level, key_bytes: $key_bytes,
            encrypt_mechanism: $mech, data_len: $data_len, iv_len: $iv_len,
        };
    };
}

aes_point!(AES_128_CBC_64B,  "AES-128-CBC-64B",  "L1", 16, CKM_AES_CBC, 64,   16);
aes_point!(AES_128_CBC_1KB,  "AES-128-CBC-1KB",  "L1", 16, CKM_AES_CBC, 1024, 16);
aes_point!(AES_256_CBC_64B,  "AES-256-CBC-64B",  "L5", 32, CKM_AES_CBC, 64,   16);
aes_point!(AES_256_CBC_1KB,  "AES-256-CBC-1KB",  "L5", 32, CKM_AES_CBC, 1024, 16);
aes_point!(AES_128_GCM_64B,  "AES-128-GCM-64B",  "L1", 16, CKM_AES_GCM, 64,   12);
aes_point!(AES_128_GCM_1KB,  "AES-128-GCM-1KB",  "L1", 16, CKM_AES_GCM, 1024, 12);
aes_point!(AES_256_GCM_64B,  "AES-256-GCM-64B",  "L5", 32, CKM_AES_GCM, 64,   12);
aes_point!(AES_256_GCM_1KB,  "AES-256-GCM-1KB",  "L5", 32, CKM_AES_GCM, 1024, 12);
// 16 KiB — TLS 1.3's maximum record size (RFC 8446 §5.1), i.e. the largest
// single chunk a real transport hands a cipher in one call. Added 2026-09-26
// after the first run showed WHY a third size is needed: at 64 B the per-call
// PKCS#11 path dominates so completely that AES-256 measured no slower than
// AES-128 (42,707 vs 41,714 TPS on the KV260 — the key schedule was invisible),
// and even at 1 KiB the fixed overhead is still a visible share. At 16 KiB the
// figure is the cipher's own bulk rate, which is what a "how fast is AES here"
// question actually means.
aes_point!(AES_128_CBC_16KB, "AES-128-CBC-16KB", "L1", 16, CKM_AES_CBC, 16384, 16);
aes_point!(AES_256_CBC_16KB, "AES-256-CBC-16KB", "L5", 32, CKM_AES_CBC, 16384, 16);
aes_point!(AES_128_GCM_16KB, "AES-128-GCM-16KB", "L1", 16, CKM_AES_GCM, 16384, 12);
aes_point!(AES_256_GCM_16KB, "AES-256-GCM-16KB", "L5", 32, CKM_AES_GCM, 16384, 12);

pub const SYMMETRIC_ALGOS: &[SymmetricAlgo] = &[
    AES_128_CBC_64B, AES_128_CBC_1KB, AES_128_CBC_16KB,
    AES_256_CBC_64B, AES_256_CBC_1KB, AES_256_CBC_16KB,
    AES_128_GCM_64B, AES_128_GCM_1KB, AES_128_GCM_16KB,
    AES_256_GCM_64B, AES_256_GCM_1KB, AES_256_GCM_16KB,
];

/// One benchmarked DIGEST point — mechanism plus the message size it is
/// measured at, same "size is part of the name" reasoning as
/// `SymmetricAlgo`.
///
/// **SHAKE is deliberately absent, and it is not an omission this harness
/// can fix.** PKCS#11 v3.2 defines no SHAKE *digest* mechanism at all —
/// the only SHAKE codepoints in the standard (and in this engine's
/// `constants.rs`) are `CKM_SHAKE_256_KEY_DERIVATION` and the
/// `CKM_HASH_*_SHAKE*` pre-hash mechanisms that exist only as part of
/// ML-DSA/SLH-DSA signing. Confirmed against the engine's own
/// `C_DigestInit` dispatch, which answers `CKR_MECHANISM_INVALID` for
/// anything outside {SHA-1, SHA-2 family, SHA-3 family, MD5, Keccak-256,
/// RIPEMD-160}. SHA-3 IS the Keccak sponge SHAKE is built on and is what
/// a PKCS#11 caller reaches for instead, so the SHA3-256/512 rows below
/// are the closestmeasurement of that family available through this
/// access path; the SHAKE cost that IS measurable here shows up inside
/// the SLH-DSA-SHAKE-* signature rows, which are pure SHAKE workloads.
#[derive(Clone, Copy, Debug)]
pub struct DigestAlgo {
    pub name: &'static str,
    pub security_level: &'static str,
    pub mechanism: u32,
    pub data_len: usize,
    /// Output length in bytes — used to size the caller-owned output
    /// buffer `Engine::digest_into` writes into (no size query per op).
    pub digest_len: usize,
}

macro_rules! digest_point {
    ($konst:ident, $name:literal, $level:literal, $mech:expr, $data_len:expr, $digest_len:expr) => {
        pub const $konst: DigestAlgo = DigestAlgo {
            name: $name, security_level: $level, mechanism: $mech,
            data_len: $data_len, digest_len: $digest_len,
        };
    };
}

digest_point!(SHA256_64B,   "SHA-256-64B",  "L1", CKM_SHA256,   64,   32);
digest_point!(SHA256_1KB,   "SHA-256-1KB",  "L1", CKM_SHA256,   1024, 32);
digest_point!(SHA384_64B,   "SHA-384-64B",  "L3", CKM_SHA384,   64,   48);
digest_point!(SHA384_1KB,   "SHA-384-1KB",  "L3", CKM_SHA384,   1024, 48);
digest_point!(SHA512_64B,   "SHA-512-64B",  "L5", CKM_SHA512,   64,   64);
digest_point!(SHA512_1KB,   "SHA-512-1KB",  "L5", CKM_SHA512,   1024, 64);
digest_point!(SHA3_256_64B, "SHA3-256-64B", "L1", CKM_SHA3_256, 64,   32);
digest_point!(SHA3_256_1KB, "SHA3-256-1KB", "L1", CKM_SHA3_256, 1024, 32);
digest_point!(SHA3_512_64B, "SHA3-512-64B", "L5", CKM_SHA3_512, 64,   64);
digest_point!(SHA3_512_1KB, "SHA3-512-1KB", "L5", CKM_SHA3_512, 1024, 64);
// 16 KiB, same reasoning as the AES 16 KiB points: at 64 B every digest here
// landed within 12% of every other (347k-390k TPS on the KV260), which measures
// the call path, not the hash. The large size is where SHA-2's `sha2` ISA
// extension vs software Keccak actually separates.
digest_point!(SHA256_16KB,   "SHA-256-16KB",  "L1", CKM_SHA256,   16384, 32);
digest_point!(SHA384_16KB,   "SHA-384-16KB",  "L3", CKM_SHA384,   16384, 48);
digest_point!(SHA512_16KB,   "SHA-512-16KB",  "L5", CKM_SHA512,   16384, 64);
digest_point!(SHA3_256_16KB, "SHA3-256-16KB", "L1", CKM_SHA3_256, 16384, 32);
digest_point!(SHA3_512_16KB, "SHA3-512-16KB", "L5", CKM_SHA3_512, 16384, 64);

pub const DIGEST_ALGOS: &[DigestAlgo] = &[
    SHA256_64B, SHA256_1KB, SHA256_16KB,
    SHA384_64B, SHA384_1KB, SHA384_16KB,
    SHA512_64B, SHA512_1KB, SHA512_16KB,
    SHA3_256_64B, SHA3_256_1KB, SHA3_256_16KB,
    SHA3_512_64B, SHA3_512_1KB, SHA3_512_16KB,
];
