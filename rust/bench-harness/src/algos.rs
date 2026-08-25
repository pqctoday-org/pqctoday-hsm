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
    CKM_RSA_PKCS_KEY_PAIR_GEN, CKM_RSA_PKCS_OAEP, CKM_SHA256_RSA_PKCS_PSS, CKM_SHA384_RSA_PKCS_PSS,
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
/// classical algorithm referenced most, absent from this harness until
/// now). PSS needs no `CK_RSA_PKCS_PSS_PARAMS` at sign/verify time:
/// confirmed against `ffi.rs`'s dispatch that absent params fall back to
/// sane legacy defaults ("Absent params keep legacy defaults") — the
/// existing `sign_init`/`sign`/`verify_init`/`verify` wrappers (which
/// always pass null mechanism parameters) work unchanged, no new
/// params-struct plumbing needed. Key sizes/levels match the hub guide's
/// own RSA-PSS rows (2048->L1, 3072->L3, 4096->L5).
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
    ED25519, ECDSA_P256, ECDSA_P384, ECDSA_P521,
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
