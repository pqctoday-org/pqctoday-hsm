// SPDX-License-Identifier: AGPL-3.0-only
//
//! Composite ML-DSA and composite ML-KEM parameter sets — PKCS#11 v3.3
//! working draft (`working/doc/spec/comp_sig.md`, `comp_kem.md`, OASIS
//! PKCS 11 TC commit 9ef73f9). v3.2 has no composites, so v3.3 governs here
//! (root `CLAUDE.md`); the engine still reports Cryptoki 3.2.0.
//!
//! ONE table, one row per `CKP_COMP_SIG_*` / `CKP_COMP_KEM_*` value: 18
//! signature rows and 12 KEM rows. Every composite behaviour (key sizes,
//! M' construction, the KEM combiner, certificate OIDs) reads its per-set
//! facts from here and nowhere else, so a change in the drafts is a change
//! in one place.
//!
//! Sources, each pinned by SHA-256 in the committed fact extracts under
//! `rust/kat/pkcs11-v33/` that the tests below compare every row against:
//! - CKP values: the TC header `working/headers/pkcs11t.h` at commit 9ef73f9
//!   (`pkcs11-v33-identifiers.json`).
//! - Signature sets: draft-ietf-lamps-pq-composite-sigs-19 §2.2 (prefix),
//!   §6 (OID, label, PH, components), §6.1 Tables 2–3 (RSASSA-PSS),
//!   Appendix A Table 4 (sizes) (`composite-sigs-draft19-facts.json`).
//! - KEM sets: draft-ietf-lamps-pq-composite-kem-23 §3.4 (combiner), §6
//!   (OID, label, components), §6.1 Table 2 (RSA-OAEP), Appendix A Table 3
//!   (sizes) (`composite-kem-draft23-facts.json`).
//!
//! v3.3 cites the -14 and -12 revisions (`working/doc/spec/references.md`);
//! their OIDs and labels are identical to -19 and -23.
//!
//! Component sizes: the ML-DSA / ML-KEM sizes are the drafts' Table 1 in
//! each. A traditional component's size is the draft's Appendix A composite
//! size minus that ML size; the tests add the two back together and compare
//! with Appendix A, including whether the draft marks the size as a maximum
//! (`*`) rather than fixed.
//!
//! This module holds data only; the key objects are `native::composite_key`
//! and the KEM is `native::composite_kem`. The four brainpool rows are
//! `supported: false` until the engine has brainpool curves.

use crate::constants::{
    CKK_COMP_KEM, CKK_COMP_SIG, CKM_SHA256, CKM_SHA384, CKM_SHA512, CKP_COMP_KEM_MLKEM1024_ECDH_BRAINPOOLP384R1,
    CKP_COMP_KEM_MLKEM1024_ECDH_P384, CKP_COMP_KEM_MLKEM1024_ECDH_P521, CKP_COMP_KEM_MLKEM1024_RSA3072,
    CKP_COMP_KEM_MLKEM1024_X448, CKP_COMP_KEM_MLKEM768_ECDH_BRAINPOOLP256R1, CKP_COMP_KEM_MLKEM768_ECDH_P256,
    CKP_COMP_KEM_MLKEM768_ECDH_P384, CKP_COMP_KEM_MLKEM768_RSA2048, CKP_COMP_KEM_MLKEM768_RSA3072,
    CKP_COMP_KEM_MLKEM768_RSA4096, CKP_COMP_KEM_MLKEM768_X25519, CKP_COMP_SIG_MLDSA44_ECDSA_P256_SHA256,
    CKP_COMP_SIG_MLDSA44_ED25519_SHA512, CKP_COMP_SIG_MLDSA44_RSA2048_PKCS15_SHA256,
    CKP_COMP_SIG_MLDSA44_RSA2048_PSS_SHA256, CKP_COMP_SIG_MLDSA65_ECDSA_BRAINPOOLP256R1_SHA512,
    CKP_COMP_SIG_MLDSA65_ECDSA_P256_SHA512, CKP_COMP_SIG_MLDSA65_ECDSA_P384_SHA512,
    CKP_COMP_SIG_MLDSA65_ED25519_SHA512, CKP_COMP_SIG_MLDSA65_RSA3072_PKCS15_SHA512,
    CKP_COMP_SIG_MLDSA65_RSA3072_PSS_SHA512, CKP_COMP_SIG_MLDSA65_RSA4096_PKCS15_SHA512,
    CKP_COMP_SIG_MLDSA65_RSA4096_PSS_SHA512, CKP_COMP_SIG_MLDSA87_ECDSA_BRAINPOOLP384R1_SHA512,
    CKP_COMP_SIG_MLDSA87_ECDSA_P384_SHA512, CKP_COMP_SIG_MLDSA87_ECDSA_P521_SHA512,
    CKP_COMP_SIG_MLDSA87_ED448_SHAKE256, CKP_COMP_SIG_MLDSA87_RSA3072_PSS_SHA512,
    CKP_COMP_SIG_MLDSA87_RSA4096_PSS_SHA512, CKP_ML_DSA_44, CKP_ML_DSA_65, CKP_ML_DSA_87, CKP_ML_KEM_1024,
    CKP_ML_KEM_768,
};

/// M' prefix: the ASCII bytes of "CompositeAlgorithmSignatures2025"
/// (composite-sigs-19 §2.2; hex 436F6D706F73697465416C676F726974686D5369676E61747572657332303235).
pub const COMPOSITE_SIG_PREFIX: &[u8] = b"CompositeAlgorithmSignatures2025";

/// Length of the ML-DSA private seed ξ inside a composite private key
/// (composite-sigs-19 §4 Table 1, "Private key" = 32).
pub const MLDSA_SEED_LEN: usize = 32;
/// Length of the ML-KEM private seed d‖z inside a composite private key
/// (composite-kem-23 §4 Table 1, "Private Key" = 64).
pub const MLKEM_SEED_LEN: usize = 64;
/// Composite ML-KEM shared secret: 256 bits at every level
/// (composite-kem-23 §3.4 and §6; Appendix A Table 3 "SS" = 32).
pub const COMPOSITE_KEM_SS_LEN: usize = 32;

/// Which v3.3 composite family a parameter set belongs to. The CKP values
/// of the two families overlap (both start at 1), so a CKP value alone never
/// identifies a set.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CompositeFamily {
    /// `CKK_COMP_SIG`, `CKP_COMP_SIG_*`.
    Sig,
    /// `CKK_COMP_KEM`, `CKP_COMP_KEM_*`.
    Kem,
}

impl CompositeFamily {
    /// The family of a `CKA_KEY_TYPE`, or `None` for a non-composite type.
    pub fn from_key_type(ckk: u32) -> Option<Self> {
        match ckk {
            CKK_COMP_SIG => Some(CompositeFamily::Sig),
            CKK_COMP_KEM => Some(CompositeFamily::Kem),
            _ => None,
        }
    }

    pub fn key_type(self) -> u32 {
        match self {
            CompositeFamily::Sig => CKK_COMP_SIG,
            CompositeFamily::Kem => CKK_COMP_KEM,
        }
    }
}

/// A byte length that is either fixed or only an upper bound. The drafts'
/// Appendix A marks the second kind with `*` (RSA keys, DER ECDSA
/// signatures): an implementation must not length-check such a value for
/// equality.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Size {
    Exact(usize),
    Max(usize),
}

impl Size {
    pub fn bytes(self) -> usize {
        match self {
            Size::Exact(n) | Size::Max(n) => n,
        }
    }

    pub fn is_exact(self) -> bool {
        matches!(self, Size::Exact(_))
    }

    /// Whether `len` is a valid length for this size.
    pub fn admits(self, len: usize) -> bool {
        match self {
            Size::Exact(n) => len == n,
            Size::Max(n) => len <= n,
        }
    }

    /// A fixed ML component followed by this traditional component.
    const fn after(self, ml: usize) -> Size {
        match self {
            Size::Exact(n) => Size::Exact(ml + n),
            Size::Max(n) => Size::Max(ml + n),
        }
    }
}

/// The sizes of a traditional component in the drafts' §4 encodings: public
/// key, private key, and the signature (sig) or ciphertext (KEM).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ComponentSizes {
    pub public_key: Size,
    pub private_key: Size,
    pub output: Size,
}

/// Hash used by a traditional component (composite-sigs-19 §6 "Traditional
/// Signature Algorithm", §6.1 Tables 2–3). Distinct from the pre-hash PH.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TradHash {
    Sha256,
    Sha384,
    Sha512,
}

impl TradHash {
    pub fn mechanism(self) -> u32 {
        match self {
            TradHash::Sha256 => CKM_SHA256,
            TradHash::Sha384 => CKM_SHA384,
            TradHash::Sha512 => CKM_SHA512,
        }
    }

    pub fn output_len(self) -> usize {
        match self {
            TradHash::Sha256 => 32,
            TradHash::Sha384 => 48,
            TradHash::Sha512 => 64,
        }
    }
}

/// The pre-hash PH applied to the message before M' is built
/// (composite-sigs-19 §6 "Pre-Hash function (PH)"; OIDs from Appendix B
/// Table 7). `CKM_COMP_SIG_EXTERNAL_HASH` input must be exactly
/// [`PreHash::output_len`] bytes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PreHash {
    Sha256,
    Sha512,
    /// SHAKE256 with 64 bytes (512 bits) of output (§6 note "**").
    Shake256_64,
}

impl PreHash {
    pub fn output_len(self) -> usize {
        match self {
            PreHash::Sha256 => 32,
            PreHash::Sha512 | PreHash::Shake256_64 => 64,
        }
    }

    pub fn oid(self) -> &'static str {
        match self {
            PreHash::Sha256 => "2.16.840.1.101.3.4.2.1",
            PreHash::Sha512 => "2.16.840.1.101.3.4.2.3",
            PreHash::Shake256_64 => "2.16.840.1.101.3.4.2.18",
        }
    }
}

/// Named curves used by the composite sets (composite-sigs-19 Appendix B
/// Table 6; composite-kem-23 Appendix B Table 5).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EcCurve {
    P256,
    P384,
    P521,
    BrainpoolP256r1,
    BrainpoolP384r1,
}

impl EcCurve {
    pub fn oid(self) -> &'static str {
        match self {
            EcCurve::P256 => "1.2.840.10045.3.1.7",
            EcCurve::P384 => "1.3.132.0.34",
            EcCurve::P521 => "1.3.132.0.35",
            EcCurve::BrainpoolP256r1 => "1.3.36.3.3.2.8.1.1.7",
            EcCurve::BrainpoolP384r1 => "1.3.36.3.3.2.8.1.1.11",
        }
    }

    /// Field element width in bytes.
    pub fn field_bytes(self) -> usize {
        match self {
            EcCurve::P256 | EcCurve::BrainpoolP256r1 => 32,
            EcCurve::P384 | EcCurve::BrainpoolP384r1 => 48,
            EcCurve::P521 => 66,
        }
    }

    /// Uncompressed X9.62 point `04‖X‖Y`, the only public-key and ECDH
    /// ciphertext encoding the drafts allow (composite-sigs-19 §4,
    /// composite-kem-23 §4).
    pub fn uncompressed_point_len(self) -> usize {
        1 + 2 * self.field_bytes()
    }
}

/// Traditional half of a composite signature set (composite-sigs-19 §6).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SigClassical {
    /// id-RSASSA-PSS; hash, MGF1 hash and salt length from §6.1 Table 2
    /// (2048/3072: SHA-256, 32) or Table 3 (4096: SHA-384, 48).
    RsaPss { modulus_bits: u32, hash: TradHash, salt_len: usize },
    /// RSASSA-PKCS1-v1_5 with the §6 "shaNNNWithRSAEncryption" hash.
    RsaPkcs15 { modulus_bits: u32, hash: TradHash },
    /// ECDSA with the §6 "ecdsa-with-SHAnnn" hash, which tracks the curve,
    /// not PH.
    Ecdsa { curve: EcCurve, hash: TradHash },
    /// PureEdDSA over M' (id-Ed25519).
    Ed25519,
    /// PureEdDSA over M' (id-Ed448).
    Ed448,
}

/// Traditional half of a composite KEM set (composite-kem-23 §6).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KemClassical {
    /// id-RSAES-OAEP promoted to a KEM (§2.1) with the fixed §6.1 Table 2
    /// parameters for every size: SHA-256, MGF1-SHA-256, empty label, a
    /// 32-byte secret.
    RsaOaep { modulus_bits: u32 },
    /// id-ecDH promoted to a KEM (§2.2).
    Ecdh { curve: EcCurve },
    X25519,
    X448,
}

/// One `CKP_COMP_SIG_*` parameter set.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CompositeSigParams {
    /// `CKA_PARAMETER_SET` value (TC header, commit 9ef73f9).
    pub ckp: u32,
    /// The draft's algorithm identifier name (§6), e.g. `id-MLDSA65-ECDSA-P256-SHA512`.
    pub name: &'static str,
    /// The draft's OID (§6).
    pub oid: &'static str,
    /// Signature label, the ASCII bytes of §6 "Label".
    pub label: &'static [u8],
    /// The ML-DSA component as a `CKP_ML_DSA_*` value.
    pub ml_dsa: u32,
    pub pre_hash: PreHash,
    pub classical: SigClassical,
    pub classical_sizes: ComponentSizes,
    /// Whether the engine can run this set. False for brainpool until the
    /// engine has brainpool curves.
    pub supported: bool,
}

/// One `CKP_COMP_KEM_*` parameter set.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CompositeKemParams {
    /// `CKA_PARAMETER_SET` value (TC header, commit 9ef73f9).
    pub ckp: u32,
    /// The draft's algorithm identifier name (§6), e.g. `id-MLKEM768-X25519-SHA3-256`.
    pub name: &'static str,
    /// The draft's OID (§6).
    pub oid: &'static str,
    /// KEM combiner label (§6 "Label"), exact bytes. Most are ASCII; the
    /// X25519 label is the six bytes 5c2e2f2f5e5c.
    pub label: &'static [u8],
    /// The ML-KEM component as a `CKP_ML_KEM_*` value.
    pub ml_kem: u32,
    pub classical: KemClassical,
    pub classical_sizes: ComponentSizes,
    /// Whether the engine can run this set. False for brainpool until the
    /// engine has brainpool curves.
    pub supported: bool,
}

/// ML-DSA component sizes (composite-sigs-19 §4 Table 1): public key, signature.
const fn ml_dsa_sizes(ckp_ml_dsa: u32) -> (usize, usize) {
    match ckp_ml_dsa {
        CKP_ML_DSA_44 => (1312, 2420),
        CKP_ML_DSA_65 => (1952, 3309),
        CKP_ML_DSA_87 => (2592, 4627),
        _ => panic!("not an ML-DSA parameter set"),
    }
}

/// ML-KEM component sizes (composite-kem-23 §4 Table 1): public key, ciphertext.
const fn ml_kem_sizes(ckp_ml_kem: u32) -> (usize, usize) {
    match ckp_ml_kem {
        CKP_ML_KEM_768 => (1184, 1088),
        CKP_ML_KEM_1024 => (1568, 1568),
        _ => panic!("not a composite ML-KEM parameter set"),
    }
}

impl CompositeSigParams {
    pub fn ml_dsa_public_key_len(&self) -> usize {
        ml_dsa_sizes(self.ml_dsa).0
    }

    pub fn ml_dsa_signature_len(&self) -> usize {
        ml_dsa_sizes(self.ml_dsa).1
    }

    /// `CKA_VALUE` of the public key: `mldsaPK ‖ tradPK` (§4.1).
    pub fn public_key_size(&self) -> Size {
        self.classical_sizes.public_key.after(self.ml_dsa_public_key_len())
    }

    /// `CKA_VALUE` of the private key: `mldsaSeed ‖ tradSK` (§4.2).
    pub fn private_key_size(&self) -> Size {
        self.classical_sizes.private_key.after(MLDSA_SEED_LEN)
    }

    /// Composite signature: `mldsaSig ‖ tradSig` (§4.3).
    pub fn signature_size(&self) -> Size {
        self.classical_sizes.output.after(self.ml_dsa_signature_len())
    }
}

impl CompositeKemParams {
    pub fn ml_kem_public_key_len(&self) -> usize {
        ml_kem_sizes(self.ml_kem).0
    }

    pub fn ml_kem_ciphertext_len(&self) -> usize {
        ml_kem_sizes(self.ml_kem).1
    }

    /// `CKA_VALUE` of the public key: `mlkemPK ‖ tradPK` (§4.1).
    pub fn public_key_size(&self) -> Size {
        self.classical_sizes.public_key.after(self.ml_kem_public_key_len())
    }

    /// `CKA_VALUE` of the private key: `mlkemSeed ‖ tradSK` (§4.2).
    pub fn private_key_size(&self) -> Size {
        self.classical_sizes.private_key.after(MLKEM_SEED_LEN)
    }

    /// Composite ciphertext: `mlkemCT ‖ tradCT` (§4.3).
    pub fn ciphertext_size(&self) -> Size {
        self.classical_sizes.output.after(self.ml_kem_ciphertext_len())
    }
}

// ── Traditional component sizes ─────────────────────────────────────────────
// Appendix A composite size minus the Table 1 ML size (see module doc).
// RSA public keys are DER RSAPublicKey with e = 65537 and private keys DER
// RSAPrivateKey, both maxima; RSA signatures and OAEP ciphertexts are the
// modulus length. ECDSA private keys are DER ECPrivateKey without the
// publicKey field; ECDSA signatures are DER Ecdsa-Sig-Value, a maximum.

const RSA2048: ComponentSizes =
    ComponentSizes { public_key: Size::Max(270), private_key: Size::Max(1194), output: Size::Exact(256) };
const RSA3072: ComponentSizes =
    ComponentSizes { public_key: Size::Max(398), private_key: Size::Max(1770), output: Size::Exact(384) };
const RSA4096: ComponentSizes =
    ComponentSizes { public_key: Size::Max(526), private_key: Size::Max(2351), output: Size::Exact(512) };
const ED25519: ComponentSizes =
    ComponentSizes { public_key: Size::Exact(32), private_key: Size::Exact(32), output: Size::Exact(64) };
const ED448: ComponentSizes =
    ComponentSizes { public_key: Size::Exact(57), private_key: Size::Exact(57), output: Size::Exact(114) };
const ECDSA_P256: ComponentSizes =
    ComponentSizes { public_key: Size::Exact(65), private_key: Size::Exact(51), output: Size::Max(72) };
const ECDSA_P384: ComponentSizes =
    ComponentSizes { public_key: Size::Exact(97), private_key: Size::Exact(64), output: Size::Max(104) };
const ECDSA_P521: ComponentSizes =
    ComponentSizes { public_key: Size::Exact(133), private_key: Size::Exact(82), output: Size::Max(139) };
const ECDSA_BP256: ComponentSizes =
    ComponentSizes { public_key: Size::Exact(65), private_key: Size::Exact(52), output: Size::Max(72) };
const ECDSA_BP384: ComponentSizes =
    ComponentSizes { public_key: Size::Exact(97), private_key: Size::Exact(68), output: Size::Max(104) };
const X25519: ComponentSizes =
    ComponentSizes { public_key: Size::Exact(32), private_key: Size::Exact(32), output: Size::Exact(32) };
const X448: ComponentSizes =
    ComponentSizes { public_key: Size::Exact(56), private_key: Size::Exact(56), output: Size::Exact(56) };
const ECDH_P256: ComponentSizes =
    ComponentSizes { public_key: Size::Exact(65), private_key: Size::Exact(51), output: Size::Exact(65) };
const ECDH_P384: ComponentSizes =
    ComponentSizes { public_key: Size::Exact(97), private_key: Size::Exact(64), output: Size::Exact(97) };
const ECDH_P521: ComponentSizes =
    ComponentSizes { public_key: Size::Exact(133), private_key: Size::Exact(82), output: Size::Exact(133) };
const ECDH_BP256: ComponentSizes =
    ComponentSizes { public_key: Size::Exact(65), private_key: Size::Exact(52), output: Size::Exact(65) };
const ECDH_BP384: ComponentSizes =
    ComponentSizes { public_key: Size::Exact(97), private_key: Size::Exact(68), output: Size::Exact(97) };

const PSS_2048_3072: TradHash = TradHash::Sha256; // §6.1 Table 2
const PSS_2048_3072_SALT: usize = 32;
const PSS_4096: TradHash = TradHash::Sha384; // §6.1 Table 3
const PSS_4096_SALT: usize = 48;

/// The 18 composite ML-DSA sets, in `CKP_COMP_SIG_*` order (draft §6 order).
pub const COMPOSITE_SIG_SETS: [CompositeSigParams; 18] = [
    CompositeSigParams {
        ckp: CKP_COMP_SIG_MLDSA44_RSA2048_PSS_SHA256,
        name: "id-MLDSA44-RSA2048-PSS-SHA256",
        oid: "1.3.6.1.5.5.7.6.37",
        label: b"COMPSIG-MLDSA44-RSA2048-PSS-SHA256",
        ml_dsa: CKP_ML_DSA_44,
        pre_hash: PreHash::Sha256,
        classical: SigClassical::RsaPss { modulus_bits: 2048, hash: PSS_2048_3072, salt_len: PSS_2048_3072_SALT },
        classical_sizes: RSA2048,
        supported: true,
    },
    CompositeSigParams {
        ckp: CKP_COMP_SIG_MLDSA44_RSA2048_PKCS15_SHA256,
        name: "id-MLDSA44-RSA2048-PKCS15-SHA256",
        oid: "1.3.6.1.5.5.7.6.38",
        label: b"COMPSIG-MLDSA44-RSA2048-PKCS15-SHA256",
        ml_dsa: CKP_ML_DSA_44,
        pre_hash: PreHash::Sha256,
        classical: SigClassical::RsaPkcs15 { modulus_bits: 2048, hash: TradHash::Sha256 },
        classical_sizes: RSA2048,
        supported: true,
    },
    CompositeSigParams {
        ckp: CKP_COMP_SIG_MLDSA44_ED25519_SHA512,
        name: "id-MLDSA44-Ed25519-SHA512",
        oid: "1.3.6.1.5.5.7.6.39",
        label: b"COMPSIG-MLDSA44-Ed25519-SHA512",
        ml_dsa: CKP_ML_DSA_44,
        pre_hash: PreHash::Sha512,
        classical: SigClassical::Ed25519,
        classical_sizes: ED25519,
        supported: true,
    },
    CompositeSigParams {
        ckp: CKP_COMP_SIG_MLDSA44_ECDSA_P256_SHA256,
        name: "id-MLDSA44-ECDSA-P256-SHA256",
        oid: "1.3.6.1.5.5.7.6.40",
        label: b"COMPSIG-MLDSA44-ECDSA-P256-SHA256",
        ml_dsa: CKP_ML_DSA_44,
        pre_hash: PreHash::Sha256,
        classical: SigClassical::Ecdsa { curve: EcCurve::P256, hash: TradHash::Sha256 },
        classical_sizes: ECDSA_P256,
        supported: true,
    },
    CompositeSigParams {
        ckp: CKP_COMP_SIG_MLDSA65_RSA3072_PSS_SHA512,
        name: "id-MLDSA65-RSA3072-PSS-SHA512",
        oid: "1.3.6.1.5.5.7.6.41",
        label: b"COMPSIG-MLDSA65-RSA3072-PSS-SHA512",
        ml_dsa: CKP_ML_DSA_65,
        pre_hash: PreHash::Sha512,
        classical: SigClassical::RsaPss { modulus_bits: 3072, hash: PSS_2048_3072, salt_len: PSS_2048_3072_SALT },
        classical_sizes: RSA3072,
        supported: true,
    },
    CompositeSigParams {
        ckp: CKP_COMP_SIG_MLDSA65_RSA3072_PKCS15_SHA512,
        name: "id-MLDSA65-RSA3072-PKCS15-SHA512",
        oid: "1.3.6.1.5.5.7.6.42",
        label: b"COMPSIG-MLDSA65-RSA3072-PKCS15-SHA512",
        ml_dsa: CKP_ML_DSA_65,
        pre_hash: PreHash::Sha512,
        // §6: sha256WithRSAEncryption (not SHA-512, which is PH).
        classical: SigClassical::RsaPkcs15 { modulus_bits: 3072, hash: TradHash::Sha256 },
        classical_sizes: RSA3072,
        supported: true,
    },
    CompositeSigParams {
        ckp: CKP_COMP_SIG_MLDSA65_RSA4096_PSS_SHA512,
        name: "id-MLDSA65-RSA4096-PSS-SHA512",
        oid: "1.3.6.1.5.5.7.6.43",
        label: b"COMPSIG-MLDSA65-RSA4096-PSS-SHA512",
        ml_dsa: CKP_ML_DSA_65,
        pre_hash: PreHash::Sha512,
        classical: SigClassical::RsaPss { modulus_bits: 4096, hash: PSS_4096, salt_len: PSS_4096_SALT },
        classical_sizes: RSA4096,
        supported: true,
    },
    CompositeSigParams {
        ckp: CKP_COMP_SIG_MLDSA65_RSA4096_PKCS15_SHA512,
        name: "id-MLDSA65-RSA4096-PKCS15-SHA512",
        oid: "1.3.6.1.5.5.7.6.44",
        label: b"COMPSIG-MLDSA65-RSA4096-PKCS15-SHA512",
        ml_dsa: CKP_ML_DSA_65,
        pre_hash: PreHash::Sha512,
        // §6: sha384WithRSAEncryption.
        classical: SigClassical::RsaPkcs15 { modulus_bits: 4096, hash: TradHash::Sha384 },
        classical_sizes: RSA4096,
        supported: true,
    },
    CompositeSigParams {
        ckp: CKP_COMP_SIG_MLDSA65_ECDSA_P256_SHA512,
        name: "id-MLDSA65-ECDSA-P256-SHA512",
        oid: "1.3.6.1.5.5.7.6.45",
        label: b"COMPSIG-MLDSA65-ECDSA-P256-SHA512",
        ml_dsa: CKP_ML_DSA_65,
        pre_hash: PreHash::Sha512,
        classical: SigClassical::Ecdsa { curve: EcCurve::P256, hash: TradHash::Sha256 },
        classical_sizes: ECDSA_P256,
        supported: true,
    },
    CompositeSigParams {
        ckp: CKP_COMP_SIG_MLDSA65_ECDSA_P384_SHA512,
        name: "id-MLDSA65-ECDSA-P384-SHA512",
        oid: "1.3.6.1.5.5.7.6.46",
        label: b"COMPSIG-MLDSA65-ECDSA-P384-SHA512",
        ml_dsa: CKP_ML_DSA_65,
        pre_hash: PreHash::Sha512,
        classical: SigClassical::Ecdsa { curve: EcCurve::P384, hash: TradHash::Sha384 },
        classical_sizes: ECDSA_P384,
        supported: true,
    },
    CompositeSigParams {
        ckp: CKP_COMP_SIG_MLDSA65_ECDSA_BRAINPOOLP256R1_SHA512,
        name: "id-MLDSA65-ECDSA-brainpoolP256r1-SHA512",
        oid: "1.3.6.1.5.5.7.6.47",
        label: b"COMPSIG-MLDSA65-ECDSA-BP256-SHA512",
        ml_dsa: CKP_ML_DSA_65,
        pre_hash: PreHash::Sha512,
        classical: SigClassical::Ecdsa { curve: EcCurve::BrainpoolP256r1, hash: TradHash::Sha256 },
        classical_sizes: ECDSA_BP256,
        supported: false,
    },
    CompositeSigParams {
        ckp: CKP_COMP_SIG_MLDSA65_ED25519_SHA512,
        name: "id-MLDSA65-Ed25519-SHA512",
        oid: "1.3.6.1.5.5.7.6.48",
        label: b"COMPSIG-MLDSA65-Ed25519-SHA512",
        ml_dsa: CKP_ML_DSA_65,
        pre_hash: PreHash::Sha512,
        classical: SigClassical::Ed25519,
        classical_sizes: ED25519,
        supported: true,
    },
    CompositeSigParams {
        ckp: CKP_COMP_SIG_MLDSA87_ECDSA_P384_SHA512,
        name: "id-MLDSA87-ECDSA-P384-SHA512",
        oid: "1.3.6.1.5.5.7.6.49",
        label: b"COMPSIG-MLDSA87-ECDSA-P384-SHA512",
        ml_dsa: CKP_ML_DSA_87,
        pre_hash: PreHash::Sha512,
        classical: SigClassical::Ecdsa { curve: EcCurve::P384, hash: TradHash::Sha384 },
        classical_sizes: ECDSA_P384,
        supported: true,
    },
    CompositeSigParams {
        ckp: CKP_COMP_SIG_MLDSA87_ECDSA_BRAINPOOLP384R1_SHA512,
        name: "id-MLDSA87-ECDSA-brainpoolP384r1-SHA512",
        oid: "1.3.6.1.5.5.7.6.50",
        label: b"COMPSIG-MLDSA87-ECDSA-BP384-SHA512",
        ml_dsa: CKP_ML_DSA_87,
        pre_hash: PreHash::Sha512,
        classical: SigClassical::Ecdsa { curve: EcCurve::BrainpoolP384r1, hash: TradHash::Sha384 },
        classical_sizes: ECDSA_BP384,
        supported: false,
    },
    CompositeSigParams {
        ckp: CKP_COMP_SIG_MLDSA87_ED448_SHAKE256,
        name: "id-MLDSA87-Ed448-SHAKE256",
        oid: "1.3.6.1.5.5.7.6.51",
        label: b"COMPSIG-MLDSA87-Ed448-SHAKE256",
        ml_dsa: CKP_ML_DSA_87,
        pre_hash: PreHash::Shake256_64,
        classical: SigClassical::Ed448,
        classical_sizes: ED448,
        supported: true,
    },
    CompositeSigParams {
        ckp: CKP_COMP_SIG_MLDSA87_RSA3072_PSS_SHA512,
        name: "id-MLDSA87-RSA3072-PSS-SHA512",
        oid: "1.3.6.1.5.5.7.6.52",
        label: b"COMPSIG-MLDSA87-RSA3072-PSS-SHA512",
        ml_dsa: CKP_ML_DSA_87,
        pre_hash: PreHash::Sha512,
        classical: SigClassical::RsaPss { modulus_bits: 3072, hash: PSS_2048_3072, salt_len: PSS_2048_3072_SALT },
        classical_sizes: RSA3072,
        supported: true,
    },
    CompositeSigParams {
        ckp: CKP_COMP_SIG_MLDSA87_RSA4096_PSS_SHA512,
        name: "id-MLDSA87-RSA4096-PSS-SHA512",
        oid: "1.3.6.1.5.5.7.6.53",
        label: b"COMPSIG-MLDSA87-RSA4096-PSS-SHA512",
        ml_dsa: CKP_ML_DSA_87,
        pre_hash: PreHash::Sha512,
        classical: SigClassical::RsaPss { modulus_bits: 4096, hash: PSS_4096, salt_len: PSS_4096_SALT },
        classical_sizes: RSA4096,
        supported: true,
    },
    CompositeSigParams {
        ckp: CKP_COMP_SIG_MLDSA87_ECDSA_P521_SHA512,
        name: "id-MLDSA87-ECDSA-P521-SHA512",
        oid: "1.3.6.1.5.5.7.6.54",
        label: b"COMPSIG-MLDSA87-ECDSA-P521-SHA512",
        ml_dsa: CKP_ML_DSA_87,
        pre_hash: PreHash::Sha512,
        classical: SigClassical::Ecdsa { curve: EcCurve::P521, hash: TradHash::Sha512 },
        classical_sizes: ECDSA_P521,
        supported: true,
    },
];

/// The 12 composite ML-KEM sets, in `CKP_COMP_KEM_*` order (draft §6 order).
/// Every set uses SHA3-256 as the combiner KDF (§3.4, §6).
pub const COMPOSITE_KEM_SETS: [CompositeKemParams; 12] = [
    CompositeKemParams {
        ckp: CKP_COMP_KEM_MLKEM768_RSA2048,
        name: "id-MLKEM768-RSA2048-SHA3-256",
        oid: "1.3.6.1.5.5.7.6.55",
        label: b"MLKEM768-RSAOAEP2048",
        ml_kem: CKP_ML_KEM_768,
        classical: KemClassical::RsaOaep { modulus_bits: 2048 },
        classical_sizes: RSA2048,
        supported: true,
    },
    CompositeKemParams {
        ckp: CKP_COMP_KEM_MLKEM768_RSA3072,
        name: "id-MLKEM768-RSA3072-SHA3-256",
        oid: "1.3.6.1.5.5.7.6.56",
        label: b"MLKEM768-RSAOAEP3072",
        ml_kem: CKP_ML_KEM_768,
        classical: KemClassical::RsaOaep { modulus_bits: 3072 },
        classical_sizes: RSA3072,
        supported: true,
    },
    CompositeKemParams {
        ckp: CKP_COMP_KEM_MLKEM768_RSA4096,
        name: "id-MLKEM768-RSA4096-SHA3-256",
        oid: "1.3.6.1.5.5.7.6.57",
        label: b"MLKEM768-RSAOAEP4096",
        ml_kem: CKP_ML_KEM_768,
        classical: KemClassical::RsaOaep { modulus_bits: 4096 },
        classical_sizes: RSA4096,
        supported: true,
    },
    CompositeKemParams {
        ckp: CKP_COMP_KEM_MLKEM768_X25519,
        name: "id-MLKEM768-X25519-SHA3-256",
        oid: "1.3.6.1.5.5.7.6.58",
        // §6: given only in hex, 5c2e2f2f5e5c (ASCII "\.//^\").
        label: &[0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c],
        ml_kem: CKP_ML_KEM_768,
        classical: KemClassical::X25519,
        classical_sizes: X25519,
        supported: true,
    },
    CompositeKemParams {
        ckp: CKP_COMP_KEM_MLKEM768_ECDH_P256,
        name: "id-MLKEM768-ECDH-P256-SHA3-256",
        oid: "1.3.6.1.5.5.7.6.59",
        label: b"MLKEM768-P256",
        ml_kem: CKP_ML_KEM_768,
        classical: KemClassical::Ecdh { curve: EcCurve::P256 },
        classical_sizes: ECDH_P256,
        supported: true,
    },
    CompositeKemParams {
        ckp: CKP_COMP_KEM_MLKEM768_ECDH_P384,
        name: "id-MLKEM768-ECDH-P384-SHA3-256",
        oid: "1.3.6.1.5.5.7.6.60",
        label: b"MLKEM768-P384",
        ml_kem: CKP_ML_KEM_768,
        classical: KemClassical::Ecdh { curve: EcCurve::P384 },
        classical_sizes: ECDH_P384,
        supported: true,
    },
    CompositeKemParams {
        ckp: CKP_COMP_KEM_MLKEM768_ECDH_BRAINPOOLP256R1,
        name: "id-MLKEM768-ECDH-brainpoolP256r1-SHA3-256",
        oid: "1.3.6.1.5.5.7.6.61",
        label: b"MLKEM768-BP256",
        ml_kem: CKP_ML_KEM_768,
        classical: KemClassical::Ecdh { curve: EcCurve::BrainpoolP256r1 },
        classical_sizes: ECDH_BP256,
        supported: false,
    },
    CompositeKemParams {
        ckp: CKP_COMP_KEM_MLKEM1024_RSA3072,
        name: "id-MLKEM1024-RSA3072-SHA3-256",
        oid: "1.3.6.1.5.5.7.6.62",
        label: b"MLKEM1024-RSAOAEP3072",
        ml_kem: CKP_ML_KEM_1024,
        classical: KemClassical::RsaOaep { modulus_bits: 3072 },
        classical_sizes: RSA3072,
        supported: true,
    },
    CompositeKemParams {
        ckp: CKP_COMP_KEM_MLKEM1024_ECDH_P384,
        name: "id-MLKEM1024-ECDH-P384-SHA3-256",
        oid: "1.3.6.1.5.5.7.6.63",
        label: b"MLKEM1024-P384",
        ml_kem: CKP_ML_KEM_1024,
        classical: KemClassical::Ecdh { curve: EcCurve::P384 },
        classical_sizes: ECDH_P384,
        supported: true,
    },
    CompositeKemParams {
        ckp: CKP_COMP_KEM_MLKEM1024_ECDH_BRAINPOOLP384R1,
        name: "id-MLKEM1024-ECDH-brainpoolP384r1-SHA3-256",
        oid: "1.3.6.1.5.5.7.6.64",
        label: b"MLKEM1024-BP384",
        ml_kem: CKP_ML_KEM_1024,
        classical: KemClassical::Ecdh { curve: EcCurve::BrainpoolP384r1 },
        classical_sizes: ECDH_BP384,
        supported: false,
    },
    CompositeKemParams {
        ckp: CKP_COMP_KEM_MLKEM1024_X448,
        name: "id-MLKEM1024-X448-SHA3-256",
        oid: "1.3.6.1.5.5.7.6.65",
        label: b"MLKEM1024-X448",
        ml_kem: CKP_ML_KEM_1024,
        classical: KemClassical::X448,
        classical_sizes: X448,
        supported: true,
    },
    CompositeKemParams {
        ckp: CKP_COMP_KEM_MLKEM1024_ECDH_P521,
        name: "id-MLKEM1024-ECDH-P521-SHA3-256",
        oid: "1.3.6.1.5.5.7.6.66",
        label: b"MLKEM1024-P521",
        ml_kem: CKP_ML_KEM_1024,
        classical: KemClassical::Ecdh { curve: EcCurve::P521 },
        classical_sizes: ECDH_P521,
        supported: true,
    },
];

/// A composite parameter set of either family.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CompositeParams {
    Sig(&'static CompositeSigParams),
    Kem(&'static CompositeKemParams),
}

impl CompositeParams {
    pub fn family(self) -> CompositeFamily {
        match self {
            CompositeParams::Sig(_) => CompositeFamily::Sig,
            CompositeParams::Kem(_) => CompositeFamily::Kem,
        }
    }

    pub fn ckp(self) -> u32 {
        match self {
            CompositeParams::Sig(p) => p.ckp,
            CompositeParams::Kem(p) => p.ckp,
        }
    }

    pub fn oid(self) -> &'static str {
        match self {
            CompositeParams::Sig(p) => p.oid,
            CompositeParams::Kem(p) => p.oid,
        }
    }

    pub fn supported(self) -> bool {
        match self {
            CompositeParams::Sig(p) => p.supported,
            CompositeParams::Kem(p) => p.supported,
        }
    }
}

/// The signature set for a `CKP_COMP_SIG_*` value.
pub fn sig_params(ckp: u32) -> Option<&'static CompositeSigParams> {
    COMPOSITE_SIG_SETS.iter().find(|p| p.ckp == ckp)
}

/// The KEM set for a `CKP_COMP_KEM_*` value.
pub fn kem_params(ckp: u32) -> Option<&'static CompositeKemParams> {
    COMPOSITE_KEM_SETS.iter().find(|p| p.ckp == ckp)
}

/// The set for a `CKA_PARAMETER_SET` value within a family.
pub fn params_by_ckp(family: CompositeFamily, ckp: u32) -> Option<CompositeParams> {
    match family {
        CompositeFamily::Sig => sig_params(ckp).map(CompositeParams::Sig),
        CompositeFamily::Kem => kem_params(ckp).map(CompositeParams::Kem),
    }
}

/// `(ulMinKeySize, ulMaxKeySize)` of `CKM_COMP_KEM_KEY_PAIR_GEN` and
/// `CKM_COMP_KEM`: "the supported range of Composite KEM public key[s] in
/// bytes" (comp_kem.md), i.e. the smallest and largest `mlkemPK ‖ tradPK`
/// over the sets this engine supports. An RSA public key's size is a maximum
/// (Appendix A `*`), so the upper bound is that maximum.
pub fn kem_public_key_size_range() -> (u32, u32) {
    let sizes = COMPOSITE_KEM_SETS.iter().filter(|p| p.supported).map(|p| p.public_key_size().bytes() as u32);
    (sizes.clone().min().unwrap_or(0), sizes.max().unwrap_or(0))
}

/// The set for a `CKA_KEY_TYPE` (`CKK_COMP_SIG` / `CKK_COMP_KEM`) and
/// `CKA_PARAMETER_SET` pair.
pub fn params_for_key(ckk: u32, ckp: u32) -> Option<CompositeParams> {
    params_by_ckp(CompositeFamily::from_key_type(ckk)?, ckp)
}

/// The set for a dotted-decimal OID (both families; the OID arcs do not
/// overlap).
pub fn params_by_oid(oid: &str) -> Option<CompositeParams> {
    COMPOSITE_SIG_SETS
        .iter()
        .find(|p| p.oid == oid)
        .map(CompositeParams::Sig)
        .or_else(|| COMPOSITE_KEM_SETS.iter().find(|p| p.oid == oid).map(CompositeParams::Kem))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::*;
    use serde_json::Value;
    use std::collections::{BTreeMap, BTreeSet};

    const IDENTIFIERS: &str = include_str!("../../kat/pkcs11-v33/pkcs11-v33-identifiers.json");
    const SIG_FACTS: &str = include_str!("../../kat/pkcs11-v33/composite-sigs-draft19-facts.json");
    const KEM_FACTS: &str = include_str!("../../kat/pkcs11-v33/composite-kem-draft23-facts.json");

    fn json(s: &str) -> Value {
        serde_json::from_str(s).expect("fixture parses")
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Header name → value, from the extract of the TC header at the pin.
    fn header_values() -> BTreeMap<String, u32> {
        let v = json(IDENTIFIERS);
        let prov = &v["_provenance"];
        assert_eq!(prov["source_commit"], "9ef73f9f44ed8a240b05484427a0851ab36be251");
        assert_eq!(prov["source_path"], "working/headers/pkcs11t.h");
        assert_eq!(prov["source_sha256"], "765a28ac349d3cd940e5a90392fb9bc4a939151b29f63b5c156723c64f61f70e");
        v["identifiers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| {
                let s = e["value"].as_str().unwrap();
                let n = u32::from_str_radix(s.trim_start_matches("0x"), 16).unwrap();
                (e["name"].as_str().unwrap().to_string(), n)
            })
            .collect()
    }

    /// Every v3.3 identifier this engine defines equals the TC header at the
    /// pinned commit, and nothing in the extract is missing from the engine.
    #[test]
    fn v33_header_constants_match_engine_constants() {
        let engine: &[(&str, u32)] = &[
            ("CKK_COMP_KEM", CKK_COMP_KEM),
            ("CKK_COMP_SIG", CKK_COMP_SIG),
            ("CKA_KEYS_REMAINING", CKA_KEYS_REMAINING),
            ("CKA_HSS_KEYS_REMAINING", CKA_HSS_KEYS_REMAINING),
            ("CKM_COMP_SIG_KEY_PAIR_GEN", CKM_COMP_SIG_KEY_PAIR_GEN),
            ("CKM_COMP_SIG", CKM_COMP_SIG),
            ("CKM_COMP_SIG_EXTERNAL_HASH", CKM_COMP_SIG_EXTERNAL_HASH),
            ("CKM_COMP_KEM_KEY_PAIR_GEN", CKM_COMP_KEM_KEY_PAIR_GEN),
            ("CKM_COMP_KEM", CKM_COMP_KEM),
            ("CKM_ML_DSA_EXTERNAL_MU_GEN", CKM_ML_DSA_EXTERNAL_MU_GEN),
            ("CKM_ML_DSA_EXTERNAL_MU", CKM_ML_DSA_EXTERNAL_MU),
            ("CKP_COMP_SIG_MLDSA44_RSA2048_PSS_SHA256", CKP_COMP_SIG_MLDSA44_RSA2048_PSS_SHA256),
            ("CKP_COMP_SIG_MLDSA44_RSA2048_PKCS15_SHA256", CKP_COMP_SIG_MLDSA44_RSA2048_PKCS15_SHA256),
            ("CKP_COMP_SIG_MLDSA44_ED25519_SHA512", CKP_COMP_SIG_MLDSA44_ED25519_SHA512),
            ("CKP_COMP_SIG_MLDSA44_ECDSA_P256_SHA256", CKP_COMP_SIG_MLDSA44_ECDSA_P256_SHA256),
            ("CKP_COMP_SIG_MLDSA65_RSA3072_PSS_SHA512", CKP_COMP_SIG_MLDSA65_RSA3072_PSS_SHA512),
            ("CKP_COMP_SIG_MLDSA65_RSA3072_PKCS15_SHA512", CKP_COMP_SIG_MLDSA65_RSA3072_PKCS15_SHA512),
            ("CKP_COMP_SIG_MLDSA65_RSA4096_PSS_SHA512", CKP_COMP_SIG_MLDSA65_RSA4096_PSS_SHA512),
            ("CKP_COMP_SIG_MLDSA65_RSA4096_PKCS15_SHA512", CKP_COMP_SIG_MLDSA65_RSA4096_PKCS15_SHA512),
            ("CKP_COMP_SIG_MLDSA65_ECDSA_P256_SHA512", CKP_COMP_SIG_MLDSA65_ECDSA_P256_SHA512),
            ("CKP_COMP_SIG_MLDSA65_ECDSA_P384_SHA512", CKP_COMP_SIG_MLDSA65_ECDSA_P384_SHA512),
            ("CKP_COMP_SIG_MLDSA65_ECDSA_BRAINPOOLP256R1_SHA512", CKP_COMP_SIG_MLDSA65_ECDSA_BRAINPOOLP256R1_SHA512),
            ("CKP_COMP_SIG_MLDSA65_ED25519_SHA512", CKP_COMP_SIG_MLDSA65_ED25519_SHA512),
            ("CKP_COMP_SIG_MLDSA87_ECDSA_P384_SHA512", CKP_COMP_SIG_MLDSA87_ECDSA_P384_SHA512),
            ("CKP_COMP_SIG_MLDSA87_ECDSA_BRAINPOOLP384R1_SHA512", CKP_COMP_SIG_MLDSA87_ECDSA_BRAINPOOLP384R1_SHA512),
            ("CKP_COMP_SIG_MLDSA87_ED448_SHAKE256", CKP_COMP_SIG_MLDSA87_ED448_SHAKE256),
            ("CKP_COMP_SIG_MLDSA87_RSA3072_PSS_SHA512", CKP_COMP_SIG_MLDSA87_RSA3072_PSS_SHA512),
            ("CKP_COMP_SIG_MLDSA87_RSA4096_PSS_SHA512", CKP_COMP_SIG_MLDSA87_RSA4096_PSS_SHA512),
            ("CKP_COMP_SIG_MLDSA87_ECDSA_P521_SHA512", CKP_COMP_SIG_MLDSA87_ECDSA_P521_SHA512),
            ("CKP_COMP_KEM_MLKEM768_RSA2048", CKP_COMP_KEM_MLKEM768_RSA2048),
            ("CKP_COMP_KEM_MLKEM768_RSA3072", CKP_COMP_KEM_MLKEM768_RSA3072),
            ("CKP_COMP_KEM_MLKEM768_RSA4096", CKP_COMP_KEM_MLKEM768_RSA4096),
            ("CKP_COMP_KEM_MLKEM768_X25519", CKP_COMP_KEM_MLKEM768_X25519),
            ("CKP_COMP_KEM_MLKEM768_ECDH_P256", CKP_COMP_KEM_MLKEM768_ECDH_P256),
            ("CKP_COMP_KEM_MLKEM768_ECDH_P384", CKP_COMP_KEM_MLKEM768_ECDH_P384),
            ("CKP_COMP_KEM_MLKEM768_ECDH_BRAINPOOLP256R1", CKP_COMP_KEM_MLKEM768_ECDH_BRAINPOOLP256R1),
            ("CKP_COMP_KEM_MLKEM1024_RSA3072", CKP_COMP_KEM_MLKEM1024_RSA3072),
            ("CKP_COMP_KEM_MLKEM1024_ECDH_P384", CKP_COMP_KEM_MLKEM1024_ECDH_P384),
            ("CKP_COMP_KEM_MLKEM1024_ECDH_BRAINPOOLP384R1", CKP_COMP_KEM_MLKEM1024_ECDH_BRAINPOOLP384R1),
            ("CKP_COMP_KEM_MLKEM1024_X448", CKP_COMP_KEM_MLKEM1024_X448),
            ("CKP_COMP_KEM_MLKEM1024_ECDH_P521", CKP_COMP_KEM_MLKEM1024_ECDH_P521),
        ];
        let header = header_values();
        let engine_names: BTreeSet<&str> = engine.iter().map(|(n, _)| *n).collect();
        let header_names: BTreeSet<&str> = header.keys().map(String::as_str).collect();
        assert_eq!(engine_names, header_names, "engine and header extract name different identifier sets");
        for (name, value) in engine {
            assert_eq!(header[*name], *value, "{name}: engine 0x{value:x} != TC header 0x{:x}", header[*name]);
        }
        // The extract records the header's own alias, not just equal values.
        let v = json(IDENTIFIERS);
        let alias = v["identifiers"].as_array().unwrap().iter().find(|e| e["name"] == "CKA_HSS_KEYS_REMAINING").unwrap();
        assert_eq!(alias["alias_of"], "CKA_KEYS_REMAINING");
    }

    /// Each row's CKP value is the header value of the identifier whose name
    /// is the draft's algorithm name (`id-` dropped, `-` → `_`, upper case,
    /// and for KEM the `-SHA3-256` suffix dropped). Ties the header to the
    /// draft row by name, so a row cannot carry another set's CKP value.
    #[test]
    fn composite_rows_ckp_match_header_by_name() {
        let header = header_values();
        for p in &COMPOSITE_SIG_SETS {
            let n = format!("CKP_COMP_SIG_{}", p.name.trim_start_matches("id-").replace('-', "_").to_uppercase());
            assert_eq!(header.get(&n), Some(&p.ckp), "{}", p.name);
        }
        for p in &COMPOSITE_KEM_SETS {
            let base = p.name.trim_start_matches("id-").trim_end_matches("-SHA3-256");
            let n = format!("CKP_COMP_KEM_{}", base.replace('-', "_").to_uppercase());
            assert_eq!(header.get(&n), Some(&p.ckp), "{}", p.name);
        }
    }

    #[test]
    fn composite_table_has_18_sig_and_12_kem_rows_with_unique_keys() {
        assert_eq!(COMPOSITE_SIG_SETS.len(), 18);
        assert_eq!(COMPOSITE_KEM_SETS.len(), 12);
        let sig_ckp: BTreeSet<u32> = COMPOSITE_SIG_SETS.iter().map(|p| p.ckp).collect();
        let kem_ckp: BTreeSet<u32> = COMPOSITE_KEM_SETS.iter().map(|p| p.ckp).collect();
        assert_eq!(sig_ckp, (1..=18).collect());
        assert_eq!(kem_ckp, (1..=12).collect());
        let oids: BTreeSet<&str> =
            COMPOSITE_SIG_SETS.iter().map(|p| p.oid).chain(COMPOSITE_KEM_SETS.iter().map(|p| p.oid)).collect();
        assert_eq!(oids.len(), 30);
        let labels: BTreeSet<&[u8]> =
            COMPOSITE_SIG_SETS.iter().map(|p| p.label).chain(COMPOSITE_KEM_SETS.iter().map(|p| p.label)).collect();
        assert_eq!(labels.len(), 30);
        // Brainpool is the only unsupported family for now.
        let unsupported: Vec<&str> = COMPOSITE_SIG_SETS
            .iter()
            .filter(|p| !p.supported)
            .map(|p| p.name)
            .chain(COMPOSITE_KEM_SETS.iter().filter(|p| !p.supported).map(|p| p.name))
            .collect();
        assert_eq!(unsupported.len(), 4);
        assert!(unsupported.iter().all(|n| n.contains("brainpool")), "{unsupported:?}");
    }

    fn draft_size(v: &Value) -> Size {
        let n = v["bytes"].as_u64().unwrap() as usize;
        if v["max"].as_bool().unwrap() {
            Size::Max(n)
        } else {
            Size::Exact(n)
        }
    }

    fn trad_hash_name(h: TradHash) -> &'static str {
        match h {
            TradHash::Sha256 => "SHA256",
            TradHash::Sha384 => "SHA384",
            TradHash::Sha512 => "SHA512",
        }
    }

    fn curve_name(c: EcCurve) -> &'static str {
        match c {
            EcCurve::P256 => "secp256r1",
            EcCurve::P384 => "secp384r1",
            EcCurve::P521 => "secp521r1",
            EcCurve::BrainpoolP256r1 => "brainpoolP256r1",
            EcCurve::BrainpoolP384r1 => "brainpoolP384r1",
        }
    }

    /// Every signature row against composite-sigs-19 §2.2, §6, §6.1 and
    /// Appendix A, via the committed extract.
    #[test]
    fn composite_sig_rows_match_draft19_extract() {
        let v = json(SIG_FACTS);
        assert_eq!(v["_provenance"]["draft"], "draft-ietf-lamps-pq-composite-sigs-19");
        assert_eq!(
            v["_provenance"]["sha256"],
            "b4ee04416efc26e7d8de7c740dc3848ffe8b8cc9dcd035ad9d4e33e18844ec83"
        );
        assert_eq!(v["prefix_hex"].as_str().unwrap().to_lowercase(), hex(COMPOSITE_SIG_PREFIX));
        for (lvl, ckp) in [("44", CKP_ML_DSA_44), ("65", CKP_ML_DSA_65), ("87", CKP_ML_DSA_87)] {
            let t = &v["ml_dsa_sizes"][format!("id-ML-DSA-{lvl}")];
            assert_eq!(t["public_key"], ml_dsa_sizes(ckp).0 as u64);
            assert_eq!(t["signature"], ml_dsa_sizes(ckp).1 as u64);
            assert_eq!(t["private_key"], MLDSA_SEED_LEN as u64);
        }
        let pss = &v["rsassa_pss"];
        assert_eq!(pss["2048_3072"]["hash"], trad_hash_name(PSS_2048_3072));
        assert_eq!(pss["2048_3072"]["mgf1_hash"], trad_hash_name(PSS_2048_3072));
        assert_eq!(pss["2048_3072"]["salt_length"], PSS_2048_3072_SALT as u64);
        assert_eq!(pss["4096"]["hash"], trad_hash_name(PSS_4096));
        assert_eq!(pss["4096"]["mgf1_hash"], trad_hash_name(PSS_4096));
        assert_eq!(pss["4096"]["salt_length"], PSS_4096_SALT as u64);

        let rows = v["algorithms"].as_array().unwrap();
        assert_eq!(rows.len(), COMPOSITE_SIG_SETS.len());
        for (d, p) in rows.iter().zip(COMPOSITE_SIG_SETS.iter()) {
            let name = p.name;
            assert_eq!(d["name"], name, "row order");
            assert_eq!(d["oid"], p.oid, "{name} OID");
            assert_eq!(d["label"].as_str().unwrap().as_bytes(), p.label, "{name} label");
            let ph = match p.pre_hash {
                PreHash::Sha256 => "SHA256",
                PreHash::Sha512 => "SHA512",
                PreHash::Shake256_64 => "SHAKE256/64",
            };
            assert_eq!(d["pre_hash"], ph, "{name} PH");
            let lvl = match p.ml_dsa {
                CKP_ML_DSA_44 => "ML-DSA-44",
                CKP_ML_DSA_65 => "ML-DSA-65",
                _ => "ML-DSA-87",
            };
            assert_eq!(d["ml_dsa"], lvl, "{name} ML-DSA");
            let alg = d["traditional_signature_algorithm"].as_str().unwrap();
            match p.classical {
                SigClassical::RsaPss { modulus_bits, hash, salt_len } => {
                    assert_eq!(alg, "id-RSASSA-PSS", "{name}");
                    assert_eq!(d["rsa_size"], modulus_bits.to_string(), "{name}");
                    let (table, h, s) = if modulus_bits == 4096 {
                        ("See Table 3", PSS_4096, PSS_4096_SALT)
                    } else {
                        ("See Table 2", PSS_2048_3072, PSS_2048_3072_SALT)
                    };
                    assert_eq!(d["rsassa_pss_parameters"], table, "{name}");
                    assert_eq!((hash, salt_len), (h, s), "{name}");
                }
                SigClassical::RsaPkcs15 { modulus_bits, hash } => {
                    assert_eq!(alg, format!("{}WithRSAEncryption", trad_hash_name(hash).to_lowercase()), "{name}");
                    assert_eq!(d["rsa_size"], modulus_bits.to_string(), "{name}");
                }
                SigClassical::Ecdsa { curve, hash } => {
                    assert_eq!(alg, format!("ecdsa-with-{}", trad_hash_name(hash)), "{name}");
                    assert_eq!(d["ecdsa_curve"], curve_name(curve), "{name}");
                    assert_eq!(p.classical_sizes.public_key, Size::Exact(curve.uncompressed_point_len()), "{name}");
                }
                SigClassical::Ed25519 => assert_eq!(alg, "id-Ed25519", "{name}"),
                SigClassical::Ed448 => assert_eq!(alg, "id-Ed448", "{name}"),
            }
            if let SigClassical::RsaPss { modulus_bits, .. } | SigClassical::RsaPkcs15 { modulus_bits, .. } =
                p.classical
            {
                assert_eq!(p.classical_sizes.output, Size::Exact(modulus_bits as usize / 8), "{name}");
            }
            let m = &d["max_sizes"];
            assert_eq!(p.public_key_size(), draft_size(&m["public_key"]), "{name} public key");
            assert_eq!(p.private_key_size(), draft_size(&m["private_key"]), "{name} private key");
            assert_eq!(p.signature_size(), draft_size(&m["signature"]), "{name} signature");
        }
    }

    /// Every KEM row against composite-kem-23 §3.4, §6, §6.1 and Appendix A,
    /// via the committed extract.
    #[test]
    fn composite_kem_rows_match_draft23_extract() {
        let v = json(KEM_FACTS);
        assert_eq!(v["_provenance"]["draft"], "draft-ietf-lamps-pq-composite-kem-23");
        assert_eq!(
            v["_provenance"]["sha256"],
            "aaaffdf5eca9cf8e2757e2fd4257a30536f2c6ead7c6eb24f542fcc8b28e26b8"
        );
        assert_eq!(v["combiner"], "ss = SHA3-256(mlkemSS || tradSS || tradCT || tradPK || Label)");
        assert_eq!(v["rsa_oaep"]["hash"], "SHA256");
        assert_eq!(v["rsa_oaep"]["mgf1_hash"], "SHA256");
        for (lvl, ckp) in [("768", CKP_ML_KEM_768), ("1024", CKP_ML_KEM_1024)] {
            let t = &v["ml_kem_sizes"][format!("id-alg-ml-kem-{lvl}")];
            assert_eq!(t["public_key"], ml_kem_sizes(ckp).0 as u64);
            assert_eq!(t["ciphertext"], ml_kem_sizes(ckp).1 as u64);
            assert_eq!(t["private_key"], MLKEM_SEED_LEN as u64);
        }

        let rows = v["algorithms"].as_array().unwrap();
        assert_eq!(rows.len(), COMPOSITE_KEM_SETS.len());
        for (d, p) in rows.iter().zip(COMPOSITE_KEM_SETS.iter()) {
            let name = p.name;
            assert_eq!(d["name"], name, "row order");
            assert_eq!(d["oid"], p.oid, "{name} OID");
            assert_eq!(d["label_hex"], hex(p.label), "{name} label");
            let lvl = if p.ml_kem == CKP_ML_KEM_768 { "ML-KEM-768" } else { "ML-KEM-1024" };
            assert_eq!(d["ml_kem"], lvl, "{name} ML-KEM");
            let alg = d["traditional_kem_algorithm"].as_str().unwrap();
            match p.classical {
                KemClassical::RsaOaep { modulus_bits } => {
                    assert_eq!(alg, "id-RSAES-OAEP", "{name}");
                    assert_eq!(d["rsa_size"], modulus_bits.to_string(), "{name}");
                    assert_eq!(p.classical_sizes.output, Size::Exact(modulus_bits as usize / 8), "{name}");
                }
                KemClassical::Ecdh { curve } => {
                    assert_eq!(alg, "id-ecDH", "{name}");
                    assert_eq!(d["ecdh_curve"], curve_name(curve), "{name}");
                    let point = Size::Exact(curve.uncompressed_point_len());
                    assert_eq!((p.classical_sizes.public_key, p.classical_sizes.output), (point, point), "{name}");
                }
                KemClassical::X25519 => assert_eq!(alg, "id-X25519", "{name}"),
                KemClassical::X448 => assert_eq!(alg, "id-X448", "{name}"),
            }
            let m = &d["max_sizes"];
            assert_eq!(p.public_key_size(), draft_size(&m["public_key"]), "{name} public key");
            assert_eq!(p.private_key_size(), draft_size(&m["private_key"]), "{name} private key");
            assert_eq!(p.ciphertext_size(), draft_size(&m["ciphertext"]), "{name} ciphertext");
            assert_eq!(m["shared_secret"]["bytes"], COMPOSITE_KEM_SS_LEN as u64, "{name} SS");
        }
    }

    /// The LAMPS composite-KEM test vectors (lamps-wg/draft-composite-kem
    /// src/testvectors.json at d77e75420034d826e14cbef0b779986511f114e9) name
    /// the 12 composite sets by these tcIds, with these decoded `ek`, `dk`
    /// and `c` lengths — values read from that file, recorded here as facts.
    /// The table's names and sizes must agree with the vectors the KAT step
    /// will run.
    #[test]
    fn composite_kem_rows_match_lamps_vector_tcids_and_lengths() {
        let vectors: [(&str, usize, usize, usize); 12] = [
            ("id-MLKEM768-RSA2048-SHA3-256", 1454, 1255, 1344),
            ("id-MLKEM768-RSA3072-SHA3-256", 1582, 1831, 1472),
            ("id-MLKEM768-RSA4096-SHA3-256", 1710, 2412, 1600),
            ("id-MLKEM768-X25519-SHA3-256", 1216, 96, 1120),
            ("id-MLKEM768-ECDH-P256-SHA3-256", 1249, 115, 1153),
            ("id-MLKEM768-ECDH-P384-SHA3-256", 1281, 128, 1185),
            ("id-MLKEM768-ECDH-brainpoolP256r1-SHA3-256", 1249, 116, 1153),
            ("id-MLKEM1024-RSA3072-SHA3-256", 1966, 1831, 1952),
            ("id-MLKEM1024-ECDH-P384-SHA3-256", 1665, 128, 1665),
            ("id-MLKEM1024-ECDH-brainpoolP384r1-SHA3-256", 1665, 132, 1665),
            ("id-MLKEM1024-X448-SHA3-256", 1624, 120, 1624),
            ("id-MLKEM1024-ECDH-P521-SHA3-256", 1701, 146, 1701),
        ];
        for ((tc, ek, dk, c), p) in vectors.iter().zip(COMPOSITE_KEM_SETS.iter()) {
            assert_eq!(*tc, p.name);
            assert!(p.public_key_size().admits(*ek), "{tc} ek {ek} vs {:?}", p.public_key_size());
            assert!(p.private_key_size().admits(*dk), "{tc} dk {dk} vs {:?}", p.private_key_size());
            assert!(p.ciphertext_size().admits(*c), "{tc} c {c} vs {:?}", p.ciphertext_size());
        }
    }

    /// The 8 signature profiles KMIP implements today
    /// (`kmip/src/ops/composite_sig.rs`, profile constants: `oid`, `label`,
    /// `signature_label`, `pre_hash_mech`, `mldsa_param_set`,
    /// `mldsa_sig_bytes`, `mldsa_pubkey_bytes`, `classical_sign_mech`)
    /// agree with this table. Values copied from that file; when KMIP moves
    /// onto this table the copy goes away.
    #[test]
    fn composite_table_agrees_with_kmip_profiles() {
        struct Kmip {
            oid: &'static str,
            label: &'static str,
            signature_label: &'static str,
            pre_hash_mech: u32,
            mldsa_param_set: u32,
            mldsa_sig_bytes: usize,
            mldsa_pubkey_bytes: usize,
            classical_sign_mech: u32,
        }
        let kmip = [
            Kmip {
                oid: "1.3.6.1.5.5.7.6.37",
                label: "id-MLDSA44-RSA2048-PSS-SHA256",
                signature_label: "COMPSIG-MLDSA44-RSA2048-PSS-SHA256",
                pre_hash_mech: CKM_SHA256,
                mldsa_param_set: CKP_ML_DSA_44,
                mldsa_sig_bytes: 2420,
                mldsa_pubkey_bytes: 1312,
                classical_sign_mech: CKM_SHA256_RSA_PKCS_PSS,
            },
            Kmip {
                oid: "1.3.6.1.5.5.7.6.45",
                label: "id-MLDSA65-ECDSA-P256-SHA512",
                signature_label: "COMPSIG-MLDSA65-ECDSA-P256-SHA512",
                pre_hash_mech: CKM_SHA512,
                mldsa_param_set: CKP_ML_DSA_65,
                mldsa_sig_bytes: 3309,
                mldsa_pubkey_bytes: 1952,
                classical_sign_mech: CKM_ECDSA_SHA256,
            },
            Kmip {
                oid: "1.3.6.1.5.5.7.6.49",
                label: "id-MLDSA87-ECDSA-P384-SHA512",
                signature_label: "COMPSIG-MLDSA87-ECDSA-P384-SHA512",
                pre_hash_mech: CKM_SHA512,
                mldsa_param_set: CKP_ML_DSA_87,
                mldsa_sig_bytes: 4627,
                mldsa_pubkey_bytes: 2592,
                classical_sign_mech: CKM_ECDSA_SHA384,
            },
            Kmip {
                oid: "1.3.6.1.5.5.7.6.39",
                label: "id-MLDSA44-Ed25519-SHA512",
                signature_label: "COMPSIG-MLDSA44-Ed25519-SHA512",
                pre_hash_mech: CKM_SHA512,
                mldsa_param_set: CKP_ML_DSA_44,
                mldsa_sig_bytes: 2420,
                mldsa_pubkey_bytes: 1312,
                classical_sign_mech: CKM_EDDSA,
            },
            Kmip {
                oid: "1.3.6.1.5.5.7.6.40",
                label: "id-MLDSA44-ECDSA-P256-SHA256",
                signature_label: "COMPSIG-MLDSA44-ECDSA-P256-SHA256",
                pre_hash_mech: CKM_SHA256,
                mldsa_param_set: CKP_ML_DSA_44,
                mldsa_sig_bytes: 2420,
                mldsa_pubkey_bytes: 1312,
                classical_sign_mech: CKM_ECDSA_SHA256,
            },
            Kmip {
                oid: "1.3.6.1.5.5.7.6.41",
                label: "id-MLDSA65-RSA3072-PSS-SHA512",
                signature_label: "COMPSIG-MLDSA65-RSA3072-PSS-SHA512",
                pre_hash_mech: CKM_SHA512,
                mldsa_param_set: CKP_ML_DSA_65,
                mldsa_sig_bytes: 3309,
                mldsa_pubkey_bytes: 1952,
                classical_sign_mech: CKM_SHA256_RSA_PKCS_PSS,
            },
            Kmip {
                oid: "1.3.6.1.5.5.7.6.48",
                label: "id-MLDSA65-Ed25519-SHA512",
                signature_label: "COMPSIG-MLDSA65-Ed25519-SHA512",
                pre_hash_mech: CKM_SHA512,
                mldsa_param_set: CKP_ML_DSA_65,
                mldsa_sig_bytes: 3309,
                mldsa_pubkey_bytes: 1952,
                classical_sign_mech: CKM_EDDSA,
            },
            Kmip {
                oid: "1.3.6.1.5.5.7.6.46",
                label: "id-MLDSA65-ECDSA-P384-SHA512",
                signature_label: "COMPSIG-MLDSA65-ECDSA-P384-SHA512",
                pre_hash_mech: CKM_SHA512,
                mldsa_param_set: CKP_ML_DSA_65,
                mldsa_sig_bytes: 3309,
                mldsa_pubkey_bytes: 1952,
                classical_sign_mech: CKM_ECDSA_SHA384,
            },
        ];
        for k in &kmip {
            let Some(CompositeParams::Sig(p)) = params_by_oid(k.oid) else {
                panic!("{}: no signature row for KMIP OID", k.label)
            };
            assert_eq!(p.name, k.label);
            assert_eq!(p.label, k.signature_label.as_bytes(), "{}", k.label);
            let ph = match p.pre_hash {
                PreHash::Sha256 => CKM_SHA256,
                PreHash::Sha512 => CKM_SHA512,
                PreHash::Shake256_64 => panic!("{}: KMIP has no SHAKE profile", k.label),
            };
            assert_eq!(ph, k.pre_hash_mech, "{}", k.label);
            assert_eq!(p.ml_dsa, k.mldsa_param_set, "{}", k.label);
            assert_eq!(p.ml_dsa_signature_len(), k.mldsa_sig_bytes, "{}", k.label);
            assert_eq!(p.ml_dsa_public_key_len(), k.mldsa_pubkey_bytes, "{}", k.label);
            let classical = match p.classical {
                SigClassical::RsaPss { hash: TradHash::Sha256, .. } => CKM_SHA256_RSA_PKCS_PSS,
                SigClassical::Ecdsa { hash: TradHash::Sha256, .. } => CKM_ECDSA_SHA256,
                SigClassical::Ecdsa { hash: TradHash::Sha384, .. } => CKM_ECDSA_SHA384,
                SigClassical::Ed25519 => CKM_EDDSA,
                other => panic!("{}: unexpected classical {other:?}", k.label),
            };
            assert_eq!(classical, k.classical_sign_mech, "{}", k.label);
            assert!(p.supported, "{}", k.label);
        }
    }

    #[test]
    fn composite_lookups() {
        // CKP values overlap across families; the family decides.
        let s = params_by_ckp(CompositeFamily::Sig, 4).unwrap();
        let k = params_by_ckp(CompositeFamily::Kem, 4).unwrap();
        assert_eq!(s.oid(), "1.3.6.1.5.5.7.6.40");
        assert_eq!(k.oid(), "1.3.6.1.5.5.7.6.58");
        assert_eq!(params_for_key(CKK_COMP_SIG, 4), Some(s));
        assert_eq!(params_for_key(CKK_COMP_KEM, 4), Some(k));
        assert_eq!(params_for_key(CKK_ML_DSA, 4), None);
        assert_eq!(params_by_ckp(CompositeFamily::Sig, 0), None);
        assert_eq!(params_by_ckp(CompositeFamily::Sig, 19), None);
        assert_eq!(params_by_ckp(CompositeFamily::Kem, 13), None);
        for p in &COMPOSITE_SIG_SETS {
            assert_eq!(params_by_oid(p.oid), Some(CompositeParams::Sig(p)));
            assert_eq!(sig_params(p.ckp), Some(p));
        }
        for p in &COMPOSITE_KEM_SETS {
            assert_eq!(params_by_oid(p.oid), Some(CompositeParams::Kem(p)));
            assert_eq!(kem_params(p.ckp), Some(p));
            assert_eq!(params_by_oid(p.oid).unwrap().family(), CompositeFamily::Kem);
        }
        assert_eq!(params_by_oid("1.3.6.1.5.5.7.6.36"), None);
        assert_eq!(params_by_oid("1.3.6.1.5.5.7.6.67"), None);
        assert_eq!(CompositeFamily::from_key_type(CKK_COMP_KEM).map(|f| f.key_type()), Some(CKK_COMP_KEM));
        assert_eq!(kem_params(CKP_COMP_KEM_MLKEM768_X25519).unwrap().label, b"\\.//^\\");
        assert_eq!(sig_params(CKP_COMP_SIG_MLDSA87_ED448_SHAKE256).unwrap().pre_hash.output_len(), 64);
        assert!(Size::Max(10).admits(9) && !Size::Exact(10).admits(9));
    }
}
