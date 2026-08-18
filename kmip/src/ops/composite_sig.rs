//! LAMPS composite-signature support (draft-ietf-lamps-pq-composite-
//! sigs-19) — the profile table + message-representative builder shared
//! by `certify.rs`'s composite issuance path and `validate.rs`'s
//! composite verification path.
//!
//! ## Scope discipline (invariant 0a — no crypto in kmip, only encoding)
//!
//! This file does exactly two things, both encoding:
//! 1. Look up a composite algorithm's fixed profile constants (OIDs,
//!    label, split point) — plain data, no computation.
//! 2. Assemble the draft-19 §2.2 message representative `M' = Prefix ||
//!    Label || len(ctx) || ctx || PH(TBS)` — byte concatenation. The one
//!    hash in that formula (`PH`) is NOT computed locally: it goes
//!    through `softhsmrustv3::native::digest` (the same engine primitive
//!    `certify.rs::store_certificate`'s digest_value uses), exactly like
//!    every other cryptographic primitive in this crate.
//!
//! Neither the ML-DSA half nor the classical half is signed or verified
//! here — that's `certify.rs`/`validate.rs`'s job, calling
//! `native::sign_pqc`/`native::verify_pqc` (which already accept a
//! context-string parameter — no new engine primitive was needed; K18's
//! `Sign` op wiring in `ops/sign.rs` already exercises the same
//! `native::sign_pqc(..., ctx, ...)` shape this file's callers reuse) and
//! `native::sign_with_pss_salt`/`native::sign`/`verify` for the classical
//! half.
//!
//! ## Reference material
//!
//! Ported from the hub's own `certBuilder.ts::buildCompositeCertDraft19`/
//! `buildCompositeMessageRepresentative`/`COMPOSITE_PROFILE_MLDSA*`
//! constants — the OID values, the exact M' byte layout, and the
//! per-profile pre-hash/split-length table are copied from there, not
//! re-derived from the draft text (see the composite/hybrid remediation
//! plan §2 for why: `certBuilder.ts` is already a tested, spec-cited
//! reference implementation; the wire format is independently
//! corroborated by `pkcs11-provider/src/composite.c`, a separate TLS-
//! composite-sig initiative that computes the identical M').

use spki::SubjectPublicKeyInfoOwned;

use crate::error::{KmipError, Result, ResultReason};
use crate::kmip30::KmipAlgorithm;


/// Fixed Prefix per draft-19 §2.2 — ASCII "CompositeAlgorithmSignatures2025",
/// byte-identical to `certBuilder.ts::COMPOSITE_DRAFT19_PREFIX` (verified
/// there against the draft's own worked examples).
const PREFIX: &[u8] = b"CompositeAlgorithmSignatures2025";

/// RFC 8410 fixes the Ed25519 public key at 32 raw bytes, RFC 8032 fixes the
/// signature at 64. Unlike ECDSA and RSA both are exact, so a wrong length is
/// a conformance failure the verifier can state outright (draft §3.3 step 2).
const ED25519_PUBKEY_BYTES: usize = 32;
const ED25519_SIG_BYTES: usize = 64;

/// Modulus bit length of a DER `RSAPublicKey` (RFC 8017 §A.1.1), for the
/// draft §6 "RSA size" check.
///
/// Parsed here rather than via the engine because this is pure encoding, not
/// crypto (invariant 0a): read `SEQUENCE { modulus INTEGER, .. }` and measure
/// the first INTEGER's magnitude. ASN.1 INTEGER is signed, so an RSA modulus —
/// whose top bit is always set — always carries a leading 0x00 pad; counting
/// that byte would report 2048 bits as 2056 and fail every conformant key.
fn rsa_public_key_modulus_bits(rsa_public_key_der: &[u8]) -> Result<u32> {
    let bad = |why: &str| {
        KmipError::failed(
            ResultReason::CryptographicFailure,
            format!("composite RSA classical key is not a parseable DER RSAPublicKey: {why}"),
        )
    };
    // Minimal TLV reader: enough for SEQUENCE { INTEGER, INTEGER } and no more.
    fn read_tlv(b: &[u8], off: usize) -> Option<(u8, &[u8], usize)> {
        let tag = *b.get(off)?;
        let first = *b.get(off + 1)?;
        let (len, mut p) = if first & 0x80 == 0 {
            (first as usize, off + 2)
        } else {
            let n = (first & 0x7f) as usize;
            if n == 0 || n > 4 {
                return None;
            }
            let mut len = 0usize;
            for i in 0..n {
                len = len.checked_mul(256)?.checked_add(*b.get(off + 2 + i)? as usize)?;
            }
            (len, off + 2 + n)
        };
        let value = b.get(p..p.checked_add(len)?)?;
        p += len;
        Some((tag, value, p))
    }

    let (tag, seq, _) = read_tlv(rsa_public_key_der, 0).ok_or_else(|| bad("truncated outer TLV"))?;
    if tag != 0x30 {
        return Err(bad("outer element is not a SEQUENCE"));
    }
    let (mtag, modulus, _) = read_tlv(seq, 0).ok_or_else(|| bad("truncated modulus"))?;
    if mtag != 0x02 {
        return Err(bad("modulus is not an INTEGER"));
    }
    let magnitude = modulus.iter().position(|&b| b != 0).map_or(&modulus[0..0], |i| &modulus[i..]);
    if magnitude.is_empty() {
        return Err(bad("modulus is zero"));
    }
    Ok(((magnitude.len() - 1) * 8 + (8 - magnitude[0].leading_zeros() as usize)) as u32)
}

/// One LAMPS draft-19 §6 composite-sig profile. Every field is ported
/// verbatim from `certBuilder.ts`'s `CompositeProfileDraft19` — see that
/// file's own doc comment for the field-by-field spec citations.
pub struct CompositeSigProfile {
    /// Composite AlgorithmIdentifier OID (used for BOTH the TBS
    /// `signature` field and `signatureAlgorithm` — X.509 requires they
    /// match — and, with the composite public key, `subjectPublicKeyInfo.
    /// algorithm`; draft-19 has no separate SPKI-vs-signature OID split
    /// the way classical RSA/ECDSA do, unlike single-algorithm certs).
    pub oid: &'static str,
    /// `id-MLDSAxx-...` label (draft-19 §6), used only in error messages.
    pub label: &'static str,
    /// Signature label — part of M' AND the ML-DSA `ctx` parameter (FIPS
    /// 204 Algorithm 2). Passed to `native::sign_pqc`/`verify_pqc`
    /// verbatim; `certBuilder.ts`'s doc comment stresses this is
    /// security-critical, not optional (draft-19 §9.2.3 weak/strong
    /// non-separability).
    pub signature_label: &'static str,
    /// Pre-hash mechanism for `PH(TBS)` — routed through
    /// `native::digest`, never computed locally.
    pub pre_hash_mech: u32,
    /// ML-DSA parameter set (`CKP_ML_DSA_44/65/87`) for keygen/sign/
    /// verify dispatch.
    pub mldsa_param_set: u32,
    /// Exact ML-DSA signature length in bytes (FIPS 204 Table 1) — the
    /// split point `mldsaSig || classicalSig` verification uses, and the
    /// value issuance asserts the engine actually returned (mirrors
    /// `certBuilder.ts`'s own length check).
    pub mldsa_sig_bytes: usize,
    /// Exact ML-DSA raw public key length in bytes (FIPS 204 Table 1:
    /// 1312/1952/2592 for 44/65/87) — the split point
    /// `mldsaPubKey || classicalPubKey` verification uses to recover each
    /// component's raw key bytes from a composite SPKI.
    pub mldsa_pubkey_bytes: usize,
    /// Classical component: engine keygen mechanism.
    pub classical_keygen_mech: u32,
    /// Classical component: engine sign/verify mechanism. Per draft §3.2,
    /// the classical algorithm signs M' using its OWN standard
    /// hash-then-sign convention — M' is the "message" from the classical
    /// algorithm's point of view, not a pre-hashed digest to sign raw.
    /// This mechanism is therefore the ordinary hash-composite one
    /// (`CKM_ECDSA_SHA256`, `CKM_ECDSA_SHA384`, `CKM_SHA256_RSA_PKCS_PSS`),
    /// not a raw/no-hash variant.
    ///
    /// The hash here comes from §6's "Traditional Signature Algorithm" for
    /// the profile and pairs with the CURVE (P-256 → SHA-256, P-384 →
    /// SHA-384). It is NOT the `SHA512` in the profile name — that is the
    /// pre-hash PH applied when building M'. This doc previously gave
    /// "ECDSA-with-SHA512" as the example, matching a bug corrected
    /// 2026-08-17.
    pub classical_sign_mech: u32,
    /// Classical component's X.509 AlgorithmIdentifier OID (used only to
    /// resolve the EC curve for keygen — the outer cert never carries
    /// this OID directly, since the composite `oid` above covers both
    /// SPKI and signature).
    pub classical_oid: &'static str,
    /// The classical half's family and its draft §6 parameters.
    ///
    /// REPLACED `classical_ec_field_width: Option<usize>` on 2026-08-18.
    /// That field doubled as the family discriminator, with `None` meaning
    /// "RSA" — which worked only while RSA was the sole non-EC family. Draft
    /// §6 also defines Ed25519 profiles (.39, .48), which are equally
    /// non-EC, so `None` would have silently routed an Ed25519 profile into
    /// `create_key_pair.rs`'s RSA keygen arm. It also had nowhere to record
    /// an RSA modulus size, which §6 fixes per profile (2048 for .37, 3072
    /// for .41) and which the old code hard-coded to 2048 at the call site.
    ///
    /// The previous doc was right that nothing should infer the family from
    /// `classical_sign_mech` — a hash change silently breaks that. This goes
    /// further: the family is now stated outright rather than inferred from
    /// any field at all, and `match` exhaustiveness makes the compiler
    /// reject a new family that a consumer has not handled.
    pub classical: CompositeClassical,
}

/// Traditional (non-PQ) half of a composite profile, exactly as draft-19 §6
/// specifies it. Mirrors `certBuilder.ts`'s `CompositeClassicalSpec`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CompositeClassical {
    /// §6 "Traditional Algorithm: ECDSA".
    Ecdsa {
        /// Field width in bytes — 32 for P-256, 48 for P-384. Used for the
        /// raw↔DER `Ecdsa-Sig-Value` conversion: PKCS#11 `C_Sign` returns
        /// fixed-width `r||s`, while §4.1 requires DER (RFC 3279 §2.2.3).
        field_width: usize,
    },
    /// §6 "Traditional Signature Algorithm: id-RSASSA-PSS".
    RsaPss {
        /// §6 "RSA size" — normative and per-profile. §3.3 step 2 makes a
        /// component key "not of the correct type or length" an invalid
        /// signature, so this is a conformance requirement, not a default.
        modulus_bits: u32,
    },
    /// §6 "Traditional Signature Algorithm: id-Ed25519".
    ///
    /// PureEdDSA (RFC 8032 §5.1): signs M' whole and hashes internally with
    /// SHA-512, so there is no separate traditional hash to record. Both the
    /// key (32 B) and the signature (64 B) are raw fixed-length byte strings
    /// per RFC 8410 — notably NOT DER — so Ed25519 must stay out of the
    /// raw→DER conversion that ECDSA needs.
    Ed25519,
}

impl CompositeClassical {
    /// EC field width, or `None` for the non-EC families. Keeps call sites
    /// that genuinely want the width (raw↔DER conversion) unchanged, while
    /// leaving the family decision to an explicit `match`.
    pub fn ec_field_width(self) -> Option<usize> {
        match self {
            CompositeClassical::Ecdsa { field_width } => Some(field_width),
            _ => None,
        }
    }
}

const OID_MLDSA44_RSA2048_PSS_SHA256: &str = "1.3.6.1.5.5.7.6.37";
const OID_MLDSA65_ECDSA_P256_SHA512: &str = "1.3.6.1.5.5.7.6.45";
const OID_MLDSA87_ECDSA_P384_SHA512: &str = "1.3.6.1.5.5.7.6.49";
const OID_MLDSA44_ED25519_SHA512: &str = "1.3.6.1.5.5.7.6.39";
const OID_MLDSA44_ECDSA_P256_SHA256: &str = "1.3.6.1.5.5.7.6.40";
const OID_MLDSA65_RSA3072_PSS_SHA512: &str = "1.3.6.1.5.5.7.6.41";
const OID_MLDSA65_ED25519_SHA512: &str = "1.3.6.1.5.5.7.6.48";
const OID_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
const OID_EC_P256: &str = "1.2.840.10045.3.1.7";
const OID_EC_P384: &str = "1.3.132.0.34";
const OID_ED25519: &str = "1.3.101.112";

pub const MLDSA44_RSA2048_PSS_SHA256: CompositeSigProfile = CompositeSigProfile {
    oid: OID_MLDSA44_RSA2048_PSS_SHA256,
    label: "id-MLDSA44-RSA2048-PSS-SHA256",
    signature_label: "COMPSIG-MLDSA44-RSA2048-PSS-SHA256",
    pre_hash_mech: softhsmrustv3::constants::CKM_SHA256,
    mldsa_param_set: softhsmrustv3::constants::CKP_ML_DSA_44,
    mldsa_sig_bytes: 2420,
    mldsa_pubkey_bytes: 1312,
    classical_keygen_mech: softhsmrustv3::constants::CKM_RSA_PKCS_KEY_PAIR_GEN,
    classical_sign_mech: softhsmrustv3::constants::CKM_SHA256_RSA_PKCS_PSS,
    classical_oid: OID_RSA_ENCRYPTION,
    // §6 "RSA size: 2048" for this profile.
    classical: CompositeClassical::RsaPss { modulus_bits: 2048 },
};

pub const MLDSA65_ECDSA_P256_SHA512: CompositeSigProfile = CompositeSigProfile {
    oid: OID_MLDSA65_ECDSA_P256_SHA512,
    label: "id-MLDSA65-ECDSA-P256-SHA512",
    signature_label: "COMPSIG-MLDSA65-ECDSA-P256-SHA512",
    pre_hash_mech: softhsmrustv3::constants::CKM_SHA512,
    mldsa_param_set: softhsmrustv3::constants::CKP_ML_DSA_65,
    mldsa_sig_bytes: 3309,
    mldsa_pubkey_bytes: 1952,
    classical_keygen_mech: softhsmrustv3::constants::CKM_EC_KEY_PAIR_GEN,
    // draft-ietf-lamps-pq-composite-sigs §6 gives this profile
    // "Traditional Signature Algorithm: ecdsa-with-SHA256". The SHA512 in the
    // profile NAME is the pre-hash PH above, applied to the message when
    // building M' — it is NOT the traditional algorithm's hash, which tracks
    // the CURVE (P-256 -> SHA-256, P-384 -> SHA-384).
    // Corrected 2026-08-17: was CKM_ECDSA_SHA512, which produced signatures
    // that verified only against implementations sharing the same misreading.
    // Confirmed against the Bouncy Castle IETF Hackathon r5 trust anchor
    // (MLDSA65-ECDSA-P256-SHA512-1.3.6.1.5.5.7.6.45_ta.der), which verifies
    // under SHA-256 and fails under SHA-512.
    classical_sign_mech: softhsmrustv3::constants::CKM_ECDSA_SHA256,
    classical_oid: OID_EC_P256,
    classical: CompositeClassical::Ecdsa { field_width: 32 },
};

pub const MLDSA87_ECDSA_P384_SHA512: CompositeSigProfile = CompositeSigProfile {
    oid: OID_MLDSA87_ECDSA_P384_SHA512,
    label: "id-MLDSA87-ECDSA-P384-SHA512",
    signature_label: "COMPSIG-MLDSA87-ECDSA-P384-SHA512",
    pre_hash_mech: softhsmrustv3::constants::CKM_SHA512,
    mldsa_param_set: softhsmrustv3::constants::CKP_ML_DSA_87,
    mldsa_sig_bytes: 4627,
    mldsa_pubkey_bytes: 2592,
    classical_keygen_mech: softhsmrustv3::constants::CKM_EC_KEY_PAIR_GEN,
    // §6: "Traditional Signature Algorithm: ecdsa-with-SHA384" — the ECDSA
    // hash tracks the P-384 curve, not the SHA512 pre-hash in the name.
    // Corrected 2026-08-17 alongside the P-256 profile above.
    classical_sign_mech: softhsmrustv3::constants::CKM_ECDSA_SHA384,
    classical_oid: OID_EC_P384,
    classical: CompositeClassical::Ecdsa { field_width: 48 },
};

/// id-MLDSA44-Ed25519-SHA512 — draft §6, and one of the two profiles §10.4
/// recommends "when performance or bandwidth is a concern".
///
/// The pre-hash is SHA-512 rather than the SHA-256 the other ML-DSA-44
/// profiles use. That is deliberate per §6's note: for Ed25519 and Ed448 the
/// pre-hash matches the hash inside RFC 8032 itself, not the ML-DSA parameter
/// set.
pub const MLDSA44_ED25519_SHA512: CompositeSigProfile = CompositeSigProfile {
    oid: OID_MLDSA44_ED25519_SHA512,
    label: "id-MLDSA44-Ed25519-SHA512",
    signature_label: "COMPSIG-MLDSA44-Ed25519-SHA512",
    pre_hash_mech: softhsmrustv3::constants::CKM_SHA512,
    mldsa_param_set: softhsmrustv3::constants::CKP_ML_DSA_44,
    mldsa_sig_bytes: 2420,
    mldsa_pubkey_bytes: 1312,
    classical_keygen_mech: softhsmrustv3::constants::CKM_EC_EDWARDS_KEY_PAIR_GEN,
    // CKM_EDDSA, never CKM_EDDSA_PH: §6 specifies id-Ed25519, i.e. PureEdDSA
    // over M' itself. Pre-hashing M' would implement Ed25519ph, a different
    // algorithm that no §6 profile uses.
    classical_sign_mech: softhsmrustv3::constants::CKM_EDDSA,
    classical_oid: OID_ED25519,
    classical: CompositeClassical::Ed25519,
};

/// id-MLDSA44-ECDSA-P256-SHA256 — draft §6, §10.4 recommended.
///
/// The only profile where the pre-hash and the traditional hash are the SAME
/// (both SHA-256), which makes it the control case for the 2026-08-17
/// traditional-hash bug: an implementation that wrongly uses PH as the
/// traditional hash still produces a VALID certificate here and diverges only
/// on the profiles where the two differ.
pub const MLDSA44_ECDSA_P256_SHA256: CompositeSigProfile = CompositeSigProfile {
    oid: OID_MLDSA44_ECDSA_P256_SHA256,
    label: "id-MLDSA44-ECDSA-P256-SHA256",
    signature_label: "COMPSIG-MLDSA44-ECDSA-P256-SHA256",
    pre_hash_mech: softhsmrustv3::constants::CKM_SHA256,
    mldsa_param_set: softhsmrustv3::constants::CKP_ML_DSA_44,
    mldsa_sig_bytes: 2420,
    mldsa_pubkey_bytes: 1312,
    classical_keygen_mech: softhsmrustv3::constants::CKM_EC_KEY_PAIR_GEN,
    classical_sign_mech: softhsmrustv3::constants::CKM_ECDSA_SHA256,
    classical_oid: OID_EC_P256,
    classical: CompositeClassical::Ecdsa { field_width: 32 },
};

/// id-MLDSA65-RSA3072-PSS-SHA512 — draft §6, the profile §10.4 recommends
/// "when RSA is required" (note it points here, NOT at the RSA-2048 .37).
///
/// The RSA analogue of the traditional-hash trap: PH is SHA-512 while §6.1
/// Table 2 fixes the RSASSA-PSS hash at SHA-256 for both the 2048- and
/// 3072-bit levels. .37 cannot expose a mistake here — both of its hashes are
/// SHA-256 — so this is the profile where reusing PH as the PSS hash finally
/// shows up.
pub const MLDSA65_RSA3072_PSS_SHA512: CompositeSigProfile = CompositeSigProfile {
    oid: OID_MLDSA65_RSA3072_PSS_SHA512,
    label: "id-MLDSA65-RSA3072-PSS-SHA512",
    signature_label: "COMPSIG-MLDSA65-RSA3072-PSS-SHA512",
    pre_hash_mech: softhsmrustv3::constants::CKM_SHA512,
    mldsa_param_set: softhsmrustv3::constants::CKP_ML_DSA_65,
    mldsa_sig_bytes: 3309,
    mldsa_pubkey_bytes: 1952,
    classical_keygen_mech: softhsmrustv3::constants::CKM_RSA_PKCS_KEY_PAIR_GEN,
    // §6.1 Table 2: SHA-256 digest + MGF1-SHA-256 + 32-byte salt, at BOTH
    // 2048 and 3072 bits. NOT SHA-512 — that is the pre-hash above.
    classical_sign_mech: softhsmrustv3::constants::CKM_SHA256_RSA_PKCS_PSS,
    classical_oid: OID_RSA_ENCRYPTION,
    classical: CompositeClassical::RsaPss { modulus_bits: 3072 },
};

/// id-MLDSA65-Ed25519-SHA512 — draft §6, named by §10.4 for applications
/// concerned with SUF-CMA.
///
/// Read §9.2.2 before relying on that: the draft's own analysis concludes
/// Composite ML-DSA is NOT SUF-CMA secure against quantum adversaries and that
/// "applications where SUF-CMA security is critical SHOULD NOT use Composite
/// ML-DSA". Ed25519 removes ECDSA's trivial signature malleability, which is a
/// real improvement but not the full property.
pub const MLDSA65_ED25519_SHA512: CompositeSigProfile = CompositeSigProfile {
    oid: OID_MLDSA65_ED25519_SHA512,
    label: "id-MLDSA65-Ed25519-SHA512",
    signature_label: "COMPSIG-MLDSA65-Ed25519-SHA512",
    pre_hash_mech: softhsmrustv3::constants::CKM_SHA512,
    mldsa_param_set: softhsmrustv3::constants::CKP_ML_DSA_65,
    mldsa_sig_bytes: 3309,
    mldsa_pubkey_bytes: 1952,
    classical_keygen_mech: softhsmrustv3::constants::CKM_EC_EDWARDS_KEY_PAIR_GEN,
    classical_sign_mech: softhsmrustv3::constants::CKM_EDDSA,
    classical_oid: OID_ED25519,
    classical: CompositeClassical::Ed25519,
};

/// Every composite profile the engine implements. Single source for both
/// lookup directions below, so a new profile cannot be added to one and
/// forgotten in the other.
pub const ALL_PROFILES: [&CompositeSigProfile; 7] = [
    &MLDSA44_RSA2048_PSS_SHA256,
    &MLDSA44_ED25519_SHA512,
    &MLDSA44_ECDSA_P256_SHA256,
    &MLDSA65_RSA3072_PSS_SHA512,
    &MLDSA65_ECDSA_P256_SHA512,
    &MLDSA65_ED25519_SHA512,
    &MLDSA87_ECDSA_P384_SHA512,
];

/// Resolve a `KmipAlgorithm` composite variant to its profile. `None` for
/// every non-composite algorithm.
pub fn profile_for(algo: KmipAlgorithm) -> Option<&'static CompositeSigProfile> {
    match algo {
        KmipAlgorithm::CompositeMlDsa44Rsa2048PssSha256 => Some(&MLDSA44_RSA2048_PSS_SHA256),
        KmipAlgorithm::CompositeMlDsa44Ed25519Sha512 => Some(&MLDSA44_ED25519_SHA512),
        KmipAlgorithm::CompositeMlDsa44EcdsaP256Sha256 => Some(&MLDSA44_ECDSA_P256_SHA256),
        KmipAlgorithm::CompositeMlDsa65Rsa3072PssSha512 => Some(&MLDSA65_RSA3072_PSS_SHA512),
        KmipAlgorithm::CompositeMlDsa65EcdsaP256Sha512 => Some(&MLDSA65_ECDSA_P256_SHA512),
        KmipAlgorithm::CompositeMlDsa65Ed25519Sha512 => Some(&MLDSA65_ED25519_SHA512),
        KmipAlgorithm::CompositeMlDsa87EcdsaP384Sha512 => Some(&MLDSA87_ECDSA_P384_SHA512),
        _ => None,
    }
}

/// Resolve a profile from its composite OID string (the direction
/// `validate.rs` needs: an inbound certificate names the OID, not the
/// `KmipAlgorithm`).
pub fn profile_for_oid(oid: &str) -> Option<&'static CompositeSigProfile> {
    for p in ALL_PROFILES {
        if p.oid == oid {
            return Some(p);
        }
    }
    None
}

/// Build the draft-19 §2.2 message representative:
///   `M' = Prefix || Label || len(ctx) || ctx || PH(M)`
/// where `M` is the TBSCertificate DER and `PH` is the profile's
/// pre-hash, computed in the engine via `native::digest` — never a local
/// `sha2` call (invariant 0a). `ctx` must be ≤ 255 bytes (the length
/// prefix is a single byte, per draft-19 §2.2) — checked, not truncated.
/// No `Deps`/session parameter: `native::digest` is session-less by
/// design (hashing touches no key material or engine session state —
/// same reasoning the cert-ops plan's WP7-d already established for
/// `store_certificate`'s digest_value).
pub fn build_message_representative(
    profile: &CompositeSigProfile,
    tbs_der: &[u8],
    ctx: &[u8],
) -> Result<Vec<u8>> {
    if ctx.len() > 255 {
        return Err(KmipError::failed(
            ResultReason::InvalidField,
            format!(
                "composite-sig application context exceeds 255 bytes (got {}) for {}",
                ctx.len(),
                profile.label
            ),
        ));
    }
    let ph = softhsmrustv3::native::digest(profile.pre_hash_mech, tbs_der).map_err(|rv| {
        super::helpers::ck_rv_to_kmip_error(rv, "composite_sig:build_message_representative:digest")
    })?;

    let label = profile.signature_label.as_bytes();
    let mut out = Vec::with_capacity(PREFIX.len() + label.len() + 1 + ctx.len() + ph.len());
    out.extend_from_slice(PREFIX);
    out.extend_from_slice(label);
    out.push(ctx.len() as u8);
    out.extend_from_slice(ctx);
    out.extend_from_slice(&ph);
    Ok(out)
}

/// `Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }` — same shape
/// as `certify.rs`'s and `spki_verify.rs`'s own private copies (each of
/// those two files keeps its own rather than share one across a 3-way
/// split, per `spki_verify.rs`'s own module doc: "the two files read it
/// in opposite directions"; this is now a third reader, in a third
/// direction — decode only, for the classical half of a composite).
#[derive(der::Sequence)]
struct EcdsaSigValue<'a> {
    r: der::asn1::UintRef<'a>,
    s: der::asn1::UintRef<'a>,
}

fn ecdsa_der_to_raw(der_sig: &[u8], field_width: usize) -> Result<Vec<u8>> {
    use der::Decode;
    let sig = EcdsaSigValue::from_der(der_sig).map_err(|e| {
        KmipError::failed(ResultReason::CryptographicFailure, format!("composite classical (ECDSA) signature DER: {e}"))
    })?;
    let (r, s) = (sig.r.as_bytes(), sig.s.as_bytes());
    if r.len() > field_width || s.len() > field_width {
        return Err(KmipError::failed(
            ResultReason::CryptographicFailure,
            format!("composite classical (ECDSA) signature INTEGER wider than the {field_width}-byte curve field"),
        ));
    }
    let mut out = vec![0u8; field_width * 2];
    out[field_width - r.len()..field_width].copy_from_slice(r);
    out[field_width * 2 - s.len()..].copy_from_slice(s);
    Ok(out)
}

/// Destroys the transient engine object on drop — mirrors
/// `spki_verify.rs::DestroyOnDrop` exactly (a caller-supplied SPKI must
/// never linger in the engine's live object table after verification,
/// success or failure).
struct DestroyOnDrop {
    session: u32,
    handle: u32,
}

impl Drop for DestroyOnDrop {
    fn drop(&mut self) {
        let _ = softhsmrustv3::native::destroy_object(self.session, self.handle);
    }
}

/// Verify a composite signature: split `composite_spki`/`composite_sig`
/// at the profile's fixed ML-DSA lengths, recompute M' from `tbs_der`,
/// and verify BOTH components independently against their own public
/// keys — each transiently imported, verified, and destroyed (the same
/// discipline `spki_verify.rs::verify_with_spki` already uses for every
/// other algorithm, just executed twice here since `verify_with_spki`
/// itself can't be reused: its OID table hardcodes a hash-to-curve
/// pairing these composite profiles deliberately don't follow — see
/// [`CompositeSigProfile::classical_ec_field_width`]'s doc — and its
/// ML-DSA arm always verifies with an empty context, never a composite's
/// real `signature_label`).
///
/// Returns `Ok(SpkiVerdict::Valid)` only if BOTH components verify;
/// `Ok(SpkiVerdict::Invalid)` if either affirmatively fails; propagates
/// `Err` for a structural problem (malformed split, unparsable DER,
/// engine error) — `validate.rs`'s caller degrades an `Err` to `Unknown`
/// exactly like it already does for `verify_with_spki`, never surfacing
/// it as a false `Invalid`.
pub fn verify_composite_signature(
    session: Option<u32>,
    profile: &CompositeSigProfile,
    composite_spki: &SubjectPublicKeyInfoOwned,
    tbs_der: &[u8],
    composite_sig: &[u8],
) -> Result<super::spki_verify::SpkiVerdict> {
    use super::spki_verify::SpkiVerdict;
    use softhsmrustv3::constants::CKR_SIGNATURE_INVALID;

    // Part F §F7 — caller-resolved tenant session; see
    // `spki_verify::verify_with_spki`'s doc comment for why this is an
    // explicit parameter rather than a `deps.engine_session` read.
    let session = session.ok_or_else(|| {
        KmipError::failed(
            ResultReason::CryptographicFailure,
            "verify_composite_signature: no engine session — cannot verify without key material",
        )
    })?;

    let spki_raw = composite_spki.subject_public_key.raw_bytes();
    if spki_raw.len() <= profile.mldsa_pubkey_bytes {
        return Err(KmipError::failed(
            ResultReason::CryptographicFailure,
            format!(
                "{}: composite SPKI is {} bytes, too short for the {}-byte ML-DSA half plus a classical tail",
                profile.label, spki_raw.len(), profile.mldsa_pubkey_bytes
            ),
        ));
    }
    let (mldsa_pk, classical_pk) = spki_raw.split_at(profile.mldsa_pubkey_bytes);

    if composite_sig.len() <= profile.mldsa_sig_bytes {
        return Err(KmipError::failed(
            ResultReason::CryptographicFailure,
            format!(
                "{}: composite signature is {} bytes, too short for the {}-byte ML-DSA half plus a classical tail",
                profile.label, composite_sig.len(), profile.mldsa_sig_bytes
            ),
        ));
    }
    let (mldsa_sig, classical_sig_der) = composite_sig.split_at(profile.mldsa_sig_bytes);

    let mprime = build_message_representative(profile, tbs_der, &[])?;

    const TRANSIENT_ID: &[u8] = b"\x00";
    const TRANSIENT_LABEL: &str = "composite-verify-transient";

    // ── ML-DSA half ──────────────────────────────────────────────────
    let mldsa_handle = softhsmrustv3::native::register_ml_dsa_public_key(
        session, profile.mldsa_param_set, mldsa_pk, TRANSIENT_ID, TRANSIENT_LABEL,
    )
    .map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "verify_composite_signature:import-mldsa"))?;
    let mldsa_ok = {
        let _guard = DestroyOnDrop { session, handle: mldsa_handle };
        match softhsmrustv3::native::verify_pqc(
            session, mldsa_handle, softhsmrustv3::constants::CKM_ML_DSA, &mprime, mldsa_sig,
            profile.signature_label.as_bytes(), false, false,
        ) {
            Ok(()) => true,
            Err(rv) if rv == CKR_SIGNATURE_INVALID => false,
            Err(rv) => return Err(super::helpers::ck_rv_to_kmip_error(rv, "verify_composite_signature:verify-mldsa")),
        }
    };
    if !mldsa_ok {
        // A signature that affirmatively fails → Invalid, without even
        // touching the classical half (an ML-DSA-only attacker doesn't
        // get a free oracle on the classical component either).
        return Ok(SpkiVerdict::Invalid);
    }

    // ── Classical half ───────────────────────────────────────────────
    // EC: built via the engine's OWN `build_ec_spki_p256`/`p384` helpers
    // (`rust/src/crypto/handlers.rs`, already used by
    // `register_ecdsa_public_key`'s own callers elsewhere in the engine)
    // rather than hand-rolled — `SubjectPublicKeyInfoOwned{ oid:
    // classical_oid, parameters: None }` looks plausible but is actually
    // WRONG: an EC SPKI's algorithm OID is always id-ecPublicKey
    // (1.2.840.10045.2.1); the curve is the PARAMETERS field, decoded by
    // `register_ecdsa_public_key` itself
    // (`spki.algorithm.parameters.decode_as::<ObjectIdentifier>()`) — a
    // real bug caught by this file's own test actually running against
    // the engine, not by inspection.
    let (classical_handle, classical_native_sig) = match profile.classical {
        CompositeClassical::Ecdsa { field_width } => {
            let spki_der = match field_width {
                32 => softhsmrustv3::crypto::handlers::build_ec_spki_p256(classical_pk),
                48 => softhsmrustv3::crypto::handlers::build_ec_spki_p384(classical_pk),
                other => {
                    return Err(KmipError::failed(
                        ResultReason::CryptographicFailure,
                        format!("{}: no composite profile uses a {other}-byte EC field width", profile.label),
                    ))
                }
            };
            let h = softhsmrustv3::native::register_ecdsa_public_key(session, &spki_der, TRANSIENT_ID, TRANSIENT_LABEL)
                .map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "verify_composite_signature:import-classical"))?;
            (h, ecdsa_der_to_raw(classical_sig_der, field_width)?)
        }
        CompositeClassical::RsaPss { modulus_bits } => {
            // draft §6 fixes "RSA size" per profile, and §3.3 step 2 makes a
            // component key "not of the correct type or length for the given
            // component algorithm" an INVALID signature. So a certificate
            // claiming .41 while carrying a 2048-bit modulus must be rejected
            // — checked here because it is the only conformance property of
            // the RSA half that stays checkable regardless of the signature.
            let actual_bits = rsa_public_key_modulus_bits(classical_pk)?;
            if actual_bits != modulus_bits {
                return Ok(SpkiVerdict::Invalid);
            }
            // `register_rsa_public_key_der` accepts a bare PKCS#1
            // `RSAPublicKey` DER too (`RsaPublicKey::from_pkcs1_der`
            // fallback), so `classical_pk` — raw modulus||exponent-free
            // bytes are NOT what draft-19 carries here; the composite SPKI's
            // classical half for RSA is itself a full DER `RSAPublicKey`
            // (`SEQUENCE { modulus, publicExponent }`, RFC 8017 §A.1.1) per
            // `certBuilder.ts`'s own RSA composite handling — passed through
            // unwrapped, no AlgorithmIdentifier reconstruction needed.
            let h = softhsmrustv3::native::register_rsa_public_key_der(session, classical_pk, TRANSIENT_ID, TRANSIENT_LABEL)
                .map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "verify_composite_signature:import-classical"))?;
            (h, classical_sig_der.to_vec())
        }
        CompositeClassical::Ed25519 => {
            // RFC 8410: the composite carries the bare 32-byte public key and
            // RFC 8032 fixes the signature at 64 bytes — both raw, neither
            // DER, so there is no `ecdsa_der_to_raw` step and no length
            // ambiguity. Reject wrong lengths outright (§3.3 step 2 again)
            // rather than letting the engine fail opaquely.
            if classical_pk.len() != ED25519_PUBKEY_BYTES {
                return Ok(SpkiVerdict::Invalid);
            }
            if classical_sig_der.len() != ED25519_SIG_BYTES {
                return Ok(SpkiVerdict::Invalid);
            }
            // Built via the engine's own helper for the same reason the EC
            // arm does: `register_ed25519_public_key` parses a full SPKI and
            // checks the algorithm OID, so a raw 32-byte key handed to it
            // straight would be rejected as key-type-inconsistent.
            let spki_der = softhsmrustv3::crypto::handlers::build_ed25519_spki(classical_pk);
            let h = softhsmrustv3::native::register_ed25519_public_key(session, &spki_der, TRANSIENT_ID, TRANSIENT_LABEL)
                .map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "verify_composite_signature:import-classical"))?;
            (h, classical_sig_der.to_vec())
        }
    };
    let classical_ok = {
        let _guard = DestroyOnDrop { session, handle: classical_handle };
        softhsmrustv3::native::verify(session, classical_handle, profile.classical_sign_mech, &mprime, &classical_native_sig)
            .map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "verify_composite_signature:verify-classical"))?
    };

    Ok(if classical_ok { SpkiVerdict::Valid } else { SpkiVerdict::Invalid })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the exact byte layout against draft-19 §2.2's worked-example
    /// shape (prefix + label + len(ctx) + ctx + PH), the same structural
    /// assertion `certBuilder.test.ts`'s
    /// `buildCompositeMessageRepresentative` tests make — independent
    /// confirmation the two implementations agree, not just that this one
    /// doesn't panic.
    // No engine session bootstrap in these two tests — `native::digest`
    // (the one engine call `build_message_representative` makes) is
    // session-less by design, same as `digest_of` already is (see the
    // module doc). Nothing here touches OBJECTS/SESSIONS state, so
    // there's nothing to serialise against other engine-touching tests
    // either (no `engine_lock()` needed).

    #[test]
    fn message_representative_layout_matches_draft19_worked_shape() {
        let tbs = b"a fake TBSCertificate DER for layout testing";
        let ctx = b"app-context";
        let mprime = build_message_representative(&MLDSA65_ECDSA_P256_SHA512, tbs, ctx).unwrap();

        let label = MLDSA65_ECDSA_P256_SHA512.signature_label.as_bytes();
        let expected_len = PREFIX.len() + label.len() + 1 + ctx.len() + 64; // SHA-512 = 64 bytes
        assert_eq!(mprime.len(), expected_len);
        assert_eq!(&mprime[..PREFIX.len()], PREFIX);
        assert_eq!(&mprime[PREFIX.len()..PREFIX.len() + label.len()], label);
        assert_eq!(mprime[PREFIX.len() + label.len()], ctx.len() as u8);
        assert_eq!(
            &mprime[PREFIX.len() + label.len() + 1..PREFIX.len() + label.len() + 1 + ctx.len()],
            ctx
        );
    }

    #[test]
    fn oversized_context_is_rejected_not_truncated() {
        let ctx = vec![0u8; 256];
        let err = build_message_representative(&MLDSA65_ECDSA_P256_SHA512, b"tbs", &ctx).unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::InvalidField);
    }

    #[test]
    fn profile_for_oid_resolves_all_three_and_rejects_unknown() {
        assert!(profile_for_oid("1.3.6.1.5.5.7.6.37").is_some());
        assert!(profile_for_oid("1.3.6.1.5.5.7.6.45").is_some());
        assert!(profile_for_oid("1.3.6.1.5.5.7.6.49").is_some());
        assert!(profile_for_oid("1.2.840.113549.1.1.11").is_none());
    }

    #[test]
    fn profile_for_matches_kmip_algorithm_variants() {
        assert!(profile_for(KmipAlgorithm::CompositeMlDsa44Rsa2048PssSha256).is_some());
        assert!(profile_for(KmipAlgorithm::CompositeMlDsa65EcdsaP256Sha512).is_some());
        assert!(profile_for(KmipAlgorithm::CompositeMlDsa87EcdsaP384Sha512).is_some());
        assert!(profile_for(KmipAlgorithm::Ecdsa).is_none());
        assert!(profile_for(KmipAlgorithm::MlDsa65).is_none());
    }
}
