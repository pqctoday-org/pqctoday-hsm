//! PKCS#11 mechanism constants used by the bridge.
//!
//! The authoritative table is [`crate::kmip30::algos`] — Phase 3 already
//! defined the FIPS-only vendor codepoints (`CKM_PQCTODAY_*`) and verified
//! them against `pkcs11-mech-manifest.json` at test time. This module
//! re-exports them so bridge call sites can `use crate::pkcs11bridge::mechs`
//! without reaching into the algo registry.
//!
//! If a future phase needs the bridge to know about mechs that aren't tied
//! to a `KmipAlgorithm` (e.g. `CKM_*_KEY_DERIVATION` for KDFs), add the
//! consts here as well so this module stays the single mech-lookup table
//! the bridge consults.

pub use crate::kmip30::algos::{
    CkMechanismType,
    // Vendor codepoints from pqctoday-hsm/softhsmv3 (manifest-pinned in Phase 3).
    CKM_PQCTODAY_HSS_KEY_PAIR_GEN,
    CKM_PQCTODAY_SLH_DSA_SIGN_VERIFY,
    CKM_PQCTODAY_ML_KEM_KEY_PAIR_GEN,
    CKM_PQCTODAY_ML_DSA_KEY_PAIR_GEN,
    CKM_PQCTODAY_ML_DSA_SIGN_VERIFY,
    CKM_PQCTODAY_ML_KEM_ENCAPSULATE,
    // Standard PKCS#11 v3.2 codepoints (classical surface).
    CKM_RSA_PKCS_KEY_PAIR_GEN,
    CKM_RSA_PKCS,
    CKM_RSA_PKCS_OAEP,
    CKM_RSA_PKCS_PSS,
    CKM_EC_KEY_PAIR_GEN,
    CKM_ECDSA,
    CKM_ECDSA_SHA256,
    CKM_AES_KEY_GEN,
    CKM_AES_GCM,
    CKM_GENERIC_SECRET_KEY_GEN,
    CKM_SHA256_HMAC,
    CKM_SHA384_HMAC,
    CKM_SHA512_HMAC,
};

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity check that the bridge's view of the FIPS PQC vendor codepoints
    /// matches what `pkcs11-mech-manifest.json` (sha256-pinned in Phase 3)
    /// says. Different module, same numbers.
    #[test]
    fn vendor_codepoints_match_manifest() {
        assert_eq!(CKM_PQCTODAY_HSS_KEY_PAIR_GEN,    0x4032);
        assert_eq!(CKM_PQCTODAY_SLH_DSA_SIGN_VERIFY, 0x4033);
        assert_eq!(CKM_PQCTODAY_ML_KEM_KEY_PAIR_GEN, 0x4034);
        assert_eq!(CKM_PQCTODAY_ML_DSA_KEY_PAIR_GEN, 0x4035);
        assert_eq!(CKM_PQCTODAY_ML_DSA_SIGN_VERIFY,  0x4036);
        assert_eq!(CKM_PQCTODAY_ML_KEM_ENCAPSULATE,  0x4037);
    }
}
