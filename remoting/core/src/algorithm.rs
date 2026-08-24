//! The representative algorithm cell set (decision 6) — Ed25519 (classical
//! signature control), ML-DSA-{44,65,87} (FIPS 204), ML-KEM-{512,768,1024}
//! (FIPS 203). Parameter-set-generic: widening later is a new match arm
//! here, not new code in `verbs.rs`, `remoting/grpc`, or `remoting/rest`.

use serde::{Deserialize, Serialize};
use softhsmrustv3::constants::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Algorithm {
    Ed25519,
    MlDsa44,
    MlDsa65,
    MlDsa87,
    MlKem512,
    MlKem768,
    MlKem1024,
}

impl Algorithm {
    pub const ALL: [Algorithm; 7] = [
        Algorithm::Ed25519,
        Algorithm::MlDsa44,
        Algorithm::MlDsa65,
        Algorithm::MlDsa87,
        Algorithm::MlKem512,
        Algorithm::MlKem768,
        Algorithm::MlKem1024,
    ];

    pub fn is_kem(self) -> bool {
        matches!(self, Algorithm::MlKem512 | Algorithm::MlKem768 | Algorithm::MlKem1024)
    }

    pub fn is_signature(self) -> bool {
        !self.is_kem()
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Algorithm::Ed25519 => "Ed25519",
            Algorithm::MlDsa44 => "ML-DSA-44",
            Algorithm::MlDsa65 => "ML-DSA-65",
            Algorithm::MlDsa87 => "ML-DSA-87",
            Algorithm::MlKem512 => "ML-KEM-512",
            Algorithm::MlKem768 => "ML-KEM-768",
            Algorithm::MlKem1024 => "ML-KEM-1024",
        }
    }

    pub fn parse(s: &str) -> Option<Algorithm> {
        Algorithm::ALL.into_iter().find(|a| a.as_str().eq_ignore_ascii_case(s))
    }

    /// The sign/verify mechanism (signature cells only).
    pub(crate) fn sign_mechanism(self) -> u32 {
        match self {
            Algorithm::Ed25519 => CKM_EDDSA,
            Algorithm::MlDsa44 | Algorithm::MlDsa65 | Algorithm::MlDsa87 => CKM_ML_DSA,
            _ => unreachable!("sign_mechanism called on a KEM algorithm"),
        }
    }

    /// The encapsulate/decapsulate mechanism (KEM cells only).
    pub(crate) fn kem_mechanism(self) -> u32 {
        match self {
            Algorithm::MlKem512 | Algorithm::MlKem768 | Algorithm::MlKem1024 => CKM_ML_KEM,
            _ => unreachable!("kem_mechanism called on a signature algorithm"),
        }
    }

    /// `CKP_*` parameter set — `None` for Ed25519, which has none.
    pub(crate) fn parameter_set(self) -> Option<u32> {
        match self {
            Algorithm::Ed25519 => None,
            Algorithm::MlDsa44 => Some(CKP_ML_DSA_44),
            Algorithm::MlDsa65 => Some(CKP_ML_DSA_65),
            Algorithm::MlDsa87 => Some(CKP_ML_DSA_87),
            Algorithm::MlKem512 => Some(CKP_ML_KEM_512),
            Algorithm::MlKem768 => Some(CKP_ML_KEM_768),
            Algorithm::MlKem1024 => Some(CKP_ML_KEM_1024),
        }
    }
}

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_round_trips_every_cell() {
        for a in Algorithm::ALL {
            assert_eq!(Algorithm::parse(a.as_str()), Some(a));
        }
    }

    #[test]
    fn kem_and_signature_partition_all_cells() {
        for a in Algorithm::ALL {
            assert_ne!(a.is_kem(), a.is_signature());
        }
    }
}
