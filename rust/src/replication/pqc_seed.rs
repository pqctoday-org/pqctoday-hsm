//! Retained PQC Seed profile inside the existing replication protocol.
//! Destination policy selects Seed or legacy Expanded representation; its
//! identity is already bound into evidence, header, transaction and retries.

use crate::constants::*;
use crate::crypto::handlers::Attributes;
use der::Sequence;

pub const PROFILE: &[u8] = b"PQCToday PQC Seed Profile 1: ML-KEM-768 d||z 64; ML-DSA-65 xi 32";

pub fn profile_hash() -> [u8; 48] {
    super::sha384(PROFILE)
}

pub fn is_profile(hash: &[u8; 48]) -> bool {
    *hash == profile_hash()
}

pub fn supported(key_type: u32, parameter_set: u32) -> bool {
    matches!(
        (key_type, parameter_set),
        (CKK_ML_KEM, CKP_ML_KEM_768) | (CKK_ML_DSA, CKP_ML_DSA_65)
    )
}

pub fn seed_len(key_type: u32) -> Option<usize> {
    match key_type {
        CKK_ML_KEM => Some(64),
        CKK_ML_DSA => Some(32),
        _ => None,
    }
}

pub fn eligible(attrs: &Attributes) -> bool {
    let kt = crate::state::get_object_attr_u32_from(attrs, CKA_KEY_TYPE).unwrap_or(u32::MAX);
    let ps = crate::state::get_object_param_set_from(attrs);
    supported(kt, ps) && attrs.get(&CKA_SEED).map(Vec::len) == seed_len(kt)
}

/// The only additional policy transition drops seed-retention rights.
pub fn equal_or_stricter(destination: &[u8; 48], source: &[u8; 48]) -> bool {
    destination == source || (*destination == super::sha384(b"") && is_profile(source))
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct Descriptor {
    pub version: u8,
    pub key_type: u32,
    pub parameter_set: u32,
}

impl Descriptor {
    pub fn encode(key_type: u32, parameter_set: u32) -> Result<Vec<u8>, u32> {
        if !supported(key_type, parameter_set) {
            return Err(CKR_KEY_TYPE_INCONSISTENT);
        }
        super::asn1::to_der(&Self {
            version: 1,
            key_type,
            parameter_set,
        })
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, u32> {
        let d: Self = super::asn1::decode_strict(bytes, 64)?;
        if d.version != 1 || !supported(d.key_type, d.parameter_set) {
            return Err(CKR_DATA_INVALID);
        }
        Ok(d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_rejects_unknown_versions_sets_and_trailing_data() {
        for (version, key_type, parameter_set) in [
            (2, CKK_ML_KEM, CKP_ML_KEM_768),
            (1, CKK_ML_KEM, CKP_ML_KEM_512),
            (1, CKK_ML_DSA, CKP_ML_DSA_87),
            (1, CKK_AES, CKP_ML_DSA_65),
        ] {
            let bytes = super::super::asn1::to_der(&Descriptor { version, key_type, parameter_set }).unwrap();
            assert!(Descriptor::parse(&bytes).is_err());
        }
        let mut bytes = Descriptor::encode(CKK_ML_KEM, CKP_ML_KEM_768).unwrap();
        bytes.push(0);
        assert!(Descriptor::parse(&bytes).is_err());
    }

    #[test]
    fn profile_transition_drops_rights_only_and_never_crosses_into_fhe() {
        let seed = profile_hash();
        let legacy = super::super::sha384(b"");
        let fhe = super::super::fhe::profile_constraint_hash();
        assert!(equal_or_stricter(&legacy, &seed));
        assert!(!equal_or_stricter(&seed, &legacy));
        assert!(!equal_or_stricter(&seed, &fhe));
        assert!(!equal_or_stricter(&fhe, &seed));
    }
}
