use core::marker::PhantomData;

use crate::hasher::{sha256::Sha256_256, HashChain};

/// Specifies the used Tree height.
#[derive(Clone, Copy)]
pub enum LmsAlgorithm {
    LmsReserved = 0,
    #[cfg(test)]
    LmsH2 = 1,
    LmsH5 = 5,
    LmsH10 = 6,
    LmsH15 = 7,
    LmsH20 = 8,
    LmsH25 = 9,
}

impl Default for LmsAlgorithm {
    fn default() -> Self {
        LmsAlgorithm::LmsReserved
    }
}

impl From<u32> for LmsAlgorithm {
    /// Family-agnostic: maps any SP 800-208 LMS type ID (SHA-256 N32 0x05-0x09,
    /// SHA-256 N24 0x0A-0x0E, SHAKE N32 0x0F-0x13, SHAKE N24 0x14-0x18) to its
    /// tree-height variant. The hash family is carried separately by `H`.
    fn from(_type: u32) -> Self {
        match _type {
            #[cfg(test)]
            1 => LmsAlgorithm::LmsH2,
            0x05..=0x18 => match (_type - 0x05) % 5 {
                0 => LmsAlgorithm::LmsH5,
                1 => LmsAlgorithm::LmsH10,
                2 => LmsAlgorithm::LmsH15,
                3 => LmsAlgorithm::LmsH20,
                _ => LmsAlgorithm::LmsH25,
            },
            _ => LmsAlgorithm::LmsReserved,
        }
    }
}

impl LmsAlgorithm {
    pub fn construct_default_parameter() -> LmsParameter<Sha256_256> {
        LmsAlgorithm::LmsH5.construct_parameter().unwrap()
    }

    pub fn construct_parameter<H: HashChain>(&self) -> Option<LmsParameter<H>> {
        // Type IDs are family-specific (SP 800-208 §4): the H5..H25 variant
        // offset is added to the hash family's IANA base.
        match *self {
            LmsAlgorithm::LmsReserved => None,
            #[cfg(test)]
            LmsAlgorithm::LmsH2 => Some(LmsParameter::new(1, 2)),
            LmsAlgorithm::LmsH5 => Some(LmsParameter::new(H::LMS_TYPE_BASE, 5)),
            LmsAlgorithm::LmsH10 => Some(LmsParameter::new(H::LMS_TYPE_BASE + 1, 10)),
            LmsAlgorithm::LmsH15 => Some(LmsParameter::new(H::LMS_TYPE_BASE + 2, 15)),
            LmsAlgorithm::LmsH20 => Some(LmsParameter::new(H::LMS_TYPE_BASE + 3, 20)),
            LmsAlgorithm::LmsH25 => Some(LmsParameter::new(H::LMS_TYPE_BASE + 4, 25)),
        }
    }

    pub fn get_from_type<H: HashChain>(_type: u32) -> Option<LmsParameter<H>> {
        #[cfg(test)]
        if _type == 1 {
            return LmsAlgorithm::LmsH2.construct_parameter();
        }
        // Accept only this hash family's IANA range (wire bytes are
        // family-specific per SP 800-208 §4).
        match _type.checked_sub(H::LMS_TYPE_BASE) {
            Some(0) => LmsAlgorithm::LmsH5.construct_parameter(),
            Some(1) => LmsAlgorithm::LmsH10.construct_parameter(),
            Some(2) => LmsAlgorithm::LmsH15.construct_parameter(),
            Some(3) => LmsAlgorithm::LmsH20.construct_parameter(),
            Some(4) => LmsAlgorithm::LmsH25.construct_parameter(),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LmsParameter<H: HashChain> {
    type_id: u32,
    tree_height: u8,
    phantom_data: PhantomData<H>,
}

// Manually implement Copy because HashChain trait does not.
// However, it does not make a difference, because we don't hold a instance for HashChain.
impl<H: HashChain> Copy for LmsParameter<H> {}

impl<H: HashChain> LmsParameter<H> {
    const HASH_FUNCTION_OUTPUT_SIZE: usize = H::OUTPUT_SIZE as usize;

    pub fn new(type_id: u32, tree_height: u8) -> Self {
        Self {
            type_id,
            tree_height,
            phantom_data: PhantomData,
        }
    }

    pub fn get_type_id(&self) -> u32 {
        self.type_id
    }

    pub fn get_hash_function_output_size(&self) -> usize {
        Self::HASH_FUNCTION_OUTPUT_SIZE
    }

    pub fn get_tree_height(&self) -> u8 {
        self.tree_height
    }

    pub fn number_of_lm_ots_keys(&self) -> usize {
        2usize.pow(self.tree_height as u32)
    }

    pub fn get_hasher(&self) -> H {
        H::default()
    }
}

impl<H: HashChain> Default for LmsParameter<H> {
    fn default() -> Self {
        LmsAlgorithm::LmsH5.construct_parameter().unwrap()
    }
}
