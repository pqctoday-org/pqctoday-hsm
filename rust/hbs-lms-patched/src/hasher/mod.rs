use core::{
    convert::TryFrom,
    fmt::Debug,
    ops::{Deref, DerefMut},
};
use digest::{FixedOutput, Update};
use tinyvec::ArrayVec;

use crate::constants::{winternitz_chain::*, MAX_HASH_SIZE};

pub mod sha256;
pub mod shake256;

pub struct HashChainData {
    data: ArrayVec<[u8; ITER_MAX_LEN]>,
}

impl Deref for HashChainData {
    type Target = ArrayVec<[u8; ITER_MAX_LEN]>;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl DerefMut for HashChainData {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

/**
 *
 * This trait is used inside the library to generate hashes. Default implementations are available with [`sha256::Sha256`] and [`shake256::Shake256`].
 * It can be used to outsource calculations to hardware accelerators.
 *
 *
 * Requires PartialEq, to use compare within the tests.
 * This is required as long as this [issue](https://github.com/rust-lang/rust/issues/26925) is
 * open.
 * */
pub trait HashChain:
    Debug + Default + Clone + PartialEq + Send + Sync + FixedOutput + Update
{
    const OUTPUT_SIZE: u16;
    const BLOCK_SIZE: u16;
    /// IANA "Leighton-Micali Signatures" LMS type ID of this hash family's
    /// H5 variant (SP 800-208 §4 / RFC 8554 §5.1). H10..H25 are BASE+1..+4.
    /// Defaults to SHA-256/192-bit-security N32 (0x05) for backward compat.
    const LMS_TYPE_BASE: u32 = 0x05;
    /// IANA LM-OTS type ID of this family's W1 variant; W2/W4/W8 are
    /// BASE+1..+3. Defaults to SHA-256 N32 (0x01).
    const LMOTS_TYPE_BASE: u32 = 0x01;

    fn finalize(self) -> ArrayVec<[u8; MAX_HASH_SIZE]>;
    fn finalize_reset(&mut self) -> ArrayVec<[u8; MAX_HASH_SIZE]>;

    fn prepare_hash_chain_data(
        lms_tree_identifier: &[u8],
        lms_leaf_identifier: &[u8],
    ) -> HashChainData {
        let mut hc_data = HashChainData {
            data: ArrayVec::from_array_len(
                [0u8; ITER_MAX_LEN],
                iter_len(Self::OUTPUT_SIZE as usize),
            ),
        };
        hc_data[ITER_I..ITER_Q].copy_from_slice(lms_tree_identifier);
        hc_data[ITER_Q..ITER_K].copy_from_slice(lms_leaf_identifier);
        hc_data
    }

    fn do_hash_chain(
        &mut self,
        hc_data: &mut HashChainData,
        hash_chain_id: u16,
        initial_value: &[u8],
        from: usize,
        to: usize,
    ) -> ArrayVec<[u8; MAX_HASH_SIZE]> {
        hc_data[ITER_K..ITER_J].copy_from_slice(&hash_chain_id.to_be_bytes());
        hc_data[ITER_PREV..].copy_from_slice(initial_value);

        self.do_actual_hash_chain(hc_data, from, to);

        ArrayVec::try_from(&hc_data[ITER_PREV..]).unwrap()
    }

    fn do_actual_hash_chain(&mut self, hc_data: &mut HashChainData, from: usize, to: usize) {
        for j in from..to {
            hc_data[ITER_J] = j as u8;
            // We assume that the hasher is fresh initialized on the first round
            self.update(&hc_data.data);
            let temp_hash = self.finalize_reset();
            hc_data[ITER_PREV..].copy_from_slice(temp_hash.as_slice());
        }
    }
}
