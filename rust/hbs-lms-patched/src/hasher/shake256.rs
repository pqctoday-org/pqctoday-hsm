use tinyvec::ArrayVec;

use sha3::{
    digest::{
        typenum::U32, ExtendableOutput, ExtendableOutputReset, FixedOutput, FixedOutputReset,
        Output, OutputSizeUser, Reset, Update, XofReader,
    },
    Shake256 as Hasher,
};

use crate::constants::MAX_HASH_SIZE;

use super::HashChain;

macro_rules! define_shake {
    ($name:ident, $output_size:expr, $lms_base:expr, $lmots_base:expr) => {
        /**
         * Extension of [`sha3::Shake256`], which can be passed into the library, as it implements the [`HashChain`] trait.
         * */
        #[derive(Debug, Default, Clone)]
        pub struct $name {
            hasher: Hasher,
        }

        impl HashChain for $name {
            const OUTPUT_SIZE: u16 = $output_size;
            const BLOCK_SIZE: u16 = 64;
            // SP 800-208 / IANA type-ID bases for this hash family
            const LMS_TYPE_BASE: u32 = $lms_base;
            const LMOTS_TYPE_BASE: u32 = $lmots_base;

            fn finalize(self) -> ArrayVec<[u8; MAX_HASH_SIZE]> {
                let mut digest = [0u8; MAX_HASH_SIZE];
                self.hasher.finalize_xof().read(&mut digest);
                ArrayVec::from_array_len(digest, Self::OUTPUT_SIZE as usize)
            }

            fn finalize_reset(&mut self) -> ArrayVec<[u8; MAX_HASH_SIZE]> {
                let mut digest = [0u8; MAX_HASH_SIZE];
                self.hasher.finalize_xof_reset().read(&mut digest);
                ArrayVec::from_array_len(digest, Self::OUTPUT_SIZE as usize)
            }
        }

        impl OutputSizeUser for $name {
            type OutputSize = U32;
        }

        impl FixedOutput for $name {
            fn finalize_into(self, out: &mut Output<Self>) {
                self.hasher.finalize_xof().read(out);
            }
        }

        impl Reset for $name {
            fn reset(&mut self) {
                *self = Default::default();
            }
        }

        impl FixedOutputReset for $name {
            fn finalize_into_reset(&mut self, out: &mut Output<Self>) {
                self.hasher.finalize_xof_reset().read(out);
            }
        }

        impl Update for $name {
            fn update(&mut self, data: &[u8]) {
                self.hasher.update(data);
            }
        }

        impl PartialEq for $name {
            fn eq(&self, _: &Self) -> bool {
                false
            }
        }
    };
}

define_shake!(Shake256_256, 32, 0x0F, 0x09); // SP 800-208: LMS_SHAKE_M32_*, LMOTS_SHAKE_N32_*

define_shake!(Shake256_192, 24, 0x14, 0x0D); // SP 800-208: LMS_SHAKE_M24_*, LMOTS_SHAKE_N24_*

define_shake!(Shake256_128, 16, 0x05, 0x01); // no IANA assignment — keeps legacy ids
