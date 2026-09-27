use zeroize::{Zeroize, ZeroizeOnDrop};


/// Supported hash functions for `hash_sign()` and `hash_verify()` functions
pub enum Ph {
    /// Use SHA256 as the pre-hash function
    SHA256,
    /// Use SHA512 as the pre-hash function
    SHA512,
    /// Use Shake128 as the pre-hash function (256-bit output)
    SHAKE128,
    /// Use SHA224 as the pre-hash function [PKCS#11 v3.2 CKM_HASH_ML_DSA_SHA224]
    SHA224,
    /// Use SHA384 as the pre-hash function [PKCS#11 v3.2 CKM_HASH_ML_DSA_SHA384]
    SHA384,
    /// Use SHA3-224 as the pre-hash function [PKCS#11 v3.2 CKM_HASH_ML_DSA_SHA3_224]
    SHA3_224,
    /// Use SHA3-256 as the pre-hash function [PKCS#11 v3.2 CKM_HASH_ML_DSA_SHA3_256]
    SHA3_256,
    /// Use SHA3-384 as the pre-hash function [PKCS#11 v3.2 CKM_HASH_ML_DSA_SHA3_384]
    SHA3_384,
    /// Use SHA3-512 as the pre-hash function [PKCS#11 v3.2 CKM_HASH_ML_DSA_SHA3_512]
    SHA3_512,
    /// Use SHAKE256 as the pre-hash function (512-bit output) [PKCS#11 v3.2 CKM_HASH_ML_DSA_SHAKE256]
    SHAKE256,
}


/// Private key specific to the target security parameter set that contains
/// precomputed elements which improve signature performance.
///
/// Implements the [`crate::traits::Signer`] and [`crate::traits::SerDes`] traits.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[repr(align(8))]
pub struct PrivateKey<const K: usize, const L: usize> {
    pub(crate) rho: [u8; 32],
    pub(crate) cap_k: [u8; 32],
    pub(crate) tr: [u8; 64],
    pub(crate) s_1_hat_mont: [T; L],
    pub(crate) s_2_hat_mont: [T; K],
    pub(crate) t_0_hat_mont: [T; K],
}


/// A private key together with its expanded public matrix `Â = ExpandA(ρ)`.
/// See `ml_dsa_xx::ExpandedPrivateKey`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[repr(align(8))]
pub struct ExpandedPrivateKey<const K: usize, const L: usize> {
    pub(crate) sk: PrivateKey<K, L>,
    pub(crate) cap_a_hat: [[T; L]; K],
}

impl<const K: usize, const L: usize> ExpandedPrivateKey<K, L> {
    /// Expands `Â = ExpandA(ρ)` once for `sk`.
    #[must_use]
    pub fn new(sk: PrivateKey<K, L>) -> Self {
        let cap_a_hat = stage!(ExpandA, crate::hashing::expand_a::<false, K, L>(&sk.rho));
        Self { sk, cap_a_hat }
    }

    /// The decoded private key.
    #[must_use]
    pub fn private_key(&self) -> &PrivateKey<K, L> {
        &self.sk
    }
}


/// Public key specific to the target security parameter set that contains
/// precomputed elements which improve verification performance.
///
/// Implements the [`crate::traits::Verifier`] and [`crate::traits::SerDes`] traits.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[repr(align(8))]
pub struct PublicKey<const K: usize, const L: usize> {
    pub(crate) rho: [u8; 32],
    pub(crate) tr: [u8; 64],
    pub(crate) t1_d2_hat_mont: [T; K],
}


/// Polynomial coefficients in R, with default R0
#[derive(Clone, Debug, PartialEq, Zeroize, ZeroizeOnDrop)]
#[repr(align(8))]
pub(crate) struct R(pub(crate) [i32; 256]);
pub(crate) const R0: R = R([0i32; 256]);


/// Polynomial coefficients in T, with default T0
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[repr(align(8))]
pub(crate) struct T(pub(crate) [i32; 256]);
pub(crate) const T0: T = T([0i32; 256]);


/// Individual Zq element
pub(crate) type Zq = i32;


#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::KeyGen;
    use zeroize::Zeroize;

    /// What `ZeroizeOnDrop` runs on drop: every secret field of an expanded
    /// key (and the public matrix) is cleared.
    #[test]
    fn expanded_private_key_zeroize_clears_every_field() {
        let (_pk, sk) = crate::ml_dsa_65::KG::keygen_from_seed(&[9u8; 32]);
        let mut expanded = ExpandedPrivateKey::new(sk);
        assert!(expanded.sk.s_1_hat_mont.iter().any(|p| p.0.iter().any(|c| *c != 0)));
        expanded.zeroize();
        let sk = &expanded.sk;
        assert!(sk.rho.iter().chain(&sk.cap_k).chain(&sk.tr).all(|b| *b == 0));
        let polys = sk.s_1_hat_mont.iter().chain(&sk.s_2_hat_mont).chain(&sk.t_0_hat_mont);
        assert!(polys.flat_map(|p| p.0.iter()).all(|c| *c == 0));
        assert!(expanded.cap_a_hat.iter().flatten().flat_map(|p| p.0.iter()).all(|c| *c == 0));
    }
}
