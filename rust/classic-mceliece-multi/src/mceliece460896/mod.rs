//! Classic McEliece 460896 — NIST category 3, wide field (GFBITS=13), non-`f`.
//! BSI TR-02102-1 §2.4.2 recommended.

use crate::shared::{decrypt, encrypt, gf, operations, root, sk_gen, util};
use crate::{Ciphertext, PublicKey, SecretKey, SharedSecret};
use alloc::boxed::Box;
use rand::{CryptoRng, RngCore};

pub const GFBITS: usize = 13;
pub const SYS_N: usize = 4608;
pub const SYS_T: usize = 96;
const GFMASK: u16 = 0x1FFF;

pub(crate) const COND_BYTES: usize = (1 << (GFBITS - 4)) * (2 * GFBITS - 1);
pub(crate) const IRR_BYTES: usize = SYS_T * 2;
pub(crate) const PK_NROWS: usize = SYS_T * GFBITS;
const PK_NCOLS: usize = SYS_N - PK_NROWS;
pub(crate) const PK_ROW_BYTES: usize = PK_NCOLS.div_ceil(8);
#[cfg(test)]
const SYND_BYTES: usize = PK_NROWS.div_ceil(8);

pub const CRYPTO_PUBLICKEYBYTES: usize = 524_160;
pub const CRYPTO_SECRETKEYBYTES: usize = 13_608;
pub const CRYPTO_CIPHERTEXTBYTES: usize = 156;
pub const CRYPTO_BYTES: usize = 32;

pub type PublicKeyOwned = PublicKey<CRYPTO_PUBLICKEYBYTES>;
pub type SecretKeyOwned = SecretKey<CRYPTO_SECRETKEYBYTES>;
pub type CiphertextOwned = Ciphertext<CRYPTO_CIPHERTEXTBYTES>;

pub fn keypair_boxed<R: CryptoRng + RngCore>(rng: &mut R) -> (PublicKeyOwned, SecretKeyOwned) {
    let mut pk = util::alloc_boxed_array::<CRYPTO_PUBLICKEYBYTES>();
    let mut sk = util::alloc_boxed_array::<CRYPTO_SECRETKEYBYTES>();

    operations::crypto_kem_keypair_plain(
        pk.as_mut(),
        sk.as_mut(),
        rng,
        operations::KeypairSizes {
            sys_n: SYS_N,
            sys_t: SYS_T,
            gfbits: GFBITS,
            gfmask: GFMASK,
            cond_bytes: COND_BYTES,
            irr_bytes: IRR_BYTES,
            pk_nrows: PK_NROWS,
            pk_row_bytes: PK_ROW_BYTES,
        },
        root::root_wide,
        util::bitrev_wide,
        gf::gf_inv_wide_fn,
        gf::gf_mul_wide_fn,
        sk_gen::genpoly_gen_460896,
    );

    (PublicKey::from(pk), SecretKey::from(sk))
}

pub fn encapsulate_boxed<R: CryptoRng + RngCore>(
    public_key: &PublicKeyOwned,
    rng: &mut R,
) -> (CiphertextOwned, SharedSecret) {
    let mut ciphertext_buf = [0u8; CRYPTO_CIPHERTEXTBYTES];
    let mut key = Box::new([0u8; 32]);
    let mut e_buf = [0u8; SYS_N / 8];

    operations::crypto_kem_enc_plain(
        &mut ciphertext_buf,
        key.as_mut(),
        public_key.as_array(),
        &mut e_buf,
        rng,
        |c, pk, e, rng| {
            encrypt::encrypt_rangereject_plain(
                c, pk, e, SYS_T, SYS_N, GFMASK, PK_NROWS, PK_ROW_BYTES, rng,
            )
        },
    );

    (Ciphertext::from(ciphertext_buf), SharedSecret::from(key))
}

pub fn decapsulate_boxed(ciphertext: &CiphertextOwned, secret_key: &SecretKeyOwned) -> SharedSecret {
    let mut key = Box::new([0u8; 32]);
    let mut e_buf = [0u8; SYS_N / 8];
    let sk = secret_key.as_array();
    let sk_irr_cond = &sk[40..40 + IRR_BYTES + COND_BYTES];
    let sk_s = &sk[40 + IRR_BYTES + COND_BYTES..];

    operations::crypto_kem_dec_plain(
        key.as_mut(),
        ciphertext.as_array(),
        sk_irr_cond,
        sk_s,
        &mut e_buf,
        |e, sk_irr_cond, c| decrypt::decrypt_wide(e, SYS_T, sk_irr_cond, c),
    );

    SharedSecret::from(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::XorShiftRng;

    #[test]
    fn sizes_match_the_official_table() {
        assert_eq!(CRYPTO_PUBLICKEYBYTES, PK_NROWS * PK_ROW_BYTES);
        assert_eq!(CRYPTO_CIPHERTEXTBYTES, SYND_BYTES);
    }

    #[test]
    #[ignore = "460896 keygen is slow in debug builds — run --release"]
    fn keygen_encaps_decaps_round_trip() {
        let mut rng = XorShiftRng::new(0xC0FFEE);
        let (pk, sk) = keypair_boxed(&mut rng);
        let (ct, ss1) = encapsulate_boxed(&pk, &mut rng);
        let ss2 = decapsulate_boxed(&ct, &sk);
        assert_eq!(ss1.as_array(), ss2.as_array());
    }
}
