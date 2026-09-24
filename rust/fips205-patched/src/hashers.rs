use crate::types::Adrs;
use crate::Ph;


// Holds hasher function references; constructed by each security parameter set wrapper
#[allow(clippy::type_complexity)]
pub(crate) struct Hashers<const K: usize, const LEN: usize, const M: usize, const N: usize> {
    pub(crate) pk_seed: fn(&[u8; N]) -> PkSeed<N>,
    pub(crate) h_msg: fn(&[u8], &[u8], &[u8], &[&[u8]]) -> [u8; M],
    pub(crate) prf: fn(&PkSeed<N>, &[u8], &Adrs) -> [u8; N],
    pub(crate) prf_msg: fn(&[u8], &[u8], &[&[u8]]) -> [u8; N],
    pub(crate) f: fn(&PkSeed<N>, &Adrs, &[u8]) -> [u8; N],
    pub(crate) h: fn(&PkSeed<N>, &Adrs, &[u8], &[u8]) -> [u8; N],
    pub(crate) t_l: fn(&PkSeed<N>, &Adrs, &[[u8; N]; LEN]) -> [u8; N],
    pub(crate) t_len: fn(&PkSeed<N>, &Adrs, &[[u8; N]; K]) -> [u8; N],
}


/// PK.seed, plus the hash state after absorbing the first block of every
/// tweakable-hash input (pqctoday-hsm addition).
///
/// FIPS 205 §11.2 pads PK.seed to a full block for the SHA-2 sets:
/// F, PRF (and H, T_l for category 1) hash `PK.seed ‖ toByte(0, 64 − n) ‖
/// ADRSc ‖ …` with SHA-256, and category 3/5 H, T_l hash `PK.seed ‖
/// toByte(0, 128 − n) ‖ ADRSc ‖ …` with SHA-512. That first block is the
/// same for every call made with one key, so it is compressed once here
/// and each call resumes from a copy of the state: F and PRF drop from two
/// SHA-256 compressions to one. The output is the same hash of the same
/// bytes — SHA-2 processes a message block by block, and the saved state is
/// exactly what the removed block would have produced (sha2's block buffer
/// is `Eager`, so a full block is compressed as soon as it is absorbed).
///
/// Built once per sign/verify/keygen by `Hashers::pk_seed`; the SHAKE sets
/// leave both states empty (their input fits one Keccak block anyway).
#[derive(Clone)]
pub(crate) struct PkSeed<const N: usize> {
    pub(crate) bytes: [u8; N],
    #[allow(dead_code)] // unused when no SHA-2 parameter set is compiled in
    sha256: Option<sha2::Sha256>,
    #[allow(dead_code)] // unused unless a category 3/5 SHA-2 set is compiled in
    sha512: Option<sha2::Sha512>,
}


#[cfg(any(
    feature = "slh_dsa_shake_128f",
    feature = "slh_dsa_shake_128s",
    feature = "slh_dsa_shake_192f",
    feature = "slh_dsa_shake_192s",
    feature = "slh_dsa_shake_256f",
    feature = "slh_dsa_shake_256s"
))]
pub(crate) mod shake {
    use super::PkSeed;
    use crate::types::Adrs;
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    use sha3::Shake256;


    fn shake256(input: &[&[u8]], out: &mut [u8]) {
        profile_phase!(Hashing);
        let mut hasher = Shake256::default();
        input.iter().for_each(|item| hasher.update(item));
        let mut reader = hasher.finalize_xof();
        reader.read(out);
    }


    pub(crate) fn h_msg<const M: usize>(
        r: &[u8], pk_seed: &[u8], pk_root: &[u8], m: &[&[u8]],
    ) -> [u8; M] {
        let mut digest = [0u8; M];
        let mut inp = [r, pk_seed, pk_root, &[], &[], &[], &[], &[]];
        inp[3..3 + m.len()].copy_from_slice(m); // m can have up to 5 elements
        shake256(&inp, &mut digest);
        digest
    }


    pub(crate) fn pk_seed<const N: usize>(pk_seed: &[u8; N]) -> PkSeed<N> {
        PkSeed { bytes: *pk_seed, sha256: None, sha512: None }
    }


    #[allow(clippy::similar_names)] // pk_seed and sk_seed
    pub(crate) fn prf<const N: usize>(pk_seed: &PkSeed<N>, sk_seed: &[u8], adrs: &Adrs) -> [u8; N] {
        let mut digest = [0u8; N];
        shake256(&[&pk_seed.bytes, &adrs.to_32_bytes(), sk_seed], &mut digest); // Spec swaps order of last two params 557/997/1005
        digest
    }


    pub(crate) fn prf_msg<const N: usize>(sk_prf: &[u8], opt_rand: &[u8], m: &[&[u8]]) -> [u8; N] {
        let mut digest = [0u8; N];
        let mut inp = [sk_prf, opt_rand, &[], &[], &[], &[], &[]];
        inp[2..2 + m.len()].copy_from_slice(m); // m can have up to 5 elements
        shake256(&inp, &mut digest);
        digest
    }


    pub(crate) fn f<const N: usize>(pk_seed: &PkSeed<N>, adrs: &Adrs, m1: &[u8]) -> [u8; N] {
        let mut digest = [0u8; N];
        shake256(&[&pk_seed.bytes, &adrs.to_32_bytes(), m1], &mut digest);
        digest
    }


    pub(crate) fn h<const N: usize>(pk_seed: &PkSeed<N>, adrs: &Adrs, m1: &[u8], m2: &[u8]) -> [u8; N] {
        let mut digest = [0u8; N];
        shake256(&[&pk_seed.bytes, &adrs.to_32_bytes(), m1, m2], &mut digest);
        digest
    }


    // Perhaps there is a more elegant way to covert ml into list of bytes
    pub(crate) fn t_l<const X: usize, const Y: usize>(
        pk_seed: &PkSeed<Y>, adrs: &Adrs, ml: &[[u8; Y]; X],
    ) -> [u8; Y] {
        let mut hasher = Shake256::default();
        hasher.update(&pk_seed.bytes);
        hasher.update(&adrs.to_32_bytes());
        ml.iter().for_each(|item| hasher.update(item));
        let mut reader = hasher.finalize_xof();
        let mut result = [0u8; Y];
        reader.read(&mut result);
        result
    }
}


#[cfg(any(feature = "slh_dsa_sha2_128f", feature = "slh_dsa_sha2_128s"))]
pub(crate) mod sha2_cat_1 {
    use super::PkSeed;
    use crate::types::Adrs;
    use core::cmp::min;
    use sha2::{Digest, Sha256};


    fn sha2_256(input: &[&[u8]], out: &mut [u8]) {
        profile_phase!(Hashing);
        let mut hasher = Sha256::new();
        input.iter().for_each(|item| hasher.update(item));
        let result = hasher.finalize();
        out.copy_from_slice(&result[0..out.len()]);
    }


    /// SHA-256 state after `PK.seed ‖ toByte(0, 64 − n)`, one full block.
    fn seeded_sha256<const N: usize>(pk_seed: &[u8; N]) -> Sha256 {
        let mut hasher = Sha256::new();
        hasher.update(pk_seed);
        hasher.update(&[0u8; 48][0..(64 - N)]);
        hasher
    }


    /// Resume from the cached first block; rebuild it if absent (it is
    /// always present when the `PkSeed` came from `pk_seed` below).
    fn resume<const N: usize>(pk_seed: &PkSeed<N>) -> Sha256 {
        match &pk_seed.sha256 {
            Some(state) => state.clone(),
            None => seeded_sha256(&pk_seed.bytes),
        }
    }


    fn finish<const N: usize>(hasher: Sha256) -> [u8; N] {
        let mut out = [0u8; N];
        out.copy_from_slice(&hasher.finalize()[0..N]);
        out
    }


    pub(crate) fn pk_seed<const N: usize>(pk_seed: &[u8; N]) -> PkSeed<N> {
        PkSeed { bytes: *pk_seed, sha256: Some(seeded_sha256(pk_seed)), sha512: None }
    }


    pub(crate) fn h_msg<const M: usize>(
        r: &[u8], pk_seed: &[u8], pk_root: &[u8], m: &[&[u8]],
    ) -> [u8; M] {
        let mut digest1 = [0u8; 32];
        let mut inp = [r, pk_seed, pk_root, &[], &[], &[], &[], &[]];
        inp[3..3 + m.len()].copy_from_slice(m); // m can have up to 5 elements
        sha2_256(&inp, &mut digest1);
        let mut result = [0u8; M];
        let mut start = 0;
        let mut counter = 0u32;
        while start < M {
            let mut tmp = [0u8; 32];
            sha2_256(&[r, pk_seed, &digest1, &counter.to_be_bytes()], &mut tmp);
            let len = min(M - start, 32);
            result[start..start + len].copy_from_slice(&tmp[0..len]);
            start += 32;
            counter += 1;
        }
        result
    }


    #[allow(clippy::similar_names)] // pk_seed and sk_seed
    pub(crate) fn prf<const N: usize>(pk_seed: &PkSeed<N>, sk_seed: &[u8], adrs: &Adrs) -> [u8; N] {
        // SHA-256(PK.seed ‖ toByte(0, 64 − n) ‖ ADRSc ‖ SK.seed)
        profile_phase!(Hashing);
        let mut hasher = resume(pk_seed);
        hasher.update(adrs.to_22_bytes());
        hasher.update(sk_seed); // Spec swaps order of last two params 557/997/1005
        finish(hasher)
    }


    fn hmac_sha_256(key: &[u8], a0: &[u8], m: &[&[u8]]) -> [u8; 32] {
        profile_phase!(Hashing);
        let mut padding = [0x36; 64];
        for (p, &k) in padding.iter_mut().zip(key.iter()) {
            *p ^= k;
        }
        let mut inner_hasher = Sha256::new();
        inner_hasher.update(&padding[..]);
        inner_hasher.update(a0);
        m.iter().for_each(|item| inner_hasher.update(item));
        for p in &mut padding {
            *p ^= 0x6a;
        }
        let mut outer_hasher = Sha256::new();
        outer_hasher.update(&padding[..]);
        outer_hasher.update(inner_hasher.finalize());
        outer_hasher.finalize().into()
    }


    pub(crate) fn prf_msg<const N: usize>(sk_prf: &[u8], opt_rand: &[u8], m: &[&[u8]]) -> [u8; N] {
        let mut digest = [0u8; N];
        let full_digest = hmac_sha_256(sk_prf, opt_rand, m);
        digest.copy_from_slice(&full_digest[0..N]);
        digest
    }


    pub(crate) fn f<const N: usize>(pk_seed: &PkSeed<N>, adrs: &Adrs, m1: &[u8]) -> [u8; N] {
        // SHA-256(PK.seed ‖ toByte(0, 64 − n) ‖ ADRSc ‖ M1)
        profile_phase!(Hashing);
        let mut hasher = resume(pk_seed);
        hasher.update(adrs.to_22_bytes());
        hasher.update(m1);
        finish(hasher)
    }


    pub(crate) fn h<const N: usize>(pk_seed: &PkSeed<N>, adrs: &Adrs, m1: &[u8], m2: &[u8]) -> [u8; N] {
        // SHA-256(PK.seed ‖ toByte(0, 64 − n) ‖ ADRSc ‖ M1 ‖ M2)
        profile_phase!(Hashing);
        let mut hasher = resume(pk_seed);
        hasher.update(adrs.to_22_bytes());
        hasher.update(m1);
        hasher.update(m2);
        finish(hasher)
    }


    pub(crate) fn t_l<const LEN: usize, const N: usize>(
        pk_seed: &PkSeed<N>, adrs: &Adrs, ml: &[[u8; N]; LEN],
    ) -> [u8; N] {
        // SHA-256(PK.seed ‖ toByte(0, 64 − n) ‖ ADRSc ‖ M_l)
        let mut hasher = resume(pk_seed);
        hasher.update(adrs.to_22_bytes());
        ml.iter().for_each(|item| hasher.update(item));
        finish(hasher)
    }
}


#[cfg(any(
    feature = "slh_dsa_sha2_192f",
    feature = "slh_dsa_sha2_192s",
    feature = "slh_dsa_sha2_256f",
    feature = "slh_dsa_sha2_256s"
))]
pub(crate) mod sha2_cat_3_5 {
    use super::PkSeed;
    use crate::types::Adrs;
    use core::cmp::min;
    use sha2::{Digest, Sha256, Sha512};


    fn sha2_512(input: &[&[u8]], out: &mut [u8]) {
        profile_phase!(Hashing);
        let mut hasher = Sha512::new();
        input.iter().for_each(|item| hasher.update(item));
        let result = hasher.finalize();
        out.copy_from_slice(&result[0..out.len()]);
    }


    /// SHA-256 state after `PK.seed ‖ toByte(0, 64 − n)` (F, PRF).
    fn seeded_sha256<const N: usize>(pk_seed: &[u8; N]) -> Sha256 {
        let mut hasher = Sha256::new();
        hasher.update(pk_seed);
        hasher.update(&[0u8; 40][0..(64 - N)]);
        hasher
    }


    /// SHA-512 state after `PK.seed ‖ toByte(0, 128 − n)` (H, T_l).
    fn seeded_sha512<const N: usize>(pk_seed: &[u8; N]) -> Sha512 {
        let mut hasher = Sha512::new();
        hasher.update(pk_seed);
        hasher.update(&[0u8; 104][0..(128 - N)]);
        hasher
    }


    fn resume256<const N: usize>(pk_seed: &PkSeed<N>) -> Sha256 {
        match &pk_seed.sha256 {
            Some(state) => state.clone(),
            None => seeded_sha256(&pk_seed.bytes),
        }
    }


    fn resume512<const N: usize>(pk_seed: &PkSeed<N>) -> Sha512 {
        match &pk_seed.sha512 {
            Some(state) => state.clone(),
            None => seeded_sha512(&pk_seed.bytes),
        }
    }


    fn finish<D: Digest, const N: usize>(hasher: D) -> [u8; N] {
        let mut out = [0u8; N];
        out.copy_from_slice(&hasher.finalize()[0..N]);
        out
    }


    pub(crate) fn pk_seed<const N: usize>(pk_seed: &[u8; N]) -> PkSeed<N> {
        PkSeed {
            bytes: *pk_seed,
            sha256: Some(seeded_sha256(pk_seed)),
            sha512: Some(seeded_sha512(pk_seed)),
        }
    }


    pub(crate) fn h_msg<const M: usize>(
        r: &[u8], pk_seed: &[u8], pk_root: &[u8], m: &[&[u8]],
    ) -> [u8; M] {
        let mut digest1 = [0u8; 64];
        let mut inp = [r, pk_seed, pk_root, &[], &[], &[], &[], &[]];
        inp[3..3 + m.len()].copy_from_slice(m); // m can have up to 5 elements
        sha2_512(&inp, &mut digest1);
        let mut result = [0u8; M];
        let mut start = 0;
        let mut counter = 0u32;
        while start < M {
            let mut tmp = [0u8; 64];
            sha2_512(&[r, pk_seed, &digest1, &counter.to_be_bytes()], &mut tmp);
            let len = min(M - start, 64);
            result[start..start + len].copy_from_slice(&tmp[0..len]);
            start += 64;
            counter += 1;
        }
        result
    }


    #[allow(clippy::similar_names)] // pk_seed and sk_seed
    pub(crate) fn prf<const N: usize>(pk_seed: &PkSeed<N>, sk_seed: &[u8], adrs: &Adrs) -> [u8; N] {
        // SHA-256(PK.seed ‖ toByte(0, 64 − n) ‖ ADRSc ‖ SK.seed)
        profile_phase!(Hashing);
        let mut hasher = resume256(pk_seed);
        Digest::update(&mut hasher, adrs.to_22_bytes());
        Digest::update(&mut hasher, sk_seed); // Spec swaps order of last two params 557/997/1005
        finish(hasher)
    }


    fn hmac_sha_512(key: &[u8], a0: &[u8], m: &[&[u8]]) -> [u8; 64] {
        profile_phase!(Hashing);
        let mut padding = [0x36; 128];
        for (p, &k) in padding.iter_mut().zip(key.iter()) {
            *p ^= k;
        }
        let mut inner_hasher = Sha512::new();
        inner_hasher.update(&padding[..]);
        inner_hasher.update(a0);
        m.iter().for_each(|item| inner_hasher.update(item));
        for p in &mut padding {
            *p ^= 0x6a;
        }
        let mut outer_hasher = Sha512::new();
        outer_hasher.update(&padding[..]);
        outer_hasher.update(inner_hasher.finalize());
        outer_hasher.finalize().into()
    }


    pub(crate) fn prf_msg<const N: usize>(sk_prf: &[u8], opt_rand: &[u8], m: &[&[u8]]) -> [u8; N] {
        let mut digest = [0u8; N];
        let full_digest = hmac_sha_512(sk_prf, opt_rand, m);
        digest.copy_from_slice(&full_digest[0..N]);
        digest
    }


    pub(crate) fn f<const N: usize>(pk_seed: &PkSeed<N>, adrs: &Adrs, m1: &[u8]) -> [u8; N] {
        // SHA-256(PK.seed ‖ toByte(0, 64 − n) ‖ ADRSc ‖ M1)
        profile_phase!(Hashing);
        let mut hasher = resume256(pk_seed);
        Digest::update(&mut hasher, adrs.to_22_bytes());
        Digest::update(&mut hasher, m1);
        finish(hasher)
    }


    pub(crate) fn h<const N: usize>(pk_seed: &PkSeed<N>, adrs: &Adrs, m1: &[u8], m2: &[u8]) -> [u8; N] {
        // SHA-512(PK.seed ‖ toByte(0, 128 − n) ‖ ADRSc ‖ M1 ‖ M2)
        profile_phase!(Hashing);
        let mut hasher = resume512(pk_seed);
        Digest::update(&mut hasher, adrs.to_22_bytes());
        Digest::update(&mut hasher, m1);
        Digest::update(&mut hasher, m2);
        finish(hasher)
    }


    pub(crate) fn t_l<const LEN: usize, const N: usize>(
        pk_seed: &PkSeed<N>, adrs: &Adrs, ml: &[[u8; N]; LEN],
    ) -> [u8; N] {
        // SHA-512(PK.seed ‖ toByte(0, 128 − n) ‖ ADRSc ‖ M_l)
        let mut hasher = resume512(pk_seed);
        Digest::update(&mut hasher, adrs.to_22_bytes());
        ml.iter().for_each(|item| Digest::update(&mut hasher, item));
        finish(hasher)
    }
}

/// Remediation R37 (phase 8): the same `(OID, expected PHM length)` pair
/// [`hash_message`] returns, but WITHOUT hashing anything -- for callers
/// (PKCS#11 v3.2 SS6.69.6's bare generic `CKM_HASH_SLH_DSA`) that already
/// hold a pre-computed PHM and must not hash it a second time.
pub(crate) fn oid_and_len(ph: &Ph) -> ([u8; 11], usize) {
    match ph {
        Ph::SHA224 => ([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04], 28),
        Ph::SHA256 => ([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01], 32),
        Ph::SHA384 => ([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02], 48),
        Ph::SHA512 => ([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03], 64),
        Ph::SHA3_224 => ([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07], 28),
        Ph::SHA3_256 => ([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08], 32),
        Ph::SHA3_384 => ([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09], 48),
        Ph::SHA3_512 => ([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a], 64),
        Ph::SHAKE128 => ([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0b], 32),
        Ph::SHAKE256 => ([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0c], 64),
    }
}

pub(crate) fn hash_message(message: &[u8], ph: &Ph, phm: &mut [u8; 64]) -> ([u8; 11], usize) {
    use sha2::{Digest, Sha256, Sha512};
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    use sha3::{Shake128, Shake256};

    match ph {
        Ph::SHA256 => (
            [
                0x06u8, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
            ],
            {
                let mut hasher = Sha256::new();
                Digest::update(&mut hasher, message);
                phm[0..32].copy_from_slice(&hasher.finalize());
                32
            },
        ),
        Ph::SHA512 => (
            [
                0x06u8, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
            ],
            {
                let mut hasher = Sha512::new();
                Digest::update(&mut hasher, message);
                phm.copy_from_slice(&hasher.finalize());
                64
            },
        ),
        Ph::SHAKE128 => (
            [
                0x06u8, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B,
            ],
            {
                let mut hasher = Shake128::default();
                hasher.update(message);
                let mut reader = hasher.finalize_xof();
                reader.read(&mut phm[0..32]);
                32
            },
        ),
        Ph::SHAKE256 => (
            [
                0x06u8, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0C,
            ],
            {
                let mut hasher = Shake256::default();
                hasher.update(message);
                let mut reader = hasher.finalize_xof();
                reader.read(phm);
                64
            },
        ),
        // ── New variants for PKCS#11 v3.2 §6.69.7 HashSLH-DSA-with-hashing ─────────
        Ph::SHA224 => (
            // id-sha224 OID 2.16.840.1.101.3.4.2.4
            [0x06u8, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04],
            {
                use sha2::{Digest, Sha224};
                let mut hasher = Sha224::new();
                // UFCS: under wasm32 `CoreWrapper<T>` also impls `Update`,
                // which collides on `update()`. Pin the call to `Digest::update`.
                <Sha224 as Digest>::update(&mut hasher, message);
                phm[0..28].copy_from_slice(&hasher.finalize());
                28
            },
        ),
        Ph::SHA384 => (
            // id-sha384 OID 2.16.840.1.101.3.4.2.2
            [0x06u8, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02],
            {
                use sha2::{Digest, Sha384};
                let mut hasher = Sha384::new();
                <Sha384 as Digest>::update(&mut hasher, message);
                phm[0..48].copy_from_slice(&hasher.finalize());
                48
            },
        ),
        Ph::SHA3_224 => (
            // id-sha3-224 OID 2.16.840.1.101.3.4.2.7
            [0x06u8, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07],
            {
                use sha3::{Digest, Sha3_224};
                let mut hasher = Sha3_224::new();
                <Sha3_224 as Digest>::update(&mut hasher, message);
                phm[0..28].copy_from_slice(&hasher.finalize());
                28
            },
        ),
        Ph::SHA3_256 => (
            // id-sha3-256 OID 2.16.840.1.101.3.4.2.8
            [0x06u8, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08],
            {
                use sha3::{Digest, Sha3_256};
                let mut hasher = Sha3_256::new();
                <Sha3_256 as Digest>::update(&mut hasher, message);
                phm[0..32].copy_from_slice(&hasher.finalize());
                32
            },
        ),
        Ph::SHA3_384 => (
            // id-sha3-384 OID 2.16.840.1.101.3.4.2.9
            [0x06u8, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09],
            {
                use sha3::{Digest, Sha3_384};
                let mut hasher = Sha3_384::new();
                <Sha3_384 as Digest>::update(&mut hasher, message);
                phm[0..48].copy_from_slice(&hasher.finalize());
                48
            },
        ),
        Ph::SHA3_512 => (
            // id-sha3-512 OID 2.16.840.1.101.3.4.2.10 (0x0a)
            [0x06u8, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a],
            {
                use sha3::{Digest, Sha3_512};
                let mut hasher = Sha3_512::new();
                <Sha3_512 as Digest>::update(&mut hasher, message);
                phm.copy_from_slice(&hasher.finalize());
                64
            },
        ),
    }
}

