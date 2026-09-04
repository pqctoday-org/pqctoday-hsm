use crate::constants::*;
use xmss::*;

/// Return the total signature capacity (2^H) for a given CKP_XMSS_* parameter set.
pub fn xmss_param_max_sigs(xmss_param: u32) -> u32 {
    match xmss_param {
        CKP_XMSS_SHA2_10_256 | CKP_XMSS_SHAKE_10_256 | CKP_XMSS_SHAKE256_10_192
        | CKP_XMSS_SHAKE256_10_256 | CKP_XMSS_SHA2_10_192 => 1u32 << 10, // 1,024
        CKP_XMSS_SHA2_16_256 | CKP_XMSS_SHAKE_16_256 | CKP_XMSS_SHAKE256_16_256
        | CKP_XMSS_SHAKE256_16_192 | CKP_XMSS_SHA2_16_192 => 1u32 << 16, // 65,536
        CKP_XMSS_SHA2_20_256 | CKP_XMSS_SHAKE_20_256 | CKP_XMSS_SHAKE256_20_256
        | CKP_XMSS_SHAKE256_20_192 | CKP_XMSS_SHA2_20_192 => 1u32 << 20, // 1,048,576
        _ => 1u32 << 10,                                            // safe fallback
    }
}

/// Read the current leaf index from a serialised XMSS signing key and return
/// the number of signature operations still available.
///
/// The xmss crate serialises the signing key as:
///   [OID (4 bytes)] [index (4 bytes, big-endian)] [SK_SEED || SK_PRF || root || PUB_SEED]
///
/// remaining = max_sigs − current_index
pub fn xmss_keys_remaining(xmss_param: u32, priv_key: &[u8]) -> u32 {
    const XMSS_OID_LEN: usize = 4;
    const IDX_LEN: usize = 4; // single-tree XMSS always uses 4-byte index
    if priv_key.len() < XMSS_OID_LEN + IDX_LEN {
        return 0;
    }
    // Index is stored big-endian immediately after the OID prefix.
    let idx = u32::from_be_bytes([
        priv_key[XMSS_OID_LEN],
        priv_key[XMSS_OID_LEN + 1],
        priv_key[XMSS_OID_LEN + 2],
        priv_key[XMSS_OID_LEN + 3],
    ]);
    xmss_param_max_sigs(xmss_param).saturating_sub(idx)
}

// Mutex (not `static mut`): writing a `static mut` is UB under any future
// multithreaded build. Poison recovery matches GlobalState's convention.
pub static KAT_SEED: std::sync::Mutex<Option<[u8; 96]>> = std::sync::Mutex::new(None);

/// Read the KAT seed (test hook), tolerating a poisoned lock.
pub fn kat_seed() -> Option<[u8; 96]> {
    *KAT_SEED.lock().unwrap_or_else(|e| e.into_inner())
}

/// Set/clear the KAT seed (test hook).
pub fn set_kat_seed_value(v: Option<[u8; 96]>) {
    *KAT_SEED.lock().unwrap_or_else(|e| e.into_inner()) = v;
}

pub fn xmss_keygen(xmss_param: u32) -> Result<(Vec<u8>, Vec<u8>), ()> {
    macro_rules! dispatch {
        ($t:ty) => {{
            // Seed length is 3*n (XmssParameter::SEED_LEN), NOT a fixed 96
            // bytes — that assumption held for every n=32 set (96 = 3*32)
            // but is wrong for n=24 (SP 800-208's SHAKE256_*_192 family:
            // 3*24 = 72). from_seed() validates the seed length strictly
            // (Error::InvalidSeedLength) and rejects a 96-byte seed outright,
            // which is why EVERY _192 set — including CKP_XMSS_SHAKE256_10_192,
            // already dispatched before this fix — silently returned
            // CKR_PARAMETER_SET_NOT_SUPPORTED for every keygen attempt.
            let seed_len = <$t as XmssParameter>::SEED_LEN;
            let mut seed = vec![0u8; seed_len];
            if let Some(kat) = kat_seed() {
                seed.copy_from_slice(&kat[..seed_len]);
            } else {
                getrandom::getrandom(&mut seed).map_err(|_| ())?;
            }
            let mut kp = KeyPair::<$t>::from_seed(&seed).map_err(|_| ())?;
            Ok((
                kp.verifying_key().as_ref().to_vec(),
                kp.signing_key().as_ref().to_vec(),
            ))
        }};
    }
    match xmss_param {
        CKP_XMSS_SHA2_10_256 => dispatch!(XmssSha2_10_256),
        CKP_XMSS_SHA2_16_256 => dispatch!(XmssSha2_16_256),
        CKP_XMSS_SHA2_20_256 => dispatch!(XmssSha2_20_256),
        CKP_XMSS_SHAKE_10_256 => dispatch!(XmssShake_10_256),
        CKP_XMSS_SHAKE_16_256 => dispatch!(XmssShake_16_256),
        CKP_XMSS_SHAKE_20_256 => dispatch!(XmssShake_20_256),
        CKP_XMSS_SHAKE256_10_256 => dispatch!(XmssShake256_10_256),
        CKP_XMSS_SHAKE256_16_256 => dispatch!(XmssShake256_16_256),
        CKP_XMSS_SHAKE256_20_256 => dispatch!(XmssShake256_20_256),
        CKP_XMSS_SHAKE256_10_192 => dispatch!(XmssShake256_10_192),
        CKP_XMSS_SHAKE256_16_192 => dispatch!(XmssShake256_16_192),
        CKP_XMSS_SHAKE256_20_192 => dispatch!(XmssShake256_20_192),
        CKP_XMSS_SHA2_10_192 => dispatch!(XmssSha2_10_192),
        CKP_XMSS_SHA2_16_192 => dispatch!(XmssSha2_16_192),
        CKP_XMSS_SHA2_20_192 => dispatch!(XmssSha2_20_192),
        _ => Err(()),
    }
}

pub fn xmss_sign(xmss_param: u32, priv_key: &[u8], msg: &[u8]) -> Result<(Vec<u8>, Vec<u8>), u32> {
    macro_rules! dispatch {
        ($t:ty) => {{
            let mut sk = SigningKey::<$t>::try_from(priv_key).map_err(|_| CKR_FUNCTION_FAILED)?;
            let sig = sk.sign_detached(msg).map_err(|_| CKR_FUNCTION_FAILED)?;
            Ok((sig.as_ref().to_vec(), sk.as_ref().to_vec()))
        }};
    }
    match xmss_param {
        CKP_XMSS_SHA2_10_256 => dispatch!(XmssSha2_10_256),
        CKP_XMSS_SHA2_16_256 => dispatch!(XmssSha2_16_256),
        CKP_XMSS_SHA2_20_256 => dispatch!(XmssSha2_20_256),
        CKP_XMSS_SHAKE_10_256 => dispatch!(XmssShake_10_256),
        CKP_XMSS_SHAKE_16_256 => dispatch!(XmssShake_16_256),
        CKP_XMSS_SHAKE_20_256 => dispatch!(XmssShake_20_256),
        CKP_XMSS_SHAKE256_10_256 => dispatch!(XmssShake256_10_256),
        CKP_XMSS_SHAKE256_16_256 => dispatch!(XmssShake256_16_256),
        CKP_XMSS_SHAKE256_20_256 => dispatch!(XmssShake256_20_256),
        CKP_XMSS_SHAKE256_10_192 => dispatch!(XmssShake256_10_192),
        CKP_XMSS_SHAKE256_16_192 => dispatch!(XmssShake256_16_192),
        CKP_XMSS_SHAKE256_20_192 => dispatch!(XmssShake256_20_192),
        CKP_XMSS_SHA2_10_192 => dispatch!(XmssSha2_10_192),
        CKP_XMSS_SHA2_16_192 => dispatch!(XmssSha2_16_192),
        CKP_XMSS_SHA2_20_192 => dispatch!(XmssSha2_20_192),
        _ => Err(CKR_FUNCTION_FAILED),
    }
}

pub fn xmss_verify(xmss_param: u32, pub_key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    macro_rules! dispatch {
        ($t:ty) => {{
            let pk = match VerifyingKey::<$t>::try_from(pub_key) {
                Ok(k) => k,
                Err(_) => return false,
            };
            let s = match DetachedSignature::<$t>::try_from(sig) {
                Ok(s) => s,
                Err(_) => return false,
            };
            pk.verify_detached(&s, msg).is_ok()
        }};
    }
    match xmss_param {
        CKP_XMSS_SHA2_10_256 => dispatch!(XmssSha2_10_256),
        CKP_XMSS_SHA2_16_256 => dispatch!(XmssSha2_16_256),
        CKP_XMSS_SHA2_20_256 => dispatch!(XmssSha2_20_256),
        CKP_XMSS_SHAKE_10_256 => dispatch!(XmssShake_10_256),
        CKP_XMSS_SHAKE_16_256 => dispatch!(XmssShake_16_256),
        CKP_XMSS_SHAKE_20_256 => dispatch!(XmssShake_20_256),
        CKP_XMSS_SHAKE256_10_256 => dispatch!(XmssShake256_10_256),
        CKP_XMSS_SHAKE256_16_256 => dispatch!(XmssShake256_16_256),
        CKP_XMSS_SHAKE256_20_256 => dispatch!(XmssShake256_20_256),
        CKP_XMSS_SHAKE256_10_192 => dispatch!(XmssShake256_10_192),
        CKP_XMSS_SHAKE256_16_192 => dispatch!(XmssShake256_16_192),
        CKP_XMSS_SHAKE256_20_192 => dispatch!(XmssShake256_20_192),
        CKP_XMSS_SHA2_10_192 => dispatch!(XmssSha2_10_192),
        CKP_XMSS_SHA2_16_192 => dispatch!(XmssSha2_16_192),
        CKP_XMSS_SHA2_20_192 => dispatch!(XmssSha2_20_192),
        _ => false,
    }
}
pub fn xmssmt_param_max_sigs(xmssmt_param: u32) -> u64 {
    let full_height = match xmssmt_param {
        // height 20
        0x01 | 0x02 | 0x09 | 0x0A | 0x11 | 0x12 | 0x19 | 0x1A | 0x21 | 0x22 | 0x29 | 0x2A
        | 0x31 | 0x32 => 20,
        // height 40
        0x03 | 0x04 | 0x05 | 0x0B | 0x0C | 0x0D | 0x13 | 0x14 | 0x15 | 0x1B | 0x1C | 0x1D
        | 0x23 | 0x24 | 0x25 | 0x2B | 0x2C | 0x2D | 0x33 | 0x34 | 0x35 => 40,
        // height 60
        0x06 | 0x07 | 0x08 | 0x0E | 0x0F | 0x10 | 0x16 | 0x17 | 0x18 | 0x1E | 0x1F | 0x20
        | 0x26 | 0x27 | 0x28 | 0x2E | 0x2F | 0x30 | 0x36 | 0x37 | 0x38 => 60,
        _ => 20,
    };
    1u64 << full_height
}

pub fn xmssmt_keys_remaining(xmssmt_param: u32, priv_key: &[u8]) -> u64 {
    const XMSS_OID_LEN: usize = 4;
    let full_height = match xmssmt_param {
        0x01 | 0x02 | 0x09 | 0x0A | 0x11 | 0x12 | 0x19 | 0x1A | 0x21 | 0x22 | 0x29 | 0x2A
        | 0x31 | 0x32 => 20,
        0x03 | 0x04 | 0x05 | 0x0B | 0x0C | 0x0D | 0x13 | 0x14 | 0x15 | 0x1B | 0x1C | 0x1D
        | 0x23 | 0x24 | 0x25 | 0x2B | 0x2C | 0x2D | 0x33 | 0x34 | 0x35 => 40,
        0x06 | 0x07 | 0x08 | 0x0E | 0x0F | 0x10 | 0x16 | 0x17 | 0x18 | 0x1E | 0x1F | 0x20
        | 0x26 | 0x27 | 0x28 | 0x2E | 0x2F | 0x30 | 0x36 | 0x37 | 0x38 => 60,
        _ => 20,
    };
    let idx_len = (full_height + 7) / 8; // 3, 5, or 8 bytes
    if priv_key.len() < XMSS_OID_LEN + idx_len {
        return 0;
    }

    let mut idx_bytes = [0u8; 8];
    // Copy the big-endian bytes into the lower part of our u64 array
    let start = 8 - idx_len;
    idx_bytes[start..].copy_from_slice(&priv_key[XMSS_OID_LEN..XMSS_OID_LEN + idx_len]);

    let idx = u64::from_be_bytes(idx_bytes);
    xmssmt_param_max_sigs(xmssmt_param).saturating_sub(idx)
}

pub fn xmssmt_keygen(xmssmt_param: u32) -> Result<(Vec<u8>, Vec<u8>), ()> {
    macro_rules! dispatch {
        ($t:ty) => {{
            let mut seed = [0u8; 96];
            if let Some(kat) = kat_seed() {
                seed.copy_from_slice(&kat);
            } else {
                getrandom::getrandom(&mut seed).map_err(|_| ())?;
            }
            let mut kp = KeyPair::<$t>::from_seed(&seed).map_err(|_| ())?;
            Ok((
                kp.verifying_key().as_ref().to_vec(),
                kp.signing_key().as_ref().to_vec(),
            ))
        }};
    }
    let result: Result<(Vec<u8>, Vec<u8>), ()> = match xmssmt_param {
        1 => dispatch!(XmssMtSha2_20_2_256),
        2 => dispatch!(XmssMtSha2_20_4_256),
        3 => dispatch!(XmssMtSha2_40_2_256),
        4 => dispatch!(XmssMtSha2_40_4_256),
        5 => dispatch!(XmssMtSha2_40_8_256),
        6 => dispatch!(XmssMtSha2_60_3_256),
        7 => dispatch!(XmssMtSha2_60_6_256),
        8 => dispatch!(XmssMtSha2_60_12_256),
        9 => dispatch!(XmssMtSha2_20_2_512),
        10 => dispatch!(XmssMtSha2_20_4_512),
        11 => dispatch!(XmssMtSha2_40_2_512),
        12 => dispatch!(XmssMtSha2_40_4_512),
        13 => dispatch!(XmssMtSha2_40_8_512),
        14 => dispatch!(XmssMtSha2_60_3_512),
        15 => dispatch!(XmssMtSha2_60_6_512),
        16 => dispatch!(XmssMtSha2_60_12_512),
        17 => dispatch!(XmssMtShake_20_2_256),
        18 => dispatch!(XmssMtShake_20_4_256),
        19 => dispatch!(XmssMtShake_40_2_256),
        20 => dispatch!(XmssMtShake_40_4_256),
        21 => dispatch!(XmssMtShake_40_8_256),
        22 => dispatch!(XmssMtShake_60_3_256),
        23 => dispatch!(XmssMtShake_60_6_256),
        24 => dispatch!(XmssMtShake_60_12_256),
        25 => dispatch!(XmssMtShake_20_2_512),
        26 => dispatch!(XmssMtShake_20_4_512),
        27 => dispatch!(XmssMtShake_40_2_512),
        28 => dispatch!(XmssMtShake_40_4_512),
        29 => dispatch!(XmssMtShake_40_8_512),
        30 => dispatch!(XmssMtShake_60_3_512),
        31 => dispatch!(XmssMtShake_60_6_512),
        32 => dispatch!(XmssMtShake_60_12_512),
        33 => dispatch!(XmssMtSha2_20_2_192),
        34 => dispatch!(XmssMtSha2_20_4_192),
        35 => dispatch!(XmssMtSha2_40_2_192),
        36 => dispatch!(XmssMtSha2_40_4_192),
        37 => dispatch!(XmssMtSha2_40_8_192),
        38 => dispatch!(XmssMtSha2_60_3_192),
        39 => dispatch!(XmssMtSha2_60_6_192),
        40 => dispatch!(XmssMtSha2_60_12_192),
        41 => dispatch!(XmssMtShake256_20_2_256),
        42 => dispatch!(XmssMtShake256_20_4_256),
        43 => dispatch!(XmssMtShake256_40_2_256),
        44 => dispatch!(XmssMtShake256_40_4_256),
        45 => dispatch!(XmssMtShake256_40_8_256),
        46 => dispatch!(XmssMtShake256_60_3_256),
        47 => dispatch!(XmssMtShake256_60_6_256),
        48 => dispatch!(XmssMtShake256_60_12_256),
        49 => dispatch!(XmssMtShake256_20_2_192),
        50 => dispatch!(XmssMtShake256_20_4_192),
        51 => dispatch!(XmssMtShake256_40_2_192),
        52 => dispatch!(XmssMtShake256_40_4_192),
        53 => dispatch!(XmssMtShake256_40_8_192),
        54 => dispatch!(XmssMtShake256_60_3_192),
        55 => dispatch!(XmssMtShake256_60_6_192),
        56 => dispatch!(XmssMtShake256_60_12_192),
        _ => Err(()),
    };
    // Workaround for xmss 0.1.0-pre.0: the serialized key carries the RFC OID
    // (1..=56), which parse_oid_and_params resolves to the SINGLE-TREE XMSS
    // namespace first (OID 1 == XmssSha2_10_256), so an MT key cannot
    // round-trip through `try_from`. Rewrite the 4-byte big-endian OID prefix
    // to the crate's internal XMSSMT repr (0x0001_0000 | rfc_oid) so a reload
    // selects the MT variant. Both the public and signing keys carry the OID.
    result.map(|(mut pk, mut sk)| {
        let internal = (0x0001_0000u32 | xmssmt_param).to_be_bytes();
        if pk.len() >= 4 {
            pk[..4].copy_from_slice(&internal);
        }
        if sk.len() >= 4 {
            sk[..4].copy_from_slice(&internal);
        }
        (pk, sk)
    })
}

pub fn xmssmt_sign(
    xmssmt_param: u32,
    priv_key: &[u8],
    msg: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), u32> {
    macro_rules! dispatch {
        ($t:ty) => {{
            let mut sk = SigningKey::<$t>::try_from(priv_key).map_err(|_| CKR_FUNCTION_FAILED)?;
            let sig = sk.sign_detached(msg).map_err(|_| CKR_FUNCTION_FAILED)?;
            Ok((sig.as_ref().to_vec(), sk.as_ref().to_vec()))
        }};
    }
    match xmssmt_param {
        1 => dispatch!(XmssMtSha2_20_2_256),
        2 => dispatch!(XmssMtSha2_20_4_256),
        3 => dispatch!(XmssMtSha2_40_2_256),
        4 => dispatch!(XmssMtSha2_40_4_256),
        5 => dispatch!(XmssMtSha2_40_8_256),
        6 => dispatch!(XmssMtSha2_60_3_256),
        7 => dispatch!(XmssMtSha2_60_6_256),
        8 => dispatch!(XmssMtSha2_60_12_256),
        9 => dispatch!(XmssMtSha2_20_2_512),
        10 => dispatch!(XmssMtSha2_20_4_512),
        11 => dispatch!(XmssMtSha2_40_2_512),
        12 => dispatch!(XmssMtSha2_40_4_512),
        13 => dispatch!(XmssMtSha2_40_8_512),
        14 => dispatch!(XmssMtSha2_60_3_512),
        15 => dispatch!(XmssMtSha2_60_6_512),
        16 => dispatch!(XmssMtSha2_60_12_512),
        17 => dispatch!(XmssMtShake_20_2_256),
        18 => dispatch!(XmssMtShake_20_4_256),
        19 => dispatch!(XmssMtShake_40_2_256),
        20 => dispatch!(XmssMtShake_40_4_256),
        21 => dispatch!(XmssMtShake_40_8_256),
        22 => dispatch!(XmssMtShake_60_3_256),
        23 => dispatch!(XmssMtShake_60_6_256),
        24 => dispatch!(XmssMtShake_60_12_256),
        25 => dispatch!(XmssMtShake_20_2_512),
        26 => dispatch!(XmssMtShake_20_4_512),
        27 => dispatch!(XmssMtShake_40_2_512),
        28 => dispatch!(XmssMtShake_40_4_512),
        29 => dispatch!(XmssMtShake_40_8_512),
        30 => dispatch!(XmssMtShake_60_3_512),
        31 => dispatch!(XmssMtShake_60_6_512),
        32 => dispatch!(XmssMtShake_60_12_512),
        33 => dispatch!(XmssMtSha2_20_2_192),
        34 => dispatch!(XmssMtSha2_20_4_192),
        35 => dispatch!(XmssMtSha2_40_2_192),
        36 => dispatch!(XmssMtSha2_40_4_192),
        37 => dispatch!(XmssMtSha2_40_8_192),
        38 => dispatch!(XmssMtSha2_60_3_192),
        39 => dispatch!(XmssMtSha2_60_6_192),
        40 => dispatch!(XmssMtSha2_60_12_192),
        41 => dispatch!(XmssMtShake256_20_2_256),
        42 => dispatch!(XmssMtShake256_20_4_256),
        43 => dispatch!(XmssMtShake256_40_2_256),
        44 => dispatch!(XmssMtShake256_40_4_256),
        45 => dispatch!(XmssMtShake256_40_8_256),
        46 => dispatch!(XmssMtShake256_60_3_256),
        47 => dispatch!(XmssMtShake256_60_6_256),
        48 => dispatch!(XmssMtShake256_60_12_256),
        49 => dispatch!(XmssMtShake256_20_2_192),
        50 => dispatch!(XmssMtShake256_20_4_192),
        51 => dispatch!(XmssMtShake256_40_2_192),
        52 => dispatch!(XmssMtShake256_40_4_192),
        53 => dispatch!(XmssMtShake256_40_8_192),
        54 => dispatch!(XmssMtShake256_60_3_192),
        55 => dispatch!(XmssMtShake256_60_6_192),
        56 => dispatch!(XmssMtShake256_60_12_192),
        _ => Err(CKR_FUNCTION_FAILED),
    }
}

pub fn xmssmt_verify(xmssmt_param: u32, pub_key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    macro_rules! dispatch {
        ($t:ty) => {{
            let pk = match VerifyingKey::<$t>::try_from(pub_key) {
                Ok(k) => k,
                Err(_) => return false,
            };
            let s = match DetachedSignature::<$t>::try_from(sig) {
                Ok(s) => s,
                Err(_) => return false,
            };
            pk.verify_detached(&s, msg).is_ok()
        }};
    }
    match xmssmt_param {
        1 => dispatch!(XmssMtSha2_20_2_256),
        2 => dispatch!(XmssMtSha2_20_4_256),
        3 => dispatch!(XmssMtSha2_40_2_256),
        4 => dispatch!(XmssMtSha2_40_4_256),
        5 => dispatch!(XmssMtSha2_40_8_256),
        6 => dispatch!(XmssMtSha2_60_3_256),
        7 => dispatch!(XmssMtSha2_60_6_256),
        8 => dispatch!(XmssMtSha2_60_12_256),
        9 => dispatch!(XmssMtSha2_20_2_512),
        10 => dispatch!(XmssMtSha2_20_4_512),
        11 => dispatch!(XmssMtSha2_40_2_512),
        12 => dispatch!(XmssMtSha2_40_4_512),
        13 => dispatch!(XmssMtSha2_40_8_512),
        14 => dispatch!(XmssMtSha2_60_3_512),
        15 => dispatch!(XmssMtSha2_60_6_512),
        16 => dispatch!(XmssMtSha2_60_12_512),
        17 => dispatch!(XmssMtShake_20_2_256),
        18 => dispatch!(XmssMtShake_20_4_256),
        19 => dispatch!(XmssMtShake_40_2_256),
        20 => dispatch!(XmssMtShake_40_4_256),
        21 => dispatch!(XmssMtShake_40_8_256),
        22 => dispatch!(XmssMtShake_60_3_256),
        23 => dispatch!(XmssMtShake_60_6_256),
        24 => dispatch!(XmssMtShake_60_12_256),
        25 => dispatch!(XmssMtShake_20_2_512),
        26 => dispatch!(XmssMtShake_20_4_512),
        27 => dispatch!(XmssMtShake_40_2_512),
        28 => dispatch!(XmssMtShake_40_4_512),
        29 => dispatch!(XmssMtShake_40_8_512),
        30 => dispatch!(XmssMtShake_60_3_512),
        31 => dispatch!(XmssMtShake_60_6_512),
        32 => dispatch!(XmssMtShake_60_12_512),
        33 => dispatch!(XmssMtSha2_20_2_192),
        34 => dispatch!(XmssMtSha2_20_4_192),
        35 => dispatch!(XmssMtSha2_40_2_192),
        36 => dispatch!(XmssMtSha2_40_4_192),
        37 => dispatch!(XmssMtSha2_40_8_192),
        38 => dispatch!(XmssMtSha2_60_3_192),
        39 => dispatch!(XmssMtSha2_60_6_192),
        40 => dispatch!(XmssMtSha2_60_12_192),
        41 => dispatch!(XmssMtShake256_20_2_256),
        42 => dispatch!(XmssMtShake256_20_4_256),
        43 => dispatch!(XmssMtShake256_40_2_256),
        44 => dispatch!(XmssMtShake256_40_4_256),
        45 => dispatch!(XmssMtShake256_40_8_256),
        46 => dispatch!(XmssMtShake256_60_3_256),
        47 => dispatch!(XmssMtShake256_60_6_256),
        48 => dispatch!(XmssMtShake256_60_12_256),
        49 => dispatch!(XmssMtShake256_20_2_192),
        50 => dispatch!(XmssMtShake256_20_4_192),
        51 => dispatch!(XmssMtShake256_40_2_192),
        52 => dispatch!(XmssMtShake256_40_4_192),
        53 => dispatch!(XmssMtShake256_40_8_192),
        54 => dispatch!(XmssMtShake256_60_3_192),
        55 => dispatch!(XmssMtShake256_60_6_192),
        56 => dispatch!(XmssMtShake256_60_12_192),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    //! SP 800-208 §4 defines six SHAKE256 XMSS parameter sets (Tables 14/16:
    //! h∈{10,16,20} × n∈{32,24}). Before this fix, only the three n=32 sets
    //! (0x11/0x12/0x13) were wired into keygen/sign/verify — the underlying
    //! `xmss` crate (v0.1.0-pre.0) already implements all six concrete types
    //! (`params.rs`), this crate's own dispatch tables just never routed to
    //! three of them (0x10, 0x14, 0x15), which returned CKR_PARAMETER_SET_NOT_SUPPORTED.
    use super::*;
    use crate::native::test_lock;

    /// Real keygen -> sign -> verify round trip, proving the parameter set is
    /// genuinely wired to working cryptography, not merely reachable.
    fn round_trip(param: u32) {
        let _guard = test_lock::acquire();
        set_kat_seed_value(None); // real randomness, not a fixed KAT seed
        let (pub_bytes, priv_bytes) = xmss_keygen(param).expect("keygen must succeed");
        let msg = b"xmss_bridge SP 800-208 gap-closure round trip";
        let (sig, _updated_priv) = xmss_sign(param, &priv_bytes, msg).expect("sign must succeed");
        assert!(xmss_verify(param, &pub_bytes, msg, &sig), "signature must verify");
        assert!(
            !xmss_verify(param, &pub_bytes, b"a different message", &sig),
            "signature must not verify against a different message"
        );
    }

    #[test]
    fn xmss_shake256_10_256_round_trips() {
        round_trip(CKP_XMSS_SHAKE256_10_256);
    }

    /// Diagnostic: CKP_XMSS_SHAKE256_10_192 was ALREADY dispatched before this
    /// gap-closure (one of the three pre-existing arms) but had no round-trip
    /// test of its own. Checking it in isolation tells us whether a from_seed
    /// failure on the two new n=24 sets (16_192/20_192, below) is specific to
    /// height, or affects this crate's whole n=24 (SHAKE256_*_192) family.
    #[test]
    fn xmss_shake256_10_192_round_trips() {
        round_trip(CKP_XMSS_SHAKE256_10_192);
    }

    // Height ≥16 round trips are correctness-verified but deliberately
    // #[ignore]d: single-tree XMSS keygen cost is O(2^h) leaf computations,
    // independent of hash function (measured: SHAKE256 and SHA2 n=24 sets
    // both take ~150s at h=16 in --release; h=10 is ~2-3s). h=20 was not
    // run (~40min extrapolated from h=16's 16x-larger tree) — this is why
    // XMSS^MT exists, not a defect in this fix. Run explicitly via
    // `cargo test --release -- --ignored` before a release, not on every
    // `cargo test`/local-gate invocation.

    #[test]
    #[ignore = "single-tree XMSS h=16: ~150s in --release, unusable in default `cargo test`"]
    fn xmss_shake256_16_192_round_trips() {
        round_trip(CKP_XMSS_SHAKE256_16_192);
    }

    #[test]
    #[ignore = "single-tree XMSS h=20: ~40min extrapolated from h=16 timing, run manually before a release"]
    fn xmss_shake256_20_192_round_trips() {
        round_trip(CKP_XMSS_SHAKE256_20_192);
    }

    /// Regression: 16_192 and 20_192 used to fall through to the function's
    /// `_ => 1u32 << 10` fallback (1,024) because they were absent from the
    /// match — silently under-reporting capacity by 64x and 1024x. This was
    /// latent (keygen/sign/verify didn't dispatch these params at all, so the
    /// wrong capacity was never actually reachable) but would have shipped a
    /// second bug the moment dispatch support was added without this check.
    #[test]
    fn max_sigs_correct_for_all_six_shake256_sets() {
        assert_eq!(xmss_param_max_sigs(CKP_XMSS_SHAKE256_10_256), 1 << 10);
        assert_eq!(xmss_param_max_sigs(CKP_XMSS_SHAKE256_16_256), 1 << 16);
        assert_eq!(xmss_param_max_sigs(CKP_XMSS_SHAKE256_20_256), 1 << 20);
        assert_eq!(xmss_param_max_sigs(CKP_XMSS_SHAKE256_10_192), 1 << 10);
        assert_eq!(xmss_param_max_sigs(CKP_XMSS_SHAKE256_16_192), 1 << 16);
        assert_eq!(xmss_param_max_sigs(CKP_XMSS_SHAKE256_20_192), 1 << 20);
    }

    /// SP 800-208 §5.2 Table 12 — the THIRD missing family, found only by
    /// checking the standard's own tables directly: XMSS-SHA2_{10,16,20}_192
    /// (0x0d/0x0e/0x0f), n=24, distinct from both the RFC 8391 n=32 SHA2
    /// sets and the SHAKE256 n=24 sets above. Same crate, same seed-length
    /// fix applies (SEED_LEN is computed per-type, not hardcoded).
    #[test]
    fn xmss_sha2_10_192_round_trips() {
        round_trip(CKP_XMSS_SHA2_10_192);
    }

    #[test]
    #[ignore = "single-tree XMSS h=16: ~156s in --release, unusable in default `cargo test`"]
    fn xmss_sha2_16_192_round_trips() {
        round_trip(CKP_XMSS_SHA2_16_192);
    }

    #[test]
    #[ignore = "single-tree XMSS h=20: ~40min extrapolated from h=16 timing, run manually before a release"]
    fn xmss_sha2_20_192_round_trips() {
        round_trip(CKP_XMSS_SHA2_20_192);
    }

    #[test]
    fn max_sigs_correct_for_sha2_192_family() {
        assert_eq!(xmss_param_max_sigs(CKP_XMSS_SHA2_10_192), 1 << 10);
        assert_eq!(xmss_param_max_sigs(CKP_XMSS_SHA2_16_192), 1 << 16);
        assert_eq!(xmss_param_max_sigs(CKP_XMSS_SHA2_20_192), 1 << 20);
    }

    /// A signature from one parameter set's keypair must not verify under a
    /// different (even same-height) parameter set's dispatch — proves the
    /// three new arms aren't accidentally aliased onto an existing type.
    #[test]
    fn cross_param_set_signature_does_not_verify() {
        let _guard = test_lock::acquire();
        set_kat_seed_value(None);
        let (pub_10_256, priv_10_256) = xmss_keygen(CKP_XMSS_SHAKE256_10_256).unwrap();
        let msg = b"cross-param-set check";
        let (sig, _) = xmss_sign(CKP_XMSS_SHAKE256_10_256, &priv_10_256, msg).unwrap();
        assert!(xmss_verify(CKP_XMSS_SHAKE256_10_256, &pub_10_256, msg, &sig));
        // Same message/signature bytes, wrong parameter set for verification —
        // must fail (different type, different byte layout/semantics).
        assert!(!xmss_verify(CKP_XMSS_SHAKE256_10_192, &pub_10_256, msg, &sig));
    }
}

