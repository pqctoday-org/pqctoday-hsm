use crate::constants::*;
use xmss::*;

/// Return the total signature capacity (2^H) for a given CKP_XMSS_* parameter set.
pub fn xmss_param_max_sigs(xmss_param: u32) -> u32 {
    match xmss_param {
        CKP_XMSS_SHA2_10_256 | CKP_XMSS_SHAKE_10_256 => 1u32 << 10, // 1,024
        CKP_XMSS_SHA2_16_256 | CKP_XMSS_SHAKE_16_256 => 1u32 << 16, // 65,536
        CKP_XMSS_SHA2_20_256 | CKP_XMSS_SHAKE_20_256 => 1u32 << 20, // 1,048,576
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
    match xmss_param {
        CKP_XMSS_SHA2_10_256 => dispatch!(XmssSha2_10_256),
        CKP_XMSS_SHA2_16_256 => dispatch!(XmssSha2_16_256),
        CKP_XMSS_SHA2_20_256 => dispatch!(XmssSha2_20_256),
        CKP_XMSS_SHAKE_10_256 => dispatch!(XmssShake_10_256),
        CKP_XMSS_SHAKE_16_256 => dispatch!(XmssShake_16_256),
        CKP_XMSS_SHAKE_20_256 => dispatch!(XmssShake_20_256),
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
