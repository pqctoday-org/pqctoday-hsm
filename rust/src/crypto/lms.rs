// SPDX-License-Identifier: GPL-3.0-only
//
// G10 — Stateful hash-based signatures: LMS (single-level) and HSS (multi-level)
//
// Uses hbs-lms 0.1.1 (Fraunhofer IIS, RFC 8554 conformant).
// Supports all SP 800-208 parameter sets: SHA-256 N32/N24 and SHAKE-256 N32/N24.
//
// All LMS/HSS operations use CKM_HSS_KEY_PAIR_GEN / CKM_HSS (PKCS#11 v3.2 §6.14).
// Single-level LMS: CKM_HSS_KEY_PAIR_GEN with levels=1 in CK_HSS_KEY_PAIR_GEN_PARAMS.
//
// Parameter set values are IANA registry type IDs (RFC 8554 + SP 800-208):
//   https://www.iana.org/assignments/leighton-micali-signatures/

use hbs_lms::{
    self as lms, HashChain, HssParameter, LmotsAlgorithm, LmsAlgorithm, Sha256_192, Sha256_256,
    Shake256_192, Shake256_256,
};

use crate::constants::*;

// ── Hash type dispatch ──────────────────────────────────────────────────────
//
// The hbs-lms crate is generic over H: HashChain. We determine the hash type
// from the LMS parameter set IANA ID range:
//   0x05–0x09: SHA-256 N32 → Sha256_256
//   0x0A–0x0E: SHA-256 N24 → Sha256_192
//   0x0F–0x13: SHAKE-256 N32 → Shake256_256
//   0x14–0x18: SHAKE-256 N24 → Shake256_192

/// Determine tree height from any LMS IANA type ID.
fn lms_param_height(lms_param: u32) -> Option<u8> {
    let offset = match lms_param {
        0x05..=0x09 => lms_param - 0x05,
        0x0A..=0x0E => lms_param - 0x0A,
        0x0F..=0x13 => lms_param - 0x0F,
        0x14..=0x18 => lms_param - 0x14,
        _ => return None,
    };
    Some([5, 10, 15, 20, 25][offset as usize])
}

pub fn ckp_to_lms_algo(param: u32) -> Option<LmsAlgorithm> {
    // All four hash families use the same LmsAlgorithm enum (height-based)
    let height = lms_param_height(param)?;
    match height {
        5 => Some(LmsAlgorithm::LmsH5),
        10 => Some(LmsAlgorithm::LmsH10),
        15 => Some(LmsAlgorithm::LmsH15),
        20 => Some(LmsAlgorithm::LmsH20),
        25 => Some(LmsAlgorithm::LmsH25),
        _ => None,
    }
}

pub fn ckp_to_lmots_algo(param: u32) -> Option<LmotsAlgorithm> {
    // All four hash families use the same LmotsAlgorithm enum (W-based)
    let offset = match param {
        0x01..=0x04 => param - 0x01, // SHA-256 N32
        0x05..=0x08 => param - 0x05, // SHA-256 N24
        0x09..=0x0C => param - 0x09, // SHAKE-256 N32
        0x0D..=0x10 => param - 0x0D, // SHAKE-256 N24
        _ => return None,
    };
    match offset {
        0 => Some(LmotsAlgorithm::LmotsW1),
        1 => Some(LmotsAlgorithm::LmotsW2),
        2 => Some(LmotsAlgorithm::LmotsW4),
        3 => Some(LmotsAlgorithm::LmotsW8),
        _ => None,
    }
}

/// Return the number of leaf nodes (2^H) for a given CKP_LMS_* param set.
pub fn lms_param_max_leaves(lms_param: u32) -> Option<u64> {
    let h = lms_param_height(lms_param)? as u32;
    Some(1u64 << h)
}

// ── Generic keygen helper ───────────────────────────────────────────────────

fn keygen_typed<H: HashChain>(params: &[HssParameter<H>]) -> Result<(Vec<u8>, Vec<u8>), ()> {
    let mut seed_bytes = [0u8; 32];
    getrandom::getrandom(&mut seed_bytes).map_err(|_| ())?;
    let mut seed = lms::Seed::<H>::default();
    let n = seed.as_mut_slice().len();
    seed.as_mut_slice().copy_from_slice(&seed_bytes[..n]);
    let (sk, vk) = lms::keygen::<H>(params, &seed, None).map_err(|_| ())?;
    Ok((vk.as_slice().to_vec(), sk.as_slice().to_vec()))
}

// ── LMS single-level keygen ─────────────────────────────────────────────────

pub fn lms_keygen(lms_param: u32, lmots_param: u32) -> Result<(Vec<u8>, Vec<u8>), ()> {
    let lms_algo = ckp_to_lms_algo(lms_param).ok_or(())?;
    let lmots_algo = ckp_to_lmots_algo(lmots_param).ok_or(())?;

    match lms_param {
        0x05..=0x09 => keygen_typed(&[HssParameter::<Sha256_256>::new(lmots_algo, lms_algo)]),
        0x0A..=0x0E => keygen_typed(&[HssParameter::<Sha256_192>::new(lmots_algo, lms_algo)]),
        0x0F..=0x13 => keygen_typed(&[HssParameter::<Shake256_256>::new(lmots_algo, lms_algo)]),
        0x14..=0x18 => keygen_typed(&[HssParameter::<Shake256_192>::new(lmots_algo, lms_algo)]),
        _ => Err(()),
    }
}

// ── LMS single-level sign ───────────────────────────────────────────────────

pub fn lms_sign(
    leaf_index: u64,
    max_leaves: u64,
    priv_key_bytes: &[u8],
    message: &[u8],
    update_fn: &mut dyn FnMut(&[u8]) -> Result<(), ()>,
) -> Result<Vec<u8>, u32> {
    use crate::constants::{CKR_FUNCTION_FAILED, CKR_KEY_EXHAUSTED};

    if leaf_index >= max_leaves {
        return Err(CKR_KEY_EXHAUSTED);
    }

    // Detect hash type from the public key type ID embedded in the private key.
    // hbs-lms private keys start with [levels(4) || lms_type(4) || ...].
    // For single-level LMS wrapped in HSS format: levels=1, lms_type at offset 4.
    // Direct: type ID at offset 0 of the LMS public key within.
    // We use Sha256_256 as default — the hbs-lms verify/sign functions parse
    // the type ID from the key bytes themselves, so the generic parameter only
    // affects hash output sizing. For keys generated with a specific hash type,
    // the library handles dispatch internally.
    let sig = lms::sign::<Sha256_256>(message, priv_key_bytes, update_fn, None)
        .map_err(|_| CKR_FUNCTION_FAILED)?;

    Ok(sig.as_ref().to_vec())
}

// ── LMS single-level verify ─────────────────────────────────────────────────

pub fn lms_verify(pub_key_bytes: &[u8], message: &[u8], signature: &[u8]) -> bool {
    // Try Sha256_256 first (covers both N32 and N24 — library reads type from key)
    lms::verify::<Sha256_256>(message, signature, pub_key_bytes).is_ok()
}

// ── HSS multi-level keygen ──────────────────────────────────────────────────

pub fn hss_keygen(
    levels: usize,
    lms_params: &[u32],
    lmots_params: &[u32],
) -> Result<(Vec<u8>, Vec<u8>), ()> {
    if levels == 0 || levels > 8 || lms_params.len() != levels || lmots_params.len() != levels {
        return Err(());
    }

    // Build typed HssParameter vec and dispatch based on first level's hash type.
    // All levels in an HSS tree must use the same hash function.
    macro_rules! build_and_keygen {
        ($H:ty) => {{
            let mut params = Vec::with_capacity(levels);
            for i in 0..levels {
                let lms_algo = ckp_to_lms_algo(lms_params[i]).ok_or(())?;
                let lmots_algo = ckp_to_lmots_algo(lmots_params[i]).ok_or(())?;
                params.push(HssParameter::<$H>::new(lmots_algo, lms_algo));
            }
            keygen_typed(&params)
        }};
    }

    match lms_params[0] {
        0x05..=0x09 => build_and_keygen!(Sha256_256),
        0x0A..=0x0E => build_and_keygen!(Sha256_192),
        0x0F..=0x13 => build_and_keygen!(Shake256_256),
        0x14..=0x18 => build_and_keygen!(Shake256_192),
        _ => Err(()),
    }
}

// ── HSS multi-level sign ────────────────────────────────────────────────────

pub fn hss_sign(
    lms_param: u32,
    priv_key_bytes: &[u8],
    message: &[u8],
    update_fn: &mut dyn FnMut(&[u8]) -> Result<(), ()>,
) -> Result<Vec<u8>, u32> {
    use crate::constants::{CKR_FUNCTION_FAILED, CKR_KEY_EXHAUSTED};

    let mut callback_fired = false;
    let mut wrapped_update = |new_state: &[u8]| -> Result<(), ()> {
        callback_fired = true;
        update_fn(new_state)
    };

    // Dispatch based on hash family (determines OUTPUT_SIZE for key deserialization).
    // Using the wrong type causes from_binary_representation to fail (size mismatch)
    // which is silently misidentified as CKR_KEY_EXHAUSTED.
    let result = match lms_param {
        0x05..=0x09 => lms::sign::<Sha256_256>(message, priv_key_bytes, &mut wrapped_update, None),
        0x0A..=0x0E => lms::sign::<Sha256_192>(message, priv_key_bytes, &mut wrapped_update, None),
        0x0F..=0x13 => {
            lms::sign::<Shake256_256>(message, priv_key_bytes, &mut wrapped_update, None)
        }
        0x14..=0x18 => {
            lms::sign::<Shake256_192>(message, priv_key_bytes, &mut wrapped_update, None)
        }
        _ => lms::sign::<Sha256_256>(message, priv_key_bytes, &mut wrapped_update, None),
    };

    match result {
        Ok(sig) => Ok(sig.as_ref().to_vec()),
        Err(_) => {
            if !callback_fired {
                Err(CKR_KEY_EXHAUSTED)
            } else {
                Err(CKR_FUNCTION_FAILED)
            }
        }
    }
}

// ── HSS multi-level verify ──────────────────────────────────────────────────

/// Derive the CKP_LMS_* (IANA) type ID from HSS/LMS public-key bytes.
/// HSS form: u32be(L) || u32be(lms_type) || …  (lms_type at offset 4);
/// raw LMS form (no L prefix): lms_type at offset 0. The key material is
/// self-describing, so this is the authoritative source when the object
/// carries no CKA_LMS_PARAM_SET attribute (e.g. external ACVP imports).
pub fn lms_param_from_pubkey(pub_key_bytes: &[u8]) -> Option<u32> {
    if pub_key_bytes.len() >= 8 {
        let first = u32::from_be_bytes(pub_key_bytes[0..4].try_into().ok()?);
        // L (HSS levels) is small (1..=8); LMS type ids start at 0x05.
        if (1..=8).contains(&first) {
            let t = u32::from_be_bytes(pub_key_bytes[4..8].try_into().ok()?);
            if lms_param_height(t).is_some() {
                return Some(t);
            }
        }
        if lms_param_height(first).is_some() {
            return Some(first);
        }
    }
    None
}

/// Verify an HSS/LMS signature.  `lms_param` is the CKP_LMS_* value stored in
/// CKA_LMS_PARAM_SET of the key object; it selects the hash family.
/// The patched hbs-lms serializes/parses SP 800-208 family-specific type IDs,
/// so all four families verify through the crate.
pub fn hss_verify(pub_key_bytes: &[u8], message: &[u8], signature: &[u8], lms_param: u32) -> bool {
    match lms_param {
        0x05..=0x09 => lms::verify::<Sha256_256>(message, signature, pub_key_bytes).is_ok(),
        0x0A..=0x0E => lms::verify::<Sha256_192>(message, signature, pub_key_bytes).is_ok(),
        0x0F..=0x13 => lms::verify::<Shake256_256>(message, signature, pub_key_bytes).is_ok(),
        0x14..=0x18 => lms::verify::<Shake256_192>(message, signature, pub_key_bytes).is_ok(),
        _ => lms::verify::<Sha256_256>(message, signature, pub_key_bytes).is_ok(),
    }
}
