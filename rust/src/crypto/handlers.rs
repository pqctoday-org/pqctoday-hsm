#![allow(clippy::missing_safety_doc)]
use std::collections::HashMap;
use std::sync::atomic::AtomicU32;
use wasm_bindgen::prelude::*;

use crate::constants::*;
use crate::state::*;

// Install panic hook on WASM start — turns panics into console.error with stack traces
#[wasm_bindgen(start)]
pub fn wasm_start() {
    console_error_panic_hook::set_once();
}

// Algorithm family identifiers (stored in CKA_PRIV_ALGO_FAMILY)
pub const ALGO_ML_KEM: u32 = 1;
pub const ALGO_ML_DSA: u32 = 2;
pub const ALGO_SLH_DSA: u32 = 3;
pub const ALGO_RSA: u32 = 4;
pub const ALGO_ECDSA: u32 = 5;
pub const ALGO_EDDSA: u32 = 6;
pub const ALGO_ECDH_P256: u32 = 7;
pub const ALGO_ECDH_X25519: u32 = 8;
pub const ALGO_ECDH_X448: u32 = 9;

// ECDSA curve identifiers (stored in CKA_PRIV_PARAM_SET)
pub const CURVE_P256: u32 = 256;
pub const CURVE_P384: u32 = 384;
pub const CURVE_P521: u32 = 521;
pub const CURVE_K256: u32 = 257;

// ── Object Store ─────────────────────────────────────────────────────────────

pub type Attributes = HashMap<u32, Vec<u8>>;

pub enum DigestCtx {
    Sha256(sha2::Sha256),
    Sha384(sha2::Sha384),
    Sha512(sha2::Sha512),
    Sha3_256(sha3::Sha3_256),
    Sha3_512(sha3::Sha3_512),
    /// G11 — Keccak-256 (vendor CKM_KECCAK_256). Buffers data for single-shot finalize.
    Keccak256(Vec<u8>),
}

pub struct FindCtx {
    pub handles: Vec<u32>,
    pub cursor: usize,
}

// ── Template Parsing ─────────────────────────────────────────────────────────

/// Read a CK_ULONG attribute from a CK_ATTRIBUTE template array.
/// Each CK_ATTRIBUTE is 12 bytes: type(4) + pValue(4) + ulValueLen(4).
pub unsafe fn get_attr_ulong(template: *mut u8, count: u32, attr_type: u32) -> Option<u32> {
    if template.is_null() {
        return None;
    }
    if count > 65536 {
        return None; // Guard against malformed templates with huge count values
    }
    let ptr = template as *mut u32;
    for i in 0..count {
        let t = *ptr.add((i * 3) as usize);
        if t == attr_type {
            let val_ptr = *ptr.add((i * 3 + 1) as usize) as usize as *const u32;
            if !val_ptr.is_null() {
                // CK_ATTRIBUTE.pValue carries NO alignment guarantee — an aligned
                // deref panics (misaligned pointer) on a legal caller template.
                return Some(std::ptr::read_unaligned(val_ptr));
            }
        }
    }
    None
}

/// Read a byte-array attribute from a CK_ATTRIBUTE template array.
pub unsafe fn get_attr_bytes(template: *mut u8, count: u32, attr_type: u32) -> Option<Vec<u8>> {
    if template.is_null() {
        return None;
    }
    if count > 65536 {
        return None; // Guard against malformed templates with huge count values
    }
    let ptr = template as *mut u32;
    for i in 0..count {
        let t = *ptr.add((i * 3) as usize);
        if t == attr_type {
            let val_ptr = *ptr.add((i * 3 + 1) as usize) as usize as *const u8;
            let val_len = *ptr.add((i * 3 + 2) as usize) as usize;
            if !val_ptr.is_null() && val_len > 0 {
                return Some(std::slice::from_raw_parts(val_ptr, val_len).to_vec());
            }
        }
    }
    None
}

/// True if `attr_type` is a server-managed (read-only) attribute that a caller's
/// template must never set on a generate/derive/unwrap operation. PKCS#11 v3.2
/// §4.1.1 / §4.3 Table 13 / §4.9 / §4.10: these are determined by the token, and
/// honoring a template value would let a client forge key provenance.
pub(crate) fn is_server_managed_attr(attr_type: u32) -> bool {
    matches!(
        attr_type,
        CKA_CLASS
            | CKA_KEY_TYPE
            | CKA_LOCAL
            | CKA_KEY_GEN_MECHANISM
            | CKA_ALWAYS_SENSITIVE
            | CKA_NEVER_EXTRACTABLE
            | CKA_CHECK_VALUE
            // §4.4.1 — CKA_UNIQUE_ID is token-generated at object creation
            // (state::allocate_handle); a caller template must never supply it.
            | CKA_UNIQUE_ID
            // §4.1.1 Table 12 — CKA_TRUSTED requires an SO login to set. This
            // crate has no SO-session concept, so ALL caller sets are refused
            // (CKR_ATTRIBUTE_READ_ONLY on C_CreateObject / set-attr paths,
            // skipped on generate templates) and the FALSE default from
            // state::apply_object_defaults stands.
            | CKA_TRUSTED
    )
}

/// True if `attr_type` must NOT be absorbed from a caller template into a new
/// object's attribute map: raw key material (CKA_VALUE), seed material
/// (CKA_SEED — sensitive-class per the v3.2 PQC key tables, like CKA_VALUE),
/// engine-internal CKA_PRIV_* attrs, and the server-managed read-only set.
pub(crate) fn template_attr_is_skipped(attr_type: u32) -> bool {
    attr_type == CKA_VALUE
        || attr_type == CKA_SEED
        || attr_type >= 0xFFFF0000
        || is_server_managed_attr(attr_type)
}

/// Copy all attributes from a caller's CK_ATTRIBUTE template into the attrs map.
/// Skips: CKA_VALUE / CKA_SEED (key + seed material), internal CKA_PRIV_*
/// (>= 0xFFFF0000), and the server-managed read-only attributes (see
/// `template_attr_is_skipped` / `is_server_managed_attr`).
/// Call AFTER setting defaults so the caller's template can override the
/// remaining (client-settable) attributes.
pub unsafe fn absorb_template_attrs(attrs: &mut Attributes, template: *mut u8, count: u32) {
    if template.is_null() || count == 0 || count > 65536 {
        return;
    }
    let ptr = template as *mut u32;
    for i in 0..count {
        let attr_type = *ptr.add((i * 3) as usize);
        let val_ptr = *ptr.add((i * 3 + 1) as usize) as usize as *const u8;
        let val_len = *ptr.add((i * 3 + 2) as usize) as usize;
        // Skip key/seed material, internal private attrs, and server-managed attrs.
        if template_attr_is_skipped(attr_type) {
            continue;
        }
        if !val_ptr.is_null() && val_len > 0 {
            let v = std::slice::from_raw_parts(val_ptr, val_len).to_vec();
            attrs.insert(attr_type, v);
        }
    }
}

// ── Session/Token Info ───────────────────────────────────────────────────────

pub fn get_ml_dsa_ph(mech: u32) -> Option<fips204::Ph> {
    match mech {
        crate::constants::CKM_HASH_ML_DSA_SHA256 => Some(fips204::Ph::SHA256),
        crate::constants::CKM_HASH_ML_DSA_SHA512 => Some(fips204::Ph::SHA512),
        crate::constants::CKM_HASH_ML_DSA_SHAKE128 => Some(fips204::Ph::SHAKE128),
        // Newly supported via patched fips204 crate (all 10 PKCS#11 v3.2 §6.67.7 variants)
        crate::constants::CKM_HASH_ML_DSA_SHA224 => Some(fips204::Ph::SHA224),
        crate::constants::CKM_HASH_ML_DSA_SHA384 => Some(fips204::Ph::SHA384),
        crate::constants::CKM_HASH_ML_DSA_SHA3_224 => Some(fips204::Ph::SHA3_224),
        crate::constants::CKM_HASH_ML_DSA_SHA3_256 => Some(fips204::Ph::SHA3_256),
        crate::constants::CKM_HASH_ML_DSA_SHA3_384 => Some(fips204::Ph::SHA3_384),
        crate::constants::CKM_HASH_ML_DSA_SHA3_512 => Some(fips204::Ph::SHA3_512),
        crate::constants::CKM_HASH_ML_DSA_SHAKE256 => Some(fips204::Ph::SHAKE256),
        _ => None,
    }
}

pub fn get_slh_dsa_ph(mech: u32) -> Option<fips205::Ph> {
    match mech {
        crate::constants::CKM_HASH_SLH_DSA_SHA256 => Some(fips205::Ph::SHA256),
        crate::constants::CKM_HASH_SLH_DSA_SHA512 => Some(fips205::Ph::SHA512),
        crate::constants::CKM_HASH_SLH_DSA_SHAKE128 => Some(fips205::Ph::SHAKE128),
        crate::constants::CKM_HASH_SLH_DSA_SHAKE256 => Some(fips205::Ph::SHAKE256),
        // Newly supported via patched fips205 crate (all 10 PKCS#11 v3.2 §6.69.7 variants)
        crate::constants::CKM_HASH_SLH_DSA_SHA224 => Some(fips205::Ph::SHA224),
        crate::constants::CKM_HASH_SLH_DSA_SHA384 => Some(fips205::Ph::SHA384),
        crate::constants::CKM_HASH_SLH_DSA_SHA3_224 => Some(fips205::Ph::SHA3_224),
        crate::constants::CKM_HASH_SLH_DSA_SHA3_256 => Some(fips205::Ph::SHA3_256),
        crate::constants::CKM_HASH_SLH_DSA_SHA3_384 => Some(fips205::Ph::SHA3_384),
        crate::constants::CKM_HASH_SLH_DSA_SHA3_512 => Some(fips205::Ph::SHA3_512),
        _ => None,
    }
}

pub unsafe fn write_fixed_str(buf: *mut u8, offset: usize, s: &str, max_len: usize) {
    let bytes = s.as_bytes();
    let copy_len = bytes.len().min(max_len);
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf.add(offset), copy_len);
}

// ── SLH-DSA Macros ──────────────────────────────────────────────────────────

#[macro_export]
macro_rules! slh_dsa_keygen {
    ($func:path, $n:expr, $pub_attrs:expr, $prv_attrs:expr) => {{
        let mut rng = rand::rngs::OsRng;
        match $func(&mut rng) {
            Ok((vk, sk)) => {
                use fips205::traits::SerDes;
                $pub_attrs.insert(CKA_VALUE, fips205::traits::SerDes::into_bytes(vk).to_vec());
                $prv_attrs.insert(CKA_VALUE, fips205::traits::SerDes::into_bytes(sk).to_vec());
            }
            Err(_) => return CKR_FUNCTION_FAILED,
        }
    }};
}

#[macro_export]
macro_rules! slh_dsa_sign {
    ($ps:ty, $mech:expr, $sk_bytes:expr, $msg:expr, $ctx:expr, $deterministic:expr) => {{
        use fips205::traits::Signer;
        let sk_arr: &<$ps as fips205::traits::SerDes>::ByteArray = $sk_bytes
            .try_into()
            .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
        let sk = <$ps as fips205::traits::SerDes>::try_from_bytes(sk_arr)
            .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
        match crate::crypto::handlers::get_slh_dsa_ph($mech) {
            Some(ph) => sk
                .try_hash_sign($msg, $ctx, &ph, !$deterministic)
                .map_err(|_| CKR_FUNCTION_FAILED)
                .map(|s| Into::<Vec<u8>>::into(s)),
            None => sk
                .try_sign($msg, $ctx, !$deterministic)
                .map_err(|_| CKR_FUNCTION_FAILED)
                .map(|s| Into::<Vec<u8>>::into(s)),
        }
    }};
}

#[macro_export]
macro_rules! slh_dsa_verify {
    ($ps:ty, $mech:expr, $pk_bytes:expr, $msg:expr, $sig_bytes:expr, $ctx:expr) => {{
        use fips205::traits::Verifier;
        let pk_arr: &<$ps as fips205::traits::SerDes>::ByteArray = $pk_bytes
            .try_into()
            .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
        let vk = <$ps as fips205::traits::SerDes>::try_from_bytes(pk_arr)
            .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
        let sig: <$ps as fips205::traits::Verifier>::Signature =
            $sig_bytes.try_into().map_err(|_| CKR_SIGNATURE_INVALID)?;
        match crate::crypto::handlers::get_slh_dsa_ph($mech) {
            Some(ph) => {
                if vk.hash_verify($msg, &sig, $ctx, &ph) {
                    Ok(())
                } else {
                    Err(CKR_SIGNATURE_INVALID)
                }
            }
            None => {
                if vk.verify($msg, &sig, $ctx) {
                    Ok(())
                } else {
                    Err(CKR_SIGNATURE_INVALID)
                }
            }
        }
    }};
}

// ── SubjectPublicKeyInfo (SPKI) DER Builders ─────────────────────────────────
//
// These functions construct DER-encoded SubjectPublicKeyInfo (RFC 5480 / RFC 8410)
// from raw public key bytes. Headers are constant for each curve.

/// Build SPKI DER for P-256 (secp256r1) from a 65-byte uncompressed point.
/// Structure: SEQUENCE { AlgorithmIdentifier { ecPublicKey, secp256r1 }, BIT STRING { 00 || pt } }
pub fn build_ec_spki_p256(pt: &[u8]) -> Vec<u8> {
    // AlgId for P-256: 30 13 06 07 2a8648ce3d0201 06 08 2a8648ce3d030107
    // BIT STRING header: 03 <len+1> 00
    let alg_id: &[u8] = &[
        0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // ecPublicKey OID
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // secp256r1 OID
    ];
    build_spki_from_parts(alg_id, pt)
}

/// Build SPKI DER for P-384 (secp384r1) from a 97-byte uncompressed point.
pub fn build_ec_spki_p384(pt: &[u8]) -> Vec<u8> {
    // AlgId for P-384: 30 10 06 07 2a8648ce3d0201 06 05 2b8104 0022
    let alg_id: &[u8] = &[
        0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // ecPublicKey OID
        0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, // secp384r1 OID
    ];
    build_spki_from_parts(alg_id, pt)
}

/// Build SPKI DER for P-521 (secp521r1) from a 133-byte uncompressed point.
pub fn build_ec_spki_p521(pt: &[u8]) -> Vec<u8> {
    // AlgId for P-521: 30 10 06 07 2a8648ce3d0201 06 05 2b8104 0023
    let alg_id: &[u8] = &[
        0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // ecPublicKey OID
        0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23, // secp521r1 OID
    ];
    build_spki_from_parts(alg_id, pt)
}

/// Build SPKI DER for Ed25519 (id-EdDSA, OID 1.3.101.112) from a 32-byte key.
pub fn build_ed25519_spki(pk: &[u8]) -> Vec<u8> {
    // AlgId: 30 05 06 03 2b6570  (OID 1.3.101.112)
    let alg_id: &[u8] = &[0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];
    build_spki_from_parts(alg_id, pk)
}

pub fn build_x25519_spki(pk: &[u8]) -> Vec<u8> {
    // AlgId: 30 05 06 03 2b656e  (OID 1.3.101.110 — id-X25519, RFC 8410)
    let alg_id: &[u8] = &[0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e];
    build_spki_from_parts(alg_id, pk)
}

/// Build SPKI DER for X448 (id-X448, OID 1.3.101.111) from a 56-byte public key.
pub fn build_x448_spki(pk: &[u8]) -> Vec<u8> {
    // AlgId: 30 05 06 03 2b656f  (OID 1.3.101.111 — id-X448, RFC 8410)
    let alg_id: &[u8] = &[0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6f];
    build_spki_from_parts(alg_id, pk)
}

/// Assemble SEQUENCE { alg_id_der | BIT STRING { 00 || key_bytes } }.
pub fn build_spki_from_parts(alg_id: &[u8], key_bytes: &[u8]) -> Vec<u8> {
    // BIT STRING: tag 03 | len (key_bytes.len + 1 for unused-bits byte 00) | 00 | key_bytes
    let bs_len = key_bytes.len() + 1;
    let bs_len_enc = der_length(bs_len);
    let inner_len = alg_id.len() + 1 + bs_len_enc.len() + bs_len;
    let outer_len_enc = der_length(inner_len);

    let mut out = Vec::with_capacity(1 + outer_len_enc.len() + inner_len);
    out.push(0x30); // SEQUENCE tag
    out.extend_from_slice(&outer_len_enc);
    out.extend_from_slice(alg_id);
    out.push(0x03); // BIT STRING tag
    out.extend_from_slice(&bs_len_enc);
    out.push(0x00); // unused bits = 0
    out.extend_from_slice(key_bytes);
    out
}

/// Encode a DER length field (short or long form).
pub fn der_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len < 0x100 {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, (len & 0xff) as u8]
    }
}

// ── PQC SubjectPublicKeyInfo (SPKI) builders ─────────────────────────────────
//
// PKCS#11 v3.2 §4.14 requires CKA_PUBLIC_KEY_INFO on all public (and private) keys.
// The SPKI format per RFC 5480 / NIST FIPS 203/204/205:
//   SEQUENCE { AlgorithmIdentifier { OID }, BIT STRING { 0x00 || key_bytes } }
// PQC AlgorithmIdentifiers have NO parameters (absent, not NULL).

/// Build SPKI for ML-KEM-512 (OID 2.16.840.1.101.3.4.4.1)
pub fn build_mlkem512_spki(pk: &[u8]) -> Vec<u8> {
    // AlgId = SEQUENCE(11) { OID(9) 60 86 48 01 65 03 04 04 01 }
    let alg_id: &[u8] = &[
        0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x01,
    ];
    build_spki_from_parts(alg_id, pk)
}

/// Build SPKI for ML-KEM-768 (OID 2.16.840.1.101.3.4.4.2)
pub fn build_mlkem768_spki(pk: &[u8]) -> Vec<u8> {
    let alg_id: &[u8] = &[
        0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x02,
    ];
    build_spki_from_parts(alg_id, pk)
}

/// Build SPKI for ML-KEM-1024 (OID 2.16.840.1.101.3.4.4.3)
pub fn build_mlkem1024_spki(pk: &[u8]) -> Vec<u8> {
    let alg_id: &[u8] = &[
        0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x03,
    ];
    build_spki_from_parts(alg_id, pk)
}

/// Build SPKI for ML-DSA-44 (OID 2.16.840.1.101.3.4.3.17)
pub fn build_mldsa44_spki(pk: &[u8]) -> Vec<u8> {
    let alg_id: &[u8] = &[
        0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11,
    ];
    build_spki_from_parts(alg_id, pk)
}

/// Build SPKI for ML-DSA-65 (OID 2.16.840.1.101.3.4.3.18)
pub fn build_mldsa65_spki(pk: &[u8]) -> Vec<u8> {
    let alg_id: &[u8] = &[
        0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12,
    ];
    build_spki_from_parts(alg_id, pk)
}

/// Build SPKI for ML-DSA-87 (OID 2.16.840.1.101.3.4.3.19)
pub fn build_mldsa87_spki(pk: &[u8]) -> Vec<u8> {
    let alg_id: &[u8] = &[
        0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13,
    ];
    build_spki_from_parts(alg_id, pk)
}

/// Build SPKI for SLH-DSA given a CKP_SLH_DSA_* parameter set.
/// OIDs from NIST FIPS 205: 2.16.840.1.101.3.4.20.{1..12}
/// SHA2 variants: 1–6; SHAKE variants: 7–12.
/// CKP_SLH_DSA_* constants interleave SHA2/SHAKE by security level — map to sequential OIDs.
pub fn build_slhdsa_spki(ckp: u32, pk: &[u8]) -> Vec<u8> {
    // Mapping from CKP constant to OID arc-20 last byte
    let oid_last: u8 = match ckp {
        1 => 0x01,              // SHA2-128s
        3 => 0x02,              // SHA2-128f
        5 => 0x03,              // SHA2-192s
        7 => 0x04,              // SHA2-192f
        9 => 0x05,              // SHA2-256s
        11 => 0x06,             // SHA2-256f
        2 => 0x07,              // SHAKE-128s
        4 => 0x08,              // SHAKE-128f
        6 => 0x09,              // SHAKE-192s
        8 => 0x0a,              // SHAKE-192f
        10 => 0x0b,             // SHAKE-256s
        12 => 0x0c,             // SHAKE-256f
        _ => return Vec::new(), // unknown parameter set
    };
    let alg_id = [
        0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x14, oid_last,
    ];
    build_spki_from_parts(&alg_id, pk)
}

// ── Pre-Hash Dispatch Helpers ────────────────────────────────────────────────

/// Returns true if `mech` is one of the CKM_HASH_ML_DSA_* pre-hash variants.
pub fn is_prehash_ml_dsa(mech: u32) -> bool {
    matches!(
        mech,
        CKM_HASH_ML_DSA_SHA224
            | CKM_HASH_ML_DSA_SHA256
            | CKM_HASH_ML_DSA_SHA384
            | CKM_HASH_ML_DSA_SHA512
            | CKM_HASH_ML_DSA_SHA3_224
            | CKM_HASH_ML_DSA_SHA3_256
            | CKM_HASH_ML_DSA_SHA3_384
            | CKM_HASH_ML_DSA_SHA3_512
            | CKM_HASH_ML_DSA_SHAKE128
            | CKM_HASH_ML_DSA_SHAKE256
    )
}

/// Returns true if `mech` is one of the CKM_HASH_SLH_DSA_* pre-hash variants.
pub fn is_prehash_slh_dsa(mech: u32) -> bool {
    matches!(
        mech,
        CKM_HASH_SLH_DSA_SHA224
            | CKM_HASH_SLH_DSA_SHA256
            | CKM_HASH_SLH_DSA_SHA384
            | CKM_HASH_SLH_DSA_SHA512
            | CKM_HASH_SLH_DSA_SHA3_224
            | CKM_HASH_SLH_DSA_SHA3_256
            | CKM_HASH_SLH_DSA_SHA3_384
            | CKM_HASH_SLH_DSA_SHA3_512
            | CKM_HASH_SLH_DSA_SHAKE128
            | CKM_HASH_SLH_DSA_SHAKE256
    )
}

/// Hash `msg` with the hash function encoded in `mech`.
/// Used by CKM_HASH_ML_DSA_* and CKM_HASH_SLH_DSA_* to compute the pre-hash before signing.
pub fn prehash_message(mech: u32, msg: &[u8]) -> Option<Vec<u8>> {
    use sha2::Digest as Sha2Digest;
    match mech {
        CKM_HASH_ML_DSA_SHA224 | CKM_HASH_SLH_DSA_SHA224 => {
            Some(sha2::Sha224::digest(msg).to_vec())
        }
        CKM_HASH_ML_DSA_SHA256 | CKM_HASH_SLH_DSA_SHA256 => {
            Some(sha2::Sha256::digest(msg).to_vec())
        }
        CKM_HASH_ML_DSA_SHA384 | CKM_HASH_SLH_DSA_SHA384 => {
            Some(sha2::Sha384::digest(msg).to_vec())
        }
        CKM_HASH_ML_DSA_SHA512 | CKM_HASH_SLH_DSA_SHA512 => {
            Some(sha2::Sha512::digest(msg).to_vec())
        }
        CKM_HASH_ML_DSA_SHA3_224 | CKM_HASH_SLH_DSA_SHA3_224 => {
            Some(sha3::Sha3_224::digest(msg).to_vec())
        }
        CKM_HASH_ML_DSA_SHA3_256 | CKM_HASH_SLH_DSA_SHA3_256 => {
            Some(sha3::Sha3_256::digest(msg).to_vec())
        }
        CKM_HASH_ML_DSA_SHA3_384 | CKM_HASH_SLH_DSA_SHA3_384 => {
            Some(sha3::Sha3_384::digest(msg).to_vec())
        }
        CKM_HASH_ML_DSA_SHA3_512 | CKM_HASH_SLH_DSA_SHA3_512 => {
            Some(sha3::Sha3_512::digest(msg).to_vec())
        }
        CKM_HASH_ML_DSA_SHAKE128 | CKM_HASH_SLH_DSA_SHAKE128 => {
            use sha3::digest::{ExtendableOutput, Update, XofReader};
            let mut h = sha3::Shake128::default();
            h.update(msg);
            let mut out = vec![0u8; 32];
            h.finalize_xof().read(&mut out);
            Some(out)
        }
        CKM_HASH_ML_DSA_SHAKE256 | CKM_HASH_SLH_DSA_SHAKE256 => {
            use sha3::digest::{ExtendableOutput, Update, XofReader};
            let mut h = sha3::Shake256::default();
            h.update(msg);
            let mut out = vec![0u8; 64];
            h.finalize_xof().read(&mut out);
            Some(out)
        }
        _ => None,
    }
}

// ── Sign Helpers ────────────────────────────────────────────────────────────

/// Zero-filled RNG for FIPS 204 §5.2 deterministic ML-DSA signing
/// (algorithm 2 line 5: "for the optional deterministic variant,
/// substitute rnd ← {0}^32"). Only `try_fill_bytes`/`fill_bytes` are
/// exercised by the fips204 crate's signing path.
struct ZeroRng;
impl rand::RngCore for ZeroRng {
    fn next_u32(&mut self) -> u32 {
        0
    }
    fn next_u64(&mut self) -> u64 {
        0
    }
    fn fill_bytes(&mut self, out: &mut [u8]) {
        out.fill(0);
    }
    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), rand::Error> {
        out.fill(0);
        Ok(())
    }
}
impl rand::CryptoRng for ZeroRng {}

/// Sign with ML-DSA, honoring the PKCS#11 v3.2 CK_SIGN_ADDITIONAL_CONTEXT
/// parameters: `ctx` is the FIPS 204 context string (≤255 bytes, validated at
/// C_SignInit), `deterministic` selects the §5.2 deterministic variant
/// (CKH_DETERMINISTIC_REQUIRED); otherwise signing is hedged (default).
pub fn sign_ml_dsa(
    mech: u32,
    ps: u32,
    sk_bytes: &[u8],
    msg: &[u8],
    ctx: &[u8],
    deterministic: bool,
) -> Result<Vec<u8>, u32> {
    use fips204::traits::Signer;
    macro_rules! ml_dsa_sign {
        ($variant:path) => {{
            type Sk = <$variant as KeyGen>::PrivateKey;
            let sk_arr: &<Sk as fips204::traits::SerDes>::ByteArray =
                sk_bytes.try_into().map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let sk = <Sk as fips204::traits::SerDes>::try_from_bytes(*sk_arr)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let result = match (get_ml_dsa_ph(mech), deterministic) {
                (Some(ph), false) => sk.try_hash_sign(msg, ctx, &ph),
                (Some(ph), true) => sk.try_hash_sign_with_rng(&mut ZeroRng, msg, ctx, &ph),
                (None, false) => sk.try_sign(msg, ctx),
                (None, true) => sk.try_sign_with_rng(&mut ZeroRng, msg, ctx),
            };
            result
                .map_err(|_| CKR_FUNCTION_FAILED)
                .map(|s| Into::<Vec<u8>>::into(s))
        }};
    }
    use fips204::traits::KeyGen;
    match ps {
        CKP_ML_DSA_44 => ml_dsa_sign!(fips204::ml_dsa_44::KG),
        CKP_ML_DSA_65 | 0 => ml_dsa_sign!(fips204::ml_dsa_65::KG),
        CKP_ML_DSA_87 => ml_dsa_sign!(fips204::ml_dsa_87::KG),
        _ => Err(CKR_KEY_TYPE_INCONSISTENT),
    }
}

pub fn sign_slh_dsa(
    mech: u32,
    ps: u32,
    sk_bytes: &[u8],
    msg: &[u8],
    ctx: &[u8],
    deterministic: bool,
) -> Result<Vec<u8>, u32> {
    match ps {
        CKP_SLH_DSA_SHA2_128S => slh_dsa_sign!(
            fips205::slh_dsa_sha2_128s::PrivateKey,
            mech,
            sk_bytes,
            msg,
            ctx,
            deterministic
        ),
        CKP_SLH_DSA_SHAKE_128S => slh_dsa_sign!(
            fips205::slh_dsa_shake_128s::PrivateKey,
            mech,
            sk_bytes,
            msg,
            ctx,
            deterministic
        ),
        CKP_SLH_DSA_SHA2_128F => slh_dsa_sign!(
            fips205::slh_dsa_sha2_128f::PrivateKey,
            mech,
            sk_bytes,
            msg,
            ctx,
            deterministic
        ),
        CKP_SLH_DSA_SHAKE_128F => slh_dsa_sign!(
            fips205::slh_dsa_shake_128f::PrivateKey,
            mech,
            sk_bytes,
            msg,
            ctx,
            deterministic
        ),
        CKP_SLH_DSA_SHA2_192S => slh_dsa_sign!(
            fips205::slh_dsa_sha2_192s::PrivateKey,
            mech,
            sk_bytes,
            msg,
            ctx,
            deterministic
        ),
        CKP_SLH_DSA_SHAKE_192S => slh_dsa_sign!(
            fips205::slh_dsa_shake_192s::PrivateKey,
            mech,
            sk_bytes,
            msg,
            ctx,
            deterministic
        ),
        CKP_SLH_DSA_SHA2_192F => slh_dsa_sign!(
            fips205::slh_dsa_sha2_192f::PrivateKey,
            mech,
            sk_bytes,
            msg,
            ctx,
            deterministic
        ),
        CKP_SLH_DSA_SHAKE_192F => slh_dsa_sign!(
            fips205::slh_dsa_shake_192f::PrivateKey,
            mech,
            sk_bytes,
            msg,
            ctx,
            deterministic
        ),
        CKP_SLH_DSA_SHA2_256S => slh_dsa_sign!(
            fips205::slh_dsa_sha2_256s::PrivateKey,
            mech,
            sk_bytes,
            msg,
            ctx,
            deterministic
        ),
        CKP_SLH_DSA_SHAKE_256S => slh_dsa_sign!(
            fips205::slh_dsa_shake_256s::PrivateKey,
            mech,
            sk_bytes,
            msg,
            ctx,
            deterministic
        ),
        CKP_SLH_DSA_SHA2_256F => slh_dsa_sign!(
            fips205::slh_dsa_sha2_256f::PrivateKey,
            mech,
            sk_bytes,
            msg,
            ctx,
            deterministic
        ),
        CKP_SLH_DSA_SHAKE_256F => slh_dsa_sign!(
            fips205::slh_dsa_shake_256f::PrivateKey,
            mech,
            sk_bytes,
            msg,
            ctx,
            deterministic
        ),
        _ => Err(CKR_KEY_TYPE_INCONSISTENT),
    }
}

pub fn sign_hmac(mech: u32, key_bytes: &[u8], msg: &[u8]) -> Result<Vec<u8>, u32> {
    use hmac::{Hmac, Mac};
    match mech {
        CKM_SHA256_HMAC => {
            let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key_bytes)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            mac.update(msg);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        CKM_SHA384_HMAC => {
            let mut mac = Hmac::<sha2::Sha384>::new_from_slice(key_bytes)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            mac.update(msg);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        CKM_SHA512_HMAC => {
            let mut mac = Hmac::<sha2::Sha512>::new_from_slice(key_bytes)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            mac.update(msg);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        CKM_SHA3_256_HMAC => {
            let mut mac = Hmac::<sha3::Sha3_256>::new_from_slice(key_bytes)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            mac.update(msg);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        CKM_SHA3_512_HMAC => {
            let mut mac = Hmac::<sha3::Sha3_512>::new_from_slice(key_bytes)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            mac.update(msg);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        _ => Err(CKR_MECHANISM_INVALID),
    }
}

pub fn sign_kmac(mech: u32, key_bytes: &[u8], msg: &[u8]) -> Result<Vec<u8>, u32> {
    sign_kmac_ext(mech, key_bytes, msg, b"", 0)
}

/// SP 800-185 KMAC with customization string `s` and `out_len` bytes of
/// output (0 = mechanism default: 32 for KMAC-128, 64 for KMAC-256).
pub fn sign_kmac_ext(
    mech: u32,
    key_bytes: &[u8],
    msg: &[u8],
    s: &[u8],
    out_len: usize,
) -> Result<Vec<u8>, u32> {
    use sp800_185::KMac;
    match mech {
        CKM_KMAC_128 => {
            let mut mac = KMac::new_kmac128(key_bytes, s);
            mac.update(msg);
            let mut out = vec![0u8; if out_len == 0 { 32 } else { out_len }];
            mac.finalize(&mut out);
            Ok(out)
        }
        CKM_KMAC_256 => {
            let mut mac = KMac::new_kmac256(key_bytes, s);
            mac.update(msg);
            let mut out = vec![0u8; if out_len == 0 { 64 } else { out_len }];
            mac.finalize(&mut out);
            Ok(out)
        }
        _ => Err(CKR_KEY_TYPE_INCONSISTENT),
    }
}

/// `pss_salt_len`: caller-supplied CK_RSA_PKCS_PSS_PARAMS.sLen (bytes).
/// `None` = the documented default (PKCS#11 v3.2 §6.2: sLen = hash length —
/// 32/48/64 for SHA-256/384/512; MGF1 uses the same hash as the mechanism).
pub fn sign_rsa(
    mech: u32,
    sk_bytes: &[u8],
    msg: &[u8],
    pss_salt_len: Option<usize>,
) -> Result<Vec<u8>, u32> {
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::signature::SignatureEncoding;
    let private_key =
        rsa::RsaPrivateKey::from_pkcs8_der(sk_bytes).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
    macro_rules! pkcs1v15_sign {
        ($hash:ty) => {{
            use rsa::pkcs1v15::SigningKey;
            use rsa::signature::Signer;
            let signing_key = SigningKey::<$hash>::new(private_key);
            let sig = signing_key.sign(msg);
            Ok(sig.to_vec())
        }};
    }
    macro_rules! pss_sign {
        ($hash:ty, $hash_len:expr) => {{
            use rsa::pss::BlindedSigningKey;
            use rsa::signature::RandomizedSigner;
            let salt_len = pss_salt_len.unwrap_or($hash_len);
            let signing_key =
                BlindedSigningKey::<$hash>::new_with_salt_len(private_key, salt_len);
            let mut rng = rand::rngs::OsRng;
            let sig = signing_key
                .try_sign_with_rng(&mut rng, msg)
                .map_err(|_| CKR_FUNCTION_FAILED)?;
            Ok(sig.to_vec())
        }};
    }
    match mech {
        CKM_SHA256_RSA_PKCS => pkcs1v15_sign!(sha2::Sha256),
        CKM_SHA384_RSA_PKCS => pkcs1v15_sign!(sha2::Sha384),
        CKM_SHA512_RSA_PKCS => pkcs1v15_sign!(sha2::Sha512),
        CKM_SHA256_RSA_PKCS_PSS => pss_sign!(sha2::Sha256, 32),
        CKM_SHA384_RSA_PKCS_PSS => pss_sign!(sha2::Sha384, 48),
        CKM_SHA512_RSA_PKCS_PSS => pss_sign!(sha2::Sha512, 64),
        _ => Err(CKR_MECHANISM_INVALID),
    }
}

pub fn sign_ecdsa(mech: u32, curve: u32, sk_bytes: &[u8], msg: &[u8]) -> Result<Vec<u8>, u32> {
    match (mech, curve) {
        (CKM_ECDSA_SHA256, CURVE_P256) | (CKM_ECDSA_SHA256, 0) => {
            use p256::ecdsa::signature::Signer;
            let sk = p256::ecdsa::SigningKey::from_slice(sk_bytes)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let sig: p256::ecdsa::Signature = sk.sign(msg);
            Ok(sig.to_bytes().to_vec())
        }
        (CKM_ECDSA_SHA384, CURVE_P384) => {
            use p384::ecdsa::signature::Signer;
            let sk = p384::ecdsa::SigningKey::from_slice(sk_bytes)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let sig: p384::ecdsa::Signature = sk.sign(msg);
            Ok(sig.to_bytes().to_vec())
        }
        (CKM_ECDSA_SHA512, CURVE_P521) => {
            use p521::ecdsa::signature::Signer;
            let sk = p521::ecdsa::SigningKey::from_slice(sk_bytes)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let sig: p521::ecdsa::Signature = sk.sign(msg);
            Ok(sig.to_bytes().to_vec())
        }
        // SHA-512 prehash on P-256 (id-MLDSA65-ECDSA-P256-SHA512 composite OID)
        // FIPS 186-5 §6.4: when hash length > curve order, use leftmost bits (truncate 64→32)
        (CKM_ECDSA_SHA512, CURVE_P256) | (CKM_ECDSA_SHA512, 0) => {
            use p256::ecdsa::signature::hazmat::PrehashSigner;
            use sha2::Digest as _;
            let sk = p256::ecdsa::SigningKey::from_slice(sk_bytes)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let hash_full = sha2::Sha512::digest(msg);
            let hash = &hash_full[..32]; // truncate to P-256 field size (FIPS 186-5 §6.4)
            let sig: p256::ecdsa::Signature =
                sk.sign_prehash(hash).map_err(|_| CKR_FUNCTION_FAILED)?;
            Ok(sig.to_bytes().to_vec())
        }
        // SHA-512 prehash on P-384
        // FIPS 186-5 §6.4: when hash length > curve order, use leftmost bits (truncate 64→48)
        (CKM_ECDSA_SHA512, CURVE_P384) => {
            use p384::ecdsa::signature::hazmat::PrehashSigner;
            use sha2::Digest as _;
            let sk = p384::ecdsa::SigningKey::from_slice(sk_bytes)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let hash_full = sha2::Sha512::digest(msg);
            let hash = &hash_full[..48]; // truncate to P-384 field size (FIPS 186-5 §6.4)
            let sig: p384::ecdsa::Signature =
                sk.sign_prehash(hash).map_err(|_| CKR_FUNCTION_FAILED)?;
            Ok(sig.to_bytes().to_vec())
        }
        (CKM_ECDSA_SHA256, CURVE_K256) => {
            use k256::ecdsa::signature::Signer;
            let sk = k256::ecdsa::SigningKey::from_slice(sk_bytes)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let sig: k256::ecdsa::Signature = sk.sign(msg);
            Ok(sig.to_bytes().to_vec())
        }
        // SHA-3 prehash variants on P-256 — manually hash then sign prehash bytes
        (CKM_ECDSA_SHA3_224, CURVE_P256)
        | (CKM_ECDSA_SHA3_224, 0)
        | (CKM_ECDSA_SHA3_256, CURVE_P256)
        | (CKM_ECDSA_SHA3_256, 0) => {
            use p256::ecdsa::signature::hazmat::PrehashSigner;
            use sha3::Digest as _;
            let sk = p256::ecdsa::SigningKey::from_slice(sk_bytes)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let hash: Vec<u8> = match mech {
                CKM_ECDSA_SHA3_224 => sha3::Sha3_224::digest(msg).to_vec(),
                _ => sha3::Sha3_256::digest(msg).to_vec(),
            };
            let sig: p256::ecdsa::Signature =
                sk.sign_prehash(&hash).map_err(|_| CKR_FUNCTION_FAILED)?;
            Ok(sig.to_bytes().to_vec())
        }
        // SHA-3 prehash variants on P-384 — manually hash then sign prehash bytes.
        // FIPS 186-5 §6.4: digests longer than the curve order use the LEFTMOST
        // bits — SHA3-512 (64 B) must be truncated to the P-384 field size (48 B).
        (CKM_ECDSA_SHA3_384, CURVE_P384) | (CKM_ECDSA_SHA3_512, CURVE_P384) => {
            use p384::ecdsa::signature::hazmat::PrehashSigner;
            use sha3::Digest as _;
            let sk = p384::ecdsa::SigningKey::from_slice(sk_bytes)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let mut hash: Vec<u8> = match mech {
                CKM_ECDSA_SHA3_512 => sha3::Sha3_512::digest(msg).to_vec(),
                _ => sha3::Sha3_384::digest(msg).to_vec(),
            };
            hash.truncate(48);
            let sig: p384::ecdsa::Signature =
                sk.sign_prehash(&hash).map_err(|_| CKR_FUNCTION_FAILED)?;
            Ok(sig.to_bytes().to_vec())
        }
        // CKM_ECDSA raw (pre-hashed) — PKCS#11 v3.2 §6.3.12
        // Spec: caller supplies the digest; token signs it directly; truncation done internally by token.
        // PrehashSigner accepts the digest bytes and signs without re-hashing.
        (CKM_ECDSA, CURVE_P256) | (CKM_ECDSA, 0) => {
            use p256::ecdsa::signature::hazmat::PrehashSigner;
            let sk = p256::ecdsa::SigningKey::from_slice(sk_bytes)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let sig: p256::ecdsa::Signature =
                sk.sign_prehash(msg).map_err(|_| CKR_FUNCTION_FAILED)?;
            Ok(sig.to_bytes().to_vec())
        }
        (CKM_ECDSA, CURVE_P384) => {
            use p384::ecdsa::signature::hazmat::PrehashSigner;
            let sk = p384::ecdsa::SigningKey::from_slice(sk_bytes)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let sig: p384::ecdsa::Signature =
                sk.sign_prehash(msg).map_err(|_| CKR_FUNCTION_FAILED)?;
            Ok(sig.to_bytes().to_vec())
        }
        (CKM_ECDSA, CURVE_P521) => {
            use p521::ecdsa::signature::hazmat::PrehashSigner;
            let sk = p521::ecdsa::SigningKey::from_slice(sk_bytes)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let sig: p521::ecdsa::Signature =
                sk.sign_prehash(msg).map_err(|_| CKR_FUNCTION_FAILED)?;
            Ok(sig.to_bytes().to_vec())
        }
        (CKM_ECDSA, CURVE_K256) => {
            use k256::ecdsa::signature::hazmat::PrehashSigner;
            let sk = k256::ecdsa::SigningKey::from_slice(sk_bytes)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let sig: k256::ecdsa::Signature =
                sk.sign_prehash(msg).map_err(|_| CKR_FUNCTION_FAILED)?;
            Ok(sig.to_bytes().to_vec())
        }
        _ => Err(CKR_MECHANISM_INVALID),
    }
}

pub fn sign_eddsa(sk_bytes: &[u8], msg: &[u8]) -> Result<Vec<u8>, u32> {
    if sk_bytes.len() != 32 {
        return Err(CKR_KEY_TYPE_INCONSISTENT);
    }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(sk_bytes);
    let sk = ed25519_dalek::SigningKey::from_bytes(&key_bytes);
    use ed25519_dalek::Signer;
    Ok(sk.sign(msg).to_bytes().to_vec())
}

pub fn sign_eddsa_ph(sk_bytes: &[u8], msg: &[u8]) -> Result<Vec<u8>, u32> {
    use sha2::Digest;
    if sk_bytes.len() != 32 {
        return Err(CKR_KEY_TYPE_INCONSISTENT);
    }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(sk_bytes);
    let sk = ed25519_dalek::SigningKey::from_bytes(&key_bytes);
    let prehash = sha2::Sha512::new().chain_update(msg);
    sk.sign_prehashed(prehash, None)
        .map(|sig| sig.to_bytes().to_vec())
        .map_err(|_| CKR_FUNCTION_FAILED)
}

/// Map a CKM_*_HMAC_GENERAL mechanism to (base full-length HMAC mechanism,
/// digest length in bytes). None for non-general mechanisms.
pub fn hmac_general_base(mech: u32) -> Option<(u32, usize)> {
    match mech {
        CKM_SHA256_HMAC_GENERAL => Some((CKM_SHA256_HMAC, 32)),
        CKM_SHA384_HMAC_GENERAL => Some((CKM_SHA384_HMAC, 48)),
        CKM_SHA512_HMAC_GENERAL => Some((CKM_SHA512_HMAC, 64)),
        CKM_SHA3_256_HMAC_GENERAL => Some((CKM_SHA3_256_HMAC, 32)),
        CKM_SHA3_512_HMAC_GENERAL => Some((CKM_SHA3_512_HMAC, 64)),
        _ => None,
    }
}

pub fn get_sig_len(mech: u32, hkey: u32) -> u32 {
    let ps = get_object_param_set(hkey);
    match mech {
        CKM_ML_DSA => match ps {
            CKP_ML_DSA_44 => 2420,
            CKP_ML_DSA_87 => 4627,
            _ => 3309,
        },
        // Pre-hash ML-DSA variants produce the same signature length as pure ML-DSA
        m if is_prehash_ml_dsa(m) => match ps {
            CKP_ML_DSA_44 => 2420,
            CKP_ML_DSA_87 => 4627,
            _ => 3309,
        },
        CKM_SLH_DSA => match ps {
            CKP_SLH_DSA_SHA2_128S | CKP_SLH_DSA_SHAKE_128S => 7856,
            CKP_SLH_DSA_SHA2_128F | CKP_SLH_DSA_SHAKE_128F => 17088,
            CKP_SLH_DSA_SHA2_192S | CKP_SLH_DSA_SHAKE_192S => 16224,
            CKP_SLH_DSA_SHA2_192F | CKP_SLH_DSA_SHAKE_192F => 35664,
            CKP_SLH_DSA_SHA2_256S | CKP_SLH_DSA_SHAKE_256S => 29792,
            _ => 49856,
        },
        // Pre-hash SLH-DSA variants produce the same signature length as pure SLH-DSA
        m if is_prehash_slh_dsa(m) => match ps {
            CKP_SLH_DSA_SHA2_128S | CKP_SLH_DSA_SHAKE_128S => 7856,
            CKP_SLH_DSA_SHA2_128F | CKP_SLH_DSA_SHAKE_128F => 17088,
            CKP_SLH_DSA_SHA2_192S | CKP_SLH_DSA_SHAKE_192S => 16224,
            CKP_SLH_DSA_SHA2_192F | CKP_SLH_DSA_SHAKE_192F => 35664,
            CKP_SLH_DSA_SHA2_256S | CKP_SLH_DSA_SHAKE_256S => 29792,
            _ => 49856,
        },
        // XMSS — sig = idx(4) + random(n) + WOTS+_sig(len*n) + auth_path(h*n); n=32, len=67 (w=16)
        CKM_XMSS => {
            let xmss_param =
                get_object_attr_u32(hkey, CKA_XMSS_PARAM_SET).unwrap_or(CKP_XMSS_SHA2_10_256);
            let h: u32 = match xmss_param {
                CKP_XMSS_SHA2_16_256 | CKP_XMSS_SHAKE_16_256 => 16,
                CKP_XMSS_SHA2_20_256 | CKP_XMSS_SHAKE_20_256 => 20,
                _ => 10,
            };
            4 + 32 + 67 * 32 + h * 32
        }
        // LMS/HSS — size depends on param set; compute from key attributes.
        // Formula (RFC 8554): LMOTS sig = 4+n+p*n; LMS sig = 4+lmots_sig+4+h*n; HSS sig = 4+Npub*pub_size+Nsig*lms_sig
        // For n=32: LMOTS(W1)=4+32+265*32=8724, LMOTS(W4)=4+32+67*32=2180, LMOTS(W8)=4+32+34*32=1124
        // LMS(H5/W4)=2348, LMS(H25/W4)=8188; HSS(L=8,H5/W4) ≈ 8*(2348+52)+4 = 19204
        CKM_HSS => {
            let lms_param =
                get_object_attr_u32(hkey, CKA_LMS_PARAM_SET).unwrap_or(CKP_LMS_SHA256_M32_H5);
            let lmots_param =
                get_object_attr_u32(hkey, CKA_LMOTS_PARAM_SET).unwrap_or(CKP_LMOTS_SHA256_N32_W4);
            let levels = get_object_attr_u32(hkey, CKA_HSS_LMS_TYPE).unwrap_or(1);
            hss_sig_len(levels, lms_param, lmots_param)
        }
        CKM_SHA256_HMAC | CKM_SHA3_256_HMAC => 32,
        CKM_SHA384_HMAC => 48,
        CKM_SHA512_HMAC | CKM_SHA3_512_HMAC => 64,
        CKM_KMAC_128 => 32,
        CKM_KMAC_256 => 64,
        CKM_SHA256_RSA_PKCS | CKM_SHA384_RSA_PKCS | CKM_SHA512_RSA_PKCS
        | CKM_SHA256_RSA_PKCS_PSS | CKM_SHA384_RSA_PKCS_PSS | CKM_SHA512_RSA_PKCS_PSS => 512,
        // ECDSA — sig size = 2 × ⌈curve_bits / 8⌉, independent of the hash. The
        // SHA384/SHA3-384 hardcode for 96-byte was wrong for P-256 + P-521 etc;
        // size MUST come from the key's curve, not the hash mechanism.
        // - P-256 / secp256k1 (256-bit) → 64 bytes (32 + 32)
        // - P-384            (384-bit) → 96 bytes (48 + 48)
        // - P-521            (521-bit) → 132 bytes (66 + 66)
        CKM_ECDSA_SHA256
        | CKM_ECDSA_SHA384
        | CKM_ECDSA_SHA512
        | CKM_ECDSA_SHA3_224
        | CKM_ECDSA_SHA3_256
        | CKM_ECDSA_SHA3_384
        | CKM_ECDSA_SHA3_512 => match ps {
            CURVE_P521 => 132,
            CURVE_P384 => 96,
            _ => 64, // CURVE_P256, CURVE_K256, and default
        },
        CKM_EDDSA | CKM_EDDSA_PH => 64,
        _ => 512,
    }
}

/// Compute the byte length of a single-level LMS signature (RFC 8554 §5.4).
/// n=32 (SHA-256/M32), p depends on W.
pub fn lms_single_sig_len(lms_param: u32, lmots_param: u32) -> u32 {
    // Derive n (hash output bytes) from LMS IANA type ID range (SP 800-208 §4):
    //   0x05–0x09: SHA-256/M32, 0x0F–0x13: SHAKE-256/M32 → n=32
    //   0x0A–0x0E: SHA-256/M24, 0x14–0x18: SHAKE-256/M24 → n=24
    let n: u32 = match lms_param {
        0x05..=0x09 | 0x0F..=0x13 => 32,
        0x0A..=0x0E | 0x14..=0x18 => 24,
        _ => 32,
    };
    // p = LMOTS chain count per (n, W). SP 800-208 Appendix B.
    let p: u32 = match lmots_param {
        0x01 | 0x09 => 265, // N32 W1 (SHA-256 / SHAKE-256)
        0x02 | 0x0A => 133, // N32 W2
        0x03 | 0x0B => 67,  // N32 W4
        0x04 | 0x0C => 34,  // N32 W8
        0x05 | 0x0D => 200, // N24 W1
        0x06 | 0x0E => 101, // N24 W2
        0x07 | 0x0F => 51,  // N24 W4
        0x08 | 0x10 => 26,  // N24 W8
        _ => 67,
    };
    // h = tree height (same offset pattern in each range of 5)
    let h: u32 = match lms_param {
        0x05 | 0x0A | 0x0F | 0x14 => 5,
        0x06 | 0x0B | 0x10 | 0x15 => 10,
        0x07 | 0x0C | 0x11 | 0x16 => 15,
        0x08 | 0x0D | 0x12 | 0x17 => 20,
        0x09 | 0x0E | 0x13 | 0x18 => 25,
        _ => 5,
    };
    let lmots_sig_len = 4 + n + p * n; // typecode + C + y[]
    4 + lmots_sig_len + 4 + h * n // q + ots_sig + typecode + path[]
}

/// Compute the byte length of an HSS signature (RFC 8554 §6.3).
/// LMS public key size = 4+16+32 = 52 bytes.
pub fn hss_sig_len(levels: u32, lms_param: u32, lmots_param: u32) -> u32 {
    let lms_sig = lms_single_sig_len(lms_param, lmots_param);
    let lms_pub = 56u32; // lms_type(4) + lmots_type(4) + I(16) + T[1](32) — RFC 8554 §5.4
    let l = levels.max(1);
    // HSS sig: Nspk(4) + (L-1)*(pub + sig) + 1*sig
    4 + (l - 1) * (lms_pub + lms_sig) + lms_sig
}

// ── Verify Helpers ──────────────────────────────────────────────────────────

/// Verify an ML-DSA signature with the caller's FIPS 204 context string
/// (empty when no CK_SIGN_ADDITIONAL_CONTEXT was supplied).
pub fn verify_ml_dsa(
    mech: u32,
    ps: u32,
    pk_bytes: &[u8],
    msg: &[u8],
    sig_bytes: &[u8],
    ctx: &[u8],
) -> Result<(), u32> {
    use fips204::traits::Verifier;
    match ps {
        CKP_ML_DSA_44 => {
            let pk_arr: &<fips204::ml_dsa_44::PublicKey as fips204::traits::SerDes>::ByteArray =
                pk_bytes.try_into().map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let pk =
                <fips204::ml_dsa_44::PublicKey as fips204::traits::SerDes>::try_from_bytes(*pk_arr)
                    .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let sig: <fips204::ml_dsa_44::PublicKey as fips204::traits::Verifier>::Signature =
                sig_bytes.try_into().map_err(|_| CKR_SIGNATURE_INVALID)?;
            match get_ml_dsa_ph(mech) {
                Some(ph) => {
                    if pk.hash_verify(msg, &sig, ctx, &ph) {
                        Ok(())
                    } else {
                        Err(CKR_SIGNATURE_INVALID)
                    }
                }
                None => {
                    if pk.verify(msg, &sig, ctx) {
                        Ok(())
                    } else {
                        Err(CKR_SIGNATURE_INVALID)
                    }
                }
            }
        }
        CKP_ML_DSA_65 | 0 => {
            let pk_arr: &<fips204::ml_dsa_65::PublicKey as fips204::traits::SerDes>::ByteArray =
                pk_bytes.try_into().map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let pk =
                <fips204::ml_dsa_65::PublicKey as fips204::traits::SerDes>::try_from_bytes(*pk_arr)
                    .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let sig: <fips204::ml_dsa_65::PublicKey as fips204::traits::Verifier>::Signature =
                sig_bytes.try_into().map_err(|_| CKR_SIGNATURE_INVALID)?;
            match get_ml_dsa_ph(mech) {
                Some(ph) => {
                    if pk.hash_verify(msg, &sig, ctx, &ph) {
                        Ok(())
                    } else {
                        Err(CKR_SIGNATURE_INVALID)
                    }
                }
                None => {
                    if pk.verify(msg, &sig, ctx) {
                        Ok(())
                    } else {
                        Err(CKR_SIGNATURE_INVALID)
                    }
                }
            }
        }
        CKP_ML_DSA_87 => {
            let pk_arr: &<fips204::ml_dsa_87::PublicKey as fips204::traits::SerDes>::ByteArray =
                pk_bytes.try_into().map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let pk =
                <fips204::ml_dsa_87::PublicKey as fips204::traits::SerDes>::try_from_bytes(*pk_arr)
                    .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let sig: <fips204::ml_dsa_87::PublicKey as fips204::traits::Verifier>::Signature =
                sig_bytes.try_into().map_err(|_| CKR_SIGNATURE_INVALID)?;
            match get_ml_dsa_ph(mech) {
                Some(ph) => {
                    if pk.hash_verify(msg, &sig, ctx, &ph) {
                        Ok(())
                    } else {
                        Err(CKR_SIGNATURE_INVALID)
                    }
                }
                None => {
                    if pk.verify(msg, &sig, ctx) {
                        Ok(())
                    } else {
                        Err(CKR_SIGNATURE_INVALID)
                    }
                }
            }
        }
        _ => Err(CKR_KEY_TYPE_INCONSISTENT),
    }
}

pub fn verify_slh_dsa(
    mech: u32,
    ps: u32,
    pk_bytes: &[u8],
    msg: &[u8],
    sig_bytes: &[u8],
    ctx: &[u8],
) -> Result<(), u32> {
    match ps {
        CKP_SLH_DSA_SHA2_128S => slh_dsa_verify!(
            fips205::slh_dsa_sha2_128s::PublicKey,
            mech,
            pk_bytes,
            msg,
            sig_bytes,
            ctx
        ),
        CKP_SLH_DSA_SHAKE_128S => slh_dsa_verify!(
            fips205::slh_dsa_shake_128s::PublicKey,
            mech,
            pk_bytes,
            msg,
            sig_bytes,
            ctx
        ),
        CKP_SLH_DSA_SHA2_128F => slh_dsa_verify!(
            fips205::slh_dsa_sha2_128f::PublicKey,
            mech,
            pk_bytes,
            msg,
            sig_bytes,
            ctx
        ),
        CKP_SLH_DSA_SHAKE_128F => slh_dsa_verify!(
            fips205::slh_dsa_shake_128f::PublicKey,
            mech,
            pk_bytes,
            msg,
            sig_bytes,
            ctx
        ),
        CKP_SLH_DSA_SHA2_192S => slh_dsa_verify!(
            fips205::slh_dsa_sha2_192s::PublicKey,
            mech,
            pk_bytes,
            msg,
            sig_bytes,
            ctx
        ),
        CKP_SLH_DSA_SHAKE_192S => slh_dsa_verify!(
            fips205::slh_dsa_shake_192s::PublicKey,
            mech,
            pk_bytes,
            msg,
            sig_bytes,
            ctx
        ),
        CKP_SLH_DSA_SHA2_192F => slh_dsa_verify!(
            fips205::slh_dsa_sha2_192f::PublicKey,
            mech,
            pk_bytes,
            msg,
            sig_bytes,
            ctx
        ),
        CKP_SLH_DSA_SHAKE_192F => slh_dsa_verify!(
            fips205::slh_dsa_shake_192f::PublicKey,
            mech,
            pk_bytes,
            msg,
            sig_bytes,
            ctx
        ),
        CKP_SLH_DSA_SHA2_256S => slh_dsa_verify!(
            fips205::slh_dsa_sha2_256s::PublicKey,
            mech,
            pk_bytes,
            msg,
            sig_bytes,
            ctx
        ),
        CKP_SLH_DSA_SHAKE_256S => slh_dsa_verify!(
            fips205::slh_dsa_shake_256s::PublicKey,
            mech,
            pk_bytes,
            msg,
            sig_bytes,
            ctx
        ),
        CKP_SLH_DSA_SHA2_256F => slh_dsa_verify!(
            fips205::slh_dsa_sha2_256f::PublicKey,
            mech,
            pk_bytes,
            msg,
            sig_bytes,
            ctx
        ),
        CKP_SLH_DSA_SHAKE_256F => slh_dsa_verify!(
            fips205::slh_dsa_shake_256f::PublicKey,
            mech,
            pk_bytes,
            msg,
            sig_bytes,
            ctx
        ),
        _ => Err(CKR_KEY_TYPE_INCONSISTENT),
    }
}

pub fn verify_hmac(mech: u32, key_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> Result<(), u32> {
    use subtle::ConstantTimeEq;
    let expected = sign_hmac(mech, key_bytes, msg)?;
    if expected.len() == sig_bytes.len() && expected.ct_eq(sig_bytes).into() {
        Ok(())
    } else {
        Err(CKR_SIGNATURE_INVALID)
    }
}

/// PKCS#11 v3.2 §2.1.2: RSA public key has CKA_MODULUS (n) and CKA_PUBLIC_EXPONENT (e).
/// Both are unsigned big-endian byte arrays; CKA_VALUE is NOT defined for RSA public keys.
/// `pss_salt_len`: caller-supplied CK_RSA_PKCS_PSS_PARAMS.sLen (bytes).
/// `Some(n)` pins EMSA-PSS-VERIFY to that salt length (§6.4.5 — the caller's
/// parameters are authoritative). `None` (no params supplied / native path)
/// keeps the historical two-candidate acceptance: sLen = hashLen and
/// sLen = modOctets - hashLen - 2 (OpenSSL's `rsa_pss_saltlen:auto`), which
/// the KMIP conformance suite depends on.
pub fn verify_rsa(
    mech: u32,
    n_bytes: &[u8],
    e_bytes: &[u8],
    msg: &[u8],
    sig_bytes: &[u8],
    pss_salt_len: Option<usize>,
) -> Result<(), u32> {
    use rsa::signature::Verifier;
    if n_bytes.is_empty() || e_bytes.is_empty() {
        return Err(CKR_KEY_TYPE_INCONSISTENT);
    }
    let n = rsa::BigUint::from_bytes_be(n_bytes);
    let e = rsa::BigUint::from_bytes_be(e_bytes);
    let public_key = rsa::RsaPublicKey::new(n, e).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;

    macro_rules! pkcs1v15_verify {
        ($hash:ty) => {{
            let vk = rsa::pkcs1v15::VerifyingKey::<$hash>::new(public_key);
            let sig =
                rsa::pkcs1v15::Signature::try_from(sig_bytes).map_err(|_| CKR_SIGNATURE_INVALID)?;
            vk.verify(msg, &sig).map_err(|_| CKR_SIGNATURE_INVALID)
        }};
    }
    macro_rules! pss_verify {
        ($hash:ty, $hash_len:expr) => {{
            use rsa::traits::PublicKeyParts;
            let sig =
                rsa::pss::Signature::try_from(sig_bytes).map_err(|_| CKR_SIGNATURE_INVALID)?;
            // RFC 8017 §9.1.2 — EMSA-PSS-VERIFY parameterised by salt
            // length. The `rsa` crate's default verifier pins sLen =
            // hashLen. OASIS conformance signatures use sLen =
            // modulus_octets - hashLen - 2 (the "maximum" form openssl
            // exposes as `rsa_pss_saltlen:auto`). Try both so we accept
            // either convention.
            let mod_octets = public_key.size();
            let hash_len: usize = $hash_len;
            let candidates: Vec<usize> = match pss_salt_len {
                Some(s) => vec![s],
                None => vec![hash_len, mod_octets.saturating_sub(hash_len + 2)],
            };
            for salt_len in candidates {
                let vk = rsa::pss::VerifyingKey::<$hash>::new_with_salt_len(
                    public_key.clone(),
                    salt_len,
                );
                if vk.verify(msg, &sig).is_ok() {
                    return Ok(());
                }
            }
            Err(CKR_SIGNATURE_INVALID)
        }};
    }
    match mech {
        CKM_SHA256_RSA_PKCS => pkcs1v15_verify!(sha2::Sha256),
        CKM_SHA384_RSA_PKCS => pkcs1v15_verify!(sha2::Sha384),
        CKM_SHA512_RSA_PKCS => pkcs1v15_verify!(sha2::Sha512),
        CKM_SHA256_RSA_PKCS_PSS => pss_verify!(sha2::Sha256, 32),
        CKM_SHA384_RSA_PKCS_PSS => pss_verify!(sha2::Sha384, 48),
        CKM_SHA512_RSA_PKCS_PSS => pss_verify!(sha2::Sha512, 64),
        _ => Err(CKR_MECHANISM_INVALID),
    }
}

pub fn verify_ecdsa(
    mech: u32,
    curve: u32,
    pk_bytes: &[u8],
    msg: &[u8],
    sig_bytes: &[u8],
) -> Result<(), u32> {
    match (mech, curve) {
        (CKM_ECDSA_SHA256, CURVE_P256) | (CKM_ECDSA_SHA256, 0) => {
            use p256::ecdsa::signature::Verifier;
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(pk_bytes)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let sig =
                p256::ecdsa::Signature::try_from(sig_bytes).map_err(|_| CKR_SIGNATURE_INVALID)?;
            vk.verify(msg, &sig).map_err(|_| CKR_SIGNATURE_INVALID)
        }
        (CKM_ECDSA_SHA384, CURVE_P384) | (CKM_ECDSA_SHA384, 0) => {
            use p384::ecdsa::signature::Verifier;
            let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(pk_bytes)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let sig =
                p384::ecdsa::Signature::try_from(sig_bytes).map_err(|_| CKR_SIGNATURE_INVALID)?;
            vk.verify(msg, &sig).map_err(|_| CKR_SIGNATURE_INVALID)
        }
        (CKM_ECDSA_SHA512, CURVE_P521) => {
            use p521::ecdsa::signature::Verifier;
            let vk = p521::ecdsa::VerifyingKey::from_sec1_bytes(pk_bytes)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let sig =
                p521::ecdsa::Signature::try_from(sig_bytes).map_err(|_| CKR_SIGNATURE_INVALID)?;
            vk.verify(msg, &sig).map_err(|_| CKR_SIGNATURE_INVALID)
        }
        // SHA-512 prehash on P-256 (id-MLDSA65-ECDSA-P256-SHA512 composite OID)
        // FIPS 186-5 §6.4: truncate 64-byte hash to leftmost 32 bytes (P-256 field size)
        (CKM_ECDSA_SHA512, CURVE_P256) | (CKM_ECDSA_SHA512, 0) => {
            use p256::ecdsa::signature::hazmat::PrehashVerifier;
            use sha2::Digest as _;
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(pk_bytes)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let sig =
                p256::ecdsa::Signature::try_from(sig_bytes).map_err(|_| CKR_SIGNATURE_INVALID)?;
            let hash_full = sha2::Sha512::digest(msg);
            let hash = &hash_full[..32]; // truncate to P-256 field size (FIPS 186-5 §6.4)
            vk.verify_prehash(hash, &sig)
                .map_err(|_| CKR_SIGNATURE_INVALID)
        }
        // SHA-512 prehash on P-384
        // FIPS 186-5 §6.4: truncate 64-byte hash to leftmost 48 bytes (P-384 field size)
        (CKM_ECDSA_SHA512, CURVE_P384) => {
            use p384::ecdsa::signature::hazmat::PrehashVerifier;
            use sha2::Digest as _;
            let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(pk_bytes)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let sig =
                p384::ecdsa::Signature::try_from(sig_bytes).map_err(|_| CKR_SIGNATURE_INVALID)?;
            let hash_full = sha2::Sha512::digest(msg);
            let hash = &hash_full[..48]; // truncate to P-384 field size (FIPS 186-5 §6.4)
            vk.verify_prehash(hash, &sig)
                .map_err(|_| CKR_SIGNATURE_INVALID)
        }
        (CKM_ECDSA_SHA256, CURVE_K256) => {
            use k256::ecdsa::signature::Verifier;
            let vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(pk_bytes)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let sig =
                k256::ecdsa::Signature::try_from(sig_bytes).map_err(|_| CKR_SIGNATURE_INVALID)?;
            vk.verify(msg, &sig).map_err(|_| CKR_SIGNATURE_INVALID)
        }
        // SHA-3 prehash variants on P-256 — manually hash then verify prehash bytes
        (CKM_ECDSA_SHA3_224, CURVE_P256)
        | (CKM_ECDSA_SHA3_224, 0)
        | (CKM_ECDSA_SHA3_256, CURVE_P256)
        | (CKM_ECDSA_SHA3_256, 0) => {
            use p256::ecdsa::signature::hazmat::PrehashVerifier;
            use sha3::Digest as _;
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(pk_bytes)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let sig =
                p256::ecdsa::Signature::try_from(sig_bytes).map_err(|_| CKR_SIGNATURE_INVALID)?;
            let hash: Vec<u8> = match mech {
                CKM_ECDSA_SHA3_224 => sha3::Sha3_224::digest(msg).to_vec(),
                _ => sha3::Sha3_256::digest(msg).to_vec(),
            };
            vk.verify_prehash(&hash, &sig)
                .map_err(|_| CKR_SIGNATURE_INVALID)
        }
        // SHA-3 prehash variants on P-384 — manually hash then verify prehash bytes
        (CKM_ECDSA_SHA3_384, CURVE_P384) | (CKM_ECDSA_SHA3_512, CURVE_P384) => {
            use p384::ecdsa::signature::hazmat::PrehashVerifier;
            use sha3::Digest as _;
            let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(pk_bytes)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let sig =
                p384::ecdsa::Signature::try_from(sig_bytes).map_err(|_| CKR_SIGNATURE_INVALID)?;
            // FIPS 186-5 §6.4 — truncate SHA3-512 (64 B) to the P-384 field
            // size (48 B), matching sign_ecdsa.
            let mut hash: Vec<u8> = match mech {
                CKM_ECDSA_SHA3_512 => sha3::Sha3_512::digest(msg).to_vec(),
                _ => sha3::Sha3_384::digest(msg).to_vec(),
            };
            hash.truncate(48);
            vk.verify_prehash(&hash, &sig)
                .map_err(|_| CKR_SIGNATURE_INVALID)
        }
        // CKM_ECDSA raw (pre-hashed) — PKCS#11 v3.2 §6.3.12
        // Spec: caller supplies the digest; token verifies it directly; truncation done internally by token.
        // PrehashVerifier accepts the digest bytes and verifies without re-hashing.
        (CKM_ECDSA, CURVE_P256) | (CKM_ECDSA, 0) => {
            use p256::ecdsa::signature::hazmat::PrehashVerifier;
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(pk_bytes)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let sig =
                p256::ecdsa::Signature::try_from(sig_bytes).map_err(|_| CKR_SIGNATURE_INVALID)?;
            vk.verify_prehash(msg, &sig)
                .map_err(|_| CKR_SIGNATURE_INVALID)
        }
        (CKM_ECDSA, CURVE_P384) => {
            use p384::ecdsa::signature::hazmat::PrehashVerifier;
            let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(pk_bytes)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let sig =
                p384::ecdsa::Signature::try_from(sig_bytes).map_err(|_| CKR_SIGNATURE_INVALID)?;
            vk.verify_prehash(msg, &sig)
                .map_err(|_| CKR_SIGNATURE_INVALID)
        }
        (CKM_ECDSA, CURVE_P521) => {
            use p521::ecdsa::signature::hazmat::PrehashVerifier;
            let vk = p521::ecdsa::VerifyingKey::from_sec1_bytes(pk_bytes)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let sig =
                p521::ecdsa::Signature::try_from(sig_bytes).map_err(|_| CKR_SIGNATURE_INVALID)?;
            vk.verify_prehash(msg, &sig)
                .map_err(|_| CKR_SIGNATURE_INVALID)
        }
        (CKM_ECDSA, CURVE_K256) => {
            use k256::ecdsa::signature::hazmat::PrehashVerifier;
            let vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(pk_bytes)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let sig =
                k256::ecdsa::Signature::try_from(sig_bytes).map_err(|_| CKR_SIGNATURE_INVALID)?;
            vk.verify_prehash(msg, &sig)
                .map_err(|_| CKR_SIGNATURE_INVALID)
        }
        _ => Err(CKR_MECHANISM_INVALID),
    }
}

pub fn verify_eddsa(pk_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> Result<(), u32> {
    let pk_arr: &[u8; 32] = pk_bytes.try_into().map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
    let sig_arr: &[u8; 64] = sig_bytes.try_into().map_err(|_| CKR_SIGNATURE_INVALID)?;
    let vk =
        ed25519_dalek::VerifyingKey::from_bytes(pk_arr).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
    let sig = ed25519_dalek::Signature::from_bytes(sig_arr);
    use ed25519_dalek::Verifier;
    vk.verify(msg, &sig).map_err(|_| CKR_SIGNATURE_INVALID)
}

pub fn verify_eddsa_ph(pk_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> Result<(), u32> {
    use sha2::Digest;
    let pk_arr: &[u8; 32] = pk_bytes.try_into().map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
    let sig_arr: &[u8; 64] = sig_bytes.try_into().map_err(|_| CKR_SIGNATURE_INVALID)?;
    let vk =
        ed25519_dalek::VerifyingKey::from_bytes(pk_arr).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
    let sig = ed25519_dalek::Signature::from_bytes(sig_arr);
    let prehash = sha2::Sha512::new().chain_update(msg);
    vk.verify_prehashed(prehash, None, &sig)
        .map_err(|_| CKR_SIGNATURE_INVALID)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn test_p521_kat_verify() {
        // RFC 6979 Appendix A.2.7 — ECDSA, P-521, SHA-512, message "sample"
        let msg = b"sample";

        // SEC1 uncompressed: 04 || Ux(66 bytes) || Uy(66 bytes) = 133 bytes
        let pk_hex = "04\
01894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD371123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F5023A4\
00493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A28A0DB25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDFCF5";
        let pk_bytes = decode_hex(pk_hex);
        assert_eq!(pk_bytes.len(), 133);

        // r(66 bytes) || s(66 bytes) = 132 bytes
        let sig_hex = "\
00C328FAFCBD79DD77850370C46325D987CB525569FB63C5D3BC53950E6D4C5F174E25A1EE9017B5D450606ADD152B534931D7D4E8455CC91F9B15BF05EC36E377FA\
00617CCE7CF5064806C467F678D3B4080D6F1CC50AF26CA209417308281B68AF282623EAA63E5B5C0723D8B8C37FF0777B1A20F8CCB1DCCC43997F1EE0E44DA4A67A";
        let sig_bytes = decode_hex(sig_hex);
        assert_eq!(sig_bytes.len(), 132);

        let rv = verify_ecdsa(
            crate::constants::CKM_ECDSA_SHA512,
            CURVE_P521,
            &pk_bytes,
            msg,
            &sig_bytes,
        );
        assert_eq!(rv, Ok(()));
    }

    // ── S6 — RSA SHA-384/512 PKCS#1 v1.5 + PSS cross-validation ────────────
    //
    // Fixed RSA-2048 test key + signatures generated with OpenSSL 3.6.2:
    //   openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048
    //   openssl dgst -sha384|-sha512 -sign key.pem msg            (v1.5)
    //   openssl dgst -sha384|-sha512 -sign key.pem \
    //     -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest msg
    // msg = "S6 RSA hash-variant KAT message".

    const S6_MSG: &[u8] = b"S6 RSA hash-variant KAT message";

    /// PKCS#8 DER of the RSA-2048 test private key.
    const S6_KEY_PKCS8_HEX: &str = "\
308204bc020100300d06092a864886f70d0101010500048204a6308204a20201000282010100d617b3c9aeeb2b114984bffe9776a5f2b47db90d5e9c11a5028f\
ece637e4d2181fd3be5e59c29e96a179793c7b2c4f1ea6fada330ac47b79930d101db591d612cbfcd6dd1eb1d22b6b4d1de5edd760e0697bef75763a0d5ad469\
67bcda98e10e6076b91590407fa16965f0648d0233d30f4735e8a7d67e9c8d1b9367ef77fb8d4e4477ed941b4ee05474d932f3bc03a976f2e404500f4d320327\
e3725f9f2a76f59003ecd7e0cebfc2c35ad445c348a396cc0ff6fcbd7635892f8dd1518ecde00339b623e19dc1ef12ef06515e0bf53cc3415e51751d476904eb\
1a66cc7904a25cc92328b5edcdaec514d4740a198559244a415622b481130779e6d1b0347ee302030100010282010021c874b4d716c1e184f5df2c07ef8f8928\
650c5de9377c6b4ae7b62cafd63a36d752dcdfdb8f23e24611ba894a30783db080b60cc6deb153425a95d7f24e5476fbdc667557021d557fa59819afb9c44e35\
26fae6d0a4a175db3dd4c24ec640013a4491b92edd96a63c50fb298abcb5bbd0d5de525ba5b3adf5704c06e3194e46b85b67e0f638ad33b26f515407973cf163\
8491466f19e14e4814bb9e5761465c7b03827ea108352029410f1e99fe8a4154b9e30862a94fe8332dc965b56a9f1b893637c16ba571e6b6545ca521b9674644\
e1540a25dc9c732994a258d16e5a73154487ce9b1b71c0cdbc84800e86314f6514193b3fbd5a60dfe1eba1ac6ea67902818100fd9ebdf767cc9b2115215f9835\
2edd13f9d2d7c54650272a780a1ff0c0dcf500df71faa6d5e6834d9c3210e3bf3d5242a16f2c3a34a5d0dc62f7e119272d30cc6b8b777dc42174d940c12aef20\
e9390ff06fe128ae7efc2d0c29563b5285ef76f7613751cb7ea26ed37421acaf49531d9561c4dc2e86920f0a67f5c344ba2c4902818100d81a0164f5beab523c\
aa226c2550473b6eb1bf0faf7ef321442b4caea946c6ba3d2e2d10b2ae286f08d81a4216d3af8f16d36233bc348b94102c7eff69faeb1c920e186fcb27ad1def\
50411044602392271afcc51dbc601ba75e63ffd08fcea528a494a3511d7e97acad9a1f0c230aac2ea3371173ef7fe2ec1b19b9d1be59cb028180250ed4e3199f\
a3eb29933ecc96b8ca44e8f40de31d6b08ce03cc36ee8ebfba6cee39514e9f62973cf7ddb8ea0e3f7f8d8cd919b5478c1300a0d56766ad7ac4ee99a83f45792b\
0a4fd44e655f9b87787703c2d53b8483b9853b89aeb7ec4ef5b6845f081e4385b5664c2f63dc3fa08f2c7b6f55bc766fe3579f45a17b6ec765410281804bf217\
bb5b81fec38ffe5aca96f277963378d424b7106e71aa7b6d1f94ee02b940f7116f64dc3fe985ba2cc03d3577e559a84042de49b923f7eb2b56a7f03ee07393f0\
92995b00441cee9f6f10189967abc6983ece0c7dda3a1fba15153ef4e8a637f0e4d48501105ce745dad3711d3715ccd67593c0ffb8c8315e0127ed35b1028180\
569e4b3c52670f759b6dadb46bfbd47c96068d6584a06a3e881b991bc6e9840e787f606d65f401c81e51dc44729e8cad40b6d1897a65ef663185185608f8ac47\
e2f63942788c7560167d92250a8b346fa3e75c46e35c4c0bc817c9071e188e30345cbbb39c05f9c94bcf2b83b6802f67a545e7daeb3f52e6a46ae6caf6d42d9b";

    /// CKA_MODULUS of the test key (e = 65537).
    const S6_MODULUS_HEX: &str = "\
d617b3c9aeeb2b114984bffe9776a5f2b47db90d5e9c11a5028fece637e4d2181fd3be5e59c29e96a179793c7b2c4f1ea6fada330ac47b79930d101db591d612\
cbfcd6dd1eb1d22b6b4d1de5edd760e0697bef75763a0d5ad46967bcda98e10e6076b91590407fa16965f0648d0233d30f4735e8a7d67e9c8d1b9367ef77fb8d\
4e4477ed941b4ee05474d932f3bc03a976f2e404500f4d320327e3725f9f2a76f59003ecd7e0cebfc2c35ad445c348a396cc0ff6fcbd7635892f8dd1518ecde0\
0339b623e19dc1ef12ef06515e0bf53cc3415e51751d476904eb1a66cc7904a25cc92328b5edcdaec514d4740a198559244a415622b481130779e6d1b0347ee3";

    /// OpenSSL `dgst -sha384 -sign` (PKCS#1 v1.5 — deterministic).
    const S6_SIG_SHA384_V15_HEX: &str = "\
c37657596f2f09f61c9255bf6b5b32dc4c3938c2a850b4ad996c1df4a35c054462723b37e2e79c3c63eeaa5211d184382cd49dd60006864d89ff3e43f1fb5a76\
e0ff3e8cee25157af90546ff73ef65e0a99b834d1d07b970ac1955df7752bba3992d7dedc8c3bb6745b9d5813a771e2c0951c2405a03b32bbb8a7598d1604ceb\
99134afc7fa0a08ba99875c21db6b0362d9a383dea39da83610717103e7ff29421ea890448682a9902ba7dfc60e4cbb20774d8414d56dd02711b400179821e0a\
072f1a4de653ae6a0702ba3b48589508737bb696333925ab0b7377aa605508ca5376b00d30b7c57a8a5153e177fbadbc9d378adb834ca6cfd1bac6d098066a87";

    /// OpenSSL `dgst -sha512 -sign` (PKCS#1 v1.5 — deterministic).
    const S6_SIG_SHA512_V15_HEX: &str = "\
ca9163a016c9b58af59d823d49a0115f2831e164c704eb073a91b91e8cfeca2a2305c733870866b82903b7719a80a697f94b569493051bef81ab16d1c46a9ef0\
f438f295565b741df993c70bf59b4aa6103a7da949a5fc3a04d03db11109071a5d5994a10325038a3b924248c74d2955652950eaab757586623cf90ceaa038eb\
2410b37e656b24ca61b5118f4e4c4f2e0ef30d8b79e4afdff0dd1d65905d7654d0342254f8127a3aee468495f25688d40dd0df257fc66ed97d3652c983a01f3f\
7ea7f06d3786dfa959f40ff8cfe4322d299327a0112c5c68167ad60c23f8af982c181a3869ef25744a417e62ea5cad47d17eaaf262109ccc1496a191d89aca7b";

    /// OpenSSL PSS, SHA-384 + MGF1-SHA384, saltlen = digest (48).
    const S6_SIG_SHA384_PSS_HEX: &str = "\
56595a5e87afa7a7dc0f2a49f694c40a05c5f7ca2b4bcf854329acc70fff65c097701e9b56583aaf01de2805d404a6fa8586cc1ce47c890dbf0183da1727ec78\
b9b6737711268ed5b1447aeb62ed24f7dcb399bed5d590f70a2b817ed2fe2785d996311bf6ec2b071dc4f6eae8eefa4e08d7e7b651970a6cdb802fcb10409301\
5a0616adc7a1955cc2d422fecdbc68cbf13e90bbdb72f399d203b108a64d2ec5310adb83b2191c926d973c27f0a14c9cdecfeb92c3d3656cd29d6e7876cc3edf\
97be2fcb5d106332bc38b01de6d33960d2c16c234add43a4f5e4be3e1e3b542d4359978a7666b402deda1f3c856529b8a2bc6a7b98727c009d080288cfba0879";

    /// OpenSSL PSS, SHA-512 + MGF1-SHA512, saltlen = digest (64).
    const S6_SIG_SHA512_PSS_HEX: &str = "\
c9953b1ca32cca974e11acab07607b6e7ac852aa06395b8da8250c4d883f6b414d2b3e39273dde78b2e3c8ba0ba9b999354134d2f89fcca1fd35362f6135e0ca\
0d01b9869ba3fe172b206c88b95a785da414b0f36231f9d45e98bb3916eb77c80d22393bb06a5612a6c59fcd29e3412aae292ef88707e7ed4b28858a5055ed23\
e3c0089c5f7f3293edcbef738e9f39431610289a6e67fececc85a4b0897e8672c6454613a4b7fc0b22edf155265b51ec1c117958fbe4d0b5d1030777d6661de1\
94ee5ab46aa917b07346a8ae943618cd1303491f9e4f7c989892a305de22f9ea3b3104a978cf7e51c0df04c13377cfbece97f6c531c4fd1bc7d9f32ab9e09f0c";

    fn s6_key() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        (
            decode_hex(S6_KEY_PKCS8_HEX),
            decode_hex(S6_MODULUS_HEX),
            vec![0x01, 0x00, 0x01],
        )
    }

    /// PKCS#1 v1.5 is deterministic — our signature must byte-match OpenSSL's,
    /// and OpenSSL's must verify (S6 KAT cross-check).
    #[test]
    fn s6_rsa_sha384_pkcs1v15_matches_openssl_kat() {
        let (sk, n, e) = s6_key();
        let kat = decode_hex(S6_SIG_SHA384_V15_HEX);
        let sig = sign_rsa(crate::constants::CKM_SHA384_RSA_PKCS, &sk, S6_MSG, None).unwrap();
        assert_eq!(sig, kat, "PKCS#1 v1.5 SHA-384 must byte-match OpenSSL");
        assert_eq!(
            verify_rsa(crate::constants::CKM_SHA384_RSA_PKCS, &n, &e, S6_MSG, &kat, None),
            Ok(())
        );
    }

    #[test]
    fn s6_rsa_sha512_pkcs1v15_matches_openssl_kat() {
        let (sk, n, e) = s6_key();
        let kat = decode_hex(S6_SIG_SHA512_V15_HEX);
        let sig = sign_rsa(crate::constants::CKM_SHA512_RSA_PKCS, &sk, S6_MSG, None).unwrap();
        assert_eq!(sig, kat, "PKCS#1 v1.5 SHA-512 must byte-match OpenSSL");
        assert_eq!(
            verify_rsa(crate::constants::CKM_SHA512_RSA_PKCS, &n, &e, S6_MSG, &kat, None),
            Ok(())
        );
    }

    /// PSS is randomized — verify the OpenSSL-produced signature (MGF1 same
    /// hash, salt = hash length per §6.2 defaults), with and without an
    /// explicit sLen, plus a fresh sign→verify round-trip.
    #[test]
    fn s6_rsa_sha384_pss_verifies_openssl_signature_and_round_trips() {
        let (sk, n, e) = s6_key();
        let kat = decode_hex(S6_SIG_SHA384_PSS_HEX);
        let m = crate::constants::CKM_SHA384_RSA_PKCS_PSS;
        assert_eq!(verify_rsa(m, &n, &e, S6_MSG, &kat, None), Ok(()));
        assert_eq!(verify_rsa(m, &n, &e, S6_MSG, &kat, Some(48)), Ok(()));
        let sig = sign_rsa(m, &sk, S6_MSG, None).unwrap();
        assert_eq!(verify_rsa(m, &n, &e, S6_MSG, &sig, None), Ok(()));
    }

    #[test]
    fn s6_rsa_sha512_pss_verifies_openssl_signature_and_round_trips() {
        let (sk, n, e) = s6_key();
        let kat = decode_hex(S6_SIG_SHA512_PSS_HEX);
        let m = crate::constants::CKM_SHA512_RSA_PKCS_PSS;
        assert_eq!(verify_rsa(m, &n, &e, S6_MSG, &kat, None), Ok(()));
        assert_eq!(verify_rsa(m, &n, &e, S6_MSG, &kat, Some(64)), Ok(()));
        let sig = sign_rsa(m, &sk, S6_MSG, None).unwrap();
        assert_eq!(verify_rsa(m, &n, &e, S6_MSG, &sig, None), Ok(()));
    }

    /// Cross-mechanism negative: a SHA-384 signature must not verify under
    /// the SHA-512 mechanism (and vice versa), for both v1.5 and PSS.
    #[test]
    fn s6_rsa_cross_hash_verify_fails() {
        use crate::constants::*;
        let (sk, n, e) = s6_key();
        let sig384 = sign_rsa(CKM_SHA384_RSA_PKCS, &sk, S6_MSG, None).unwrap();
        let sig512 = sign_rsa(CKM_SHA512_RSA_PKCS, &sk, S6_MSG, None).unwrap();
        assert_eq!(
            verify_rsa(CKM_SHA512_RSA_PKCS, &n, &e, S6_MSG, &sig384, None),
            Err(CKR_SIGNATURE_INVALID)
        );
        assert_eq!(
            verify_rsa(CKM_SHA384_RSA_PKCS, &n, &e, S6_MSG, &sig512, None),
            Err(CKR_SIGNATURE_INVALID)
        );
        let pss384 = sign_rsa(CKM_SHA384_RSA_PKCS_PSS, &sk, S6_MSG, None).unwrap();
        assert_eq!(
            verify_rsa(CKM_SHA512_RSA_PKCS_PSS, &n, &e, S6_MSG, &pss384, None),
            Err(CKR_SIGNATURE_INVALID)
        );
    }

    /// Tampered message → CKR_SIGNATURE_INVALID for every new mechanism.
    #[test]
    fn s6_rsa_tampered_message_fails_all_new_mechs() {
        use crate::constants::*;
        let (sk, n, e) = s6_key();
        for m in [
            CKM_SHA384_RSA_PKCS,
            CKM_SHA512_RSA_PKCS,
            CKM_SHA384_RSA_PKCS_PSS,
            CKM_SHA512_RSA_PKCS_PSS,
        ] {
            let sig = sign_rsa(m, &sk, S6_MSG, None).unwrap();
            assert_eq!(sig.len(), 256, "RSA-2048 signature is 256 bytes");
            assert_eq!(
                verify_rsa(m, &n, &e, b"tampered message", &sig, None),
                Err(CKR_SIGNATURE_INVALID),
                "mech {m:#06x}"
            );
        }
    }
}
