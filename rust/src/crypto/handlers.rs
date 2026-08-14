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
pub const ALGO_FRODOKEM: u32 = 10;
pub const ALGO_CLASSIC_MCELIECE: u32 = 11;

// ECDSA curve identifiers (stored in CKA_PRIV_PARAM_SET)
pub const CURVE_P256: u32 = 256;
pub const CURVE_P384: u32 = 384;
pub const CURVE_P521: u32 = 521;
pub const CURVE_K256: u32 = 257;
/// Curve identifiers this engine RECOGNISES from `CKA_EC_PARAMS` but does not
/// implement. Kept distinct from "undecodable" so [`decode_ec_params`] can
/// answer `CKR_CURVE_NOT_SUPPORTED` rather than `CKR_DOMAIN_PARAMS_INVALID`.
pub const CURVE_UNSUPPORTED: u32 = u32::MAX;

/// W1 (2026-08-13) — decode `CKA_EC_PARAMS` as the X9.62 `Parameters` CHOICE
/// the specification defines, and NEVER default a curve.
///
/// §6.3.9 generates a key pair "with particular EC domain parameters, as
/// specified in the CKA_EC_PARAMS attribute of the template for the public
/// key"; §6.3 gives `CKR_CURVE_NOT_SUPPORTED` for an unsupported curve and
/// `CKR_DOMAIN_PARAMS_INVALID` for an invalid or unsupported representation;
/// the attribute is mandatory at generation, so absence is
/// `CKR_TEMPLATE_INCOMPLETE`. §6.3.10 additionally requires the Edwards and
/// Montgomery curves be given "using the curveName or the oID methods".
///
/// What this replaces: identification by the attribute's LAST BYTE — `0x23`
/// meant P-521, `0x22` P-384, `0x0a` secp256k1, and a bare `else` produced a
/// **P-256 key stamped as P-256, returning success**. So a missing attribute
/// yielded P-256; every brainpool curve and every NIST curve whose OID does
/// not end in those bytes yielded P-256; the curve-NAME form the spec
/// recommends was never recognised at all; and last-byte matching collides
/// freely across the OID space.
///
/// Accepts both legal forms, as §6.3.10's interop note asks:
///   * `OBJECT IDENTIFIER` — `06 len <oid bytes>`
///   * `PrintableString` curve name — `13 len <ascii>`
///
/// `explicit ECParameters` (a `SEQUENCE`, tag `0x30`) is a legal CHOICE arm
/// this engine does not implement — `CKR_CURVE_NOT_SUPPORTED`. The
/// implicitCA form (`NULL`, tag `0x05`) is forbidden outright and is
/// reported as an invalid representation.
pub fn decode_ec_params(params: &[u8]) -> Result<u32, u32> {
    use crate::constants::{CKR_CURVE_NOT_SUPPORTED, CKR_DOMAIN_PARAMS_INVALID};
    if params.len() < 2 {
        return Err(CKR_DOMAIN_PARAMS_INVALID);
    }
    let tag = params[0];
    let len = params[1] as usize;
    // Only short-form DER lengths occur for these values (the longest named
    // curve OID is well under 127 bytes).
    if params[1] & 0x80 != 0 || params.len() < 2 + len {
        return Err(CKR_DOMAIN_PARAMS_INVALID);
    }
    let body = &params[2..2 + len];
    match tag {
        // ── OBJECT IDENTIFIER ────────────────────────────────────────────
        0x06 => Ok(match body {
            // 1.2.840.10045.3.1.7  prime256v1 / P-256
            [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07] => CURVE_P256,
            // 1.3.132.0.34  secp384r1 / P-384
            [0x2b, 0x81, 0x04, 0x00, 0x22] => CURVE_P384,
            // 1.3.132.0.35  secp521r1 / P-521
            [0x2b, 0x81, 0x04, 0x00, 0x23] => CURVE_P521,
            // 1.3.132.0.10  secp256k1
            [0x2b, 0x81, 0x04, 0x00, 0x0a] => CURVE_K256,
            // 1.3.101.110 / .111 — X25519 / X448 (Montgomery)
            [0x2b, 0x65, 0x6e] => CURVE_X25519,
            [0x2b, 0x65, 0x6f] => CURVE_X448,
            // 1.3.101.112 / .113 — Ed25519 / Ed448 (Edwards)
            [0x2b, 0x65, 0x70] => CURVE_ED25519,
            [0x2b, 0x65, 0x71] => CURVE_ED448,
            // A well-formed OID naming a curve this token does not
            // implement (brainpool, the F_2^m curves, …).
            _ => CURVE_UNSUPPORTED,
        }),
        // ── PrintableString curveName ────────────────────────────────────
        0x13 => {
            let name = core::str::from_utf8(body).map_err(|_| CKR_DOMAIN_PARAMS_INVALID)?;
            Ok(match name {
                "P-256" | "prime256v1" | "secp256r1" => CURVE_P256,
                "P-384" | "secp384r1" => CURVE_P384,
                "P-521" | "secp521r1" => CURVE_P521,
                "secp256k1" => CURVE_K256,
                "curve25519" | "X25519" => CURVE_X25519,
                "curve448" | "X448" => CURVE_X448,
                "edwards25519" | "Ed25519" => CURVE_ED25519,
                "edwards448" | "Ed448" => CURVE_ED448,
                _ => CURVE_UNSUPPORTED,
            })
        }
        // ── explicit ECParameters (SEQUENCE) ─────────────────────────────
        0x30 => Err(CKR_CURVE_NOT_SUPPORTED),
        // ── implicitCA (NULL) — forbidden by the spec ────────────────────
        0x05 => Err(CKR_DOMAIN_PARAMS_INVALID),
        _ => Err(CKR_DOMAIN_PARAMS_INVALID),
    }
}

/// Curve ids for the Edwards / Montgomery families, which have no key-size
/// number to reuse the way the Weierstrass curves do.
pub const CURVE_X25519: u32 = 25519;
pub const CURVE_X448: u32 = 448;
pub const CURVE_ED25519: u32 = 25520;
pub const CURVE_ED448: u32 = 449;

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
    /// Historical RIPEMD-160 (CKM_RIPEMD160) — 20-byte digest.
    Ripemd160(ripemd::Ripemd160),
}

pub struct FindCtx {
    pub handles: Vec<u32>,
    pub cursor: usize,
}

// ── Template Parsing ─────────────────────────────────────────────────────────

/// Read a `CK_ULONG`-valued attribute from a `CK_ATTRIBUTE` template array, at
/// the target ABI's **native** `CK_ULONG` width.
///
/// `CK_ATTRIBUTE` is three words — `type` (`CK_ATTRIBUTE_TYPE`, a `CK_ULONG`),
/// `pValue` (`CK_VOID_PTR`) and `ulValueLen` (`CK_ULONG`) — so the `i * 3`
/// stride below is ABI-correct on every target this engine builds for; it is
/// deliberately unchanged. What was wrong until 2026-08-14 is what happened at
/// the end of that stride:
///
/// ```text
/// let val_ptr = *ptr.add(i * 3 + 1) as *const u32;   // <- 4 bytes, always
/// return Some(read_unaligned(val_ptr));              // <- ulValueLen ignored
/// ```
///
/// Two defects in two lines, reported twice before being fixed:
///
/// 1. **`ulValueLen` was never consulted.** A caller passing a one-byte
///    `pValue` — a malformed template, or a `CK_BBOOL` where the engine
///    expected a `CK_ULONG` — got a **four**-byte read. Three of those bytes
///    are outside the buffer the caller lent the library. Unbounded on every
///    target.
/// 2. **The value was read as `u32`, not `CK_ULONG`.** Latent on
///    little-endian LP64 (the low half of the word happens to be the value)
///    and correct on wasm32 (`CK_ULONG` is 4 bytes there), but it reads the
///    wrong half on any big-endian LP64 target.
///
/// Now: `ulValueLen` must equal `sizeof(CK_ULONG)` on this target, and the
/// value is read at that width. A matching entry whose length is anything else
/// is not a `CK_ULONG` and is skipped, so the caller sees the attribute as
/// absent rather than as a number assembled from adjacent memory.
///
/// # Safety
/// `template` must be NULL or point to `count` readable `CK_ATTRIBUTE`s, whose
/// `pValue`/`ulValueLen` pairs describe readable memory.
pub unsafe fn get_attr_ulong_native(
    template: *mut u8,
    count: u32,
    attr_type: u32,
) -> Option<usize> {
    if template.is_null() {
        return None;
    }
    if count > 65536 {
        return None; // Guard against malformed templates with huge count values
    }
    let ptr = template as *mut usize;
    for i in 0..count {
        let t = *ptr.add((i * 3) as usize) as u32;
        if t == attr_type {
            let val_ptr = *ptr.add((i * 3 + 1) as usize) as usize as *const u8;
            let val_len = *ptr.add((i * 3 + 2) as usize);
            // A CK_ULONG-valued attribute is exactly sizeof(CK_ULONG) bytes.
            // Anything else — including the 0/CK_UNAVAILABLE_INFORMATION
            // length a caller uses to SIZE the attribute rather than supply it
            // — is not a value this reader may take.
            if !val_ptr.is_null()
                && val_len == core::mem::size_of::<crate::ck_abi::CK_ULONG>()
            {
                // CK_ATTRIBUTE.pValue carries NO alignment guarantee — an aligned
                // deref panics (misaligned pointer) on a legal caller template.
                return Some(std::ptr::read_unaligned(val_ptr as *const usize));
            }
        }
    }
    None
}

/// [`get_attr_ulong_native`] narrowed to the engine's internal 32-bit width —
/// the same deliberate narrowing `ck_param::ulong32` performs, and what all
/// nineteen call sites want (key types, parameter-set codes, key lengths).
///
/// # Safety
/// As [`get_attr_ulong_native`].
pub unsafe fn get_attr_ulong(template: *mut u8, count: u32, attr_type: u32) -> Option<u32> {
    get_attr_ulong_native(template, count, attr_type).map(|v| v as u32)
}

/// Read a byte-array attribute from a CK_ATTRIBUTE template array.
pub unsafe fn get_attr_bytes(template: *mut u8, count: u32, attr_type: u32) -> Option<Vec<u8>> {
    if template.is_null() {
        return None;
    }
    if count > 65536 {
        return None; // Guard against malformed templates with huge count values
    }
    let ptr = template as *mut usize;
    for i in 0..count {
        let t = *ptr.add((i * 3) as usize) as u32;
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
    let ptr = template as *mut usize;
    for i in 0..count {
        let attr_type = *ptr.add((i * 3) as usize) as u32;
        let val_ptr = *ptr.add((i * 3 + 1) as usize) as usize as *const u8;
        let val_len = *ptr.add((i * 3 + 2) as usize) as usize;
        // Skip key/seed material, internal private attrs, and server-managed attrs.
        if template_attr_is_skipped(attr_type) {
            continue;
        }
        if !val_ptr.is_null() && val_len > 0 {
            // S2 — an ATTRIBUTE-array attribute's pValue is a CK_ATTRIBUTE[],
            // whose own pValue pointers are dangling the instant this call
            // returns. Copying the raw struct bytes (what every other
            // attribute does) would store pointers, not data. Flatten instead.
            let v = if attr_is_attribute_array(attr_type) {
                match flatten_attr_array(val_ptr, val_len) {
                    Some(flat) => flat,
                    // Malformed array — drop it rather than store a
                    // half-decoded restriction. `validate_create_template`
                    // rejects the same shape up front on the create path.
                    None => continue,
                }
            } else {
                std::slice::from_raw_parts(val_ptr, val_len).to_vec()
            };
            attrs.insert(attr_type, v);
        }
    }
}

/// Like [`get_attr_bytes`], but distinguishes "present with a ZERO-length
/// value" (`Some(vec![])`) from "absent" (`None`). PKCS#11 v3.2 §4.11 gives
/// the zero-length form its own meaning for `CKA_CHECK_VALUE` — "The
/// generation of the KCV may be prevented by the application supplying the
/// attribute in the template as a no-value (0 length) entry" — which
/// `get_attr_bytes` collapses into `None`.
///
/// # Safety
/// Same contract as [`get_attr_bytes`].
pub unsafe fn find_template_entry(
    template: *mut u8,
    count: u32,
    attr_type: u32,
) -> Option<Vec<u8>> {
    if template.is_null() || count > 65536 {
        return None;
    }
    let ptr = template as *mut usize;
    for i in 0..count {
        let t = *ptr.add((i * 3) as usize) as u32;
        if t != attr_type {
            continue;
        }
        let val_ptr = *ptr.add((i * 3 + 1) as usize) as usize as *const u8;
        let val_len = *ptr.add((i * 3 + 2) as usize) as usize;
        if val_ptr.is_null() || val_len == 0 {
            return Some(Vec::new());
        }
        return Some(std::slice::from_raw_parts(val_ptr, val_len).to_vec());
    }
    None
}

/// PKCS#11 v3.2 §5.18.3 — the attribute types whose value is a
/// `CK_ATTRIBUTE[]` (as opposed to `CKA_ALLOWED_MECHANISMS`, which carries
/// the CKF_ARRAY_ATTRIBUTE bit but is a `CK_MECHANISM_TYPE[]` of plain
/// integers and must NOT be flattened).
pub(crate) fn attr_is_attribute_array(attr_type: u32) -> bool {
    matches!(
        attr_type,
        crate::constants::CKA_WRAP_TEMPLATE
            | crate::constants::CKA_UNWRAP_TEMPLATE
            | crate::constants::CKA_DERIVE_TEMPLATE
    )
}

/// Flatten a caller's `CK_ATTRIBUTE[]` into a SELF-CONTAINED byte blob the
/// engine can store and compare later:
///
/// ```text
///   repeat { u32 attr_type ‖ u32 value_len ‖ value_len bytes }
/// ```
///
/// `byte_len` is the array's size in bytes (the `ulValueLen` the caller
/// supplied), which must be a whole number of `CK_ATTRIBUTE` structs.
/// Returns `None` for a ragged length or an entry whose `pValue` is NULL
/// with a non-zero length.
///
/// # Safety
/// `arr` must point to `byte_len` readable bytes shaped as `CK_ATTRIBUTE[]`.
pub unsafe fn flatten_attr_array(arr: *const u8, byte_len: usize) -> Option<Vec<u8>> {
    let word = std::mem::size_of::<usize>();
    let stride = word * 3;
    if byte_len == 0 || byte_len % stride != 0 {
        return None;
    }
    let n = byte_len / stride;
    if n > 65536 {
        return None;
    }
    let ptr = arr as *const usize;
    let mut out = Vec::with_capacity(byte_len);
    for i in 0..n {
        let t = *ptr.add(i * 3) as u32;
        let vp = *ptr.add(i * 3 + 1) as *const u8;
        let vl = *ptr.add(i * 3 + 2);
        if vp.is_null() && vl > 0 {
            return None;
        }
        if vl > byte_len.max(1 << 20) {
            return None; // implausible length — refuse rather than read wild
        }
        out.extend_from_slice(&t.to_le_bytes());
        out.extend_from_slice(&(vl as u32).to_le_bytes());
        if vl > 0 {
            out.extend_from_slice(std::slice::from_raw_parts(vp, vl));
        }
    }
    Some(out)
}

/// Inverse of [`flatten_attr_array`]. `None` if the blob is truncated.
pub fn parse_flat_attr_array(blob: &[u8]) -> Option<Vec<(u32, Vec<u8>)>> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < blob.len() {
        if i + 8 > blob.len() {
            return None;
        }
        let t = u32::from_le_bytes([blob[i], blob[i + 1], blob[i + 2], blob[i + 3]]);
        let l = u32::from_le_bytes([blob[i + 4], blob[i + 5], blob[i + 6], blob[i + 7]]) as usize;
        i += 8;
        if i + l > blob.len() {
            return None;
        }
        out.push((t, blob[i..i + l].to_vec()));
        i += l;
    }
    Some(out)
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

/// SLH-DSA keygen for the C ABI (`ffi::C_GenerateKeyPair`). `$m` is the
/// `fips205` parameter-set module; `$seed` is `Option<&[u8]>` — `Some` runs
/// FIPS 205 Algorithm 18 `slh_keygen_internal(SK.seed, SK.prf, PK.seed)`
/// deterministically from a `3n`-byte `CKA_SEED` (PKCS#11 v3.2 §6.69.2),
/// `None` keeps the random path (Algorithm 21 via OsRng). A wrong-length
/// seed returns `CKR_ATTRIBUTE_VALUE_INVALID` (n is per-param-set: 16/24/32).
#[macro_export]
macro_rules! slh_dsa_keygen {
    ($m:ident, $seed:expr, $pub_attrs:expr, $prv_attrs:expr) => {{
        use fips205::traits::{KeyGen, SerDes};
        const N: usize = fips205::$m::N;
        match $seed {
            Some(s) => {
                if s.len() != 3 * N {
                    return CKR_ATTRIBUTE_VALUE_INVALID;
                }
                // FIPS 205 §9.1 — CKA_SEED = SK.seed ‖ SK.prf ‖ PK.seed.
                let (vk, sk) = fips205::$m::KG::keygen_with_seeds::<N>(
                    s[..N].try_into().expect("length checked"),
                    s[N..2 * N].try_into().expect("length checked"),
                    s[2 * N..].try_into().expect("length checked"),
                );
                $pub_attrs.insert(CKA_VALUE, SerDes::into_bytes(vk).to_vec());
                $prv_attrs.insert(CKA_VALUE, SerDes::into_bytes(sk).to_vec());
            }
            None => {
                // P5 (PKCS#11 v3.2 §6.69.4 / FIPS 205): keygen CONTRIBUTES
                // CKA_SEED (SK.seed ‖ SK.prf ‖ PK.seed, 3N bytes) to the private
                // key. Sample the seed explicitly and expand deterministically —
                // functionally identical to try_keygen_with_rng — then retain it
                // as CKA_SEED so the private key carries its seed.
                use rand::RngCore;
                let mut sk_seed = [0u8; N];
                let mut sk_prf = [0u8; N];
                let mut pk_seed = [0u8; N];
                let mut rng = rand::rngs::OsRng;
                rng.fill_bytes(&mut sk_seed);
                rng.fill_bytes(&mut sk_prf);
                rng.fill_bytes(&mut pk_seed);
                let (vk, sk) = fips205::$m::KG::keygen_with_seeds::<N>(&sk_seed, &sk_prf, &pk_seed);
                $pub_attrs.insert(CKA_VALUE, SerDes::into_bytes(vk).to_vec());
                $prv_attrs.insert(CKA_VALUE, SerDes::into_bytes(sk).to_vec());
                let mut seed = Vec::with_capacity(3 * N);
                seed.extend_from_slice(&sk_seed);
                seed.extend_from_slice(&sk_prf);
                seed.extend_from_slice(&pk_seed);
                $prv_attrs.insert(CKA_SEED, seed);
            }
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

#[macro_export]
macro_rules! slh_dsa_sign_internal {
    ($ps:ty, $sk_bytes:expr, $msg:expr, $addrnd:expr) => {{
        use fips205::traits::Signer;
        let sk_arr: &<$ps as fips205::traits::SerDes>::ByteArray = $sk_bytes
            .try_into()
            .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
        let sk = <$ps as fips205::traits::SerDes>::try_from_bytes(sk_arr)
            .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
        // `_test_only_raw_sign` is FIPS 205 `slh_sign_internal(M, SK, addrnd)`:
        // it signs the bare message (no `(0‖|ctx|‖ctx)` framing). `addrnd =
        // None` ⇒ the deterministic variant (addrnd = PK.seed); `Some(r)` ⇒
        // the hedged variant with the explicit ACVP/OASIS `<Random>` addrnd.
        match $addrnd {
            Some(r) => sk._test_only_raw_sign(&mut crate::crypto::handlers::FixedRng::new(r), $msg, true),
            None => sk._test_only_raw_sign(&mut rand::rngs::OsRng, $msg, false),
        }
        .map_err(|_| CKR_FUNCTION_FAILED)
        .map(|s| Into::<Vec<u8>>::into(s))
    }};
}

#[macro_export]
macro_rules! slh_dsa_sign_external_rnd {
    ($ps:ty, $sk_bytes:expr, $msg:expr, $ctx:expr, $addrnd:expr) => {{
        use fips205::traits::Signer;
        let sk_arr: &<$ps as fips205::traits::SerDes>::ByteArray = $sk_bytes
            .try_into()
            .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
        let sk = <$ps as fips205::traits::SerDes>::try_from_bytes(sk_arr)
            .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
        // External `SLH-DSA.Sign` (with `(0‖|ctx|‖ctx)` framing). `addrnd =
        // None` ⇒ deterministic (hedged=false → addrnd = PK.seed); `Some(r)` ⇒
        // hedged with the explicit `<Random>` addrnd drawn from `FixedRng`.
        match $addrnd {
            Some(r) => sk.try_sign_with_rng(&mut crate::crypto::handlers::FixedRng::new(r), $msg, $ctx, true),
            None => sk.try_sign_with_rng(&mut rand::rngs::OsRng, $msg, $ctx, false),
        }
        .map_err(|_| CKR_FUNCTION_FAILED)
        .map(|s| Into::<Vec<u8>>::into(s))
    }};
}

#[macro_export]
macro_rules! slh_dsa_verify_internal {
    ($ps:ty, $pk_bytes:expr, $msg:expr, $sig_bytes:expr) => {{
        use fips205::traits::Verifier;
        let pk_arr: &<$ps as fips205::traits::SerDes>::ByteArray = $pk_bytes
            .try_into()
            .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
        let vk = <$ps as fips205::traits::SerDes>::try_from_bytes(pk_arr)
            .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
        let sig: <$ps as fips205::traits::Verifier>::Signature =
            $sig_bytes.try_into().map_err(|_| CKR_SIGNATURE_INVALID)?;
        match vk._test_only_raw_verify($msg, &sig) {
            Ok(true) => Ok(()),
            _ => Err(CKR_SIGNATURE_INVALID),
        }
    }};
}

/// SLH-DSA **internal-interface** signing (ACVP `signatureInterface="internal"`
/// / OASIS interop `<Internal value="true"/>`, FIPS 205 `slh_sign_internal`):
/// signs `msg` directly without the external `(0‖|ctx|‖ctx)` framing applied
/// by [`sign_slh_dsa`]. `deterministic` ⇒ addrnd = PK.seed.
pub fn sign_slh_dsa_internal(
    ps: u32,
    sk_bytes: &[u8],
    msg: &[u8],
    addrnd: Option<&[u8]>,
) -> Result<Vec<u8>, u32> {
    match ps {
        CKP_SLH_DSA_SHA2_128S => slh_dsa_sign_internal!(fips205::slh_dsa_sha2_128s::PrivateKey, sk_bytes, msg, addrnd),
        CKP_SLH_DSA_SHAKE_128S => slh_dsa_sign_internal!(fips205::slh_dsa_shake_128s::PrivateKey, sk_bytes, msg, addrnd),
        CKP_SLH_DSA_SHA2_128F => slh_dsa_sign_internal!(fips205::slh_dsa_sha2_128f::PrivateKey, sk_bytes, msg, addrnd),
        CKP_SLH_DSA_SHAKE_128F => slh_dsa_sign_internal!(fips205::slh_dsa_shake_128f::PrivateKey, sk_bytes, msg, addrnd),
        CKP_SLH_DSA_SHA2_192S => slh_dsa_sign_internal!(fips205::slh_dsa_sha2_192s::PrivateKey, sk_bytes, msg, addrnd),
        CKP_SLH_DSA_SHAKE_192S => slh_dsa_sign_internal!(fips205::slh_dsa_shake_192s::PrivateKey, sk_bytes, msg, addrnd),
        CKP_SLH_DSA_SHA2_192F => slh_dsa_sign_internal!(fips205::slh_dsa_sha2_192f::PrivateKey, sk_bytes, msg, addrnd),
        CKP_SLH_DSA_SHAKE_192F => slh_dsa_sign_internal!(fips205::slh_dsa_shake_192f::PrivateKey, sk_bytes, msg, addrnd),
        CKP_SLH_DSA_SHA2_256S => slh_dsa_sign_internal!(fips205::slh_dsa_sha2_256s::PrivateKey, sk_bytes, msg, addrnd),
        CKP_SLH_DSA_SHAKE_256S => slh_dsa_sign_internal!(fips205::slh_dsa_shake_256s::PrivateKey, sk_bytes, msg, addrnd),
        CKP_SLH_DSA_SHA2_256F => slh_dsa_sign_internal!(fips205::slh_dsa_sha2_256f::PrivateKey, sk_bytes, msg, addrnd),
        CKP_SLH_DSA_SHAKE_256F => slh_dsa_sign_internal!(fips205::slh_dsa_shake_256f::PrivateKey, sk_bytes, msg, addrnd),
        _ => Err(CKR_KEY_TYPE_INCONSISTENT),
    }
}

/// SLH-DSA **external-interface** signing with explicit `addrnd` — the
/// rnd-aware form of [`sign_slh_dsa`] (full `SLH-DSA.Sign` with the
/// `(0‖|ctx|‖ctx)` framing). `addrnd = None` ⇒ deterministic (addrnd =
/// PK.seed); `Some(r)` ⇒ hedged with the explicit ACVP/OASIS `<Random>`.
pub fn sign_slh_dsa_external_rnd(
    ps: u32,
    sk_bytes: &[u8],
    msg: &[u8],
    ctx: &[u8],
    addrnd: Option<&[u8]>,
) -> Result<Vec<u8>, u32> {
    match ps {
        CKP_SLH_DSA_SHA2_128S => slh_dsa_sign_external_rnd!(fips205::slh_dsa_sha2_128s::PrivateKey, sk_bytes, msg, ctx, addrnd),
        CKP_SLH_DSA_SHAKE_128S => slh_dsa_sign_external_rnd!(fips205::slh_dsa_shake_128s::PrivateKey, sk_bytes, msg, ctx, addrnd),
        CKP_SLH_DSA_SHA2_128F => slh_dsa_sign_external_rnd!(fips205::slh_dsa_sha2_128f::PrivateKey, sk_bytes, msg, ctx, addrnd),
        CKP_SLH_DSA_SHAKE_128F => slh_dsa_sign_external_rnd!(fips205::slh_dsa_shake_128f::PrivateKey, sk_bytes, msg, ctx, addrnd),
        CKP_SLH_DSA_SHA2_192S => slh_dsa_sign_external_rnd!(fips205::slh_dsa_sha2_192s::PrivateKey, sk_bytes, msg, ctx, addrnd),
        CKP_SLH_DSA_SHAKE_192S => slh_dsa_sign_external_rnd!(fips205::slh_dsa_shake_192s::PrivateKey, sk_bytes, msg, ctx, addrnd),
        CKP_SLH_DSA_SHA2_192F => slh_dsa_sign_external_rnd!(fips205::slh_dsa_sha2_192f::PrivateKey, sk_bytes, msg, ctx, addrnd),
        CKP_SLH_DSA_SHAKE_192F => slh_dsa_sign_external_rnd!(fips205::slh_dsa_shake_192f::PrivateKey, sk_bytes, msg, ctx, addrnd),
        CKP_SLH_DSA_SHA2_256S => slh_dsa_sign_external_rnd!(fips205::slh_dsa_sha2_256s::PrivateKey, sk_bytes, msg, ctx, addrnd),
        CKP_SLH_DSA_SHAKE_256S => slh_dsa_sign_external_rnd!(fips205::slh_dsa_shake_256s::PrivateKey, sk_bytes, msg, ctx, addrnd),
        CKP_SLH_DSA_SHA2_256F => slh_dsa_sign_external_rnd!(fips205::slh_dsa_sha2_256f::PrivateKey, sk_bytes, msg, ctx, addrnd),
        CKP_SLH_DSA_SHAKE_256F => slh_dsa_sign_external_rnd!(fips205::slh_dsa_shake_256f::PrivateKey, sk_bytes, msg, ctx, addrnd),
        _ => Err(CKR_KEY_TYPE_INCONSISTENT),
    }
}

/// SLH-DSA internal-interface verification — counterpart to
/// [`sign_slh_dsa_internal`] (`slh_verify_internal`).
pub fn verify_slh_dsa_internal(
    ps: u32,
    pk_bytes: &[u8],
    msg: &[u8],
    sig_bytes: &[u8],
) -> Result<(), u32> {
    match ps {
        CKP_SLH_DSA_SHA2_128S => slh_dsa_verify_internal!(fips205::slh_dsa_sha2_128s::PublicKey, pk_bytes, msg, sig_bytes),
        CKP_SLH_DSA_SHAKE_128S => slh_dsa_verify_internal!(fips205::slh_dsa_shake_128s::PublicKey, pk_bytes, msg, sig_bytes),
        CKP_SLH_DSA_SHA2_128F => slh_dsa_verify_internal!(fips205::slh_dsa_sha2_128f::PublicKey, pk_bytes, msg, sig_bytes),
        CKP_SLH_DSA_SHAKE_128F => slh_dsa_verify_internal!(fips205::slh_dsa_shake_128f::PublicKey, pk_bytes, msg, sig_bytes),
        CKP_SLH_DSA_SHA2_192S => slh_dsa_verify_internal!(fips205::slh_dsa_sha2_192s::PublicKey, pk_bytes, msg, sig_bytes),
        CKP_SLH_DSA_SHAKE_192S => slh_dsa_verify_internal!(fips205::slh_dsa_shake_192s::PublicKey, pk_bytes, msg, sig_bytes),
        CKP_SLH_DSA_SHA2_192F => slh_dsa_verify_internal!(fips205::slh_dsa_sha2_192f::PublicKey, pk_bytes, msg, sig_bytes),
        CKP_SLH_DSA_SHAKE_192F => slh_dsa_verify_internal!(fips205::slh_dsa_shake_192f::PublicKey, pk_bytes, msg, sig_bytes),
        CKP_SLH_DSA_SHA2_256S => slh_dsa_verify_internal!(fips205::slh_dsa_sha2_256s::PublicKey, pk_bytes, msg, sig_bytes),
        CKP_SLH_DSA_SHAKE_256S => slh_dsa_verify_internal!(fips205::slh_dsa_shake_256s::PublicKey, pk_bytes, msg, sig_bytes),
        CKP_SLH_DSA_SHA2_256F => slh_dsa_verify_internal!(fips205::slh_dsa_sha2_256f::PublicKey, pk_bytes, msg, sig_bytes),
        CKP_SLH_DSA_SHAKE_256F => slh_dsa_verify_internal!(fips205::slh_dsa_shake_256f::PublicKey, pk_bytes, msg, sig_bytes),
        _ => Err(CKR_KEY_TYPE_INCONSISTENT),
    }
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
///
/// Pure SLH-DSA OIDs are RFC 9909 §3 — NIST CSOR arc
/// `2.16.840.1.101.3.4.3.{20..31}` (nistAlgorithms(4).sigAlgs(3), the SAME
/// parent arc as ML-DSA's `.3.{17,18,19}` above, contiguous from where it
/// leaves off), NOT `2.16.840.1.101.3.4.20.{1..12}` — that shape (this
/// function's previous, wrong implementation) doesn't exist in the RFC;
/// every OpenSSL >=3.5 build with SLH-DSA support disagrees with it too
/// (`openssl list -signature-algorithms` — `id-slh-dsa-sha2-128s` is
/// `2.16.840.1.101.3.4.3.20`), which is how this was caught: the
/// kmip/tests/openssl_cert_crosscheck.rs external cross-check failed to
/// even DECODE a CA cert's SLH-DSA SubjectPublicKeyInfo built by this
/// function. Verified against the RFC 9909 ASN.1 module directly (§3):
/// `sigAlgs OBJECT IDENTIFIER ::= { nistAlgorithms 3 }`, then
/// `id-slh-dsa-sha2-128s ::= { sigAlgs 20 }` counting up to
/// `id-slh-dsa-shake-256f ::= { sigAlgs 31 }` — matches
/// `kmip::ops::certify`'s own independently-verified OID table exactly.
pub fn build_slhdsa_spki(ckp: u32, pk: &[u8]) -> Vec<u8> {
    // CKP_SLH_DSA_* constant -> RFC 9909 final OID arc (20-31). All 12
    // values fit a single base-128 byte (< 0x80), so `oid_last` IS that
    // byte, not a further-encoded multi-byte value.
    let oid_last: u8 = match ckp {
        1 => 0x14,               // SHA2-128s  -> .20
        3 => 0x15,               // SHA2-128f  -> .21
        5 => 0x16,               // SHA2-192s  -> .22
        7 => 0x17,               // SHA2-192f  -> .23
        9 => 0x18,               // SHA2-256s  -> .24
        11 => 0x19,              // SHA2-256f  -> .25
        2 => 0x1a,               // SHAKE-128s -> .26
        4 => 0x1b,               // SHAKE-128f -> .27
        6 => 0x1c,               // SHAKE-192s -> .28
        8 => 0x1d,               // SHAKE-192f -> .29
        10 => 0x1e,              // SHAKE-256s -> .30
        12 => 0x1f,              // SHAKE-256f -> .31
        _ => return Vec::new(), // unknown parameter set
    };
    let alg_id = [
        0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, oid_last,
    ];
    build_spki_from_parts(&alg_id, pk)
}

// ── Pre-Hash Dispatch Helpers ────────────────────────────────────────────────

/// PKCS#11 v3.2 §6.67.7/§6.69.7 — map a `CK_HASH_SIGN_ADDITIONAL_CONTEXT.hash`
/// value onto this engine's concrete hash-specific pre-hash mechanism.
/// `base` is the GENERIC mechanism the caller requested (CKM_HASH_ML_DSA or
/// CKM_HASH_SLH_DSA); `hash` is the digest mechanism named in the param.
/// Only the 8 real digest mechanisms are legal here — SHAKE128/256 have no
/// standalone CKM_ digest identifier in the v3.2 header (only a KDF variant,
/// CKM_SHAKE_128/256_KEY_DERIVATION), so SHAKE pre-hash is reachable ONLY via
/// its own dedicated CKM_HASH_{ML,SLH}_DSA_SHAKE128/256 mechanism, never
/// through this generic param path. Returns None for anything else.
pub fn map_generic_hash_mech(base: u32, hash: u32) -> Option<u32> {
    let is_ml_dsa = base == CKM_HASH_ML_DSA;
    match hash {
        CKM_SHA224 => Some(if is_ml_dsa { CKM_HASH_ML_DSA_SHA224 } else { CKM_HASH_SLH_DSA_SHA224 }),
        CKM_SHA256 => Some(if is_ml_dsa { CKM_HASH_ML_DSA_SHA256 } else { CKM_HASH_SLH_DSA_SHA256 }),
        CKM_SHA384 => Some(if is_ml_dsa { CKM_HASH_ML_DSA_SHA384 } else { CKM_HASH_SLH_DSA_SHA384 }),
        CKM_SHA512 => Some(if is_ml_dsa { CKM_HASH_ML_DSA_SHA512 } else { CKM_HASH_SLH_DSA_SHA512 }),
        CKM_SHA3_224 => Some(if is_ml_dsa { CKM_HASH_ML_DSA_SHA3_224 } else { CKM_HASH_SLH_DSA_SHA3_224 }),
        CKM_SHA3_256 => Some(if is_ml_dsa { CKM_HASH_ML_DSA_SHA3_256 } else { CKM_HASH_SLH_DSA_SHA3_256 }),
        CKM_SHA3_384 => Some(if is_ml_dsa { CKM_HASH_ML_DSA_SHA3_384 } else { CKM_HASH_SLH_DSA_SHA3_384 }),
        CKM_SHA3_512 => Some(if is_ml_dsa { CKM_HASH_ML_DSA_SHA3_512 } else { CKM_HASH_SLH_DSA_SHA3_512 }),
        _ => None,
    }
}

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

/// RNG that replays a fixed byte string — used to inject an explicit signing
/// randomizer (ACVP/OASIS hedged `<Random>` value): the signer draws its
/// `rnd` (ML-DSA, 32 B) / `addrnd` (SLH-DSA, n B) from this instead of the OS
/// RNG, making the hedged signature byte-exactly reproducible. Bytes past the
/// supplied buffer read as zero (a single fixed-size draw never exhausts it).
pub(crate) struct FixedRng {
    bytes: Vec<u8>,
    pos: usize,
}
impl FixedRng {
    pub(crate) fn new(bytes: &[u8]) -> Self {
        Self { bytes: bytes.to_vec(), pos: 0 }
    }
}
impl rand::RngCore for FixedRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, out: &mut [u8]) {
        for o in out.iter_mut() {
            *o = self.bytes.get(self.pos).copied().unwrap_or(0);
            self.pos += 1;
        }
    }
    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(out);
        Ok(())
    }
}
impl rand::CryptoRng for FixedRng {}

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

/// ML-DSA **internal-interface** signing — ACVP `signatureInterface="internal"`
/// / OASIS interop `<Internal value="true"/>` (FIPS 204 `ML-DSA.Sign_internal`):
/// signs `message` directly as M′, WITHOUT the external
/// `(IntegerToBytes(0,1) ‖ IntegerToBytes(|ctx|,1) ‖ ctx)` domain framing that
/// [`sign_ml_dsa`] prepends. `rnd` is the 32-byte signing randomizer:
/// `[0u8; 32]` for the deterministic variant, or the explicit ACVP/OASIS
/// hedged `<Random>` value.
pub fn sign_ml_dsa_internal(
    ps: u32,
    sk_bytes: &[u8],
    message: &[u8],
    ctx: &[u8],
    rnd: [u8; 32],
) -> Result<Vec<u8>, u32> {
    macro_rules! sign_with {
        ($m:ident) => {{
            use fips204::traits::SerDes;
            let arr: &<fips204::$m::PrivateKey as SerDes>::ByteArray =
                sk_bytes.try_into().map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let sk = <fips204::$m::PrivateKey as SerDes>::try_from_bytes(*arr)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            #[allow(deprecated)]
            fips204::$m::_internal_sign(&sk, message, ctx, rnd)
                .map(|s| s.to_vec())
                .map_err(|_| CKR_FUNCTION_FAILED)
        }};
    }
    match ps {
        CKP_ML_DSA_44 => sign_with!(ml_dsa_44),
        CKP_ML_DSA_65 | 0 => sign_with!(ml_dsa_65),
        CKP_ML_DSA_87 => sign_with!(ml_dsa_87),
        _ => Err(CKR_KEY_TYPE_INCONSISTENT),
    }
}

/// ML-DSA internal-interface verification — counterpart to
/// [`sign_ml_dsa_internal`] (`ML-DSA.Verify_internal`).
pub fn verify_ml_dsa_internal(
    ps: u32,
    pk_bytes: &[u8],
    message: &[u8],
    sig_bytes: &[u8],
    ctx: &[u8],
) -> Result<(), u32> {
    use fips204::traits::Verifier;
    macro_rules! ver {
        ($m:ident) => {{
            use fips204::traits::SerDes;
            let arr: &<fips204::$m::PublicKey as SerDes>::ByteArray =
                pk_bytes.try_into().map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let pk = <fips204::$m::PublicKey as SerDes>::try_from_bytes(*arr)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let sig: <fips204::$m::PublicKey as Verifier>::Signature =
                sig_bytes.try_into().map_err(|_| CKR_SIGNATURE_INVALID)?;
            #[allow(deprecated)]
            if fips204::$m::_internal_verify(&pk, message, &sig, ctx) {
                Ok(())
            } else {
                Err(CKR_SIGNATURE_INVALID)
            }
        }};
    }
    match ps {
        CKP_ML_DSA_44 => ver!(ml_dsa_44),
        CKP_ML_DSA_65 | 0 => ver!(ml_dsa_65),
        CKP_ML_DSA_87 => ver!(ml_dsa_87),
        _ => Err(CKR_KEY_TYPE_INCONSISTENT),
    }
}

/// ML-DSA **external-µ** signing (ACVP `externalMu=true` / OASIS interop
/// `<ExternalMu value="true"/>`): the caller supplies the 64-byte message
/// representative µ directly (the `Data` field carries µ = H(tr‖M′), not the
/// message). FIPS 204 IPD external-mu mode. `deterministic` ⇒ rnd←0^32.
pub fn sign_ml_dsa_external_mu(
    ps: u32,
    sk_bytes: &[u8],
    mu: &[u8],
    rnd: [u8; 32],
) -> Result<Vec<u8>, u32> {
    let mu64: [u8; 64] = mu.try_into().map_err(|_| CKR_ARGUMENTS_BAD)?;
    macro_rules! sign_with {
        ($m:ident) => {{
            use fips204::traits::SerDes;
            let arr: &<fips204::$m::PrivateKey as SerDes>::ByteArray =
                sk_bytes.try_into().map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let sk = <fips204::$m::PrivateKey as SerDes>::try_from_bytes(*arr)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            #[allow(deprecated)]
            fips204::$m::_internal_sign_external_mu(&sk, &mu64, rnd)
                .map(|s| s.to_vec())
                .map_err(|_| CKR_FUNCTION_FAILED)
        }};
    }
    match ps {
        CKP_ML_DSA_44 => sign_with!(ml_dsa_44),
        CKP_ML_DSA_65 | 0 => sign_with!(ml_dsa_65),
        CKP_ML_DSA_87 => sign_with!(ml_dsa_87),
        _ => Err(CKR_KEY_TYPE_INCONSISTENT),
    }
}

/// ML-DSA external-µ verification — counterpart to [`sign_ml_dsa_external_mu`].
pub fn verify_ml_dsa_external_mu(
    ps: u32,
    pk_bytes: &[u8],
    mu: &[u8],
    sig_bytes: &[u8],
) -> Result<(), u32> {
    use fips204::traits::Verifier;
    let mu64: [u8; 64] = mu.try_into().map_err(|_| CKR_ARGUMENTS_BAD)?;
    macro_rules! ver {
        ($m:ident) => {{
            use fips204::traits::SerDes;
            let arr: &<fips204::$m::PublicKey as SerDes>::ByteArray =
                pk_bytes.try_into().map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let pk = <fips204::$m::PublicKey as SerDes>::try_from_bytes(*arr)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let sig: <fips204::$m::PublicKey as Verifier>::Signature =
                sig_bytes.try_into().map_err(|_| CKR_SIGNATURE_INVALID)?;
            #[allow(deprecated)]
            if fips204::$m::_internal_verify_external_mu(&pk, &mu64, &sig) {
                Ok(())
            } else {
                Err(CKR_SIGNATURE_INVALID)
            }
        }};
    }
    match ps {
        CKP_ML_DSA_44 => ver!(ml_dsa_44),
        CKP_ML_DSA_65 | 0 => ver!(ml_dsa_65),
        CKP_ML_DSA_87 => ver!(ml_dsa_87),
        _ => Err(CKR_KEY_TYPE_INCONSISTENT),
    }
}

/// ML-DSA **external-interface** signing with an explicit 32-byte randomizer —
/// the rnd-aware form of [`sign_ml_dsa`] (full `ML-DSA.Sign` with the
/// `(0‖|ctx|‖ctx)` framing). `rnd = [0u8; 32]` reproduces the deterministic
/// variant; a non-zero `rnd` reproduces the ACVP/OASIS hedged `<Random>`
/// signature byte-exact.
pub fn sign_ml_dsa_external_rnd(
    ps: u32,
    sk_bytes: &[u8],
    message: &[u8],
    ctx: &[u8],
    rnd: [u8; 32],
) -> Result<Vec<u8>, u32> {
    use fips204::traits::{SerDes, Signer};
    macro_rules! sign_with {
        ($m:ident) => {{
            let arr: &<fips204::$m::PrivateKey as SerDes>::ByteArray =
                sk_bytes.try_into().map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let sk = <fips204::$m::PrivateKey as SerDes>::try_from_bytes(*arr)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            sk.try_sign_with_rng(&mut FixedRng::new(&rnd), message, ctx)
                .map(|s| Into::<Vec<u8>>::into(s))
                .map_err(|_| CKR_FUNCTION_FAILED)
        }};
    }
    match ps {
        CKP_ML_DSA_44 => sign_with!(ml_dsa_44),
        CKP_ML_DSA_65 | 0 => sign_with!(ml_dsa_65),
        CKP_ML_DSA_87 => sign_with!(ml_dsa_87),
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
        CKM_RIPEMD160_HMAC => {
            let mut mac = Hmac::<ripemd::Ripemd160>::new_from_slice(key_bytes)
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
        CKM_SHA3_384_RSA_PKCS => pkcs1v15_sign!(sha3::Sha3_384),
        CKM_SHA3_384_RSA_PKCS_PSS => pss_sign!(sha3::Sha3_384, 48),
        // Raw PKCS#1 v1.5: the caller supplies the bytes (already a DigestInfo
        // or arbitrary data); no hashing, no DigestInfo prefix.
        CKM_RSA_PKCS => private_key
            .sign(rsa::Pkcs1v15Sign::new_unprefixed(), msg)
            .map_err(|_| CKR_FUNCTION_FAILED),
        _ => Err(CKR_MECHANISM_INVALID),
    }
}

/// Digest `msg` per a hash-composite ECDSA mechanism (`CKM_ECDSA_SHAx` /
/// `CKM_ECDSA_SHA3_x`). `None` for anything else — including raw
/// `CKM_ECDSA`, whose input is already a digest.
fn ecdsa_mech_digest(mech: u32, msg: &[u8]) -> Option<Vec<u8>> {
    use sha2::Digest as _;
    Some(match mech {
        CKM_ECDSA_SHA256 => sha2::Sha256::digest(msg).to_vec(),
        CKM_ECDSA_SHA384 => sha2::Sha384::digest(msg).to_vec(),
        CKM_ECDSA_SHA512 => sha2::Sha512::digest(msg).to_vec(),
        CKM_ECDSA_SHA3_224 => sha3::Sha3_224::digest(msg).to_vec(),
        CKM_ECDSA_SHA3_256 => sha3::Sha3_256::digest(msg).to_vec(),
        CKM_ECDSA_SHA3_384 => sha3::Sha3_384::digest(msg).to_vec(),
        CKM_ECDSA_SHA3_512 => sha3::Sha3_512::digest(msg).to_vec(),
        _ => return None,
    })
}

/// FIPS 186-5 §6.4 — condition a digest for prehash-sign/verify on `curve`:
/// digests longer than the field are truncated to the LEFTMOST field-size
/// bytes; shorter digests are left-padded with zeros to the field size
/// (zero-extension keeps the integer value E unchanged — also works around
/// the RustCrypto `bits2field` minimum-length check, which would reject a
/// 32-byte SHA-256/SHA3-256 digest on P-521).
fn fit_digest_to_curve(curve: u32, mut digest: Vec<u8>) -> Vec<u8> {
    let field: usize = match curve {
        CURVE_P521 => 66,
        CURVE_P384 => 48,
        _ => 32, // CURVE_P256 / CURVE_K256
    };
    if digest.len() >= field {
        digest.truncate(field);
        digest
    } else {
        let mut padded = vec![0u8; field - digest.len()];
        padded.extend_from_slice(&digest);
        padded
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
        // ── T1 (round-2) — residual (hash-mech, named-curve) pairs ─────────
        // PKCS#11 v3.2 §6.3 places no curve/hash pairing constraint on the
        // hash-composite ECDSA mechanisms, so any pair within the advertised
        // (256, 521) range without a dedicated arm above dispatches here:
        // digest per the mechanism, FIPS 186-5 §6.4 leftmost-bits
        // conditioning, then prehash-sign on the key's curve.
        (m, CURVE_P256 | CURVE_P384 | CURVE_P521 | CURVE_K256) => {
            let digest = match ecdsa_mech_digest(m, msg) {
                Some(d) => fit_digest_to_curve(curve, d),
                None => return Err(CKR_MECHANISM_INVALID),
            };
            match curve {
                CURVE_P256 => {
                    use p256::ecdsa::signature::hazmat::PrehashSigner;
                    let sk = p256::ecdsa::SigningKey::from_slice(sk_bytes)
                        .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
                    let sig: p256::ecdsa::Signature =
                        sk.sign_prehash(&digest).map_err(|_| CKR_FUNCTION_FAILED)?;
                    Ok(sig.to_bytes().to_vec())
                }
                CURVE_P384 => {
                    use p384::ecdsa::signature::hazmat::PrehashSigner;
                    let sk = p384::ecdsa::SigningKey::from_slice(sk_bytes)
                        .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
                    let sig: p384::ecdsa::Signature =
                        sk.sign_prehash(&digest).map_err(|_| CKR_FUNCTION_FAILED)?;
                    Ok(sig.to_bytes().to_vec())
                }
                CURVE_P521 => {
                    use p521::ecdsa::signature::hazmat::PrehashSigner;
                    let sk = p521::ecdsa::SigningKey::from_slice(sk_bytes)
                        .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
                    let sig: p521::ecdsa::Signature =
                        sk.sign_prehash(&digest).map_err(|_| CKR_FUNCTION_FAILED)?;
                    Ok(sig.to_bytes().to_vec())
                }
                _ => {
                    // CURVE_K256 (the arm's pattern admits nothing else)
                    use k256::ecdsa::signature::hazmat::PrehashSigner;
                    let sk = k256::ecdsa::SigningKey::from_slice(sk_bytes)
                        .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
                    let sig: k256::ecdsa::Signature =
                        sk.sign_prehash(&digest).map_err(|_| CKR_FUNCTION_FAILED)?;
                    Ok(sig.to_bytes().to_vec())
                }
            }
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
            // W3 — prefer the STANDARD CKA_PARAMETER_SET (§6.66.6); the
            // legacy vendor attribute is only a fallback. A signature-length
            // estimate computed from the wrong parameter set under-sizes the
            // caller's buffer.
            let xmss_param = get_object_attr_u32(hkey, CKA_PARAMETER_SET)
                .filter(|v| *v != 0)
                .or_else(|| get_object_attr_u32(hkey, CKA_XMSS_PARAM_SET).filter(|v| *v != 0))
                .unwrap_or(CKP_XMSS_SHA2_10_256);
            // SHAKE256_10_192 is the one n=24 set (SP 800-208): len=51, h=10.
            if xmss_param == CKP_XMSS_SHAKE256_10_192 {
                return 4 + 24 + (51 + 10) * 24;
            }
            let h: u32 = match xmss_param {
                CKP_XMSS_SHA2_16_256 | CKP_XMSS_SHAKE_16_256 | CKP_XMSS_SHAKE256_16_256 => 16,
                CKP_XMSS_SHA2_20_256 | CKP_XMSS_SHAKE_20_256 | CKP_XMSS_SHAKE256_20_256 => 20,
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
        CKM_RIPEMD160_HMAC => 20,
        CKM_SHA384_HMAC => 48,
        CKM_SHA512_HMAC | CKM_SHA3_512_HMAC => 64,
        CKM_KMAC_128 => 32,
        CKM_KMAC_256 => 64,
        CKM_SHA256_RSA_PKCS | CKM_SHA384_RSA_PKCS | CKM_SHA512_RSA_PKCS
        | CKM_SHA256_RSA_PKCS_PSS | CKM_SHA384_RSA_PKCS_PSS | CKM_SHA512_RSA_PKCS_PSS
        | CKM_SHA3_384_RSA_PKCS | CKM_SHA3_384_RSA_PKCS_PSS | CKM_RSA_PKCS => 512,
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
        CKM_SHA3_384_RSA_PKCS => pkcs1v15_verify!(sha3::Sha3_384),
        CKM_SHA3_384_RSA_PKCS_PSS => pss_verify!(sha3::Sha3_384, 48),
        // Raw PKCS#1 v1.5 — caller-supplied bytes, no DigestInfo prefix.
        CKM_RSA_PKCS => public_key
            .verify(rsa::Pkcs1v15Sign::new_unprefixed(), msg, sig_bytes)
            .map_err(|_| CKR_SIGNATURE_INVALID),
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
        // ── T1 (round-2) — residual (hash-mech, named-curve) pairs ─────────
        // Mirror of the sign_ecdsa catch-all: digest per the mechanism,
        // FIPS 186-5 §6.4 leftmost-bits conditioning, prehash-verify on the
        // key's curve. Covers every advertised pair without a dedicated arm.
        (m, CURVE_P256 | CURVE_P384 | CURVE_P521 | CURVE_K256) => {
            let digest = match ecdsa_mech_digest(m, msg) {
                Some(d) => fit_digest_to_curve(curve, d),
                None => return Err(CKR_MECHANISM_INVALID),
            };
            match curve {
                CURVE_P256 => {
                    use p256::ecdsa::signature::hazmat::PrehashVerifier;
                    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(pk_bytes)
                        .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
                    let sig = p256::ecdsa::Signature::try_from(sig_bytes)
                        .map_err(|_| CKR_SIGNATURE_INVALID)?;
                    vk.verify_prehash(&digest, &sig)
                        .map_err(|_| CKR_SIGNATURE_INVALID)
                }
                CURVE_P384 => {
                    use p384::ecdsa::signature::hazmat::PrehashVerifier;
                    let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(pk_bytes)
                        .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
                    let sig = p384::ecdsa::Signature::try_from(sig_bytes)
                        .map_err(|_| CKR_SIGNATURE_INVALID)?;
                    vk.verify_prehash(&digest, &sig)
                        .map_err(|_| CKR_SIGNATURE_INVALID)
                }
                CURVE_P521 => {
                    use p521::ecdsa::signature::hazmat::PrehashVerifier;
                    let vk = p521::ecdsa::VerifyingKey::from_sec1_bytes(pk_bytes)
                        .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
                    let sig = p521::ecdsa::Signature::try_from(sig_bytes)
                        .map_err(|_| CKR_SIGNATURE_INVALID)?;
                    vk.verify_prehash(&digest, &sig)
                        .map_err(|_| CKR_SIGNATURE_INVALID)
                }
                _ => {
                    // CURVE_K256 (the arm's pattern admits nothing else)
                    use k256::ecdsa::signature::hazmat::PrehashVerifier;
                    let vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(pk_bytes)
                        .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
                    let sig = k256::ecdsa::Signature::try_from(sig_bytes)
                        .map_err(|_| CKR_SIGNATURE_INVALID)?;
                    vk.verify_prehash(&digest, &sig)
                        .map_err(|_| CKR_SIGNATURE_INVALID)
                }
            }
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

    /// OpenSSL PSS, SHA-256 + MGF1-SHA256, saltlen = 0 (K18 KAT):
    ///   openssl dgst -sha256 -sign key.pem \
    ///     -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:0 msg
    /// PSS with a zero-length salt is DETERMINISTIC (RFC 8017 §9.1.1 —
    /// the only randomness is the salt), so our signature must
    /// byte-match OpenSSL's.
    const K18_SIG_SHA256_PSS_SALT0_HEX: &str = "\
cfb60dbd1706a95d149004631b7b6e49672331cdd99a55561fd95e22016c74389763b9996c5ac95640482cb7712571ae35e4d9062c36bb6db622bb21900f13af\
3e48b390a9bacb892e3bbf336531f14e6c6809b72a2514e19d1052af00a8ff01fc735322c9e6fb3558a9117a8ba4895ca2048157cc7d44470c248ce8fcb8c2cb\
1f8029c232b17d653902dfb8dc56c8fb716aec5913728c02889fe538eb25691988ad26e32e13401e62cfd840333bf2e5e820578e9340e578cc46a3dd3f3be671\
6782527238e219d2ad51ccb210b152eb8781371c3dbf4f4c74305ba5d20bb2e1eb91ec4e289ada28824cea168372cd6fa8536b1f7c48ffd42f91d3dabeaabe9f";

    /// K18 — explicit PSS salt length end-to-end at the handler layer:
    /// salt = 0 is deterministic and byte-matches the OpenSSL KAT;
    /// verify with an explicit salt pins EMSA-PSS-VERIFY to exactly
    /// that length (the `rsa` crate does NOT recover the salt length
    /// from the padding); `None` keeps the two-candidate default,
    /// which does NOT include 0; oversized salt (> emLen - hLen - 2 =
    /// 222 for RSA-2048/SHA-256) errors at sign time.
    #[test]
    fn k18_rsa_pss_explicit_salt_len_matches_openssl_salt0_kat() {
        let (sk, n, e) = s6_key();
        let m = crate::constants::CKM_SHA256_RSA_PKCS_PSS;
        let kat = decode_hex(K18_SIG_SHA256_PSS_SALT0_HEX);

        let sig = sign_rsa(m, &sk, S6_MSG, Some(0)).unwrap();
        assert_eq!(sig, kat, "PSS salt=0 is deterministic, must byte-match OpenSSL");
        assert_eq!(verify_rsa(m, &n, &e, S6_MSG, &sig, Some(0)), Ok(()));
        // Default verify candidates are {hashLen, maximal} — 0 is not
        // among them, so a salt-0 signature needs the explicit salt.
        assert_eq!(
            verify_rsa(m, &n, &e, S6_MSG, &sig, None),
            Err(CKR_SIGNATURE_INVALID)
        );
        // Wrong explicit salt → invalid.
        assert_eq!(
            verify_rsa(m, &n, &e, S6_MSG, &sig, Some(32)),
            Err(CKR_SIGNATURE_INVALID)
        );

        // salt = 20 round-trip: randomized, pinned verify succeeds.
        let sig20 = sign_rsa(m, &sk, S6_MSG, Some(20)).unwrap();
        assert_eq!(verify_rsa(m, &n, &e, S6_MSG, &sig20, Some(20)), Ok(()));
        assert_eq!(
            verify_rsa(m, &n, &e, S6_MSG, &sig20, Some(0)),
            Err(CKR_SIGNATURE_INVALID)
        );

        // Oversized salt: RSA-2048 + SHA-256 → emLen - hLen - 2 = 222.
        assert_eq!(sign_rsa(m, &sk, S6_MSG, Some(300)), Err(CKR_FUNCTION_FAILED));
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

    /// Regression test for a real bug the `openssl_cert_crosscheck.rs`
    /// external cross-check caught (kmip cert-ops port, 2026-07-09):
    /// `build_slhdsa_spki` encoded every parameter set's OID as
    /// `2.16.840.1.101.3.4.20.{1..12}` — a shape that doesn't exist in
    /// RFC 9909 at all — instead of the real `2.16.840.1.101.3.4.3.{20..31}`
    /// (§3, verified against the RFC's own ASN.1 module and independently
    /// against `openssl list -signature-algorithms`' registered OIDs).
    /// OpenSSL couldn't even DECODE a cert carrying the old, wrong SPKI.
    /// Checks all 12 parameter sets against RFC 9909, decoded with the
    /// SAME `spki` crate the kmip crate's Certify/Validate use — an
    /// independent parse of this function's own output, not a
    /// self-referential byte comparison.
    #[test]
    fn build_slhdsa_spki_encodes_the_real_rfc9909_oid_for_all_twelve_parameter_sets() {
        use spki::der::Decode;
        use spki::SubjectPublicKeyInfoOwned;

        let cases: [(u32, &str); 12] = [
            (1, "2.16.840.1.101.3.4.3.20"),  // SHA2-128s
            (3, "2.16.840.1.101.3.4.3.21"),  // SHA2-128f
            (5, "2.16.840.1.101.3.4.3.22"),  // SHA2-192s
            (7, "2.16.840.1.101.3.4.3.23"),  // SHA2-192f
            (9, "2.16.840.1.101.3.4.3.24"),  // SHA2-256s
            (11, "2.16.840.1.101.3.4.3.25"), // SHA2-256f
            (2, "2.16.840.1.101.3.4.3.26"),  // SHAKE-128s
            (4, "2.16.840.1.101.3.4.3.27"),  // SHAKE-128f
            (6, "2.16.840.1.101.3.4.3.28"),  // SHAKE-192s
            (8, "2.16.840.1.101.3.4.3.29"),  // SHAKE-192f
            (10, "2.16.840.1.101.3.4.3.30"), // SHAKE-256s
            (12, "2.16.840.1.101.3.4.3.31"), // SHAKE-256f
        ];
        for (ckp, expected_oid) in cases {
            let fake_pk = vec![0u8; 32]; // OID check only — key length is irrelevant here.
            let spki_der = build_slhdsa_spki(ckp, &fake_pk);
            assert!(!spki_der.is_empty(), "CKP {ckp}: build_slhdsa_spki returned empty (unknown parameter set?)");
            let spki = SubjectPublicKeyInfoOwned::from_der(&spki_der)
                .unwrap_or_else(|e| panic!("CKP {ckp}: SPKI must be valid DER, decodable by an independent parser: {e}"));
            assert_eq!(
                spki.algorithm.oid.to_string(),
                expected_oid,
                "CKP {ckp}: wrong SLH-DSA OID"
            );
            assert!(spki.algorithm.parameters.is_none(), "CKP {ckp}: RFC 9909 requires ABSENT parameters");
        }
    }
}
