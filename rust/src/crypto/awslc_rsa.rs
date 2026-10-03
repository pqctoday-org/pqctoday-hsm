//! Native RSA private-key operations over raw AWS-LC (owner decision
//! 2026-10-03, RUSTSEC-2023-0071 "Marvin").
//!
//! On native builds EVERY RSA private-key operation — signing, decryption,
//! unwrapping, sign-recover and key generation — runs in AWS-LC, whose RSA
//! is blinded and constant-time. This module covers what `crypto::awslc`
//! (aws-lc-rs) does not expose: the MD5 / SHA-1 / SHA-224 / SHA-3 PKCS#1 v1.5
//! variants, PSS with a caller-chosen salt and bare (pre-hashed) PSS, raw
//! unprefixed PKCS#1 v1.5 signing, raw RSASP1 (`CKM_RSA_X_509`), OAEP with a
//! hash ≠ MGF1 hash or a PKCS#1-DER key, PKCS#1 v1.5 decryption of a
//! PKCS#1-DER key, and generation of any size in the policy range.
//!
//! Policy (owner decisions 2026-10-03): a native private-key operation needs
//! a modulus of 2048–8192 bits; anything else is `CKR_KEY_SIZE_RANGE`.
//! Public-key operations are not affected. WASM builds never compile this
//! module and keep the pure-Rust `rsa` crate (blinded everywhere).

use std::os::raw::c_int;
use std::ptr;

use aws_lc_sys as sys;

use crate::constants::*;
type CkRv = u32;

/// Native private-key modulus policy, in bits.
pub const MIN_PRIVATE_BITS: u32 = 2048;
pub const MAX_PRIVATE_BITS: u32 = 8192;

struct Rsa(*mut sys::RSA);

impl Drop for Rsa {
    fn drop(&mut self) {
        unsafe { sys::RSA_free(self.0) }
    }
}

struct Pkey(*mut sys::EVP_PKEY);

impl Drop for Pkey {
    fn drop(&mut self) {
        unsafe { sys::EVP_PKEY_free(self.0) }
    }
}

struct PkeyCtx(*mut sys::EVP_PKEY_CTX);

impl Drop for PkeyCtx {
    fn drop(&mut self) {
        unsafe { sys::EVP_PKEY_CTX_free(self.0) }
    }
}

/// `true` when `bits` is inside the native private-key policy.
pub fn private_bits_allowed(bits: u32) -> bool {
    (MIN_PRIVATE_BITS..=MAX_PRIVATE_BITS).contains(&bits)
}

/// Parse a PKCS#8 `PrivateKeyInfo` or a PKCS#1 `RSAPrivateKey` DER into an
/// `RSA`, with no size policy. `None` if it is neither.
fn parse_private(der: &[u8]) -> Option<Rsa> {
    let rsa = unsafe {
        let mut cbs = std::mem::zeroed::<sys::CBS>();
        sys::CBS_init(&mut cbs, der.as_ptr(), der.len());
        let pkey = sys::EVP_parse_private_key(&mut cbs);
        let from_pkcs8 = if !pkey.is_null() && sys::CBS_len(&cbs) == 0 {
            let p = Pkey(pkey);
            sys::EVP_PKEY_get1_RSA(p.0)
        } else {
            if !pkey.is_null() {
                sys::EVP_PKEY_free(pkey);
            }
            ptr::null_mut()
        };
        if from_pkcs8.is_null() {
            sys::ERR_clear_error();
            sys::RSA_private_key_from_bytes(der.as_ptr(), der.len())
        } else {
            from_pkcs8
        }
    };
    if rsa.is_null() {
        unsafe { sys::ERR_clear_error() };
        return None;
    }
    Some(Rsa(rsa))
}

/// [`parse_private`] plus the native policy: a key that does not parse is
/// `CKR_KEY_TYPE_INCONSISTENT` (the code the pure-Rust path used), a modulus
/// outside 2048–8192 bits is `CKR_KEY_SIZE_RANGE`.
fn load_private(der: &[u8]) -> Result<Rsa, CkRv> {
    let rsa = parse_private(der).ok_or(CKR_KEY_TYPE_INCONSISTENT)?;
    if !private_bits_allowed(unsafe { sys::RSA_bits(rsa.0) }) {
        return Err(CKR_KEY_SIZE_RANGE);
    }
    Ok(rsa)
}

fn modulus_len(rsa: &Rsa) -> usize {
    unsafe { sys::RSA_size(rsa.0) as usize }
}

/// The modulus size in bits of a private-key DER (no policy), or `None` if
/// it does not parse.
pub fn private_key_bits(der: &[u8]) -> Option<u32> {
    parse_private(der).map(|r| unsafe { sys::RSA_bits(r.0) })
}

/// `(NID, EVP_MD, digest length)` for a PKCS#11 hash mechanism.
fn hash_of(ckm: u32) -> Option<(c_int, *const sys::EVP_MD, usize)> {
    unsafe {
        Some(match ckm {
            CKM_MD5 => (sys::NID_md5, sys::EVP_md5(), 16),
            CKM_SHA_1 => (sys::NID_sha1, sys::EVP_sha1(), 20),
            CKM_SHA224 => (sys::NID_sha224, sys::EVP_sha224(), 28),
            CKM_SHA256 => (sys::NID_sha256, sys::EVP_sha256(), 32),
            CKM_SHA384 => (sys::NID_sha384, sys::EVP_sha384(), 48),
            CKM_SHA512 => (sys::NID_sha512, sys::EVP_sha512(), 64),
            CKM_SHA3_224 => (sys::NID_sha3_224, sys::EVP_sha3_224(), 28),
            CKM_SHA3_256 => (sys::NID_sha3_256, sys::EVP_sha3_256(), 32),
            CKM_SHA3_384 => (sys::NID_sha3_384, sys::EVP_sha3_384(), 48),
            CKM_SHA3_512 => (sys::NID_sha3_512, sys::EVP_sha3_512(), 64),
            _ => return None,
        })
    }
}

/// `CKG_MGF1_*` → the matching hash mechanism.
pub fn mgf_hash(ckg: u32) -> Option<u32> {
    Some(match ckg {
        CKG_MGF1_SHA1 => CKM_SHA_1,
        CKG_MGF1_SHA224 => CKM_SHA224,
        CKG_MGF1_SHA256 => CKM_SHA256,
        CKG_MGF1_SHA384 => CKM_SHA384,
        CKG_MGF1_SHA512 => CKM_SHA512,
        CKG_MGF1_SHA3_224 => CKM_SHA3_224,
        CKG_MGF1_SHA3_256 => CKM_SHA3_256,
        CKG_MGF1_SHA3_384 => CKM_SHA3_384,
        CKG_MGF1_SHA3_512 => CKM_SHA3_512,
        _ => return None,
    })
}

/// Hash `msg` with the digest behind `ckm` (AWS-LC `EVP_Digest`).
pub fn digest(ckm: u32, msg: &[u8]) -> Result<Vec<u8>, CkRv> {
    let (_, md, len) = hash_of(ckm).ok_or(CKR_MECHANISM_INVALID)?;
    let mut out = vec![0u8; len];
    let mut out_len: std::os::raw::c_uint = 0;
    let ok = unsafe { sys::EVP_Digest(msg.as_ptr().cast(), msg.len(), out.as_mut_ptr(), &mut out_len, md, ptr::null_mut()) };
    if ok != 1 || out_len as usize != len {
        unsafe { sys::ERR_clear_error() };
        return Err(CKR_FUNCTION_FAILED);
    }
    Ok(out)
}

/// PKCS#1 v1.5 signature over `digest` with the DigestInfo of `hash_ckm`.
pub fn sign_pkcs1_digest(der: &[u8], hash_ckm: u32, digest: &[u8]) -> Result<Vec<u8>, CkRv> {
    let rsa = load_private(der)?;
    let (nid, _, len) = hash_of(hash_ckm).ok_or(CKR_MECHANISM_INVALID)?;
    if digest.len() != len {
        return Err(CKR_DATA_LEN_RANGE);
    }
    let mut out = vec![0u8; modulus_len(&rsa)];
    let mut out_len: std::os::raw::c_uint = 0;
    let ok = unsafe { sys::RSA_sign(nid, digest.as_ptr(), digest.len(), out.as_mut_ptr(), &mut out_len, rsa.0) };
    finish(ok, out, out_len as usize, CKR_FUNCTION_FAILED)
}

/// Raw PKCS#1 v1.5 signature of caller-supplied bytes (no DigestInfo):
/// `CKM_RSA_PKCS` sign and sign-recover.
pub fn sign_pkcs1_raw(der: &[u8], msg: &[u8]) -> Result<Vec<u8>, CkRv> {
    let rsa = load_private(der)?;
    let k = modulus_len(&rsa);
    if msg.len() + 11 > k {
        return Err(CKR_DATA_LEN_RANGE);
    }
    let mut out = vec![0u8; k];
    let mut out_len = 0usize;
    let ok = unsafe { sys::RSA_sign_raw(rsa.0, &mut out_len, out.as_mut_ptr(), k, msg.as_ptr(), msg.len(), sys::RSA_PKCS1_PADDING) };
    finish(ok, out, out_len, CKR_FUNCTION_FAILED)
}

/// RSASP1 with no padding (`CKM_RSA_X_509` sign-recover): `msg` is
/// left-padded to the modulus length; a representative ≥ n is
/// `CKR_DATA_LEN_RANGE`.
pub fn sign_x509_raw(der: &[u8], msg: &[u8]) -> Result<Vec<u8>, CkRv> {
    let rsa = load_private(der)?;
    let k = modulus_len(&rsa);
    if msg.len() > k {
        return Err(CKR_DATA_LEN_RANGE);
    }
    let mut input = vec![0u8; k - msg.len()];
    input.extend_from_slice(msg);
    let mut out = vec![0u8; k];
    let mut out_len = 0usize;
    let ok = unsafe { sys::RSA_sign_raw(rsa.0, &mut out_len, out.as_mut_ptr(), k, input.as_ptr(), k, sys::RSA_NO_PADDING) };
    finish(ok, out, out_len, CKR_DATA_LEN_RANGE)
}

/// RSASSA-PSS over a precomputed `digest` of `hash_ckm`, MGF1 with
/// `mgf_ckm`, salt length `salt_len` (`CKM_*_RSA_PKCS_PSS` with any salt and
/// bare `CKM_RSA_PKCS_PSS`).
pub fn sign_pss_digest(der: &[u8], hash_ckm: u32, mgf_ckm: u32, salt_len: usize, digest: &[u8]) -> Result<Vec<u8>, CkRv> {
    let rsa = load_private(der)?;
    let (_, md, len) = hash_of(hash_ckm).ok_or(CKR_MECHANISM_PARAM_INVALID)?;
    let (_, mgf_md, _) = hash_of(mgf_ckm).ok_or(CKR_MECHANISM_PARAM_INVALID)?;
    if digest.len() != len {
        return Err(CKR_DATA_LEN_RANGE);
    }
    let k = modulus_len(&rsa);
    let salt = c_int::try_from(salt_len).map_err(|_| CKR_MECHANISM_PARAM_INVALID)?;
    let mut out = vec![0u8; k];
    let mut out_len = 0usize;
    let ok = unsafe { sys::RSA_sign_pss_mgf1(rsa.0, &mut out_len, out.as_mut_ptr(), k, digest.as_ptr(), digest.len(), md, mgf_md, salt) };
    // An unsatisfiable salt length (salt > emLen − hLen − 2) fails here:
    // CKR_FUNCTION_FAILED, as the pure-Rust path reported it.
    finish(ok, out, out_len, CKR_FUNCTION_FAILED)
}

/// RSAES-PKCS1-v1_5 decryption (`CKM_RSA_PKCS` decrypt/unwrap). Any failure
/// is the uniform `CKR_ENCRYPTED_DATA_INVALID` — no padding oracle.
pub fn decrypt_pkcs1(der: &[u8], ct: &[u8]) -> Result<Vec<u8>, CkRv> {
    let rsa = load_private(der)?;
    let k = modulus_len(&rsa);
    if ct.len() != k {
        return Err(CKR_ENCRYPTED_DATA_LEN_RANGE);
    }
    let mut out = vec![0u8; k];
    let mut out_len = 0usize;
    let ok = unsafe { sys::RSA_decrypt(rsa.0, &mut out_len, out.as_mut_ptr(), k, ct.as_ptr(), ct.len(), sys::RSA_PKCS1_PADDING) };
    finish(ok, out, out_len, CKR_ENCRYPTED_DATA_INVALID)
}

/// RSAES-OAEP decryption with independent hash and MGF1 hash and an
/// optional label. Any failure is `CKR_ENCRYPTED_DATA_INVALID`.
pub fn decrypt_oaep(der: &[u8], hash_ckm: u32, mgf_ckm: u32, label: &[u8], ct: &[u8]) -> Result<Vec<u8>, CkRv> {
    let rsa = load_private(der)?;
    let (_, md, _) = hash_of(hash_ckm).ok_or(CKR_MECHANISM_PARAM_INVALID)?;
    let (_, mgf_md, _) = hash_of(mgf_ckm).ok_or(CKR_MECHANISM_PARAM_INVALID)?;
    let k = modulus_len(&rsa);
    if ct.len() != k {
        return Err(CKR_ENCRYPTED_DATA_LEN_RANGE);
    }
    unsafe {
        let pkey = Pkey(sys::EVP_PKEY_new());
        if pkey.0.is_null() || sys::EVP_PKEY_set1_RSA(pkey.0, rsa.0) != 1 {
            sys::ERR_clear_error();
            return Err(CKR_DEVICE_ERROR);
        }
        let ctx = PkeyCtx(sys::EVP_PKEY_CTX_new(pkey.0, ptr::null_mut()));
        if ctx.0.is_null()
            || sys::EVP_PKEY_decrypt_init(ctx.0) != 1
            || sys::EVP_PKEY_CTX_set_rsa_padding(ctx.0, sys::RSA_PKCS1_OAEP_PADDING) != 1
            || sys::EVP_PKEY_CTX_set_rsa_oaep_md(ctx.0, md) != 1
            || sys::EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.0, mgf_md) != 1
        {
            sys::ERR_clear_error();
            return Err(CKR_DEVICE_ERROR);
        }
        if !label.is_empty() {
            // set0 takes ownership of an OPENSSL_malloc'd copy.
            let l = sys::OPENSSL_malloc(label.len()) as *mut u8;
            if l.is_null() {
                return Err(CKR_HOST_MEMORY);
            }
            ptr::copy_nonoverlapping(label.as_ptr(), l, label.len());
            if sys::EVP_PKEY_CTX_set0_rsa_oaep_label(ctx.0, l, label.len()) != 1 {
                sys::OPENSSL_free(l.cast());
                sys::ERR_clear_error();
                return Err(CKR_DEVICE_ERROR);
            }
        }
        let mut out = vec![0u8; k];
        let mut out_len = k;
        let ok = sys::EVP_PKEY_decrypt(ctx.0, out.as_mut_ptr(), &mut out_len, ct.as_ptr(), ct.len());
        finish(ok, out, out_len, CKR_ENCRYPTED_DATA_INVALID)
    }
}

/// Generate an RSA key of `bits` (policy range, multiple of 8) with public
/// exponent `e` (odd, ≥ 3; normally 65537). Returns `(pkcs8_der, n_be,
/// e_be)` — the tuple the engine stores.
pub fn generate(bits: u32, e: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), CkRv> {
    if !private_bits_allowed(bits) || bits % 8 != 0 {
        return Err(CKR_KEY_SIZE_RANGE);
    }
    unsafe {
        let rsa = Rsa(sys::RSA_new());
        let bn_e = sys::BN_bin2bn(e.as_ptr(), e.len(), ptr::null_mut());
        if rsa.0.is_null() || bn_e.is_null() {
            sys::BN_free(bn_e);
            return Err(CKR_HOST_MEMORY);
        }
        let ok = sys::RSA_generate_key_ex(rsa.0, bits as c_int, bn_e, ptr::null_mut());
        sys::BN_free(bn_e);
        if ok != 1 {
            sys::ERR_clear_error();
            return Err(CKR_TEMPLATE_INCONSISTENT); // e.g. an unusable exponent
        }
        let pkey = Pkey(sys::EVP_PKEY_new());
        if pkey.0.is_null() || sys::EVP_PKEY_set1_RSA(pkey.0, rsa.0) != 1 {
            sys::ERR_clear_error();
            return Err(CKR_DEVICE_ERROR);
        }
        let mut cbb = std::mem::zeroed::<sys::CBB>();
        if sys::CBB_init(&mut cbb, 0) != 1 || sys::EVP_marshal_private_key(&mut cbb, pkey.0) != 1 {
            sys::CBB_cleanup(&mut cbb);
            sys::ERR_clear_error();
            return Err(CKR_DEVICE_ERROR);
        }
        let (mut data, mut len) = (ptr::null_mut::<u8>(), 0usize);
        if sys::CBB_finish(&mut cbb, &mut data, &mut len) != 1 {
            sys::CBB_cleanup(&mut cbb);
            return Err(CKR_DEVICE_ERROR);
        }
        let pkcs8 = std::slice::from_raw_parts(data, len).to_vec();
        sys::OPENSSL_free(data.cast());
        let (mut n, mut ee, mut d) = (ptr::null(), ptr::null(), ptr::null());
        sys::RSA_get0_key(rsa.0, &mut n, &mut ee, &mut d);
        Ok((pkcs8, bn_bytes(n), bn_bytes(ee)))
    }
}

unsafe fn bn_bytes(bn: *const sys::BIGNUM) -> Vec<u8> {
    let len = unsafe { sys::BN_num_bytes(bn) } as usize;
    let mut v = vec![0u8; len];
    unsafe { sys::BN_bn2bin(bn, v.as_mut_ptr()) };
    v
}

/// Map an AWS-LC 1/0 result to the output buffer or `fail`.
fn finish(ok: c_int, mut out: Vec<u8>, len: usize, fail: CkRv) -> Result<Vec<u8>, CkRv> {
    if ok != 1 {
        unsafe { sys::ERR_clear_error() };
        return Err(fail);
    }
    out.truncate(len);
    Ok(out)
}

/// `(hash mechanism, is_pss)` for a composite RSA signing mechanism.
fn composite(mech: u32) -> Option<(u32, bool)> {
    Some(match mech {
        CKM_MD5_RSA_PKCS => (CKM_MD5, false),
        CKM_SHA1_RSA_PKCS => (CKM_SHA_1, false),
        CKM_SHA224_RSA_PKCS => (CKM_SHA224, false),
        CKM_SHA256_RSA_PKCS => (CKM_SHA256, false),
        CKM_SHA384_RSA_PKCS => (CKM_SHA384, false),
        CKM_SHA512_RSA_PKCS => (CKM_SHA512, false),
        CKM_SHA3_224_RSA_PKCS => (CKM_SHA3_224, false),
        CKM_SHA3_256_RSA_PKCS => (CKM_SHA3_256, false),
        CKM_SHA3_384_RSA_PKCS => (CKM_SHA3_384, false),
        CKM_SHA3_512_RSA_PKCS => (CKM_SHA3_512, false),
        CKM_SHA1_RSA_PKCS_PSS => (CKM_SHA_1, true),
        CKM_SHA224_RSA_PKCS_PSS => (CKM_SHA224, true),
        CKM_SHA256_RSA_PKCS_PSS => (CKM_SHA256, true),
        CKM_SHA384_RSA_PKCS_PSS => (CKM_SHA384, true),
        CKM_SHA512_RSA_PKCS_PSS => (CKM_SHA512, true),
        CKM_SHA3_224_RSA_PKCS_PSS => (CKM_SHA3_224, true),
        CKM_SHA3_256_RSA_PKCS_PSS => (CKM_SHA3_256, true),
        CKM_SHA3_384_RSA_PKCS_PSS => (CKM_SHA3_384, true),
        CKM_SHA3_512_RSA_PKCS_PSS => (CKM_SHA3_512, true),
        _ => return None,
    })
}

/// `sign_rsa`'s native implementation for every mechanism it accepts:
/// composite PKCS#1 v1.5 and PSS (default salt = hash length, MGF1 with the
/// same hash, or `pss_salt_len`) and raw `CKM_RSA_PKCS`.
pub fn sign_mech(mech: u32, der: &[u8], msg: &[u8], pss_salt_len: Option<usize>) -> Result<Vec<u8>, CkRv> {
    if mech == CKM_RSA_PKCS {
        return sign_pkcs1_raw(der, msg);
    }
    let (hash, pss) = composite(mech).ok_or(CKR_MECHANISM_INVALID)?;
    // Size policy before hashing, so an out-of-range key fails the same way
    // whatever the mechanism.
    load_private(der)?;
    let d = digest(hash, msg)?;
    if pss {
        let salt = pss_salt_len.unwrap_or(d.len());
        sign_pss_digest(der, hash, hash, salt, &d)
    } else {
        sign_pkcs1_digest(der, hash, &d)
    }
}

/// [`decrypt_oaep`] with PKCS#11's MGF encoding: `mgf` is a `CKG_MGF1_*`
/// code, or 0 for "MGF1 with the OAEP hash".
pub fn decrypt_oaep_ck(der: &[u8], hash_alg: u32, mgf: u32, label: &[u8], ct: &[u8]) -> Result<Vec<u8>, CkRv> {
    let mgf_ckm = if mgf == 0 { hash_alg } else { mgf_hash(mgf).ok_or(CKR_MECHANISM_PARAM_INVALID)? };
    decrypt_oaep(der, hash_alg, mgf_ckm, label, ct)
}
