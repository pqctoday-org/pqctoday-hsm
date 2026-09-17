//! Native fast path over AWS-LC (`aws-lc-rs`) for RSA and NIST-curve ECDH.
//!
//! ## Why this exists
//!
//! Measured on the FRDM-IMX95 (6× Cortex-A55 @ 1.8 GHz) on 2026-09-15, one
//! thread, against OpenSSL 3.6.3 on the same core:
//!
//! | operation        | pure-Rust crate | OpenSSL / AWS-LC | gap   |
//! |------------------|-----------------|------------------|-------|
//! | RSA-2048 sign    | 57.7 /s (`rsa`) | 166.8 /s         | 2.9×  |
//! | ML-DSA-44 sign   | 245.2 /s        | 284.9 /s         | 1.16× |
//!
//! ML-DSA is the only algorithm where the pure-Rust engine is competitive;
//! And `rsa` 0.9 is RUSTSEC-2023-0071 (the Marvin attack — private-key
//! recovery through a network-observable timing side channel), unpatched
//! upstream as of 2026-09, while this engine is statically linked into the
//! KMIP server that serves RSA on :5696. AWS-LC's RSA is constant-time.
//!
//! ## The dispatch rule
//!
//! Every function here returns `Option<Result<_, CkRv>>`:
//!
//! * `Some(r)` — AWS-LC handled it; `r` is the answer, error codes already
//!   mapped to PKCS#11 `CKR_*` exactly as the pure-Rust path maps them.
//! * `None` — **not handled here; the caller MUST fall through to the existing
//!   pure-Rust implementation**, which is left untouched as the fallback.
//!
//! `None` is returned for everything AWS-LC deliberately does not expose, so
//! no mechanism the engine supported before this module exists is lost:
//! raw `CKM_RSA_X_509`, unprefixed `CKM_RSA_PKCS`, ALL RSA-PSS (its
//! verify is salt-length-agnostic in the `rsa` crate but salt-fixed in
//! AWS-LC), PSS with a caller-chosen
//! salt length (AWS-LC pins salt = digest length), the MD5 / SHA-1 / SHA-224 /
//! SHA-3 RSA variants, OAEP with a hash ≠ MGF1 hash, RSA keys under 2048 bits,
//! non-standard key sizes at generation, compressed EC points, and every curve
//! but P-256 / P-384 / P-521. The pure-Rust code path is therefore still the
//! conformance reference; this module is a performance-and-side-channel
//! overlay on the hot, modern, network-exposed subset.
//!
//! ## Where it is compiled
//!
//! Only on non-wasm32 targets — see the `aws-lc-rs` entry in `Cargo.toml`
//! for why the hub's wasm-bindgen build cannot carry a C crypto library, and
//! why that is fine (no network timing oracle inside a browser tab). Callers
//! use `#[cfg(not(target_arch = "wasm32"))]` around the `if let Some(..)`
//! probe, so the wasm build is byte-for-byte the pre-existing code.

use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::KeyPair as _;
use aws_lc_rs::{agreement, rsa, signature};

use crate::constants::*;
use crate::crypto::handlers::{CURVE_P256, CURVE_P384, CURVE_P521};
use crate::native::CkRv;

/// `(pkcs8_der, n_be, e_be)` — the tuple `rsa_generate` yields, matching the
/// shapes the pure-Rust keygen produces so the attribute-building code is shared.
type RsaKeyParts = (Vec<u8>, Vec<u8>, Vec<u8>);

/// RSA keys AWS-LC's `RSA_PKCS1_2048_8192_*` verify algorithms accept. The
/// pure-Rust path accepts anything; smaller moduli fall back to it.
const MIN_MODULUS_BYTES: usize = 256;

// ── RSA sign ───────────────────────────────────────────────────────────────

/// Maps a PKCS#11 RSA signing mechanism to AWS-LC's padding algorithm, or
/// `None` when AWS-LC has no equivalent (see module doc).
fn rsa_sign_alg(mech: u32, _pss_salt_len: Option<usize>) -> Option<&'static dyn signature::RsaEncoding> {
    match mech {
        CKM_SHA256_RSA_PKCS => Some(&signature::RSA_PKCS1_SHA256),
        CKM_SHA384_RSA_PKCS => Some(&signature::RSA_PKCS1_SHA384),
        CKM_SHA512_RSA_PKCS => Some(&signature::RSA_PKCS1_SHA512),
        // RSA-PSS stays on the pure-Rust path, NOT AWS-LC. AWS-LC's PSS
        // verify requires salt length == digest length, but the `rsa` crate
        // (and the KMIP contract) do salt-length-AGNOSTIC verification —
        // recovering the salt from the signature. Routing PSS here made a
        // valid externally-produced signature (OASIS CS-AC-M-2-30, a
        // non-default salt) verify as INVALID. PSS is randomized anyway, so
        // it is not a meaningful speedup target; keep the whole scheme on the
        // salt-agnostic pure-Rust path. `pss_salt_len` is now unused here.
        _ => None,
    }
}

/// `sign_rsa`'s fast path. `sk_pkcs8` is PKCS#8 `PrivateKeyInfo` DER — the
/// format `generate_rsa_keypair` stores and every RSA sign site passes.
pub fn rsa_sign(mech: u32, sk_pkcs8: &[u8], msg: &[u8], pss_salt_len: Option<usize>) -> Option<Result<Vec<u8>, CkRv>> {
    let alg = rsa_sign_alg(mech, pss_salt_len)?;
    Some((|| {
        // Parsed once per distinct key, not once per signature — see
        // `crypto::awslc_keycache`. A build failure keeps this function's
        // pre-existing error code for an unparseable/unsupported key.
        let kp = crate::crypto::awslc_keycache::signer(sk_pkcs8).ok_or(CKR_KEY_TYPE_INCONSISTENT)?;
        let mut sig = vec![0u8; kp.public_modulus_len()];
        kp.sign(alg, &SystemRandom::new(), msg, &mut sig).map_err(|_| CKR_FUNCTION_FAILED)?;
        Ok(sig)
    })())
}

// ── RSA verify ─────────────────────────────────────────────────────────────

fn rsa_verify_alg(mech: u32, _pss_salt_len: Option<usize>) -> Option<&'static signature::RsaParameters> {
    match mech {
        CKM_SHA256_RSA_PKCS => Some(&signature::RSA_PKCS1_2048_8192_SHA256),
        CKM_SHA384_RSA_PKCS => Some(&signature::RSA_PKCS1_2048_8192_SHA384),
        CKM_SHA512_RSA_PKCS => Some(&signature::RSA_PKCS1_2048_8192_SHA512),
        // RSA-PSS verify stays pure-Rust (salt-agnostic); see rsa_sign_alg.
        _ => None,
    }
}

/// `verify_rsa`'s fast path over the raw public components `(n, e)` the
/// engine stores as `CKA_MODULUS` / `CKA_PUBLIC_EXPONENT`.
pub fn rsa_verify(mech: u32, n: &[u8], e: &[u8], msg: &[u8], sig: &[u8], pss_salt_len: Option<usize>) -> Option<Result<bool, CkRv>> {
    let alg = rsa_verify_alg(mech, pss_salt_len)?;
    // Leading zero bytes on `n` are not a smaller key; strip before the size check.
    let n_len = n.iter().position(|&b| b != 0).map_or(0, |i| n.len() - i);
    if n_len < MIN_MODULUS_BYTES {
        return None;
    }
    let pk = signature::RsaPublicKeyComponents { n, e };
    Some(Ok(pk.verify(alg, msg, sig).is_ok()))
}

// ── RSA key generation ─────────────────────────────────────────────────────

/// `generate_rsa_keypair`'s fast path. Returns `(pkcs8_der, n, e)` in the
/// same shapes the pure-Rust path produces, so the attribute-building code
/// after it is shared. Only the three sizes AWS-LC generates are handled.
pub fn rsa_generate(bits: u32) -> Option<Result<RsaKeyParts, CkRv>> {
    let size = match bits {
        2048 => rsa::KeySize::Rsa2048,
        3072 => rsa::KeySize::Rsa3072,
        4096 => rsa::KeySize::Rsa4096,
        _ => return None,
    };
    Some((|| {
        let kp = rsa::KeyPair::generate(size).map_err(|_| CKR_FUNCTION_FAILED)?;
        let pkcs8 = AsDer::<Pkcs8V1Der>::as_der(&kp).map_err(|_| CKR_FUNCTION_FAILED)?;
        let comps = rsa::PublicKeyComponents::<Vec<u8>>::from(kp.public_key());
        Ok((pkcs8.as_ref().to_vec(), comps.n, comps.e))
    })())
}

// ── RSA OAEP / PKCS#1 v1.5 encryption ──────────────────────────────────────

/// Which of AWS-LC's OAEP algorithms matches `(hash, mgf1_hash)` — only the
/// matched pairs exist there, so a mismatched pair returns `None`.
fn oaep_alg(hash: u32, mgf_hash: u32) -> Option<&'static rsa::OaepAlgorithm> {
    match (hash, mgf_hash) {
        (CKM_SHA_1, CKG_MGF1_SHA1) => Some(&rsa::OAEP_SHA1_MGF1SHA1),
        (CKM_SHA256, CKG_MGF1_SHA256) => Some(&rsa::OAEP_SHA256_MGF1SHA256),
        (CKM_SHA384, CKG_MGF1_SHA384) => Some(&rsa::OAEP_SHA384_MGF1SHA384),
        (CKM_SHA512, CKG_MGF1_SHA512) => Some(&rsa::OAEP_SHA512_MGF1SHA512),
        _ => None,
    }
}

/// OAEP encrypt with an X.509 SPKI public key. PKCS#1 `RSAPublicKey` DER
/// (the other format the engine accepts) is not parsed by AWS-LC's SPKI
/// constructor, so it returns `None` and takes the pure-Rust path.
pub fn rsa_oaep_encrypt(spki: &[u8], hash: u32, mgf_hash: u32, label: Option<&[u8]>, plaintext: &[u8]) -> Option<Result<Vec<u8>, CkRv>> {
    let alg = oaep_alg(hash, mgf_hash)?;
    let pk = rsa::PublicEncryptingKey::from_der(spki).ok()?;
    let pk = rsa::OaepPublicEncryptingKey::new(pk).ok()?;
    Some((|| {
        let mut out = vec![0u8; pk.ciphertext_size()];
        let n = pk.encrypt(alg, plaintext, &mut out, label).map_err(|_| CKR_FUNCTION_FAILED)?.len();
        out.truncate(n);
        Ok(out)
    })())
}

/// OAEP decrypt with a PKCS#8 private key. PKCS#1 `RSAPrivateKey` DER input
/// returns `None` for the same reason as above.
pub fn rsa_oaep_decrypt(sk_pkcs8: &[u8], hash: u32, mgf_hash: u32, label: Option<&[u8]>, ciphertext: &[u8]) -> Option<Result<Vec<u8>, CkRv>> {
    let alg = oaep_alg(hash, mgf_hash)?;
    // Cached parse (see `crypto::awslc_keycache`). `None` still means "not
    // handled here", so a PKCS#1 `RSAPrivateKey` DER falls through to the
    // pure-Rust path exactly as before.
    let sk = crate::crypto::awslc_keycache::oaep(sk_pkcs8)?;
    Some((|| {
        let mut out = vec![0u8; sk.min_output_size()];
        // PKCS#11 v3.2 §6.13 — an OAEP decode failure is
        // CKR_ENCRYPTED_DATA_INVALID, matching the pure-Rust branch.
        let n = sk.decrypt(alg, ciphertext, &mut out, label).map_err(|_| CKR_ENCRYPTED_DATA_INVALID)?.len();
        out.truncate(n);
        Ok(out)
    })())
}

/// PKCS#1 v1.5 encrypt (`CKM_RSA_PKCS`) with an X.509 SPKI public key.
pub fn rsa_pkcs1_encrypt(spki: &[u8], plaintext: &[u8]) -> Option<Result<Vec<u8>, CkRv>> {
    let pk = rsa::PublicEncryptingKey::from_der(spki).ok()?;
    let pk = rsa::Pkcs1PublicEncryptingKey::new(pk).ok()?;
    Some((|| {
        let mut out = vec![0u8; pk.ciphertext_size()];
        let n = pk.encrypt(plaintext, &mut out).map_err(|_| CKR_FUNCTION_FAILED)?.len();
        out.truncate(n);
        Ok(out)
    })())
}

/// PKCS#1 v1.5 encrypt (`CKM_RSA_PKCS`) from the raw public components
/// `(n, e)` — the shape the engine stores packed as `[n_len][n][e]` and the
/// two public-key encrypt sites (C_Encrypt, C_WrapKey) hand in. Public-key
/// only: no timing-oracle concern, routed for backend uniformity and speed.
pub fn rsa_pkcs1_encrypt_components(n: &[u8], e: &[u8], plaintext: &[u8]) -> Option<Result<Vec<u8>, CkRv>> {
    // Strip leading zeros: AWS-LC wants components "without leading zeros".
    let n = &n[n.iter().position(|&b| b != 0).unwrap_or(n.len())..];
    let e = &e[e.iter().position(|&b| b != 0).unwrap_or(e.len())..];
    if n.len() < MIN_MODULUS_BYTES {
        return None;
    }
    let pk: rsa::PublicEncryptingKey =
        rsa::PublicKeyComponents { n, e }.try_into().ok()?;
    let pk = rsa::Pkcs1PublicEncryptingKey::new(pk).ok()?;
    Some((|| {
        let mut out = vec![0u8; pk.ciphertext_size()];
        let n = pk.encrypt(plaintext, &mut out).map_err(|_| CKR_FUNCTION_FAILED)?.len();
        out.truncate(n);
        Ok(out)
    })())
}

/// PKCS#1 v1.5 decrypt (`CKM_RSA_PKCS`) with a PKCS#8 private key.
///
/// **This is the Marvin-attack surface.** RUSTSEC-2023-0071 is specifically
/// the `rsa` crate's PKCS#1 v1.5 decryption leaking key material through
/// timing; AWS-LC implements this operation in constant time, which is the
/// point of routing it here rather than merely the speed.
pub fn rsa_pkcs1_decrypt(sk_pkcs8: &[u8], ciphertext: &[u8]) -> Option<Result<Vec<u8>, CkRv>> {
    // Cached parse (see `crypto::awslc_keycache`); `None` falls through to
    // the pure-Rust path as before.
    let sk = crate::crypto::awslc_keycache::pkcs1(sk_pkcs8)?;
    Some((|| {
        let mut out = vec![0u8; sk.min_output_size()];
        let n = sk.decrypt(ciphertext, &mut out).map_err(|_| CKR_ENCRYPTED_DATA_INVALID)?.len();
        out.truncate(n);
        Ok(out)
    })())
}

// ── ECDH ───────────────────────────────────────────────────────────────────

fn ecdh_alg(curve: u32) -> Option<&'static agreement::Algorithm> {
    match curve {
        CURVE_P256 | 0 => Some(&agreement::ECDH_P256),
        CURVE_P384 => Some(&agreement::ECDH_P384),
        CURVE_P521 => Some(&agreement::ECDH_P521),
        _ => None,
    }
}

/// ECDH over a NIST curve: raw scalar in, uncompressed peer point in, the
/// x-coordinate shared secret out — the same bytes `p256::ecdh::diffie_hellman`
/// yields, so KDF code downstream is unchanged.
pub fn ecdh(curve: u32, sk: &[u8], peer_uncompressed: &[u8]) -> Option<Result<Vec<u8>, CkRv>> {
    let alg = ecdh_alg(curve)?;
    if peer_uncompressed.first() != Some(&0x04) {
        return None;
    }
    Some((|| {
        let sk = agreement::PrivateKey::from_private_key(alg, sk).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
        let peer = agreement::UnparsedPublicKey::new(alg, peer_uncompressed);
        agreement::agree(&sk, peer, CKR_FUNCTION_FAILED, |shared| Ok(shared.to_vec()))
    })())
}
