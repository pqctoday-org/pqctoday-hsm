//! Sign / Verify — typed dispatcher over `crypto::handlers::sign_*` and
//! `crypto::handlers::verify_*` (which already accept typed args).
//!
//! Resolves the key handle to its stored bytes via `state::*`, dispatches
//! on `mechanism` based on the engine's existing per-family logic, calls
//! the right typed primitive. Returns the signature as `Vec<u8>` (no
//! caller-allocated output buffer).
//!
//! Mirrors the dispatch logic in `ffi::C_Sign` / `ffi::C_Verify`, minus
//! the wasm32 pointer marshalling. Stateful HSS sign/verify IS
//! implemented here (leaf-index advancement + tamper detection covered
//! by this module's own tests); XMSS/XMSS-MT sign/verify is not — an
//! XMSS key handle correctly falls through to `CKR_MECHANISM_INVALID`
//! rather than mis-signing.
//!
//! See [`super`] for the typed-vs-FFI architectural relationship.

use super::CkRv;
use crate::constants::*;
use crate::crypto::handlers::{
    is_prehash_ml_dsa, is_prehash_slh_dsa, sign_ecdsa, sign_eddsa, sign_eddsa_ctx, sign_eddsa_ph,
    sign_hmac, sign_kmac, sign_ml_dsa, sign_ml_dsa_external_mu, sign_ml_dsa_external_rnd,
    sign_ml_dsa_internal, sign_rsa, sign_slh_dsa, sign_slh_dsa_external_rnd,
    sign_slh_dsa_internal, verify_ecdsa, verify_eddsa, verify_eddsa_ctx, verify_eddsa_ph,
    verify_hmac, verify_ml_dsa, verify_ml_dsa_external_mu,
    verify_ml_dsa_internal, verify_rsa, verify_slh_dsa, verify_slh_dsa_internal,
};
use crate::state::{
    check_mechanism_allowed_from, get_ec_point_sec1_from, get_object_attr_u32_from,
    get_object_param_set_from, get_object_value_from, get_rsa_public_components_from,
    read_bool_attr, resolve_session_access, with_object_checked,
};

// PKCS#11 v3.2 §5.12.4 — `CKA_SIGN` (private key) / `CKA_VERIFY` (public key)
// must be true before sign / verify is permitted. Engine constants:
use crate::constants::{CKA_SIGN, CKA_VERIFY};

/// Sign `data` with the key at `key_handle` using `mechanism`. Dispatches
/// to `crypto::handlers::sign_{ml_dsa, slh_dsa, rsa, ecdsa, eddsa, hmac,
/// kmac}` based on `mechanism`.
///
/// **Pre-conditions**:
/// - `key_handle` must refer to a key with `CKA_SIGN = true`. For PQC
///   sig algorithms this is the **private** key from
///   [`super::keygen::generate_ml_dsa_keypair`] / `generate_slh_dsa_keypair`.
/// - `mechanism` must match the key's algorithm family
///   (`CKM_ML_DSA` for ML-DSA keys, `CKM_SLH_DSA` for SLH-DSA, etc.).
///
/// **Returns** the raw signature bytes — length is per FIPS spec
/// (e.g. ML-DSA-65: 3309, ML-DSA-87: 4627).
pub fn sign(
    session: u32,
    key_handle: u32,
    mechanism: u32,
    data: &[u8],
) -> Result<Vec<u8>, CkRv> {
    sign_with_pss_salt(session, key_handle, mechanism, data, None, None)
}

/// [`sign`] with an explicit RSA-PSS salt length (bytes) — the typed
/// equivalent of supplying `CK_RSA_PKCS_PSS_PARAMS.sLen` on the FFI
/// path. `None` keeps the PKCS#11 v3.2 §6.2 default (salt = hash
/// length). Ignored for non-PSS mechanisms. KMIP slice K18 threads the
/// `Cryptographic Parameters` `Salt Length` field through here.
///
/// `eddsa_ctx`: RFC 8032 context string for `CKM_EDDSA` (KMIP/CACP
/// coverage gap-analysis items 9a/9b, 2026-08-30) — threaded from
/// `CryptographicParameters.context_string`, the same field PQC signing
/// already uses. `None`/empty keeps ordinary EdDSA (Ed448's own default
/// is an empty, not absent, context — [`sign_eddsa`] already does this
/// correctly for that case). Ignored for every other mechanism.
pub fn sign_with_pss_salt(
    session: u32,
    key_handle: u32,
    mechanism: u32,
    data: &[u8],
    pss_salt_len: Option<usize>,
    eddsa_ctx: Option<&[u8]>,
) -> Result<Vec<u8>, CkRv> {
    // Isolation gate (rust-hsm-perf-bench-scenario-plan-07182026.md Part F)
    // + CKA_SIGN + CKA_ALLOWED_MECHANISMS + CKA_VALUE + CKA_PRIV_PARAM_SET,
    // ALL read from the SAME borrowed attrs — one OBJECTS lock instead of
    // the four separate locks this function used to take. `sk_bytes` is
    // `None` for HSS keys (their material lives in
    // `CKA_PRIV_STATEFUL_KEY_STATE`, not `CKA_VALUE`) — harmless, discarded on
    // the HSS branch below.
    let access = resolve_session_access(session)?;
    let (can_sign, mech_ok, sk_bytes, ps) = with_object_checked(&access, key_handle, |attrs| {
        (
            read_bool_attr(attrs, CKA_SIGN),
            check_mechanism_allowed_from(attrs, mechanism),
            get_object_value_from(attrs),
            get_object_param_set_from(attrs),
        )
    })?;
    if !can_sign {
        return Err(CKR_KEY_FUNCTION_NOT_PERMITTED);
    }
    mech_ok?;

    // HSS/LMS is stateful and keeps its key material in
    // `CKA_PRIV_STATEFUL_KEY_STATE`, not `CKA_VALUE` (mirrors `ffi::C_Sign`'s
    // separate stateful-sign branch) — dispatch it BEFORE the generic
    // `sk_bytes` use below, which would otherwise fail closed with
    // `CKR_ARGUMENTS_BAD` for every HSS key. The gate above already
    // covers HSS (CKA_SIGN + slot/login) — `hbs::sign_prepare`/
    // `sign_commit` are `pub(crate)` and deliberately ungated; this
    // function is their only caller and is where the gate must live.
    if mechanism == CKM_HSS {
        // Stateful — the two-phase prepare/commit in `native::hbs` is the
        // single source of truth for leaf advance-and-persist, shared
        // with `ffi::C_Sign`'s HSS path. No output buffer here (KMIP
        // callers get an owned `Vec<u8>`), so commit immediately after a
        // successful prepare.
        let prepared = super::hbs::sign_prepare(key_handle, data)?;
        super::hbs::sign_commit(key_handle, &prepared);
        return Ok(prepared.signature);
    }

    let sk_bytes = sk_bytes.ok_or(CKR_ARGUMENTS_BAD)?;

    match mechanism {
        m if m == CKM_ML_DSA || is_prehash_ml_dsa(m) => {
            // Native surface signs with empty context, hedged (the FIPS 204
            // defaults) — same convention as the SLH-DSA arm below.
            sign_ml_dsa(m, ps, &sk_bytes, data, &[], false)
        }
        m if m == CKM_SLH_DSA || is_prehash_slh_dsa(m) => {
            // v0.1: SLH-DSA signing uses empty context + non-deterministic
            // (random hedge). FIPS 205 §10. KMIP's Phase-5 Sign handler
            // doesn't expose a context param yet; if it ever does, this
            // signature can grow optional args.
            sign_slh_dsa(m, ps, &sk_bytes, data, &[], false)
        }
        CKM_SHA256_HMAC | CKM_SHA384_HMAC | CKM_SHA512_HMAC | CKM_SHA512_224_HMAC
        | CKM_SHA512_256_HMAC | CKM_SHA3_224_HMAC | CKM_SHA3_256_HMAC
        | CKM_SHA3_384_HMAC | CKM_SHA3_512_HMAC => sign_hmac(mechanism, &sk_bytes, data),
        CKM_KMAC_128 | CKM_KMAC_256 => sign_kmac(mechanism, &sk_bytes, data),
        CKM_SHA256_RSA_PKCS | CKM_SHA384_RSA_PKCS | CKM_SHA512_RSA_PKCS
        | CKM_SHA256_RSA_PKCS_PSS | CKM_SHA384_RSA_PKCS_PSS | CKM_SHA512_RSA_PKCS_PSS => {
            sign_rsa(mechanism, &sk_bytes, data, pss_salt_len)
        }
        CKM_ECDSA | CKM_ECDSA_SHA256 | CKM_ECDSA_SHA384 | CKM_ECDSA_SHA512
        | CKM_ECDSA_SHA3_224 | CKM_ECDSA_SHA3_256 | CKM_ECDSA_SHA3_384
        | CKM_ECDSA_SHA3_512 => sign_ecdsa(mechanism, ps, &sk_bytes, data),
        CKM_EDDSA => match eddsa_ctx {
            Some(ctx) if !ctx.is_empty() => sign_eddsa_ctx(&sk_bytes, data, ctx),
            _ => sign_eddsa(&sk_bytes, data),
        },
        CKM_EDDSA_PH => sign_eddsa_ph(&sk_bytes, data),
        _ => Err(CKR_MECHANISM_INVALID),
    }
}

/// Verify `signature` over `data` with the key at `key_handle` using
/// `mechanism`.
///
/// **Returns**:
/// - `Ok(true)` — signature is valid.
/// - `Ok(false)` — signature is invalid (matches KMIP's
///   `validity_indicator` model — a failed verification is NOT a
///   protocol error).
/// - `Err(_)` — protocol-level failure (wrong key type, bad mechanism,
///   missing key material, …).
pub fn verify(
    session: u32,
    key_handle: u32,
    mechanism: u32,
    data: &[u8],
    signature: &[u8],
) -> Result<bool, CkRv> {
    verify_with_pss_salt(session, key_handle, mechanism, data, signature, None, None)
}

/// [`verify`] with an explicit RSA-PSS salt length (bytes). `Some(n)`
/// pins EMSA-PSS-VERIFY to exactly that salt (RFC 8017 §9.1.2 — the
/// caller's parameters are authoritative); `None` keeps the historical
/// two-candidate acceptance (salt = hash length, salt = maximal — see
/// `crypto::handlers::verify_rsa`). Ignored for non-PSS mechanisms.
///
/// `eddsa_ctx`: see [`sign_with_pss_salt`]'s doc comment — same field,
/// verify direction.
pub fn verify_with_pss_salt(
    session: u32,
    key_handle: u32,
    mechanism: u32,
    data: &[u8],
    signature: &[u8],
    pss_salt_len: Option<usize>,
    eddsa_ctx: Option<&[u8]>,
) -> Result<bool, CkRv> {
    // Isolation gate + CKA_VERIFY + CKA_ALLOWED_MECHANISMS + every
    // key-material shape a verify mechanism might need, ALL read from one
    // borrowed attrs — one OBJECTS lock. `CKA_VALUE` holds the
    // verification key bytes for most algorithms (ML-DSA, SLH-DSA, EdDSA,
    // HMAC, KMAC, HSS); RSA/ECDSA public keys additionally need the
    // dedicated modulus+exponent / EC-point attributes, fetched
    // unconditionally here (cheap absent-key lookups) rather than
    // re-locking per mechanism branch below.
    let access = resolve_session_access(session)?;
    let (can_verify, mech_ok, pk_bytes, ps, ec_point, rsa_components, lms_param) =
        with_object_checked(&access, key_handle, |attrs| {
            (
                read_bool_attr(attrs, CKA_VERIFY),
                check_mechanism_allowed_from(attrs, mechanism),
                get_object_value_from(attrs).unwrap_or_default(),
                get_object_param_set_from(attrs),
                get_ec_point_sec1_from(attrs),
                get_rsa_public_components_from(attrs),
                get_object_attr_u32_from(attrs, CKA_LMS_PARAM_SET).unwrap_or(0x05),
            )
        })?;
    if !can_verify {
        return Err(CKR_KEY_FUNCTION_NOT_PERMITTED);
    }
    mech_ok?;

    let result: Result<(), CkRv> = match mechanism {
        m if m == CKM_ML_DSA || is_prehash_ml_dsa(m) => {
            verify_ml_dsa(m, ps, &pk_bytes, data, signature, &[])
        }
        m if m == CKM_SLH_DSA || is_prehash_slh_dsa(m) => {
            verify_slh_dsa(m, ps, &pk_bytes, data, signature, &[])
        }
        CKM_SHA256_HMAC | CKM_SHA384_HMAC | CKM_SHA512_HMAC | CKM_SHA512_224_HMAC
        | CKM_SHA512_256_HMAC | CKM_SHA3_224_HMAC | CKM_SHA3_256_HMAC
        | CKM_SHA3_384_HMAC | CKM_SHA3_512_HMAC => verify_hmac(mechanism, &pk_bytes, data, signature),
        CKM_KMAC_128 | CKM_KMAC_256 => {
            // KMAC verify is constant-time signature comparison against a
            // fresh MAC, mirroring `ffi::C_Verify` behaviour.
            match sign_kmac(mechanism, &pk_bytes, data) {
                Ok(mac) => {
                    use subtle::ConstantTimeEq;
                    if mac.len() == signature.len() && mac.ct_eq(signature).into() {
                        Ok(())
                    } else {
                        Err(CKR_SIGNATURE_INVALID)
                    }
                }
                Err(e) => Err(e),
            }
        }
        CKM_SHA256_RSA_PKCS | CKM_SHA384_RSA_PKCS | CKM_SHA512_RSA_PKCS
        | CKM_SHA256_RSA_PKCS_PSS | CKM_SHA384_RSA_PKCS_PSS | CKM_SHA512_RSA_PKCS_PSS => {
            match rsa_components {
                Some((n, e)) => verify_rsa(mechanism, &n, &e, data, signature, pss_salt_len),
                None => Err(CKR_KEY_TYPE_INCONSISTENT),
            }
        }
        CKM_ECDSA | CKM_ECDSA_SHA256 | CKM_ECDSA_SHA384 | CKM_ECDSA_SHA512
        | CKM_ECDSA_SHA3_224 | CKM_ECDSA_SHA3_256 | CKM_ECDSA_SHA3_384
        | CKM_ECDSA_SHA3_512 => match ec_point {
            Some(point) => verify_ecdsa(mechanism, ps, &point, data, signature),
            None => Err(CKR_KEY_TYPE_INCONSISTENT),
        },
        CKM_EDDSA => match eddsa_ctx {
            Some(ctx) if !ctx.is_empty() => verify_eddsa_ctx(&pk_bytes, data, signature, ctx),
            _ => verify_eddsa(&pk_bytes, data, signature),
        },
        CKM_EDDSA_PH => verify_eddsa_ph(&pk_bytes, data, signature),
        CKM_HSS => {
            // Stateless — RFC 8554 verification needs no key-object
            // mutation, unlike sign's leaf advance-and-persist.
            if crate::crypto::lms::hss_verify(&pk_bytes, data, signature, lms_param) {
                Ok(())
            } else {
                Err(CKR_SIGNATURE_INVALID)
            }
        }
        _ => Err(CKR_MECHANISM_INVALID),
    };

    match result {
        Ok(()) => Ok(true),
        // CKR_SIGNATURE_INVALID is the "valid call, signature didn't
        // verify" outcome — surface as Ok(false), matching the KMIP
        // ValidityIndicator model.
        Err(CKR_SIGNATURE_INVALID) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Check `CKA_SIGN` (for sign) or `CKA_VERIFY` (for verify) on the key.
/// Returns `false` if the key is missing or the flag is not set.
/// PQC sign with the full KMIP 3.0 WD19 / ACVP interface knobs:
/// `internal` selects `*.Sign_internal` (no domain framing), `external_mu`
/// treats `data` as the 64-byte message representative µ, `deterministic`
/// picks the deterministic randomizer, and `random` supplies the explicit
/// hedge randomizer (ML-DSA rnd / SLH-DSA addrnd) when not deterministic.
#[allow(clippy::too_many_arguments)]
pub fn sign_pqc(
    session: u32,
    key_handle: u32,
    mechanism: u32,
    data: &[u8],
    ctx: &[u8],
    deterministic: bool,
    internal: bool,
    external_mu: bool,
    random: Option<&[u8]>,
) -> Result<Vec<u8>, CkRv> {
    let access = resolve_session_access(session)?;
    let (can_sign, mech_ok, sk, ps) = with_object_checked(&access, key_handle, |attrs| {
        (
            read_bool_attr(attrs, CKA_SIGN),
            check_mechanism_allowed_from(attrs, mechanism),
            get_object_value_from(attrs),
            get_object_param_set_from(attrs),
        )
    })?;
    if !can_sign {
        return Err(CKR_KEY_FUNCTION_NOT_PERMITTED);
    }
    mech_ok?;
    let sk = sk.ok_or(CKR_ARGUMENTS_BAD)?;
    use rand::RngCore;
    match mechanism {
        m if m == CKM_ML_DSA || is_prehash_ml_dsa(m) => {
            // rnd: deterministic ⇒ 0^32; hedged ⇒ explicit <Random> (must be
            // 32 bytes) or, when absent, drawn from the OS RNG (normal hedge).
            let rnd: [u8; 32] = if deterministic {
                [0u8; 32]
            } else if let Some(r) = random {
                r.try_into().map_err(|_| CKR_ARGUMENTS_BAD)?
            } else {
                let mut b = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut b);
                b
            };
            if external_mu {
                sign_ml_dsa_external_mu(ps, &sk, data, rnd)
            } else if internal {
                sign_ml_dsa_internal(ps, &sk, data, ctx, rnd)
            } else {
                sign_ml_dsa_external_rnd(ps, &sk, data, ctx, rnd)
            }
        }
        m if m == CKM_SLH_DSA || is_prehash_slh_dsa(m) => {
            // addrnd: deterministic ⇒ None (PK.seed); hedged ⇒ explicit
            // <Random> or, when absent, n OS-random bytes (normal hedge).
            let addrnd_buf: Option<Vec<u8>> = if deterministic {
                None
            } else if let Some(r) = random {
                Some(r.to_vec())
            } else {
                let mut b = vec![0u8; slh_dsa_n(ps)];
                rand::rngs::OsRng.fill_bytes(&mut b);
                Some(b)
            };
            let addrnd = addrnd_buf.as_deref();
            if internal {
                sign_slh_dsa_internal(ps, &sk, data, addrnd)
            } else {
                sign_slh_dsa_external_rnd(ps, &sk, data, ctx, addrnd)
            }
        }
        _ => Err(CKR_MECHANISM_INVALID),
    }
}

/// SLH-DSA security parameter `n` (addrnd / hash length, bytes) per parameter
/// set — 16/24/32 for the 128/192/256 levels (FIPS 205 Table 2).
fn slh_dsa_n(ps: u32) -> usize {
    match ps {
        CKP_SLH_DSA_SHA2_128S | CKP_SLH_DSA_SHA2_128F | CKP_SLH_DSA_SHAKE_128S
        | CKP_SLH_DSA_SHAKE_128F => 16,
        CKP_SLH_DSA_SHA2_192S | CKP_SLH_DSA_SHA2_192F | CKP_SLH_DSA_SHAKE_192S
        | CKP_SLH_DSA_SHAKE_192F => 24,
        _ => 32,
    }
}

/// PQC verify counterpart to [`sign_pqc`]. `external_mu` ⇒ `data` is the
/// 64-byte µ; `internal` ⇒ `*.Verify_internal`.
#[allow(clippy::too_many_arguments)]
pub fn verify_pqc(
    session: u32,
    key_handle: u32,
    mechanism: u32,
    data: &[u8],
    signature: &[u8],
    ctx: &[u8],
    internal: bool,
    external_mu: bool,
) -> Result<(), CkRv> {
    let access = resolve_session_access(session)?;
    let (can_verify, mech_ok, pk, ps) = with_object_checked(&access, key_handle, |attrs| {
        (
            read_bool_attr(attrs, CKA_VERIFY),
            check_mechanism_allowed_from(attrs, mechanism),
            get_object_value_from(attrs),
            get_object_param_set_from(attrs),
        )
    })?;
    if !can_verify {
        return Err(CKR_KEY_FUNCTION_NOT_PERMITTED);
    }
    mech_ok?;
    let pk = pk.ok_or(CKR_ARGUMENTS_BAD)?;
    match mechanism {
        m if m == CKM_ML_DSA || is_prehash_ml_dsa(m) => {
            if external_mu {
                verify_ml_dsa_external_mu(ps, &pk, data, signature)
            } else if internal {
                verify_ml_dsa_internal(ps, &pk, data, signature, ctx)
            } else {
                verify_ml_dsa(m, ps, &pk, data, signature, ctx)
            }
        }
        m if m == CKM_SLH_DSA || is_prehash_slh_dsa(m) => {
            if internal {
                verify_slh_dsa_internal(ps, &pk, data, signature)
            } else {
                verify_slh_dsa(m, ps, &pk, data, signature, ctx)
            }
        }
        _ => Err(CKR_MECHANISM_INVALID),
    }
}

// The former `check_can_sign(key_handle, attr_type)` free function (a
// direct, ungated OBJECTS lock) is gone — CKA_SIGN/CKA_VERIFY are now
// read via `read_bool_attr` inside the isolation gate's single borrow
// (`with_object_checked` above), the same predicate `can_access_object`
// already uses for CKA_PRIVATE.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::keygen::{generate_ml_dsa_keypair, generate_ml_kem_keypair};
    use crate::native::session::{bootstrap_default_token, close_session, finalize, init};
    use crate::native::test_lock;

    fn fresh_session() -> u32 {
        let _ = finalize();
        init().unwrap();
        bootstrap_default_token(0, "so", "user", "native-sign-test").unwrap()
    }

    /// ML-DSA-65 round-trip: keygen → sign → verify(correct) → Ok(true).
    /// FIPS 204 §5 — ML-DSA-65 signature is 3309 bytes.
    #[test]
    fn ml_dsa_65_sign_then_verify_returns_valid() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, prv_h) =
            generate_ml_dsa_keypair(session, CKP_ML_DSA_65, b"\x01\x02", "sig-key").unwrap();

        let message = b"the quick brown fox jumps over the lazy dog";
        let sig = sign(session, prv_h, CKM_ML_DSA, message).expect("sign must succeed");
        assert_eq!(sig.len(), 3309, "FIPS 204 §5 ML-DSA-65 signature = 3309 bytes");

        let valid = verify(session, pub_h, CKM_ML_DSA, message, &sig).expect("verify must succeed");
        assert!(valid, "freshly-signed message must verify");

        close_session(session).unwrap();
    }

    /// ML-DSA-87: signature = 4627 bytes (FIPS 204 §5).
    #[test]
    fn ml_dsa_87_sign_then_verify_returns_valid() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, prv_h) =
            generate_ml_dsa_keypair(session, CKP_ML_DSA_87, b"\x03", "sig-87").unwrap();
        let sig = sign(session, prv_h, CKM_ML_DSA, b"hello").unwrap();
        assert_eq!(sig.len(), 4627);
        assert!(verify(session, pub_h, CKM_ML_DSA, b"hello", &sig).unwrap());
        close_session(session).unwrap();
    }

    /// Tampered signature → Ok(false), NOT Err. Matches KMIP
    /// `ValidityIndicator::Invalid` semantics.
    #[test]
    fn tampered_signature_returns_ok_false_not_err() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, prv_h) =
            generate_ml_dsa_keypair(session, CKP_ML_DSA_65, b"\x01", "tamper").unwrap();
        let mut sig = sign(session, prv_h, CKM_ML_DSA, b"data").unwrap();
        // Flip a byte in the middle of the signature.
        let mid = sig.len() / 2;
        sig[mid] ^= 0xFF;
        let result = verify(session, pub_h, CKM_ML_DSA, b"data", &sig);
        assert_eq!(result, Ok(false), "tampered sig is Ok(false), not Err");
        close_session(session).unwrap();
    }

    /// Signing with the public-key handle (CKA_SIGN = false) →
    /// CKR_KEY_FUNCTION_NOT_PERMITTED.
    #[test]
    fn sign_with_public_key_handle_is_denied() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, _prv_h) =
            generate_ml_dsa_keypair(session, CKP_ML_DSA_65, b"\x01", "denied").unwrap();
        let result = sign(session, pub_h, CKM_ML_DSA, b"data");
        assert_eq!(result, Err(CKR_KEY_FUNCTION_NOT_PERMITTED));
        close_session(session).unwrap();
    }

    /// Verifying with the private-key handle (CKA_VERIFY = false) →
    /// CKR_KEY_FUNCTION_NOT_PERMITTED.
    #[test]
    fn verify_with_private_key_handle_is_denied() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (_pub_h, prv_h) =
            generate_ml_dsa_keypair(session, CKP_ML_DSA_65, b"\x01", "denied").unwrap();
        let result = verify(session, prv_h, CKM_ML_DSA, b"data", b"\x00" .repeat(3309).as_slice());
        assert_eq!(result, Err(CKR_KEY_FUNCTION_NOT_PERMITTED));
        close_session(session).unwrap();
    }

    /// Unknown mechanism → CKR_MECHANISM_INVALID.
    #[test]
    fn unknown_mechanism_returns_err() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (_pub_h, prv_h) =
            generate_ml_dsa_keypair(session, CKP_ML_DSA_65, b"\x01", "unknown-mech").unwrap();
        let result = sign(session, prv_h, 0xDEAD_BEEF, b"data");
        assert_eq!(result, Err(CKR_MECHANISM_INVALID));
        close_session(session).unwrap();
    }

    /// Sign with an ML-KEM key (CKA_SIGN=false) → denied. Cross-family
    /// check that the permission gate works.
    #[test]
    fn ml_kem_key_cannot_be_used_for_signing() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (_pub_h, prv_h) =
            generate_ml_kem_keypair(session, CKP_ML_KEM_768, b"\x01", "kem-not-sig").unwrap();
        let result = sign(session, prv_h, CKM_ML_DSA, b"data");
        assert_eq!(result, Err(CKR_KEY_FUNCTION_NOT_PERMITTED));
        close_session(session).unwrap();
    }

    /// S6 — RSA SHA-384/512 PKCS#1 v1.5 + PSS through the native dispatch:
    /// one RSA-2048 keypair, sign/verify round-trip per mechanism, tampered
    /// signature → Ok(false), cross-hash verify → Ok(false).
    #[test]
    fn s6_rsa_hash_variant_mechs_round_trip_via_native_dispatch() {
        use crate::native::keygen::generate_rsa_keypair;
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, prv_h) = generate_rsa_keypair(session, 2048, b"\x01", "s6-rsa").unwrap();

        let msg = b"S6 native dispatch round-trip";
        let mechs = [
            CKM_SHA384_RSA_PKCS,
            CKM_SHA512_RSA_PKCS,
            CKM_SHA384_RSA_PKCS_PSS,
            CKM_SHA512_RSA_PKCS_PSS,
        ];
        for mech in mechs {
            let sig = sign(session, prv_h, mech, msg).expect("sign must succeed");
            assert_eq!(sig.len(), 256, "RSA-2048 signature is 256 bytes ({mech:#06x})");
            assert_eq!(
                verify(session, pub_h, mech, msg, &sig),
                Ok(true),
                "round-trip must verify ({mech:#06x})"
            );
            let mut bad = sig.clone();
            bad[128] ^= 0xFF;
            assert_eq!(
                verify(session, pub_h, mech, msg, &bad),
                Ok(false),
                "tampered sig is Ok(false) ({mech:#06x})"
            );
        }

        // Cross-mechanism: SHA-384 signature must not verify as SHA-512.
        let sig384 = sign(session, prv_h, CKM_SHA384_RSA_PKCS, msg).unwrap();
        assert_eq!(verify(session, pub_h, CKM_SHA512_RSA_PKCS, msg, &sig384), Ok(false));
        let pss384 = sign(session, prv_h, CKM_SHA384_RSA_PKCS_PSS, msg).unwrap();
        assert_eq!(verify(session, pub_h, CKM_SHA512_RSA_PKCS_PSS, msg, &pss384), Ok(false));

        close_session(session).unwrap();
    }

    /// Empty message — ML-DSA is well-defined for any message length
    /// per FIPS 204. Signature still 3309 bytes.
    #[test]
    fn ml_dsa_65_sign_empty_message() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, prv_h) =
            generate_ml_dsa_keypair(session, CKP_ML_DSA_65, b"\x01", "empty-msg").unwrap();
        let sig = sign(session, prv_h, CKM_ML_DSA, b"").unwrap();
        assert_eq!(sig.len(), 3309);
        assert!(verify(session, pub_h, CKM_ML_DSA, b"", &sig).unwrap());
        close_session(session).unwrap();
    }

    // ── HSS/LMS (RFC 8554) — native::sign was missing this arm entirely
    // before this change (ffi::C_Sign already had it); these tests prove
    // the native path now works, and that it genuinely advances +
    // persists the leaf index rather than reusing one. ──────────────────

    fn register_fresh_hss_keypair(session: u32, label: &str) -> (u32, u32) {
        use crate::native::keygen::{register_hss_private_key, register_hss_public_key};
        let (pub_bytes, priv_bytes) =
            crate::crypto::lms::hss_keygen(1, &[CKP_LMS_SHA256_M32_H5], &[CKP_LMOTS_SHA256_N32_W4])
                .expect("hss_keygen must succeed");
        let pub_h = register_hss_public_key(session, &pub_bytes, b"\x01", label).unwrap();
        let prv_h = register_hss_private_key(session, &priv_bytes, b"\x01", label).unwrap();
        (pub_h, prv_h)
    }

    #[test]
    fn hss_sign_then_verify_returns_valid() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, prv_h) = register_fresh_hss_keypair(session, "hss-basic");

        let message = b"the quick brown fox jumps over the lazy dog";
        let sig = sign(session, prv_h, CKM_HSS, message).expect("HSS sign must succeed");
        let valid = verify(session, pub_h, CKM_HSS, message, &sig).expect("verify must succeed");
        assert!(valid, "freshly-signed HSS message must verify");

        close_session(session).unwrap();
    }

    /// The core one-time-signature safety property: two sequential signs
    /// on the same key MUST consume two distinct leaves — a real signal
    /// that `native::hbs::sign_commit` actually persisted the advanced
    /// state, not just computed a signature and discarded it.
    #[test]
    fn hss_second_sign_uses_a_new_leaf_and_persists_the_counter() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, prv_h) = register_fresh_hss_keypair(session, "hss-leaf-advance");

        let leaf_index = || {
            crate::state::get_object_attr_u64(prv_h, CKA_PRIV_LEAF_INDEX).expect("leaf index must be set")
        };
        let keys_remaining = || {
            crate::state::get_object_attr_u32(prv_h, CKA_HSS_KEYS_REMAINING)
                .expect("keys remaining must be set")
        };

        let total = keys_remaining();
        assert_eq!(leaf_index(), 0, "fresh key starts at leaf 0");

        let sig1 = sign(session, prv_h, CKM_HSS, b"message one").unwrap();
        assert_eq!(leaf_index(), 1, "first sign advances to leaf 1");
        assert_eq!(keys_remaining(), total - 1);

        let sig2 = sign(session, prv_h, CKM_HSS, b"message two").unwrap();
        assert_eq!(leaf_index(), 2, "second sign advances to leaf 2");
        assert_eq!(keys_remaining(), total - 2);

        assert_ne!(sig1, sig2, "distinct leaves must produce distinct signatures");
        assert!(verify(session, pub_h, CKM_HSS, b"message one", &sig1).unwrap());
        assert!(verify(session, pub_h, CKM_HSS, b"message two", &sig2).unwrap());

        close_session(session).unwrap();
    }

    #[test]
    fn hss_verify_rejects_tampered_signature() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, prv_h) = register_fresh_hss_keypair(session, "hss-tamper");
        let mut sig = sign(session, prv_h, CKM_HSS, b"data").unwrap();
        let mid = sig.len() / 2;
        sig[mid] ^= 0xFF;
        let result = verify(session, pub_h, CKM_HSS, b"data", &sig);
        assert_eq!(result, Ok(false), "tampered HSS sig is Ok(false), not Err");
        close_session(session).unwrap();
    }

    #[test]
    fn hss_sign_with_public_key_handle_is_denied() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, _prv_h) = register_fresh_hss_keypair(session, "hss-wrong-handle");
        let result = sign(session, pub_h, CKM_HSS, b"data");
        assert_eq!(result, Err(CKR_KEY_FUNCTION_NOT_PERMITTED));
        close_session(session).unwrap();
    }

    /// Real exhaustion, not a mocked one: `CKP_LMS_SHA256_M32_H5` has
    /// exactly `2^5 = 32` leaves (RFC 8554 §5.3). Sign 32 times (every
    /// leaf), confirm each is genuinely usable, then confirm the 33rd
    /// sign fails clean with `CKR_KEY_EXHAUSTED` instead of panicking,
    /// corrupting state, or silently reusing a leaf.
    #[test]
    fn hss_key_signs_exactly_its_capacity_then_exhausts_cleanly() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, prv_h) = register_fresh_hss_keypair(session, "hss-exhaust");

        let total = crate::state::get_object_attr_u32(prv_h, CKA_HSS_KEYS_REMAINING).unwrap();
        assert_eq!(total, 32, "CKP_LMS_SHA256_M32_H5 = 2^5 leaves");

        for i in 0..total {
            let msg = format!("message {i}");
            let sig = sign(session, prv_h, CKM_HSS, msg.as_bytes())
                .unwrap_or_else(|e| panic!("sign #{i} of {total} must succeed, got {e:#x}"));
            assert!(
                verify(session, pub_h, CKM_HSS, msg.as_bytes(), &sig).unwrap(),
                "signature #{i} must verify"
            );
        }
        assert_eq!(
            crate::state::get_object_attr_u64(prv_h, CKA_PRIV_LEAF_INDEX).unwrap(),
            total as u64,
            "every leaf must have been consumed exactly once"
        );
        assert_eq!(
            crate::state::get_object_attr_u32(prv_h, CKA_HSS_KEYS_REMAINING).unwrap(),
            0
        );

        let result = sign(session, prv_h, CKM_HSS, b"one too many");
        assert_eq!(result, Err(CKR_KEY_EXHAUSTED), "the 33rd sign must fail, not reuse a leaf");

        close_session(session).unwrap();
    }
}
