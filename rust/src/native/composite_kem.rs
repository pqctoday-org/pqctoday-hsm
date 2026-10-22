// SPDX-License-Identifier: AGPL-3.0-only
//
//! Composite ML-KEM — `CKM_COMP_KEM`, PKCS#11 v3.3 working draft
//! (`working/doc/spec/comp_kem.md`, OASIS PKCS 11 TC commit 9ef73f9), over
//! draft-ietf-lamps-pq-composite-kem-23 §3.2 (Encaps), §3.3 (Decaps) and
//! §3.4 (KEM combiner). The engine still reports Cryptoki 3.2.0.
//!
//! Not the TLS hybrid groups of `native::hybrid` (plain concatenation, two
//! handles): a composite key is one object, and its shared secret is
//!
//! ```text
//! ss = SHA3-256(mlkemSS ‖ tradSS ‖ tradCT ‖ tradPK ‖ Label)      (§3.4)
//! ```
//!
//! with `Label` the set's combiner label (`native::composite`), `tradCT` the
//! traditional ciphertext and `tradPK` the traditional public key in the §4
//! encodings: DER `RSAPublicKey` for RSA, the uncompressed point for ECDH,
//! the raw RFC 7748 key for X25519 / X448. The combiner runs on handles
//! through the engine's derive machinery (`derive::run_combiner`:
//! `CKM_CONCATENATE_BASE_AND_KEY`, `CKM_CONCATENATE_BASE_AND_DATA`,
//! `CKM_SHA3_256_KEY_DERIVATION`), whose intermediate objects are destroyed
//! (and their values zeroised) before it returns. The component secrets and
//! the ML-KEM `dk` live in `Zeroizing` buffers here; only the final 32-byte
//! secret leaves this module, and the FFI layer stores it as a key object.
//!
//! Traditional KEMs (§2): RSA-OAEP promoted to a KEM by encrypting a random
//! 32-byte secret (§2.1) with the §6.1 Table 2 parameters (SHA-256,
//! MGF1-SHA-256, empty label, ss_len 256 bits); ECDH / X25519 / X448 as the
//! simplified DHKEM of §2.2 (ciphertext = ephemeral public key, secret = Z /
//! K).

use zeroize::Zeroizing;

use super::composite::{CompositeKemParams, CompositeParams, COMPOSITE_KEM_SS_LEN};
use super::composite_key::{trad_public_from_private, Layout, TradKey};
use super::derive::{run_combiner, Combiner, FinalizeStep};
use super::encrypt::{rsa_oaep_decrypt, rsa_oaep_encrypt, OaepHash, OaepParams};
use super::CkRv;
use crate::constants::*;

/// composite-kem-23 §6.1 Table 2: id-sha256, MGF1 with id-sha256,
/// pSpecifiedEmpty (§2.1: "the OAEP label L is left to its default value,
/// which is the empty string").
fn oaep_params() -> OaepParams<'static> {
    OaepParams { hash: Some(OaepHash::Sha256), mgf_hash: Some(OaepHash::Sha256), label: None }
}

/// The §3.4 combiner as a `derive::run_combiner` recipe: the two component
/// secrets are concatenated as keys, then `tradCT`, `tradPK` and the label
/// are appended as data, then SHA3-256. Exactly
/// `SHA3-256(mlkemSS ‖ tradSS ‖ tradCT ‖ tradPK ‖ Label)`.
fn combiner(trad_ct: &[u8], trad_pk: &[u8], label: &[u8]) -> Combiner {
    Combiner::Concat {
        finalize: vec![
            FinalizeStep::ConcatData(trad_ct.to_vec()),
            FinalizeStep::ConcatData(trad_pk.to_vec()),
            FinalizeStep::ConcatData(label.to_vec()),
            FinalizeStep::Digest(CKM_SHA3_256_KEY_DERIVATION),
        ],
    }
}

fn combine(
    session: u32,
    p: &CompositeKemParams,
    mlkem_ss: &[u8],
    trad_ss: &[u8],
    trad_ct: &[u8],
    trad_pk: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CkRv> {
    let ss = Zeroizing::new(run_combiner(session, &[mlkem_ss, trad_ss], &combiner(trad_ct, trad_pk, p.label))?);
    // §3.4: a 256-bit output at every level.
    if ss.len() != COMPOSITE_KEM_SS_LEN {
        return Err(CKR_FUNCTION_FAILED);
    }
    Ok(ss)
}

/// `TradKEM.Encaps(tradPK)` (§2.1 / §2.2) → `(tradCT, tradSS)`.
fn trad_encaps(trad: TradKey, trad_pk: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CkRv> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let mut rng = rand::rngs::OsRng;
    macro_rules! dhkem {
        ($c:ident) => {{
            let peer = $c::PublicKey::from_sec1_bytes(trad_pk).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let eph = $c::ecdh::EphemeralSecret::random(&mut rng);
            let ct = eph.public_key().to_encoded_point(false).as_bytes().to_vec();
            let z = eph.diffie_hellman(&peer);
            (ct, Zeroizing::new(z.raw_secret_bytes().to_vec()))
        }};
    }
    Ok(match trad {
        TradKey::Rsa { .. } => {
            use rand::RngCore;
            // §2.1: shared_secret = SecureRandom(ss_len), ss_len = 256 bits (§6.1).
            let mut ss = Zeroizing::new(vec![0u8; COMPOSITE_KEM_SS_LEN]);
            rng.fill_bytes(&mut ss);
            let ct = rsa_oaep_encrypt(trad_pk, &ss, &oaep_params())?;
            (ct, ss)
        }
        TradKey::Ec(super::composite::EcCurve::P256) => dhkem!(p256),
        TradKey::Ec(super::composite::EcCurve::P384) => dhkem!(p384),
        TradKey::Ec(super::composite::EcCurve::P521) => dhkem!(p521),
        // brainpool (crypto::brainpool): the same DHKEM, §2.2.
        TradKey::Ec(curve) => {
            use rand::RngCore;
            let c = curve.engine_curve();
            if !crate::crypto::brainpool::validate_public(c, trad_pk) {
                return Err(CKR_KEY_TYPE_INCONSISTENT);
            }
            let (eph_d, ct) = crate::crypto::brainpool::generate(c, &mut |b: &mut [u8]| rng.fill_bytes(b))?;
            (ct, crate::crypto::brainpool::ecdh(c, &eph_d, trad_pk)?)
        }
        TradKey::X25519 => {
            let peer: [u8; 32] = trad_pk.try_into().map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let eph = x25519_dalek::EphemeralSecret::random_from_rng(&mut rng);
            let ct = x25519_dalek::PublicKey::from(&eph).as_bytes().to_vec();
            // RFC 7748 §6.1: a low-order peer key gives the all-zero K; the
            // component errors and §3.2 step 3 forwards it.
            let k = crate::crypto::handlers::x25519_contributory(eph.diffie_hellman(&peer.into()))
                .ok_or(CKR_FUNCTION_FAILED)?;
            (ct, Zeroizing::new(k.as_bytes().to_vec()))
        }
        TradKey::X448 => {
            let peer: [u8; 56] = trad_pk.try_into().map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let mut eph = Zeroizing::new([0u8; 56]);
            getrandom::getrandom(eph.as_mut()).map_err(|_| CKR_FUNCTION_FAILED)?;
            let ct = x448::PublicKey::from(&x448::StaticSecret::from(*eph)).as_bytes().to_vec();
            // RFC 7748 §6.2: the all-zero K is refused (x448 returns None).
            let k = x448::x448(*eph, peer).ok_or(CKR_FUNCTION_FAILED)?;
            (ct, Zeroizing::new(k.to_vec()))
        }
        TradKey::Ed25519 | TradKey::Ed448 => return Err(CKR_KEY_TYPE_INCONSISTENT),
    })
}

/// `TradKEM.Decaps(tradSK, tradCT)` (§2.1 / §2.2). The traditional
/// components are explicitly rejecting, and §3.5 requires the composite to
/// be too: "Composite ML-KEM MUST be explicitly rejecting whenever one of its
/// components is." An RSA-OAEP decoding failure, a point that is not on the
/// curve, or a low-order X25519 / X448 point is therefore an error, reported
/// as `CKR_WRAPPED_KEY_INVALID` — the code PKCS#11 v3.2 §5.18.9 lists for
/// C_DecapsulateKey input that is not valid (§5.1.6: "The provided wrapped
/// key is not valid"; §5.18.9's list does not include the decryption-only
/// CKR_ENCRYPTED_DATA_* codes, see the CKM_ML_KEM arm of
/// `ffi::C_DecapsulateKey`).
fn trad_decaps(trad: TradKey, trad_sk: &[u8], trad_ct: &[u8]) -> Result<Zeroizing<Vec<u8>>, CkRv> {
    macro_rules! dhkem {
        ($c:ident) => {{
            let d = super::composite_key::ec_private_key_scalar(trad_curve(trad), trad_sk).ok_or(CKR_KEY_TYPE_INCONSISTENT)?;
            let sk = $c::SecretKey::from_slice(d).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let eph = $c::PublicKey::from_sec1_bytes(trad_ct).map_err(|_| CKR_WRAPPED_KEY_INVALID)?;
            let z = $c::ecdh::diffie_hellman(sk.to_nonzero_scalar(), eph.as_affine());
            Zeroizing::new(z.raw_secret_bytes().to_vec())
        }};
    }
    Ok(match trad {
        TradKey::Rsa { .. } => {
            let ss = Zeroizing::new(rsa_oaep_decrypt(trad_sk, trad_ct, &oaep_params()).map_err(|rv| match rv {
                CKR_KEY_SIZE_RANGE | CKR_KEY_TYPE_INCONSISTENT => rv,
                _ => CKR_WRAPPED_KEY_INVALID,
            })?);
            // §6.1: ss_len is 256 bits, and §3.3 requires every combiner input
            // to be fixed-length; a well-formed OAEP payload of another length
            // is not a composite-KEM secret.
            if ss.len() != COMPOSITE_KEM_SS_LEN {
                return Err(CKR_WRAPPED_KEY_INVALID);
            }
            ss
        }
        TradKey::Ec(super::composite::EcCurve::P256) => dhkem!(p256),
        TradKey::Ec(super::composite::EcCurve::P384) => dhkem!(p384),
        TradKey::Ec(super::composite::EcCurve::P521) => dhkem!(p521),
        TradKey::X25519 => {
            let k: [u8; 32] = trad_sk.try_into().map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let k = Zeroizing::new(k);
            let eph: [u8; 32] = trad_ct.try_into().map_err(|_| CKR_WRAPPED_KEY_LEN_RANGE)?;
            let z = crate::crypto::handlers::x25519_contributory(
                x25519_dalek::StaticSecret::from(*k).diffie_hellman(&eph.into()),
            )
            .ok_or(CKR_WRAPPED_KEY_INVALID)?;
            Zeroizing::new(z.as_bytes().to_vec())
        }
        // brainpool: an off-curve or undecodable ephemeral point is invalid
        // input, as for the NIST curves above.
        TradKey::Ec(curve) => {
            let d = super::composite_key::ec_private_key_scalar(curve, trad_sk).ok_or(CKR_KEY_TYPE_INCONSISTENT)?;
            crate::crypto::brainpool::ecdh(curve.engine_curve(), d, trad_ct).map_err(|rv| match rv {
                CKR_ARGUMENTS_BAD => CKR_WRAPPED_KEY_INVALID,
                rv => rv,
            })?
        }
        TradKey::X448 => {
            let k: [u8; 56] = trad_sk.try_into().map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let k = Zeroizing::new(k);
            let eph: [u8; 56] = trad_ct.try_into().map_err(|_| CKR_WRAPPED_KEY_LEN_RANGE)?;
            Zeroizing::new(x448::x448(*k, eph).ok_or(CKR_WRAPPED_KEY_INVALID)?.to_vec())
        }
        TradKey::Ed25519 | TradKey::Ed448 => return Err(CKR_KEY_TYPE_INCONSISTENT),
    })
}

fn trad_curve(trad: TradKey) -> super::composite::EcCurve {
    match trad {
        TradKey::Ec(c) => c,
        _ => unreachable!("only called for EC components"),
    }
}

/// `Composite-ML-KEM.Encaps(pk)` (§3.2) → `(ct, ss)`, `ct = mlkemCT ‖
/// tradCT` (§4.3). `pk` is the public key's CKA_VALUE, already validated
/// when the object was created; a value that no longer splits is
/// `CKR_KEY_TYPE_INCONSISTENT`, the code the CKM_ML_KEM arm returns for
/// wrong-length key material. Component errors are forwarded (§3.2 step 3).
pub fn encapsulate(session: u32, p: &'static CompositeKemParams, pk: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CkRv> {
    use rand::RngCore;
    if !p.supported {
        return Err(CKR_PARAMETER_SET_NOT_SUPPORTED);
    }
    let layout = Layout::from(CompositeParams::Kem(p));
    let (ek, trad_pk) = layout.split_public(pk).ok_or(CKR_KEY_TYPE_INCONSISTENT)?;
    // ML-KEM.Encaps(ek): m drawn here, then the engine's single-algorithm
    // Encaps_internal (crypto::handlers::ml_kem_encaps, AWS-LC or ml-kem).
    let mut m = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(m.as_mut());
    let (mut ct, mlkem_ss) = crate::crypto::handlers::ml_kem_encaps(p.ml_kem, ek, &m)?;
    let mlkem_ss = Zeroizing::new(mlkem_ss);
    let (trad_ct, trad_ss) = trad_encaps(layout.trad, trad_pk)?;
    // §3.4 wants fixed-length combiner inputs and §4.3 a fixed ciphertext
    // length; the FFI copies `ct` into a buffer sized from the table. A
    // hard check, not a debug assertion: a component that ever returned
    // another length must fail here, before the combiner runs.
    if !p.ciphertext_size().admits(ct.len() + trad_ct.len()) {
        return Err(CKR_FUNCTION_FAILED);
    }
    let ss = combine(session, p, &mlkem_ss, &trad_ss, &trad_ct, trad_pk)?;
    ct.extend_from_slice(&trad_ct);
    Ok((ct, ss))
}

/// `Composite-ML-KEM.Decaps(sk, ct)` (§3.3). `sk` is the private key's
/// CKA_VALUE `mlkemSeed ‖ tradSK`; `tradPK` is re-derived from `tradSK` (the
/// first option of §10.4).
///
/// Failure semantics (§3.3 step 3, §3.5):
/// - `ct` of the wrong length → `CKR_WRAPPED_KEY_LEN_RANGE` before any
///   decapsulation. Every supported set has a fixed ciphertext length
///   (Appendix A; RSA-OAEP ciphertexts are the modulus length, and §3.3
///   requires RSA composites to check it). PKCS#11 v3.2 §5.1.6: input that
///   "can be seen to be invalid solely on the basis of its length"; the same
///   code as the CKM_ML_KEM arm.
/// - a tampered ML-KEM half is NOT an error: ML-KEM.Decaps is implicitly
///   rejecting (FIPS 203 §7.3, draft §3.5) and yields a pseudo-random
///   `mlkemSS`, so the call succeeds with a secret that does not match the
///   sender's.
/// - a traditional half the component refuses → `CKR_WRAPPED_KEY_INVALID`
///   (see `trad_decaps`); the ML-KEM secret computed alongside is dropped
///   zeroised, and no combiner runs (§3.3: "the KEM combiner step should not
///   be performed if either of the component decapsulations returned an
///   error").
pub fn decapsulate(session: u32, p: &'static CompositeKemParams, sk: &[u8], ct: &[u8]) -> Result<Zeroizing<Vec<u8>>, CkRv> {
    if !p.supported {
        return Err(CKR_PARAMETER_SET_NOT_SUPPORTED);
    }
    if !p.ciphertext_size().admits(ct.len()) {
        return Err(CKR_WRAPPED_KEY_LEN_RANGE);
    }
    let layout = Layout::from(CompositeParams::Kem(p));
    let (seed, trad_sk) = layout.split_private(sk).ok_or(CKR_KEY_TYPE_INCONSISTENT)?;
    let (mlkem_ct, trad_ct) = ct.split_at(p.ml_kem_ciphertext_len());
    // (_, mlkemSK) = ML-KEM.KeyGen(mlkemSeed[:32], mlkemSeed[32:]) — §3.3 step 1.
    let (_, dk) = crate::crypto::handlers::ml_kem_keygen_from_seed(p.ml_kem, seed).ok_or(CKR_KEY_TYPE_INCONSISTENT)?;
    let dk = Zeroizing::new(dk);
    let trad_pk = trad_public_from_private(layout.trad, trad_sk).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
    // Both component decapsulations run before either result is inspected.
    let mlkem_ss = crate::crypto::handlers::ml_kem_decaps(p.ml_kem, &dk, mlkem_ct).map(Zeroizing::new);
    let trad_ss = trad_decaps(layout.trad, trad_sk, trad_ct);
    let (mlkem_ss, trad_ss) = (mlkem_ss?, trad_ss?);
    combine(session, p, &mlkem_ss, &trad_ss, trad_ct, &trad_pk)
}
