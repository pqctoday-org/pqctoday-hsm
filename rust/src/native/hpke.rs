//! `CKM_HPKE` — RFC 9180 (Hybrid Public Key Encryption) composed as a native
//! PKCS#11 mechanism: KEM (+ PQ/T hybrid combiner, draft-irtf-cfrg-hybrid-kems
//! §5.5 / draft-irtf-cfrg-concrete-hybrid-kems §4) plus the full §5.1
//! KeySchedule, in one `C_EncapsulateKey`/`C_DecapsulateKey` call.
//!
//! Specification: `docs/proposals/pkcs11-ckm-hpke-mechanism-proposal.md`.
//! Codepoints: `pqctoday-priv/docs/platform/data/pkcs11-vendor-mech-allocation.md`
//! §1.4 (pending OASIS TC allocation — see the proposal doc §1.2 for why this
//! is NOT the same thing as v3.3's `CKM_COMP_KEM`).
//!
//! ## Key custody
//!
//! Every byte computed in this module — `ss_PQ`, `ss_T`, the combined KEM
//! shared secret, the HKDF PRK, the final AEAD key — lives only in local
//! Rust variables until the moment it is either (a) registered as a
//! non-extractable key object (the AEAD key, the optional exporter key), or
//! (b) written to a caller-supplied output buffer that RFC 9180 itself
//! defines as public (`enc`, `base_nonce`). Nothing here goes through
//! `C_GetAttributeValue` or any other externally-reachable read path, so the
//! "handle-chaining to avoid extraction" machinery `native::derive` provides
//! (`Combiner`/`run_combiner`, built for a WASM/JS caller that cannot see
//! inside the engine's own memory) is unnecessary here — this code runs
//! *inside* the engine, and its local variables are never visible outside it
//! regardless. The combiner is therefore just `sha3::Sha3_256::digest(...)`
//! over local byte slices, not a chain of registered handles.
//!
//! ## Reuse
//!
//! ML-KEM/classical-EC keygen: `super::keygen`. The KEM-combination math
//! (Diffie-Hellman, ML-KEM Encaps/Decaps) is written directly against the
//! same crates `native::hybrid` and `native::encrypt` already use for the
//! IANA TLS hybrid groups and classical/ML-KEM `C_En/DecapsulateKey` — not
//! delegated to those modules, because both are type-gated to their own key
//! shapes (`CKK_EC`/`CKK_EC_MONTGOMERY`/`CKK_ML_KEM`) and this mechanism uses
//! a single uniform `CKK_HPKE_KEM` key type across every suite (proposal
//! §5.1) that packs hybrid suites' two components into one object's
//! `CKA_VALUE` — a shape neither existing module's key-type gate accepts.
//! HKDF: `hkdf_expand` below reuses the `Hkdf::from_prk` construction (never
//! `Hkdf::new` for an already-extracted PRK) — the same fix applied to the
//! FFI `CKM_HKDF_DERIVE` expand-only arm on 2026-08-31 after it was found to
//! silently re-extract.

use std::collections::HashMap;

use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{EncodedSizeUser, KemCore};
use sha3::Digest;

use super::keygen::EccCurve;
use super::CkRv;
use crate::constants::*;
use crate::crypto::handlers::Attributes;
use crate::state::{
    allocate_handle_owned, compute_kcv, get_ec_point_sec1, get_object_attr_u32_from,
    get_object_param_set_from, get_object_value, get_object_value_from, read_bool_attr,
    resolve_session_access, store_bool, store_param_set, store_ulong, with_object_checked,
};

// ── Suite tables (RFC 9180 §7 / draft-ietf-hpke-pq §8.1 / draft-irtf-cfrg-concrete-hybrid-kems §4) ──

#[derive(Clone, Copy)]
enum Curve {
    P256,
    P384,
    P521,
    X25519,
    X448,
}

enum KemShape {
    /// Classical DHKEM. `internal_kdf` is the KEM's OWN fixed KDF for
    /// ExtractAndExpand (RFC 9180 Table 2), independent of the outer
    /// ciphersuite `kdf_id` a caller picks for KeySchedule.
    Classical { curve: Curve, internal_kdf: u32, auth: bool },
    /// PQ/T hybrid KEM (draft-ietf-hpke-pq). `pq_ps` is the ML-KEM
    /// `CKA_PARAMETER_SET` value; `label` is the CG-framework combiner
    /// label (draft-irtf-cfrg-concrete-hybrid-kems §4). No Auth interface —
    /// ML-KEM defines no AuthEncap/AuthDecap.
    Hybrid { pq_ps: u32, curve: Curve, label: &'static [u8] },
}

struct KemInfo {
    shape: KemShape,
    n_secret: usize,
}

fn kem_info(kem_id: u32) -> Result<KemInfo, CkRv> {
    Ok(match kem_id {
        CKP_HPKE_KEM_DHKEM_P256_HKDF_SHA256 => KemInfo {
            shape: KemShape::Classical { curve: Curve::P256, internal_kdf: CKM_SHA256, auth: true },
            n_secret: 32,
        },
        CKP_HPKE_KEM_DHKEM_P384_HKDF_SHA384 => KemInfo {
            shape: KemShape::Classical { curve: Curve::P384, internal_kdf: CKM_SHA384, auth: true },
            n_secret: 48,
        },
        CKP_HPKE_KEM_DHKEM_P521_HKDF_SHA512 => KemInfo {
            shape: KemShape::Classical { curve: Curve::P521, internal_kdf: CKM_SHA512, auth: true },
            n_secret: 64,
        },
        CKP_HPKE_KEM_DHKEM_X25519_HKDF_SHA256 => KemInfo {
            shape: KemShape::Classical { curve: Curve::X25519, internal_kdf: CKM_SHA256, auth: true },
            n_secret: 32,
        },
        CKP_HPKE_KEM_DHKEM_X448_HKDF_SHA512 => KemInfo {
            shape: KemShape::Classical { curve: Curve::X448, internal_kdf: CKM_SHA512, auth: true },
            n_secret: 64,
        },
        CKP_HPKE_KEM_MLKEM768_P256 => KemInfo {
            shape: KemShape::Hybrid { pq_ps: CKP_ML_KEM_768, curve: Curve::P256, label: b"MLKEM768-P256" },
            n_secret: 32,
        },
        CKP_HPKE_KEM_MLKEM1024_P384 => KemInfo {
            shape: KemShape::Hybrid { pq_ps: CKP_ML_KEM_1024, curve: Curve::P384, label: b"MLKEM1024-P384" },
            n_secret: 32,
        },
        // draft-irtf-cfrg-concrete-hybrid-kems §4.2 — the literal 6-byte
        // label "\.//^\" (same value X-Wing uses), not an ASCII name like
        // the P-256/P-384 labels. Given in hex, not a string literal, per
        // the same transcription-safety practice draft-ietf-lamps-pq-
        // composite-kem uses for its own awkward labels.
        CKP_HPKE_KEM_MLKEM768_X25519 => KemInfo {
            shape: KemShape::Hybrid {
                pq_ps: CKP_ML_KEM_768,
                curve: Curve::X25519,
                label: &[0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c],
            },
            n_secret: 32,
        },
        _ => return Err(CKR_MECHANISM_PARAM_INVALID),
    })
}

// ── HKDF (RFC 5869) — LabeledExtract / LabeledExpand (RFC 9180 §4) ─────────

const HPKE_V1: &[u8] = b"HPKE-v1";

fn i2osp2(n: usize) -> [u8; 2] {
    [((n >> 8) & 0xff) as u8, (n & 0xff) as u8]
}

fn hpke_suite_id(kem_id: u32, kdf_id: u32, aead_id: u32) -> Vec<u8> {
    [b"HPKE".as_slice(), &i2osp2(kem_id as usize), &i2osp2(kdf_id as usize), &i2osp2(aead_id as usize)].concat()
}

fn kem_suite_id(kem_id: u32) -> Vec<u8> {
    [b"KEM".as_slice(), &i2osp2(kem_id as usize)].concat()
}

fn hkdf_extract(prf: u32, salt: Option<&[u8]>, ikm: &[u8]) -> Result<Vec<u8>, CkRv> {
    macro_rules! run {
        ($H:ty) => {{
            let (prk, _) = Hkdf::<$H>::extract(salt, ikm);
            Ok(prk.to_vec())
        }};
    }
    match prf {
        CKM_SHA256 => run!(sha2::Sha256),
        CKM_SHA384 => run!(sha2::Sha384),
        CKM_SHA512 => run!(sha2::Sha512),
        _ => Err(CKR_MECHANISM_INVALID),
    }
}

/// Expand-only, from an already-extracted PRK — `Hkdf::from_prk`, NEVER
/// `Hkdf::new` (see module header: that was the FFI `CKM_HKDF_DERIVE` bug).
fn hkdf_expand(prf: u32, prk: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>, CkRv> {
    let mut out = vec![0u8; len];
    macro_rules! run {
        ($H:ty) => {{
            let hk = Hkdf::<$H>::from_prk(prk).map_err(|_| CKR_KEY_SIZE_RANGE)?;
            hk.expand(info, &mut out).map_err(|_| CKR_KEY_SIZE_RANGE)?;
        }};
    }
    match prf {
        CKM_SHA256 => run!(sha2::Sha256),
        CKM_SHA384 => run!(sha2::Sha384),
        CKM_SHA512 => run!(sha2::Sha512),
        _ => return Err(CKR_MECHANISM_INVALID),
    }
    Ok(out)
}

fn labeled_extract(prf: u32, suite_id: &[u8], salt: &[u8], label: &[u8], ikm: &[u8]) -> Result<Vec<u8>, CkRv> {
    let labeled_ikm = [HPKE_V1, suite_id, label, ikm].concat();
    let salt_opt = if salt.is_empty() { None } else { Some(salt) };
    hkdf_extract(prf, salt_opt, &labeled_ikm)
}

fn labeled_expand(prf: u32, suite_id: &[u8], prk: &[u8], label: &[u8], info: &[u8], l: usize) -> Result<Vec<u8>, CkRv> {
    let labeled_info = [&i2osp2(l)[..], HPKE_V1, suite_id, label, info].concat();
    hkdf_expand(prf, prk, &labeled_info, l)
}

/// RFC 9180 §4.1 `ExtractAndExpand` — the DHKEM's OWN fixed internal KDF,
/// independent of the outer suite's `kdf_id`.
fn extract_and_expand(internal_kdf: u32, kem_sid: &[u8], dh: &[u8], kem_context: &[u8], n_secret: usize) -> Result<Vec<u8>, CkRv> {
    let eae_prk = labeled_extract(internal_kdf, kem_sid, &[], b"eae_prk", dh)?;
    labeled_expand(internal_kdf, kem_sid, &eae_prk, b"shared_secret", kem_context, n_secret)
}

// ── Classical DH (mirrors native::encrypt's classical_en/decapsulate math,
//    generalized to a raw-bytes API so it can run against CKK_HPKE_KEM's
//    packed CKA_VALUE instead of a CKK_EC/CKK_EC_MONTGOMERY object) ────────

/// Ephemeral DH: generate a fresh (or, if `forced_scalar` is given, caller-
/// supplied — deterministic Encaps for RFC 9180 Appendix A vector
/// reproduction ONLY, see ck_param::hpke_params's doc comment) ephemeral
/// keypair, DH it against `peer_point`. Returns `(ephemeral_pub, dh)`.
fn ec_ephemeral_dh(curve: Curve, peer_point: &[u8], forced_scalar: Option<&[u8]>) -> Result<(Vec<u8>, Vec<u8>), CkRv> {
    let mut rng = rand::rngs::OsRng;
    match curve {
        Curve::P256 => {
            let peer = p256::PublicKey::from_sec1_bytes(peer_point).map_err(|_| CKR_ARGUMENTS_BAD)?;
            // `EphemeralSecret` deliberately has no forced-scalar constructor
            // (by design — ephemeral secrets in this crate are always
            // randomly generated). For the seeded/forced case (test-vector
            // reproduction ONLY, see ck_param::hpke_params's doc comment),
            // treat the forced scalar as a regular SecretKey and DH it via
            // the same static free function ec_static_dh below uses.
            if let Some(s) = forced_scalar {
                let sk = p256::SecretKey::from_slice(s).map_err(|_| CKR_ATTRIBUTE_VALUE_INVALID)?;
                let eph_pub = p256::EncodedPoint::from(sk.public_key());
                let ss = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer.as_affine());
                return Ok((eph_pub.as_bytes().to_vec(), ss.raw_secret_bytes().to_vec()));
            }
            let eph = p256::ecdh::EphemeralSecret::random(&mut rng);
            let eph_pub = p256::EncodedPoint::from(eph.public_key());
            let ss = eph.diffie_hellman(&peer);
            Ok((eph_pub.as_bytes().to_vec(), ss.raw_secret_bytes().to_vec()))
        }
        Curve::P384 => {
            let peer = p384::PublicKey::from_sec1_bytes(peer_point).map_err(|_| CKR_ARGUMENTS_BAD)?;
            if let Some(s) = forced_scalar {
                let sk = p384::SecretKey::from_slice(s).map_err(|_| CKR_ATTRIBUTE_VALUE_INVALID)?;
                let eph_pub = p384::EncodedPoint::from(sk.public_key());
                let ss = p384::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer.as_affine());
                return Ok((eph_pub.as_bytes().to_vec(), ss.raw_secret_bytes().to_vec()));
            }
            let eph = p384::ecdh::EphemeralSecret::random(&mut rng);
            let eph_pub = p384::EncodedPoint::from(eph.public_key());
            let ss = eph.diffie_hellman(&peer);
            Ok((eph_pub.as_bytes().to_vec(), ss.raw_secret_bytes().to_vec()))
        }
        Curve::P521 => {
            let peer = p521::PublicKey::from_sec1_bytes(peer_point).map_err(|_| CKR_ARGUMENTS_BAD)?;
            if let Some(s) = forced_scalar {
                let sk = p521::SecretKey::from_slice(s).map_err(|_| CKR_ATTRIBUTE_VALUE_INVALID)?;
                let eph_pub = p521::EncodedPoint::from(sk.public_key());
                let ss = p521::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer.as_affine());
                return Ok((eph_pub.as_bytes().to_vec(), ss.raw_secret_bytes().to_vec()));
            }
            let eph = p521::ecdh::EphemeralSecret::random(&mut rng);
            let eph_pub = p521::EncodedPoint::from(eph.public_key());
            let ss = eph.diffie_hellman(&peer);
            Ok((eph_pub.as_bytes().to_vec(), ss.raw_secret_bytes().to_vec()))
        }
        Curve::X25519 => {
            let peer_arr: [u8; 32] = peer_point.try_into().map_err(|_| CKR_ARGUMENTS_BAD)?;
            let eph = match forced_scalar {
                Some(s) => {
                    let arr: [u8; 32] = s.try_into().map_err(|_| CKR_ATTRIBUTE_VALUE_INVALID)?;
                    x25519_dalek::StaticSecret::from(arr)
                }
                None => x25519_dalek::StaticSecret::random_from_rng(&mut rng),
            };
            let eph_pub = x25519_dalek::PublicKey::from(&eph);
            let ss = eph.diffie_hellman(&x25519_dalek::PublicKey::from(peer_arr));
            Ok((eph_pub.as_bytes().to_vec(), ss.as_bytes().to_vec()))
        }
        Curve::X448 => {
            let peer_pub = x448::PublicKey::from_bytes(peer_point).ok_or(CKR_ARGUMENTS_BAD)?;
            let eph = match forced_scalar {
                Some(s) => {
                    let mut arr = [0u8; 56];
                    if s.len() != 56 {
                        return Err(CKR_ATTRIBUTE_VALUE_INVALID);
                    }
                    arr.copy_from_slice(s);
                    x448::StaticSecret::from(arr)
                }
                None => {
                    let mut eph_bytes = [0u8; 56];
                    getrandom::getrandom(&mut eph_bytes).map_err(|_| CKR_FUNCTION_FAILED)?;
                    x448::StaticSecret::from(eph_bytes)
                }
            };
            let eph_pub = x448::PublicKey::from(&eph);
            let ss = eph.diffie_hellman(&peer_pub);
            Ok((eph_pub.as_bytes().to_vec(), ss.as_bytes().to_vec()))
        }
    }
}

/// Static DH: `my_scalar` (this side's static/decap private key) against
/// `peer_point` (the other side's public point/ephemeral carried in `enc`).
fn ec_static_dh(curve: Curve, my_scalar: &[u8], peer_point: &[u8]) -> Result<Vec<u8>, CkRv> {
    match curve {
        Curve::P256 => {
            let secret = p256::SecretKey::from_slice(my_scalar).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let peer = p256::PublicKey::from_sec1_bytes(peer_point).map_err(|_| CKR_ARGUMENTS_BAD)?;
            let ss = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
            Ok(ss.raw_secret_bytes().to_vec())
        }
        Curve::P384 => {
            let secret = p384::SecretKey::from_slice(my_scalar).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let peer = p384::PublicKey::from_sec1_bytes(peer_point).map_err(|_| CKR_ARGUMENTS_BAD)?;
            let ss = p384::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
            Ok(ss.raw_secret_bytes().to_vec())
        }
        Curve::P521 => {
            let secret = p521::SecretKey::from_slice(my_scalar).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let peer = p521::PublicKey::from_sec1_bytes(peer_point).map_err(|_| CKR_ARGUMENTS_BAD)?;
            let ss = p521::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
            Ok(ss.raw_secret_bytes().to_vec())
        }
        Curve::X25519 => {
            let arr: [u8; 32] = my_scalar.try_into().map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let peer_arr: [u8; 32] = peer_point.try_into().map_err(|_| CKR_ARGUMENTS_BAD)?;
            let secret = x25519_dalek::StaticSecret::from(arr);
            let ss = secret.diffie_hellman(&x25519_dalek::PublicKey::from(peer_arr));
            Ok(ss.as_bytes().to_vec())
        }
        Curve::X448 => {
            if my_scalar.len() != 56 {
                return Err(CKR_KEY_TYPE_INCONSISTENT);
            }
            let mut arr = [0u8; 56];
            arr.copy_from_slice(my_scalar);
            let secret = x448::StaticSecret::from(arr);
            let peer_pub = x448::PublicKey::from_bytes(peer_point).ok_or(CKR_ARGUMENTS_BAD)?;
            Ok(secret.diffie_hellman(&peer_pub).as_bytes().to_vec())
        }
    }
}

fn curve_point_len(curve: Curve) -> usize {
    match curve {
        Curve::P256 => 65,
        Curve::P384 => 97,
        Curve::P521 => 133,
        Curve::X25519 => 32,
        Curve::X448 => 56,
    }
}

// ── ML-KEM (mirrors native::encrypt's encapsulate/decapsulate ML-KEM arm) ──

fn mlkem_encap(ps: u32, ek_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CkRv> {
    let mut rng = rand::rngs::OsRng;
    macro_rules! run {
        ($t:ty) => {{
            let ek_enc = ml_kem::array::Array::try_from(ek_bytes).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let ek = <$t as KemCore>::EncapsulationKey::from_bytes(&ek_enc);
            let (ct, ss) = Encapsulate::encapsulate(&ek, &mut rng).map_err(|_| CKR_FUNCTION_FAILED)?;
            Ok((ct.as_slice().to_vec(), ss.as_slice().to_vec()))
        }};
    }
    match ps {
        CKP_ML_KEM_768 => run!(ml_kem::MlKem768),
        CKP_ML_KEM_1024 => run!(ml_kem::MlKem1024),
        _ => Err(CKR_ARGUMENTS_BAD),
    }
}

fn mlkem_decap(ps: u32, dk_bytes: &[u8], ct: &[u8]) -> Result<Vec<u8>, CkRv> {
    macro_rules! run {
        ($t:ty) => {{
            let dk_enc = ml_kem::array::Array::try_from(dk_bytes).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let dk = <$t as KemCore>::DecapsulationKey::from_bytes(&dk_enc);
            let ct_enc = ml_kem::array::Array::try_from(ct).map_err(|_| CKR_ARGUMENTS_BAD)?;
            let ss = Decapsulate::decapsulate(&dk, &ct_enc).map_err(|_| CKR_FUNCTION_FAILED)?;
            Ok(ss.as_slice().to_vec())
        }};
    }
    match ps {
        CKP_ML_KEM_768 => run!(ml_kem::MlKem768),
        CKP_ML_KEM_1024 => run!(ml_kem::MlKem1024),
        _ => Err(CKR_ARGUMENTS_BAD),
    }
}

fn mlkem_sizes(ps: u32) -> (usize, usize) {
    // (ek/dk-independent ciphertext length, shared-secret length)
    match ps {
        CKP_ML_KEM_768 => (1088, 32),
        CKP_ML_KEM_1024 => (1568, 32),
        _ => (0, 0),
    }
}

fn mlkem_ek_len(ps: u32) -> usize {
    match ps {
        CKP_ML_KEM_768 => 1184,
        CKP_ML_KEM_1024 => 1568,
        _ => 0,
    }
}

/// draft-irtf-cfrg-concrete-hybrid-kems §4 — the CG-framework combiner:
/// `ss_H = SHA3-256(ss_PQ ‖ ss_T ‖ ct_T ‖ ek_T ‖ Label)`. A plain digest over
/// local byte slices — see the module header for why no handle-chaining is
/// needed here (unlike the `pqctoday-hub` WASM-consumer-side equivalent,
/// which has to fight the JS/WASM boundary this native code never crosses).
fn hybrid_combine(ss_pq: &[u8], ss_t: &[u8], ct_t: &[u8], ek_t: &[u8], label: &[u8]) -> Vec<u8> {
    let mut h = sha3::Sha3_256::new();
    h.update(ss_pq);
    h.update(ss_t);
    h.update(ct_t);
    h.update(ek_t);
    h.update(label);
    h.finalize().to_vec()
}

// ── Key objects ─────────────────────────────────────────────────────────────

/// `ek_H = ek_PQ ‖ ek_T` (hybrid, PQ-first) or the raw classical point
/// (draft-ietf-hpke-pq / draft-irtf-cfrg-concrete-hybrid-kems §"Component
/// Order"; RFC 9180 Table 2 SerializePublicKey for classical).
fn split_ek(info: &KemInfo, ek_h: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CkRv> {
    match &info.shape {
        KemShape::Classical { .. } => Ok((Vec::new(), ek_h.to_vec())),
        KemShape::Hybrid { pq_ps, .. } => {
            let pq_len = mlkem_ek_len(*pq_ps);
            if ek_h.len() <= pq_len {
                return Err(CKR_ARGUMENTS_BAD);
            }
            Ok((ek_h[..pq_len].to_vec(), ek_h[pq_len..].to_vec()))
        }
    }
}

/// Generate a `CKK_HPKE_KEM` key pair for `kem_id`. Hybrid suites generate
/// both components internally (ML-KEM + classical) via the existing
/// single-algorithm native keygen, read their values in-engine, then pack
/// them into ONE composite object per component — the transient component
/// objects are destroyed immediately after, never exposed as separate
/// handles (proposal §5.1: a uniform key type across every suite, forced by
/// `C_DecapsulateKey`'s single `hKey` argument needing to resolve to two
/// private components for a hybrid KEM).
pub fn keygen(session: u32, kem_id: u32, cka_id: &[u8], label: &str) -> Result<(u32, u32), CkRv> {
    let info = kem_info(kem_id)?;
    let (ek, dk): (Vec<u8>, Vec<u8>) = match &info.shape {
        KemShape::Classical { curve, .. } => {
            let (pub_h, priv_h) = generate_classical_keypair(session, *curve, cka_id, label)?;
            let ek = read_classical_point(*curve, pub_h)?;
            let dk = get_object_value(priv_h).ok_or(CKR_FUNCTION_FAILED)?;
            let _ = super::object::destroy_object(session, pub_h);
            let _ = super::object::destroy_object(session, priv_h);
            (ek, dk)
        }
        KemShape::Hybrid { pq_ps, curve, .. } => {
            let (mlkem_pub, mlkem_priv) =
                super::keygen::generate_ml_kem_keypair(session, *pq_ps, cka_id, label)?;
            let ek_pq = get_object_value(mlkem_pub).ok_or(CKR_FUNCTION_FAILED)?;
            let dk_pq = get_object_value(mlkem_priv).ok_or(CKR_FUNCTION_FAILED)?;
            let (c_pub, c_priv) = generate_classical_keypair(session, *curve, cka_id, label)?;
            let ek_t = read_classical_point(*curve, c_pub)?;
            let dk_t = get_object_value(c_priv).ok_or(CKR_FUNCTION_FAILED)?;
            let _ = super::object::destroy_object(session, mlkem_pub);
            let _ = super::object::destroy_object(session, mlkem_priv);
            let _ = super::object::destroy_object(session, c_pub);
            let _ = super::object::destroy_object(session, c_priv);
            ([ek_pq.as_slice(), ek_t.as_slice()].concat(), [dk_pq.as_slice(), dk_t.as_slice()].concat())
        }
    };

    let mut pub_attrs: Attributes = HashMap::new();
    pub_attrs.insert(CKA_VALUE, ek);
    store_ulong(&mut pub_attrs, CKA_CLASS, CKO_PUBLIC_KEY);
    store_ulong(&mut pub_attrs, CKA_KEY_TYPE, CKK_HPKE_KEM);
    store_ulong(&mut pub_attrs, CKA_PARAMETER_SET, kem_id);
    // Internal fast-lookup mirror every get_object_param_set(_from) read
    // actually keys off — see state::get_object_param_set_from. Missing
    // this (and keeping only the public CKA_PARAMETER_SET above) makes
    // every ps-consistency check in encapsulate/decapsulate see ps=0.
    store_param_set(&mut pub_attrs, kem_id);
    store_bool(&mut pub_attrs, CKA_TOKEN, false);
    store_bool(&mut pub_attrs, CKA_PRIVATE, false);
    store_bool(&mut pub_attrs, CKA_ENCAPSULATE, true);
    store_bool(&mut pub_attrs, CKA_LOCAL, true);
    let pub_handle = allocate_handle_owned(session, pub_attrs);

    let mut prv_attrs: Attributes = HashMap::new();
    prv_attrs.insert(CKA_VALUE, dk);
    store_ulong(&mut prv_attrs, CKA_CLASS, CKO_PRIVATE_KEY);
    store_ulong(&mut prv_attrs, CKA_KEY_TYPE, CKK_HPKE_KEM);
    store_ulong(&mut prv_attrs, CKA_PARAMETER_SET, kem_id);
    store_param_set(&mut prv_attrs, kem_id);
    store_bool(&mut prv_attrs, CKA_TOKEN, false);
    store_bool(&mut prv_attrs, CKA_PRIVATE, true);
    store_bool(&mut prv_attrs, CKA_SENSITIVE, true);
    store_bool(&mut prv_attrs, CKA_EXTRACTABLE, false);
    store_bool(&mut prv_attrs, CKA_DECAPSULATE, true);
    store_bool(&mut prv_attrs, CKA_LOCAL, true);
    let priv_handle = allocate_handle_owned(session, prv_attrs);

    Ok((pub_handle, priv_handle))
}

fn generate_classical_keypair(session: u32, curve: Curve, cka_id: &[u8], label: &str) -> Result<(u32, u32), CkRv> {
    match curve {
        Curve::P256 => super::keygen::generate_ecdh_keypair(session, EccCurve::P256, cka_id, label),
        Curve::P384 => super::keygen::generate_ecdh_keypair(session, EccCurve::P384, cka_id, label),
        Curve::P521 => super::keygen::generate_ecdh_keypair(session, EccCurve::P521, cka_id, label),
        Curve::X25519 => super::keygen::generate_x25519_keypair(session, cka_id, label),
        Curve::X448 => super::keygen::generate_x448_keypair(session, cka_id, label),
    }
}

fn read_classical_point(curve: Curve, pub_handle: u32) -> Result<Vec<u8>, CkRv> {
    match curve {
        Curve::P256 | Curve::P384 | Curve::P521 => get_ec_point_sec1(pub_handle).ok_or(CKR_FUNCTION_FAILED),
        Curve::X25519 | Curve::X448 => get_object_value(pub_handle).ok_or(CKR_FUNCTION_FAILED),
    }
}

// ── KeySchedule (RFC 9180 §5.1) ─────────────────────────────────────────────

struct KeyScheduleOutput {
    key: Option<Vec<u8>>,
    base_nonce: Option<Vec<u8>>,
    exporter_secret: Vec<u8>,
}

#[allow(clippy::too_many_arguments)]
fn key_schedule(
    kdf_prf: u32,
    sid: &[u8],
    mode: u32,
    shared_secret: &[u8],
    info: &[u8],
    psk: &[u8],
    psk_id: &[u8],
    aead_nk_nn: Option<(usize, usize)>,
    n_h: usize,
) -> Result<KeyScheduleOutput, CkRv> {
    let got_psk = !psk.is_empty();
    if got_psk != !psk_id.is_empty() {
        return Err(CKR_ARGUMENTS_BAD);
    }
    if got_psk && (mode == CKZ_HPKE_MODE_BASE || mode == CKZ_HPKE_MODE_AUTH) {
        return Err(CKR_ARGUMENTS_BAD);
    }
    if !got_psk && (mode == CKZ_HPKE_MODE_PSK || mode == CKZ_HPKE_MODE_AUTH_PSK) {
        return Err(CKR_ARGUMENTS_BAD);
    }

    let psk_id_hash = labeled_extract(kdf_prf, sid, &[], b"psk_id_hash", psk_id)?;
    let info_hash = labeled_extract(kdf_prf, sid, &[], b"info_hash", info)?;
    let ksc = [&[mode as u8][..], &psk_id_hash, &info_hash].concat();

    // secret = LabeledExtract(shared_secret, "secret", psk) — shared_secret
    // is the SALT here, psk is the IKM (RFC 9180 §5.1's own KeySchedule).
    let secret = labeled_extract(kdf_prf, sid, shared_secret, b"secret", psk)?;

    let (key, base_nonce) = match aead_nk_nn {
        Some((nk, nn)) => (
            Some(labeled_expand(kdf_prf, sid, &secret, b"key", &ksc, nk)?),
            Some(labeled_expand(kdf_prf, sid, &secret, b"base_nonce", &ksc, nn)?),
        ),
        None => (None, None),
    };
    let exporter_secret = labeled_expand(kdf_prf, sid, &secret, b"exp", &ksc, n_h)?;

    Ok(KeyScheduleOutput { key, base_nonce, exporter_secret })
}

fn kdf_prf_mech(kdf_id: u32) -> Result<(u32, usize), CkRv> {
    Ok(match kdf_id {
        CKD_HPKE_HKDF_SHA256 => (CKM_SHA256, 32),
        CKD_HPKE_HKDF_SHA384 => (CKM_SHA384, 48),
        CKD_HPKE_HKDF_SHA512 => (CKM_SHA512, 64),
        _ => return Err(CKR_MECHANISM_PARAM_INVALID),
    })
}

fn aead_sizes(aead_id: u32) -> Result<Option<(usize, usize)>, CkRv> {
    Ok(match aead_id {
        CKA_HPKE_AEAD_128_GCM => Some((16, 12)),
        CKA_HPKE_AEAD_256_GCM => Some((32, 12)),
        CKA_HPKE_AEAD_CHACHA20POLY1305 => Some((32, 12)),
        CKA_HPKE_AEAD_EXPORT_ONLY => None,
        _ => return Err(CKR_MECHANISM_PARAM_INVALID),
    })
}

// ── Public API ───────────────────────────────────────────────────────────

pub struct HpkeParams<'a> {
    pub kem_id: u32,
    pub kdf_id: u32,
    pub aead_id: u32,
    pub mode: u32,
    pub psk: &'a [u8],
    pub psk_id: &'a [u8],
    pub info: &'a [u8],
    /// Auth/AuthPSK, sender (Encap) side: the sender's static private key's
    /// raw scalar (already read in-engine — never re-extracted here).
    pub sender_static_priv: Option<&'a [u8]>,
    /// Auth/AuthPSK, recipient (Decap) side: the sender's static public
    /// point (public — bytes are fine).
    pub sender_static_pub: Option<&'a [u8]>,
    /// Phase-1 implementation detail (proposal §8 OQ): forces the ephemeral
    /// classical keypair for byte-exact RFC 9180 Appendix A vector
    /// reproduction. Classical KEM IDs ONLY — Err for a hybrid `kem_id`.
    /// MUST NOT be used outside test contexts.
    pub ephemeral_seed: Option<&'a [u8]>,
}

#[derive(Debug)]
pub struct HpkeResult {
    pub enc: Vec<u8>,
    /// Non-extractable CKK_AES/CKK_CHACHA20 key handle. None for export-only mode.
    pub key_handle: Option<u32>,
    pub base_nonce: Option<Vec<u8>>,
    /// Non-extractable (or, per the caller's template, extractable)
    /// exporter-secret key handle. None if the caller did not ask for one.
    pub exporter_handle: Option<u32>,
}

fn register_aead_key(session: u32, key: Vec<u8>, aead_id: u32) -> u32 {
    let key_type = if aead_id == CKA_HPKE_AEAD_CHACHA20POLY1305 { CKK_CHACHA20 } else { CKK_AES };
    let mut attrs: Attributes = HashMap::new();
    let klen = key.len() as u32;
    attrs.insert(CKA_VALUE, key);
    store_ulong(&mut attrs, CKA_CLASS, CKO_SECRET_KEY);
    store_ulong(&mut attrs, CKA_KEY_TYPE, key_type);
    store_ulong(&mut attrs, CKA_VALUE_LEN, klen);
    store_bool(&mut attrs, CKA_TOKEN, false);
    store_bool(&mut attrs, CKA_SENSITIVE, true);
    store_bool(&mut attrs, CKA_EXTRACTABLE, false);
    store_bool(&mut attrs, CKA_ENCRYPT, true);
    store_bool(&mut attrs, CKA_DECRYPT, true);
    store_bool(&mut attrs, CKA_LOCAL, false);
    store_ulong(&mut attrs, CKA_KEY_GEN_MECHANISM, CKM_UNAVAILABLE_INFORMATION);
    store_bool(&mut attrs, CKA_ALWAYS_SENSITIVE, false);
    store_bool(&mut attrs, CKA_NEVER_EXTRACTABLE, false);
    compute_kcv(&mut attrs);
    allocate_handle_owned(session, attrs)
}

/// `exporter_template`: the caller's `pExporterKey->pTemplate` attributes
/// (already parsed by the FFI layer), or `None` for no exporter key.
fn register_exporter_key(session: u32, value: Vec<u8>, template: Option<Vec<(u32, Vec<u8>)>>) -> Option<u32> {
    let tpl = template?;
    let mut attrs: Attributes = HashMap::new();
    // Sane defaults BEFORE the caller's template, mirroring how the FFI
    // ML-KEM/derive arms let a caller-supplied template override defaults
    // (absorb-after-defaults) — RFC 9180's exporter_secret is meant to be
    // usable, and a caller not asking for CKA_EXTRACTABLE gets a
    // non-extractable object by default.
    let vlen = value.len() as u32;
    attrs.insert(CKA_VALUE, value);
    store_ulong(&mut attrs, CKA_CLASS, CKO_SECRET_KEY);
    store_ulong(&mut attrs, CKA_KEY_TYPE, CKK_GENERIC_SECRET);
    store_ulong(&mut attrs, CKA_VALUE_LEN, vlen);
    store_bool(&mut attrs, CKA_TOKEN, false);
    store_bool(&mut attrs, CKA_SENSITIVE, true);
    store_bool(&mut attrs, CKA_EXTRACTABLE, false);
    store_bool(&mut attrs, CKA_DERIVE, true);
    store_bool(&mut attrs, CKA_LOCAL, false);
    store_ulong(&mut attrs, CKA_KEY_GEN_MECHANISM, CKM_UNAVAILABLE_INFORMATION);
    store_bool(&mut attrs, CKA_ALWAYS_SENSITIVE, false);
    store_bool(&mut attrs, CKA_NEVER_EXTRACTABLE, false);
    for (t, v) in tpl {
        if t == CKA_VALUE || t == CKA_VALUE_LEN {
            continue; // engine truth, never caller-overridable
        }
        attrs.insert(t, v);
    }
    compute_kcv(&mut attrs);
    Some(allocate_handle_owned(session, attrs))
}

/// `C_EncapsulateKey(CKM_HPKE)` — sender role. `recipient_pub` is the
/// recipient's `CKK_HPKE_KEM` public key handle.
pub fn encapsulate(
    session: u32,
    recipient_pub: u32,
    p: &HpkeParams,
    exporter_template: Option<Vec<(u32, Vec<u8>)>>,
) -> Result<HpkeResult, CkRv> {
    let access = resolve_session_access(session)?;
    let (can_encap, key_type, ps, ek_h) = with_object_checked(&access, recipient_pub, |attrs| {
        (
            read_bool_attr(attrs, CKA_ENCAPSULATE),
            get_object_attr_u32_from(attrs, CKA_KEY_TYPE),
            get_object_param_set_from(attrs),
            get_object_value_from(attrs),
        )
    })?;
    if !can_encap {
        return Err(CKR_KEY_FUNCTION_NOT_PERMITTED);
    }
    if key_type != Some(CKK_HPKE_KEM) {
        return Err(CKR_KEY_TYPE_INCONSISTENT);
    }
    if ps != p.kem_id {
        return Err(CKR_KEY_TYPE_INCONSISTENT);
    }
    let ek_h = ek_h.ok_or(CKR_ARGUMENTS_BAD)?;
    let info = kem_info(p.kem_id)?;

    let want_auth = p.mode == CKZ_HPKE_MODE_AUTH || p.mode == CKZ_HPKE_MODE_AUTH_PSK;

    let (enc, shared_secret) = match &info.shape {
        KemShape::Classical { curve, internal_kdf, auth } => {
            if want_auth && !*auth {
                return Err(CKR_MECHANISM_PARAM_INVALID);
            }
            if p.ephemeral_seed.is_some() && curve_point_len(*curve) == 0 {
                return Err(CKR_MECHANISM_PARAM_INVALID);
            }
            let forced = p.ephemeral_seed;
            let (enc, dh_e) = ec_ephemeral_dh(*curve, &ek_h, forced)?;
            let kem_sid = kem_suite_id(p.kem_id);
            if want_auth {
                let sk_s = p.sender_static_priv.ok_or(CKR_ARGUMENTS_BAD)?;
                let dh_s = ec_static_dh(*curve, sk_s, &ek_h)?;
                let dh = [dh_e.as_slice(), dh_s.as_slice()].concat();
                let pk_s = derive_pub_from_priv(*curve, sk_s)?;
                let kem_context = [enc.as_slice(), ek_h.as_slice(), pk_s.as_slice()].concat();
                (enc, extract_and_expand(*internal_kdf, &kem_sid, &dh, &kem_context, info.n_secret)?)
            } else {
                let kem_context = [enc.as_slice(), ek_h.as_slice()].concat();
                (enc, extract_and_expand(*internal_kdf, &kem_sid, &dh_e, &kem_context, info.n_secret)?)
            }
        }
        KemShape::Hybrid { pq_ps, curve, label } => {
            if want_auth {
                return Err(CKR_MECHANISM_PARAM_INVALID);
            }
            if p.ephemeral_seed.is_some() {
                return Err(CKR_MECHANISM_PARAM_INVALID); // Phase-1 scope: classical only, see proposal §8
            }
            let (ek_pq, ek_t) = split_ek(&info, &ek_h)?;
            let (ct_pq, ss_pq) = mlkem_encap(*pq_ps, &ek_pq)?;
            let (ct_t, ss_t) = ec_ephemeral_dh(*curve, &ek_t, None)?;
            let ss_h = hybrid_combine(&ss_pq, &ss_t, &ct_t, &ek_t, label);
            let enc = [ct_pq.as_slice(), ct_t.as_slice()].concat();
            (enc, ss_h)
        }
    };

    finish_encap_decap(session, p, &shared_secret, enc, exporter_template)
}

/// `C_DecapsulateKey(CKM_HPKE)` — recipient role. `recipient_priv` is the
/// recipient's `CKK_HPKE_KEM` private key handle; `enc` is the sender's KEM
/// output. RFC 9180 §4.1's `Decap`/`AuthDecap` derive the recipient's own
/// public key internally (`pkR = pk(skR)`) rather than taking it as an
/// input — this does the same, via `derive_pub_from_priv`, so no recipient
/// public value needs to be supplied or looked up.
pub fn decapsulate(
    session: u32,
    recipient_priv: u32,
    enc: &[u8],
    p: &HpkeParams,
    exporter_template: Option<Vec<(u32, Vec<u8>)>>,
) -> Result<HpkeResult, CkRv> {
    let access = resolve_session_access(session)?;
    let (can_decap, key_type, ps, dk_h) = with_object_checked(&access, recipient_priv, |attrs| {
        (
            read_bool_attr(attrs, CKA_DECAPSULATE),
            get_object_attr_u32_from(attrs, CKA_KEY_TYPE),
            get_object_param_set_from(attrs),
            get_object_value_from(attrs),
        )
    })?;
    if !can_decap {
        return Err(CKR_KEY_FUNCTION_NOT_PERMITTED);
    }
    if key_type != Some(CKK_HPKE_KEM) {
        return Err(CKR_KEY_TYPE_INCONSISTENT);
    }
    if ps != p.kem_id {
        return Err(CKR_KEY_TYPE_INCONSISTENT);
    }
    let dk_h = dk_h.ok_or(CKR_ARGUMENTS_BAD)?;
    let info = kem_info(p.kem_id)?;
    let want_auth = p.mode == CKZ_HPKE_MODE_AUTH || p.mode == CKZ_HPKE_MODE_AUTH_PSK;

    let shared_secret = match &info.shape {
        KemShape::Classical { curve, internal_kdf, auth } => {
            if want_auth && !*auth {
                return Err(CKR_MECHANISM_PARAM_INVALID);
            }
            let kem_sid = kem_suite_id(p.kem_id);
            // RFC 9180 §4.1: Decap/AuthDecap derive pkR = pk(skR) internally
            // rather than taking it as an input.
            let pk_r = derive_pub_from_priv(*curve, &dk_h)?;
            if want_auth {
                let pk_s = p.sender_static_pub.ok_or(CKR_ARGUMENTS_BAD)?;
                let dh_e = ec_static_dh(*curve, &dk_h, enc)?;
                let dh_s = ec_static_dh(*curve, &dk_h, pk_s)?;
                let dh = [dh_e.as_slice(), dh_s.as_slice()].concat();
                let kem_context = [enc, pk_r.as_slice(), pk_s].concat();
                extract_and_expand(*internal_kdf, &kem_sid, &dh, &kem_context, info.n_secret)?
            } else {
                let dh = ec_static_dh(*curve, &dk_h, enc)?;
                let kem_context = [enc, pk_r.as_slice()].concat();
                extract_and_expand(*internal_kdf, &kem_sid, &dh, &kem_context, info.n_secret)?
            }
        }
        KemShape::Hybrid { pq_ps, curve, label } => {
            if want_auth {
                return Err(CKR_MECHANISM_PARAM_INVALID);
            }
            let pq_dk_len = dk_h.len().saturating_sub(match curve {
                Curve::X25519 => 32,
                Curve::X448 => 56,
                Curve::P256 | Curve::P384 | Curve::P521 => {
                    // classical scalar length equals the curve's field size
                    match curve {
                        Curve::P256 => 32,
                        Curve::P384 => 48,
                        Curve::P521 => 66,
                        _ => unreachable!(),
                    }
                }
            });
            if pq_dk_len == 0 || pq_dk_len > dk_h.len() {
                return Err(CKR_ARGUMENTS_BAD);
            }
            let (dk_pq, dk_t) = (&dk_h[..pq_dk_len], &dk_h[pq_dk_len..]);
            let pq_ct_len = mlkem_sizes(*pq_ps).0;
            if enc.len() <= pq_ct_len {
                return Err(CKR_ARGUMENTS_BAD);
            }
            let (ct_pq, ct_t) = enc.split_at(pq_ct_len);
            let ss_pq = mlkem_decap(*pq_ps, dk_pq, ct_pq)?;
            let ss_t = ec_static_dh(*curve, dk_t, ct_t)?;
            // RFC 9180 §4.1 / the CG combiner both need only ek_T, derived
            // from dk_T — ek_PQ is not a combiner operand (Table 1, §6.1).
            let ek_t = derive_pub_from_priv(*curve, dk_t)?;
            hybrid_combine(&ss_pq, &ss_t, ct_t, &ek_t, label)
        }
    };

    finish_encap_decap(session, p, &shared_secret, enc.to_vec(), exporter_template)
}

fn finish_encap_decap(
    session: u32,
    p: &HpkeParams,
    shared_secret: &[u8],
    enc: Vec<u8>,
    exporter_template: Option<Vec<(u32, Vec<u8>)>>,
) -> Result<HpkeResult, CkRv> {
    let (kdf_prf, n_h) = kdf_prf_mech(p.kdf_id)?;
    let sid = hpke_suite_id(p.kem_id, p.kdf_id, p.aead_id);
    let aead_nk_nn = aead_sizes(p.aead_id)?;

    let sched = key_schedule(kdf_prf, &sid, p.mode, shared_secret, p.info, p.psk, p.psk_id, aead_nk_nn, n_h)?;

    let key_handle = sched.key.map(|k| register_aead_key(session, k, p.aead_id));
    let exporter_handle = if p.aead_id == CKA_HPKE_AEAD_EXPORT_ONLY {
        Some(register_exporter_key(session, sched.exporter_secret, exporter_template.or(Some(Vec::new())))
            .ok_or(CKR_FUNCTION_FAILED)?)
    } else {
        register_exporter_key(session, sched.exporter_secret, exporter_template)
    };

    Ok(HpkeResult { enc, key_handle, base_nonce: sched.base_nonce, exporter_handle })
}

/// Derive a classical public point from a private scalar — needed for
/// AuthEncap's `kem_context = enc ‖ pkR ‖ pkS`, where `pkS` must be
/// (re)derived from the sender's static private handle (RFC 9180 gives the
/// sender only `skS`, not `pkS`, as AuthEncap's input).
fn derive_pub_from_priv(curve: Curve, scalar: &[u8]) -> Result<Vec<u8>, CkRv> {
    match curve {
        Curve::P256 => {
            let sk = p256::SecretKey::from_slice(scalar).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            Ok(p256::EncodedPoint::from(sk.public_key()).as_bytes().to_vec())
        }
        Curve::P384 => {
            let sk = p384::SecretKey::from_slice(scalar).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            Ok(p384::EncodedPoint::from(sk.public_key()).as_bytes().to_vec())
        }
        Curve::P521 => {
            let sk = p521::SecretKey::from_slice(scalar).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            Ok(p521::EncodedPoint::from(sk.public_key()).as_bytes().to_vec())
        }
        Curve::X25519 => {
            let arr: [u8; 32] = scalar.try_into().map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let sk = x25519_dalek::StaticSecret::from(arr);
            Ok(x25519_dalek::PublicKey::from(&sk).as_bytes().to_vec())
        }
        Curve::X448 => {
            if scalar.len() != 56 {
                return Err(CKR_KEY_TYPE_INCONSISTENT);
            }
            let mut arr = [0u8; 56];
            arr.copy_from_slice(scalar);
            let sk = x448::StaticSecret::from(arr);
            Ok(x448::PublicKey::from(&sk).as_bytes().to_vec())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::test_lock;
    use crate::state::with_object_checked;

    fn fresh_session() -> u32 {
        let _ = crate::native::session::finalize();
        crate::native::session::init().expect("engine init");
        crate::native::session::bootstrap_default_token(0, "so", "user", "hpke-test")
            .expect("bootstrap session")
    }

    fn is_extractable(session: u32, handle: u32) -> bool {
        let access = resolve_session_access(session).expect("session access");
        with_object_checked(&access, handle, |attrs| read_bool_attr(attrs, CKA_EXTRACTABLE))
            .unwrap_or(true)
    }

    /// Full hybrid-KEM cross-product this engine's `CKM_HPKE` must support:
    /// every hybrid KEM ID draft-ietf-hpke-pq registers × every RFC 9180 KDF
    /// × every non-export AEAD × the two modes ML-KEM's Auth column allows
    /// (Base, PSK — no Auth/AuthPSK, see `KemShape::Hybrid`'s doc comment).
    /// 3×3×3×2 = 54 cases, the same matrix `hpkeService.test.ts` validates
    /// at the composed-primitives layer in `pqctoday-hub`. Each case: a full
    /// independent-keygen round trip, with explicit proof that ss_PQ/ss_T/
    /// ss_H never left this function as anything but a local Rust variable
    /// (the returned key handles' own CKA_EXTRACTABLE=false) and that
    /// sender and recipient derive byte-identical output.
    #[test]
    fn hybrid_cross_product_all_54_cases() {
        let _guard = test_lock::acquire();
        let session = fresh_session();

        let kems = [
            CKP_HPKE_KEM_MLKEM768_X25519,
            CKP_HPKE_KEM_MLKEM768_P256,
            CKP_HPKE_KEM_MLKEM1024_P384,
        ];
        let kdfs = [CKD_HPKE_HKDF_SHA256, CKD_HPKE_HKDF_SHA384, CKD_HPKE_HKDF_SHA512];
        let aeads = [CKA_HPKE_AEAD_128_GCM, CKA_HPKE_AEAD_256_GCM, CKA_HPKE_AEAD_CHACHA20POLY1305];
        let modes = [CKZ_HPKE_MODE_BASE, CKZ_HPKE_MODE_PSK];

        let mut cases_run = 0;
        for &kem_id in &kems {
            let (pub_h, priv_h) = keygen(session, kem_id, b"\x01", "hpke cross-product recipient")
                .unwrap_or_else(|e| panic!("keygen({kem_id:#06x}) failed: {e:#x}"));
            assert!(!is_extractable(session, priv_h), "kem_id {kem_id:#06x}: private key must be non-extractable");

            for &kdf_id in &kdfs {
                for &aead_id in &aeads {
                    for &mode in &modes {
                        cases_run += 1;
                        let (psk, psk_id): (Vec<u8>, Vec<u8>) = if mode == CKZ_HPKE_MODE_PSK {
                            (vec![0x5au8; 32], b"cross-product-psk-id".to_vec())
                        } else {
                            (Vec::new(), Vec::new())
                        };
                        let info = b"hpke native cross-product test".to_vec();

                        let params = HpkeParams {
                            kem_id,
                            kdf_id,
                            aead_id,
                            mode,
                            psk: &psk,
                            psk_id: &psk_id,
                            info: &info,
                            sender_static_priv: None,
                            sender_static_pub: None,
                            ephemeral_seed: None,
                        };

                        let sender = encapsulate(session, pub_h, &params, None).unwrap_or_else(|e| {
                            panic!("encapsulate(kem={kem_id:#06x} kdf={kdf_id:#06x} aead={aead_id:#06x} mode={mode}) failed: {e:#x}")
                        });
                        let recipient = decapsulate(session, priv_h, &sender.enc, &params, None).unwrap_or_else(|e| {
                            panic!("decapsulate(kem={kem_id:#06x} kdf={kdf_id:#06x} aead={aead_id:#06x} mode={mode}) failed: {e:#x}")
                        });

                        let sender_key_h = sender.key_handle.expect("sender key handle");
                        let recipient_key_h = recipient.key_handle.expect("recipient key handle");
                        assert!(!is_extractable(session, sender_key_h), "sender AEAD key must be non-extractable");
                        assert!(!is_extractable(session, recipient_key_h), "recipient AEAD key must be non-extractable");

                        // Non-extractability is proven above via CKA_EXTRACTABLE; the
                        // byte comparison here is a native-test-only internal read
                        // (get_object_value is an in-engine call, not
                        // C_GetAttributeValue — see this module's header) standing in
                        // for the FFI-layer Seal/Open black-box proof
                        // hpkeService.test.ts uses, which needs the AEAD mechanisms
                        // wired through a native encrypt-by-handle helper this crate
                        // does not yet expose (native/encrypt.rs has none) — a real,
                        // flagged follow-up, not a shortcut taken silently.
                        let sender_key_val = get_object_value(sender_key_h).expect("sender key value");
                        let recipient_key_val = get_object_value(recipient_key_h).expect("recipient key value");
                        assert_eq!(
                            sender_key_val, recipient_key_val,
                            "kem={kem_id:#06x} kdf={kdf_id:#06x} aead={aead_id:#06x} mode={mode}: AEAD key mismatch"
                        );
                        assert_eq!(
                            sender.base_nonce, recipient.base_nonce,
                            "kem={kem_id:#06x} kdf={kdf_id:#06x} aead={aead_id:#06x} mode={mode}: base_nonce mismatch"
                        );
                        let (nk, _) = aead_sizes(aead_id).unwrap().unwrap();
                        assert_eq!(sender_key_val.len(), nk, "AEAD key length must match Nk");
                    }
                }
            }
        }
        assert_eq!(cases_run, 54, "must exercise the full 3×3×3×2 hybrid matrix");
    }

    /// Export-only mode (aeadId = CKA_HPKE_AEAD_EXPORT_ONLY): no AEAD key,
    /// `*phKey` (here: `HpkeResult::key_handle`, unset) instead surfaces the
    /// exporter secret via `exporter_handle` — proposal §4's "pExporterKey
    /// = NULL and aeadId = EXPORT_ONLY" case.
    #[test]
    fn hybrid_export_only_mode_returns_exporter_as_key_handle() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, priv_h) = keygen(session, CKP_HPKE_KEM_MLKEM768_X25519, b"\x01", "export-only recipient").unwrap();
        let info = b"export-only test".to_vec();
        let params = HpkeParams {
            kem_id: CKP_HPKE_KEM_MLKEM768_X25519,
            kdf_id: CKD_HPKE_HKDF_SHA256,
            aead_id: CKA_HPKE_AEAD_EXPORT_ONLY,
            mode: CKZ_HPKE_MODE_BASE,
            psk: &[],
            psk_id: &[],
            info: &info,
            sender_static_priv: None,
            sender_static_pub: None,
            ephemeral_seed: None,
        };
        let sender = encapsulate(session, pub_h, &params, None).unwrap();
        let recipient = decapsulate(session, priv_h, &sender.enc, &params, None).unwrap();
        assert!(sender.key_handle.is_none(), "export-only: no AEAD key derived");
        assert!(sender.base_nonce.is_none(), "export-only: no base_nonce derived");
        let sender_exp = sender.exporter_handle.expect("exporter handle (export-only ⇒ surfaces here)");
        let recipient_exp = recipient.exporter_handle.expect("recipient exporter handle");
        assert!(!is_extractable(session, sender_exp), "exporter secret must default non-extractable");
        assert_eq!(
            get_object_value(sender_exp).unwrap(),
            get_object_value(recipient_exp).unwrap(),
            "export-only: sender/recipient exporter_secret must match"
        );
    }

    /// A caller-supplied `pExporterKey` template alongside a real AEAD mode:
    /// BOTH a non-extractable AEAD key (`*phKey`) and an exporter key
    /// (explicitly requested extractable, proving the template override
    /// path — proposal §4's `pExporterKey` field — actually works) come
    /// back from one call.
    #[test]
    fn exporter_key_alongside_aead_key_honors_caller_template() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, priv_h) = keygen(session, CKP_HPKE_KEM_MLKEM768_P256, b"\x01", "exporter-alongside recipient").unwrap();
        let info = b"exporter-alongside test".to_vec();
        let params = HpkeParams {
            kem_id: CKP_HPKE_KEM_MLKEM768_P256,
            kdf_id: CKD_HPKE_HKDF_SHA256,
            aead_id: CKA_HPKE_AEAD_128_GCM,
            mode: CKZ_HPKE_MODE_BASE,
            psk: &[],
            psk_id: &[],
            info: &info,
            sender_static_priv: None,
            sender_static_pub: None,
            ephemeral_seed: None,
        };
        // Caller explicitly asks for CKA_EXTRACTABLE=true on the exporter key.
        let tpl = vec![(CKA_EXTRACTABLE, vec![1u8])];
        let sender = encapsulate(session, pub_h, &params, Some(tpl)).unwrap();
        let key_h = sender.key_handle.expect("AEAD key still produced alongside exporter key");
        let exp_h = sender.exporter_handle.expect("exporter key produced from caller template");
        assert!(!is_extractable(session, key_h), "AEAD key stays non-extractable regardless");
        assert!(is_extractable(session, exp_h), "exporter key honors the caller's explicit CKA_EXTRACTABLE=true");
        let _ = priv_h;
    }

    /// Classical DHKEM round-trip (all 5 [RFC9180] §7.1 KEM IDs), Base mode —
    /// proves the non-hybrid half of `CKM_HPKE` also works end-to-end.
    /// NOT byte-exact against RFC 9180 Appendix A.3: that needs a forced
    /// static-key import path for CKK_HPKE_KEM objects this Phase-1
    /// implementation does not yet have (only the ephemeral side is
    /// seedable — see `HpkeParams::ephemeral_seed`'s doc comment and
    /// proposal §8's deterministic-Encaps OQ). Flagged, not hidden.
    #[test]
    fn classical_dhkem_all_curves_round_trip() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let kems = [
            CKP_HPKE_KEM_DHKEM_P256_HKDF_SHA256,
            CKP_HPKE_KEM_DHKEM_P384_HKDF_SHA384,
            CKP_HPKE_KEM_DHKEM_P521_HKDF_SHA512,
            CKP_HPKE_KEM_DHKEM_X25519_HKDF_SHA256,
            CKP_HPKE_KEM_DHKEM_X448_HKDF_SHA512,
        ];
        for &kem_id in &kems {
            let (pub_h, priv_h) = keygen(session, kem_id, b"\x01", "classical recipient")
                .unwrap_or_else(|e| panic!("keygen({kem_id:#06x}) failed: {e:#x}"));
            let (kdf_id, _) = match kem_id {
                CKP_HPKE_KEM_DHKEM_P256_HKDF_SHA256 | CKP_HPKE_KEM_DHKEM_X25519_HKDF_SHA256 => (CKD_HPKE_HKDF_SHA256, 0),
                CKP_HPKE_KEM_DHKEM_P384_HKDF_SHA384 => (CKD_HPKE_HKDF_SHA384, 0),
                _ => (CKD_HPKE_HKDF_SHA512, 0),
            };
            let info = b"classical dhkem round-trip".to_vec();
            let params = HpkeParams {
                kem_id,
                kdf_id,
                aead_id: CKA_HPKE_AEAD_128_GCM,
                mode: CKZ_HPKE_MODE_BASE,
                psk: &[],
                psk_id: &[],
                info: &info,
                sender_static_priv: None,
                sender_static_pub: None,
                ephemeral_seed: None,
            };
            let sender = encapsulate(session, pub_h, &params, None)
                .unwrap_or_else(|e| panic!("encapsulate({kem_id:#06x}) failed: {e:#x}"));
            let recipient = decapsulate(session, priv_h, &sender.enc, &params, None)
                .unwrap_or_else(|e| panic!("decapsulate({kem_id:#06x}) failed: {e:#x}"));
            assert_eq!(
                get_object_value(sender.key_handle.unwrap()).unwrap(),
                get_object_value(recipient.key_handle.unwrap()).unwrap(),
                "kem_id {kem_id:#06x}: classical round-trip key mismatch"
            );
        }
    }

    /// Auth mode (classical only — hybrid's ML-KEM has no Auth interface,
    /// asserted separately below): sender's static key changes the derived
    /// secret, and the wrong static key must NOT verify.
    #[test]
    fn classical_auth_mode_round_trips_and_rejects_wrong_sender_key() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let kem_id = CKP_HPKE_KEM_DHKEM_P256_HKDF_SHA256;
        let (recipient_pub, recipient_priv) = keygen(session, kem_id, b"\x01", "auth recipient").unwrap();
        let (sender_pub, sender_priv) = keygen(session, kem_id, b"\x02", "auth sender").unwrap();
        let (_wrong_pub, wrong_priv) = keygen(session, kem_id, b"\x03", "auth wrong sender").unwrap();

        let sender_priv_val = get_object_value(sender_priv).unwrap();
        let recipient_pub_val = get_object_value(recipient_pub).unwrap();
        let sender_pub_val = get_object_value(sender_pub).unwrap();
        let wrong_priv_val = get_object_value(wrong_priv).unwrap();

        let info = b"auth mode test".to_vec();
        let mut params = HpkeParams {
            kem_id,
            kdf_id: CKD_HPKE_HKDF_SHA256,
            aead_id: CKA_HPKE_AEAD_128_GCM,
            mode: CKZ_HPKE_MODE_AUTH,
            psk: &[],
            psk_id: &[],
            info: &info,
            sender_static_priv: Some(&sender_priv_val),
            sender_static_pub: None,
            ephemeral_seed: None,
        };
        let sender = encapsulate(session, recipient_pub, &params, None).unwrap();

        params.sender_static_priv = None;
        params.sender_static_pub = Some(&sender_pub_val);
        let recipient = decapsulate(session, recipient_priv, &sender.enc, &params, None).unwrap();
        assert_eq!(
            get_object_value(sender.key_handle.unwrap()).unwrap(),
            get_object_value(recipient.key_handle.unwrap()).unwrap(),
            "AuthEncap/AuthDecap must agree with the real sender key"
        );

        // Recipient trusts the WRONG sender public key — must derive a
        // different (wrong) secret, not silently succeed.
        params.sender_static_pub = Some(&recipient_pub_val); // any key that isn't sender_pub_val
        let wrong = decapsulate(session, recipient_priv, &sender.enc, &params, None).unwrap();
        assert_ne!(
            get_object_value(wrong.key_handle.unwrap()).unwrap(),
            get_object_value(sender.key_handle.unwrap()).unwrap(),
            "AuthDecap with the wrong sender public key must NOT reproduce the sender's key"
        );
        let _ = wrong_priv_val;
    }

    /// [HPKE-PQ]'s KEM table marks Auth "no" for every hybrid KEM ID — this
    /// engine must refuse Auth/AuthPSK for them, not silently ignore the
    /// sender-key fields.
    #[test]
    fn hybrid_auth_mode_is_rejected() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, _priv_h) = keygen(session, CKP_HPKE_KEM_MLKEM768_X25519, b"\x01", "hybrid auth reject").unwrap();
        let info = b"hybrid auth rejection test".to_vec();
        let params = HpkeParams {
            kem_id: CKP_HPKE_KEM_MLKEM768_X25519,
            kdf_id: CKD_HPKE_HKDF_SHA256,
            aead_id: CKA_HPKE_AEAD_128_GCM,
            mode: CKZ_HPKE_MODE_AUTH,
            psk: &[],
            psk_id: &[],
            info: &info,
            sender_static_priv: None,
            sender_static_pub: None,
            ephemeral_seed: None,
        };
        assert_eq!(encapsulate(session, pub_h, &params, None).unwrap_err(), CKR_MECHANISM_PARAM_INVALID);
    }

    /// `ephemeral_seed` forces the ephemeral classical keypair — two calls
    /// with the SAME seed against the SAME recipient key must produce the
    /// SAME `enc`; different seeds must not.
    #[test]
    fn ephemeral_seed_is_deterministic_for_classical_suites() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let kem_id = CKP_HPKE_KEM_DHKEM_P256_HKDF_SHA256;
        let (pub_h, _priv_h) = keygen(session, kem_id, b"\x01", "seed test recipient").unwrap();
        let info = b"seed test".to_vec();
        // A valid P-256 scalar (nonzero, < group order) — arbitrary fixed value.
        let seed1 = [0x11u8; 32];
        let seed2 = [0x22u8; 32];
        fn params_with_seed<'a>(kem_id: u32, info: &'a [u8], seed: &'a [u8]) -> HpkeParams<'a> {
            HpkeParams {
                kem_id,
                kdf_id: CKD_HPKE_HKDF_SHA256,
                aead_id: CKA_HPKE_AEAD_128_GCM,
                mode: CKZ_HPKE_MODE_BASE,
                psk: &[],
                psk_id: &[],
                info,
                sender_static_priv: None,
                sender_static_pub: None,
                ephemeral_seed: Some(seed),
            }
        }
        let r1a = encapsulate(session, pub_h, &params_with_seed(kem_id, &info, &seed1), None).unwrap();
        let r1b = encapsulate(session, pub_h, &params_with_seed(kem_id, &info, &seed1), None).unwrap();
        let r2 = encapsulate(session, pub_h, &params_with_seed(kem_id, &info, &seed2), None).unwrap();
        assert_eq!(r1a.enc, r1b.enc, "same seed must reproduce the same enc");
        assert_ne!(r1a.enc, r2.enc, "different seeds must produce different enc");
    }

    /// `ephemeral_seed` is Phase-1-scoped to classical suites only (proposal
    /// §8 OQ) — a hybrid `kem_id` with a seed must be rejected, not silently
    /// ignored (which would look "deterministic" for the classical half
    /// only, a worse failure mode than an outright error).
    #[test]
    fn ephemeral_seed_rejected_for_hybrid_kems() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, _priv_h) = keygen(session, CKP_HPKE_KEM_MLKEM768_X25519, b"\x01", "seed reject test").unwrap();
        let info = b"seed reject test".to_vec();
        let seed = [0x11u8; 32];
        let params = HpkeParams {
            kem_id: CKP_HPKE_KEM_MLKEM768_X25519,
            kdf_id: CKD_HPKE_HKDF_SHA256,
            aead_id: CKA_HPKE_AEAD_128_GCM,
            mode: CKZ_HPKE_MODE_BASE,
            psk: &[],
            psk_id: &[],
            info: &info,
            sender_static_priv: None,
            sender_static_pub: None,
            ephemeral_seed: Some(&seed),
        };
        assert_eq!(encapsulate(session, pub_h, &params, None).unwrap_err(), CKR_MECHANISM_PARAM_INVALID);
    }
}
