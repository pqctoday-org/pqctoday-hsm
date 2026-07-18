//! Hybrid KEM — the three IANA-registered ECDHE-MLKEM groups
//! (`draft-ietf-tls-ecdhe-mlkem`), implemented in the PKCS#11 engine where all
//! cryptography belongs (the KMIP layer holds no crypto crate).
//!
//! ## One KMIP object → TWO PKCS#11 handles (classical + PQC)
//!
//! A hybrid key is NOT a single composite blob. It is two ordinary,
//! NON-EXTRACTABLE engine keypairs — a classical one (X25519 or ECDH P-256/
//! P-384) and an ML-KEM one — each created by the existing single-algorithm
//! keygen (`generate_x25519_keypair`/`generate_ecdh_keypair` +
//! `generate_ml_kem_keypair`, all `CKA_SENSITIVE`/`CKA_EXTRACTABLE=false`). The
//! KMIP layer ties the two together at the KMIP-object level (a primary +
//! secondary `cka_id`). Because each private key is a normal sensitive engine
//! object, KMIP `Get` refuses it through the existing `CKA_SENSITIVE` gate — no
//! new non-extractability code, and no private material ever crosses into
//! `kmip/`.
//!
//! `keygen` returns the two PRIVATE handles + the assembled public wire share.
//! `decapsulate` takes the two PRIVATE handles and reads their values in-HSM
//! (`get_object_value` is an internal read, not an export; the ML-KEM half goes
//! through `native::encrypt::decapsulate`, so `dk` never leaves the engine).
//!
//! ## Combiner (verified vs draft-ietf-tls-ecdhe-mlkem + IANA)
//!
//! The two component shared secrets are combined through the PKCS#11 v3.2
//! derive machinery (`derive::run_combiner` over `CKM_CONCATENATE_BASE_AND_KEY`)
//! — NOT an inline byte concat. All three groups are PURE CONCATENATION
//! (`Concat { finalize: [] }`), order per-variant and load-bearing:
//! - X25519MLKEM768 (0x11EC): `ss_mlkem ‖ ss_x25519`; share `ek_mlkem ‖ x_pub`,
//!   ct `ct_mlkem ‖ eph_x`.
//! - SecP256r1MLKEM768 (0x11EB): `ss_p256 ‖ ss_mlkem`; share `p_pub ‖ ek_mlkem`,
//!   ct `eph_p ‖ ct_mlkem`.
//! - SecP384r1MLKEM1024 (0x11ED): `ss_p384 ‖ ss_mlkem`; share `p_pub ‖ ek_mlkem`,
//!   ct `eph_p ‖ ct_mlkem`.
//!
//! The classical half is an ephemeral-static ECDHE: encapsulation samples a
//! fresh ephemeral against the peer's static public; decapsulation DHs the
//! static secret (read from its handle) against the ephemeral public in the ct.

use ml_kem::kem::Encapsulate;
use ml_kem::{EncodedSizeUser, KemCore, MlKem1024, MlKem768};

use super::derive::{run_combiner, Combiner};
use super::keygen::{generate_ecdh_keypair, generate_ml_kem_keypair, generate_x25519_keypair, EccCurve};
use super::CkRv;
use crate::constants::*;

/// Which hybrid group — selects curve, ML-KEM parameter set, and combine order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hybrid {
    X25519MlKem768,
    SecP256r1MlKem768,
    SecP384r1MlKem1024,
}

// ML-KEM encoded sizes.
const MLKEM768_EK: usize = 1184;
const MLKEM768_CT: usize = 1088;
const MLKEM1024_EK: usize = 1568;
const MLKEM1024_CT: usize = 1568;
const X25519_LEN: usize = 32;
const P256_PUB: usize = 65;
const P384_PUB: usize = 97;

/// Result of a hybrid keygen: the public wire share plus the two
/// NON-EXTRACTABLE private-key HANDLES (classical + ML-KEM). The KMIP layer
/// records both handles' `cka_id`s on the one KMIP object.
pub struct HybridKeyGen {
    pub public: Vec<u8>,
    pub mlkem_priv: u32,
    pub classical_priv: u32,
}

/// Output of an encapsulation.
pub struct Encapsulated {
    pub ciphertext: Vec<u8>,
    pub shared_secret: Vec<u8>,
}

/// Generate a hybrid keypair as TWO non-extractable engine keypairs. The ML-KEM
/// keypair is created under `mlkem_cka_id`, the classical under
/// `classical_cka_id` (they MUST differ so the KMIP layer can resolve each
/// private handle independently). Returns the assembled public wire share and
/// the two private handles; the transient public engine handles are destroyed
/// after their bytes are read into the share (the share is the canonical
/// public, stored by KMIP as the public object's material).
pub fn keygen(
    session: u32,
    hybrid: Hybrid,
    mlkem_cka_id: &[u8],
    classical_cka_id: &[u8],
) -> Result<HybridKeyGen, CkRv> {
    let mlkem_ps = match hybrid {
        Hybrid::SecP384r1MlKem1024 => CKP_ML_KEM_1024,
        _ => CKP_ML_KEM_768,
    };
    let (mlkem_pub, mlkem_priv) =
        generate_ml_kem_keypair(session, mlkem_ps, mlkem_cka_id, "hybrid-mlkem")?;
    let ek = crate::state::get_object_value(mlkem_pub).ok_or(CKR_FUNCTION_FAILED)?;

    let (classical_pub_h, classical_priv, classical_pub) = match hybrid {
        Hybrid::X25519MlKem768 => {
            let (pub_h, priv_h) =
                generate_x25519_keypair(session, classical_cka_id, "hybrid-x25519")?;
            let x_pub = crate::state::get_object_value(pub_h).ok_or(CKR_FUNCTION_FAILED)?;
            (pub_h, priv_h, x_pub)
        }
        Hybrid::SecP256r1MlKem768 => {
            let (pub_h, priv_h) =
                generate_ecdh_keypair(session, EccCurve::P256, classical_cka_id, "hybrid-p256")?;
            let p_pub = crate::state::get_ec_point_sec1(pub_h).ok_or(CKR_FUNCTION_FAILED)?;
            (pub_h, priv_h, p_pub)
        }
        Hybrid::SecP384r1MlKem1024 => {
            let (pub_h, priv_h) =
                generate_ecdh_keypair(session, EccCurve::P384, classical_cka_id, "hybrid-p384")?;
            let p_pub = crate::state::get_ec_point_sec1(pub_h).ok_or(CKR_FUNCTION_FAILED)?;
            (pub_h, priv_h, p_pub)
        }
    };

    // Assemble the wire share in the per-variant component order.
    let public = match hybrid {
        Hybrid::X25519MlKem768 => [ek.as_slice(), classical_pub.as_slice()].concat(),
        Hybrid::SecP256r1MlKem768 | Hybrid::SecP384r1MlKem1024 => {
            [classical_pub.as_slice(), ek.as_slice()].concat()
        }
    };

    // The engine public handles are not needed after assembling the share.
    let _ = crate::native::object::destroy_object(session, mlkem_pub);
    let _ = crate::native::object::destroy_object(session, classical_pub_h);

    Ok(HybridKeyGen { public, mlkem_priv, classical_priv })
}

/// Encapsulate to a peer's public wire share. Uses only the peer's public + a
/// fresh ephemeral ECDHE — no long-term private key, hence no handle.
pub fn encapsulate(session: u32, hybrid: Hybrid, peer_public: &[u8]) -> Result<Encapsulated, CkRv> {
    let mut rng = rand::rngs::OsRng;
    match hybrid {
        Hybrid::X25519MlKem768 => {
            if peer_public.len() != MLKEM768_EK + X25519_LEN {
                return Err(CKR_ARGUMENTS_BAD);
            }
            let (ek_b, x_pub_b) = peer_public.split_at(MLKEM768_EK);
            let ek = mlkem768_ek(ek_b)?;
            let (ct_mlkem, ss_mlkem) = ek.encapsulate(&mut rng).map_err(|_| CKR_FUNCTION_FAILED)?;
            let x_peer: [u8; 32] = x_pub_b.try_into().map_err(|_| CKR_ARGUMENTS_BAD)?;
            let eph = x25519_dalek::EphemeralSecret::random_from_rng(&mut rng);
            let eph_pub = x25519_dalek::PublicKey::from(&eph);
            let ss_x = eph.diffie_hellman(&x25519_dalek::PublicKey::from(x_peer));
            Ok(Encapsulated {
                ciphertext: [ct_mlkem.as_slice(), eph_pub.as_bytes().as_slice()].concat(),
                shared_secret: combine(session, &[ss_mlkem.as_slice(), ss_x.as_bytes()])?,
            })
        }
        Hybrid::SecP256r1MlKem768 => {
            if peer_public.len() != P256_PUB + MLKEM768_EK {
                return Err(CKR_ARGUMENTS_BAD);
            }
            let (p_pub_b, ek_b) = peer_public.split_at(P256_PUB);
            let ek = mlkem768_ek(ek_b)?;
            let (ct_mlkem, ss_mlkem) = ek.encapsulate(&mut rng).map_err(|_| CKR_FUNCTION_FAILED)?;
            let peer_pub = p256::PublicKey::from_sec1_bytes(p_pub_b).map_err(|_| CKR_ARGUMENTS_BAD)?;
            let eph = p256::ecdh::EphemeralSecret::random(&mut rng);
            let eph_pub = p256::EncodedPoint::from(eph.public_key());
            let ss_p = eph.diffie_hellman(&peer_pub);
            Ok(Encapsulated {
                ciphertext: [eph_pub.as_bytes(), ct_mlkem.as_slice()].concat(),
                shared_secret: combine(session, &[ss_p.raw_secret_bytes().as_slice(), ss_mlkem.as_slice()])?,
            })
        }
        Hybrid::SecP384r1MlKem1024 => {
            if peer_public.len() != P384_PUB + MLKEM1024_EK {
                return Err(CKR_ARGUMENTS_BAD);
            }
            let (p_pub_b, ek_b) = peer_public.split_at(P384_PUB);
            let ek = mlkem1024_ek(ek_b)?;
            let (ct_mlkem, ss_mlkem) = ek.encapsulate(&mut rng).map_err(|_| CKR_FUNCTION_FAILED)?;
            let peer_pub = p384::PublicKey::from_sec1_bytes(p_pub_b).map_err(|_| CKR_ARGUMENTS_BAD)?;
            let eph = p384::ecdh::EphemeralSecret::random(&mut rng);
            let eph_pub = p384::EncodedPoint::from(eph.public_key());
            let ss_p = eph.diffie_hellman(&peer_pub);
            Ok(Encapsulated {
                ciphertext: [eph_pub.as_bytes(), ct_mlkem.as_slice()].concat(),
                shared_secret: combine(session, &[ss_p.raw_secret_bytes().as_slice(), ss_mlkem.as_slice()])?,
            })
        }
    }
}

/// Decapsulate using the two NON-EXTRACTABLE private handles. The ML-KEM half
/// goes through `native::encrypt::decapsulate` (reads `dk` in-HSM, honours the
/// `CKA_DECAPSULATE` gate); the classical scalar is read from its handle and
/// DH'd against the ephemeral public in the ciphertext. Never exports either
/// private key.
pub fn decapsulate(
    session: u32,
    hybrid: Hybrid,
    mlkem_priv: u32,
    classical_priv: u32,
    ciphertext: &[u8],
) -> Result<Vec<u8>, CkRv> {
    // Isolation gate on the classical half's handle. NOTE: the ML-KEM
    // half is gated TRANSITIVELY (native::encrypt::decapsulate below is
    // gated in encrypt.rs) — this direct fetch is the one place a
    // transitive gate is NOT enough, since this function reads
    // classical_priv's CKA_VALUE itself rather than delegating.
    let access = crate::state::resolve_session_access(session).map_err(|_| CKR_KEY_HANDLE_INVALID)?;
    let scalar = crate::state::with_object_checked(&access, classical_priv, crate::state::get_object_value_from)
        .map_err(|_| CKR_KEY_HANDLE_INVALID)?
        .ok_or(CKR_KEY_HANDLE_INVALID)?;
    match hybrid {
        Hybrid::X25519MlKem768 => {
            if ciphertext.len() != MLKEM768_CT + X25519_LEN {
                return Err(CKR_ARGUMENTS_BAD);
            }
            let (ct_mlkem_b, eph_x_b) = ciphertext.split_at(MLKEM768_CT);
            let ss_mlkem = crate::native::encrypt::decapsulate(session, mlkem_priv, CKM_ML_KEM, ct_mlkem_b)?;
            let x_sec: [u8; 32] = scalar.as_slice().try_into().map_err(|_| CKR_KEY_HANDLE_INVALID)?;
            let eph_pub: [u8; 32] = eph_x_b.try_into().map_err(|_| CKR_ARGUMENTS_BAD)?;
            let secret = x25519_dalek::StaticSecret::from(x_sec);
            let ss_x = secret.diffie_hellman(&x25519_dalek::PublicKey::from(eph_pub));
            combine(session, &[ss_mlkem.as_slice(), ss_x.as_bytes()])
        }
        Hybrid::SecP256r1MlKem768 => {
            if ciphertext.len() != P256_PUB + MLKEM768_CT {
                return Err(CKR_ARGUMENTS_BAD);
            }
            let (eph_p_b, ct_mlkem_b) = ciphertext.split_at(P256_PUB);
            let ss_mlkem = crate::native::encrypt::decapsulate(session, mlkem_priv, CKM_ML_KEM, ct_mlkem_b)?;
            let arr: [u8; 32] = scalar.as_slice().try_into().map_err(|_| CKR_KEY_HANDLE_INVALID)?;
            let secret = p256::SecretKey::from_bytes((&arr).into()).map_err(|_| CKR_KEY_HANDLE_INVALID)?;
            let eph_pub = p256::PublicKey::from_sec1_bytes(eph_p_b).map_err(|_| CKR_ARGUMENTS_BAD)?;
            let ss_p = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), eph_pub.as_affine());
            combine(session, &[ss_p.raw_secret_bytes().as_slice(), ss_mlkem.as_slice()])
        }
        Hybrid::SecP384r1MlKem1024 => {
            if ciphertext.len() != P384_PUB + MLKEM1024_CT {
                return Err(CKR_ARGUMENTS_BAD);
            }
            let (eph_p_b, ct_mlkem_b) = ciphertext.split_at(P384_PUB);
            let ss_mlkem = crate::native::encrypt::decapsulate(session, mlkem_priv, CKM_ML_KEM, ct_mlkem_b)?;
            let arr: [u8; 48] = scalar.as_slice().try_into().map_err(|_| CKR_KEY_HANDLE_INVALID)?;
            let secret = p384::SecretKey::from_bytes((&arr).into()).map_err(|_| CKR_KEY_HANDLE_INVALID)?;
            let eph_pub = p384::PublicKey::from_sec1_bytes(eph_p_b).map_err(|_| CKR_ARGUMENTS_BAD)?;
            let ss_p = p384::ecdh::diffie_hellman(secret.to_nonzero_scalar(), eph_pub.as_affine());
            combine(session, &[ss_p.raw_secret_bytes().as_slice(), ss_mlkem.as_slice()])
        }
    }
}

/// Combine the two component shared secrets through the PKCS#11 derive
/// machinery. All three TLS groups are pure concatenation.
fn combine(session: u32, components: &[&[u8]]) -> Result<Vec<u8>, CkRv> {
    run_combiner(session, components, &Combiner::Concat { finalize: vec![] })
}

// ── ML-KEM encapsulation-key helpers (encapsulate side, operates on peer bytes) ─
fn mlkem768_ek(ek_b: &[u8]) -> Result<<MlKem768 as KemCore>::EncapsulationKey, CkRv> {
    let arr = ml_kem::Encoded::<<MlKem768 as KemCore>::EncapsulationKey>::try_from(ek_b)
        .map_err(|_| CKR_ARGUMENTS_BAD)?;
    Ok(<MlKem768 as KemCore>::EncapsulationKey::from_bytes(&arr))
}
fn mlkem1024_ek(ek_b: &[u8]) -> Result<<MlKem1024 as KemCore>::EncapsulationKey, CkRv> {
    let arr = ml_kem::Encoded::<<MlKem1024 as KemCore>::EncapsulationKey>::try_from(ek_b)
        .map_err(|_| CKR_ARGUMENTS_BAD)?;
    Ok(<MlKem1024 as KemCore>::EncapsulationKey::from_bytes(&arr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::test_lock;

    fn fresh_session() -> u32 {
        let _ = crate::native::session::finalize();
        crate::native::session::init().expect("engine init");
        crate::native::session::bootstrap_default_token(0, "so", "user", "hybrid-test")
            .expect("bootstrap session")
    }

    /// Full two-handle round trip for each variant: keygen registers two
    /// non-extractable private handles; encapsulate(public) and
    /// decapsulate(both handles) agree on the shared secret. Also asserts the
    /// combined SS length. (Self-consistency — interop-vs-OpenSSL is an
    /// out-of-scope follow-on per the revised plan, Correction 3.)
    fn round_trip(hybrid: Hybrid, ss_len: usize) {
        let session = fresh_session();
        let kg = keygen(session, hybrid, b"hyb-mlkem", b"hyb-classical").expect("keygen");
        let enc = encapsulate(session, hybrid, &kg.public).expect("encapsulate");
        assert_eq!(enc.shared_secret.len(), ss_len, "combined SS length");
        let dec = decapsulate(session, hybrid, kg.mlkem_priv, kg.classical_priv, &enc.ciphertext)
            .expect("decapsulate");
        assert_eq!(enc.shared_secret, dec, "encapsulator and decapsulator must agree");
    }

    #[test]
    fn x25519_mlkem768_two_handle_round_trip() {
        let _g = test_lock::acquire();
        round_trip(Hybrid::X25519MlKem768, 64);
    }

    #[test]
    fn secp256r1_mlkem768_two_handle_round_trip() {
        let _g = test_lock::acquire();
        round_trip(Hybrid::SecP256r1MlKem768, 64);
    }

    #[test]
    fn secp384r1_mlkem1024_two_handle_round_trip() {
        let _g = test_lock::acquire();
        round_trip(Hybrid::SecP384r1MlKem1024, 80);
    }

    /// THE security property: BOTH private handles keygen registers are
    /// non-extractable / sensitive, so KMIP Get refuses each of them.
    #[test]
    fn both_private_handles_are_non_extractable() {
        use crate::state::get_object_attr_bytes;
        let _g = test_lock::acquire();
        let session = fresh_session();
        let kg = keygen(session, Hybrid::X25519MlKem768, b"hyb-m", b"hyb-c").expect("keygen");
        for h in [kg.mlkem_priv, kg.classical_priv] {
            assert_eq!(get_object_attr_bytes(h, CKA_EXTRACTABLE), Some(vec![0x00]), "non-extractable");
            assert_eq!(get_object_attr_bytes(h, CKA_SENSITIVE), Some(vec![0x01]), "sensitive");
        }
    }

    #[test]
    fn decapsulate_rejects_wrong_length_ciphertext() {
        let _g = test_lock::acquire();
        let session = fresh_session();
        let kg = keygen(session, Hybrid::X25519MlKem768, b"hyb-m2", b"hyb-c2").expect("keygen");
        assert_eq!(
            decapsulate(session, Hybrid::X25519MlKem768, kg.mlkem_priv, kg.classical_priv, &[0u8; 10]),
            Err(CKR_ARGUMENTS_BAD)
        );
    }
}
