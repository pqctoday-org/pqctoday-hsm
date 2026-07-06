//! ECDH / X25519 / X448 key agreement — the shared-secret half of a KMIP
//! `DeriveKey` with `DerivationMethod = Asymmetric Key` (KMIP 3.0 §7.13).
//!
//! Reads the caller's STATIC private key from its non-extractable handle
//! in-HSM (`get_object_value` is an internal read, not an export) and computes
//! the Diffie-Hellman shared secret against the peer's public key. The private
//! scalar never leaves the engine; only the resulting shared secret is
//! returned (that value becomes the caller's newly derived key material).

use super::CkRv;
use crate::constants::*;
use crate::state::{get_object_attr_u32, get_object_value};

/// Compute the ECDH shared secret between the private key at `priv_handle` and
/// `peer_public`. The curve is inferred from the private key's PKCS#11 type +
/// scalar length (both set by the engine's keygen):
/// - `CKK_EC_MONTGOMERY`, 32-byte scalar → X25519 (peer = raw 32-byte point)
/// - `CKK_EC_MONTGOMERY`, 56-byte scalar → X448 (peer = raw 56-byte point)
/// - `CKK_EC`, 32-byte scalar → P-256 (peer = SEC1 uncompressed, 65 bytes)
/// - `CKK_EC`, 48-byte scalar → P-384 (peer = SEC1 uncompressed, 97 bytes)
///
/// Returns `CKR_KEY_TYPE_INCONSISTENT` for any other key, `CKR_ARGUMENTS_BAD`
/// for a malformed peer public.
pub fn ecdh_agree(_session: u32, priv_handle: u32, peer_public: &[u8]) -> Result<Vec<u8>, CkRv> {
    let key_type = get_object_attr_u32(priv_handle, CKA_KEY_TYPE).ok_or(CKR_KEY_HANDLE_INVALID)?;
    let scalar = get_object_value(priv_handle).ok_or(CKR_KEY_HANDLE_INVALID)?;
    match (key_type, scalar.len()) {
        // ── X25519 (RFC 7748) ───────────────────────────────────────────────
        (CKK_EC_MONTGOMERY, 32) => {
            let sk: [u8; 32] = scalar.as_slice().try_into().map_err(|_| CKR_KEY_HANDLE_INVALID)?;
            let peer: [u8; 32] = peer_public.try_into().map_err(|_| CKR_ARGUMENTS_BAD)?;
            let secret = x25519_dalek::StaticSecret::from(sk);
            let ss = secret.diffie_hellman(&x25519_dalek::PublicKey::from(peer));
            Ok(ss.as_bytes().to_vec())
        }
        // ── X448 (RFC 7748) ─────────────────────────────────────────────────
        (CKK_EC_MONTGOMERY, 56) => {
            let sk: [u8; 56] = scalar.as_slice().try_into().map_err(|_| CKR_KEY_HANDLE_INVALID)?;
            let peer: [u8; 56] = peer_public.try_into().map_err(|_| CKR_ARGUMENTS_BAD)?;
            // x448::x448(scalar, point) performs Extract+DH, None on invalid point.
            let ss = x448::x448(sk, peer).ok_or(CKR_ARGUMENTS_BAD)?;
            Ok(ss.to_vec())
        }
        // ── NIST P-256 ──────────────────────────────────────────────────────
        (CKK_EC, 32) => {
            let arr: [u8; 32] = scalar.as_slice().try_into().map_err(|_| CKR_KEY_HANDLE_INVALID)?;
            let secret = p256::SecretKey::from_bytes((&arr).into()).map_err(|_| CKR_KEY_HANDLE_INVALID)?;
            let peer = p256::PublicKey::from_sec1_bytes(peer_public).map_err(|_| CKR_ARGUMENTS_BAD)?;
            let ss = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
            Ok(ss.raw_secret_bytes().to_vec())
        }
        // ── NIST P-384 ──────────────────────────────────────────────────────
        (CKK_EC, 48) => {
            let arr: [u8; 48] = scalar.as_slice().try_into().map_err(|_| CKR_KEY_HANDLE_INVALID)?;
            let secret = p384::SecretKey::from_bytes((&arr).into()).map_err(|_| CKR_KEY_HANDLE_INVALID)?;
            let peer = p384::PublicKey::from_sec1_bytes(peer_public).map_err(|_| CKR_ARGUMENTS_BAD)?;
            let ss = p384::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
            Ok(ss.raw_secret_bytes().to_vec())
        }
        // ── NIST P-521 (66-byte scalar) ─────────────────────────────────────
        (CKK_EC, 66) => {
            let secret = p521::SecretKey::from_slice(&scalar).map_err(|_| CKR_KEY_HANDLE_INVALID)?;
            let peer = p521::PublicKey::from_sec1_bytes(peer_public).map_err(|_| CKR_ARGUMENTS_BAD)?;
            let ss = p521::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
            Ok(ss.raw_secret_bytes().to_vec())
        }
        _ => Err(CKR_KEY_TYPE_INCONSISTENT),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::keygen::{generate_ecdh_keypair, generate_x25519_keypair, generate_x448_keypair, EccCurve};
    use crate::native::test_lock;
    use crate::state::{get_ec_point_sec1, get_object_value as gov};

    fn fresh_session() -> u32 {
        let _ = crate::native::session::finalize();
        crate::native::session::init().expect("engine init");
        crate::native::session::bootstrap_default_token(0, "so", "user", "agree-test")
            .expect("bootstrap session")
    }

    /// ECDH is symmetric: agree(A_priv, B_pub) == agree(B_priv, A_pub). This is
    /// the property every key-agreement scheme must satisfy, checked in-engine
    /// against two freshly generated keypairs. `pub_of` reads the public share
    /// the way the KMIP layer would.
    fn symmetric(genfn: impl Fn(u32, &[u8]) -> (u32, u32), pub_of: impl Fn(u32) -> Vec<u8>) {
        let session = fresh_session();
        let (pub_a, priv_a) = genfn(session, b"a");
        let (pub_b, priv_b) = genfn(session, b"b");
        let ss_ab = ecdh_agree(session, priv_a, &pub_of(pub_b)).expect("A agrees with B");
        let ss_ba = ecdh_agree(session, priv_b, &pub_of(pub_a)).expect("B agrees with A");
        assert_eq!(ss_ab, ss_ba, "both parties derive the same shared secret");
        assert!(!ss_ab.iter().all(|&b| b == 0), "shared secret is non-trivial");
    }

    #[test]
    fn x25519_agreement_is_symmetric() {
        let _g = test_lock::acquire();
        symmetric(
            |s, id| generate_x25519_keypair(s, id, "x").unwrap(),
            |h| gov(h).unwrap(), // X25519 public is the raw 32-byte point in CKA_VALUE
        );
    }

    #[test]
    fn x448_agreement_is_symmetric() {
        let _g = test_lock::acquire();
        symmetric(
            |s, id| generate_x448_keypair(s, id, "x").unwrap(),
            |h| gov(h).unwrap(), // X448 public is the raw 56-byte point in CKA_VALUE
        );
    }

    #[test]
    fn p256_agreement_is_symmetric() {
        let _g = test_lock::acquire();
        symmetric(
            |s, id| generate_ecdh_keypair(s, EccCurve::P256, id, "p").unwrap(),
            |h| get_ec_point_sec1(h).unwrap(), // NIST public is SEC1
        );
    }

    #[test]
    fn p521_agreement_is_symmetric() {
        let _g = test_lock::acquire();
        symmetric(
            |s, id| generate_ecdh_keypair(s, EccCurve::P521, id, "p").unwrap(),
            |h| get_ec_point_sec1(h).unwrap(),
        );
    }

    #[test]
    fn agree_rejects_wrong_length_peer() {
        let _g = test_lock::acquire();
        let session = fresh_session();
        let (_pub, priv_h) = generate_x25519_keypair(session, b"z", "x").unwrap();
        assert_eq!(ecdh_agree(session, priv_h, &[0u8; 10]), Err(CKR_ARGUMENTS_BAD));
    }
}
