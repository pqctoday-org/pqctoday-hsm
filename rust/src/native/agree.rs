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
use crate::crypto::handlers::{CURVE_K256, CURVE_P256, CURVE_P384, CURVE_P521};
use crate::state::{
    get_object_attr_u32_from, get_object_value_from, resolve_session_access, with_object_checked,
};

/// Compute the ECDH shared secret between the private key at `priv_handle` and
/// `peer_public`. The curve is inferred from the private key's PKCS#11 type +
/// scalar length (both set by the engine's keygen):
/// - `CKK_EC_MONTGOMERY`, 32-byte scalar → X25519 (peer = raw 32-byte point)
/// - `CKK_EC_MONTGOMERY`, 56-byte scalar → X448 (peer = raw 56-byte point)
/// - `CKK_EC` → the key's stored curve: P-256, P-384, P-521 or secp256k1
///   (peer = SEC1). Only a key with no stored curve falls back to the
///   scalar length (32 → P-256, 48 → P-384, 66 → P-521).
///
/// Returns `CKR_KEY_TYPE_INCONSISTENT` for any other key, `CKR_ARGUMENTS_BAD`
/// for a malformed peer public.
pub fn ecdh_agree(session: u32, priv_handle: u32, peer_public: &[u8]) -> Result<Vec<u8>, CkRv> {
    // Isolation gate folded into the existing single lookup. This
    // function's pre-existing error vocabulary (CKR_KEY_HANDLE_INVALID,
    // the derive-context code C_DeriveKey callers expect) is preserved
    // for missing/cross-slot/not-logged-in alike — the gate's generic
    // CKR_OBJECT_HANDLE_INVALID is remapped so callers see no behavior
    // change, while cross-tenant access now denies exactly like a
    // missing handle (same anti-oracle property, this function's code).
    let access = resolve_session_access(session)?;
    let (allowed, key_type, scalar, curve_id) = with_object_checked(&access, priv_handle, |attrs| {
        (
            // S12 (2026-08-13) — §4.8 Table 13. THIS is the KMIP seam:
            // kmip/src/ops/derive_key.rs calls straight into this function,
            // so a mechanism-restricted key was enforced over PKCS#11 and
            // unenforced over KMIP. Checked inside the SAME borrow the
            // isolation gate already takes, so no extra lock traffic.
            crate::state::check_mechanism_allowed_from(attrs, CKM_ECDH1_DERIVE),
            get_object_attr_u32_from(attrs, CKA_KEY_TYPE),
            get_object_value_from(attrs),
            // The curve decoded from CKA_EC_PARAMS when the key was created
            // (0 when unknown, e.g. legacy metadata).
            crate::state::get_object_param_set_from(attrs),
        )
    })
    .map_err(|_| CKR_KEY_HANDLE_INVALID)?;
    allowed?;
    let key_type = key_type.ok_or(CKR_KEY_HANDLE_INVALID)?;
    let scalar = scalar.ok_or(CKR_KEY_HANDLE_INVALID)?;
    // 4.E (2026-09-27): a CKK_EC key's curve is the one stored on the key,
    // not a guess from the scalar's length. Every 32-byte scalar used to run
    // as P-256, so a secp256k1 key (imported, or derived via BIP32) failed
    // with CKR_ARGUMENTS_BAD over KMIP while C_DeriveKey — which reads the
    // stored curve — derived correctly. A stored curve that disagrees with
    // the scalar length is refused rather than guessed at. Keys with no
    // stored curve (0) keep the length-based NIST mapping below.
    if key_type == CKK_EC && curve_id == CURVE_K256 {
        let secret = k256::SecretKey::from_slice(&scalar).map_err(|_| CKR_KEY_HANDLE_INVALID)?;
        let peer = k256::PublicKey::from_sec1_bytes(peer_public).map_err(|_| CKR_ARGUMENTS_BAD)?;
        let ss = k256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
        return Ok(ss.raw_secret_bytes().to_vec());
    }
    if key_type == CKK_EC
        && curve_id != 0
        && !matches!((curve_id, scalar.len()), (CURVE_P256, 32) | (CURVE_P384, 48) | (CURVE_P521, 66))
    {
        return Err(CKR_KEY_TYPE_INCONSISTENT);
    }
    // Native fast path (AWS-LC) for the three NIST curves — constant-time and
    // assembly-optimised. X25519/X448 stay on dalek/x448 (AWS-LC's agreement
    // API here covers only the NIST curves we route). `None` falls through to
    // the pure-Rust match below unchanged. See crypto::awslc.
    #[cfg(not(target_arch = "wasm32"))]
    if key_type == CKK_EC {
        let curve = match scalar.len() {
            32 => CURVE_P256,
            48 => CURVE_P384,
            66 => CURVE_P521,
            _ => 0,
        };
        if curve != 0 {
            if let Some(r) = crate::crypto::awslc::ecdh(curve, &scalar, peer_public) {
                // AWS-LC surfaces a bad peer point as the generic failure code;
                // remap to this function's ARGUMENTS_BAD to match the pure-Rust
                // branches' anti-oracle behaviour.
                return r.map_err(|_| CKR_ARGUMENTS_BAD);
            }
        }
    }
    match (key_type, scalar.len()) {
        // ── X25519 (RFC 7748) ───────────────────────────────────────────────
        (CKK_EC_MONTGOMERY, 32) => {
            let sk: [u8; 32] = scalar.as_slice().try_into().map_err(|_| CKR_KEY_HANDLE_INVALID)?;
            let peer: [u8; 32] = peer_public.try_into().map_err(|_| CKR_ARGUMENTS_BAD)?;
            let secret = x25519_dalek::StaticSecret::from(sk);
            let ss = crate::crypto::handlers::x25519_contributory(secret.diffie_hellman(&x25519_dalek::PublicKey::from(peer)))
                .ok_or(CKR_ARGUMENTS_BAD)?;
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
    // AWS-LC and the pure-Rust p256 path must derive the IDENTICAL ECDH
    // shared secret (both yield the x-coordinate). If the fast path returned
    // a different encoding, every derived key would silently diverge.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn awslc_ecdh_p256_matches_pure_rust() {
        // Two P-256 scalars; compute A·B two ways and require equality.
        let a = [0x22u8; 32];
        let b_sk = p256::SecretKey::from_bytes((&[0x33u8; 32]).into()).unwrap();
        let b_pub = b_sk.public_key().to_sec1_bytes().to_vec();
        // pure Rust: a_priv · b_pub
        let a_sk = p256::SecretKey::from_bytes((&a).into()).unwrap();
        let peer = p256::PublicKey::from_sec1_bytes(&b_pub).unwrap();
        let pure = p256::ecdh::diffie_hellman(a_sk.to_nonzero_scalar(), peer.as_affine())
            .raw_secret_bytes().to_vec();
        // AWS-LC: same inputs
        let fast = crate::crypto::awslc::ecdh(CURVE_P256, &a, &b_pub)
            .expect("awslc handles P-256").unwrap();
        assert_eq!(pure, fast, "AWS-LC and p256 must agree on the ECDH secret");
        assert_eq!(fast.len(), 32, "P-256 ECDH secret is the 32-byte x-coordinate");
    }

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

    /// 4.E: the curve used to be inferred from the scalar's LENGTH, so every
    /// 32-byte CKK_EC key ran as P-256 — including secp256k1 keys, which reach
    /// the engine through import and BIP32 derivation. A secp256k1 peer point
    /// is not on P-256, so KMIP DeriveKey failed with CKR_ARGUMENTS_BAD, while
    /// C_DeriveKey (which reads the stored curve) derived correctly. The
    /// expected secret is computed independently with the k256 crate.
    #[test]
    fn secp256k1_imported_key_agrees_on_its_own_curve() {
        let _g = test_lock::acquire();
        let session = fresh_session();
        const OID_K256: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a];
        let d = [0x11u8; 32];
        let (class, kt) = (CKO_PRIVATE_KEY as usize, CKK_EC as usize);
        let us = std::mem::size_of::<usize>();
        let attrs: [(u32, *const u8, usize); 6] = [
            (CKA_CLASS, &class as *const _ as *const u8, us),
            (CKA_KEY_TYPE, &kt as *const _ as *const u8, us),
            (CKA_TOKEN, [0u8].as_ptr(), 1),
            (CKA_DERIVE, [1u8].as_ptr(), 1),
            (CKA_EC_PARAMS, OID_K256.as_ptr(), OID_K256.len()),
            (CKA_VALUE, d.as_ptr(), d.len()),
        ];
        let tmpl: Vec<usize> = attrs.iter().flat_map(|(t, p, l)| [*t as usize, *p as usize, *l]).collect();
        let mut h_priv = 0u32;
        assert_eq!(
            crate::ffi::C_CreateObject(session, tmpl.as_ptr() as *mut u8, attrs.len() as u32, &mut h_priv),
            CKR_OK
        );
        let peer_sk = k256::SecretKey::from_bytes((&[0x22u8; 32]).into()).unwrap();
        let peer_pub = peer_sk.public_key().to_sec1_bytes().to_vec();
        let want = k256::ecdh::diffie_hellman(
            peer_sk.to_nonzero_scalar(),
            k256::SecretKey::from_bytes((&d).into()).unwrap().public_key().as_affine(),
        );
        let got = ecdh_agree(session, h_priv, &peer_pub).expect("secp256k1 agreement");
        assert_eq!(got, want.raw_secret_bytes().to_vec());
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
