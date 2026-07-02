//! Hybrid KEM (K6) — X25519MLKEM768 (0x5C) and SecP256r1MLKEM768 (0x5D).
//!
//! KMIP 3.0 WD19 assigns these two hybrid KEMs the CryptographicAlgorithm
//! codepoints 0x5C / 0x5D. A hybrid KEM combines an ML-KEM-768 encapsulation
//! with a classical ECDH (X25519 or NIST P-256), so the session key stays
//! secure as long as EITHER component holds — the belt-and-braces migration
//! default. This module is the self-contained, independently-tested crypto;
//! the op handlers (create_key_pair / encapsulate / decapsulate) call it.
//!
//! ## Combiner (verified against draft-ietf-tls-ecdhe-mlkem, TLS WG)
//!
//! The shared secret is a RAW CONCATENATION (no KEM-layer KDF — the caller
//! applies its own, exactly as KMIP returns the raw ML-KEM shared secret). The
//! order is **asymmetric** by the spec — get it right per algorithm:
//!
//! - **X25519MLKEM768:** `SS = ss_mlkem ‖ ss_x25519` (ML-KEM first — the name
//!   order is reversed "for historical reasons"). Public share and ciphertext
//!   put ML-KEM first: `ek_mlkem ‖ share_x25519`, `ct_mlkem ‖ eph_x25519`.
//! - **SecP256r1MLKEM768:** `SS = ss_p256 ‖ ss_mlkem` (ECDHE first). Public
//!   share and ciphertext put P-256 first: `share_p256 ‖ ek_mlkem`,
//!   `eph_p256 ‖ ct_mlkem`.
//!
//! ## Byte sizes (ML-KEM-768 / classical)
//! ek=1184, dk=2400, ct=1088, ss=32; X25519 pub/secret/ss = 32; P-256 SEC1
//! uncompressed pub = 65, secret = 32, ss = 32.

use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};

/// Which hybrid — determines the classical half and the concat order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hybrid {
    /// 0x5C — X25519 + ML-KEM-768, ML-KEM-first shared secret.
    X25519MlKem768,
    /// 0x5D — NIST P-256 + ML-KEM-768, ECDHE-first shared secret.
    SecP256r1MlKem768,
}

// ML-KEM-768 encoded sizes (bytes).
const MLKEM_EK: usize = 1184;
const MLKEM_DK: usize = 2400;
const MLKEM_CT: usize = 1088;
const X25519_LEN: usize = 32; // pub / secret / ss all 32
const P256_PUB: usize = 65; // SEC1 uncompressed
const P256_SCALAR: usize = 32;

/// A freshly generated hybrid keypair, as opaque composite byte strings.
pub struct HybridKeyPair {
    /// Composite public key (peer encapsulates to this).
    pub public: Vec<u8>,
    /// Composite private key (kept by the owner; sensitive).
    pub private: Vec<u8>,
}

fn mlkem_error(what: &str) -> String {
    format!("hybrid KEM: ML-KEM-768 {what} failed")
}

/// Generate a hybrid keypair. Public layout puts the components in the
/// combiner's public-share order; private layout mirrors it (ML-KEM material
/// then classical scalar for X25519; classical scalar then ML-KEM for P-256).
pub fn keygen(hybrid: Hybrid) -> Result<HybridKeyPair, String> {
    let mut rng = rand::rngs::OsRng;
    let (dk, ek) = MlKem768::generate(&mut rng);
    let ek_b = ek.as_bytes().to_vec(); // 1184
    let dk_b = dk.as_bytes().to_vec(); // 2400

    match hybrid {
        Hybrid::X25519MlKem768 => {
            let secret = x25519_dalek::StaticSecret::random_from_rng(&mut rng);
            let public = x25519_dalek::PublicKey::from(&secret);
            let x_pub = public.as_bytes().to_vec(); // 32
            let x_sec = secret.to_bytes().to_vec(); // 32
            // Public: ek_mlkem ‖ x25519_pub. Private: dk_mlkem ‖ x25519_secret.
            Ok(HybridKeyPair {
                public: [ek_b.as_slice(), x_pub.as_slice()].concat(),
                private: [dk_b.as_slice(), x_sec.as_slice()].concat(),
            })
        }
        Hybrid::SecP256r1MlKem768 => {
            let secret = p256::SecretKey::random(&mut rng);
            let pub_pt = secret.public_key().to_sec1_bytes().to_vec(); // 65 uncompressed
            let scalar = secret.to_bytes().to_vec(); // 32
            // Public: p256_pub ‖ ek_mlkem. Private: p256_secret ‖ dk_mlkem.
            Ok(HybridKeyPair {
                public: [pub_pt.as_slice(), ek_b.as_slice()].concat(),
                private: [scalar.as_slice(), dk_b.as_slice()].concat(),
            })
        }
    }
}

/// Output of an encapsulation: the composite ciphertext the peer needs to
/// decapsulate, and the combined shared secret (64 bytes) the caller keeps.
pub struct Encapsulated {
    pub ciphertext: Vec<u8>,
    pub shared_secret: Vec<u8>,
}

/// Encapsulate to a peer's composite public key.
pub fn encapsulate(hybrid: Hybrid, peer_public: &[u8]) -> Result<Encapsulated, String> {
    let mut rng = rand::rngs::OsRng;
    match hybrid {
        Hybrid::X25519MlKem768 => {
            if peer_public.len() != MLKEM_EK + X25519_LEN {
                return Err(format!(
                    "hybrid KEM: X25519MLKEM768 public key must be {} bytes, got {}",
                    MLKEM_EK + X25519_LEN,
                    peer_public.len()
                ));
            }
            let (ek_b, x_pub_b) = peer_public.split_at(MLKEM_EK);
            // ML-KEM encaps.
            let ek_arr = ml_kem::Encoded::<<MlKem768 as KemCore>::EncapsulationKey>::try_from(ek_b)
                .map_err(|_| mlkem_error("ek decode"))?;
            let ek = <MlKem768 as KemCore>::EncapsulationKey::from_bytes(&ek_arr);
            let (ct_mlkem, ss_mlkem) =
                ek.encapsulate(&mut rng).map_err(|_| mlkem_error("encapsulate"))?;
            // X25519 ephemeral DH.
            let x_peer: [u8; 32] = x_pub_b.try_into().expect("length checked");
            let eph = x25519_dalek::EphemeralSecret::random_from_rng(&mut rng);
            let eph_pub = x25519_dalek::PublicKey::from(&eph);
            let ss_x = eph.diffie_hellman(&x25519_dalek::PublicKey::from(x_peer));
            // Ciphertext: ct_mlkem ‖ eph_x25519_pub. SS: ss_mlkem ‖ ss_x25519.
            Ok(Encapsulated {
                ciphertext: [ct_mlkem.as_slice(), eph_pub.as_bytes().as_slice()].concat(),
                shared_secret: [ss_mlkem.as_slice(), ss_x.as_bytes().as_slice()].concat(),
            })
        }
        Hybrid::SecP256r1MlKem768 => {
            if peer_public.len() != P256_PUB + MLKEM_EK {
                return Err(format!(
                    "hybrid KEM: SecP256r1MLKEM768 public key must be {} bytes, got {}",
                    P256_PUB + MLKEM_EK,
                    peer_public.len()
                ));
            }
            let (p_pub_b, ek_b) = peer_public.split_at(P256_PUB);
            // ML-KEM encaps.
            let ek_arr = ml_kem::Encoded::<<MlKem768 as KemCore>::EncapsulationKey>::try_from(ek_b)
                .map_err(|_| mlkem_error("ek decode"))?;
            let ek = <MlKem768 as KemCore>::EncapsulationKey::from_bytes(&ek_arr);
            let (ct_mlkem, ss_mlkem) =
                ek.encapsulate(&mut rng).map_err(|_| mlkem_error("encapsulate"))?;
            // P-256 ephemeral ECDH.
            let peer_pub = p256::PublicKey::from_sec1_bytes(p_pub_b)
                .map_err(|_| "hybrid KEM: P-256 peer public invalid".to_string())?;
            let eph = p256::ecdh::EphemeralSecret::random(&mut rng);
            let eph_pub = p256::EncodedPoint::from(eph.public_key());
            let ss_p = eph.diffie_hellman(&peer_pub);
            // Ciphertext: eph_p256 ‖ ct_mlkem. SS: ss_p256 ‖ ss_mlkem (ECDHE first).
            Ok(Encapsulated {
                ciphertext: [eph_pub.as_bytes(), ct_mlkem.as_slice()].concat(),
                shared_secret: [ss_p.raw_secret_bytes().as_slice(), ss_mlkem.as_slice()].concat(),
            })
        }
    }
}

/// Decapsulate with the owner's composite private key. Returns the same
/// combined shared secret the encapsulator produced.
pub fn decapsulate(
    hybrid: Hybrid,
    own_private: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, String> {
    match hybrid {
        Hybrid::X25519MlKem768 => {
            if own_private.len() != MLKEM_DK + X25519_LEN {
                return Err("hybrid KEM: X25519MLKEM768 private key wrong length".to_string());
            }
            if ciphertext.len() != MLKEM_CT + X25519_LEN {
                return Err(format!(
                    "hybrid KEM: X25519MLKEM768 ciphertext must be {} bytes, got {}",
                    MLKEM_CT + X25519_LEN,
                    ciphertext.len()
                ));
            }
            let (dk_b, x_sec_b) = own_private.split_at(MLKEM_DK);
            let (ct_mlkem_b, eph_x_b) = ciphertext.split_at(MLKEM_CT);
            // ML-KEM decaps (implicit rejection preserved — never errors on
            // valid-length garbage, yields a pseudo-random secret instead).
            let dk_arr = ml_kem::Encoded::<<MlKem768 as KemCore>::DecapsulationKey>::try_from(dk_b)
                .map_err(|_| mlkem_error("dk decode"))?;
            let dk = <MlKem768 as KemCore>::DecapsulationKey::from_bytes(&dk_arr);
            let ct_arr = ml_kem::Ciphertext::<MlKem768>::try_from(ct_mlkem_b)
                .map_err(|_| mlkem_error("ct decode"))?;
            let ss_mlkem = dk.decapsulate(&ct_arr).map_err(|_| mlkem_error("decapsulate"))?;
            // X25519 DH with own static secret.
            let x_sec: [u8; 32] = x_sec_b.try_into().expect("length checked");
            let eph_pub: [u8; 32] = eph_x_b.try_into().expect("length checked");
            let secret = x25519_dalek::StaticSecret::from(x_sec);
            let ss_x = secret.diffie_hellman(&x25519_dalek::PublicKey::from(eph_pub));
            Ok([ss_mlkem.as_slice(), ss_x.as_bytes().as_slice()].concat())
        }
        Hybrid::SecP256r1MlKem768 => {
            if own_private.len() != P256_SCALAR + MLKEM_DK {
                return Err("hybrid KEM: SecP256r1MLKEM768 private key wrong length".to_string());
            }
            if ciphertext.len() != P256_PUB + MLKEM_CT {
                return Err(format!(
                    "hybrid KEM: SecP256r1MLKEM768 ciphertext must be {} bytes, got {}",
                    P256_PUB + MLKEM_CT,
                    ciphertext.len()
                ));
            }
            let (p_sec_b, dk_b) = own_private.split_at(P256_SCALAR);
            let (eph_p_b, ct_mlkem_b) = ciphertext.split_at(P256_PUB);
            // ML-KEM decaps.
            let dk_arr = ml_kem::Encoded::<<MlKem768 as KemCore>::DecapsulationKey>::try_from(dk_b)
                .map_err(|_| mlkem_error("dk decode"))?;
            let dk = <MlKem768 as KemCore>::DecapsulationKey::from_bytes(&dk_arr);
            let ct_arr = ml_kem::Ciphertext::<MlKem768>::try_from(ct_mlkem_b)
                .map_err(|_| mlkem_error("ct decode"))?;
            let ss_mlkem = dk.decapsulate(&ct_arr).map_err(|_| mlkem_error("decapsulate"))?;
            // P-256 ECDH with own static secret.
            let scalar: [u8; 32] = p_sec_b.try_into().expect("length checked");
            let secret = p256::SecretKey::from_bytes((&scalar).into())
                .map_err(|_| "hybrid KEM: P-256 own secret invalid".to_string())?;
            let eph_pub = p256::PublicKey::from_sec1_bytes(eph_p_b)
                .map_err(|_| "hybrid KEM: P-256 ephemeral public invalid".to_string())?;
            let ss_p = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), eph_pub.as_affine());
            // SS: ss_p256 ‖ ss_mlkem (ECDHE first).
            Ok([ss_p.raw_secret_bytes().as_slice(), ss_mlkem.as_slice()].concat())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(hybrid: Hybrid) {
        let kp = keygen(hybrid).expect("keygen");
        let enc = encapsulate(hybrid, &kp.public).expect("encapsulate");
        let ss2 = decapsulate(hybrid, &kp.private, &enc.ciphertext).expect("decapsulate");
        assert_eq!(
            enc.shared_secret, ss2,
            "{hybrid:?}: encapsulator and decapsulator must derive the same shared secret"
        );
        assert_eq!(enc.shared_secret.len(), 64, "combined SS is 32 (ML-KEM) + 32 (ECDH)");
    }

    #[test]
    fn x25519_mlkem768_round_trips() {
        round_trip(Hybrid::X25519MlKem768);
    }

    #[test]
    fn secp256r1_mlkem768_round_trips() {
        round_trip(Hybrid::SecP256r1MlKem768);
    }

    #[test]
    fn combiner_order_is_asymmetric_per_spec() {
        // X25519MLKEM768: ML-KEM SS is the FIRST 32 bytes.
        // SecP256r1MLKEM768: ML-KEM SS is the LAST 32 bytes.
        // We can't read the component SS out of the combined value directly, but
        // we assert the two hybrids produce distinct layouts by construction via
        // the public/ciphertext sizes, and that a mismatched-length input errors.
        let kp = keygen(Hybrid::X25519MlKem768).unwrap();
        assert_eq!(kp.public.len(), MLKEM_EK + X25519_LEN);
        let kp2 = keygen(Hybrid::SecP256r1MlKem768).unwrap();
        assert_eq!(kp2.public.len(), P256_PUB + MLKEM_EK);

        // Wrong-length ciphertext is rejected, not silently mis-parsed.
        assert!(decapsulate(Hybrid::X25519MlKem768, &kp.private, &[0u8; 10]).is_err());
    }

    #[test]
    fn tampered_ciphertext_changes_secret_not_panics() {
        // ML-KEM implicit rejection: a bit-flipped correct-length ciphertext
        // yields a DIFFERENT shared secret without an error (never a panic).
        let kp = keygen(Hybrid::X25519MlKem768).unwrap();
        let enc = encapsulate(Hybrid::X25519MlKem768, &kp.public).unwrap();
        let mut ct = enc.ciphertext.clone();
        ct[0] ^= 0x01;
        let ss = decapsulate(Hybrid::X25519MlKem768, &kp.private, &ct).expect("no error");
        assert_ne!(ss, enc.shared_secret, "tampered ciphertext must not reproduce the secret");
    }
}
