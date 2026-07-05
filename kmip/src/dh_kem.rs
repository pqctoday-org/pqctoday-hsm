//! Classical Montgomery-curve KEM — X25519 (RFC 7748 §6.1) and X448 (§6.2),
//! exposed DHKEM-style (RFC 9180 §4.1) through the KMIP `Encapsulate` /
//! `Decapsulate` operations.
//!
//! The Migration tab's classical estate needs "establish a shared secret"
//! to be the SAME KMIP operation under every policy (classical → hybrid →
//! PQC), so the policy engine can substitute the algorithm without the
//! application changing its call. DHKEM gives classical ECDH that shape:
//!
//! - `encapsulate(pk_R)`: generate an ephemeral keypair, `ss = DH(sk_E, pk_R)`,
//!   **ciphertext = pk_E** (the ephemeral public key).
//! - `decapsulate(sk_R, ct)`: `ss = DH(sk_R, ct-as-pk_E)`.
//!
//! Like [`crate::hybrid_kem`], the crypto is composed in-process and the key
//! material lives on the KMIP record (`key_material`), not behind an engine
//! CKA_ID — the op handlers dispatch here the same way they dispatch to the
//! hybrid combiner. The shared secret is returned RAW (no KDF), exactly as
//! the ML-KEM and hybrid paths return theirs — the caller applies its own.
//!
//! Byte sizes: X25519 pub/secret/ss = 32; X448 pub/secret/ss = 56.

/// Which Montgomery curve — determines key/ciphertext/secret sizes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Curve {
    /// RFC 7748 §6.1 — 32-byte keys and shared secrets.
    X25519,
    /// RFC 7748 §6.2 — 56-byte keys and shared secrets.
    X448,
}

impl Curve {
    /// Public-key / ciphertext / shared-secret length in bytes.
    pub const fn len(self) -> usize {
        match self {
            Curve::X25519 => 32,
            Curve::X448 => 56,
        }
    }

    /// KMIP `CryptographicLength` (bits) the stored records carry — matches
    /// the PKCS#11 v3.2 §6.7 Montgomery mechanism-info range (255 / 448).
    pub const fn kmip_bits(self) -> u32 {
        match self {
            Curve::X25519 => 255,
            Curve::X448 => 448,
        }
    }

    /// Reverse of [`Self::kmip_bits`] — how the op handlers recognise a
    /// Montgomery record behind the coarse `KmipAlgorithm::Ecdh` variant.
    pub const fn from_kmip_bits(bits: u32) -> Option<Self> {
        match bits {
            255 => Some(Curve::X25519),
            448 => Some(Curve::X448),
            _ => None,
        }
    }

    /// Canonical policy-facing name (`X25519` / `X448`).
    pub const fn name(self) -> &'static str {
        match self {
            Curve::X25519 => "X25519",
            Curve::X448 => "X448",
        }
    }
}

/// A freshly generated Montgomery keypair (raw RFC 7748 byte strings).
pub struct DhKeyPair {
    /// Public key (peer encapsulates to this).
    pub public: Vec<u8>,
    /// Private scalar (kept by the owner; sensitive).
    pub private: Vec<u8>,
}

/// Output of an encapsulation: the ciphertext (= ephemeral public key) the
/// peer needs to decapsulate, and the raw shared secret the caller keeps.
pub struct Encapsulated {
    pub ciphertext: Vec<u8>,
    pub shared_secret: Vec<u8>,
}

/// Generate a keypair on `curve`.
pub fn keygen(curve: Curve) -> Result<DhKeyPair, String> {
    match curve {
        Curve::X25519 => {
            let mut rng = rand::rngs::OsRng;
            let secret = x25519_dalek::StaticSecret::random_from_rng(&mut rng);
            let public = x25519_dalek::PublicKey::from(&secret);
            Ok(DhKeyPair {
                public: public.as_bytes().to_vec(),
                private: secret.to_bytes().to_vec(),
            })
        }
        Curve::X448 => {
            use rand::RngCore;
            let mut sk_arr = [0u8; 56];
            rand::rngs::OsRng.fill_bytes(&mut sk_arr);
            // StaticSecret::from() applies RFC 7748 clamping; zeroizes on drop.
            let sk = x448::StaticSecret::from(sk_arr);
            let pk = x448::PublicKey::from(&sk);
            Ok(DhKeyPair {
                public: pk.as_bytes().to_vec(),
                private: sk.as_bytes().to_vec(),
            })
        }
    }
}

/// Encapsulate to a peer's public key: fresh ephemeral keypair, DH against
/// `peer_public`, ciphertext = the ephemeral public key.
pub fn encapsulate(curve: Curve, peer_public: &[u8]) -> Result<Encapsulated, String> {
    let eph = keygen(curve)?;
    let shared_secret = dh(curve, &eph.private, peer_public)?;
    Ok(Encapsulated { ciphertext: eph.public, shared_secret })
}

/// Decapsulate with the owner's private scalar: DH against the ciphertext
/// (which IS the encapsulator's ephemeral public key).
pub fn decapsulate(curve: Curve, own_private: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    dh(curve, own_private, ciphertext)
}

/// Raw RFC 7748 Diffie-Hellman. Rejects wrong-length inputs and (X448)
/// low-order peer points; X25519 all-zero outputs are rejected per RFC 7748
/// §6.1's contributory-behaviour check.
fn dh(curve: Curve, secret: &[u8], peer_public: &[u8]) -> Result<Vec<u8>, String> {
    if secret.len() != curve.len() || peer_public.len() != curve.len() {
        return Err(format!(
            "{}: secret/public must be {} bytes (got {}/{})",
            curve.name(),
            curve.len(),
            secret.len(),
            peer_public.len()
        ));
    }
    match curve {
        Curve::X25519 => {
            let sk_arr: [u8; 32] = secret.try_into().expect("length checked");
            let pk_arr: [u8; 32] = peer_public.try_into().expect("length checked");
            let sk = x25519_dalek::StaticSecret::from(sk_arr);
            let ss = sk.diffie_hellman(&x25519_dalek::PublicKey::from(pk_arr));
            if ss.as_bytes().iter().all(|&b| b == 0) {
                return Err("X25519: low-order peer public key rejected".to_string());
            }
            Ok(ss.as_bytes().to_vec())
        }
        Curve::X448 => {
            let sk_arr: [u8; 56] = secret.try_into().expect("length checked");
            let pk_arr: [u8; 56] = peer_public.try_into().expect("length checked");
            let pk = x448::PublicKey::from_bytes(&pk_arr)
                .ok_or_else(|| "X448: low-order peer public key rejected".to_string())?;
            let sk = x448::StaticSecret::from(sk_arr);
            let ss = sk.diffie_hellman(&pk);
            Ok(ss.as_bytes().to_vec())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(curve: Curve) {
        let kp = keygen(curve).expect("keygen");
        assert_eq!(kp.public.len(), curve.len());
        assert_eq!(kp.private.len(), curve.len());
        let enc = encapsulate(curve, &kp.public).expect("encapsulate");
        assert_eq!(enc.ciphertext.len(), curve.len(), "ciphertext is the ephemeral public key");
        let ss2 = decapsulate(curve, &kp.private, &enc.ciphertext).expect("decapsulate");
        assert_eq!(
            enc.shared_secret, ss2,
            "{curve:?}: encapsulator and decapsulator must derive the same shared secret"
        );
    }

    #[test]
    fn x25519_round_trips() {
        round_trip(Curve::X25519);
    }

    #[test]
    fn x448_round_trips() {
        round_trip(Curve::X448);
    }

    #[test]
    fn wrong_key_wrong_secret() {
        // Decapsulating with a DIFFERENT private key must not reproduce the secret.
        for curve in [Curve::X25519, Curve::X448] {
            let kp = keygen(curve).unwrap();
            let other = keygen(curve).unwrap();
            let enc = encapsulate(curve, &kp.public).unwrap();
            let ss_wrong = decapsulate(curve, &other.private, &enc.ciphertext).unwrap();
            assert_ne!(ss_wrong, enc.shared_secret, "{curve:?}");
        }
    }

    #[test]
    fn wrong_lengths_rejected() {
        let kp = keygen(Curve::X25519).unwrap();
        assert!(encapsulate(Curve::X25519, &[0u8; 10]).is_err());
        assert!(decapsulate(Curve::X25519, &kp.private, &[0u8; 56]).is_err());
        // X448 material fed to the X25519 curve is a length error, not a panic.
        let kp448 = keygen(Curve::X448).unwrap();
        assert!(encapsulate(Curve::X25519, &kp448.public).is_err());
    }

    #[test]
    fn low_order_peer_rejected() {
        // All-zero public key is the canonical low-order point for both curves.
        let kp25519 = keygen(Curve::X25519).unwrap();
        assert!(dh(Curve::X25519, &kp25519.private, &[0u8; 32]).is_err());
        let kp448 = keygen(Curve::X448).unwrap();
        assert!(dh(Curve::X448, &kp448.private, &[0u8; 56]).is_err());
    }

    #[test]
    fn kmip_bits_round_trip() {
        for curve in [Curve::X25519, Curve::X448] {
            assert_eq!(Curve::from_kmip_bits(curve.kmip_bits()), Some(curve));
        }
        assert_eq!(Curve::from_kmip_bits(256), None, "ECDH-P256 must NOT parse as Montgomery");
    }
}
