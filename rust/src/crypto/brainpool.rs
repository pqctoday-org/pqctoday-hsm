// SPDX-License-Identifier: AGPL-3.0-only
//
//! brainpoolP256r1 and brainpoolP384r1 (RFC 5639 §3.4 / §3.6): ECDSA and
//! ECDH for plain `CKK_EC` keys and for the four brainpool composite sets of
//! the PKCS#11 v3.3 working draft (`CKP_COMP_KEM_MLKEM768_ECDH_BRAINPOOLP256R1`,
//! `CKP_COMP_KEM_MLKEM1024_ECDH_BRAINPOOLP384R1`,
//! `CKP_COMP_SIG_MLDSA65_ECDSA_BRAINPOOLP256R1_SHA512`,
//! `CKP_COMP_SIG_MLDSA87_ECDSA_BRAINPOOLP384R1_SHA512`).
//!
//! ## Implementation choice (2026-10-21)
//!
//! RustCrypto `bp256` / `bp384` 0.14.0, on both native and wasm32:
//!
//! * AWS-LC, the engine's native backend for NIST-curve ECDH, has no
//!   brainpool curves, and it is not in the wasm32 build at all.
//! * The crates are pure Rust, `no_std` and `forbid(unsafe_code)`. Field
//!   arithmetic is fiat-crypto output (formally verified, constant time);
//!   points use primeorder's complete addition formulas; scalar
//!   multiplication goes through a constant-time lookup table. Signing uses
//!   RFC 6979 deterministic nonces, like this engine's P-256 / P-384.
//! * Licence Apache-2.0 OR MIT (allowed by `rust/deny.toml`).
//! * **Not independently audited.** The brainpool crates have had no
//!   third-party review; the P-256 / P-384 paths the engine also runs on
//!   AWS-LC have. The Wycheproof brainpool suites and the LAMPS composite
//!   vectors are this engine's evidence for them.
//!
//! ## Feature switch
//!
//! Cargo feature `brainpool`, default on (owner decision D2: the curves make
//! the browser bundle noticeably bigger, so they can be switched off). Off,
//! [`ENABLED`] is false, [`is_brainpool`] answers false for every curve,
//! `handlers::decode_ec_params` reads the brainpool OIDs as recognised but
//! unsupported (`CKR_CURVE_NOT_SUPPORTED`), the four composite sets are
//! `CKR_PARAMETER_SET_NOT_SUPPORTED`, and every operation here returns
//! `CKR_CURVE_NOT_SUPPORTED`.
//!
//! ## Encodings
//!
//! The same as the engine's other Weierstrass curves: private keys are the
//! field-width big-endian scalar (`CKA_VALUE`), public keys the uncompressed
//! SEC1 point `04‖X‖Y`, signatures fixed-width `r‖s`, and the ECDH shared
//! secret is the x-coordinate (PKCS#11 v3.2 §6.3.17, SEC 1 §3.3.1).
//!
//! The message digest is the caller's: [`sign_prehash`] and
//! [`verify_prehash`] take the digest already conditioned to the field size
//! (FIPS 186-5 §6.4), as `handlers::sign_ecdsa` does for every curve.

use zeroize::Zeroizing;

use crate::constants::*;

/// brainpoolP256r1, stored in `CKA_PRIV_PARAM_SET` like the other curve IDs.
/// The NIST / Edwards / Montgomery IDs are bit sizes (256, 384, 521, 25519,
/// …); the brainpool IDs sit above that range so they never collide, with
/// the last arc of the curve OID (1.3.36.3.3.2.8.1.1.7) in the low byte.
pub const CURVE_BP256R1: u32 = 0x1000_0007;
/// brainpoolP384r1 (1.3.36.3.3.2.8.1.1.11).
pub const CURVE_BP384R1: u32 = 0x1000_000b;

/// DER body of 1.3.36.3.3.2.8.1.1.7 (RFC 5639 §4.1, `brainpoolP256r1`).
pub const OID_BP256R1: [u8; 9] = [0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07];
/// DER body of 1.3.36.3.3.2.8.1.1.11 (RFC 5639 §4.1, `brainpoolP384r1`).
pub const OID_BP384R1: [u8; 9] = [0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0b];

/// Whether this build has the brainpool curves (feature `brainpool`).
pub const ENABLED: bool = cfg!(feature = "brainpool");

/// A brainpool curve ID this build implements (always false without the
/// feature).
pub fn is_brainpool(curve: u32) -> bool {
    ENABLED && matches!(curve, CURVE_BP256R1 | CURVE_BP384R1)
}

/// Field (and scalar) width in bytes.
pub fn field_len(curve: u32) -> Option<usize> {
    match curve {
        CURVE_BP256R1 => Some(32),
        CURVE_BP384R1 => Some(48),
        _ => None,
    }
}

/// Key size in bits, the unit of `CK_MECHANISM_INFO` ranges.
pub fn key_bits(curve: u32) -> Option<u32> {
    match curve {
        CURVE_BP256R1 => Some(256),
        CURVE_BP384R1 => Some(384),
        _ => None,
    }
}

/// `CKA_EC_PARAMS` in the namedCurve OID form (`06 09 <oid>`).
pub fn ec_params(curve: u32) -> Option<Vec<u8>> {
    let oid = match curve {
        CURVE_BP256R1 => &OID_BP256R1,
        CURVE_BP384R1 => &OID_BP384R1,
        _ => return None,
    };
    let mut out = vec![0x06, oid.len() as u8];
    out.extend_from_slice(oid);
    Some(out)
}

/// `SubjectPublicKeyInfo` of an uncompressed point `q`: id-ecPublicKey
/// (1.2.840.10045.2.1) with the namedCurve parameter (RFC 5480 §2.1.1). The
/// AlgorithmIdentifier is the one composite-sigs-19 Appendix C lists for
/// "ECDSA Brainpool-P256" / "-P384": `30 14 06 07 2A 86 48 CE 3D 02 01 06 09
/// 2B 24 03 03 02 08 01 01 07` (`… 0B` for P-384).
pub fn spki(curve: u32, q: &[u8]) -> Option<Vec<u8>> {
    let mut alg_id = vec![0x30, 0x14, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
    alg_id.extend_from_slice(&ec_params(curve)?);
    Some(crate::crypto::handlers::build_spki_from_parts(&alg_id, q))
}

/// The curve-generic operations, instantiated once per curve below.
#[cfg(feature = "brainpool")]
macro_rules! curve_ops {
    ($m:ident, $krate:ident, $curve:ty) => {
        mod $m {
            use super::*;
            use $krate::elliptic_curve::point::AffineCoordinates;
            use $krate::elliptic_curve::sec1::ToSec1Point;
            use $krate::elliptic_curve::PrimeField;

            type PublicKey = $krate::elliptic_curve::PublicKey<$curve>;
            type SecretKey = $krate::elliptic_curve::SecretKey<$curve>;
            type Signature = ecdsa017::Signature<$curve>;
            type SigningKey = ecdsa017::SigningKey<$curve>;
            type VerifyingKey = ecdsa017::VerifyingKey<$curve>;

            fn uncompressed(pk: &PublicKey) -> Vec<u8> {
                pk.as_affine().to_sec1_point(false).as_bytes().to_vec()
            }

            pub fn public_from_private(d: &[u8]) -> Result<Vec<u8>, u32> {
                let sk = SecretKey::from_slice(d).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
                Ok(uncompressed(&sk.public_key()))
            }

            pub fn validate_public(point: &[u8]) -> bool {
                PublicKey::from_sec1_bytes(point).is_ok()
            }

            /// Uniform scalar in [1, n-1] by rejection sampling from `fill`
            /// (the caller's RNG, so the ACVP test RNG reaches it too).
            pub fn generate(fill: &mut dyn FnMut(&mut [u8])) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), u32> {
                loop {
                    let mut repr = <$krate::Scalar as PrimeField>::Repr::default();
                    fill(&mut repr);
                    let candidate = $krate::r1::NonZeroScalar::from_repr(repr);
                    repr.iter_mut().for_each(|b| *b = 0);
                    if let Some(s) = Option::<$krate::r1::NonZeroScalar>::from(candidate) {
                        let sk = SecretKey::from(s);
                        let d = Zeroizing::new(sk.to_bytes().to_vec());
                        return Ok((d, uncompressed(&sk.public_key())));
                    }
                }
            }

            pub fn sign_prehash(d: &[u8], digest: &[u8]) -> Result<Vec<u8>, u32> {
                use ecdsa017::signature::hazmat::PrehashSigner;
                let sk = SigningKey::from_slice(d).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
                let sig: Signature = sk.sign_prehash(digest).map_err(|_| CKR_FUNCTION_FAILED)?;
                Ok(sig.to_bytes().to_vec())
            }

            pub fn verify_prehash(q: &[u8], digest: &[u8], sig: &[u8]) -> Result<(), u32> {
                use ecdsa017::signature::hazmat::PrehashVerifier;
                let vk = VerifyingKey::from_sec1_bytes(q).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
                let sig = Signature::from_slice(sig).map_err(|_| CKR_SIGNATURE_INVALID)?;
                vk.verify_prehash(digest, &sig).map_err(|_| CKR_SIGNATURE_INVALID)
            }

            pub fn ecdh(d: &[u8], peer: &[u8]) -> Result<Zeroizing<Vec<u8>>, u32> {
                let sk = SecretKey::from_slice(d).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
                let peer = PublicKey::from_sec1_bytes(peer).map_err(|_| CKR_ARGUMENTS_BAD)?;
                // SEC 1 §3.3.1: P = d·Q, z = x(P). Q is a validated non-identity
                // point of the prime-order group (cofactor 1), so P is never
                // the identity.
                let shared = (peer.to_projective() * *sk.to_nonzero_scalar()).to_affine();
                Ok(Zeroizing::new(shared.x().to_vec()))
            }

            pub fn raw_to_der(raw: &[u8]) -> Result<Vec<u8>, u32> {
                let sig = Signature::from_slice(raw).map_err(|_| CKR_FUNCTION_FAILED)?;
                Ok(sig.to_der().as_bytes().to_vec())
            }

            pub fn der_to_raw(der: &[u8]) -> Result<Vec<u8>, u32> {
                let sig = Signature::from_der(der).map_err(|_| CKR_SIGNATURE_INVALID)?;
                Ok(sig.to_bytes().to_vec())
            }
        }
    };
}

#[cfg(feature = "brainpool")]
curve_ops!(p256r1, bp256, bp256::BrainpoolP256r1);
#[cfg(feature = "brainpool")]
curve_ops!(p384r1, bp384, bp384::BrainpoolP384r1);

#[cfg(feature = "brainpool")]
macro_rules! dispatch {
    ($curve:expr, $f:ident ( $($arg:expr),* ), $other:expr) => {
        match $curve {
            CURVE_BP256R1 => p256r1::$f($($arg),*),
            CURVE_BP384R1 => p384r1::$f($($arg),*),
            _ => $other,
        }
    };
}

#[cfg(not(feature = "brainpool"))]
macro_rules! dispatch {
    ($curve:expr, $f:ident ( $($arg:expr),* ), $other:expr) => {{
        let _ = ($curve, $($arg),*);
        $other
    }};
}

/// Uncompressed SEC1 public point of the field-width scalar `d`.
pub fn public_from_private(curve: u32, d: &[u8]) -> Result<Vec<u8>, u32> {
    dispatch!(curve, public_from_private(d), Err(CKR_CURVE_NOT_SUPPORTED))
}

/// Whether `point` is a SEC1 encoding of a point on the curve other than the
/// identity (both curves have cofactor 1, so that is the whole group check).
pub fn validate_public(curve: u32, point: &[u8]) -> bool {
    dispatch!(curve, validate_public(point), false)
}

/// A fresh key pair `(d, Q)`: the field-width scalar and the uncompressed point.
pub fn generate(curve: u32, fill: &mut dyn FnMut(&mut [u8])) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), u32> {
    dispatch!(curve, generate(fill), Err(CKR_CURVE_NOT_SUPPORTED))
}

/// ECDSA over an already-conditioned digest, RFC 6979 nonce; `r‖s` out.
pub fn sign_prehash(curve: u32, d: &[u8], digest: &[u8]) -> Result<Vec<u8>, u32> {
    dispatch!(curve, sign_prehash(d, digest), Err(CKR_CURVE_NOT_SUPPORTED))
}

/// ECDSA verification of `r‖s` over an already-conditioned digest.
pub fn verify_prehash(curve: u32, q: &[u8], digest: &[u8], sig: &[u8]) -> Result<(), u32> {
    dispatch!(curve, verify_prehash(q, digest, sig), Err(CKR_CURVE_NOT_SUPPORTED))
}

/// ECDH: the x-coordinate of `d·peer`. An undecodable or off-curve peer is
/// `CKR_ARGUMENTS_BAD`, as in the engine's other ECDH paths.
pub fn ecdh(curve: u32, d: &[u8], peer: &[u8]) -> Result<Zeroizing<Vec<u8>>, u32> {
    dispatch!(curve, ecdh(d, peer), Err(CKR_CURVE_NOT_SUPPORTED))
}

/// `r‖s` → DER `Ecdsa-Sig-Value` (RFC 3279 §2.2.3).
pub fn sig_raw_to_der(curve: u32, raw: &[u8]) -> Result<Vec<u8>, u32> {
    dispatch!(curve, raw_to_der(raw), Err(CKR_CURVE_NOT_SUPPORTED))
}

/// Strict DER `Ecdsa-Sig-Value` → `r‖s`; anything else is
/// `CKR_SIGNATURE_INVALID`.
pub fn sig_der_to_raw(curve: u32, der: &[u8]) -> Result<Vec<u8>, u32> {
    dispatch!(curve, der_to_raw(der), Err(CKR_CURVE_NOT_SUPPORTED))
}

#[cfg(all(test, feature = "brainpool"))]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn os_fill(buf: &mut [u8]) {
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(buf)
    }

    /// RFC 5639 §3.4 / §3.6 base points: d = 1 gives G.
    #[test]
    fn generator_matches_rfc5639() {
        let mut one = vec![0u8; 32];
        one[31] = 1;
        let g = public_from_private(CURVE_BP256R1, &one).unwrap();
        assert_eq!(
            hex(&g[1..33]),
            "8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262"
        );
        let mut one = vec![0u8; 48];
        one[47] = 1;
        let g = public_from_private(CURVE_BP384R1, &one).unwrap();
        assert_eq!(
            hex(&g[1..49]),
            "1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e"
        );
    }

    #[test]
    fn ecdsa_and_ecdh_round_trip() {
        for (curve, n) in [(CURVE_BP256R1, 32usize), (CURVE_BP384R1, 48)] {
            let (d1, q1) = generate(curve, &mut os_fill).unwrap();
            let (d2, q2) = generate(curve, &mut os_fill).unwrap();
            assert_eq!((d1.len(), q1.len()), (n, 1 + 2 * n));
            assert!(validate_public(curve, &q1));
            assert_eq!(public_from_private(curve, &d1).unwrap(), q1);
            let digest = vec![0x5au8; n];
            let sig = sign_prehash(curve, &d1, &digest).unwrap();
            assert_eq!(sig.len(), 2 * n);
            // RFC 6979: the same key and digest give the same signature.
            assert_eq!(sign_prehash(curve, &d1, &digest).unwrap(), sig);
            verify_prehash(curve, &q1, &digest, &sig).unwrap();
            assert_eq!(verify_prehash(curve, &q2, &digest, &sig), Err(CKR_SIGNATURE_INVALID));
            let der = sig_raw_to_der(curve, &sig).unwrap();
            assert_eq!(sig_der_to_raw(curve, &der).unwrap(), sig);
            let z1 = ecdh(curve, &d1, &q2).unwrap();
            assert_eq!(z1.len(), n);
            assert_eq!(*z1, *ecdh(curve, &d2, &q1).unwrap());
            let mut off_curve = q2.clone();
            off_curve[n] ^= 1;
            assert!(!validate_public(curve, &off_curve));
            assert_eq!(ecdh(curve, &d1, &off_curve).err(), Some(CKR_ARGUMENTS_BAD));
        }
    }
}
