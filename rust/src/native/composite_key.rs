// SPDX-License-Identifier: AGPL-3.0-only
//
//! Composite key objects, both families — PKCS#11 v3.3 working draft
//! (`working/doc/spec/comp_kem.md`, `comp_sig.md`, OASIS PKCS 11 TC commit
//! 9ef73f9). The engine still reports Cryptoki 3.2.0 (root `CLAUDE.md`).
//!
//! One object per key (`CKK_COMP_KEM` / `CKK_COMP_SIG`), never a pair of
//! component handles. Its `CKA_VALUE` is the drafts' serialization:
//!
//! - public key: `mlPK ‖ tradPK` (composite-kem-23 §4.1, composite-sigs-19
//!   §4.1);
//! - private key: `mlSeed ‖ tradSK` — the ML-KEM seed `d ‖ z` (64 bytes,
//!   composite-kem-23 §4.2) or the ML-DSA seed ξ (32 bytes,
//!   composite-sigs-19 §4.2), followed by the traditional private key.
//!
//! Traditional component encodings (composite-kem-23 §4, composite-sigs-19
//! §4, identical in both): RSA public key DER `RSAPublicKey` and private key
//! DER `RSAPrivateKey` (RFC 8017 A.1.1/A.1.2, version 0, no
//! otherPrimeInfos); EC public key the uncompressed X9.62 point `04 ‖ X ‖ Y`
//! and private key DER `ECPrivateKey` (RFC 5915) with the named-curve OID and
//! without the publicKey field (an import that carries a matching one is
//! normalised, see `canonical_trad_private`); X25519 / X448 / Ed25519 / Ed448 raw RFC 7748
//! / RFC 8032 bytes.
//!
//! This module holds the parts both families share: splitting and
//! re-deriving the halves, generation, the composite SPKI, the default key
//! attributes and the `C_CreateObject` import check. The KEM operations are
//! in `native::composite_kem`; the per-set facts come from
//! `native::composite` and nowhere else.

use std::collections::HashMap;

use zeroize::Zeroizing;

use super::composite::{
    params_for_key, CompositeFamily, CompositeParams, ComponentSizes, EcCurve, KemClassical,
    SigClassical, MLDSA_SEED_LEN, MLKEM_SEED_LEN,
};
use super::CkRv;
use crate::constants::*;
use crate::crypto::handlers::Attributes;
use crate::state::{get_object_attr_u32_from, store_bool, store_param_set, store_ulong};

/// The traditional half of any composite set, as far as its KEY is concerned
/// (the operation — KEM or signature, padding, hash — is the caller's).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TradKey {
    Rsa { modulus_bits: u32 },
    Ec(EcCurve),
    X25519,
    X448,
    Ed25519,
    Ed448,
}

impl From<KemClassical> for TradKey {
    fn from(c: KemClassical) -> Self {
        match c {
            KemClassical::RsaOaep { modulus_bits } => TradKey::Rsa { modulus_bits },
            KemClassical::Ecdh { curve } => TradKey::Ec(curve),
            KemClassical::X25519 => TradKey::X25519,
            KemClassical::X448 => TradKey::X448,
        }
    }
}

impl From<SigClassical> for TradKey {
    fn from(c: SigClassical) -> Self {
        match c {
            SigClassical::RsaPss { modulus_bits, .. } | SigClassical::RsaPkcs15 { modulus_bits, .. } => {
                TradKey::Rsa { modulus_bits }
            }
            SigClassical::Ecdsa { curve, .. } => TradKey::Ec(curve),
            SigClassical::Ed25519 => TradKey::Ed25519,
            SigClassical::Ed448 => TradKey::Ed448,
        }
    }
}

/// The ML half: `CKP_ML_KEM_*` or `CKP_ML_DSA_*`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MlKey {
    Kem(u32),
    Dsa(u32),
}

/// Everything about a set's key layout, family-independent.
#[derive(Clone, Copy, Debug)]
pub struct Layout {
    pub params: CompositeParams,
    pub ml: MlKey,
    /// FIPS 203 `ek` / FIPS 204 `pk` length (composite-kem-23 §4 Table 1,
    /// composite-sigs-19 §4 Table 1).
    pub ml_public_len: usize,
    /// 64 (`d ‖ z`) or 32 (ξ).
    pub seed_len: usize,
    pub trad: TradKey,
    pub trad_sizes: ComponentSizes,
}

impl From<CompositeParams> for Layout {
    fn from(params: CompositeParams) -> Self {
        match params {
            CompositeParams::Kem(p) => Layout {
                params,
                ml: MlKey::Kem(p.ml_kem),
                ml_public_len: p.ml_kem_public_key_len(),
                seed_len: MLKEM_SEED_LEN,
                trad: p.classical.into(),
                trad_sizes: p.classical_sizes,
            },
            CompositeParams::Sig(p) => Layout {
                params,
                ml: MlKey::Dsa(p.ml_dsa),
                ml_public_len: p.ml_dsa_public_key_len(),
                seed_len: MLDSA_SEED_LEN,
                trad: p.classical.into(),
                trad_sizes: p.classical_sizes,
            },
        }
    }
}

impl Layout {
    /// `CKA_VALUE` of a public key → `(mlPK, tradPK)` (§4.1 Deserialize).
    /// `None` when either half has a length the set does not allow.
    pub fn split_public<'a>(&self, value: &'a [u8]) -> Option<(&'a [u8], &'a [u8])> {
        if value.len() <= self.ml_public_len {
            return None;
        }
        let (ml, trad) = value.split_at(self.ml_public_len);
        self.trad_sizes.public_key.admits(trad.len()).then_some((ml, trad))
    }

    /// `CKA_VALUE` of a private key → `(mlSeed, tradSK)` (§4.2 Deserialize).
    pub fn split_private<'a>(&self, value: &'a [u8]) -> Option<(&'a [u8], &'a [u8])> {
        if value.len() <= self.seed_len {
            return None;
        }
        let (seed, trad) = value.split_at(self.seed_len);
        self.trad_sizes.private_key.admits(trad.len()).then_some((seed, trad))
    }
}

/// The parameter set of a composite key type, refusing what this engine cannot
/// run: an unknown `CKA_PARAMETER_SET` value is not a parameter set at all
/// (`unknown_rv`), a known one the engine does not run (the brainpool sets in
/// a build without feature `brainpool`) is
/// `CKR_PARAMETER_SET_NOT_SUPPORTED` ("This parameter set is not supported by
/// this token", v3.3 `function_return_values.md`; listed for C_CreateObject
/// and C_GenerateKeyPair in v3.2 §5.7.1 / §5.18.2 and v3.3
/// `object_mgmt_functions.md` / `key_management_functions.md`). comp_kem.md:
/// "Tokens may support a subset of the defined parameter sets."
pub fn supported_layout(key_type: u32, ckp: u32, unknown_rv: CkRv) -> Result<Layout, CkRv> {
    let params = params_for_key(key_type, ckp).ok_or(unknown_rv)?;
    if !params.supported() {
        return Err(CKR_PARAMETER_SET_NOT_SUPPORTED);
    }
    Ok(Layout::from(params))
}

// ── Minimal DER ───────────────────────────────────────────────────────────

fn der_len(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.extend_from_slice(&[0x81, len as u8]);
    } else {
        out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]);
    }
}

pub(crate) fn der_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    der_len(body.len(), &mut out);
    out.extend_from_slice(body);
    out
}

/// One definite-length DER TLV at the front of `buf`: `(tag, body, rest)`.
/// Only minimal length encodings are accepted (X.690 §10.1).
fn der_take(buf: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = buf.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (first as usize, rest)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 2 || rest.len() < n || rest[0] == 0 {
            return None;
        }
        let len = rest[..n].iter().fold(0usize, |a, &b| (a << 8) | b as usize);
        if len < 0x80 {
            return None;
        }
        (len, &rest[n..])
    };
    (rest.len() >= len).then(|| (tag, &rest[..len], &rest[len..]))
}

/// DER body (contents octets) of an OBJECT IDENTIFIER in dotted form
/// (X.690 §8.19). The OIDs come from `native::composite`, never from input.
pub fn oid_body(oid: &str) -> Vec<u8> {
    let arcs: Vec<u64> = oid.split('.').map(|a| a.parse().expect("dotted OID")).collect();
    let mut out = Vec::new();
    let mut push = |mut v: u64| {
        let mut tmp = vec![(v & 0x7f) as u8];
        v >>= 7;
        while v > 0 {
            tmp.push(0x80 | (v & 0x7f) as u8);
            v >>= 7;
        }
        tmp.reverse();
        out.extend_from_slice(&tmp);
    };
    push(arcs[0] * 40 + arcs[1]);
    for &a in &arcs[2..] {
        push(a);
    }
    out
}

/// `SubjectPublicKeyInfo` of a composite public key: the set's OID with the
/// parameters ABSENT (composite-kem-23 §6.1 and composite-sigs-19 §6:
/// "AlgorithmIdentifier parameters MUST be absent"), and the BIT STRING
/// holding the raw `mlPK ‖ tradPK` (composite-kem-23 §5.1 / composite-sigs-19
/// §5.1: no further ASN.1 wrapping of the composite key). This is
/// `CKA_PUBLIC_KEY_INFO` on both objects (PKCS#11 v3.2 §4.14).
pub fn spki(oid: &str, public_key: &[u8]) -> Vec<u8> {
    let alg = der_tlv(0x30, &der_tlv(0x06, &oid_body(oid)));
    let mut bits = vec![0u8];
    bits.extend_from_slice(public_key);
    let mut body = alg;
    body.extend_from_slice(&der_tlv(0x03, &bits));
    der_tlv(0x30, &body)
}

// ── EC private keys (RFC 5915, no publicKey field) ────────────────────────

/// `ECPrivateKey ::= SEQUENCE { version INTEGER 1, privateKey OCTET STRING,
/// [0] ECParameters (namedCurve OID) }` — RFC 5915 §3, with the publicKey
/// field the drafts forbid left out (composite-kem-23 §4 "*ECDH*",
/// composite-sigs-19 §4 "*ECDSA*"). `d` is the field-width big-endian scalar.
pub fn ec_private_key_der(curve: EcCurve, d: &[u8]) -> Vec<u8> {
    // The intermediate buffers hold the scalar: wiped on drop. The caller
    // owns (and wraps) the returned encoding.
    let mut body = Zeroizing::new(vec![0x02, 0x01, 0x01]);
    body.extend_from_slice(&Zeroizing::new(der_tlv(0x04, d)));
    body.extend_from_slice(&der_tlv(0xa0, &der_tlv(0x06, &oid_body(curve.oid()))));
    der_tlv(0x30, &body)
}

/// The scalar inside a [`ec_private_key_der`] encoding. Anything else — a
/// different curve, a publicKey field, a wrong-width scalar, trailing bytes —
/// is refused: the drafts allow exactly one encoding, and it is the only one
/// the engine stores (an import carrying the publicKey field is normalised
/// by [`canonical_trad_private`] first).
pub fn ec_private_key_scalar(curve: EcCurve, der: &[u8]) -> Option<&[u8]> {
    match ec_private_key_parse(curve, der)? {
        (d, None) => Some(d),
        (_, Some(_)) => None,
    }
}

/// [`ec_private_key_scalar`] that also admits RFC 5915's optional
/// `publicKey [1] BIT STRING` after the parameters: `(d, publicKey)`. The
/// BIT STRING must have no unused bits. Nothing else is relaxed.
fn ec_private_key_parse(curve: EcCurve, der: &[u8]) -> Option<(&[u8], Option<&[u8]>)> {
    let (tag, body, rest) = der_take(der)?;
    if tag != 0x30 || !rest.is_empty() {
        return None;
    }
    let (tag, version, body) = der_take(body)?;
    if tag != 0x02 || version != [0x01] {
        return None;
    }
    let (tag, d, body) = der_take(body)?;
    if tag != 0x04 || d.len() != curve.field_bytes() {
        return None;
    }
    let (tag, params, rest) = der_take(body)?;
    if tag != 0xa0 {
        return None;
    }
    let (tag, oid, params_rest) = der_take(params)?;
    if tag != 0x06 || !params_rest.is_empty() || oid != oid_body(curve.oid()).as_slice() {
        return None;
    }
    if rest.is_empty() {
        return Some((d, None));
    }
    let (tag, public, rest) = der_take(rest)?;
    if tag != 0xa1 || !rest.is_empty() {
        return None;
    }
    let (tag, bits, rest) = der_take(public)?;
    if tag != 0x03 || !rest.is_empty() {
        return None;
    }
    match bits.split_first() {
        Some((0, point)) if !point.is_empty() => Some((d, Some(point))),
        _ => None,
    }
}

/// Import-time leniency for `tradSK`. composite-kem-23 §4 and
/// composite-sigs-19 §4 forbid the ECPrivateKey publicKey field ("in the
/// interest of having a single unique encoding", composite-kem-23 §10.4.2),
/// but composite-kem-23 §10.5 / composite-sigs-19 §10.6 encourage
/// implementations "to be lenient when parsing the key material of the
/// legacy algorithm". So an imported EC `tradSK` that carries the field is
/// accepted ONLY if the embedded point is the public key of the scalar, and
/// is then re-encoded without it — the engine stores and computes over the
/// one encoding the drafts define.
///
/// `Ok(None)`: already canonical, or not an EC half (nothing to do).
/// `Ok(Some(der))`: the canonical re-encoding. `Err(CKR_ATTRIBUTE_VALUE_
/// INVALID)`: an embedded point that is not on the curve or is not the
/// scalar's public key — the code every other invalid half gets.
pub fn canonical_trad_private(trad: TradKey, sk: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>, CkRv> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    const BAD: CkRv = CKR_ATTRIBUTE_VALUE_INVALID;
    let TradKey::Ec(curve) = trad else {
        return Ok(None);
    };
    let Some((d, Some(embedded))) = ec_private_key_parse(curve, sk) else {
        return Ok(None);
    };
    macro_rules! same_point {
        ($c:ident) => {{
            let derived = $c::SecretKey::from_slice(d).map_err(|_| BAD)?.public_key();
            let given = $c::PublicKey::from_sec1_bytes(embedded).map_err(|_| BAD)?;
            given.to_encoded_point(false) == derived.to_encoded_point(false)
        }};
    }
    let same = match curve {
        EcCurve::P256 => same_point!(p256),
        EcCurve::P384 => same_point!(p384),
        EcCurve::P521 => same_point!(p521),
        EcCurve::BrainpoolP256r1 | EcCurve::BrainpoolP384r1 => {
            let c = curve.engine_curve();
            if !crate::crypto::brainpool::validate_public(c, embedded) {
                return Err(BAD);
            }
            crate::crypto::brainpool::public_from_private(c, d).map_err(|_| BAD)? == embedded
        }
    };
    if !same {
        return Err(BAD);
    }
    Ok(Some(Zeroizing::new(ec_private_key_der(curve, d))))
}

// ── Traditional halves ─────────────────────────────────────────────────────

/// `tradPK` from `tradSK`, in the §4 encodings — the derivation the drafts
/// describe in composite-kem-23 §10.4.1 (RSA: re-encode n, e), §10.4.2 (EC:
/// scalar × generator, uncompressed) and for X25519 / X448 / EdDSA the RFC
/// 7748 / 8032 public key of the raw private key. A private key that does not
/// parse, has the wrong RSA size (composite-kem-23 §6.1: "MUST be generated
/// at the specified ... key sizes ...; intermediate sizes are not
/// acceptable"), or is not a valid key is `CKR_ATTRIBUTE_VALUE_INVALID`.
pub fn trad_public_from_private(trad: TradKey, sk: &[u8]) -> Result<Vec<u8>, CkRv> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    const BAD: CkRv = CKR_ATTRIBUTE_VALUE_INVALID;
    macro_rules! ec_pub {
        ($c:ident, $d:expr) => {
            $c::SecretKey::from_slice($d).map_err(|_| BAD)?.public_key().to_encoded_point(false).as_bytes().to_vec()
        };
    }
    Ok(match trad {
        TradKey::Rsa { modulus_bits } => {
            use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPublicKey};
            use rsa::traits::PublicKeyParts;
            // A parse and a consistency check (n = p·q, d·e ≡ 1), not a
            // private-key operation on caller input.
            let key = rsa::RsaPrivateKey::from_pkcs1_der(sk).map_err(|_| BAD)?;
            key.validate().map_err(|_| BAD)?;
            if key.n().bits() != modulus_bits as usize {
                return Err(BAD);
            }
            rsa::RsaPublicKey::from(&key).to_pkcs1_der().map_err(|_| BAD)?.as_bytes().to_vec()
        }
        TradKey::Ec(curve) => {
            let d = ec_private_key_scalar(curve, sk).ok_or(BAD)?;
            match curve {
                EcCurve::P256 => ec_pub!(p256, d),
                EcCurve::P384 => ec_pub!(p384, d),
                EcCurve::P521 => ec_pub!(p521, d),
                EcCurve::BrainpoolP256r1 | EcCurve::BrainpoolP384r1 => {
                    crate::crypto::brainpool::public_from_private(curve.engine_curve(), d).map_err(|_| BAD)?
                }
            }
        }
        TradKey::X25519 => {
            let k: [u8; 32] = sk.try_into().map_err(|_| BAD)?;
            let k = Zeroizing::new(k);
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*k)).as_bytes().to_vec()
        }
        TradKey::X448 => {
            let k: [u8; 56] = sk.try_into().map_err(|_| BAD)?;
            let k = Zeroizing::new(k);
            x448::PublicKey::from(&x448::StaticSecret::from(*k)).as_bytes().to_vec()
        }
        TradKey::Ed25519 => {
            let k: [u8; 32] = sk.try_into().map_err(|_| BAD)?;
            let k = Zeroizing::new(k);
            ed25519_dalek::SigningKey::from_bytes(&k).verifying_key().to_bytes().to_vec()
        }
        TradKey::Ed448 => {
            let sk = ed448_goldilocks::SigningKey::try_from(sk).map_err(|_| BAD)?;
            sk.verifying_key().to_bytes().to_vec()
        }
    })
}

/// Whether `pk` is a well-formed `tradPK` in the §4 encoding: an RSA key of
/// the set's size in canonical DER (the KEM combiner hashes these exact
/// bytes, composite-kem-23 §3.4, so a second encoding of the same key would
/// give a second secret), a point on the curve, or a raw key of the right
/// width.
pub fn trad_public_is_valid(trad: TradKey, pk: &[u8]) -> bool {
    match trad {
        TradKey::Rsa { modulus_bits } => {
            use rsa::pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey};
            use rsa::traits::PublicKeyParts;
            match rsa::RsaPublicKey::from_pkcs1_der(pk) {
                Ok(k) => {
                    k.n().bits() == modulus_bits as usize
                        && k.to_pkcs1_der().map(|d| d.as_bytes() == pk).unwrap_or(false)
                }
                Err(_) => false,
            }
        }
        TradKey::Ec(curve) => {
            pk.len() == curve.uncompressed_point_len()
                && pk[0] == 0x04
                && match curve {
                    EcCurve::P256 => p256::PublicKey::from_sec1_bytes(pk).is_ok(),
                    EcCurve::P384 => p384::PublicKey::from_sec1_bytes(pk).is_ok(),
                    EcCurve::P521 => p521::PublicKey::from_sec1_bytes(pk).is_ok(),
                    EcCurve::BrainpoolP256r1 | EcCurve::BrainpoolP384r1 => {
                        crate::crypto::brainpool::validate_public(curve.engine_curve(), pk)
                    }
                }
        }
        TradKey::X25519 => pk.len() == 32,
        TradKey::X448 => pk.len() == 56,
        TradKey::Ed25519 => <&[u8; 32]>::try_from(pk)
            .ok()
            .is_some_and(|a| ed25519_dalek::VerifyingKey::from_bytes(a).is_ok()),
        TradKey::Ed448 => <&[u8; 57]>::try_from(pk)
            .ok()
            .is_some_and(|a| ed448_goldilocks::VerifyingKey::from_bytes(a).is_ok()),
    }
}

/// A fresh traditional key pair `(tradPK, tradSK)` in the §4 encodings
/// (composite-kem-23 §3.1 step 1 / composite-sigs-19 §3.1: `Trad.KeyGen()`,
/// independent of the ML half). RSA uses e = 65537 (composite-kem-23 §6:
/// "the exponent is RECOMMENDED to be 65537").
pub fn trad_generate(trad: TradKey) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CkRv> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let mut rng = rand::rngs::OsRng;
    macro_rules! ec_gen {
        ($c:ident, $curve:expr) => {{
            let sk = $c::SecretKey::random(&mut rng);
            let pk = sk.public_key().to_encoded_point(false).as_bytes().to_vec();
            let d = Zeroizing::new(sk.to_bytes().to_vec());
            (pk, Zeroizing::new(ec_private_key_der($curve, &d)))
        }};
    }
    Ok(match trad {
        TradKey::Rsa { modulus_bits } => {
            use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey};
            // Native: AWS-LC generates (RUSTSEC-2023-0071 policy, see
            // crypto::awslc_rsa); its PKCS#8 output is re-encoded as the
            // PKCS#1 RSAPrivateKey the drafts require. wasm32: the `rsa` crate,
            // as in ffi::C_GenerateKeyPair's RSA arm.
            #[cfg(not(target_arch = "wasm32"))]
            let key = {
                use rsa::pkcs8::DecodePrivateKey;
                let (pkcs8, _, _) = crate::crypto::awslc_rsa::generate(modulus_bits, &[0x01, 0x00, 0x01])?;
                let pkcs8 = Zeroizing::new(pkcs8);
                rsa::RsaPrivateKey::from_pkcs8_der(&pkcs8).map_err(|_| CKR_FUNCTION_FAILED)?
            };
            #[cfg(target_arch = "wasm32")]
            let key = {
                crate::crypto::rsa_guard::note_pure_rsa_private_op();
                rsa::RsaPrivateKey::new(&mut rng, modulus_bits as usize).map_err(|_| CKR_FUNCTION_FAILED)?
            };
            let pk = rsa::RsaPublicKey::from(&key).to_pkcs1_der().map_err(|_| CKR_FUNCTION_FAILED)?;
            let sk = key.to_pkcs1_der().map_err(|_| CKR_FUNCTION_FAILED)?;
            (pk.as_bytes().to_vec(), Zeroizing::new(sk.as_bytes().to_vec()))
        }
        TradKey::Ec(EcCurve::P256) => ec_gen!(p256, EcCurve::P256),
        TradKey::Ec(EcCurve::P384) => ec_gen!(p384, EcCurve::P384),
        TradKey::Ec(EcCurve::P521) => ec_gen!(p521, EcCurve::P521),
        TradKey::Ec(curve @ (EcCurve::BrainpoolP256r1 | EcCurve::BrainpoolP384r1)) => {
            use rand::RngCore;
            let (d, pk) = crate::crypto::brainpool::generate(curve.engine_curve(), &mut |b: &mut [u8]| {
                rng.fill_bytes(b)
            })?;
            (pk, Zeroizing::new(ec_private_key_der(curve, &d)))
        }
        TradKey::X25519 => {
            let sk = x25519_dalek::StaticSecret::random_from_rng(&mut rng);
            let pk = x25519_dalek::PublicKey::from(&sk).as_bytes().to_vec();
            (pk, Zeroizing::new(Zeroizing::new(sk.to_bytes()).to_vec()))
        }
        TradKey::X448 => {
            let mut k = Zeroizing::new([0u8; 56]);
            getrandom::getrandom(k.as_mut()).map_err(|_| CKR_FUNCTION_FAILED)?;
            let pk = x448::PublicKey::from(&x448::StaticSecret::from(*k)).as_bytes().to_vec();
            (pk, Zeroizing::new(k.to_vec()))
        }
        TradKey::Ed25519 => {
            let sk = ed25519_dalek::SigningKey::generate(&mut rng);
            (sk.verifying_key().to_bytes().to_vec(), Zeroizing::new(Zeroizing::new(sk.to_bytes()).to_vec()))
        }
        TradKey::Ed448 => {
            // Same RNG plumbing as native::keygen::generate_ed448_keypair.
            use ed448_goldilocks::elliptic_curve::Generate;
            use getrandom_0_4::rand_core::UnwrapErr;
            use getrandom_0_4::SysRng;
            let sk = ed448_goldilocks::SigningKey::generate_from_rng(&mut UnwrapErr(SysRng));
            (sk.verifying_key().to_bytes().to_vec(), Zeroizing::new(sk.to_bytes().to_vec()))
        }
    })
}

// ── ML halves ──────────────────────────────────────────────────────────────

/// `mlPK` from `mlSeed` through the engine's single-algorithm key generation
/// (FIPS 203 Algorithm 16 / FIPS 204 Algorithm 6). The drafts' private key
/// is exactly that seed (composite-kem-23 §3.1 `ML-KEM.KeyGen_internal(
/// mlkemSeed[:32], mlkemSeed[32:])`; composite-sigs-19 §4.2).
pub fn ml_public_from_seed(ml: MlKey, seed: &[u8]) -> Result<Vec<u8>, CkRv> {
    match ml {
        MlKey::Kem(ps) => {
            if seed.len() != MLKEM_SEED_LEN {
                return Err(CKR_ATTRIBUTE_VALUE_INVALID);
            }
            let (ek, dk) = crate::crypto::handlers::ml_kem_keygen_from_seed(ps, seed).ok_or(CKR_FUNCTION_FAILED)?;
            drop(Zeroizing::new(dk));
            Ok(ek)
        }
        MlKey::Dsa(ps) => {
            let xi: &[u8; 32] = seed.try_into().map_err(|_| CKR_ATTRIBUTE_VALUE_INVALID)?;
            let (pk, sk) = crate::crypto::handlers::ml_dsa_keygen_from_seed(ps, xi).ok_or(CKR_FUNCTION_FAILED)?;
            drop(Zeroizing::new(sk));
            Ok(pk)
        }
    }
}

fn ml_public_is_valid(ml: MlKey, pk: &[u8]) -> bool {
    match ml {
        // FIPS 203 §7.2 encapsulation-key check, the same one C_CreateObject
        // runs on a plain CKK_ML_KEM public key.
        MlKey::Kem(ps) => crate::native::keygen::ml_kem_ek_check(ps, pk) == Some(true),
        // FIPS 204 pkDecode accepts every string of the right length.
        MlKey::Dsa(_) => true,
    }
}

// ── Whole composite keys ─────────────────────────────────────────────────

/// The composite public key `mlPK ‖ tradPK` for a composite private key
/// `mlSeed ‖ tradSK`: both halves re-derived (composite-kem-23 §10.4;
/// composite-sigs-19 §4). `CKR_ATTRIBUTE_VALUE_INVALID` if the value has a
/// length the set does not allow or either half is not a valid key.
pub fn public_from_private(layout: &Layout, sk: &[u8]) -> Result<Vec<u8>, CkRv> {
    let (seed, trad_sk) = layout.split_private(sk).ok_or(CKR_ATTRIBUTE_VALUE_INVALID)?;
    let mut pk = ml_public_from_seed(layout.ml, seed)?;
    pk.extend_from_slice(&trad_public_from_private(layout.trad, trad_sk)?);
    Ok(pk)
}

/// Whether `pk` is a well-formed composite public key for the set.
pub fn public_is_valid(layout: &Layout, pk: &[u8]) -> bool {
    layout
        .split_public(pk)
        .is_some_and(|(ml, trad)| ml_public_is_valid(layout.ml, ml) && trad_public_is_valid(layout.trad, trad))
}

/// A fresh composite key pair `(pk, sk)` (composite-kem-23 §3.1,
/// composite-sigs-19 §3.1): a random ML seed expanded by the engine's own
/// single-algorithm key generation, and an independent traditional key.
pub fn generate(layout: &Layout) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CkRv> {
    use rand::RngCore;
    let mut sk = Zeroizing::new(vec![0u8; layout.seed_len]);
    rand::rngs::OsRng.fill_bytes(&mut sk);
    let mut pk = ml_public_from_seed(layout.ml, &sk)?;
    let (trad_pk, trad_sk) = trad_generate(layout.trad)?;
    pk.extend_from_slice(&trad_pk);
    sk.extend_from_slice(&trad_sk);
    Ok((pk, sk))
}

// ── Object attributes ──────────────────────────────────────────────────────

/// Default attributes of a freshly generated composite pair, before the
/// caller's templates are absorbed. Mirrors the CKM_ML_KEM_KEY_PAIR_GEN /
/// CKM_ML_DSA_KEY_PAIR_GEN arms of `ffi::C_GenerateKeyPair`: the private key
/// is sensitive and non-extractable unless the template says otherwise, the
/// usage flags are the family's (CKA_ENCAPSULATE / CKA_DECAPSULATE or
/// CKA_VERIFY / CKA_SIGN). The mechanism contributes CKA_CLASS, CKA_KEY_TYPE
/// and CKA_VALUE to both keys and CKA_PARAMETER_SET to the private key
/// (comp_kem.md, comp_sig.md "key pair generation"); CKA_PUBLIC_KEY_INFO is
/// the composite SPKI on both (PKCS#11 v3.2 §4.14).
pub fn key_pair_attrs(layout: &Layout, pk: Vec<u8>, sk: Zeroizing<Vec<u8>>, keygen_mech: u32) -> (Attributes, Attributes) {
    let params = layout.params;
    let kem = params.family() == CompositeFamily::Kem;
    let key_type = params.family().key_type();
    let info = spki(params.oid(), &pk);
    let mut pub_attrs: Attributes = HashMap::new();
    let mut prv_attrs: Attributes = HashMap::new();
    for (attrs, class) in [(&mut pub_attrs, CKO_PUBLIC_KEY), (&mut prv_attrs, CKO_PRIVATE_KEY)] {
        store_ulong(attrs, CKA_CLASS, class);
        store_ulong(attrs, CKA_KEY_TYPE, key_type);
        store_ulong(attrs, CKA_PARAMETER_SET, params.ckp());
        store_param_set(attrs, params.ckp());
        store_ulong(attrs, CKA_KEY_GEN_MECHANISM, keygen_mech);
        store_bool(attrs, CKA_TOKEN, false);
        store_bool(attrs, CKA_DERIVE, false);
        store_bool(attrs, CKA_LOCAL, true);
        attrs.insert(CKA_PUBLIC_KEY_INFO, info.clone());
    }
    store_bool(&mut pub_attrs, CKA_PRIVATE, false);
    store_bool(&mut pub_attrs, CKA_ENCRYPT, false);
    store_bool(&mut pub_attrs, CKA_WRAP, false);
    store_bool(&mut pub_attrs, CKA_VERIFY, !kem);
    store_bool(&mut pub_attrs, CKA_ENCAPSULATE, kem);
    pub_attrs.insert(CKA_VALUE, pk);

    store_bool(&mut prv_attrs, CKA_PRIVATE, true);
    store_bool(&mut prv_attrs, CKA_SENSITIVE, true);
    store_bool(&mut prv_attrs, CKA_EXTRACTABLE, false);
    store_bool(&mut prv_attrs, CKA_DECRYPT, false);
    store_bool(&mut prv_attrs, CKA_UNWRAP, false);
    store_bool(&mut prv_attrs, CKA_SIGN, !kem);
    store_bool(&mut prv_attrs, CKA_DECAPSULATE, kem);
    prv_attrs.insert(CKA_VALUE, sk.to_vec());
    (pub_attrs, prv_attrs)
}

/// `C_CreateObject` check for an imported composite key (no-op for every
/// other key type). comp_kem.md / comp_sig.md: CKA_PARAMETER_SET and
/// CKA_VALUE "must be specified when the object is created" (footnote 1).
///
/// The value is split per the drafts' §4 and BOTH public halves are derived
/// or checked with the engine's single-algorithm code: for a private key from
/// `mlSeed` and `tradSK`, for a public key by validating `mlPK` (FIPS 203
/// §7.2 for ML-KEM) and `tradPK`. The engine then stores the composite SPKI
/// as CKA_PUBLIC_KEY_INFO.
///
/// Return codes, PKCS#11 v3.2 §4.1.1 "Creating objects":
/// - CKA_PARAMETER_SET or CKA_VALUE absent → CKR_TEMPLATE_INCOMPLETE (rule 3,
///   "does not specify all the necessary attributes");
/// - a CKA_PARAMETER_SET value that names no set, a CKA_VALUE of a length
///   the set does not allow, or a half that is not a valid key →
///   CKR_ATTRIBUTE_VALUE_INVALID (rule 2, "an invalid value for a valid
///   attribute" — the same code the engine returns for an ML-KEM key that
///   fails FIPS 203 §7.2/§7.3);
/// - a caller CKA_PUBLIC_KEY_INFO that is not the SPKI of the key derived
///   from CKA_VALUE (halves of different keys) → CKR_TEMPLATE_INCONSISTENT
///   (rule 5, attribute values that "are inconsistent");
/// - a set this build does not run (brainpool without feature `brainpool`)
///   → CKR_PARAMETER_SET_NOT_SUPPORTED (see [`supported_layout`]).
pub fn check_imported_key(class: Option<u32>, attrs: &mut Attributes) -> Result<(), CkRv> {
    let Some(key_type) = get_object_attr_u32_from(attrs, CKA_KEY_TYPE) else {
        return Ok(());
    };
    if CompositeFamily::from_key_type(key_type).is_none() {
        return Ok(());
    }
    let ckp = get_object_attr_u32_from(attrs, CKA_PARAMETER_SET).ok_or(CKR_TEMPLATE_INCOMPLETE)?;
    let layout = supported_layout(key_type, ckp, CKR_ATTRIBUTE_VALUE_INVALID)?;
    if class == Some(CKO_PRIVATE_KEY) {
        normalise_imported_private(&layout, attrs)?;
    }
    let value = attrs.get(&CKA_VALUE).ok_or(CKR_TEMPLATE_INCOMPLETE)?;
    let pk = match class {
        Some(CKO_PRIVATE_KEY) => public_from_private(&layout, value)?,
        Some(CKO_PUBLIC_KEY) if public_is_valid(&layout, value) => value.clone(),
        Some(CKO_PUBLIC_KEY) => return Err(CKR_ATTRIBUTE_VALUE_INVALID),
        _ => return Err(CKR_TEMPLATE_INCONSISTENT),
    };
    let info = spki(layout.params.oid(), &pk);
    if let Some(given) = attrs.get(&CKA_PUBLIC_KEY_INFO).filter(|v| !v.is_empty()) {
        if *given != info {
            return Err(CKR_TEMPLATE_INCONSISTENT);
        }
    }
    attrs.insert(CKA_PUBLIC_KEY_INFO, info);
    Ok(())
}

/// Replace an imported private CKA_VALUE whose `tradSK` carries the
/// ECPrivateKey publicKey field with its canonical form (see
/// [`canonical_trad_private`]). The original bytes are wiped.
fn normalise_imported_private(layout: &Layout, attrs: &mut Attributes) -> Result<(), CkRv> {
    let Some(value) = attrs.get(&CKA_VALUE) else {
        return Ok(());
    };
    if value.len() <= layout.seed_len {
        return Ok(());
    }
    let (seed, trad_sk) = value.split_at(layout.seed_len);
    if let Some(canonical) = canonical_trad_private(layout.trad, trad_sk)? {
        let mut fixed = seed.to_vec();
        fixed.extend_from_slice(&canonical);
        if let Some(old) = attrs.insert(CKA_VALUE, fixed) {
            drop(Zeroizing::new(old));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oid_and_spki_encoding() {
        // 1.3.6.1.5.5.7.6.58 = 2B 06 01 05 05 07 06 3A
        assert_eq!(oid_body("1.3.6.1.5.5.7.6.58"), [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x3a]);
        // 1.2.840.10045.3.1.7 (P-256) = 2A 86 48 CE 3D 03 01 07
        assert_eq!(oid_body("1.2.840.10045.3.1.7"), [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]);
        let s = spki("1.3.6.1.5.5.7.6.58", &[0xAA; 3]);
        // SEQUENCE(18) { SEQUENCE(10) { OID(8) }, BIT STRING(4) { 00, key } }
        assert_eq!(s, [0x30, 0x12, 0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x3a, 0x03, 0x04, 0x00, 0xAA, 0xAA, 0xAA]);
    }

    /// RFC 5915 encoding sizes are the drafts' Appendix A private sizes
    /// (P-256 51, P-384 64, P-521 82; table in native::composite), and the
    /// parser accepts exactly what the encoder writes.
    #[test]
    fn ec_private_key_round_trip_and_strictness() {
        for (curve, len) in [(EcCurve::P256, 51), (EcCurve::P384, 64), (EcCurve::P521, 82)] {
            let d = vec![0x11u8; curve.field_bytes()];
            let der = ec_private_key_der(curve, &d);
            assert_eq!(der.len(), len, "{curve:?}");
            assert_eq!(ec_private_key_scalar(curve, &der), Some(d.as_slice()));
            let other = if curve == EcCurve::P256 { EcCurve::P384 } else { EcCurve::P256 };
            assert_eq!(ec_private_key_scalar(other, &der), None, "curve OID bound");
            let mut trailing = der.clone();
            trailing.push(0);
            assert_eq!(ec_private_key_scalar(curve, &trailing), None, "trailing byte");
        }
    }

    /// RFC 5915 with the optional publicKey field: `der` plus `[1] BIT STRING`.
    fn with_public_key(der: &[u8], point: &[u8]) -> Vec<u8> {
        let (_, body, _) = der_take(der).unwrap();
        let mut bits = vec![0u8];
        bits.extend_from_slice(point);
        let mut body = body.to_vec();
        body.extend_from_slice(&der_tlv(0xa1, &der_tlv(0x03, &bits)));
        der_tlv(0x30, &body)
    }

    /// composite-kem-23 §10.5 / composite-sigs-19 §10.6 leniency: an
    /// ECPrivateKey carrying the publicKey field is accepted only when the
    /// point is the scalar's public key, and comes back canonical.
    #[test]
    fn ec_private_key_with_public_key_field() {
        for curve in [EcCurve::P256, EcCurve::P384, EcCurve::P521] {
            let (pk, sk) = trad_generate(TradKey::Ec(curve)).unwrap();
            let (other_pk, _) = trad_generate(TradKey::Ec(curve)).unwrap();
            assert_eq!(canonical_trad_private(TradKey::Ec(curve), &sk), Ok(None), "canonical already");

            let lenient = with_public_key(&sk, &pk);
            assert_eq!(ec_private_key_scalar(curve, &lenient), None, "the strict parser still refuses it");
            let canon = canonical_trad_private(TradKey::Ec(curve), &lenient).unwrap().expect("re-encoded");
            assert_eq!(canon.as_slice(), sk.as_slice(), "{curve:?}: the field is dropped");

            // The point of another key, a point off the curve, a truncated
            // BIT STRING: refused like any other invalid half.
            let wrong = with_public_key(&sk, &other_pk);
            assert_eq!(canonical_trad_private(TradKey::Ec(curve), &wrong), Err(CKR_ATTRIBUTE_VALUE_INVALID));
            let mut off = pk.clone();
            *off.last_mut().unwrap() ^= 1;
            let off_curve = with_public_key(&sk, &off);
            assert_eq!(canonical_trad_private(TradKey::Ec(curve), &off_curve), Err(CKR_ATTRIBUTE_VALUE_INVALID));
            assert_eq!(
                canonical_trad_private(TradKey::Ec(curve), &with_public_key(&sk, &pk[..pk.len() - 1])),
                Err(CKR_ATTRIBUTE_VALUE_INVALID)
            );
            // A non-zero unused-bits count is malformed, not lenient.
            let mut bad_bits = lenient.clone();
            let i = bad_bits.len() - pk.len() - 1;
            assert_eq!(bad_bits[i], 0);
            bad_bits[i] = 1;
            assert_eq!(canonical_trad_private(TradKey::Ec(curve), &bad_bits), Ok(None));
            assert_eq!(ec_private_key_scalar(curve, &bad_bits), None);
        }
        // Non-EC halves are untouched.
        let (_, sk) = trad_generate(TradKey::X25519).unwrap();
        assert_eq!(canonical_trad_private(TradKey::X25519, &sk), Ok(None));
    }
}
