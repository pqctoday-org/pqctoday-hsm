// SPDX-License-Identifier: AGPL-3.0-only
//
//! Composite ML-DSA — `CKM_COMP_SIG` and `CKM_COMP_SIG_EXTERNAL_HASH`,
//! PKCS#11 v3.3 working draft (`working/doc/spec/comp_sig.md`, OASIS
//! PKCS 11 TC commit 9ef73f9), over draft-ietf-lamps-pq-composite-sigs-19
//! §2.2 (M'), §3.2 (Sign), §3.3 (Verify), §4.3 (signature serialization)
//! and §10.5 (external pre-hashing). The engine still reports Cryptoki 3.2.0.
//!
//! ```text
//! M'       = Prefix ‖ Label ‖ len(ctx) ‖ ctx ‖ PH(M)            (§2.2)
//! mldsaSig = ML-DSA.Sign(mldsaSK, M', ctx = Label)             (§3.2 step 4)
//! tradSig  = Trad.Sign(tradSK, M')
//! s        = mldsaSig ‖ tradSig                                 (§4.3)
//! ```
//!
//! `Prefix` is [`COMPOSITE_SIG_PREFIX`], `Label` and `PH` come from the set's
//! row in `native::composite`, `len(ctx)` is one unsigned byte (§3.2 step 2,
//! "As in FIPS 204"). The ML-DSA half is pure ML-DSA (FIPS 204 Algorithm 2)
//! with the composite label as ITS context; the caller's `ctx` only enters
//! M'. The traditional half signs M' with the row's algorithm in the §4
//! encodings: RSASSA-PSS with the §6.1 Table 2/3 parameters, RSASSA-PKCS1-v1_5,
//! ECDSA as a DER `Ecdsa-Sig-Value` (RFC 3279 §2.2.3), PureEdDSA (Ed25519,
//! Ed448 with an empty context — §3.2: an EdDSA ctx "is not used by
//! Composite ML-DSA").
//!
//! Both halves run through the engine's single-algorithm code
//! (`crypto::handlers`): `sign_ml_dsa` / `verify_ml_dsa` with `CKM_ML_DSA`,
//! `sign_rsa` / `verify_rsa`, `sign_ecdsa` / `verify_ecdsa`, `sign_eddsa` /
//! `verify_eddsa`. The expanded ML-DSA key and the traditional private key
//! in PKCS#8 form live in `Zeroizing` buffers; only the signature leaves.
//!
//! Every entry point here takes PH(M), never M: `CKM_COMP_SIG` hashes M on
//! the token (one-shot through [`pre_hash`], multi-part through
//! [`PreHasher`], so the message is streamed, not buffered) and
//! `CKM_COMP_SIG_EXTERNAL_HASH` takes PH(M) from the caller — §10.5's
//! `Sign_ph`, "identical to Composite-ML-DSA<OID>.Sign (sk, M, ctx) but
//! replace the internally generated PH( M ) ... with ph".

use zeroize::Zeroizing;

use super::composite::{CompositeParams, CompositeSigParams, EcCurve, PreHash, SigClassical, TradHash, COMPOSITE_SIG_PREFIX};
use super::composite_key::{der_tlv, ec_private_key_scalar, oid_body, Layout};
use super::CkRv;
use crate::constants::*;
use crate::crypto::handlers::{CURVE_P256, CURVE_P384, CURVE_P521};

/// Maximum `ctx` length: "If len(ctx) > 255: return error" (§3.2 step 1,
/// §3.3 step 1); `len(ctx)` is a single byte.
pub const MAX_CTX_LEN: usize = 255;

// ── PH ─────────────────────────────────────────────────────────────────────

/// Incremental PH (§6 "Pre-Hash function (PH)"): SHA-256, SHA-512, or
/// SHAKE256 with 64 bytes of output (§6 note "**"). Holds only message-
/// derived state, no key material. `Clone` so a size query can finalize a
/// copy and leave the operation running.
#[derive(Clone)]
pub enum PreHasher {
    Sha256(sha2::Sha256),
    Sha512(sha2::Sha512),
    Shake256(sha3::Shake256),
}

impl PreHasher {
    pub fn new(ph: PreHash) -> Self {
        match ph {
            PreHash::Sha256 => PreHasher::Sha256(Default::default()),
            PreHash::Sha512 => PreHasher::Sha512(Default::default()),
            PreHash::Shake256_64 => PreHasher::Shake256(Default::default()),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        match self {
            PreHasher::Sha256(h) => sha2::Digest::update(h, data),
            PreHasher::Sha512(h) => sha2::Digest::update(h, data),
            PreHasher::Shake256(h) => sha3::digest::Update::update(h, data),
        }
    }

    /// PH(M): 32 or 64 bytes ([`PreHash::output_len`]).
    pub fn finalize(self) -> Vec<u8> {
        match self {
            PreHasher::Sha256(h) => sha2::Digest::finalize(h).to_vec(),
            PreHasher::Sha512(h) => sha2::Digest::finalize(h).to_vec(),
            PreHasher::Shake256(h) => {
                use sha3::digest::{ExtendableOutput, XofReader};
                let mut out = vec![0u8; PreHash::Shake256_64.output_len()];
                h.finalize_xof().read(&mut out);
                out
            }
        }
    }
}

/// PH(M) in one call.
pub fn pre_hash(ph: PreHash, m: &[u8]) -> Vec<u8> {
    let mut h = PreHasher::new(ph);
    h.update(m);
    h.finalize()
}

/// `M' = Prefix ‖ Label ‖ len(ctx) ‖ ctx ‖ PH(M)` (§2.2, §3.2 step 2).
///
/// `ph` must be exactly the set's PH length. For `CKM_COMP_SIG_EXTERNAL_HASH`
/// that is caller input, and a wrong length is `CKR_DATA_LEN_RANGE` —
/// comp_sig.md: the mechanism "MUST require PH(M) to be 64 bytes long" for a
/// SHA512 set; v3.2 §5.1.6 / v3.3 `function_return_values.md`: "The plaintext
/// input data to a cryptographic operation has a bad length", listed for both
/// C_Sign and C_Verify (v3.3 `signing_and_macing_functions.md`,
/// `functions_for_verifying_signatures_and_macs.md`); the same code the
/// engine's RSA digest-signing path returns for a digest of the wrong length
/// (`crypto::awslc_rsa::sign_pkcs1_digest`). An over-long `ctx` cannot reach
/// here (refused at C_SignInit / C_VerifyInit); it is refused again as
/// `CKR_MECHANISM_PARAM_INVALID` for any other caller.
pub fn message_representative(p: &CompositeSigParams, ctx: &[u8], ph: &[u8]) -> Result<Vec<u8>, CkRv> {
    if ctx.len() > MAX_CTX_LEN {
        return Err(CKR_MECHANISM_PARAM_INVALID);
    }
    if ph.len() != p.pre_hash.output_len() {
        return Err(CKR_DATA_LEN_RANGE);
    }
    let mut m = Vec::with_capacity(COMPOSITE_SIG_PREFIX.len() + p.label.len() + 1 + ctx.len() + ph.len());
    m.extend_from_slice(COMPOSITE_SIG_PREFIX);
    m.extend_from_slice(p.label);
    m.push(ctx.len() as u8);
    m.extend_from_slice(ctx);
    m.extend_from_slice(ph);
    Ok(m)
}

/// Whether the set can honour `CKH_DETERMINISTIC_REQUIRED`. The hedge
/// variant of `CK_SIGN_ADDITIONAL_CONTEXT` (comp_sig.md: "defined in the
/// ML-DSA section"; ml_dsa.md: with CKH_DETERMINISTIC_REQUIRED "the token
/// must produce a deterministic signature or fail") selects FIPS 204's
/// deterministic ML-DSA variant for the ML half. The whole composite
/// signature is then deterministic when the traditional half is: PKCS#1
/// v1.5 and PureEdDSA are by construction, and the engine's P-256 / P-384
/// ECDSA uses RFC 6979 nonces (`crypto::handlers::sign_ecdsa`). Two
/// traditional halves are randomised, so their sets cannot, and C_SignInit
/// refuses the request: RSASSA-PSS draws a fresh 32- or 48-byte salt (§6.1
/// Tables 2–3, saltLength), and the engine's P-521 ECDSA is the `p521`
/// crate's `Signer`, which signs with a random nonce (p521 0.13.3
/// `src/ecdsa.rs:159-162`, `try_sign_with_rng(&mut OsRng, ..)`; measured by
/// `composite_sig_tests::keygen_and_round_trip_all_supported_sets`).
pub fn deterministic_available(p: &CompositeSigParams) -> bool {
    !matches!(
        p.classical,
        SigClassical::RsaPss { .. } | SigClassical::Ecdsa { curve: EcCurve::P521, .. }
    )
}

// ── Traditional halves ─────────────────────────────────────────────────────

/// rsaEncryption, RFC 8017 Appendix C.
const RSA_ENCRYPTION_OID: &str = "1.2.840.113549.1.1.1";

/// The draft's `RSAPrivateKey` (§4) as the PKCS#8 `PrivateKeyInfo` the
/// engine's RSA signer takes (RFC 5208 §5: version 0, rsaEncryption with
/// NULL parameters, the RSAPrivateKey in the OCTET STRING).
fn rsa_pkcs8(rsa_private_key: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut alg = der_tlv(0x06, &oid_body(RSA_ENCRYPTION_OID));
    alg.extend_from_slice(&[0x05, 0x00]);
    let mut body = Zeroizing::new(vec![0x02, 0x01, 0x00]);
    body.extend_from_slice(&der_tlv(0x30, &alg));
    body.extend_from_slice(&Zeroizing::new(der_tlv(0x04, rsa_private_key)));
    Zeroizing::new(der_tlv(0x30, &body))
}

/// The engine mechanism for an RSA row: §6 "sha256WithRSAEncryption" /
/// "sha384WithRSAEncryption" for PKCS#1 v1.5, id-RSASSA-PSS with the
/// §6.1 Table 2 (SHA-256, MGF1-SHA-256, salt 32) or Table 3 (SHA-384,
/// MGF1-SHA-384, salt 48) parameters — the engine's hash-specific PSS
/// mechanisms use MGF1 with the same hash, and take the salt explicitly.
fn rsa_mechanism(c: SigClassical) -> (u32, Option<usize>) {
    match c {
        SigClassical::RsaPss { hash, salt_len, .. } => (
            match hash {
                TradHash::Sha256 => CKM_SHA256_RSA_PKCS_PSS,
                TradHash::Sha384 => CKM_SHA384_RSA_PKCS_PSS,
                TradHash::Sha512 => CKM_SHA512_RSA_PKCS_PSS,
            },
            Some(salt_len),
        ),
        SigClassical::RsaPkcs15 { hash, .. } => (
            match hash {
                TradHash::Sha256 => CKM_SHA256_RSA_PKCS,
                TradHash::Sha384 => CKM_SHA384_RSA_PKCS,
                TradHash::Sha512 => CKM_SHA512_RSA_PKCS,
            },
            None,
        ),
        _ => unreachable!("RSA rows only"),
    }
}

/// The engine's `(CKM_ECDSA_SHAnnn, curve)` for an ECDSA row: §6
/// "ecdsa-with-SHAnnn", whose hash tracks the curve, not PH.
fn ecdsa_mechanism(curve: EcCurve, hash: TradHash) -> Result<(u32, u32), CkRv> {
    let curve = match curve {
        EcCurve::P256 => CURVE_P256,
        EcCurve::P384 => CURVE_P384,
        EcCurve::P521 => CURVE_P521,
        EcCurve::BrainpoolP256r1 | EcCurve::BrainpoolP384r1 => return Err(CKR_PARAMETER_SET_NOT_SUPPORTED),
    };
    let mech = match hash {
        TradHash::Sha256 => CKM_ECDSA_SHA256,
        TradHash::Sha384 => CKM_ECDSA_SHA384,
        TradHash::Sha512 => CKM_ECDSA_SHA512,
    };
    Ok((mech, curve))
}

/// The engine's ECDSA signers and verifiers speak the fixed-width `r ‖ s`
/// form; the draft's tradSig is DER `Ecdsa-Sig-Value` (§4 "*ECDSA*", RFC 3279
/// §2.2.3). `to_der` / `from_der` are the curve crates' strict DER codecs.
fn ecdsa_raw_to_der(curve: EcCurve, raw: &[u8]) -> Result<Vec<u8>, CkRv> {
    macro_rules! der {
        ($c:ident) => {
            $c::ecdsa::Signature::from_slice(raw).map_err(|_| CKR_FUNCTION_FAILED)?.to_der().as_bytes().to_vec()
        };
    }
    Ok(match curve {
        EcCurve::P256 => der!(p256),
        EcCurve::P384 => der!(p384),
        EcCurve::P521 => der!(p521),
        EcCurve::BrainpoolP256r1 | EcCurve::BrainpoolP384r1 => return Err(CKR_PARAMETER_SET_NOT_SUPPORTED),
    })
}

fn ecdsa_der_to_raw(curve: EcCurve, der: &[u8]) -> Result<Vec<u8>, CkRv> {
    macro_rules! raw {
        ($c:ident) => {
            $c::ecdsa::Signature::from_der(der).map_err(|_| CKR_SIGNATURE_INVALID)?.to_bytes().to_vec()
        };
    }
    Ok(match curve {
        EcCurve::P256 => raw!(p256),
        EcCurve::P384 => raw!(p384),
        EcCurve::P521 => raw!(p521),
        EcCurve::BrainpoolP256r1 | EcCurve::BrainpoolP384r1 => return Err(CKR_PARAMETER_SET_NOT_SUPPORTED),
    })
}

/// `Trad.Sign(tradSK, M')` in the §4 encodings. `tradSK` is the stored
/// private value's second half, checked at import or generation.
fn trad_sign(c: SigClassical, trad_sk: &[u8], m: &[u8]) -> Result<Vec<u8>, CkRv> {
    use crate::crypto::handlers::{sign_ecdsa, sign_eddsa, sign_rsa};
    match c {
        SigClassical::RsaPss { .. } | SigClassical::RsaPkcs15 { .. } => {
            let (mech, salt) = rsa_mechanism(c);
            sign_rsa(mech, &rsa_pkcs8(trad_sk), m, salt)
        }
        SigClassical::Ecdsa { curve, hash } => {
            let (mech, ck_curve) = ecdsa_mechanism(curve, hash)?;
            let d = ec_private_key_scalar(curve, trad_sk).ok_or(CKR_KEY_TYPE_INCONSISTENT)?;
            ecdsa_raw_to_der(curve, &sign_ecdsa(mech, ck_curve, d, m)?)
        }
        // sign_eddsa picks Ed25519 / Ed448 from the 32- / 57-byte key and
        // signs PureEdDSA with no context (Ed448: the empty context).
        SigClassical::Ed25519 | SigClassical::Ed448 => sign_eddsa(trad_sk, m),
    }
}

/// `Trad.Verify(tradPK, M', tradSig)`; `Err(CKR_SIGNATURE_INVALID)` when the
/// component rejects the signature.
fn trad_verify(c: SigClassical, trad_pk: &[u8], m: &[u8], sig: &[u8]) -> Result<(), CkRv> {
    use crate::crypto::handlers::{verify_ecdsa, verify_eddsa, verify_rsa};
    match c {
        SigClassical::RsaPss { .. } | SigClassical::RsaPkcs15 { .. } => {
            use rsa::pkcs1::DecodeRsaPublicKey;
            use rsa::traits::PublicKeyParts;
            let k = rsa::RsaPublicKey::from_pkcs1_der(trad_pk).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let (mech, salt) = rsa_mechanism(c);
            verify_rsa(mech, &k.n().to_bytes_be(), &k.e().to_bytes_be(), m, sig, salt)
        }
        SigClassical::Ecdsa { curve, hash } => {
            let (mech, ck_curve) = ecdsa_mechanism(curve, hash)?;
            verify_ecdsa(mech, ck_curve, trad_pk, m, &ecdsa_der_to_raw(curve, sig)?)
        }
        SigClassical::Ed25519 | SigClassical::Ed448 => verify_eddsa(trad_pk, m, sig),
    }
}

// ── Composite operations ───────────────────────────────────────────────────

fn layout(p: &'static CompositeSigParams) -> Result<Layout, CkRv> {
    if !p.supported {
        return Err(CKR_PARAMETER_SET_NOT_SUPPORTED);
    }
    Ok(Layout::from(CompositeParams::Sig(p)))
}

/// `Composite-ML-DSA.Sign_ph(sk, ph, ctx)` (§10.5, i.e. §3.2 with PH(M)
/// given). `sk` is the private key's CKA_VALUE `mldsaSeed ‖ tradSK`;
/// `deterministic` is `CKH_DETERMINISTIC_REQUIRED` (see
/// [`deterministic_available`]; otherwise ML-DSA signs hedged, FIPS 204
/// Algorithm 2). A value that no longer splits is `CKR_KEY_TYPE_INCONSISTENT`,
/// as for CKM_COMP_KEM; a component failure is an error (§3.2 step 5).
pub fn sign_ph(p: &'static CompositeSigParams, sk: &[u8], ph: &[u8], ctx: &[u8], deterministic: bool) -> Result<Vec<u8>, CkRv> {
    let layout = layout(p)?;
    if deterministic && !deterministic_available(p) {
        return Err(CKR_MECHANISM_PARAM_INVALID);
    }
    let m = message_representative(p, ctx, ph)?;
    // (mldsaSeed, tradSK) = DeserializePrivateKey(sk);
    // (_, mldsaSK) = ML-DSA.KeyGen_internal(mldsaSeed) — §3.2 step 3.
    let (seed, trad_sk) = layout.split_private(sk).ok_or(CKR_KEY_TYPE_INCONSISTENT)?;
    let xi: &[u8; 32] = seed.try_into().map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
    let (_, ml_sk) = crate::crypto::handlers::ml_dsa_keygen_from_seed(p.ml_dsa, xi).ok_or(CKR_KEY_TYPE_INCONSISTENT)?;
    let ml_sk = Zeroizing::new(ml_sk);
    // §3.2 step 4: mldsaSig = ML-DSA.Sign(mldsaSK, M', mldsa_ctx=Label).
    let mut s = crate::crypto::handlers::sign_ml_dsa(CKM_ML_DSA, p.ml_dsa, &ml_sk, &m, p.label, deterministic)?;
    if s.len() != p.ml_dsa_signature_len() {
        return Err(CKR_FUNCTION_FAILED);
    }
    let trad_sig = trad_sign(p.classical, trad_sk, &m)?;
    if !p.classical_sizes.output.admits(trad_sig.len()) {
        return Err(CKR_FUNCTION_FAILED);
    }
    // §4.3: s = mldsaSig ‖ tradSig.
    s.extend_from_slice(&trad_sig);
    Ok(s)
}

/// `Composite-ML-DSA.Sign(sk, M, ctx)` (§3.2): PH(M) on the token, then
/// [`sign_ph`].
pub fn sign(p: &'static CompositeSigParams, sk: &[u8], m: &[u8], ctx: &[u8], deterministic: bool) -> Result<Vec<u8>, CkRv> {
    sign_ph(p, sk, &pre_hash(p.pre_hash, m), ctx, deterministic)
}

/// Split a composite signature (§4.3 DeserializeSignatureValue): the first
/// ML-DSA signature length bytes, then the rest. `None` when either half has
/// a length its component can never produce: the ML-DSA length is fixed
/// (§4 Table 1), the traditional one fixed (RSA, EdDSA) or bounded (DER
/// ECDSA, Appendix A `*`), and never empty.
pub fn split_signature<'a>(p: &CompositeSigParams, s: &'a [u8]) -> Option<(&'a [u8], &'a [u8])> {
    let n = p.ml_dsa_signature_len();
    if s.len() <= n {
        return None;
    }
    let (ml, trad) = s.split_at(n);
    p.classical_sizes.output.admits(trad.len()).then_some((ml, trad))
}

/// `Composite-ML-DSA.Verify_ph(pk, ph, s, ctx)` (§3.3 with PH(M) given,
/// §10.5). `pk` is the public key's CKA_VALUE `mldsaPK ‖ tradPK`.
///
/// §3.3: "Valid signature" "if and only if all component signatures were
/// successfully validated". Results:
/// - a signature whose length no component split allows →
///   `CKR_SIGNATURE_LEN_RANGE` ("can be seen to be invalid solely on the
///   basis of its length", v3.2 §5.1.6; §3.3 step 2: a component value "not
///   of the correct ... length" is an invalid signature);
/// - either half rejected by its component (including a traditional half
///   that does not decode, §3.3 step 2) → `CKR_SIGNATURE_INVALID`;
/// - `ph` of the wrong length → `CKR_DATA_LEN_RANGE` (see
///   [`message_representative`]).
pub fn verify_ph(p: &'static CompositeSigParams, pk: &[u8], ph: &[u8], ctx: &[u8], s: &[u8]) -> Result<(), CkRv> {
    let layout = layout(p)?;
    let m = message_representative(p, ctx, ph)?;
    let (ml_pk, trad_pk) = layout.split_public(pk).ok_or(CKR_KEY_TYPE_INCONSISTENT)?;
    let (ml_sig, trad_sig) = split_signature(p, s).ok_or(CKR_SIGNATURE_LEN_RANGE)?;
    // §3.3 step 4: ML-DSA.Verify(mldsaPK, M', mldsaSig, mldsa_ctx=Label),
    // then Trad.Verify(tradPK, M', tradSig); both must pass.
    crate::crypto::handlers::verify_ml_dsa(CKM_ML_DSA, p.ml_dsa, ml_pk, &m, ml_sig, p.label)?;
    trad_verify(p.classical, trad_pk, &m, trad_sig)
}

/// `Composite-ML-DSA.Verify(pk, M, s, ctx)` (§3.3): PH(M) on the token,
/// then [`verify_ph`].
pub fn verify(p: &'static CompositeSigParams, pk: &[u8], m: &[u8], ctx: &[u8], s: &[u8]) -> Result<(), CkRv> {
    verify_ph(p, pk, &pre_hash(p.pre_hash, m), ctx, s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::composite::{sig_params, COMPOSITE_SIG_SETS};

    /// PH lengths (§6; comp_sig.md "MUST require PH(M) to be 64 bytes long"
    /// for SHA512) and streaming == one-shot. SHA-256("abc") is the FIPS
    /// 180-4 example digest.
    #[test]
    fn pre_hash_lengths_and_streaming() {
        assert_eq!(
            pre_hash(PreHash::Sha256, b"abc"),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0,
                0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
            ]
        );
        for ph in [PreHash::Sha256, PreHash::Sha512, PreHash::Shake256_64] {
            let msg = b"The quick brown fox jumps over the lazy dog.";
            let one = pre_hash(ph, msg);
            assert_eq!(one.len(), ph.output_len());
            let mut h = PreHasher::new(ph);
            for chunk in msg.chunks(7) {
                h.update(chunk);
            }
            assert_eq!(h.clone().finalize(), one);
            assert_eq!(h.finalize(), one);
        }
    }

    /// M' layout byte by byte (§2.2) and the length rules.
    #[test]
    fn message_representative_layout() {
        let p = sig_params(CKP_COMP_SIG_MLDSA65_ECDSA_P256_SHA512).unwrap();
        let ph = [0xAB; 64];
        let m = message_representative(p, b"ctx", &ph).unwrap();
        let mut want = b"CompositeAlgorithmSignatures2025".to_vec();
        want.extend_from_slice(b"COMPSIG-MLDSA65-ECDSA-P256-SHA512");
        want.push(3);
        want.extend_from_slice(b"ctx");
        want.extend_from_slice(&ph);
        assert_eq!(m, want);
        assert_eq!(message_representative(p, &[0; 255], &ph).unwrap()[32 + p.label.len()], 255);
        assert_eq!(message_representative(p, &[0; 256], &ph), Err(CKR_MECHANISM_PARAM_INVALID));
        assert_eq!(message_representative(p, b"", &ph[..63]), Err(CKR_DATA_LEN_RANGE));
        assert_eq!(message_representative(p, b"", &[0; 65]), Err(CKR_DATA_LEN_RANGE));
    }

    /// rsa_pkcs8 produces a PrivateKeyInfo the `rsa` crate reads back as the
    /// same key.
    #[test]
    fn rsa_pkcs8_wrapping() {
        use rsa::pkcs1::EncodeRsaPrivateKey;
        use rsa::pkcs8::DecodePrivateKey;
        let (_, sk) = crate::native::composite_key::trad_generate(crate::native::composite_key::TradKey::Rsa {
            modulus_bits: 2048,
        })
        .unwrap();
        let k = rsa::RsaPrivateKey::from_pkcs8_der(&rsa_pkcs8(&sk)).unwrap();
        assert_eq!(k.to_pkcs1_der().unwrap().as_bytes(), sk.as_slice());
    }

    /// Only the RSASSA-PSS and the P-521 sets refuse CKH_DETERMINISTIC_REQUIRED.
    #[test]
    fn deterministic_availability() {
        for p in COMPOSITE_SIG_SETS.iter() {
            let randomised = p.name.contains("-PSS-") || p.name.contains("-P521-");
            assert_eq!(deterministic_available(p), !randomised, "{}", p.name);
        }
    }
}
