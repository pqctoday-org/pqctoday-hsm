//! Inlined `openpgp-x509-sequoia` (0.2.0) helpers, ported to sequoia 2.x.
//!
//! Upstream `openpgp-x509-sequoia` 0.2.0 (LGPL-2.0-or-later) is abandoned and
//! hard-pins sequoia 1.x, so it cannot coexist with our sequoia 2.x dep — see
//! `docs/PQC_PGP_IMPLEMENTATION_PLAN.md` §2.3. We absorb the ~400 LOC the bridge
//! actually uses here instead of forking a dead crate. The public surface
//! (`types::*`, `experimental::*`, `generate_x509`, `self_sign_x509`,
//! `find_key_by_x509cert`) is preserved verbatim so the call sites only change
//! their import root from `openpgp_x509_sequoia::` to `crate::x509::`.
//!
//! Porting notes (sequoia 1.x -> 2.x): the symbols this module touches
//! (`Cert`, `Fingerprint`, `Key<…>`, `crypto::mpi::PublicKey`,
//! `key.fingerprint()`, `key.creation_time()`, `key.mpis()`) are stable across
//! the major bump, so the bodies are unchanged from upstream 0.2.0. Note that
//! `Fingerprint::as_bytes()` is 20 bytes for a v4 key and 32 bytes for a v6
//! key; this RSA/ECC X.509 path only handles classical v4 keys (composite PQC
//! keys do not flow through the X.509 cert custody path), so the 20-byte serial
//! assumption in `generate_x509` is intentionally retained.

use std::ops::DerefMut;

use anyhow::Result;
use asn1_rs::nom::AsBytes;
use chrono::{DateTime, Utc};
use sequoia_openpgp::packet::key::{PublicParts, SecretParts, UnspecifiedRole};
use sequoia_openpgp::packet::Key;
use sequoia_openpgp::Cert;
use sha2::{Digest, Sha256, Sha384, Sha512};
use x509::der::write::{der_octet_string, der_sequence};
use x509::write::algorithm_identifier;
use x509_certificate::X509Certificate;
use zeroize::Zeroizing;

use self::types::{AlgorithmId, DigestId, PublicKeyInfo, SigId};

pub mod experimental;
pub mod types;

// FIXME: this is a Yubikey PIV constant, just used as a placeholder here
const CB_OBJ_MAX: usize = 3072 - 9;

fn aid_to_sid(algo_id: AlgorithmId) -> SigId {
    match algo_id {
        AlgorithmId::Rsa2048 => SigId::Sha256WithRsaEncryption,
        AlgorithmId::Rsa3072 => SigId::Sha384WithRsaEncryption,
        AlgorithmId::Rsa4096 => SigId::Sha512WithRsaEncryption,

        AlgorithmId::EccP256 => SigId::EcdsaWithSha256,
        AlgorithmId::EccP384 => SigId::EcdsaWithSha384,
        AlgorithmId::EccP521 => SigId::EcdsaWithSha512,
    }
}

/// Generate an X.509 certificate based on an OpenPGP key
///
/// Minimal metadata for the OpenPGP key is stored in the X.509 certificate:
///
/// - The X.509 serial is set to the OpenPGP V4 fingerprint
/// - The X.509 "not before" field is set to the OpenPGP key creation time
///
/// (Note that these two metadata items correspond to what is stored
/// on OpenPGP card devices)
pub fn generate_x509(
    subject_pki: &PublicKeyInfo,
    key: &Key<SecretParts, UnspecifiedRole>,
    common_name: &str,
    extensions: &[x509::Extension<&'static [u64]>],
) -> Zeroizing<Vec<u8>> {
    let creation: DateTime<Utc> = key.creation_time().into();

    // Set serial to key's OpenPGP V4 Fingerprint
    let fp: [u8; 20] = key
        .fingerprint()
        .as_bytes()
        .try_into()
        .expect("fingerprint len != 20");
    let serial: Vec<u8> = fp.into();

    let subject = x509::RelativeDistinguishedName::common_name(common_name);

    let signature_algorithm = aid_to_sid(subject_pki.algorithm());

    // Serialize X.509 certificate into a Vec<u8>
    let mut tbs_cert = Zeroizing::new(Vec::with_capacity(CB_OBJ_MAX));

    cookie_factory::gen(
        x509::write::tbs_certificate::<&mut Vec<u8>, SigId, PublicKeyInfo, &'static [u64]>(
            &serial,
            &signature_algorithm,
            // Issuer and subject are the same in self-signed certificates.
            &[subject.clone()],
            creation,
            None, // no expiration for now
            &[subject],
            subject_pki,
            extensions,
        ),
        tbs_cert.deref_mut(),
    )
    .expect("can serialize to Vec");

    tbs_cert
}

/// Self-sign an X.509 certificate
#[allow(clippy::type_complexity)]
pub fn self_sign_x509(
    tbs_cert: Zeroizing<Vec<u8>>,
    algo_id: AlgorithmId,
    signer: &mut dyn FnMut(&[u8], AlgorithmId) -> Result<Vec<u8>>,
) -> Result<Vec<u8>> {
    fn sig<Alg: x509::AlgorithmIdentifier>(
        h: &'_ [u8],
        algorithm_ident: &'_ Alg,
        algo_id: AlgorithmId,
        signer: &mut dyn FnMut(&[u8], AlgorithmId) -> Result<Vec<u8>>,
    ) -> Result<Vec<u8>> {
        let t = cookie_factory::gen_simple(
            der_sequence((algorithm_identifier(algorithm_ident), der_octet_string(h))),
            vec![],
        )
        .expect("can serialize into Vec");

        // make signature on card
        signer(&t, algo_id)
    }

    let signature_algorithm = aid_to_sid(algo_id);

    let signature: Vec<_> = match signature_algorithm {
        SigId::Sha256WithRsaEncryption => {
            let h = Sha256::digest(&tbs_cert);
            sig(&h, &DigestId::Sha256, algo_id, signer)?
        }
        SigId::Sha384WithRsaEncryption => {
            let h = Sha384::digest(&tbs_cert);
            sig(&h, &DigestId::Sha384, algo_id, signer)?
        }
        SigId::Sha512WithRsaEncryption => {
            let h = Sha512::digest(&tbs_cert);
            sig(&h, &DigestId::Sha512, algo_id, signer)?
        }
        SigId::EcdsaWithSha256 => signer(&Sha256::digest(&tbs_cert), algo_id)?,
        SigId::EcdsaWithSha384 => signer(&Sha384::digest(&tbs_cert), algo_id)?,
        SigId::EcdsaWithSha512 => signer(&Sha512::digest(&tbs_cert), algo_id)?,
    };

    let mut data = Zeroizing::new(Vec::with_capacity(CB_OBJ_MAX));

    cookie_factory::gen(
        x509::write::certificate(&tbs_cert, &signature_algorithm, &signature),
        data.deref_mut(),
    )
    .expect("can serialize to Vec");

    Ok(data.to_vec())
}

/// Find the `sequoia_openpgp::packet::Key` from `cert` that
/// matches the public key material in `X509Certificate`, if any
pub fn find_key_by_x509cert(
    x509cert: &X509Certificate,
    cert: &Cert,
) -> Result<Key<PublicParts, UnspecifiedRole>> {
    use sequoia_openpgp::crypto::mpi::PublicKey;

    let x509_cert = x509_certificate::rfc5280::Certificate::from(x509cert.clone());

    if let Ok(rsa_pub) = x509cert.rsa_public_key_data() {
        for k in cert.keys() {
            if let PublicKey::RSA { n, .. } = k.key().mpis() {
                let modulus = rsa_pub.modulus.as_slice();
                if modulus.len() < n.value().len() {
                    // x509 "modulus" is shorter than OpenPGP key "n".
                    // We don't expect a need to add padding to the X.509
                    // data, so we don't attempt to compare these two keys.
                    // We assume that they can't be "the same".
                    continue;
                }

                // Check if X.509 key and OpenPGP key have the same public
                // key material.
                //
                // (unwrap is ok: we just checked that "modulus" is not
                // shorter than n.)
                if modulus == n.value_padded(modulus.len()).unwrap().as_ref() {
                    return Ok(k.key().clone());
                }
            }
        }
    } else {
        let ai = x509_cert.tbs_certificate.subject_public_key_info.algorithm;

        if ai.algorithm.0.as_bytes() != [42, 134, 72, 206, 61, 2, 1] {
            return Err(anyhow::anyhow!("Unexpected KeyAlgorithm {:?}", ai));
        }

        let ec = x509_cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key;

        for k in cert.keys() {
            match k.key().mpis() {
                PublicKey::ECDSA { q, .. } | PublicKey::ECDH { q, .. } => {
                    if ec.octet_bytes().as_ref() == q.value() {
                        return Ok(k.key().clone());
                    }
                }
                _ => {}
            }
        }
    }

    Err(anyhow::anyhow!("Didn't find matching key in Cert"))
}
