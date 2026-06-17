use std::time::SystemTime;

use anyhow::Result;
use cryptoki::object::{Attribute, AttributeType, ObjectClass};
use cryptoki::session::Session;
use crate::x509::types::PgpKeyType;
use sequoia_openpgp::crypto::mpi;
use sequoia_openpgp::packet::key::{Key4, PublicParts, UnspecifiedRole};
use sequoia_openpgp::types::{HashAlgorithm, PublicKeyAlgorithm, SymmetricAlgorithm};
use sequoia_openpgp::Fingerprint;
use x509_certificate::rfc5280::SubjectPublicKeyInfo;

/// Get X509 Certificate for a (session, id).
pub(crate) fn x509_cert(session: &Session, id: &[u8]) -> Result<x509_certificate::X509Certificate> {
    // Find certificate for 'id'
    let objs = session.find_objects(&[
        Attribute::Class(ObjectClass::CERTIFICATE),
        Attribute::Id(id.to_vec()),
    ])?;

    if objs.len() != 1 {
        return Err(anyhow::anyhow!(
            "Didn't find exactly one ObjectClass::CERTIFICATE for {id:?}"
        ));
    }

    let attrs = session.get_attributes(objs[0], &[AttributeType::Value])?;
    if attrs.len() != 1 {
        return Err(anyhow::anyhow!(
            "Didn't find exactly one AttributeType::Value for Object {id:?}"
        ));
    }

    if let Attribute::Value(bytes) = &attrs[0] {
        x509_certificate::X509Certificate::from_der(bytes)
            .map_err(|_| anyhow::anyhow!("Unexpected value found"))
    } else {
        Err(anyhow::anyhow!("Got unexpected Attribute {:?}", attrs[0]))
    }
}

// Generate a Key from RSA input data.
pub(crate) fn get_rsa_as_pgp(
    rsa_pub: x509_certificate::rfc8017::RsaPublicKey,
    time: SystemTime,
) -> Result<Key4<PublicParts, UnspecifiedRole>> {
    let k4 = Key4::import_public_rsa(
        rsa_pub.public_exponent.as_slice(),
        rsa_pub.modulus.as_slice(),
        Some(time),
    )
    .map_err(|e| anyhow::anyhow!("sequoia Key4::import_public_rsa failed: {:?}", e))?;

    Ok(k4)
}

// Best-effort attempt to generate a Key while using extension_kdf_kek or
// extension_sfp, if available.
//
// If extension_sfp is set, but no fitting parameters can be found, an
// error is returned.
pub(crate) fn get_ecc_as_pgp(
    pkt: PgpKeyType,
    pki: SubjectPublicKeyInfo,
    time: SystemTime,
    subkey_fp: &Fingerprint,
    extension_kdf_kek: Option<[u8; 4]>,
) -> Result<Key4<PublicParts, UnspecifiedRole>> {
    if let Some(algoparam) = &pki.algorithm.parameters {
        let curve = match algoparam.decode_oid()?.as_ref() {
            [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07] => {
                sequoia_openpgp::types::Curve::NistP256
            }

            [0x2B, 0x81, 0x04, 0x00, 0x22] => sequoia_openpgp::types::Curve::NistP384,

            [0x2B, 0x81, 0x04, 0x00, 0x23] => sequoia_openpgp::types::Curve::NistP521,

            _ => return Err(anyhow::anyhow!("FIXME: unhandled ECC key type")),
        };

        let pub_data = pki.subject_public_key;

        println!("pkt: {pkt:?}");

        use asn1_rs::nom::AsBytes;
        let k4: Key4<PublicParts, UnspecifiedRole> = match pkt {
            PgpKeyType::Sign | PgpKeyType::Auth => Key4::new(
                time,
                PublicKeyAlgorithm::ECDSA,
                mpi::PublicKey::ECDSA {
                    curve,
                    q: mpi::MPI::new(pub_data.octet_bytes().as_bytes()),
                },
            )
            .map_err(|e| anyhow::anyhow!("sequoia Key4::new failed: {:?}", e))?,

            PgpKeyType::Encrypt => {
                let make_key = |hash, sym| {
                    Key4::new(
                        time,
                        PublicKeyAlgorithm::ECDH,
                        mpi::PublicKey::ECDH {
                            curve: curve.clone(),
                            q: mpi::MPI::new(pub_data.octet_bytes().as_bytes()),
                            hash,
                            sym,
                        },
                    )
                    .map_err(|e| anyhow::anyhow!("sequoia Key4::new failed: {:?}", e))
                };

                // Use different approach to KDF/KEK parameters, depending on which metadata we have
                match (extension_kdf_kek, subkey_fp) {
                    (Some([3, 1, hash, sym]), _) => {
                        // Use KDF/KEK params from extension, if available
                        // (and if the two first fields "kdf_len" and
                        // "version" contain the expected values).

                        log::debug!("Converting with KDF/KEK params {hash}/{sym}");

                        make_key(hash.into(), sym.into())?
                    }

                    (None, sfp) => {
                        // Try all common kdf/kek params if we have a target FP,
                        // and use the parameters that yield the expected fingerprint.

                        log::debug!("Converting with FP {:?}", sfp);

                        for (hash, sym) in common_kdf_kek() {
                            let key = make_key(*hash, *sym)?;
                            if &key.fingerprint() == sfp {
                                return Ok(key);
                            }
                        }
                        return Err(anyhow::anyhow!(
                            "Couldn't find matching parameters for fingerprint {}",
                            sfp
                        ));
                    }

                    _ => {
                        // Use default kdf/kek if we have no hints
                        log::debug!(
                            "Converting with curve-specific default-parameters for KDF/KEK."
                        );

                        let (hash, sym) = default_kdf_kek(&curve)?;
                        make_key(hash, sym)?
                    }
                }
            }
        };

        Ok(k4)
    } else {
        Err(anyhow::anyhow!("Couldn't get algorithm.parameters"))
    }
}

// Common hash/sym parameters based on statistics from 2019-12 SKS dump
// in descending order of occurrence.
//
// See https://gitlab.com/sequoia-pgp/sequoia/-/issues/838#note_909813463
fn common_kdf_kek() -> &'static [(HashAlgorithm, SymmetricAlgorithm)] {
    &[
        (HashAlgorithm::SHA256, SymmetricAlgorithm::AES128),
        (HashAlgorithm::SHA512, SymmetricAlgorithm::AES256),
        (HashAlgorithm::SHA384, SymmetricAlgorithm::AES256),
        (HashAlgorithm::SHA384, SymmetricAlgorithm::AES192),
        (HashAlgorithm::SHA256, SymmetricAlgorithm::AES256),
    ]
}

fn default_kdf_kek(
    curve: &sequoia_openpgp::types::Curve,
) -> Result<(HashAlgorithm, SymmetricAlgorithm)> {
    // FIXME: don't just rely on hardcoded parameters?
    // Options:
    // - use "1.3.6.1.4.1.11591.2.2.10 - OpenPGP KDF/KEK parameter"
    // - use fingerprint hints and check against those (serial + extension)

    // FIXME: if we don't have hints, we could ask an external
    // cert store for help.
    // however, unclear if that's worth the trouble?!
    let (hash, sym) = match curve {
        sequoia_openpgp::types::Curve::NistP256 => {
            (HashAlgorithm::SHA256, SymmetricAlgorithm::AES128)
        }
        sequoia_openpgp::types::Curve::NistP384 => {
            (HashAlgorithm::SHA384, SymmetricAlgorithm::AES192)
        }
        sequoia_openpgp::types::Curve::NistP521 => {
            (HashAlgorithm::SHA512, SymmetricAlgorithm::AES256)
        }
        _ => return Err(anyhow::anyhow!("Unsupported curve {curve:?}")),
    };

    Ok((hash, sym))
}
