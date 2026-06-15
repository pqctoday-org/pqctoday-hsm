//! Experimental features
//!
//! Inlined from `openpgp-x509-sequoia` 0.2.0 (LGPL-2.0-or-later). The sequoia
//! symbols used here (`Fingerprint`, `Key`, `crypto::mpi::PublicKey::ECDH`) are
//! stable across the 1.x -> 2.x bump, so the bodies are unchanged. See
//! `crate::x509` module docs and plan §2.3.

use asn1_rs::OctetString;
use sequoia_openpgp::crypto::mpi;
use sequoia_openpgp::packet::key::{SecretParts, UnspecifiedRole};
use sequoia_openpgp::packet::Key;
use zeroize::Zeroizing;

use crate::x509::types::PublicKeyInfo;

// OIDs, used for experimental/testing purposes only!
//
// From GnuPG `doc/DETAILS`

// 1.3.6.1.4.1.11591.2.2.10      OpenPGP KDF/KEK parameter
//
// (ber encoded, should contain 4 bytes of "TAG_OCTET_STRING")
//
//     0x03: Number of bytes
//     0x01: Version for this parameter format
//     KEK digest algorithm
//         -> https://www.rfc-editor.org/rfc/rfc4880#section-9.4
//     KEK cipher algorithm
//         -> https://www.rfc-editor.org/rfc/rfc4880#section-9.2
//
//   if (nbits <= 256)
//     return (const unsigned char*)"\x03\x01\x08\x07";
//   else if (nbits <= 384)
//     return (const unsigned char*)"\x03\x01\x09\x09";
//   else
//     return (const unsigned char*)"\x03\x01\x0a\x09";
//   }
pub const OPENPGP_KDF_KEK_PARAMETER_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 11591, 2, 2, 10];

// 1.3.6.1.4.1.11591.2.4.1.2     gpgSubFingerprint attribute [for LDAP]
pub const GPG_SUBFINGERPRINT_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 11591, 2, 4, 1, 2];

#[allow(dead_code)]
pub fn generate_x509_with_extensions(
    subject_pki: &PublicKeyInfo,
    key: &Key<SecretParts, UnspecifiedRole>,
    common_name: &str,
) -> Zeroizing<Vec<u8>> {
    let mut extensions: Vec<x509::Extension<&[u64]>> = vec![];

    // FIXME: extension value syntax should be "A list of hex encoded fingerprints of the subkeys."
    // FIXME: this OID is intended for LDAP, use a different one?
    let fingerprint = key.fingerprint().to_hex();
    let sfp = x509::Extension::regular(GPG_SUBFINGERPRINT_OID, fingerprint.as_bytes());

    extensions.push(sfp);

    // For ECC decryption keys, add "KDF_KEK_PARAMETER" extension
    let kek_val: Vec<u8>;
    let kek_val_oct: OctetString;
    if let mpi::PublicKey::ECDH { hash, sym, .. } = key.parts_as_public().mpis() {
        // Digest algorithm (https://www.rfc-editor.org/rfc/rfc4880#section-9.4)
        let digest: u8 = (*hash).into();

        // Cipher algorithm (https://www.rfc-editor.org/rfc/rfc4880#section-9.2)
        let cipher: u8 = (*sym).into();

        // [len, version, digest algo, cipher algo]
        kek_val = vec![0x03, 0x01, digest, cipher];

        kek_val_oct = asn1_rs::OctetString::new(&kek_val);
        let kek_kdf = x509::Extension::regular(OPENPGP_KDF_KEK_PARAMETER_OID, kek_val_oct.as_ref());

        extensions.push(kek_kdf);
    }

    crate::x509::generate_x509(subject_pki, key, common_name, &extensions[..])
}

/// Get subkey fingerprint from x509 cert extension, if set
pub fn extension_fingerprint(
    x509_cert: &x509_certificate::rfc5280::Certificate,
) -> anyhow::Result<Option<sequoia_openpgp::Fingerprint>> {
    let oid = asn1_rs::Oid::from(GPG_SUBFINGERPRINT_OID).unwrap();
    let oid = oid.as_bytes();

    for ex in x509_cert.iter_extensions() {
        if ex.id.as_ref() == oid {
            let fp = sequoia_openpgp::Fingerprint::from_hex(&String::from_utf8_lossy(
                ex.value.as_slice().unwrap(),
            ))?;
            return Ok(Some(fp));
        }
    }

    Ok(None)
}

/// Get kdf_kek params from x509 cert extension, if set
pub fn extension_kdf_kek(
    x509_cert: &x509_certificate::rfc5280::Certificate,
) -> anyhow::Result<Option<[u8; 4]>> {
    let oid = asn1_rs::Oid::from(OPENPGP_KDF_KEK_PARAMETER_OID).unwrap();
    let oid = oid.as_bytes();

    for ex in x509_cert.iter_extensions() {
        if ex.id.as_ref() == oid {
            let kdf_kek = ex.value.as_slice().unwrap();
            if kdf_kek.len() != 4 {
                return Err(anyhow::anyhow!(
                    "Unexpected data format in OPENPGP_KDF_KEK_PARAMETER_OID"
                ));
            }

            return Ok(Some(kdf_kek.try_into().unwrap()));
        }
    }

    Ok(None)
}
