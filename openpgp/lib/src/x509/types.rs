//! Types for using X.509 certificates in an OpenPGP context.
//!
//! Inlined from `openpgp-x509-sequoia` 0.2.0 (LGPL-2.0-or-later), unchanged —
//! these types do not depend on any sequoia API, so the 1.x -> 2.x bump is a
//! no-op for them. See `crate::x509` module docs and plan §2.3.

use clap::ValueEnum;
use cookie_factory::{SerializeFn, WriteContext};
use elliptic_curve::sec1::EncodedPoint as EcPublicKey;
use p256::NistP256;
use p384::NistP384;
use p521::NistP521;
use rsa::{BigUint, PublicKeyParts, RsaPublicKey};
use x509::der::write::{der_integer, der_sequence};

/// OpenPGP key type (needed for ECC keys)
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum PgpKeyType {
    Encrypt,
    Sign,
    Auth,
}

/// Information about a public key within an X.509 certificate.
#[derive(Clone, Eq, PartialEq)]
pub enum PublicKeyInfo {
    /// RSA keys
    Rsa {
        /// RSA algorithm
        algorithm: AlgorithmId,

        /// Public key
        pubkey: RsaPublicKey,
    },

    /// EC P-256 keys
    EcP256(EcPublicKey<NistP256>),

    /// EC P-384 keys
    EcP384(EcPublicKey<NistP384>),

    /// EC P-521 keys
    EcP521(EcPublicKey<NistP521>),
}

impl PublicKeyInfo {
    pub fn algorithm(&self) -> AlgorithmId {
        match self {
            PublicKeyInfo::Rsa { algorithm, .. } => *algorithm,
            PublicKeyInfo::EcP256(_) => AlgorithmId::EccP256,
            PublicKeyInfo::EcP384(_) => AlgorithmId::EccP384,
            PublicKeyInfo::EcP521(_) => AlgorithmId::EccP521,
        }
    }
}

impl x509::SubjectPublicKeyInfo for PublicKeyInfo {
    type AlgorithmId = AlgorithmId;
    type SubjectPublicKey = Vec<u8>;

    fn algorithm_id(&self) -> AlgorithmId {
        self.algorithm()
    }

    fn public_key(&self) -> Vec<u8> {
        /// Encodes a usize as an ASN.1 integer using DER.
        fn der_integer_biguint<'a, W: std::io::Write + 'a>(
            num: &'a BigUint,
        ) -> impl SerializeFn<W> + 'a {
            move |w: WriteContext<W>| der_integer(&num.to_bytes_be())(w)
        }

        match self {
            PublicKeyInfo::Rsa { pubkey, .. } => cookie_factory::gen_simple(
                der_sequence((
                    der_integer_biguint(pubkey.n()),
                    der_integer_biguint(pubkey.e()),
                )),
                vec![],
            )
            .expect("can write to Vec"),
            PublicKeyInfo::EcP256(pubkey) => pubkey.as_bytes().to_vec(),
            PublicKeyInfo::EcP384(pubkey) => pubkey.as_bytes().to_vec(),
            PublicKeyInfo::EcP521(pubkey) => pubkey.as_bytes().to_vec(),
        }
    }
}

/// Algorithm identifiers
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AlgorithmId {
    Rsa2048,
    Rsa3072,
    Rsa4096,
    EccP256,
    EccP384,
    EccP521,
}

impl x509::AlgorithmIdentifier for AlgorithmId {
    type AlgorithmOid = &'static [u64];

    fn algorithm(&self) -> Self::AlgorithmOid {
        match self {
            // RSA encryption
            Self::Rsa2048 | Self::Rsa3072 | Self::Rsa4096 => &[1, 2, 840, 113_549, 1, 1, 1],
            // EC Public Key
            Self::EccP256 | Self::EccP384 | Self::EccP521 => &[1, 2, 840, 10045, 2, 1],
        }
    }

    fn parameters<W: std::io::Write>(
        &self,
        w: cookie_factory::WriteContext<W>,
    ) -> cookie_factory::GenResult<W> {
        use x509::der::write::der_oid;

        // From [RFC 5480](https://tools.ietf.org/html/rfc5480#section-2.1.1):
        // ```text
        // ECParameters ::= CHOICE {
        //   namedCurve         OBJECT IDENTIFIER
        //   -- implicitCurve   NULL
        //   -- specifiedCurve  SpecifiedECDomain
        // }
        // ```
        match self {
            Self::EccP256 => der_oid(&[1, 2, 840, 10045, 3, 1, 7][..])(w),
            Self::EccP384 => der_oid(&[1, 3, 132, 0, 34][..])(w),
            Self::EccP521 => der_oid(&[1, 3, 132, 0, 35][..])(w),
            _ => Ok(w),
        }
    }
}

pub(crate) enum SigId {
    Sha256WithRsaEncryption,
    Sha384WithRsaEncryption,
    Sha512WithRsaEncryption,
    EcdsaWithSha256,
    EcdsaWithSha384,
    EcdsaWithSha512,
}

impl x509::AlgorithmIdentifier for SigId {
    type AlgorithmOid = &'static [u64];

    fn algorithm(&self) -> Self::AlgorithmOid {
        match self {
            Self::Sha256WithRsaEncryption => &[1, 2, 840, 113_549, 1, 1, 11],
            Self::Sha384WithRsaEncryption => &[1, 2, 840, 113_549, 1, 1, 12],
            Self::Sha512WithRsaEncryption => &[1, 2, 840, 113_549, 1, 1, 13],
            Self::EcdsaWithSha256 => &[1, 2, 840, 10045, 4, 3, 2],
            Self::EcdsaWithSha384 => &[1, 2, 840, 10045, 4, 3, 3],
            Self::EcdsaWithSha512 => &[1, 2, 840, 10045, 4, 3, 4],
        }
    }

    fn parameters<W: std::io::Write>(
        &self,
        w: cookie_factory::WriteContext<W>,
    ) -> cookie_factory::GenResult<W> {
        // No parameters for any SignatureId
        Ok(w)
    }
}

/// Digest algorithms.
///
/// See RFC 4055 and RFC 8017.
pub(crate) enum DigestId {
    Sha256,
    Sha384,
    Sha512,
}

impl x509::AlgorithmIdentifier for DigestId {
    type AlgorithmOid = &'static [u64];

    fn algorithm(&self) -> Self::AlgorithmOid {
        match self {
            // See https://tools.ietf.org/html/rfc4055#section-2.1
            DigestId::Sha256 => &[2, 16, 840, 1, 101, 3, 4, 2, 1],
            DigestId::Sha384 => &[2, 16, 840, 1, 101, 3, 4, 2, 2],
            DigestId::Sha512 => &[2, 16, 840, 1, 101, 3, 4, 2, 3],
        }
    }

    fn parameters<W: std::io::Write>(
        &self,
        w: cookie_factory::WriteContext<W>,
    ) -> cookie_factory::GenResult<W> {
        // Parameters are an explicit NULL
        // See https://tools.ietf.org/html/rfc8017#appendix-A.2.4
        x509::der::write::der_null()(w)
    }
}
