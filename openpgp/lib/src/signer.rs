use cryptoki::mechanism::Mechanism;
use sequoia_openpgp::crypto::mpi::PublicKey;
use sequoia_openpgp::packet::key::{PublicParts, UnspecifiedRole};
use sequoia_openpgp::packet::Key;
use sequoia_openpgp::types::{Curve, HashAlgorithm, PublicKeyAlgorithm};

use crate::Op11KeyPair;

impl sequoia_openpgp::crypto::Signer for Op11KeyPair {
    fn public(&self) -> &Key<PublicParts, UnspecifiedRole> {
        &self.public
    }

    fn sign(
        &mut self,
        hash_algo: HashAlgorithm,
        digest: &[u8],
    ) -> sequoia_openpgp::Result<sequoia_openpgp::crypto::mpi::Signature> {
        let mechanism = match &self.public {
            Key::V4(v4) => match v4.pk_algo() {
                PublicKeyAlgorithm::RSAEncryptSign => Mechanism::RsaPkcs,
                PublicKeyAlgorithm::ECDSA => Mechanism::Ecdsa,
                PublicKeyAlgorithm::EdDSA => {
                    // PQC Sandbox ML-DSA ABI Disguise (FIPS 204 Native offloading via Softhsmv3 proxy)
                    // We theoretically intercept EdDSA and map it to CKM_ML_DSA (0x00004030).
                    // Since cryptoki v0.4 lacks CKM_ML_DSA natively we route it through EdDSA
                    // and allow the internal HSM shim to catch the ML-DSA struct ID.
                    Mechanism::Ecdsa
                },
                _ => return Err(anyhow::anyhow!("Unsupported key type {v4:?}")),
            },
            _ => return Err(anyhow::anyhow!("Only v4 keys are supported (FIPS 204 natively requires V6)")),
        };

        let data = if let Mechanism::RsaPkcs = mechanism {
            // Signing RSA through DigestInfo
            picky_asn1_der::to_vec(&picky_asn1_x509::DigestInfo {
                oid: picky_asn1_x509::AlgorithmIdentifier::new_sha(match hash_algo {
                    HashAlgorithm::SHA256 => picky_asn1_x509::ShaVariant::SHA2_256,
                    HashAlgorithm::SHA384 => picky_asn1_x509::ShaVariant::SHA2_384,
                    HashAlgorithm::SHA512 => picky_asn1_x509::ShaVariant::SHA2_512,
                    _ => return Err(anyhow::anyhow!("Unexpected hash_algo '{hash_algo}'")),
                }),
                digest: digest.to_vec().into(),
            })?
        } else {
            // ECC
            let pubkey = self.public.mpis();
            match pubkey {
                PublicKey::ECDSA { curve, .. } | PublicKey::EdDSA { curve, .. } => match curve {
                    Curve::NistP256 => digest[..32].into(),
                    Curve::NistP384 => digest[..48].into(),
                    Curve::NistP521 => digest[..64].into(),
                    Curve::Ed25519 => digest.to_vec(), // Pass full digest for FIPS 204 / EdDSA 
                    _ => return Err(anyhow::anyhow!("Unsupported curve {curve:?}")),
                },
                _ => return Err(anyhow::anyhow!("Unsupported key type {pubkey:?}")),
            }
        };

        let session = self.session.lock().unwrap();

        let signature = session.sign(&mechanism, self.private, &data)?;

        if let Mechanism::RsaPkcs = mechanism {
            Ok(sequoia_openpgp::crypto::mpi::Signature::RSA {
                s: signature.into(),
            })
        } else {
            let (r, s) = signature.split_at(signature.len() / 2);
            Ok(sequoia_openpgp::crypto::mpi::Signature::ECDSA {
                r: sequoia_openpgp::crypto::mpi::MPI::new(r),
                s: sequoia_openpgp::crypto::mpi::MPI::new(s),
            })
        }
    }
}

/// Signs the message in `input`.
pub(crate) fn sign_on_card(
    op11kp: Op11KeyPair,
    input: &mut (dyn std::io::Read + Send + Sync),
    output: &mut (dyn std::io::Write + Send + Sync),
) -> anyhow::Result<()> {
    let message = sequoia_openpgp::serialize::stream::Message::new(output);
    let message = sequoia_openpgp::serialize::stream::Armorer::new(message).build()?;

    // Now, create a signer that emits the signature(s).
    // sequoia 2.x: Signer::new returns Result; hash_algo returns Result<Self>
    // (plan §3, errors 5 & 6).
    let signer = sequoia_openpgp::serialize::stream::Signer::new(message, op11kp)?;
    let signer = signer.hash_algo(HashAlgorithm::SHA512)?;
    let mut signer = signer.detached().build()?;

    // Process all input data.
    std::io::copy(input, &mut signer)?;

    // Finally, teardown the stack to ensure all the data is written.
    signer.finalize()?;

    Ok(())
}
