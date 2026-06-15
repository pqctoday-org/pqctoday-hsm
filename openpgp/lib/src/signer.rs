use cryptoki::mechanism::dsa::{HedgeType, SignAdditionalContext};
use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::ObjectHandle;
use cryptoki::session::Session;
use sequoia_openpgp::crypto::mpi::{self, PublicKey};
use sequoia_openpgp::packet::key::{PublicParts, UnspecifiedRole};
use sequoia_openpgp::packet::Key;
use sequoia_openpgp::types::{Curve, HashAlgorithm, PublicKeyAlgorithm};

use crate::Op11KeyPair;

/// Sign `digest` with a pure ML-DSA private-key object via `CKM_ML_DSA`.
///
/// softhsmv3's `parseMLDSASignContext` (SoftHSM_sign.cpp) accepts the 12-byte
/// `CK_SIGN_ADDITIONAL_CONTEXT` with `HedgeType::Preferred` + empty context —
/// proven by the §5.4 smoke test (returns exactly 3309 B for ML-DSA-65). This
/// is pure mode (no prehash, no context string), matching what sequoia's
/// software backend (`mldsa65_sign`, `SigAlg::Mldsa65`, ctx=None) signs, so the
/// HSM half is byte-compatible with a software verifier.
fn ml_dsa_sign(session: &Session, handle: ObjectHandle, digest: &[u8]) -> anyhow::Result<Vec<u8>> {
    let ctx = SignAdditionalContext::new(HedgeType::Preferred, Some(&[]));
    Ok(session.sign(&Mechanism::MlDsa(ctx), handle, digest)?)
}

/// Sign `digest` with a pure Ed25519 private-key object via `CKM_EDDSA`.
///
/// Pure EdDSA mode (no context, no prehash), matching sequoia's `ed25519_sign`
/// (`SigAlg::Ed25519`) — both sign the raw OpenPGP digest directly, so the
/// component is interoperable.
fn ed25519_sign(session: &Session, handle: ObjectHandle, digest: &[u8]) -> anyhow::Result<Vec<u8>> {
    let params = EddsaParams::new(EddsaSignatureScheme::Ed25519);
    Ok(session.sign(&Mechanism::Eddsa(params), handle, digest)?)
}

impl sequoia_openpgp::crypto::Signer for Op11KeyPair {
    fn public(&self) -> &Key<PublicParts, UnspecifiedRole> {
        &self.public
    }

    /// Native PQC + classical dispatch (plan §4). The old EdDSA-disguise that
    /// mapped ML-DSA onto `Mechanism::Ecdsa` and tagged the output as an ECDSA
    /// MPI (algorithm 22) is gone — composite keys now produce real
    /// `mpi::Signature::MLDSA65_Ed25519` (algorithm 30) by performing TWO
    /// `C_Sign` calls against the two custody handles and assembling both halves.
    fn sign(
        &mut self,
        hash_algo: HashAlgorithm,
        digest: &[u8],
    ) -> sequoia_openpgp::Result<sequoia_openpgp::crypto::mpi::Signature> {
        let session = self.session.lock().unwrap();

        match self.public.pk_algo() {
            // -- RSA: sign a DER DigestInfo via CKM_RSA_PKCS --
            PublicKeyAlgorithm::RSAEncryptSign => {
                let data = picky_asn1_der::to_vec(&picky_asn1_x509::DigestInfo {
                    oid: picky_asn1_x509::AlgorithmIdentifier::new_sha(match hash_algo {
                        HashAlgorithm::SHA256 => picky_asn1_x509::ShaVariant::SHA2_256,
                        HashAlgorithm::SHA384 => picky_asn1_x509::ShaVariant::SHA2_384,
                        HashAlgorithm::SHA512 => picky_asn1_x509::ShaVariant::SHA2_512,
                        _ => return Err(anyhow::anyhow!("Unexpected hash_algo '{hash_algo}'")),
                    }),
                    digest: digest.to_vec().into(),
                })?;
                let signature = session.sign(&Mechanism::RsaPkcs, self.private, &data)?;
                Ok(mpi::Signature::RSA {
                    s: signature.into(),
                })
            }

            // -- ECDSA: truncate the digest to the field size, CKM_ECDSA --
            PublicKeyAlgorithm::ECDSA => {
                let data: Vec<u8> = match self.public.mpis() {
                    PublicKey::ECDSA { curve, .. } => match curve {
                        Curve::NistP256 => digest[..32].into(),
                        Curve::NistP384 => digest[..48].into(),
                        Curve::NistP521 => digest[..64].into(),
                        _ => return Err(anyhow::anyhow!("Unsupported ECDSA curve {curve:?}")),
                    },
                    pk => return Err(anyhow::anyhow!("ECDSA pk_algo with non-ECDSA MPI {pk:?}")),
                };
                let signature = session.sign(&Mechanism::Ecdsa, self.private, &data)?;
                let (r, s) = signature.split_at(signature.len() / 2);
                Ok(mpi::Signature::ECDSA {
                    r: mpi::MPI::new(r),
                    s: mpi::MPI::new(s),
                })
            }

            // -- Real EdDSA (Ed25519) via CKM_EDDSA — no more ML-DSA disguise --
            PublicKeyAlgorithm::EdDSA => {
                let curve = match self.public.mpis() {
                    PublicKey::EdDSA { curve, .. } => curve.clone(),
                    pk => return Err(anyhow::anyhow!("EdDSA pk_algo with non-EdDSA MPI {pk:?}")),
                };
                if curve != Curve::Ed25519 {
                    return Err(anyhow::anyhow!("Unsupported EdDSA curve {curve:?}"));
                }
                let sig = ed25519_sign(&session, self.private, digest)?;
                if sig.len() != 64 {
                    return Err(anyhow::anyhow!(
                        "CKM_EDDSA returned {} bytes, expected 64",
                        sig.len()
                    ));
                }
                // OpenPGP EdDSA MPI: r = first 32 bytes, s = last 32 bytes.
                Ok(mpi::Signature::EdDSA {
                    r: mpi::MPI::new(&sig[..32]),
                    s: mpi::MPI::new(&sig[32..]),
                })
            }

            // -- Composite MLDSA65_Ed25519 (algorithm 30): TWO C_Sign calls --
            PublicKeyAlgorithm::MLDSA65_Ed25519 => {
                let pqc = self.pqc.ok_or_else(|| {
                    anyhow::anyhow!("MLDSA65_Ed25519 keypair is missing its ML-DSA custody handle")
                })?;
                // Ed25519 half on the traditional handle, ML-DSA-65 half on the
                // PQC handle — both sign the SAME digest (matching sequoia's
                // software composite signer).
                let eddsa = ed25519_sign(&session, self.private, digest)?;
                let mldsa = ml_dsa_sign(&session, pqc, digest)?;

                let eddsa: Box<[u8; 64]> = eddsa
                    .into_boxed_slice()
                    .try_into()
                    .map_err(|v: Box<[u8]>| {
                        anyhow::anyhow!("Ed25519 half is {} bytes, expected 64", v.len())
                    })?;
                let mldsa: Box<[u8; 3309]> = mldsa
                    .into_boxed_slice()
                    .try_into()
                    .map_err(|v: Box<[u8]>| {
                        anyhow::anyhow!("ML-DSA-65 half is {} bytes, expected 3309", v.len())
                    })?;
                Ok(mpi::Signature::MLDSA65_Ed25519 { eddsa, mldsa })
            }

            // -- Composite MLDSA87_Ed448 (algorithm 31): same two-handle shape --
            PublicKeyAlgorithm::MLDSA87_Ed448 => {
                let pqc = self.pqc.ok_or_else(|| {
                    anyhow::anyhow!("MLDSA87_Ed448 keypair is missing its ML-DSA custody handle")
                })?;
                let params = EddsaParams::new(EddsaSignatureScheme::Ed448(&[]));
                let eddsa = session.sign(&Mechanism::Eddsa(params), self.private, digest)?;
                let mldsa = ml_dsa_sign(&session, pqc, digest)?;

                let eddsa: Box<[u8; 114]> = eddsa
                    .into_boxed_slice()
                    .try_into()
                    .map_err(|v: Box<[u8]>| {
                        anyhow::anyhow!("Ed448 half is {} bytes, expected 114", v.len())
                    })?;
                let mldsa: Box<[u8; 4627]> = mldsa
                    .into_boxed_slice()
                    .try_into()
                    .map_err(|v: Box<[u8]>| {
                        anyhow::anyhow!("ML-DSA-87 half is {} bytes, expected 4627", v.len())
                    })?;
                Ok(mpi::Signature::MLDSA87_Ed448 { eddsa, mldsa })
            }

            other => Err(anyhow::anyhow!("Unsupported signing algorithm {other:?}")),
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
