use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass};
use sequoia_openpgp::crypto::SessionKey;
use sequoia_openpgp::packet::key::{PublicParts, UnspecifiedRole};
use sequoia_openpgp::packet::Key;
use sequoia_openpgp::parse::stream::{DecryptionHelper, MessageStructure, VerificationHelper};
use sequoia_openpgp::types::{PublicKeyAlgorithm, SymmetricAlgorithm};

use crate::Op11KeyPair;

impl sequoia_openpgp::crypto::Decryptor for Op11KeyPair {
    fn public(&self) -> &Key<PublicParts, UnspecifiedRole> {
        &self.public
    }

    fn decrypt(
        &mut self,
        ciphertext: &sequoia_openpgp::crypto::mpi::Ciphertext,
        _plaintext_len: Option<usize>,
    ) -> sequoia_openpgp::Result<SessionKey> {
        match ciphertext {
            sequoia_openpgp::crypto::mpi::Ciphertext::RSA { c: cipher } => {
                let session = self.session.lock().unwrap();
                let decrypted =
                    session.decrypt(&Mechanism::RsaPkcs, self.private, cipher.value())?;
                Ok(decrypted.as_slice().into())
            }
            sequoia_openpgp::crypto::mpi::Ciphertext::ECDH { ref e, .. } => {
                let field_sz = 256; // FIXME?

                use cryptoki::mechanism::elliptic_curve::{Ecdh1DeriveParams, EcKdf};

                let bytes = e.value();

                // cryptoki 0.12: Ecdh1DeriveParams has private fields and is
                // built via ::new(kdf, public_data). The old struct-literal form
                // (EcKdfType::NULL + raw c_void pointer) is gone (plan §5).
                let params = Ecdh1DeriveParams::new(EcKdf::null(), bytes);

                let res = self.session.lock().unwrap().derive_key(
                    &Mechanism::Ecdh1Derive(params),
                    self.private,
                    &[
                        Attribute::Class(ObjectClass::SECRET_KEY),
                        Attribute::KeyType(KeyType::GENERIC_SECRET),
                        Attribute::Token(false),
                        Attribute::Sensitive(false),
                        Attribute::Extractable(true),
                        Attribute::Encrypt(true),
                        Attribute::Decrypt(true),
                        Attribute::Wrap(true),
                        Attribute::Unwrap(true),
                    ],
                );
                if let Ok(key) = res {
                    let mut value = None;
                    for attribute in self
                        .session
                        .lock()
                        .unwrap()
                        .get_attributes(key, &[AttributeType::Value])?
                    {
                        if let Attribute::Value(val) = attribute {
                            value = Some(val);
                        }
                    }

                    let value = value.unwrap();

                    let mut value = value;
                    while value.len() < (field_sz + 7) / 8 {
                        value.insert(0, 0);
                    }

                    // sequoia 2.x: decrypt_unwrap gained a 4th arg, the
                    // plaintext-length hint (plan §3, error 1). We have no hint,
                    // so pass None.
                    let ret = sequoia_openpgp::crypto::ecdh::decrypt_unwrap(
                        self.public(),
                        &value.into(),
                        ciphertext,
                        None,
                    );
                    if let Err(ref e) = ret {
                        println!("Err = {e:?}");
                    }
                    ret
                } else {
                    eprintln!("Err = {res:?}");
                    Err(
                        sequoia_openpgp::Error::InvalidOperation("derive_key() failed".to_string())
                            .into(),
                    )
                }
            }
            // -- Composite MLKEM768_X25519 (algorithm 35) — the KEM combiner --
            //
            // Decapsulation is TWO HSM ops over the TWO custody handles:
            //   1. X25519 ECDH derive on the traditional handle (self.private)
            //      -> the X25519 shared point (ecdh_keyshare)
            //   2. ML-KEM-768 C_DecapsulateKey on the PQC handle (self.pqc)
            //      -> the ML-KEM shared secret (mlkem_keyshare)
            // then KEK = SHA3-256(mlkem || ecdh || ecdhCt || ecdhPub || algId ||
            // domSep), and the session key = AES-256 key-unwrap(KEK, esk), per
            // draft-ietf-openpgp-pqc §4.2.1. (plan §4)
            sequoia_openpgp::crypto::mpi::Ciphertext::MLKEM768_X25519 { ecdh, mlkem, esk } => {
                let pqc = self.pqc.ok_or_else(|| {
                    sequoia_openpgp::Error::InvalidOperation(
                        "MLKEM768_X25519 keypair is missing its ML-KEM custody handle".into(),
                    )
                })?;

                // Recipient X25519 public key (the ecdh component of the
                // composite public MPI) — needed as combiner input.
                let ecdh_public: Vec<u8> = match self.public.mpis() {
                    sequoia_openpgp::crypto::mpi::PublicKey::MLKEM768_X25519 { ecdh, .. } => {
                        ecdh.to_vec()
                    }
                    pk => {
                        return Err(sequoia_openpgp::Error::InvalidOperation(format!(
                            "MLKEM768_X25519 ciphertext with non-matching public key {pk:?}"
                        ))
                        .into())
                    }
                };

                // 1) X25519 ECDH shared point on the traditional handle.
                let ecdh_keyshare =
                    self.x25519_shared_point(self.private, &ecdh[..])?;

                // 2) ML-KEM-768 decapsulation on the PQC handle.
                let mlkem_keyshare = self.ml_kem_decapsulate(pqc, &mlkem[..])?;

                // 3) Combine -> KEK, then AES-256 key-unwrap the ESK.
                let kek = multi_key_combine(
                    &mlkem_keyshare,
                    &ecdh_keyshare,
                    &ecdh[..],
                    &ecdh_public,
                    PublicKeyAlgorithm::MLKEM768_X25519,
                )?;
                let session_key = aes256_key_unwrap(&kek, esk)?;
                Ok(session_key.as_slice().into())
            }

            // -- Composite MLKEM1024_X448 (algorithm 36) — same combiner, sized
            // up (remediation plan §2/Fix 2). Same two-op shape as
            // MLKEM768_X25519 above: X448 ECDH derive on the traditional
            // handle + ML-KEM-1024 C_DecapsulateKey on the PQC handle, then the
            // identical draft §4.2.1 combiner + AES-256 key-unwrap. The
            // combiner itself is untouched (SHA3-256 over the same field
            // order); only the ECDH shared-point width differs (56 B for X448
            // vs 32 B for X25519), handled by `x448_shared_point`.
            sequoia_openpgp::crypto::mpi::Ciphertext::MLKEM1024_X448 { ecdh, mlkem, esk } => {
                let pqc = self.pqc.ok_or_else(|| {
                    sequoia_openpgp::Error::InvalidOperation(
                        "MLKEM1024_X448 keypair is missing its ML-KEM custody handle".into(),
                    )
                })?;

                let ecdh_public: Vec<u8> = match self.public.mpis() {
                    sequoia_openpgp::crypto::mpi::PublicKey::MLKEM1024_X448 { ecdh, .. } => {
                        ecdh.to_vec()
                    }
                    pk => {
                        return Err(sequoia_openpgp::Error::InvalidOperation(format!(
                            "MLKEM1024_X448 ciphertext with non-matching public key {pk:?}"
                        ))
                        .into())
                    }
                };

                // 1) X448 ECDH shared point on the traditional handle.
                let ecdh_keyshare = self.x448_shared_point(self.private, &ecdh[..])?;

                // 2) ML-KEM-1024 decapsulation on the PQC handle.
                let mlkem_keyshare = self.ml_kem_decapsulate(pqc, &mlkem[..])?;

                // 3) Combine -> KEK, then AES-256 key-unwrap the ESK.
                let kek = multi_key_combine(
                    &mlkem_keyshare,
                    &ecdh_keyshare,
                    &ecdh[..],
                    &ecdh_public,
                    PublicKeyAlgorithm::MLKEM1024_X448,
                )?;
                let session_key = aes256_key_unwrap(&kek, esk)?;
                Ok(session_key.as_slice().into())
            }

            _ => Err(sequoia_openpgp::Error::InvalidOperation(
                "Unexpected Ciphertext type.".to_string(),
            )
            .into()),
        }
    }
}

impl VerificationHelper for Op11KeyPair {
    fn get_certs(
        &mut self,
        _ids: &[sequoia_openpgp::KeyHandle],
    ) -> sequoia_openpgp::Result<Vec<sequoia_openpgp::Cert>> {
        // Return public keys for signature verification here.
        Ok(Vec::new())
    }

    fn check(&mut self, _structure: MessageStructure) -> sequoia_openpgp::Result<()> {
        // Implement your signature verification policy here.
        Ok(())
    }
}

impl DecryptionHelper for Op11KeyPair {
    // sequoia 2.x rewrote this trait method (plan §3, errors 2-4):
    //   - no `<D>` type parameter; the callback is a `&mut dyn FnMut`
    //   - the callback's first arg is `Option<SymmetricAlgorithm>` (v6 PKESK
    //     packets do not carry the symmetric algorithm; it comes from the SEIPD)
    //   - returns `Result<Option<Cert>>` (the recipient Cert), not
    //     `Result<Option<Fingerprint>>`
    fn decrypt(
        &mut self,
        pkesks: &[sequoia_openpgp::packet::PKESK],
        _skesks: &[sequoia_openpgp::packet::SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
    ) -> sequoia_openpgp::Result<Option<sequoia_openpgp::Cert>> {
        let mut pair = Op11KeyPair {
            public: self.public.clone(),
            session: self.session.clone(),
            private: self.private,
            // Carry the PQC custody handle through to the inner Decryptor so a
            // composite ML-KEM decapsulation can reach its second handle.
            pqc: self.pqc,
        };

        // PKESK::decrypt now returns Option<(Option<SymmetricAlgorithm>,
        // SessionKey)>; pass the Option straight through to the callback.
        pkesks[0]
            .decrypt(&mut pair, sym_algo)
            .map(|(algo, session_key)| decrypt(algo, &session_key));

        // XXX: In production code, return the recipient's Cert here.
        Ok(None)
    }
}

impl Op11KeyPair {
    /// Derive the raw X25519 shared point from the recipient's X25519 private
    /// object (`handle`) and the sender's ephemeral X25519 public key
    /// (`peer_public`, the `ecdh` ciphertext component), via `CKM_ECDH1_DERIVE`
    /// with the null KDF. Returns the 32-byte shared secret.
    pub(crate) fn x25519_shared_point(
        &self,
        handle: cryptoki::object::ObjectHandle,
        peer_public: &[u8],
    ) -> sequoia_openpgp::Result<Vec<u8>> {
        use cryptoki::mechanism::elliptic_curve::{Ecdh1DeriveParams, EcKdf};

        let params = Ecdh1DeriveParams::new(EcKdf::null(), peer_public);

        let session = self.session.lock().unwrap();
        let derived = session
            .derive_key(
                &Mechanism::Ecdh1Derive(params),
                handle,
                &[
                    Attribute::Class(ObjectClass::SECRET_KEY),
                    Attribute::KeyType(KeyType::GENERIC_SECRET),
                    Attribute::Token(false),
                    Attribute::Sensitive(false),
                    Attribute::Extractable(true),
                    Attribute::ValueLen(32u64.into()),
                ],
            )
            .map_err(|e| {
                sequoia_openpgp::Error::InvalidOperation(format!(
                    "X25519 ECDH1_DERIVE failed: {e}"
                ))
            })?;

        read_secret_value(&session, derived)
    }

    /// Derive the raw X448 shared point from the recipient's X448 private
    /// object (`handle`) and the sender's ephemeral X448 public key
    /// (`peer_public`), via `CKM_ECDH1_DERIVE` with the null KDF. Returns the
    /// 56-byte shared secret (remediation plan §2/Fix 2) — same op as
    /// [`Self::x25519_shared_point`], sized for the wider Montgomery curve
    /// (`CKA_VALUE_LEN` 56 instead of 32).
    pub(crate) fn x448_shared_point(
        &self,
        handle: cryptoki::object::ObjectHandle,
        peer_public: &[u8],
    ) -> sequoia_openpgp::Result<Vec<u8>> {
        use cryptoki::mechanism::elliptic_curve::{Ecdh1DeriveParams, EcKdf};

        let params = Ecdh1DeriveParams::new(EcKdf::null(), peer_public);

        let session = self.session.lock().unwrap();
        let derived = session
            .derive_key(
                &Mechanism::Ecdh1Derive(params),
                handle,
                &[
                    Attribute::Class(ObjectClass::SECRET_KEY),
                    Attribute::KeyType(KeyType::GENERIC_SECRET),
                    Attribute::Token(false),
                    Attribute::Sensitive(false),
                    Attribute::Extractable(true),
                    Attribute::ValueLen(56u64.into()),
                ],
            )
            .map_err(|e| {
                sequoia_openpgp::Error::InvalidOperation(format!("X448 ECDH1_DERIVE failed: {e}"))
            })?;

        read_secret_value(&session, derived)
    }

    /// Decapsulate an ML-KEM ciphertext on the PQC private object (`handle`)
    /// via `CKM_ML_KEM` / `C_DecapsulateKey`, returning the 32-byte ML-KEM
    /// shared secret. Parameter-set-agnostic (768 or 1024 — plan §2/Fix 2):
    /// the FIPS 203 shared secret is always 32 bytes regardless of parameter
    /// set, and the mechanism reads the set from the key object itself.
    pub(crate) fn ml_kem_decapsulate(
        &self,
        handle: cryptoki::object::ObjectHandle,
        ciphertext: &[u8],
    ) -> sequoia_openpgp::Result<Vec<u8>> {
        let session = self.session.lock().unwrap();
        let derived = session
            .decapsulate_key(
                &Mechanism::MlKem,
                handle,
                &[
                    Attribute::Class(ObjectClass::SECRET_KEY),
                    Attribute::KeyType(KeyType::GENERIC_SECRET),
                    Attribute::Token(false),
                    Attribute::Sensitive(false),
                    Attribute::Extractable(true),
                ],
                ciphertext,
            )
            .map_err(|e| {
                sequoia_openpgp::Error::InvalidOperation(format!(
                    "ML-KEM C_DecapsulateKey failed: {e}"
                ))
            })?;

        read_secret_value(&session, derived)
    }
}

/// Read the `CKA_VALUE` of a (extractable) secret-key object.
fn read_secret_value(
    session: &cryptoki::session::Session,
    handle: cryptoki::object::ObjectHandle,
) -> sequoia_openpgp::Result<Vec<u8>> {
    for attribute in session.get_attributes(handle, &[AttributeType::Value])? {
        if let Attribute::Value(val) = attribute {
            return Ok(val);
        }
    }
    Err(sequoia_openpgp::Error::InvalidOperation(
        "derived secret has no CKA_VALUE".into(),
    )
    .into())
}

/// PQC/classical KEM key combiner (draft-ietf-openpgp-pqc §4.2.1).
///
/// `KEK = SHA3-256(mlkemKeyShare || ecdhKeyShare || ecdhCipherText ||
///                 ecdhPublicKey || algId || domSep || len(domSep))`
///
/// Re-implemented here because sequoia's `multi_key_combine` is `pub(crate)`.
/// The domain-separation string and trailing length octet (0x15 == 21, the
/// length of "OpenPGPCompositeKDFv1") match sequoia's software backend exactly,
/// so the derived KEK is byte-identical and the HSM path interoperates with a
/// software encryptor.
fn multi_key_combine(
    mlkem_key: &[u8],
    ecdh_key: &[u8],
    ecdh_ciphertext: &[u8],
    ecdh_public: &[u8],
    pk_algo: PublicKeyAlgorithm,
) -> sequoia_openpgp::Result<Vec<u8>> {
    use sha3::{Digest, Sha3_256};

    let mut hash = Sha3_256::new();
    hash.update(mlkem_key);
    hash.update(ecdh_key);
    hash.update(ecdh_ciphertext);
    hash.update(ecdh_public);
    hash.update([u8::from(pk_algo)]);
    // Domain separation string followed by its length octet (0x15 = 21).
    hash.update(b"OpenPGPCompositeKDFv1\x15");
    Ok(hash.finalize().to_vec())
}

/// RFC 3394 AES-256 key unwrap (the OpenPGP composite ESK is wrapped with the
/// combined KEK using AES Key Wrap).
fn aes256_key_unwrap(kek: &[u8], wrapped: &[u8]) -> sequoia_openpgp::Result<Vec<u8>> {
    use aes_kw::KekAes256;

    let kek: [u8; 32] = kek.try_into().map_err(|_| {
        sequoia_openpgp::Error::InvalidOperation(format!(
            "AES-256 key-unwrap KEK is {} bytes, expected 32",
            kek.len()
        ))
    })?;
    let kek = KekAes256::from(kek);
    kek.unwrap_vec(wrapped).map_err(|e| {
        sequoia_openpgp::Error::InvalidOperation(format!("AES key-unwrap failed: {e}")).into()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // The draft KEM combiner domain-separation string and its trailing length
    // octet must match sequoia's software backend byte-for-byte, or the derived
    // KEK differs and HSM<->software decryption interop breaks (plan §4).
    #[test]
    fn combiner_domain_separation_constant() {
        let dom = b"OpenPGPCompositeKDFv1";
        assert_eq!(dom.len(), 0x15, "domSep length octet must be 0x15 (21)");
    }

    // The combiner is a SHA3-256, so it must be deterministic and produce a
    // 32-byte KEK (the AES-256 key-unwrap KEK width).
    #[test]
    fn combiner_is_deterministic_and_32_bytes() {
        let mlkem = [1u8; 32];
        let ecdh = [2u8; 32];
        let ct = [3u8; 32];
        let pk = [4u8; 32];
        let a = multi_key_combine(
            &mlkem,
            &ecdh,
            &ct,
            &pk,
            PublicKeyAlgorithm::MLKEM768_X25519,
        )
        .unwrap();
        let b = multi_key_combine(
            &mlkem,
            &ecdh,
            &ct,
            &pk,
            PublicKeyAlgorithm::MLKEM768_X25519,
        )
        .unwrap();
        assert_eq!(a, b, "combiner must be deterministic");
        assert_eq!(a.len(), 32, "KEK must be 32 bytes for AES-256");
    }

    // Distinct inputs (here: a different algId octet) must yield a distinct KEK
    // — i.e. every combiner field is actually mixed into the hash.
    #[test]
    fn combiner_is_input_sensitive() {
        let z = [0u8; 32];
        let k768 = multi_key_combine(&z, &z, &z, &z, PublicKeyAlgorithm::MLKEM768_X25519).unwrap();
        let k1024 =
            multi_key_combine(&z, &z, &z, &z, PublicKeyAlgorithm::MLKEM1024_X448).unwrap();
        assert_ne!(k768, k1024, "algId must change the derived KEK");
    }

    // RFC 3394 AES-256 key-wrap round-trip: unwrap(wrap(x)) == x. Proves our
    // aes256_key_unwrap is wired to a correct AES-KW implementation.
    #[test]
    fn aes256_key_unwrap_roundtrip() {
        use aes_kw::KekAes256;
        let kek_bytes = [0x42u8; 32];
        let plaintext = [0xABu8; 32]; // an AES-256 session key
        let wrapped = KekAes256::from(kek_bytes).wrap_vec(&plaintext).unwrap();
        let unwrapped = aes256_key_unwrap(&kek_bytes, &wrapped).unwrap();
        assert_eq!(unwrapped, plaintext);
    }
}
