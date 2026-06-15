use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass};
use sequoia_openpgp::crypto::SessionKey;
use sequoia_openpgp::packet::key::{PublicParts, UnspecifiedRole};
use sequoia_openpgp::packet::Key;
use sequoia_openpgp::parse::stream::{DecryptionHelper, MessageStructure, VerificationHelper};
use sequoia_openpgp::types::SymmetricAlgorithm;

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
