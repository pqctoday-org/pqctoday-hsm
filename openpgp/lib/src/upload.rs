use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, CertificateType, ObjectClass, ObjectHandle};
use crate::x509::types::{AlgorithmId, PublicKeyInfo};
use p256::elliptic_curve::zeroize::Zeroizing;
use sequoia_openpgp::crypto::mpi;
use sequoia_openpgp::packet::key::{SecretKeyMaterial, SecretParts, UnspecifiedRole};
use sequoia_openpgp::packet::Key;
use sequoia_openpgp::types::Curve;

use crate::Op11Session;

impl Op11Session {
    pub(crate) fn upload_private(
        &self,
        id: &[u8],
        key: &Key<SecretParts, UnspecifiedRole>,
    ) -> anyhow::Result<ObjectHandle> {
        // --- Process private key cryptographic material ---
        let unenc = if let SecretKeyMaterial::Unencrypted(ref u) = key.secret() {
            u
        } else {
            return Err(anyhow::anyhow!("Can't get private key material"));
        };

        let secret_key_material = unenc.map(|mpis| mpis.clone());

        let priv_key = match (secret_key_material, key.parts_as_public().mpis()) {
            (mpi::SecretKeyMaterial::RSA { d, p, q, .. }, mpi::PublicKey::RSA { e, n }) => {
                {
                    fn mpi_to_biguint(mpi: &mpi::MPI) -> rsa::BigUint {
                        slice_to_biguint(mpi.value())
                    }

                    fn slice_to_biguint(bytes: &[u8]) -> rsa::BigUint {
                        rsa::BigUint::from_bytes_be(bytes)
                    }

                    let key = rsa::RsaPrivateKey::from_components(
                        mpi_to_biguint(n),
                        mpi_to_biguint(e),
                        slice_to_biguint(d.value()),
                        vec![slice_to_biguint(p.value()), slice_to_biguint(q.value())],
                    )?;

                    let pq = key.qinv().unwrap().to_biguint().unwrap().to_bytes_be();

                    let dp1 = key.dp().unwrap().to_bytes_be();

                    let dq1 = key.dq().unwrap().to_bytes_be();

                    let template = vec![
                        Attribute::Class(ObjectClass::PRIVATE_KEY),
                        Attribute::Id(id.to_vec()),
                        Attribute::KeyType(cryptoki::object::KeyType::RSA),
                        Attribute::Modulus(n.value().to_vec()), // softhsm requires Modulus
                        Attribute::PrivateExponent(d.value().to_vec()), /* softhsm requires PrivateExponent */
                        // Public exponent value of a key
                        Attribute::PublicExponent(e.value().to_vec()),
                        // The prime `p` of an RSA private key
                        Attribute::Prime1(p.value().to_vec()),
                        // The prime `q` of an RSA private key
                        Attribute::Prime2(q.value().to_vec()),
                        // The private exponent `dmp1` of an RSA private key
                        Attribute::Exponent1(dp1),
                        // The private exponent `dmq1` of an RSA private key
                        Attribute::Exponent2(dq1),
                        // The CRT coefficient `iqmp` of an RSA private key
                        Attribute::Coefficient(pq),
                        //
                        // /// Determines if a key is extractable and can be wrapped
                        // Extractable(bool),

                        // Sensitive(bool),

                        // Attribute::Private(true),
                        // Attribute::Verify(true),
                        // SignRecover(bool),

                        // https://docs.yubico.com/software/yubihsm-2/component-reference/hsm2-ref-pkcs11.html#capabilities-and-domains
                        Attribute::Sign(true), // FIXME: set depending on key type
                        // Attribute::Encrypt(bool),
                        Attribute::Decrypt(true), // FIXME: set depending on key type
                        // AlwaysAuthenticate
                        // Touch / YubicoPinPolicy
                        Attribute::Token(true),
                    ];

                    self.session.create_object(&template)?
                }
            }
            (mpi::SecretKeyMaterial::ECDSA { scalar }, mpi::PublicKey::ECDSA { curve, .. })
            | (mpi::SecretKeyMaterial::ECDH { scalar }, mpi::PublicKey::ECDH { curve, .. }) => {
                let oid = curve.oid();

                let mut ec_param: Vec<u8> = vec![0x6]; // 0x06: OID
                ec_param.push(oid.len() as u8); // len of OID
                ec_param.append(&mut oid.to_vec()); // OID

                let scalar = match curve {
                    Curve::NistP256 => scalar.value_padded(32).to_vec(),
                    Curve::NistP384 => scalar.value_padded(48).to_vec(),
                    Curve::NistP521 => scalar.value_padded(66).to_vec(),
                    _ => scalar.value().to_vec(),
                };

                let template = vec![
                    Attribute::Class(ObjectClass::PRIVATE_KEY),
                    Attribute::Id(id.to_vec()),
                    Attribute::KeyType(cryptoki::object::KeyType::EC),
                    Attribute::EcParams(ec_param),
                    Attribute::Value(scalar),
                    //
                    // /// Determines if a key is extractable and can be wrapped
                    // Extractable(bool),

                    // Sensitive(bool),

                    // Attribute::Private(true),
                    // Attribute::Verify(true),
                    Attribute::Sign(true),
                    //
                    // SignRecover(bool),
                    // Encrypt(bool),
                    // Attribute::Decrypt(true),
                    Attribute::Derive(true), // FIXME: don't set for signing keys?
                    //
                    // AlwaysAuthenticate
                    // Touch / YubicoPinPolicy
                    Attribute::Token(true),
                ];

                self.session.create_object(&template)?
            }
            s => {
                return Err(anyhow::anyhow!(
                    "Unsupported type of SecretKeyMaterial: {:?}",
                    s
                ))
            }
        };

        log::debug!("created priv_key object {:x?}", priv_key);

        Ok(priv_key)
    }

    /// Generate PublicKeyInfo
    pub(crate) fn upload_gen_pki(
        key: &Key<SecretParts, UnspecifiedRole>,
    ) -> anyhow::Result<PublicKeyInfo> {
        let pub_key_info = match key.parts_as_public().mpis() {
            mpi::PublicKey::RSA { e, n } => {
                let rsa_pub = rsa::RsaPublicKey::new(
                    rsa::BigUint::from_bytes_be(n.value()),
                    rsa::BigUint::from_bytes_be(e.value()),
                )?;

                let bits = n.value().len() * 8; // FIXME: handle leading zeros?

                PublicKeyInfo::Rsa {
                    algorithm: match bits {
                        2048 => AlgorithmId::Rsa2048,
                        3072 => AlgorithmId::Rsa3072,
                        4096 => AlgorithmId::Rsa4096,
                        _ => return Err(anyhow::anyhow!("Unexpected RSA bit size {}", bits)),
                    },

                    pubkey: rsa_pub,
                }
            }
            mpi::PublicKey::ECDH { curve, q, .. } | mpi::PublicKey::ECDSA { curve, q, .. } => {
                match curve {
                    Curve::NistP256 => {
                        let p256 = p256::EncodedPoint::from_bytes(q.value()).map_err(|e| {
                            anyhow::anyhow!("Error while creating EncodedPoint: {e:?}")
                        })?;

                        PublicKeyInfo::EcP256(p256)
                    }
                    Curve::NistP384 => {
                        let p384 = p384::EncodedPoint::from_bytes(q.value()).map_err(|e| {
                            anyhow::anyhow!("Error while creating EncodedPoint: {e:?}")
                        })?;

                        PublicKeyInfo::EcP384(p384)
                    }
                    Curve::NistP521 => {
                        let p521 = p521::EncodedPoint::from_bytes(q.value()).map_err(|e| {
                            anyhow::anyhow!("Error while creating EncodedPoint: {e:?}")
                        })?;

                        PublicKeyInfo::EcP521(p521)
                    }
                    _ => return Err(anyhow::anyhow!("Unsupported curve {curve:?}")),
                }
            }

            pk => return Err(anyhow::anyhow!("Unexpected public key type {:?}", pk)),
        };

        Ok(pub_key_info)
    }

    /// Upload PublicKeyInfo (except, we don't actually upload it, for now)
    pub(crate) fn upload_pki(&self, _pki: &PublicKeyInfo) -> anyhow::Result<()> {
        // // - create public key object [unsupported by ykcs11?]
        // let _ = match key.parts_as_public().mpis() {
        //     mpi::PublicKey::RSA { e, n } => {
        //         let template = vec![
        //             Attribute::Class(ObjectClass::PUBLIC_KEY),
        //             Attribute::Id(id.to_vec()),
        //             Attribute::KeyType(cryptoki::object::KeyType::RSA),
        //             Attribute::ModulusBits(2048.into()), // FIXME: don't hardcode!
        //             Attribute::Modulus(n.value().to_vec()),
        //             Attribute::PublicExponent(e.value().to_vec()),
        //             //
        //             // / Determines if a key is extractable and can be wrapped
        //             // Extractable(bool),
        //
        //             // Sensitive(bool),
        //
        //             // Attribute::Private(true),
        //             // Attribute::Verify(true),
        //
        //             // Sign(bool),
        //             // SignRecover(bool),
        //             // Encrypt(bool),
        //             // Decrypt(bool),
        //
        //             // AlwaysAuthenticate
        //             // Touch / YubicoPinPolicy
        //             Attribute::Token(true),
        //         ];
        //
        //         let public_key = self.session.create_object(&template)?;
        //
        //         println!("pubkey: {public_key:#?}");
        //     }
        //     pk => unimplemented!("{:?}", pk),
        // };

        Ok(())
    }

    pub(crate) fn upload_self_sign_x509(
        &self,
        priv_key: ObjectHandle,
        tbs_cert: Zeroizing<Vec<u8>>,
        algo_id: AlgorithmId,
    ) -> anyhow::Result<Vec<u8>> {
        // function to self-sign
        let mut signer = |data: &[u8], algo: AlgorithmId| {
            let mechanism = match algo {
                AlgorithmId::Rsa2048 | AlgorithmId::Rsa3072 | AlgorithmId::Rsa4096 => {
                    Mechanism::RsaPkcs
                }
                AlgorithmId::EccP256 | AlgorithmId::EccP384 | AlgorithmId::EccP521 => {
                    Mechanism::Ecdsa
                }
            };

            self.session
                .sign(&mechanism, priv_key, data)
                .map_err(|e| e.into())
        };

        let cert = crate::x509::self_sign_x509(tbs_cert, algo_id, &mut signer)?;

        Ok(cert)
    }

    pub(crate) fn upload_cert(
        &self,
        cert: Vec<u8>,
        common_name: &str,
        serial: Vec<u8>,
        id: &[u8],
    ) -> anyhow::Result<()> {
        let template = vec![
            Attribute::Class(ObjectClass::CERTIFICATE),
            Attribute::CertificateType(CertificateType::X_509), // required by softhsm
            Attribute::Id(id.to_vec()),
            // Attribute::Label("foo".into()),
            // Attribute::Issuer("foo".into()),
            Attribute::Subject(common_name.into()), // required by softhsm
            Attribute::SerialNumber(serial),
            Attribute::Value(cert),
            Attribute::Token(true),
        ];

        let handle = self.session.create_object(&template)?;
        log::debug!("created certificate object {:x?}", handle);

        Ok(())
    }
}
