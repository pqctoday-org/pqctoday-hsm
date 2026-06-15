use cryptoki::mechanism::Mechanism;
use cryptoki::object::{
    Attribute, CertificateType, KeyType, MlDsaParameterSetType, MlKemParameterSetType, ObjectClass,
    ObjectHandle, ParameterSetType,
};
use crate::x509::types::{AlgorithmId, PublicKeyInfo};
use openssl::pkey::{KeyType as OsslKeyType, PKey};
use p256::elliptic_curve::zeroize::Zeroizing;
use sequoia_openpgp::crypto::mpi;
use sequoia_openpgp::packet::key::{SecretKeyMaterial, SecretParts, UnspecifiedRole};
use sequoia_openpgp::packet::Key;
use sequoia_openpgp::types::{Curve, PublicKeyAlgorithm};

use crate::Op11Session;

// DER encoding of the Edwards/Montgomery curve OIDs stored as CKA_EC_PARAMS in
// softhsmv3 (OSSLEDPrivateKey::setEC -> OSSL::byteString2oid). Proven by the
// smoke-import probe ([C]/[D]).
const ED25519_OID_DER: &[u8] = &[0x06, 0x03, 0x2B, 0x65, 0x70]; // 1.3.101.112
const X25519_OID_DER: &[u8] = &[0x06, 0x03, 0x2B, 0x65, 0x6E]; // 1.3.101.110

/// Turn a raw FIPS deterministic seed (ML-DSA xi, 32 B; ML-KEM d||z, 64 B) into
/// the PKCS#8 DER softhsmv3 stores as `CKA_VALUE` for an ML-DSA/ML-KEM private
/// object (OSSL{MLDSA,MLKEM}PrivateKey::createOSSLKey -> d2i_PKCS8_PRIV_KEY_INFO).
///
/// sequoia keeps each composite PQC half as a *seed* (see sequoia crypto/mpi.rs
/// `SecretKeyMaterial::{MLDSA65_Ed25519,MLKEM768_X25519}`); softhsmv3 wants the
/// reconstructed PKCS#8 key. OpenSSL >= 3.5 derives the key reproducibly from the
/// seed via `PKey::private_key_from_seed`. Proven end-to-end by the smoke-import
/// probe ([A]/[B]). See PQC_PGP_IMPLEMENTATION_PLAN.md §5.
fn seed_to_pkcs8_der(seed: &[u8], key_type: OsslKeyType) -> anyhow::Result<Vec<u8>> {
    let pkey = PKey::private_key_from_seed(None, key_type, None, seed).map_err(|e| {
        anyhow::anyhow!("PKey::private_key_from_seed failed (needs OpenSSL >= 3.5): {e}")
    })?;
    pkey.private_key_to_pkcs8()
        .map_err(|e| anyhow::anyhow!("private_key_to_pkcs8 failed: {e}"))
}

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

    /// Store the TWO component private halves of a composite PQC key as two
    /// PKCS#11 private-key objects that share one `CKA_ID`, tagged with the
    /// `CKA_KEY_TYPE`s `keypair()` resolves by (plan §4/§5 two-handle custody):
    ///
    /// - `MLDSA65_Ed25519`: an Ed25519 (`CKK_EC_EDWARDS`) object + an ML-DSA-65
    ///   (`CKK_ML_DSA`) object.
    /// - `MLKEM768_X25519`: an X25519 (`CKK_EC_MONTGOMERY`) object + an
    ///   ML-KEM-768 (`CKK_ML_KEM`) object.
    ///
    /// The traditional half is imported as a raw scalar (`CKA_VALUE`) + curve OID
    /// (`CKA_EC_PARAMS`); the PQC half is imported as PKCS#8 DER derived from
    /// sequoia's stored seed (`seed_to_pkcs8_der`). Every shape here is proven
    /// against live softhsmv3 by the `smoke-import` probe. Returns
    /// `(traditional_handle, pqc_handle)`.
    pub(crate) fn upload_composite_private(
        &self,
        id: &[u8],
        key: &Key<SecretParts, UnspecifiedRole>,
    ) -> anyhow::Result<(ObjectHandle, ObjectHandle)> {
        let unenc = if let SecretKeyMaterial::Unencrypted(ref u) = key.secret() {
            u
        } else {
            return Err(anyhow::anyhow!(
                "composite upload: private key material is encrypted"
            ));
        };
        let secret = unenc.map(|mpis| mpis.clone());

        match (key.pk_algo(), secret) {
            (
                PublicKeyAlgorithm::MLDSA65_Ed25519,
                mpi::SecretKeyMaterial::MLDSA65_Ed25519 { eddsa, mldsa },
            ) => {
                // Traditional: Ed25519 raw 32-byte scalar.
                let trad = self.create_eddsa_object(
                    id,
                    KeyType::EC_EDWARDS,
                    ED25519_OID_DER,
                    &eddsa,
                    Attribute::Sign(true),
                    b"mldsa65-ed25519-eddsa",
                )?;
                // PQC: ML-DSA-65 seed (xi, 32 B) -> PKCS#8 DER.
                let der = seed_to_pkcs8_der(&mldsa, OsslKeyType::ML_DSA_65)?;
                let pqc = self.create_ml_object(
                    id,
                    KeyType::ML_DSA,
                    MlDsaParameterSetType::ML_DSA_65.into(),
                    der,
                    Attribute::Sign(true),
                    b"mldsa65-ed25519-mldsa",
                )?;
                Ok((trad, pqc))
            }
            (
                PublicKeyAlgorithm::MLKEM768_X25519,
                mpi::SecretKeyMaterial::MLKEM768_X25519 { ecdh, mlkem },
            ) => {
                // Traditional: X25519 raw 32-byte scalar.
                let trad = self.create_eddsa_object(
                    id,
                    KeyType::EC_MONTGOMERY,
                    X25519_OID_DER,
                    &ecdh,
                    Attribute::Derive(true),
                    b"mlkem768-x25519-ecdh",
                )?;
                // PQC: ML-KEM-768 seed (d||z, 64 B) -> PKCS#8 DER.
                let der = seed_to_pkcs8_der(&mlkem, OsslKeyType::ML_KEM_768)?;
                let pqc = self.create_ml_object(
                    id,
                    KeyType::ML_KEM,
                    MlKemParameterSetType::ML_KEM_768.into(),
                    der,
                    Attribute::Decapsulate(true),
                    b"mlkem768-x25519-mlkem",
                )?;
                Ok((trad, pqc))
            }
            (algo, _) => Err(anyhow::anyhow!(
                "composite upload: unsupported / mismatched composite algorithm {algo:?}"
            )),
        }
    }

    /// Create an Edwards/Montgomery private-key object (raw scalar + curve OID).
    fn create_eddsa_object(
        &self,
        id: &[u8],
        key_type: KeyType,
        oid_der: &[u8],
        scalar: &[u8],
        usage: Attribute,
        label: &[u8],
    ) -> anyhow::Result<ObjectHandle> {
        let template = vec![
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Id(id.to_vec()),
            Attribute::KeyType(key_type),
            Attribute::EcParams(oid_der.to_vec()),
            Attribute::Value(scalar.to_vec()),
            usage,
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Label(label.to_vec()),
        ];
        let handle = self.session.create_object(&template)?;
        log::debug!("created composite traditional object {:x?}", handle);
        Ok(handle)
    }

    /// Create an ML-DSA/ML-KEM private-key object (PKCS#8 DER + parameter set).
    fn create_ml_object(
        &self,
        id: &[u8],
        key_type: KeyType,
        param_set: ParameterSetType,
        pkcs8_der: Vec<u8>,
        usage: Attribute,
        label: &[u8],
    ) -> anyhow::Result<ObjectHandle> {
        let template = vec![
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Id(id.to_vec()),
            Attribute::KeyType(key_type),
            Attribute::ParameterSet(param_set),
            Attribute::Value(pkcs8_der),
            usage,
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Label(label.to_vec()),
        ];
        let handle = self.session.create_object(&template)?;
        log::debug!("created composite PQC object {:x?}", handle);
        Ok(handle)
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
