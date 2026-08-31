use cryptoki::mechanism::Mechanism;
use cryptoki::object::{
    Attribute, AttributeType, CertificateType, KeyType, MlDsaParameterSetType,
    MlKemParameterSetType, ObjectClass, ObjectHandle, ParameterSetType,
};
use crate::x509::types::{AlgorithmId, PublicKeyInfo};
use openssl::pkey::{KeyType as OsslKeyType, PKey};
use p256::elliptic_curve::zeroize::Zeroizing;
use sequoia_openpgp::crypto::mpi;
use sequoia_openpgp::packet::key::{Key6, PublicParts, SecretKeyMaterial, SecretParts, UnspecifiedRole};
use sequoia_openpgp::packet::Key;
use sequoia_openpgp::serialize::MarshalInto;
use sequoia_openpgp::types::{Curve, PublicKeyAlgorithm};

use crate::{CompositeAlgo, Op11Session, COMPOSITE_PUBKEY_LABEL};

// softhsmv3's CKA_EC_POINT wraps the raw Edwards/Montgomery public point as an
// ASN.1 OCTET STRING (tag 0x04, DER short-form length, raw bytes). Proven by
// the generate-in-HSM probe (originally for the 32-byte Ed25519/X25519 case;
// `read_ec_point` below generalizes the unwrap for Ed448/X448 too).
const EC_POINT_OCTET_TAG: u8 = 0x04;

// DER encoding of the Edwards/Montgomery curve OIDs stored as CKA_EC_PARAMS in
// softhsmv3 (OSSLEDPrivateKey::setEC -> OSSL::byteString2oid). Proven by the
// smoke-import probe ([C]/[D]).
const ED25519_OID_DER: &[u8] = &[0x06, 0x03, 0x2B, 0x65, 0x70]; // 1.3.101.112
const X25519_OID_DER: &[u8] = &[0x06, 0x03, 0x2B, 0x65, 0x6E]; // 1.3.101.110
// RFC 8410 §3 (plan §2/Fix 1+2): the Ed448/X448 counterparts, used by the
// MLDSA87_Ed448 / MLKEM1024_X448 composite algorithms (algo IDs 31/36).
const ED448_OID_DER: &[u8] = &[0x06, 0x03, 0x2B, 0x65, 0x71]; // 1.3.101.113
const X448_OID_DER: &[u8] = &[0x06, 0x03, 0x2B, 0x65, 0x6F]; // 1.3.101.111

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

/// Read `CKA_VALUE` of a (public) object — the raw FIPS public key for
/// ML-DSA/ML-KEM in softhsmv3 (1952 B / 1184 B; proven by the generate probe).
fn read_value(
    session: &cryptoki::session::Session,
    handle: ObjectHandle,
) -> anyhow::Result<Vec<u8>> {
    for attr in session.get_attributes(handle, &[AttributeType::Value])? {
        if let Attribute::Value(v) = attr {
            return Ok(v);
        }
    }
    Err(anyhow::anyhow!("public object has no CKA_VALUE"))
}

/// Read `CKA_EC_POINT` of an Edwards/Montgomery public object and strip the
/// ASN.1 OCTET-STRING wrapper (`04 <len> <raw>`), returning the raw public
/// point.
///
/// Generalized (plan §2/Fix 1+2) beyond the original Ed25519/X25519-only
/// 32-byte case to also accept Ed448 (57-byte) and X448 (56-byte) points —
/// all DER short-form lengths (< 128), so a single length octet always
/// follows the `04` tag.
fn read_ec_point(
    session: &cryptoki::session::Session,
    handle: ObjectHandle,
) -> anyhow::Result<Vec<u8>> {
    for attr in session.get_attributes(handle, &[AttributeType::EcPoint])? {
        if let Attribute::EcPoint(v) = attr {
            let raw = if v.len() >= 2
                && v[0] == EC_POINT_OCTET_TAG
                && (v[1] as usize) < 0x80
                && v.len() == 2 + v[1] as usize
            {
                v[2..].to_vec()
            } else if matches!(v.len(), 32 | 56 | 57) {
                // Some callers may already hand back an unwrapped raw point.
                v
            } else {
                return Err(anyhow::anyhow!(
                    "unexpected CKA_EC_POINT length {} (want a DER OCTET STRING \
                     wrapper or a raw 32/56/57-byte point)",
                    v.len()
                ));
            };
            return Ok(raw);
        }
    }
    Err(anyhow::anyhow!("public object has no CKA_EC_POINT"))
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
    /// - `MLDSA87_Ed448`: an Ed448 (`CKK_EC_EDWARDS`) object + an ML-DSA-87
    ///   (`CKK_ML_DSA`) object (remediation plan §2/Fix 1, algo 31).
    /// - `MLKEM768_X25519`: an X25519 (`CKK_EC_MONTGOMERY`) object + an
    ///   ML-KEM-768 (`CKK_ML_KEM`) object.
    /// - `MLKEM1024_X448`: an X448 (`CKK_EC_MONTGOMERY`) object + an
    ///   ML-KEM-1024 (`CKK_ML_KEM`) object (remediation plan §2/Fix 2, algo 36).
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

        // Store the composite *public* key as a token-resident OpenPGP packet so
        // the key can be reloaded purely from token data (plan §1 / task 1,
        // option b). The X.509 self-sign metadata flow is RSA/ECC-only and can't
        // carry a composite public MPI, so we persist the public key directly.
        self.store_composite_public(id, &key.parts_as_public().clone())?;

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
            (
                PublicKeyAlgorithm::MLDSA87_Ed448,
                mpi::SecretKeyMaterial::MLDSA87_Ed448 { eddsa, mldsa },
            ) => {
                // Traditional: Ed448 raw 57-byte scalar.
                let trad = self.create_eddsa_object(
                    id,
                    KeyType::EC_EDWARDS,
                    ED448_OID_DER,
                    &eddsa,
                    Attribute::Sign(true),
                    b"mldsa87-ed448-eddsa",
                )?;
                // PQC: ML-DSA-87 seed (xi, 32 B) -> PKCS#8 DER.
                let der = seed_to_pkcs8_der(&mldsa, OsslKeyType::ML_DSA_87)?;
                let pqc = self.create_ml_object(
                    id,
                    KeyType::ML_DSA,
                    MlDsaParameterSetType::ML_DSA_87.into(),
                    der,
                    Attribute::Sign(true),
                    b"mldsa87-ed448-mldsa",
                )?;
                Ok((trad, pqc))
            }
            (
                PublicKeyAlgorithm::MLKEM1024_X448,
                mpi::SecretKeyMaterial::MLKEM1024_X448 { ecdh, mlkem },
            ) => {
                // Traditional: X448 raw 56-byte scalar.
                let trad = self.create_eddsa_object(
                    id,
                    KeyType::EC_MONTGOMERY,
                    X448_OID_DER,
                    &ecdh,
                    Attribute::Derive(true),
                    b"mlkem1024-x448-ecdh",
                )?;
                // PQC: ML-KEM-1024 seed (d||z, 64 B) -> PKCS#8 DER.
                let der = seed_to_pkcs8_der(&mlkem, OsslKeyType::ML_KEM_1024)?;
                let pqc = self.create_ml_object(
                    id,
                    KeyType::ML_KEM,
                    MlKemParameterSetType::ML_KEM_1024.into(),
                    der,
                    Attribute::Decapsulate(true),
                    b"mlkem1024-x448-mlkem",
                )?;
                Ok((trad, pqc))
            }
            (algo, _) => Err(anyhow::anyhow!(
                "composite upload: unsupported / mismatched composite algorithm {algo:?}"
            )),
        }
    }

    /// Persist a composite key's *public* half as a token-resident `CKO_DATA`
    /// object so it can be reloaded purely from token data — no out-of-band
    /// `Cert` and no X.509 cert custody (plan task 1, option b).
    ///
    /// The X.509 self-sign path (`upload_self_sign_x509`) only knows RSA/ECC and
    /// cannot encode/sign a composite public key, so we store the public key
    /// directly as a serialized OpenPGP public-key packet. On reload, `key()`
    /// reads this `CKO_DATA` value and re-parses the exact composite public MPI
    /// (`MLDSA65_Ed25519` / `MLKEM768_X25519`), so the bridge never has to
    /// reconstruct a PQC public key from an X.509 descriptor it can't express.
    ///
    /// The id is carried in `CKA_APPLICATION` (softhsmv3 rejects `CKA_ID` on a
    /// `CKO_DATA` object — that attribute is not in its DATA template; see
    /// `P11DataObj::init`). A fixed `CKA_LABEL` (`COMPOSITE_PUBKEY_LABEL`) marks
    /// the object so `key()` can find exactly one for a given id.
    pub(crate) fn store_composite_public(
        &self,
        id: &[u8],
        public: &Key<PublicParts, UnspecifiedRole>,
    ) -> anyhow::Result<ObjectHandle> {
        // Serialize as a full OpenPGP public-key packet (tag + framing), so the
        // value round-trips through `PacketPile::from_bytes` on reload. A primary
        // role is used purely as the serialization vehicle; the reload converts
        // back to UnspecifiedRole.
        let packet: sequoia_openpgp::Packet = public.clone().role_into_primary().into();
        let bytes = packet
            .to_vec()
            .map_err(|e| anyhow::anyhow!("serialize composite public key packet failed: {e}"))?;

        let template = vec![
            Attribute::Class(ObjectClass::DATA),
            // CKA_APPLICATION carries the key id (CKA_ID is not allowed on DATA).
            Attribute::Application(id.to_vec()),
            Attribute::Label(COMPOSITE_PUBKEY_LABEL.to_vec()),
            Attribute::Value(bytes),
            Attribute::Token(true),
            Attribute::Private(false),
        ];
        let handle = self.session.create_object(&template)?;
        log::debug!("stored composite public-key DATA object {:x?}", handle);
        Ok(handle)
    }

    /// **Generate-in-HSM custody (plan task 3).** Generate a composite PQC key's
    /// two halves DIRECTLY inside the HSM via `C_GenerateKeyPair`, so the private
    /// key material never exists in software. Both private objects are marked
    /// non-extractable (`CKA_SENSITIVE=true`, `CKA_EXTRACTABLE=false`), so the
    /// HSM will refuse to release the private key bytes.
    ///
    /// This is the **default** provisioning path for the demo ("keys never leave
    /// the HSM"); `upload_key` remains the explicit bring-your-own-key import
    /// path. The two halves share one `CKA_ID`:
    ///
    /// - `MlDsa65Ed25519`: Ed25519 (`CKK_EC_EDWARDS`, sign) + ML-DSA-65
    ///   (`CKK_ML_DSA`, sign), both generated in-HSM.
    /// - `MlDsa87Ed448`: Ed448 (`CKK_EC_EDWARDS`, sign) + ML-DSA-87
    ///   (`CKK_ML_DSA`, sign), both generated in-HSM (remediation plan §2/Fix 1).
    /// - `MlKem768X25519`: X25519 (`CKK_EC_MONTGOMERY`, derive) + ML-KEM-768
    ///   (`CKK_ML_KEM`, decapsulate), both generated in-HSM.
    /// - `MlKem1024X448`: X448 (`CKK_EC_MONTGOMERY`, derive) + ML-KEM-1024
    ///   (`CKK_ML_KEM`, decapsulate), both generated in-HSM (remediation plan
    ///   §2/Fix 2).
    ///
    /// The generated *public* halves are read back from the token, assembled into
    /// the composite OpenPGP public key, and persisted as the token-resident
    /// `CKO_DATA` public object (task 1) so the key reloads purely from the token.
    /// Returns the composite public `Key`.
    pub fn generate_composite_in_hsm(
        &self,
        id: &[u8],
        algo: CompositeAlgo,
    ) -> anyhow::Result<Key<PublicParts, UnspecifiedRole>> {
        // Non-extractable private-key custody attributes — the heart of task 3.
        let sensitive = || {
            vec![
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
                Attribute::Id(id.to_vec()),
            ]
        };

        let public: Key6<PublicParts, UnspecifiedRole> = match algo {
            CompositeAlgo::MlDsa65Ed25519 => {
                // -- Ed25519 half, generated in-HSM --
                let mut ed_pub_t = vec![
                    Attribute::KeyType(KeyType::EC_EDWARDS),
                    Attribute::EcParams(ED25519_OID_DER.to_vec()),
                    Attribute::Token(true),
                    Attribute::Verify(true),
                    Attribute::Id(id.to_vec()),
                ];
                let mut ed_priv_t = sensitive();
                ed_priv_t.push(Attribute::KeyType(KeyType::EC_EDWARDS));
                ed_priv_t.push(Attribute::Sign(true));
                let (ed_pub, _ed_priv) = self.session.generate_key_pair(
                    &Mechanism::EccEdwardsKeyPairGen,
                    &{ ed_pub_t.push(Attribute::Label(b"mldsa65-ed25519-eddsa".to_vec())); ed_pub_t },
                    &{ ed_priv_t.push(Attribute::Label(b"mldsa65-ed25519-eddsa".to_vec())); ed_priv_t },
                )?;
                let eddsa = read_ec_point(&self.session, ed_pub)?;

                // -- ML-DSA-65 half, generated in-HSM --
                let ps: ParameterSetType = MlDsaParameterSetType::ML_DSA_65.into();
                let mut md_pub_t = vec![
                    Attribute::KeyType(KeyType::ML_DSA),
                    Attribute::ParameterSet(ps),
                    Attribute::Token(true),
                    Attribute::Verify(true),
                    Attribute::Id(id.to_vec()),
                ];
                let mut md_priv_t = sensitive();
                md_priv_t.push(Attribute::KeyType(KeyType::ML_DSA));
                md_priv_t.push(Attribute::ParameterSet(ps));
                md_priv_t.push(Attribute::Sign(true));
                let (md_pub, _md_priv) = self.session.generate_key_pair(
                    &Mechanism::MlDsaKeyPairGen,
                    &{ md_pub_t.push(Attribute::Label(b"mldsa65-ed25519-mldsa".to_vec())); md_pub_t },
                    &{ md_priv_t.push(Attribute::Label(b"mldsa65-ed25519-mldsa".to_vec())); md_priv_t },
                )?;
                let mldsa = read_value(&self.session, md_pub)?;

                Key6::import_public_mldsa65_ed25519(&mldsa, &eddsa, None)
                    .map_err(|e| anyhow::anyhow!("assemble MLDSA65_Ed25519 public key: {e}"))?
            }
            CompositeAlgo::MlKem768X25519 => {
                // -- X25519 half, generated in-HSM --
                let mut x_pub_t = vec![
                    Attribute::KeyType(KeyType::EC_MONTGOMERY),
                    Attribute::EcParams(X25519_OID_DER.to_vec()),
                    Attribute::Token(true),
                    Attribute::Derive(true),
                    Attribute::Id(id.to_vec()),
                ];
                let mut x_priv_t = sensitive();
                x_priv_t.push(Attribute::KeyType(KeyType::EC_MONTGOMERY));
                x_priv_t.push(Attribute::Derive(true));
                let (x_pub, _x_priv) = self.session.generate_key_pair(
                    &Mechanism::EccMontgomeryKeyPairGen,
                    &{ x_pub_t.push(Attribute::Label(b"mlkem768-x25519-ecdh".to_vec())); x_pub_t },
                    &{ x_priv_t.push(Attribute::Label(b"mlkem768-x25519-ecdh".to_vec())); x_priv_t },
                )?;
                let ecdh = read_ec_point(&self.session, x_pub)?;

                // -- ML-KEM-768 half, generated in-HSM --
                let ps: ParameterSetType = MlKemParameterSetType::ML_KEM_768.into();
                let mut mk_pub_t = vec![
                    Attribute::KeyType(KeyType::ML_KEM),
                    Attribute::ParameterSet(ps),
                    Attribute::Token(true),
                    Attribute::Encapsulate(true),
                    Attribute::Id(id.to_vec()),
                ];
                let mut mk_priv_t = sensitive();
                mk_priv_t.push(Attribute::KeyType(KeyType::ML_KEM));
                mk_priv_t.push(Attribute::ParameterSet(ps));
                mk_priv_t.push(Attribute::Decapsulate(true));
                let (mk_pub, _mk_priv) = self.session.generate_key_pair(
                    &Mechanism::MlKemKeyPairGen,
                    &{ mk_pub_t.push(Attribute::Label(b"mlkem768-x25519-mlkem".to_vec())); mk_pub_t },
                    &{ mk_priv_t.push(Attribute::Label(b"mlkem768-x25519-mlkem".to_vec())); mk_priv_t },
                )?;
                let mlkem = read_value(&self.session, mk_pub)?;

                Key6::import_public_mlkem768_x25519(&mlkem, &ecdh, None)
                    .map_err(|e| anyhow::anyhow!("assemble MLKEM768_X25519 public key: {e}"))?
            }
            CompositeAlgo::MlDsa87Ed448 => {
                // -- Ed448 half, generated in-HSM --
                let mut ed_pub_t = vec![
                    Attribute::KeyType(KeyType::EC_EDWARDS),
                    Attribute::EcParams(ED448_OID_DER.to_vec()),
                    Attribute::Token(true),
                    Attribute::Verify(true),
                    Attribute::Id(id.to_vec()),
                ];
                let mut ed_priv_t = sensitive();
                ed_priv_t.push(Attribute::KeyType(KeyType::EC_EDWARDS));
                ed_priv_t.push(Attribute::Sign(true));
                let (ed_pub, _ed_priv) = self.session.generate_key_pair(
                    &Mechanism::EccEdwardsKeyPairGen,
                    &{ ed_pub_t.push(Attribute::Label(b"mldsa87-ed448-eddsa".to_vec())); ed_pub_t },
                    &{ ed_priv_t.push(Attribute::Label(b"mldsa87-ed448-eddsa".to_vec())); ed_priv_t },
                )?;
                let eddsa = read_ec_point(&self.session, ed_pub)?;

                // -- ML-DSA-87 half, generated in-HSM --
                let ps: ParameterSetType = MlDsaParameterSetType::ML_DSA_87.into();
                let mut md_pub_t = vec![
                    Attribute::KeyType(KeyType::ML_DSA),
                    Attribute::ParameterSet(ps),
                    Attribute::Token(true),
                    Attribute::Verify(true),
                    Attribute::Id(id.to_vec()),
                ];
                let mut md_priv_t = sensitive();
                md_priv_t.push(Attribute::KeyType(KeyType::ML_DSA));
                md_priv_t.push(Attribute::ParameterSet(ps));
                md_priv_t.push(Attribute::Sign(true));
                let (md_pub, _md_priv) = self.session.generate_key_pair(
                    &Mechanism::MlDsaKeyPairGen,
                    &{ md_pub_t.push(Attribute::Label(b"mldsa87-ed448-mldsa".to_vec())); md_pub_t },
                    &{ md_priv_t.push(Attribute::Label(b"mldsa87-ed448-mldsa".to_vec())); md_priv_t },
                )?;
                let mldsa = read_value(&self.session, md_pub)?;

                Key6::import_public_mldsa87_ed448(&mldsa, &eddsa, None)
                    .map_err(|e| anyhow::anyhow!("assemble MLDSA87_Ed448 public key: {e}"))?
            }
            CompositeAlgo::MlKem1024X448 => {
                // -- X448 half, generated in-HSM --
                let mut x_pub_t = vec![
                    Attribute::KeyType(KeyType::EC_MONTGOMERY),
                    Attribute::EcParams(X448_OID_DER.to_vec()),
                    Attribute::Token(true),
                    Attribute::Derive(true),
                    Attribute::Id(id.to_vec()),
                ];
                let mut x_priv_t = sensitive();
                x_priv_t.push(Attribute::KeyType(KeyType::EC_MONTGOMERY));
                x_priv_t.push(Attribute::Derive(true));
                let (x_pub, _x_priv) = self.session.generate_key_pair(
                    &Mechanism::EccMontgomeryKeyPairGen,
                    &{ x_pub_t.push(Attribute::Label(b"mlkem1024-x448-ecdh".to_vec())); x_pub_t },
                    &{ x_priv_t.push(Attribute::Label(b"mlkem1024-x448-ecdh".to_vec())); x_priv_t },
                )?;
                let ecdh = read_ec_point(&self.session, x_pub)?;

                // -- ML-KEM-1024 half, generated in-HSM --
                let ps: ParameterSetType = MlKemParameterSetType::ML_KEM_1024.into();
                let mut mk_pub_t = vec![
                    Attribute::KeyType(KeyType::ML_KEM),
                    Attribute::ParameterSet(ps),
                    Attribute::Token(true),
                    Attribute::Encapsulate(true),
                    Attribute::Id(id.to_vec()),
                ];
                let mut mk_priv_t = sensitive();
                mk_priv_t.push(Attribute::KeyType(KeyType::ML_KEM));
                mk_priv_t.push(Attribute::ParameterSet(ps));
                mk_priv_t.push(Attribute::Decapsulate(true));
                let (mk_pub, _mk_priv) = self.session.generate_key_pair(
                    &Mechanism::MlKemKeyPairGen,
                    &{ mk_pub_t.push(Attribute::Label(b"mlkem1024-x448-mlkem".to_vec())); mk_pub_t },
                    &{ mk_priv_t.push(Attribute::Label(b"mlkem1024-x448-mlkem".to_vec())); mk_priv_t },
                )?;
                let mlkem = read_value(&self.session, mk_pub)?;

                Key6::import_public_mlkem1024_x448(&mlkem, &ecdh, None)
                    .map_err(|e| anyhow::anyhow!("assemble MLKEM1024_X448 public key: {e}"))?
            }
        };

        let public: Key<PublicParts, UnspecifiedRole> = sequoia_openpgp::packet::Key::from(public);

        // Persist the composite public key so it reloads from the token (task 1).
        self.store_composite_public(id, &public)?;

        Ok(public)
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
