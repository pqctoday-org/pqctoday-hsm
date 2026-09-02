//! Library for PKCS #11 HSM usage with Sequoia PGP.
//!
//! Example use, uploading an OpenPGP key to a PKCS #11 device:
//!
//! ```no_run
//! use openpgp_pkcs11_sequoia::Op11;
//!
//! // PKCS #11 driver module
//! let module = "/usr/lib64/pkcs11/yubihsm_pkcs11.so";
//!
//! // Serial of the PKCS #11 slot
//! let serial = "07550916";
//!
//! // Open PKCS #11 context and slot
//! let mut pkcs11 = Op11::open(module)?;
//! let slot = pkcs11.slot(serial)?;
//!
//! // Open a read-write session, log in as user
//! let session = slot.open_rw_session()?;
//! session.login("0001password")?;
//!
//! // Upload an OpenPGP component key to the PKCS #11 device as id "3"
//! # let common_name = String::new();
//! # let pgp_key = sequoia_openpgp::packet::key::Key4::generate_ecc(true, sequoia_openpgp::types::Curve::NistP256)?.into();
//! session.upload_key(&[3], &pgp_key, &common_name)?;
//! # Ok::<(), anyhow::Error>(())
//! ```

use std::sync::{Arc, Mutex};

use anyhow::Result;
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::RvError;
use cryptoki::object::{Attribute, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use sequoia_openpgp::packet::key::{PublicParts, SecretParts, UnspecifiedRole};
use sequoia_openpgp::packet::Key;
use sequoia_openpgp::parse::stream::DecryptorBuilder;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::policy::NullPolicy;
use sequoia_openpgp::types::{PublicKeyAlgorithm, Timestamp};
use sequoia_openpgp::{Cert, Fingerprint};

pub(crate) mod decryptor;
pub(crate) mod signer;
mod upload;
mod util;
pub mod x509;

// Re-export the inlined X.509/OpenPGP helper types (formerly the abandoned
// `openpgp-x509-sequoia` crate, now inlined — see plan §2.3). The CLI and the
// bridge's own modules use `PgpKeyType` through these paths.
pub use crate::x509::types::PgpKeyType;

/// Composite PQC key algorithms the bridge can custody.
///
/// Used by the generate-in-HSM provisioning path
/// ([`Op11Session::generate_composite_in_hsm`]) — the **default** custody mode
/// for the demo, in which both private halves are generated *inside* the HSM via
/// `C_GenerateKeyPair` and never exist in software (plan task 3). The
/// import/bring-your-own-key path ([`Op11Session::upload_key`]) accepts any
/// composite key sequoia can produce; this enum names the four the bridge
/// generates natively.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompositeAlgo {
    /// `MLDSA65_Ed25519` (draft-ietf-openpgp-pqc algorithm 30) — signing.
    MlDsa65Ed25519,
    /// `MLDSA87_Ed448` (draft-ietf-openpgp-pqc algorithm 31) — signing.
    MlDsa87Ed448,
    /// `MLKEM768_X25519` (draft-ietf-openpgp-pqc algorithm 35) — encryption.
    MlKem768X25519,
    /// `MLKEM1024_X448` (draft-ietf-openpgp-pqc algorithm 36) — encryption.
    MlKem1024X448,
}

/// `CKA_LABEL` of the token-resident `CKO_DATA` object that carries a composite
/// PQC key's serialized OpenPGP *public* key (plan task 1, option b).
///
/// Composite keys (`MLDSA65_Ed25519` / `MLKEM768_X25519`) cannot ride the
/// RSA/ECC-only X.509 self-sign custody path, so `upload_composite_private`
/// stores the composite public key directly as a `CKO_DATA` value sharing the
/// key's `CKA_ID`, and `key()` reloads it from the token alone — no out-of-band
/// `Cert` required.
pub(crate) const COMPOSITE_PUBKEY_LABEL: &[u8] = b"pqctoday-composite-pgp-pubkey";

/// OpenPGP PKCS #11 context
pub struct Op11 {
    pkcs11: Pkcs11,
}

impl Op11 {
    /// Open and initialize PKCS #11 context
    pub fn open(module: &str) -> Result<Self> {
        let pkcs11 = Pkcs11::new(module)?;

        // cryptoki 0.12: CInitializeArgs::OsThreads is gone; build args from
        // the OS-locking flag instead (plan §5 — cryptoki 0.4->0.12 migration).
        let res = pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK));
        match res {
            // cryptoki 0.12: Error::Pkcs11 now carries (RvError, Function).
            Err(cryptoki::error::Error::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => {
                // Ignore multiple initializations

                // If a program calls Op11::open more than once, each
                // Pkcs11::new will start out with `is_initialized=false`.
                // So we don't know if initialization is actually needed.

                // Calling initialize() and ignoring this error is one
                // way to resolve this.
            }
            Err(e) => return Err(e.into()),
            Ok(()) => {}
        }

        Ok(Op11 { pkcs11 })
    }

    /// Get PKCS #11 `Slot` that matches `serial_number`
    pub fn slot(&mut self, serial_number: &str) -> Result<Op11Slot> {
        for slot in self.pkcs11.get_all_slots()? {
            if let Ok(ti) = self.pkcs11.get_token_info(slot) {
                if serial_number == ti.serial_number() {
                    log::debug!("token info: {:#?}", ti);

                    return Ok(Op11Slot {
                        slot,
                        pkcs11: &self.pkcs11,
                    });
                }
            }
        }

        Err(anyhow::anyhow!("No slot found for '{serial_number}'"))
    }

    /// Get all (initialized) PKCS #11 `Slot`s
    pub fn slots(&mut self) -> Result<Vec<Op11Slot>> {
        Ok(self
            .pkcs11
            .get_slots_with_initialized_token()?
            .into_iter()
            .map(|slot| Op11Slot {
                slot,
                pkcs11: &self.pkcs11,
            })
            .collect())
    }

    /// XXX: escape hatch for direct PKCS #11 access (will be removed)
    pub fn pkcs11(&self) -> &Pkcs11 {
        &self.pkcs11
    }
}

/// OpenPGP PKCS #11 Slot
pub struct Op11Slot<'a> {
    slot: Slot,
    pkcs11: &'a Pkcs11,
}

impl Op11Slot<'_> {
    pub fn open_rw_session(self) -> Result<Op11Session> {
        let session = self.pkcs11.open_rw_session(self.slot)?;
        Ok(Op11Session { session })
    }

    pub fn open_ro_session(self) -> Result<Op11Session> {
        let session = self.pkcs11.open_ro_session(self.slot)?;
        Ok(Op11Session { session })
    }

    pub fn serial(&self) -> Result<String> {
        if let Ok(ti) = self.pkcs11.get_token_info(self.slot) {
            return Ok(ti.serial_number().to_string());
        }

        Err(anyhow::anyhow!("Couldn't get serial number"))
    }
}

/// OpenPGP PKCS #11 Session
pub struct Op11Session {
    session: Session,
}

impl Op11Session {
    /// Log in as UserType::User
    pub fn login(&self, pin: &str) -> Result<()> {
        // cryptoki 0.12: login takes Option<&AuthPin> (a SecretString), not
        // Option<&str> (plan §5 — cryptoki migration).
        //
        // PKCS#11 login state is per-token across all sessions of an
        // application, so a second session on the same token returns
        // CKR_USER_ALREADY_LOGGED_IN. That is a benign no-op for us (the token
        // is already in the desired logged-in state), so we treat it as success.
        match self
            .session
            .login(UserType::User, Some(&AuthPin::new(pin.to_string().into())))
        {
            Ok(()) => Ok(()),
            Err(cryptoki::error::Error::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Log in as UserType::So
    pub fn login_so(&self, pin: &str) -> Result<()> {
        self.session
            .login(UserType::So, Some(&AuthPin::new(pin.to_string().into())))?;
        Ok(())
    }

    /// Log out
    pub fn logout(&self) -> Result<()> {
        self.session.logout()?;
        Ok(())
    }

    /// Get OpenPGP [`sequoia_openpgp::packet::Key`] for `id`.
    ///
    /// The optional `cert` is used as source of OpenPGP metadata, if available.
    pub fn key(
        &self,
        id: &[u8],
        pkt: PgpKeyType,
        cert: Option<Cert>,
    ) -> Result<Key<PublicParts, UnspecifiedRole>> {
        // Composite PQC keys carry their public half as a token-resident
        // CKO_DATA object (no X.509 cert custody — plan task 1, option b). Check
        // for it FIRST so a composite key reloads purely from token data, with
        // no out-of-band Cert and even when no X.509 certificate object exists.
        if let Some(public) = self.load_composite_public(id)? {
            return Ok(public);
        }

        let x509cert = util::x509_cert(&self.session, id)?;

        // If we have a Cert, we expect to find a matching key in it, and use that
        if let Some(c) = cert {
            return crate::x509::find_key_by_x509cert(&x509cert, &c);
        }

        let x509_cert = x509_certificate::rfc5280::Certificate::from(x509cert.clone());

        let x509_creation_time = if let x509_certificate::asn1time::Time::UtcTime(utc) =
            x509_cert.tbs_certificate.validity.not_before.clone()
        {
            Timestamp::from(utc.timestamp() as u32).into()
        } else {
            return Err(anyhow::anyhow!(
                "Unexpected enum variant for validity.not_before"
            ));
        };

        // Get subkey fingerprint from x509 cert extension, if set
        let extension_subkey_fp =
            crate::x509::experimental::extension_fingerprint(&x509_cert)?;

        // Get kdf_kek params from x509 cert extension, if set
        let extension_kdf_kek: Option<[u8; 4]> =
            crate::x509::experimental::extension_kdf_kek(&x509_cert)?;

        // - If we have an extension_subkey_fp, we expect to match its FP,
        // - Otherwise, we expect the serial to match the FP.
        let fp = if let Some(fp) = extension_subkey_fp {
            fp
        } else {
            let serial = x509_cert.tbs_certificate.serial_number.as_slice();
            let serial = &serial[serial.len() - 20..]; // FIXME
            // sequoia 2.x: Fingerprint::from_bytes now takes a version (u8) and
            // returns Result. A 20-byte serial is a v4 fingerprint (plan §3).
            Fingerprint::from_bytes(4, serial)?
        };

        let k4 = if let Ok(rsa_pub) = x509cert.rsa_public_key_data() {
            // -- RSA --

            util::get_rsa_as_pgp(rsa_pub, x509_creation_time)?
        } else {
            // -- ECC --

            // (this is not currently needed for gnupg-pkcs11-scd migration,
            // because that project doesn't yet support ECC keys)
            let pki = x509_cert.tbs_certificate.subject_public_key_info;

            util::get_ecc_as_pgp(pkt, pki, x509_creation_time, &fp, extension_kdf_kek)?
        };

        // We expect a positive match, before using a key for OpenPGP.
        if k4.fingerprint() != fp {
            return Err(anyhow::anyhow!(
                "Couldn't find matching key for Fingerprint {:?}",
                fp
            ));
        }

        Ok(k4.into())
    }

    /// Reload a composite key's public half from its token-resident `CKO_DATA`
    /// object (plan task 1, option b), if present. Returns `Ok(None)` when there
    /// is no such object (i.e. a classical key that uses the X.509 cert path).
    ///
    /// This is what makes a composite key reload *purely from token data*: the
    /// stored value is the serialized OpenPGP public-key packet written by
    /// `store_composite_public`, so the exact composite public MPI
    /// (`MLDSA65_Ed25519` / `MLKEM768_X25519`) is recovered byte-for-byte with no
    /// out-of-band `Cert` and no X.509 reconstruction.
    fn load_composite_public(
        &self,
        id: &[u8],
    ) -> Result<Option<Key<PublicParts, UnspecifiedRole>>> {
        use cryptoki::object::AttributeType;
        use sequoia_openpgp::packet::Packet;
        use sequoia_openpgp::PacketPile;

        // The id is stored in CKA_APPLICATION (CKA_ID is not a valid attribute
        // on a CKO_DATA object in softhsmv3 — see store_composite_public).
        let objs = self.session.find_objects(&[
            Attribute::Class(ObjectClass::DATA),
            Attribute::Application(id.to_vec()),
            Attribute::Label(COMPOSITE_PUBKEY_LABEL.to_vec()),
        ])?;
        let handle = match objs.len() {
            0 => return Ok(None),
            1 => objs[0],
            n => {
                return Err(anyhow::anyhow!(
                    "expected at most one composite public-key DATA object for id {id:x?}, found {n}"
                ))
            }
        };

        let mut value = None;
        for attr in self.session.get_attributes(handle, &[AttributeType::Value])? {
            if let Attribute::Value(v) = attr {
                value = Some(v);
            }
        }
        let value = value
            .ok_or_else(|| anyhow::anyhow!("composite public-key DATA object has no CKA_VALUE"))?;

        // Re-parse the serialized OpenPGP public-key packet.
        let pile = PacketPile::from_bytes(&value)
            .map_err(|e| anyhow::anyhow!("parse composite public-key packet failed: {e}"))?;
        let packets: Vec<Packet> = pile.into();
        for p in packets {
            match p {
                Packet::PublicKey(k) => {
                    return Ok(Some(k.parts_into_public().role_into_unspecified()))
                }
                Packet::PublicSubkey(k) => {
                    return Ok(Some(k.parts_into_public().role_into_unspecified()))
                }
                _ => {}
            }
        }
        Err(anyhow::anyhow!(
            "composite public-key DATA object did not contain a public-key packet"
        ))
    }

    /// Get an [`Op11KeyPair`] that can perform decryption and signing operations.
    ///
    /// The optional `cert` is used as source of OpenPGP metadata, if available.
    ///
    /// For a composite PQC key (`MLDSA65_Ed25519` / `MLKEM768_X25519`) this
    /// resolves **two** private-key handles sharing the `CKA_ID` — the
    /// traditional component and the post-quantum component — and returns a
    /// two-handle [`Op11KeyPair`] (plan §4/§5). For a classical key it resolves
    /// the single handle as before.
    pub fn keypair(self, id: &[u8], pkt: PgpKeyType, cert: Option<Cert>) -> Result<Op11KeyPair> {
        // get public key for id
        let key = self.key(id, pkt, cert)?;

        let is_composite = matches!(
            key.pk_algo(),
            PublicKeyAlgorithm::MLDSA65_Ed25519
                | PublicKeyAlgorithm::MLDSA87_Ed448
                | PublicKeyAlgorithm::MLKEM768_X25519
                | PublicKeyAlgorithm::MLKEM1024_X448
        );

        if !is_composite {
            // Classical single-handle path: select by usage attribute.
            let usage = match pkt {
                PgpKeyType::Sign | PgpKeyType::Auth => Attribute::Sign(true),
                PgpKeyType::Encrypt => Attribute::Decrypt(true),
            };
            let base_template = vec![
                Attribute::Token(true),
                Attribute::Private(true),
                usage,
                Attribute::Id(id.to_vec()),
                Attribute::Class(ObjectClass::PRIVATE_KEY),
            ];
            let priv_key_handle = self.session.find_objects(&base_template)?;
            return if priv_key_handle.len() == 1 {
                Ok(Op11KeyPair::new(
                    key,
                    priv_key_handle[0],
                    Arc::new(Mutex::new(self.session)),
                ))
            } else {
                Err(anyhow::anyhow!(
                    "Unexpected number of private keys found: {}",
                    priv_key_handle.len()
                ))
            };
        }

        // Composite: resolve the two component handles by CKA_KEY_TYPE alone.
        // The two halves carry DIFFERENT usage attributes that depend on the
        // composite role — Ed25519=Sign / ML-DSA=Sign for a signing key, but
        // X25519=Derive / ML-KEM=Decapsulate (NOT Decrypt) for an encryption key
        // — so a single usage filter cannot match both. CKA_KEY_TYPE + CKA_ID +
        // CKO_PRIVATE_KEY already uniquely identifies each component, so the
        // composite path selects on key type and omits the usage attribute.
        let (trad_kt, pqc_kt) = match key.pk_algo() {
            PublicKeyAlgorithm::MLDSA65_Ed25519 | PublicKeyAlgorithm::MLDSA87_Ed448 => {
                (cryptoki::object::KeyType::EC_EDWARDS, cryptoki::object::KeyType::ML_DSA)
            }
            PublicKeyAlgorithm::MLKEM768_X25519 | PublicKeyAlgorithm::MLKEM1024_X448 => {
                // X25519 lives as a CKK_EC_MONTGOMERY object in softhsmv3.
                (cryptoki::object::KeyType::EC_MONTGOMERY, cryptoki::object::KeyType::ML_KEM)
            }
            _ => unreachable!("is_composite implies a composite pk_algo"),
        };

        let composite_base = vec![
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Id(id.to_vec()),
            Attribute::Class(ObjectClass::PRIVATE_KEY),
        ];

        let find_one = |kt| -> Result<ObjectHandle> {
            let mut tmpl = composite_base.clone();
            tmpl.push(Attribute::KeyType(kt));
            let handles = self.session.find_objects(&tmpl)?;
            if handles.len() == 1 {
                Ok(handles[0])
            } else {
                Err(anyhow::anyhow!(
                    "Composite custody: expected exactly one {:?} private key for id {:x?}, found {}",
                    kt,
                    id,
                    handles.len()
                ))
            }
        };

        let trad_handle = find_one(trad_kt)?;
        let pqc_handle = find_one(pqc_kt)?;

        Ok(Op11KeyPair::new_composite(
            key,
            trad_handle,
            pqc_handle,
            Arc::new(Mutex::new(self.session)),
        ))
    }

    /// Perform a decryption operation on a card.
    ///
    /// The optional `cert` is used as source of OpenPGP metadata, if available.
    pub fn decrypt(
        self,
        id: &[u8],
        input: &mut (dyn std::io::Read + Send + Sync),
        output: &mut (dyn std::io::Write + Send + Sync),
        cert: Option<Cert>,
    ) -> Result<()> {
        let op11kp = self.keypair(id, PgpKeyType::Encrypt, cert)?;

        // Now, create a decryptor with a helper using the given Certs.
        // sequoia 2.x hardened NullPolicy::new() to `unsafe` because a null
        // policy accepts every algorithm/parameter unconditionally. That is
        // acceptable here: this is an HSM-custody decrypt path where the caller
        // supplies the message and the key handle out-of-band, and the bridge
        // is not making trust decisions about third-party material (plan §3).
        let policy = unsafe { NullPolicy::new() };
        let policy = &policy;
        let mut decryptor =
            DecryptorBuilder::from_reader(input)?.with_policy(policy, None, op11kp)?;

        // Decrypt the data.
        std::io::copy(&mut decryptor, output)?;

        Ok(())
    }

    /// Perform a signing operation on a card.
    ///
    /// The optional `cert` is used as source of OpenPGP metadata, if available.
    pub fn sign(
        self,
        id: &[u8],
        input: &mut (dyn std::io::Read + Send + Sync),
        output: &mut (dyn std::io::Write + Send + Sync),
        cert: Option<Cert>,
    ) -> Result<()> {
        let op11kp = self.keypair(id, PgpKeyType::Sign, cert)?;

        signer::sign_on_card(op11kp, input, output)
    }

    /// Upload an OpenPGP component key to a card.
    ///
    /// - Uploads private key object
    /// - Generates an X.509 certificate (with experimental OpenPGP metadata)
    /// - Self-signs the certificate
    /// - Uploads the X.509 certificate
    ///
    /// (NOTE: The OpenPGP metadata that gets generated by this function
    /// is intended for testing purposes only!
    /// More standardization work is required to define how OpenPGP
    /// metadata gets stored in the generated X.509 certificate.)
    ///
    /// FIXME: split up private key and X.509 certificate upload
    /// -> give the user more control over the generated certificate.
    pub fn upload_key(
        &self,
        id: &[u8],
        key: &Key<SecretParts, UnspecifiedRole>,
        common_name: &str,
    ) -> Result<()> {
        // Composite PQC keys (MLDSA65_Ed25519 / MLKEM768_X25519) custody TWO
        // private halves; provision them through the dedicated two-object path
        // (plan §4/§5). The classical X.509 self-sign metadata flow below is
        // RSA/ECC-only (AlgorithmId + Mechanism::{RsaPkcs,Ecdsa}) and cannot sign
        // with a PQC key, so composite keys skip it — the bridge resolves a
        // composite keypair by CKA_KEY_TYPE in `keypair()`, not via an X.509
        // cert. (Composite X.509 metadata encoding is future work; see report.)
        if matches!(
            key.pk_algo(),
            PublicKeyAlgorithm::MLDSA65_Ed25519
                | PublicKeyAlgorithm::MLDSA87_Ed448
                | PublicKeyAlgorithm::MLKEM768_X25519
                | PublicKeyAlgorithm::MLKEM1024_X448
        ) {
            let (_trad, _pqc) = self.upload_composite_private(id, key)?;
            return Ok(());
        }

        let priv_key = self.upload_private(id, key)?;

        let pub_key_info = Self::upload_gen_pki(key)?;
        self.upload_pki(&pub_key_info)?;

        // Generate x.509 certificate
        let tbs_cert = crate::x509::generate_x509(&pub_key_info, key, common_name, &[]);

        // Self-sign x.509 certificate
        let cert = self.upload_self_sign_x509(priv_key, tbs_cert, pub_key_info.algorithm())?;

        // Upload x.509 certificate
        let serial = key.fingerprint().as_bytes().to_vec();
        self.upload_cert(cert, common_name, serial, id)?;

        Ok(())
    }

    /// XXX: escape hatch for direct pkcs11 access (will be removed)
    pub fn session(&self) -> &Session {
        &self.session
    }
}

/// PKCS #11 implementation of [`sequoia_openpgp::crypto::Signer`]
/// and [`sequoia_openpgp::crypto::Decryptor`], as well as
/// [`sequoia_openpgp::parse::stream::DecryptionHelper`] and
/// [`sequoia_openpgp::parse::stream::VerificationHelper`].
///
/// # Composite PQC custody (plan §4/§5)
///
/// A composite key — `MLDSA65_Ed25519` (sign) or `MLKEM768_X25519` (encrypt) —
/// is **two** cryptographic objects that live as **two** PKCS#11 private-key
/// handles sharing one `CKA_ID`:
///
/// - `private` holds the *traditional* component (Ed25519 for `MLDSA65_Ed25519`,
///   X25519 for `MLKEM768_X25519`, or the single RSA/ECDSA/ECDH handle for a
///   classical key).
/// - `pqc` holds the *post-quantum* component (ML-DSA-65 / ML-KEM-768), and is
///   `None` for classical keys.
///
/// Producing a composite signature is therefore two `C_Sign` calls (one per
/// handle) over the same message digest, assembled into a single
/// `mpi::Signature::MLDSA65_Ed25519 { eddsa, mldsa }` — see `signer.rs`. A
/// composite decapsulation is an X25519 ECDH op plus an ML-KEM-768 decap,
/// combined per the draft KEM combiner — see `decryptor.rs`.
pub struct Op11KeyPair {
    pub public: Key<PublicParts, UnspecifiedRole>,
    /// Traditional component handle (Ed25519/X25519/RSA/ECDSA/ECDH).
    pub private: ObjectHandle,
    /// Post-quantum component handle (ML-DSA / ML-KEM). `None` for classical
    /// keys; `Some` for composite PQC keys (the second custody handle).
    pub pqc: Option<ObjectHandle>,
    pub session: Arc<Mutex<Session>>,
}

impl Op11KeyPair {
    /// Construct a classical (single-handle) keypair.
    pub fn new(
        public: Key<PublicParts, UnspecifiedRole>,
        private: ObjectHandle,
        session: Arc<Mutex<Session>>,
    ) -> Self {
        Self {
            public,
            private,
            pqc: None,
            session,
        }
    }

    /// Construct a composite (two-handle) PQC keypair: `private` is the
    /// traditional component, `pqc` is the post-quantum component.
    pub fn new_composite(
        public: Key<PublicParts, UnspecifiedRole>,
        private: ObjectHandle,
        pqc: ObjectHandle,
        session: Arc<Mutex<Session>>,
    ) -> Self {
        Self {
            public,
            private,
            pqc: Some(pqc),
            session,
        }
    }
}

/// Live HSM integration tests for the composite PQC custody path.
///
/// These self-skip (print "SKIP" and pass) unless `OP11_MODULE` is set, so
/// `cargo test --workspace` stays green on hosts with no softhsmv3 module. Run
/// them live with, e.g.:
///
/// ```bash
/// SOFTHSM2_CONF=build/smoke-softhsm2.conf \
/// OP11_MODULE=build/src/lib/libsofthsmv3.dylib OP11_LABEL=test OP11_PIN=1234 \
///   cargo test -p openpgp-pkcs11-sequoia --lib live_composite -- --nocapture --test-threads=1
/// ```
#[cfg(test)]
mod live_composite_tests {
    use super::*;
    use sequoia_openpgp::cert::{CertBuilder, CipherSuite};
    use sequoia_openpgp::packet::Packet;
    use sequoia_openpgp::parse::Parse;
    use sequoia_openpgp::policy::StandardPolicy;
    use sequoia_openpgp::types::PublicKeyAlgorithm;
    use sequoia_openpgp::{PacketPile, Profile};

    /// draft-ietf-openpgp-pqc v17 codepoint for MLDSA65_Ed25519.
    const EXPECTED_ALGO_ID: u8 = 30;

    struct Env {
        module: String,
        label: String,
        pin: String,
    }

    fn env() -> Option<Env> {
        let module = std::env::var("OP11_MODULE").ok()?;
        Some(Env {
            module,
            label: std::env::var("OP11_LABEL").unwrap_or_else(|_| "test".into()),
            pin: std::env::var("OP11_PIN").unwrap_or_else(|_| "1234".into()),
        })
    }

    /// Open an RW session on the slot whose token has `label`, logged in as user.
    fn open_session(e: &Env) -> Op11Session {
        let mut op11 = Op11::open(&e.module).expect("Op11::open");
        let pkcs11 = op11.pkcs11();
        let slot = pkcs11
            .get_slots_with_token()
            .expect("get_slots_with_token")
            .into_iter()
            .find(|s| {
                pkcs11
                    .get_token_info(*s)
                    .map(|ti| ti.label().trim() == e.label)
                    .unwrap_or(false)
            })
            .unwrap_or_else(|| panic!("no slot with token label '{}'", e.label));
        let session = pkcs11.open_rw_session(slot).expect("open_rw_session");
        let op11_session = Op11Session { session };
        op11_session.login(&e.pin).expect("login");
        op11_session
    }

    /// Destroy every token object sharing `id` so live tests are idempotent
    /// (composite provisioning writes token-resident objects that otherwise
    /// accumulate across runs and break the "exactly one handle" resolution).
    fn purge_id(s: &Op11Session, id: &[u8]) {
        // Private-key / cert objects key off CKA_ID.
        let mut objs = s
            .session
            .find_objects(&[Attribute::Id(id.to_vec())])
            .expect("find_objects(id)");
        // The composite public-key CKO_DATA object keys off CKA_APPLICATION.
        objs.extend(
            s.session
                .find_objects(&[
                    Attribute::Class(ObjectClass::DATA),
                    Attribute::Application(id.to_vec()),
                ])
                .expect("find_objects(data application)"),
        );
        for h in objs {
            let _ = s.session.destroy_object(h);
        }
    }

    /// One-time, idempotent test-infrastructure step: ensure a token
    /// labeled `OP11_LABEL` (default "test") exists with user PIN
    /// `OP11_PIN` (default "1234"), creating it via `C_InitToken` +
    /// `C_InitPIN` if it doesn't exist yet.
    ///
    /// The Rust `softhsmrustv3` engine (this test file's `OP11_MODULE`)
    /// starts every fresh process with an empty, uninitialized token store
    /// (`state::init_token_store` seeds slot 0 with an *uninitialized*
    /// token only) — nothing else in this file creates the token that
    /// `open_session`'s label lookup requires. Since `cargo test` runs
    /// every `#[test]` in this module inside ONE process, this only needs
    /// to run once per `cargo test` invocation; the `aaa_` prefix makes
    /// `libtest`'s alphabetical-by-name ordering put it first when run
    /// with `--test-threads=1` (see the module-level doc for the exact
    /// invocation), so every other `live_*` test in the same run finds
    /// the token already there. Safe to run every time — it no-ops if a
    /// matching token already exists.
    #[test]
    fn aaa_provision_test_token() {
        let Some(e) = env() else {
            eprintln!("SKIP aaa_provision_test_token: set OP11_MODULE to run against softhsmv3");
            return;
        };

        let op11 = Op11::open(&e.module).expect("Op11::open");
        let pkcs11 = op11.pkcs11();

        let already = pkcs11
            .get_slots_with_token()
            .expect("get_slots_with_token")
            .into_iter()
            .any(|s| {
                pkcs11
                    .get_token_info(s)
                    .map(|ti| ti.label().trim() == e.label)
                    .unwrap_or(false)
            });
        if already {
            eprintln!(
                "aaa_provision_test_token: token '{}' already present, skipping init",
                e.label
            );
            return;
        }

        let slots = pkcs11.get_all_slots().expect("get_all_slots");
        let slot = *slots.first().expect("at least one slot");

        let so_pin = cryptoki::types::AuthPin::new("12345678".to_string().into());
        pkcs11
            .init_token(slot, &so_pin, &e.label)
            .expect("init_token");

        let session = pkcs11.open_rw_session(slot).expect("open_rw_session");
        session
            .login(cryptoki::session::UserType::So, Some(&so_pin))
            .expect("SO login");
        let user_pin = cryptoki::types::AuthPin::new(e.pin.clone().into());
        session.init_pin(&user_pin).expect("init_pin");

        eprintln!(
            "aaa_provision_test_token: initialized token '{}' (SO PIN set, user PIN set)",
            e.label
        );
    }

    /// End-to-end composite gate: generate a MLDSA65_Ed25519 v6 cert in software,
    /// provision its TWO private halves into softhsmv3 via the composite upload
    /// path, resolve the two custody handles, sign a message through the bridge
    /// (two C_Sign calls assembled into a composite MPI), then verify the
    /// signature with a sequoia 2.x verifier and assert it is v6 + algorithm 30.
    #[test]
    fn live_composite_mldsa65_ed25519_upload_sign_verify() {
        let Some(e) = env() else {
            eprintln!("SKIP live_composite_*: set OP11_MODULE to run against softhsmv3");
            return;
        };

        // 1) Software composite cert with a signing subkey + extract that
        //    subkey's secret. PQC suites require the RFC 9580 (v6) profile.
        let policy = &StandardPolicy::new();
        let (cert, _rev) = CertBuilder::new()
            .set_profile(Profile::RFC9580)
            .expect("RFC9580 profile")
            .set_cipher_suite(CipherSuite::MLDSA65_Ed25519)
            .add_userid("composite-live@pqctoday.test")
            .add_signing_subkey()
            .generate()
            .expect("composite cert generation");

        let signing = cert
            .keys()
            .with_policy(policy, None)
            .alive()
            .revoked(false)
            .for_signing()
            .secret()
            .next()
            .expect("signing-capable secret key")
            .key()
            .clone();
        assert_eq!(
            u8::from(signing.pk_algo()),
            EXPECTED_ALGO_ID,
            "test key must be MLDSA65_Ed25519 (algo 30)"
        );
        let public: Key<PublicParts, UnspecifiedRole> = signing.clone().parts_into_public();

        // 2) Provision the TWO private halves into softhsmv3. A single logged-in
        //    session is reused for upload + resolve + sign (PKCS#11 login state
        //    is per-token, so a second login would return CKR_USER_ALREADY_...).
        let id = b"\x05composite-live";
        let sign_session = open_session(&e);
        purge_id(&sign_session, id); // idempotent across reruns
        sign_session
            .upload_composite_private(id, &signing)
            .expect("composite upload");

        // 3) Resolve the two custody handles by CKA_KEY_TYPE (mirrors keypair()).
        let base = vec![
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sign(true),
            Attribute::Id(id.to_vec()),
            Attribute::Class(ObjectClass::PRIVATE_KEY),
        ];
        let find_one = |kt: cryptoki::object::KeyType| -> ObjectHandle {
            let mut tmpl = base.clone();
            tmpl.push(Attribute::KeyType(kt));
            let h = sign_session.session.find_objects(&tmpl).expect("find_objects");
            assert_eq!(h.len(), 1, "expected exactly one {kt:?} handle for id");
            h[0]
        };
        let ed_handle = find_one(cryptoki::object::KeyType::EC_EDWARDS);
        let mldsa_handle = find_one(cryptoki::object::KeyType::ML_DSA);

        // 4) Build the two-handle composite keypair and sign via the bridge.
        let kp = Op11KeyPair::new_composite(
            public,
            ed_handle,
            mldsa_handle,
            Arc::new(Mutex::new(sign_session.session)),
        );
        let msg = b"pqctoday composite live: HSM-backed MLDSA65_Ed25519 sign+verify";
        let mut sig = Vec::new();
        crate::signer::sign_on_card(kp, &mut &msg[..], &mut sig).expect("sign_on_card");

        // 5a) Byte-level wire assertion: parse the signature packet, assert v6 +
        //     algorithm 30 (the on-the-wire proof, strictly the spike's check on
        //     an HSM-produced signature) and that the composite MPI decomposes
        //     into a 64-byte Ed25519 + 3309-byte ML-DSA-65 half (acceptance §8).
        let pile = PacketPile::from_bytes(&sig).expect("re-parse signature");
        let mut found = None;
        for p in pile.descendants() {
            if let Packet::Signature(s) = p {
                found = Some((s.version(), s.pk_algo(), s.mpis().clone()));
            }
        }
        let (version, pk_algo, mpis) = found.expect("a Signature packet");
        assert_eq!(version, 6, "composite signature must be a v6 packet (RFC 9580)");
        assert_eq!(
            u8::from(pk_algo),
            EXPECTED_ALGO_ID,
            "HSM composite signature pk_algo must be 30 (MLDSA65_Ed25519)"
        );
        assert_eq!(pk_algo, PublicKeyAlgorithm::MLDSA65_Ed25519);
        match &mpis {
            sequoia_openpgp::crypto::mpi::Signature::MLDSA65_Ed25519 { eddsa, mldsa } => {
                assert_eq!(eddsa.len(), 64, "Ed25519 half must be 64 bytes");
                assert_eq!(mldsa.len(), 3309, "ML-DSA-65 half must be 3309 bytes");
            }
            other => panic!("expected MLDSA65_Ed25519 composite MPI, got {other:?}"),
        }

        // Wire-byte cross-check (the spike's offset-5 proof, on an HSM signature):
        // de-armor and confirm the v6 packet carries 0x1e (=30) at the spec offset.
        {
            let mut der = sequoia_openpgp::armor::Reader::from_bytes(
                &sig,
                sequoia_openpgp::armor::ReaderMode::Tolerant(None),
            );
            let mut raw = Vec::new();
            std::io::copy(&mut der, &mut raw).expect("de-armor");
            // new-format Signature: [c2][len..][06=version][type][1e=pk-algo]...
            assert_eq!(raw[3], 0x06, "wire version octet must be 0x06 (v6)");
            assert_eq!(raw[5], 0x1e, "wire pk-algo octet must be 0x1e (30)");
        }

        // 5b) Cryptographic interop: a sequoia 2.x verifier validates the
        //     HSM-produced signature against the same cert.
        struct Helper(Cert);
        impl sequoia_openpgp::parse::stream::VerificationHelper for Helper {
            fn get_certs(
                &mut self,
                _ids: &[sequoia_openpgp::KeyHandle],
            ) -> sequoia_openpgp::Result<Vec<Cert>> {
                Ok(vec![self.0.clone()])
            }
            fn check(
                &mut self,
                structure: sequoia_openpgp::parse::stream::MessageStructure,
            ) -> sequoia_openpgp::Result<()> {
                use sequoia_openpgp::parse::stream::{MessageLayer, VerificationError};
                let mut good = 0usize;
                for layer in structure.into_iter() {
                    if let MessageLayer::SignatureGroup { results } = layer {
                        for r in results {
                            match r {
                                Ok(_) => good += 1,
                                Err(VerificationError::MissingKey { .. }) => {}
                                Err(e) => return Err(anyhow::anyhow!("bad signature: {e}")),
                            }
                        }
                    }
                }
                if good >= 1 {
                    Ok(())
                } else {
                    Err(anyhow::anyhow!("no good signatures"))
                }
            }
        }

        let mut verifier =
            sequoia_openpgp::parse::stream::DetachedVerifierBuilder::from_bytes(&sig)
                .expect("DetachedVerifierBuilder")
                .with_policy(policy, None, Helper(cert.clone()))
                .expect("verifier with_policy");
        verifier
            .verify_bytes(msg)
            .expect("sequoia 2.x must verify the HSM-backed composite signature");

        eprintln!(
            "PASS live_composite: HSM MLDSA65_Ed25519 signature is v6 + algo {EXPECTED_ALGO_ID}, \
             verified by sequoia 2.x ({} bytes armored)",
            sig.len()
        );

        purge_id(&open_session(&e), id);
    }

    /// TASK 1 gate — composite public-key reconstruction *purely from the token*.
    ///
    /// This is the strict reload test the prior session's "remaining work" called
    /// out: provision a composite key, then in a SEPARATE freshly-opened session,
    /// reload the keypair via `keypair(id, Sign, cert=None)` — i.e. with NO
    /// out-of-band Cert and NO X.509 certificate object — relying solely on the
    /// token-resident CKO_DATA public-key object (plan task 1, option b). Then
    /// sign through the reloaded keypair and verify the signature against the
    /// original cert. If `key()` could not rebuild the composite public MPI from
    /// token data alone, `keypair()` would fail here.
    #[test]
    fn live_composite_provision_then_reload_from_token_sign_verify() {
        let Some(e) = env() else {
            eprintln!("SKIP live_composite_*: set OP11_MODULE to run against softhsmv3");
            return;
        };

        let policy = &StandardPolicy::new();
        let (cert, _rev) = CertBuilder::new()
            .set_profile(Profile::RFC9580)
            .expect("RFC9580 profile")
            .set_cipher_suite(CipherSuite::MLDSA65_Ed25519)
            .add_userid("composite-reload@pqctoday.test")
            .add_signing_subkey()
            .generate()
            .expect("composite cert generation");

        let signing = cert
            .keys()
            .with_policy(policy, None)
            .alive()
            .revoked(false)
            .for_signing()
            .secret()
            .next()
            .expect("signing-capable secret key")
            .key()
            .clone();
        let expected_fp = signing.fingerprint();

        let id = b"\x05composite-reload";

        // --- Provision in session #1, then DROP it entirely. ---
        {
            let s1 = open_session(&e);
            purge_id(&s1, id);
            s1.upload_composite_private(id, &signing)
                .expect("composite upload (provision)");
            // s1 dropped here: the only state that survives is on the token.
        }

        // --- Reload in a brand-new session #2 from the token ALONE. ---
        // cert = None: no out-of-band metadata. keypair() -> key() must rebuild
        // the composite public key from the token-resident CKO_DATA object.
        let s2 = open_session(&e);
        let public_reloaded = s2
            .key(id, PgpKeyType::Sign, None)
            .expect("reload composite public key from token alone (no cert)");
        assert_eq!(
            u8::from(public_reloaded.pk_algo()),
            EXPECTED_ALGO_ID,
            "reloaded public key must be MLDSA65_Ed25519 (algo 30)"
        );
        assert_eq!(
            public_reloaded.fingerprint(),
            expected_fp,
            "reloaded public key fingerprint must match the provisioned key exactly"
        );

        let kp = s2
            .keypair(id, PgpKeyType::Sign, None)
            .expect("reload composite keypair from token alone (no cert)");

        // Sign through the token-reloaded keypair.
        let msg = b"pqctoday task1: composite reloaded from token, signed in HSM";
        let mut sig = Vec::new();
        crate::signer::sign_on_card(kp, &mut &msg[..], &mut sig).expect("sign_on_card (reloaded)");

        // Wire + component assertions.
        let pile = PacketPile::from_bytes(&sig).expect("re-parse signature");
        let mut found = None;
        for p in pile.descendants() {
            if let Packet::Signature(s) = p {
                found = Some((s.version(), s.pk_algo(), s.mpis().clone()));
            }
        }
        let (version, pk_algo, mpis) = found.expect("a Signature packet");
        assert_eq!(version, 6, "reloaded-key signature must be v6");
        assert_eq!(u8::from(pk_algo), EXPECTED_ALGO_ID);
        match &mpis {
            sequoia_openpgp::crypto::mpi::Signature::MLDSA65_Ed25519 { eddsa, mldsa } => {
                assert_eq!(eddsa.len(), 64);
                assert_eq!(mldsa.len(), 3309);
            }
            other => panic!("expected MLDSA65_Ed25519 composite MPI, got {other:?}"),
        }

        // Cryptographic verification against the original cert.
        struct Helper(Cert);
        impl sequoia_openpgp::parse::stream::VerificationHelper for Helper {
            fn get_certs(
                &mut self,
                _ids: &[sequoia_openpgp::KeyHandle],
            ) -> sequoia_openpgp::Result<Vec<Cert>> {
                Ok(vec![self.0.clone()])
            }
            fn check(
                &mut self,
                structure: sequoia_openpgp::parse::stream::MessageStructure,
            ) -> sequoia_openpgp::Result<()> {
                use sequoia_openpgp::parse::stream::{MessageLayer, VerificationError};
                let mut good = 0usize;
                for layer in structure.into_iter() {
                    if let MessageLayer::SignatureGroup { results } = layer {
                        for r in results {
                            match r {
                                Ok(_) => good += 1,
                                Err(VerificationError::MissingKey { .. }) => {}
                                Err(e) => return Err(anyhow::anyhow!("bad signature: {e}")),
                            }
                        }
                    }
                }
                if good >= 1 {
                    Ok(())
                } else {
                    Err(anyhow::anyhow!("no good signatures"))
                }
            }
        }
        let mut verifier =
            sequoia_openpgp::parse::stream::DetachedVerifierBuilder::from_bytes(&sig)
                .expect("DetachedVerifierBuilder")
                .with_policy(policy, None, Helper(cert.clone()))
                .expect("verifier with_policy");
        verifier
            .verify_bytes(msg)
            .expect("sequoia 2.x must verify the signature from the token-reloaded keypair");

        eprintln!(
            "PASS live_composite reload-from-token: provision -> fresh session -> \
             keypair(cert=None) reload -> sign -> verify OK (fp {expected_fp})"
        );

        // keypair() consumed s2's session; clean up via a fresh session.
        purge_id(&open_session(&e), id);
    }

    /// TASK 2 gate — end-to-end ML-KEM encrypt -> decrypt through the bridge.
    ///
    /// Build a MLKEM768_X25519 v6 encryption key, provision its TWO private
    /// halves (X25519 + ML-KEM-768) into softhsmv3, ENCRYPT a message to the
    /// public cert with sequoia's software encryptor (producer side), then
    /// DECRYPT it through the bridge — which performs C_DeriveKey (X25519 ECDH) +
    /// C_DecapsulateKey (ML-KEM-768) on the token-resident halves, runs the draft
    /// KEM combiner, and AES-256 key-unwraps the ESK (plan task 2 / §4). Asserts
    /// the recovered plaintext is byte-identical to the original.
    ///
    /// The decrypt side reloads the keypair from the token alone (cert=None),
    /// exercising the task-1 composite public-key reload too.
    #[test]
    fn live_composite_mlkem768_x25519_encrypt_decrypt() {
        let Some(e) = env() else {
            eprintln!("SKIP live_composite_*: set OP11_MODULE to run against softhsmv3");
            return;
        };

        let policy = &StandardPolicy::new();

        // 1) Build a composite cert and pull out its MLKEM768_X25519 ENCRYPTION
        //    subkey (the MLDSA65_Ed25519 suite's encryption subkey is ML-KEM).
        let (cert, _rev) = CertBuilder::new()
            .set_profile(Profile::RFC9580)
            .expect("RFC9580 profile")
            .set_cipher_suite(CipherSuite::MLDSA65_Ed25519)
            .add_userid("composite-kem@pqctoday.test")
            .add_transport_encryption_subkey()
            .generate()
            .expect("composite cert with ML-KEM encryption subkey");

        let enc = cert
            .keys()
            .with_policy(policy, None)
            .alive()
            .revoked(false)
            .for_transport_encryption()
            .secret()
            .next()
            .expect("encryption-capable secret subkey")
            .key()
            .clone();
        assert_eq!(
            enc.pk_algo(),
            PublicKeyAlgorithm::MLKEM768_X25519,
            "encryption subkey must be MLKEM768_X25519 (algo 35)"
        );
        assert_eq!(u8::from(enc.pk_algo()), 35);

        // 2) Provision the TWO private halves (and the public DATA object).
        let id = b"\x05composite-kem";
        {
            let s1 = open_session(&e);
            purge_id(&s1, id);
            s1.upload_composite_private(id, &enc)
                .expect("composite ML-KEM upload");
        }

        // 3) Producer side: software-encrypt a message to the public cert.
        let plaintext = b"pqctoday task2: ML-KEM-768 + X25519 hybrid decrypt, HSM-backed.";
        let recipients = cert
            .keys()
            .with_policy(policy, None)
            .alive()
            .revoked(false)
            .for_transport_encryption()
            .map(|ka| {
                // Anonymous recipient (None handle), default features (None).
                sequoia_openpgp::serialize::stream::Recipient::new(None, None, ka.key())
            })
            .collect::<Vec<_>>();
        assert_eq!(recipients.len(), 1, "exactly one ML-KEM recipient expected");

        let mut ciphertext = Vec::new();
        {
            use sequoia_openpgp::serialize::stream::{Armorer, Encryptor, LiteralWriter, Message};
            let message = Message::new(&mut ciphertext);
            let message = Armorer::new(message).build().expect("armorer");
            let message = Encryptor::for_recipients(message, recipients)
                .build()
                .expect("encryptor build");
            let mut w = LiteralWriter::new(message).build().expect("literal writer");
            std::io::copy(&mut &plaintext[..], &mut w).expect("write plaintext");
            w.finalize().expect("finalize encryption");
        }
        eprintln!(
            "    software-encrypted {} B plaintext -> {} B armored ML-KEM message",
            plaintext.len(),
            ciphertext.len()
        );

        // 4) Consumer side: decrypt THROUGH THE BRIDGE using the token-resident
        //    halves. cert=None -> the bridge reloads the composite public key
        //    from the token (task 1) and resolves both custody handles.
        let s2 = open_session(&e);
        let mut recovered = Vec::new();
        s2.decrypt(id, &mut &ciphertext[..], &mut recovered, None)
            .expect("bridge ML-KEM decrypt (C_DecapsulateKey + combiner + AES-KW)");

        assert_eq!(
            recovered.as_slice(),
            &plaintext[..],
            "recovered plaintext must match the original byte-for-byte"
        );

        eprintln!(
            "PASS live_composite ML-KEM e2e: software-encrypt -> HSM decrypt \
             (X25519 ECDH + ML-KEM-768 decap + combiner + AES-256 KW) -> plaintext MATCH"
        );

        purge_id(&open_session(&e), id);
    }

    /// TASK 3 gate — generate-in-HSM custody: keys never leave the HSM.
    ///
    /// Generate a composite MLDSA65_Ed25519 key's two halves DIRECTLY inside the
    /// HSM via C_GenerateKeyPair (non-extractable: CKA_SENSITIVE=true,
    /// CKA_EXTRACTABLE=false), reload the keypair purely from the token, sign,
    /// and verify the signature against the in-HSM-generated public key (no
    /// secret key ever existed in software). Then CONFIRM both private halves are
    /// non-extractable: CKA_VALUE is refused by the HSM, and the sensitive /
    /// non-extractable flags are set.
    #[test]
    fn live_composite_generate_in_hsm_sign_verify_nonextractable() {
        let Some(e) = env() else {
            eprintln!("SKIP live_composite_*: set OP11_MODULE to run against softhsmv3");
            return;
        };

        let id = b"\x05composite-genhsm";

        // 1) GENERATE both halves in-HSM (default custody). No software secret.
        let s1 = open_session(&e);
        purge_id(&s1, id);
        let generated_public = s1
            .generate_composite_in_hsm(id, CompositeAlgo::MlDsa65Ed25519)
            .expect("generate composite in HSM");
        assert_eq!(
            u8::from(generated_public.pk_algo()),
            EXPECTED_ALGO_ID,
            "generated key must be MLDSA65_Ed25519 (algo 30)"
        );
        let expected_fp = generated_public.fingerprint();
        drop(s1);

        // 2) Reload from the token alone and sign.
        let s2 = open_session(&e);
        let public_reloaded = s2
            .key(id, PgpKeyType::Sign, None)
            .expect("reload generated public key from token");
        assert_eq!(
            public_reloaded.fingerprint(),
            expected_fp,
            "reloaded fingerprint must match the generated key"
        );
        let kp = s2
            .keypair(id, PgpKeyType::Sign, None)
            .expect("reload generated keypair from token");
        let msg = b"pqctoday task3: composite key generated in-HSM, signed in-HSM";
        let mut sig = Vec::new();
        crate::signer::sign_on_card(kp, &mut &msg[..], &mut sig).expect("sign_on_card (generated)");

        // 3) Verify the HSM signature against the in-HSM-generated public key
        //    (no Cert: Signature::verify_message verifies a detached signature
        //    directly with the public key).
        let pile = PacketPile::from_bytes(&sig).expect("re-parse signature");
        let mut sig_packet = None;
        for p in pile.descendants() {
            if let Packet::Signature(s) = p {
                sig_packet = Some(s.clone());
            }
        }
        let sig_packet = sig_packet.expect("a Signature packet");
        assert_eq!(sig_packet.version(), 6, "must be v6");
        assert_eq!(u8::from(sig_packet.pk_algo()), EXPECTED_ALGO_ID);
        match sig_packet.mpis() {
            sequoia_openpgp::crypto::mpi::Signature::MLDSA65_Ed25519 { eddsa, mldsa } => {
                assert_eq!(eddsa.len(), 64);
                assert_eq!(mldsa.len(), 3309);
            }
            other => panic!("expected MLDSA65_Ed25519 composite MPI, got {other:?}"),
        }
        sig_packet
            .verify_message(&public_reloaded, msg)
            .expect("HSM-generated composite signature must verify against the generated public key");

        // 4) CONFIRM non-extractability of BOTH private halves (keypair()
        //    consumed s2's session, so use a fresh session).
        let s3 = open_session(&e);
        let base = vec![
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Id(id.to_vec()),
            Attribute::Class(ObjectClass::PRIVATE_KEY),
        ];
        let find_one = |kt: cryptoki::object::KeyType| -> ObjectHandle {
            let mut t = base.clone();
            t.push(Attribute::KeyType(kt));
            let h = s3.session.find_objects(&t).expect("find_objects");
            assert_eq!(h.len(), 1, "expected exactly one {kt:?} private handle");
            h[0]
        };
        for (name, kt) in [
            ("Ed25519", cryptoki::object::KeyType::EC_EDWARDS),
            ("ML-DSA-65", cryptoki::object::KeyType::ML_DSA),
        ] {
            let h = find_one(kt);
            // CKA_VALUE must NOT be releasable.
            let value_released = s3
                .session
                .get_attributes(h, &[cryptoki::object::AttributeType::Value])
                .map(|attrs| {
                    attrs.iter().any(|a| {
                        matches!(a, Attribute::Value(v) if !v.is_empty())
                    })
                })
                .unwrap_or(false);
            assert!(
                !value_released,
                "{name} private CKA_VALUE was released — key IS extractable (must not be)"
            );
            // And the flags must say so.
            let mut sensitive = None;
            let mut extractable = None;
            for a in s3
                .session
                .get_attributes(
                    h,
                    &[
                        cryptoki::object::AttributeType::Sensitive,
                        cryptoki::object::AttributeType::Extractable,
                    ],
                )
                .expect("get sensitive/extractable")
            {
                match a {
                    Attribute::Sensitive(x) => sensitive = Some(x),
                    Attribute::Extractable(x) => extractable = Some(x),
                    _ => {}
                }
            }
            assert_eq!(sensitive, Some(true), "{name} CKA_SENSITIVE must be true");
            assert_eq!(extractable, Some(false), "{name} CKA_EXTRACTABLE must be false");
            eprintln!("    {name}: CKA_VALUE refused, SENSITIVE=true, EXTRACTABLE=false");
        }

        eprintln!(
            "PASS live_composite generate-in-HSM: in-HSM C_GenerateKeyPair -> reload -> \
             sign -> verify OK; both private halves NON-EXTRACTABLE (fp {expected_fp})"
        );

        let _ = s3; // (s3 dropped here)
        purge_id(&open_session(&e), id);
    }

    /// TASK 3 (ML-KEM half) — generate the MLKEM768_X25519 key in-HSM, then run
    /// the full encrypt->decrypt round-trip against it. Covers the X25519 +
    /// ML-KEM-768 generate-in-HSM path and confirms its private halves are
    /// non-extractable. The producer encrypts to the in-HSM-generated public key
    /// (read back from the token); the consumer decrypts through the bridge.
    #[test]
    fn live_composite_generate_in_hsm_mlkem_encrypt_decrypt_nonextractable() {
        let Some(e) = env() else {
            eprintln!("SKIP live_composite_*: set OP11_MODULE to run against softhsmv3");
            return;
        };

        let policy = &StandardPolicy::new();
        let id = b"\x05composite-genkem";

        // 1) GENERATE the ML-KEM composite in-HSM; get its public key.
        let s1 = open_session(&e);
        purge_id(&s1, id);
        let generated_public = s1
            .generate_composite_in_hsm(id, CompositeAlgo::MlKem768X25519)
            .expect("generate ML-KEM composite in HSM");
        assert_eq!(
            generated_public.pk_algo(),
            PublicKeyAlgorithm::MLKEM768_X25519,
            "generated key must be MLKEM768_X25519"
        );

        // Confirm non-extractability of both private halves.
        for (name, kt) in [
            ("X25519", cryptoki::object::KeyType::EC_MONTGOMERY),
            ("ML-KEM-768", cryptoki::object::KeyType::ML_KEM),
        ] {
            let h = s1
                .session
                .find_objects(&[
                    Attribute::Token(true),
                    Attribute::Private(true),
                    Attribute::Id(id.to_vec()),
                    Attribute::Class(ObjectClass::PRIVATE_KEY),
                    Attribute::KeyType(kt),
                ])
                .expect("find_objects")[0];
            let released = s1
                .session
                .get_attributes(h, &[cryptoki::object::AttributeType::Value])
                .map(|a| a.iter().any(|x| matches!(x, Attribute::Value(v) if !v.is_empty())))
                .unwrap_or(false);
            assert!(!released, "{name} private CKA_VALUE released (must be non-extractable)");
        }

        // 2) Producer: software-encrypt to the in-HSM-generated public key. Wrap
        //    it as a transient single-subkey Cert via a minimal recipient.
        let plaintext = b"pqctoday task3 ML-KEM: encrypt to an in-HSM-generated key.";
        let mut ciphertext = Vec::new();
        {
            use sequoia_openpgp::serialize::stream::{
                Armorer, Encryptor, LiteralWriter, Message, Recipient,
            };
            let recipient = Recipient::new(None, None, &generated_public);
            let message = Message::new(&mut ciphertext);
            let message = Armorer::new(message).build().expect("armorer");
            let message = Encryptor::for_recipients(message, vec![recipient])
                .build()
                .expect("encryptor");
            let mut w = LiteralWriter::new(message).build().expect("literal writer");
            std::io::copy(&mut &plaintext[..], &mut w).expect("write");
            w.finalize().expect("finalize");
        }
        drop(s1);

        // 3) Consumer: decrypt through the bridge (cert=None -> token reload).
        let s2 = open_session(&e);
        let mut recovered = Vec::new();
        s2.decrypt(id, &mut &ciphertext[..], &mut recovered, None)
            .expect("bridge decrypt of message to in-HSM-generated ML-KEM key");
        assert_eq!(recovered.as_slice(), &plaintext[..], "plaintext must match");

        let _ = policy;
        eprintln!(
            "PASS live_composite generate-in-HSM ML-KEM: in-HSM C_GenerateKeyPair -> \
             encrypt -> HSM decrypt -> plaintext MATCH; private halves NON-EXTRACTABLE"
        );

        purge_id(&open_session(&e), id);
    }

    // =====================================================================
    // Remediation plan §2/Fix 1+2 (2026-08-31): MLDSA87_Ed448 (algo 31) and
    // MLKEM1024_X448 (algo 36). Same shapes as the MLDSA65_Ed25519 /
    // MLKEM768_X25519 tests above, sized up.
    // =====================================================================

    /// draft-ietf-openpgp-pqc v17 codepoint for MLDSA87_Ed448.
    const EXPECTED_ALGO_ID_MLDSA87_ED448: u8 = 31;

    /// Fix 1 gate — mirrors `live_composite_mldsa65_ed25519_upload_sign_verify`
    /// for MLDSA87_Ed448: software composite cert -> upload TWO private halves
    /// (Ed448 + ML-DSA-87) -> resolve custody handles -> sign through the
    /// bridge (two C_Sign calls) -> verify with a sequoia 2.x verifier.
    /// Before this fix, `CompositeAlgo` had no `MlDsa87Ed448` variant and
    /// `upload_composite_private` had no match arm for it, so this key could
    /// never be provisioned even though `signer.rs`'s sign dispatch already
    /// existed.
    #[test]
    fn live_composite_mldsa87_ed448_upload_sign_verify() {
        let Some(e) = env() else {
            eprintln!("SKIP live_composite_*: set OP11_MODULE to run against softhsmv3");
            return;
        };

        let policy = &StandardPolicy::new();
        let (cert, _rev) = CertBuilder::new()
            .set_profile(Profile::RFC9580)
            .expect("RFC9580 profile")
            .set_cipher_suite(CipherSuite::MLDSA87_Ed448)
            .add_userid("composite-live-87@pqctoday.test")
            .add_signing_subkey()
            .generate()
            .expect("composite cert generation (MLDSA87_Ed448)");

        let signing = cert
            .keys()
            .with_policy(policy, None)
            .alive()
            .revoked(false)
            .for_signing()
            .secret()
            .next()
            .expect("signing-capable secret key")
            .key()
            .clone();
        assert_eq!(
            u8::from(signing.pk_algo()),
            EXPECTED_ALGO_ID_MLDSA87_ED448,
            "test key must be MLDSA87_Ed448 (algo 31)"
        );
        let public: Key<PublicParts, UnspecifiedRole> = signing.clone().parts_into_public();

        let id = b"\x05composite-live-87";
        let sign_session = open_session(&e);
        purge_id(&sign_session, id); // idempotent across reruns
        sign_session
            .upload_composite_private(id, &signing)
            .expect("composite upload (MLDSA87_Ed448)");

        let base = vec![
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sign(true),
            Attribute::Id(id.to_vec()),
            Attribute::Class(ObjectClass::PRIVATE_KEY),
        ];
        let find_one = |kt: cryptoki::object::KeyType| -> ObjectHandle {
            let mut tmpl = base.clone();
            tmpl.push(Attribute::KeyType(kt));
            let h = sign_session.session.find_objects(&tmpl).expect("find_objects");
            assert_eq!(h.len(), 1, "expected exactly one {kt:?} handle for id");
            h[0]
        };
        let ed_handle = find_one(cryptoki::object::KeyType::EC_EDWARDS);
        let mldsa_handle = find_one(cryptoki::object::KeyType::ML_DSA);

        let kp = Op11KeyPair::new_composite(
            public,
            ed_handle,
            mldsa_handle,
            Arc::new(Mutex::new(sign_session.session)),
        );
        let msg = b"pqctoday composite live: HSM-backed MLDSA87_Ed448 sign+verify";
        let mut sig = Vec::new();
        crate::signer::sign_on_card(kp, &mut &msg[..], &mut sig).expect("sign_on_card");

        // Byte-level wire assertion: v6 + algorithm 31, and the composite MPI
        // decomposes into a 114-byte Ed448 + 4627-byte ML-DSA-87 half.
        let pile = PacketPile::from_bytes(&sig).expect("re-parse signature");
        let mut found = None;
        for p in pile.descendants() {
            if let Packet::Signature(s) = p {
                found = Some((s.version(), s.pk_algo(), s.mpis().clone()));
            }
        }
        let (version, pk_algo, mpis) = found.expect("a Signature packet");
        assert_eq!(version, 6, "composite signature must be a v6 packet (RFC 9580)");
        assert_eq!(
            u8::from(pk_algo),
            EXPECTED_ALGO_ID_MLDSA87_ED448,
            "HSM composite signature pk_algo must be 31 (MLDSA87_Ed448)"
        );
        assert_eq!(pk_algo, PublicKeyAlgorithm::MLDSA87_Ed448);
        match &mpis {
            sequoia_openpgp::crypto::mpi::Signature::MLDSA87_Ed448 { eddsa, mldsa } => {
                assert_eq!(eddsa.len(), 114, "Ed448 half must be 114 bytes");
                assert_eq!(mldsa.len(), 4627, "ML-DSA-87 half must be 4627 bytes");
            }
            other => panic!("expected MLDSA87_Ed448 composite MPI, got {other:?}"),
        }

        // Wire-byte cross-check: de-armor and confirm the v6 packet carries
        // 0x1f (=31) at the spec offset.
        {
            let mut der = sequoia_openpgp::armor::Reader::from_bytes(
                &sig,
                sequoia_openpgp::armor::ReaderMode::Tolerant(None),
            );
            let mut raw = Vec::new();
            std::io::copy(&mut der, &mut raw).expect("de-armor");
            assert_eq!(raw[3], 0x06, "wire version octet must be 0x06 (v6)");
            assert_eq!(raw[5], 0x1f, "wire pk-algo octet must be 0x1f (31)");
        }

        // Cryptographic interop: a sequoia 2.x verifier validates the
        // HSM-produced signature against the same cert.
        struct Helper(Cert);
        impl sequoia_openpgp::parse::stream::VerificationHelper for Helper {
            fn get_certs(
                &mut self,
                _ids: &[sequoia_openpgp::KeyHandle],
            ) -> sequoia_openpgp::Result<Vec<Cert>> {
                Ok(vec![self.0.clone()])
            }
            fn check(
                &mut self,
                structure: sequoia_openpgp::parse::stream::MessageStructure,
            ) -> sequoia_openpgp::Result<()> {
                use sequoia_openpgp::parse::stream::{MessageLayer, VerificationError};
                let mut good = 0usize;
                for layer in structure.into_iter() {
                    if let MessageLayer::SignatureGroup { results } = layer {
                        for r in results {
                            match r {
                                Ok(_) => good += 1,
                                Err(VerificationError::MissingKey { .. }) => {}
                                Err(e) => return Err(anyhow::anyhow!("bad signature: {e}")),
                            }
                        }
                    }
                }
                if good >= 1 {
                    Ok(())
                } else {
                    Err(anyhow::anyhow!("no good signatures"))
                }
            }
        }

        let mut verifier =
            sequoia_openpgp::parse::stream::DetachedVerifierBuilder::from_bytes(&sig)
                .expect("DetachedVerifierBuilder")
                .with_policy(policy, None, Helper(cert.clone()))
                .expect("verifier with_policy");
        verifier
            .verify_bytes(msg)
            .expect("sequoia 2.x must verify the HSM-backed composite signature");

        eprintln!(
            "PASS live_composite: HSM MLDSA87_Ed448 signature is v6 + algo {EXPECTED_ALGO_ID_MLDSA87_ED448}, \
             verified by sequoia 2.x ({} bytes armored)",
            sig.len()
        );

        purge_id(&open_session(&e), id);
    }

    /// Fix 2 gate — mirrors `live_composite_mlkem768_x25519_encrypt_decrypt`
    /// for MLKEM1024_X448: build a composite cert, pull its MLKEM1024_X448
    /// encryption subkey, provision its TWO private halves, software-encrypt
    /// to the public cert, then DECRYPT through the bridge (which, before
    /// this fix, had no `decrypt()` match arm at all for this ciphertext type
    /// and fell straight to the "Unexpected Ciphertext type." catch-all).
    /// Also exercises the new `x448_shared_point` helper (56-byte X448 ECDH
    /// shared secret vs X25519's 32) and confirms the KEM combiner
    /// generalizes to the larger sizes.
    #[test]
    fn live_composite_mlkem1024_x448_encrypt_decrypt() {
        let Some(e) = env() else {
            eprintln!("SKIP live_composite_*: set OP11_MODULE to run against softhsmv3");
            return;
        };

        let policy = &StandardPolicy::new();

        let (cert, _rev) = CertBuilder::new()
            .set_profile(Profile::RFC9580)
            .expect("RFC9580 profile")
            .set_cipher_suite(CipherSuite::MLDSA87_Ed448)
            .add_userid("composite-kem-1024@pqctoday.test")
            .add_transport_encryption_subkey()
            .generate()
            .expect("composite cert with ML-KEM-1024 encryption subkey");

        let enc = cert
            .keys()
            .with_policy(policy, None)
            .alive()
            .revoked(false)
            .for_transport_encryption()
            .secret()
            .next()
            .expect("encryption-capable secret subkey")
            .key()
            .clone();
        assert_eq!(
            enc.pk_algo(),
            PublicKeyAlgorithm::MLKEM1024_X448,
            "encryption subkey must be MLKEM1024_X448 (algo 36)"
        );
        assert_eq!(u8::from(enc.pk_algo()), 36);

        let id = b"\x05composite-kem-1024";
        {
            let s1 = open_session(&e);
            purge_id(&s1, id);
            s1.upload_composite_private(id, &enc)
                .expect("composite ML-KEM-1024 upload");
        }

        let plaintext = b"pqctoday fix2: ML-KEM-1024 + X448 hybrid decrypt, HSM-backed.";
        let recipients = cert
            .keys()
            .with_policy(policy, None)
            .alive()
            .revoked(false)
            .for_transport_encryption()
            .map(|ka| sequoia_openpgp::serialize::stream::Recipient::new(None, None, ka.key()))
            .collect::<Vec<_>>();
        assert_eq!(recipients.len(), 1, "exactly one ML-KEM-1024 recipient expected");

        let mut ciphertext = Vec::new();
        {
            use sequoia_openpgp::serialize::stream::{Armorer, Encryptor, LiteralWriter, Message};
            let message = Message::new(&mut ciphertext);
            let message = Armorer::new(message).build().expect("armorer");
            let message = Encryptor::for_recipients(message, recipients)
                .build()
                .expect("encryptor build");
            let mut w = LiteralWriter::new(message).build().expect("literal writer");
            std::io::copy(&mut &plaintext[..], &mut w).expect("write plaintext");
            w.finalize().expect("finalize encryption");
        }
        eprintln!(
            "    software-encrypted {} B plaintext -> {} B armored ML-KEM-1024 message",
            plaintext.len(),
            ciphertext.len()
        );

        let s2 = open_session(&e);
        let mut recovered = Vec::new();
        s2.decrypt(id, &mut &ciphertext[..], &mut recovered, None)
            .expect("bridge ML-KEM-1024 decrypt (C_DecapsulateKey + combiner + AES-KW)");

        assert_eq!(
            recovered.as_slice(),
            &plaintext[..],
            "recovered plaintext must match the original byte-for-byte"
        );

        eprintln!(
            "PASS live_composite ML-KEM-1024 e2e: software-encrypt -> HSM decrypt \
             (X448 ECDH + ML-KEM-1024 decap + combiner + AES-256 KW) -> plaintext MATCH"
        );

        // Regression check (plan §2 verification): confirm decrypt()'s
        // catch-all is unchanged for a ciphertext type this bridge has never
        // supported (ElGamal — a real sequoia `mpi::Ciphertext` variant, but
        // not one our decrypt() match handles). This is the arm that sits
        // immediately after the new MLKEM1024_X448 arm added by this fix, so
        // it is the most at-risk spot for an accidental fallthrough
        // regression. (There is no standalone, non-composite ML-DSA/ML-KEM
        // OpenPGP algorithm ID to construct a ciphertext for — the spec only
        // defines the composite forms, confirmed by reading sequoia's
        // `mpi::Ciphertext`/`mpi::PublicKey` enums, which have no such
        // variant at all.)
        {
            let s3 = open_session(&e);
            let mut kp = s3
                .keypair(id, PgpKeyType::Encrypt, None)
                .expect("resolve composite keypair for negative-path check");
            let bogus = sequoia_openpgp::crypto::mpi::Ciphertext::ElGamal {
                e: sequoia_openpgp::crypto::mpi::MPI::new(&[1, 2, 3]),
                c: sequoia_openpgp::crypto::mpi::MPI::new(&[4, 5, 6]),
            };
            let err =
                <Op11KeyPair as sequoia_openpgp::crypto::Decryptor>::decrypt(&mut kp, &bogus, None)
                    .expect_err("an ElGamal ciphertext must still be rejected");
            assert!(
                err.to_string().contains("Unexpected Ciphertext type"),
                "unexpected error for unsupported ciphertext type: {err}"
            );
            eprintln!("    PASS regression: unsupported (ElGamal) ciphertext still rejected by the catch-all");
        }

        purge_id(&open_session(&e), id);
    }

    /// TASK 3 gate for MLDSA87_Ed448 — generate-in-HSM custody. Mirrors
    /// `live_composite_generate_in_hsm_sign_verify_nonextractable`.
    #[test]
    fn live_composite_generate_in_hsm_mldsa87ed448_sign_verify_nonextractable() {
        let Some(e) = env() else {
            eprintln!("SKIP live_composite_*: set OP11_MODULE to run against softhsmv3");
            return;
        };

        let id = b"\x05composite-genhsm-87";

        let s1 = open_session(&e);
        purge_id(&s1, id);
        let generated_public = s1
            .generate_composite_in_hsm(id, CompositeAlgo::MlDsa87Ed448)
            .expect("generate composite in HSM (MLDSA87_Ed448)");
        assert_eq!(
            u8::from(generated_public.pk_algo()),
            EXPECTED_ALGO_ID_MLDSA87_ED448,
            "generated key must be MLDSA87_Ed448 (algo 31)"
        );
        let expected_fp = generated_public.fingerprint();
        drop(s1);

        let s2 = open_session(&e);
        let public_reloaded = s2
            .key(id, PgpKeyType::Sign, None)
            .expect("reload generated public key from token");
        assert_eq!(
            public_reloaded.fingerprint(),
            expected_fp,
            "reloaded fingerprint must match the generated key"
        );
        let kp = s2
            .keypair(id, PgpKeyType::Sign, None)
            .expect("reload generated keypair from token");
        let msg = b"pqctoday fix1: composite MLDSA87_Ed448 generated in-HSM, signed in-HSM";
        let mut sig = Vec::new();
        crate::signer::sign_on_card(kp, &mut &msg[..], &mut sig).expect("sign_on_card (generated)");

        let pile = PacketPile::from_bytes(&sig).expect("re-parse signature");
        let mut sig_packet = None;
        for p in pile.descendants() {
            if let Packet::Signature(s) = p {
                sig_packet = Some(s.clone());
            }
        }
        let sig_packet = sig_packet.expect("a Signature packet");
        assert_eq!(sig_packet.version(), 6, "must be v6");
        assert_eq!(u8::from(sig_packet.pk_algo()), EXPECTED_ALGO_ID_MLDSA87_ED448);
        match sig_packet.mpis() {
            sequoia_openpgp::crypto::mpi::Signature::MLDSA87_Ed448 { eddsa, mldsa } => {
                assert_eq!(eddsa.len(), 114);
                assert_eq!(mldsa.len(), 4627);
            }
            other => panic!("expected MLDSA87_Ed448 composite MPI, got {other:?}"),
        }
        sig_packet
            .verify_message(&public_reloaded, msg)
            .expect("HSM-generated composite signature must verify against the generated public key");

        let s3 = open_session(&e);
        let base = vec![
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Id(id.to_vec()),
            Attribute::Class(ObjectClass::PRIVATE_KEY),
        ];
        let find_one = |kt: cryptoki::object::KeyType| -> ObjectHandle {
            let mut t = base.clone();
            t.push(Attribute::KeyType(kt));
            let h = s3.session.find_objects(&t).expect("find_objects");
            assert_eq!(h.len(), 1, "expected exactly one {kt:?} private handle");
            h[0]
        };
        for (name, kt) in [
            ("Ed448", cryptoki::object::KeyType::EC_EDWARDS),
            ("ML-DSA-87", cryptoki::object::KeyType::ML_DSA),
        ] {
            let h = find_one(kt);
            let value_released = s3
                .session
                .get_attributes(h, &[cryptoki::object::AttributeType::Value])
                .map(|attrs| attrs.iter().any(|a| matches!(a, Attribute::Value(v) if !v.is_empty())))
                .unwrap_or(false);
            assert!(
                !value_released,
                "{name} private CKA_VALUE was released — key IS extractable (must not be)"
            );
            let mut sensitive = None;
            let mut extractable = None;
            for a in s3
                .session
                .get_attributes(
                    h,
                    &[
                        cryptoki::object::AttributeType::Sensitive,
                        cryptoki::object::AttributeType::Extractable,
                    ],
                )
                .expect("get sensitive/extractable")
            {
                match a {
                    Attribute::Sensitive(x) => sensitive = Some(x),
                    Attribute::Extractable(x) => extractable = Some(x),
                    _ => {}
                }
            }
            assert_eq!(sensitive, Some(true), "{name} CKA_SENSITIVE must be true");
            assert_eq!(extractable, Some(false), "{name} CKA_EXTRACTABLE must be false");
            eprintln!("    {name}: CKA_VALUE refused, SENSITIVE=true, EXTRACTABLE=false");
        }

        eprintln!(
            "PASS live_composite generate-in-HSM MLDSA87_Ed448: in-HSM C_GenerateKeyPair -> reload -> \
             sign -> verify OK; both private halves NON-EXTRACTABLE (fp {expected_fp})"
        );

        let _ = s3;
        purge_id(&open_session(&e), id);
    }

    /// TASK 3 gate for MLKEM1024_X448 — generate-in-HSM + full encrypt/decrypt
    /// round trip. Mirrors
    /// `live_composite_generate_in_hsm_mlkem_encrypt_decrypt_nonextractable`.
    #[test]
    fn live_composite_generate_in_hsm_mlkem1024x448_encrypt_decrypt_nonextractable() {
        let Some(e) = env() else {
            eprintln!("SKIP live_composite_*: set OP11_MODULE to run against softhsmv3");
            return;
        };

        let id = b"\x05composite-genkem-1024";

        let s1 = open_session(&e);
        purge_id(&s1, id);
        let generated_public = s1
            .generate_composite_in_hsm(id, CompositeAlgo::MlKem1024X448)
            .expect("generate ML-KEM-1024 composite in HSM");
        assert_eq!(
            generated_public.pk_algo(),
            PublicKeyAlgorithm::MLKEM1024_X448,
            "generated key must be MLKEM1024_X448"
        );

        for (name, kt) in [
            ("X448", cryptoki::object::KeyType::EC_MONTGOMERY),
            ("ML-KEM-1024", cryptoki::object::KeyType::ML_KEM),
        ] {
            let h = s1
                .session
                .find_objects(&[
                    Attribute::Token(true),
                    Attribute::Private(true),
                    Attribute::Id(id.to_vec()),
                    Attribute::Class(ObjectClass::PRIVATE_KEY),
                    Attribute::KeyType(kt),
                ])
                .expect("find_objects")[0];
            let released = s1
                .session
                .get_attributes(h, &[cryptoki::object::AttributeType::Value])
                .map(|a| a.iter().any(|x| matches!(x, Attribute::Value(v) if !v.is_empty())))
                .unwrap_or(false);
            assert!(!released, "{name} private CKA_VALUE released (must be non-extractable)");
        }

        let plaintext = b"pqctoday fix2 ML-KEM-1024: encrypt to an in-HSM-generated key.";
        let mut ciphertext = Vec::new();
        {
            use sequoia_openpgp::serialize::stream::{
                Armorer, Encryptor, LiteralWriter, Message, Recipient,
            };
            let recipient = Recipient::new(None, None, &generated_public);
            let message = Message::new(&mut ciphertext);
            let message = Armorer::new(message).build().expect("armorer");
            let message = Encryptor::for_recipients(message, vec![recipient])
                .build()
                .expect("encryptor");
            let mut w = LiteralWriter::new(message).build().expect("literal writer");
            std::io::copy(&mut &plaintext[..], &mut w).expect("write");
            w.finalize().expect("finalize");
        }
        drop(s1);

        let s2 = open_session(&e);
        let mut recovered = Vec::new();
        s2.decrypt(id, &mut &ciphertext[..], &mut recovered, None)
            .expect("bridge decrypt of message to in-HSM-generated ML-KEM-1024 key");
        assert_eq!(recovered.as_slice(), &plaintext[..], "plaintext must match");

        eprintln!(
            "PASS live_composite generate-in-HSM ML-KEM-1024: in-HSM C_GenerateKeyPair -> \
             encrypt -> HSM decrypt -> plaintext MATCH; private halves NON-EXTRACTABLE"
        );

        purge_id(&open_session(&e), id);
    }

    // =====================================================================
    // Standalone (non-composite) Ed448 — RFC 9580 native v6 format,
    // algorithm ID 28 (`PublicKeyAlgorithm::Ed448`), distinct from the
    // composite `MLDSA87_Ed448` (algorithm 31) exercised above. Confirms
    // the wiring added to `signer.rs`'s new `Ed448` match arm and
    // `upload.rs`'s new `generate_ed448_in_hsm`. Before this fix, this
    // algorithm was cleanly rejected by `signer.rs`'s `other => Err(...)`
    // catch-all — there was no way to provision or sign with it at all.
    // =====================================================================

    /// draft/RFC 9580 codepoint for standalone Ed448.
    const EXPECTED_ALGO_ID_ED448_STANDALONE: u8 = 28;

    /// Standalone Ed448 gate — generate a single (non-composite) Ed448 key
    /// DIRECTLY inside the HSM via `C_GenerateKeyPair` (non-extractable:
    /// `CKA_SENSITIVE=true`, `CKA_EXTRACTABLE=false`, mirroring the
    /// composite generate-in-HSM discipline), reload the keypair purely
    /// from the token (no Cert, no X.509 — same token-resident `CKO_DATA`
    /// path the composites use), sign through the bridge (a single
    /// `C_Sign` call via `CKM_EDDSA`, RFC 8032 §5.2 empty-context Ed448),
    /// and verify the resulting v6 signature packet (algorithm 28) with
    /// `sequoia_openpgp`'s own `Signature::verify_message` — not a
    /// hand-rolled check. Then confirms the private key is
    /// non-extractable, and finally runs a tamper-rejection control:
    /// corrupt the signature bytes on the wire and confirm sequoia
    /// rejects the corrupted signature.
    #[test]
    fn live_ed448_standalone_generate_in_hsm_sign_verify_nonextractable() {
        let Some(e) = env() else {
            eprintln!("SKIP live_ed448_standalone_*: set OP11_MODULE to run against softhsmv3");
            return;
        };

        let id = b"\x05ed448-standalone-genhsm";

        // 1) GENERATE a standalone Ed448 key in-HSM. No software secret.
        let s1 = open_session(&e);
        purge_id(&s1, id);
        let generated_public = s1
            .generate_ed448_in_hsm(id)
            .expect("generate standalone Ed448 in HSM");
        assert_eq!(
            u8::from(generated_public.pk_algo()),
            EXPECTED_ALGO_ID_ED448_STANDALONE,
            "generated key must be standalone Ed448 (algo 28), not the MLDSA87_Ed448 composite (algo 31)"
        );
        assert_eq!(generated_public.pk_algo(), PublicKeyAlgorithm::Ed448);
        let expected_fp = generated_public.fingerprint();
        drop(s1);

        // 2) Reload from the token alone and sign.
        let s2 = open_session(&e);
        let public_reloaded = s2
            .key(id, PgpKeyType::Sign, None)
            .expect("reload generated Ed448 public key from token");
        assert_eq!(
            public_reloaded.fingerprint(),
            expected_fp,
            "reloaded fingerprint must match the generated key"
        );
        let kp = s2
            .keypair(id, PgpKeyType::Sign, None)
            .expect("reload generated Ed448 keypair from token");
        assert!(
            kp.pqc.is_none(),
            "standalone Ed448 must resolve via the classical single-handle path (no PQC custody handle)"
        );
        let msg = b"pqctoday standalone Ed448: generated in-HSM, signed in-HSM";
        let mut sig = Vec::new();
        crate::signer::sign_on_card(kp, &mut &msg[..], &mut sig).expect("sign_on_card (Ed448)");

        // 3) Wire + component assertions: v6 packet, algorithm 28,
        //    114-byte native Ed448 signature (mpi::Signature::Ed448 { s }).
        let pile = PacketPile::from_bytes(&sig).expect("re-parse signature");
        let mut sig_packet = None;
        for p in pile.descendants() {
            if let Packet::Signature(s) = p {
                sig_packet = Some(s.clone());
            }
        }
        let sig_packet = sig_packet.expect("a Signature packet");
        assert_eq!(sig_packet.version(), 6, "standalone Ed448 signature must be v6 (RFC 9580)");
        assert_eq!(u8::from(sig_packet.pk_algo()), EXPECTED_ALGO_ID_ED448_STANDALONE);
        assert_eq!(sig_packet.pk_algo(), PublicKeyAlgorithm::Ed448);
        match sig_packet.mpis() {
            sequoia_openpgp::crypto::mpi::Signature::Ed448 { s } => {
                assert_eq!(s.len(), 114, "Ed448 signature must be 114 bytes");
            }
            other => panic!("expected standalone Ed448 signature, got {other:?}"),
        }

        // 4) Cryptographic verification: sequoia_openpgp's own real
        //    verification path (Signature::verify_message), not a
        //    hand-rolled check — directly against the in-HSM-generated
        //    public key (no Cert needed for a detached-signature check).
        sig_packet
            .verify_message(&public_reloaded, msg)
            .expect("HSM-generated standalone Ed448 signature must verify against the generated public key");

        eprintln!(
            "PASS live_ed448_standalone: HSM Ed448 signature is v6 + algo {EXPECTED_ALGO_ID_ED448_STANDALONE}, \
             verified by sequoia 2.x ({} bytes armored)",
            sig.len()
        );

        // 5) Tamper-rejection control: corrupt the raw signature bytes on
        //    the wire and confirm sequoia's verifier rejects it. A
        //    detached signature file is exactly one Signature packet, and
        //    the algorithm-specific signature bytes (the native 114-byte
        //    Ed448 `s`) are the LAST field in a v6 signature packet with
        //    nothing following, so flipping the final byte of the
        //    de-armored stream corrupts the signature payload itself
        //    without touching any packet framing / subpacket structure.
        {
            let mut der = sequoia_openpgp::armor::Reader::from_bytes(
                &sig,
                sequoia_openpgp::armor::ReaderMode::Tolerant(None),
            );
            let mut raw = Vec::new();
            std::io::copy(&mut der, &mut raw).expect("de-armor for tamper test");
            let last = raw.len() - 1;
            raw[last] ^= 0xFF;

            let pile = PacketPile::from_bytes(&raw).expect("re-parse corrupted signature");
            let mut corrupted = None;
            for p in pile.descendants() {
                if let Packet::Signature(s) = p {
                    corrupted = Some(s.clone());
                }
            }
            let corrupted = corrupted.expect("a Signature packet");
            let err = corrupted
                .verify_message(&public_reloaded, msg)
                .expect_err("sequoia must reject a corrupted Ed448 signature");
            eprintln!("    PASS tamper-rejection: corrupted signature rejected: {err}");
        }

        // 6) CONFIRM non-extractability of the private key (keypair()
        //    consumed s2's session, so use a fresh session).
        let s3 = open_session(&e);
        let h = s3
            .session
            .find_objects(&[
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Id(id.to_vec()),
                Attribute::Class(ObjectClass::PRIVATE_KEY),
                Attribute::KeyType(cryptoki::object::KeyType::EC_EDWARDS),
            ])
            .expect("find_objects")[0];
        let value_released = s3
            .session
            .get_attributes(h, &[cryptoki::object::AttributeType::Value])
            .map(|attrs| attrs.iter().any(|a| matches!(a, Attribute::Value(v) if !v.is_empty())))
            .unwrap_or(false);
        assert!(
            !value_released,
            "Ed448 private CKA_VALUE was released — key IS extractable (must not be)"
        );
        let mut sensitive = None;
        let mut extractable = None;
        for a in s3
            .session
            .get_attributes(
                h,
                &[
                    cryptoki::object::AttributeType::Sensitive,
                    cryptoki::object::AttributeType::Extractable,
                ],
            )
            .expect("get sensitive/extractable")
        {
            match a {
                Attribute::Sensitive(x) => sensitive = Some(x),
                Attribute::Extractable(x) => extractable = Some(x),
                _ => {}
            }
        }
        assert_eq!(sensitive, Some(true), "Ed448 CKA_SENSITIVE must be true");
        assert_eq!(extractable, Some(false), "Ed448 CKA_EXTRACTABLE must be false");
        eprintln!("    Ed448: CKA_VALUE refused, SENSITIVE=true, EXTRACTABLE=false");

        purge_id(&open_session(&e), id);
    }
}
