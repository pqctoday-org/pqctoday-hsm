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
use sequoia_openpgp::types::Timestamp;
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
        self.session
            .login(UserType::User, Some(&AuthPin::new(pin.to_string().into())))?;
        Ok(())
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

    /// Get an [`Op11KeyPair`] that can perform decryption and signing operations.
    ///
    /// The optional `cert` is used as source of OpenPGP metadata, if available.
    pub fn keypair(self, id: &[u8], pkt: PgpKeyType, cert: Option<Cert>) -> Result<Op11KeyPair> {
        // get public key for id
        let key = self.key(id, pkt, cert)?;

        let priv_key_template = match pkt {
            PgpKeyType::Sign | PgpKeyType::Auth => {
                vec![
                    Attribute::Token(true),
                    Attribute::Private(true),
                    Attribute::Sign(true),
                    Attribute::Id(id.to_vec()),
                    Attribute::Class(ObjectClass::PRIVATE_KEY),
                ]
            }
            PgpKeyType::Encrypt => {
                vec![
                    Attribute::Token(true),
                    Attribute::Private(true),
                    Attribute::Decrypt(true), // FIXME: or Derive for ECC?!
                    Attribute::Id(id.to_vec()),
                    Attribute::Class(ObjectClass::PRIVATE_KEY),
                ]
            }
        };

        let priv_key_handle = self.session.find_objects(&priv_key_template)?;

        if priv_key_handle.len() == 1 {
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
        }
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
pub struct Op11KeyPair {
    pub public: Key<PublicParts, UnspecifiedRole>,
    pub private: ObjectHandle,
    pub session: Arc<Mutex<Session>>,
}

impl Op11KeyPair {
    pub fn new(
        public: Key<PublicParts, UnspecifiedRole>,
        private: ObjectHandle,
        session: Arc<Mutex<Session>>,
    ) -> Self {
        Self {
            public,
            private,
            session,
        }
    }
}
