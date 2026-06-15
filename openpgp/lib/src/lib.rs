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

        // Base template: all private-key objects for this id.
        let usage = match pkt {
            PgpKeyType::Sign | PgpKeyType::Auth => Attribute::Sign(true),
            // FIXME: ECDH/ML-KEM may need Derive instead of Decrypt; softhsmv3
            // accepts Decrypt(true) on the ML-KEM/X25519 private objects.
            PgpKeyType::Encrypt => Attribute::Decrypt(true),
        };
        let base_template = vec![
            Attribute::Token(true),
            Attribute::Private(true),
            usage,
            Attribute::Id(id.to_vec()),
            Attribute::Class(ObjectClass::PRIVATE_KEY),
        ];

        if !is_composite {
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

        // Composite: resolve the two component handles by CKA_KEY_TYPE.
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

        let find_one = |kt| -> Result<ObjectHandle> {
            let mut tmpl = base_template.clone();
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
    }
}
