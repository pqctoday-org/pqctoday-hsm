use std::sync::Arc;

use openmls_memory_storage::MemoryStorage;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::{CryptoError, SignatureScheme};
use openmls_traits::OpenMlsProvider;

use crate::backend::PkcsOps;
#[cfg(not(target_arch = "wasm32"))]
use crate::backend::CryptokiBackend;
#[cfg(target_arch = "wasm32")]
use crate::backend::WasmPkcs11Backend;
use crate::crypto::PqcTodayCrypto;
use crate::error::PqcTodayError;
use crate::persistence;
use crate::rand::PqcTodayRand;
#[cfg(not(target_arch = "wasm32"))]
use crate::session::HsmSession;
use crate::session::HsmConfig;
use crate::signer::PqcTodayHsmSigner;

/// `OpenMlsProvider` implementation with PKCS#11-backed crypto + RNG.
///
/// Storage is an in-memory `MemoryStorage` for now — group epoch secrets,
/// transcript hashes, and ratchet-tree state live in-process. Migrating
/// the storage half to PKCS#11 TOKEN objects is tracked in README §Phase 3.
pub struct PqcTodayProvider {
    crypto: PqcTodayCrypto,
    rand: PqcTodayRand,
    storage: MemoryStorage,
    /// `Some(label)` when this provider was created via
    /// [`PqcTodayProvider::with_persistence`]. Drives [`Self::persist`].
    persistence_label: Option<String>,
    /// Shared `PkcsOps` handle — kept here so `persist()` and
    /// `generate_signer()` can hand it to their respective modules without
    /// going through the crypto sub-provider.
    ops: Arc<dyn PkcsOps>,
    /// The underlying `HsmSession` is kept here solely to support
    /// [`Self::spawn_sibling`], which needs to open an additional session on
    /// the same PKCS#11 context. The `ops` field wraps a clone of this session.
    #[cfg(not(target_arch = "wasm32"))]
    hsm: HsmSession,
}

impl PqcTodayProvider {
    // ── Native (non-wasm32) constructors ─────────────────────────────────────

    #[cfg(not(target_arch = "wasm32"))]
    pub fn new(cfg: &HsmConfig) -> Result<Self, PqcTodayError> {
        let hsm = HsmSession::open(cfg)?;
        Ok(Self::with_session(hsm))
    }

    /// Spawn a second provider that shares this one's PKCS#11 context but
    /// opens its own session and gets its own in-memory `StorageProvider`.
    ///
    /// Useful for in-process demos (and the `two_member_group` example)
    /// where two MLS endpoints need to co-exist while sharing the HSM
    /// module — softhsmv3's `C_Initialize` is not safe to call twice in
    /// the same process.
    pub fn spawn_sibling(&self, user_pin: Option<&str>) -> Result<Self, PqcTodayError> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let new_hsm = self.hsm.open_additional_session(user_pin)?;
            return Ok(Self::with_session(new_hsm));
        }
        #[cfg(target_arch = "wasm32")]
        {
            let _ = user_pin;
            Ok(Self::new_wasm())
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn with_session(hsm: HsmSession) -> Self {
        let ops: Arc<dyn PkcsOps> = Arc::new(CryptokiBackend::new(hsm.clone()));
        let crypto = PqcTodayCrypto::new(Arc::clone(&ops));
        let rand = PqcTodayRand::new(Arc::clone(&ops));
        Self {
            crypto,
            rand,
            storage: MemoryStorage::default(),
            persistence_label: None,
            ops,
            hsm,
        }
    }

    /// Open the HSM session and **restore** a previously-snapshotted
    /// `MemoryStorage` from the `CKO_DATA` object labelled `label`,
    /// falling back to an empty storage if no snapshot exists yet.
    ///
    /// Future calls to [`Self::persist`] re-snapshot to the same label.
    /// See [`crate::persistence`] for the wire format and design notes.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn with_persistence(cfg: &HsmConfig, label: &str) -> Result<Self, PqcTodayError> {
        let hsm = HsmSession::open(cfg)?;
        let ops: Arc<dyn PkcsOps> = Arc::new(CryptokiBackend::new(hsm.clone()));
        let storage = persistence::restore_or_new(ops.as_ref(), label)?;
        let crypto = PqcTodayCrypto::new(Arc::clone(&ops));
        let rand = PqcTodayRand::new(Arc::clone(&ops));
        Ok(Self {
            crypto,
            rand,
            storage,
            persistence_label: Some(label.to_string()),
            ops,
            hsm,
        })
    }

    // ── wasm32 constructors ───────────────────────────────────────────────────

    /// Create a provider backed by the in-process `softhsmrustv3` PKCS#11
    /// engine (wasm32 only). No external module path or PIN required.
    #[cfg(target_arch = "wasm32")]
    pub fn new(_cfg: &HsmConfig) -> Result<Self, PqcTodayError> {
        Ok(Self::new_wasm())
    }

    /// Restore from a snapshot label (wasm32 only).
    #[cfg(target_arch = "wasm32")]
    pub fn with_persistence(_cfg: &HsmConfig, label: &str) -> Result<Self, PqcTodayError> {
        let ops: Arc<dyn PkcsOps> = Arc::new(WasmPkcs11Backend);
        let storage = persistence::restore_or_new(ops.as_ref(), label)?;
        let crypto = PqcTodayCrypto::new(Arc::clone(&ops));
        let rand = PqcTodayRand::new(Arc::clone(&ops));
        Ok(Self {
            crypto,
            rand,
            storage,
            persistence_label: Some(label.to_string()),
            ops,
        })
    }

    #[cfg(target_arch = "wasm32")]
    fn new_wasm() -> Self {
        let ops: Arc<dyn PkcsOps> = Arc::new(WasmPkcs11Backend);
        let crypto = PqcTodayCrypto::new(Arc::clone(&ops));
        let rand = PqcTodayRand::new(Arc::clone(&ops));
        Self {
            crypto,
            rand,
            storage: MemoryStorage::default(),
            persistence_label: None,
            ops,
        }
    }

    // ── Shared methods ────────────────────────────────────────────────────────

    /// Snapshot the current in-memory `StorageProvider` state to the
    /// HSM `CKO_DATA` object configured at construction time. Requires
    /// the provider was created with [`Self::with_persistence`].
    pub fn persist(&self) -> Result<(), PqcTodayError> {
        let label = self
            .persistence_label
            .as_ref()
            .ok_or(PqcTodayError::NotInitialised)?;
        persistence::snapshot(&self.storage, self.ops.as_ref(), label)
    }

    /// Mint a fresh HSM-backed signature keypair and return a signer that can
    /// be used with `openmls` for credential identity signing.
    ///
    /// The private key never leaves the HSM. The signer carries only the
    /// public key + the opaque [`crate::handle::HsmKeyHandle`] blob; every
    /// `sign()` looks the token object up by `CKA_ID` and runs `C_Sign`
    /// inside the HSM.
    pub fn generate_signer(
        &self,
        scheme: SignatureScheme,
    ) -> Result<PqcTodayHsmSigner, CryptoError> {
        let (public_key, handle_blob) = self.crypto.signature_key_gen(scheme)?;
        Ok(PqcTodayHsmSigner::new(
            Arc::clone(&self.ops),
            handle_blob,
            public_key,
            scheme,
        ))
    }
}

impl OpenMlsProvider for PqcTodayProvider {
    type CryptoProvider = PqcTodayCrypto;
    type RandProvider = PqcTodayRand;
    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.rand
    }
}
