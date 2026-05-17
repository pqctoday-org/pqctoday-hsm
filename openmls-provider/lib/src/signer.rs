//! `PqcTodayHsmSigner` — an [`openmls_traits::signatures::Signer`] whose
//! private key lives as a token object inside the HSM.
//!
//! This is the integration point that lets OpenMLS use HSM-resident keys
//! for **credential identity** signing (KeyPackage / Commit / framing
//! signatures), not just for the crypto inside the key schedule.
//!
//! ## Usage
//!
//! ```no_run
//! use openmls_pqctoday_crypto::{HsmConfig, PqcTodayProvider};
//! use openmls_traits::types::SignatureScheme;
//!
//! let cfg = HsmConfig::new("/path/to/libsofthsmv3.so").with_pin("1234");
//! let provider = PqcTodayProvider::new(&cfg).unwrap();
//! let signer = provider.generate_signer(SignatureScheme::ED25519).unwrap();
//!
//! // Hand `signer.public_key()` to openmls as the credential's signature key,
//! // pass `&signer` anywhere openmls asks for an `&impl Signer`.
//! ```
//!
//! The signer carries no private key material — only the public key + the
//! versioned [`HsmKeyHandle`](crate::handle::HsmKeyHandle) blob. Every
//! `sign()` call decodes the handle, looks up the token object by
//! `CKA_ID`, and runs `C_SignInit` + `C_Sign` inside the HSM.

use std::sync::Arc;

use openmls_traits::signatures::{Signer, SignerError};
use openmls_traits::types::SignatureScheme;

use crate::backend::PkcsOps;
use crate::error::PqcTodayError;

/// HSM-backed implementor of [`openmls_traits::signatures::Signer`].
pub struct PqcTodayHsmSigner {
    ops: Arc<dyn PkcsOps>,
    /// Opaque versioned blob — what OpenMLS would otherwise hold as raw `sk`.
    handle_blob: Vec<u8>,
    /// Raw public key bytes per the scheme (Ed25519: 32 B; P-256 uncompressed: 65 B).
    public_key: Vec<u8>,
    scheme: SignatureScheme,
}

impl PqcTodayHsmSigner {
    /// Construct from a freshly-minted (public, handle) pair.
    ///
    /// Crate-internal: callers go through
    /// [`crate::PqcTodayProvider::generate_signer`].
    pub(crate) fn new(
        ops: Arc<dyn PkcsOps>,
        handle_blob: Vec<u8>,
        public_key: Vec<u8>,
        scheme: SignatureScheme,
    ) -> Self {
        Self {
            ops,
            handle_blob,
            public_key,
            scheme,
        }
    }

    /// Raw public-key bytes (matches the form returned by
    /// [`openmls_traits::crypto::OpenMlsCrypto::signature_key_gen`]).
    ///
    /// Hand this to OpenMLS as the credential's `signature_key`.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// The opaque `HsmKeyHandle` blob — what OpenMLS would otherwise see as
    /// the "private key" bytes. Exposed for cases where the caller is
    /// stitching together their own credential/storage flow.
    pub fn handle_blob(&self) -> &[u8] {
        &self.handle_blob
    }

    /// The signature scheme this signer produces signatures for.
    pub fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

impl Signer for PqcTodayHsmSigner {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        self.ops
            .sign(self.scheme, &self.handle_blob, payload)
            .map_err(map_err)
    }

    fn signature_scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

fn map_err(_e: PqcTodayError) -> SignerError {
    // openmls's `SignerError` carries no detail — anything routing or PKCS#11
    // related collapses to `SigningError`. Operational debugging happens via
    // log/tracing on the PqcTodayError side before we map.
    SignerError::SigningError
}
