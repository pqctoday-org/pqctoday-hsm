//! OpenMLS crypto + rand provider backed by PKCS#11 v3.2.
//!
//! This crate implements [`openmls_traits::OpenMlsProvider`] by routing the
//! [`openmls_traits::crypto::OpenMlsCrypto`] surface through a PKCS#11
//! token — softhsmv3 by default, but any conformant module works.
//!
//! ## What runs in the HSM (v0.1)
//!
//! | Operation                  | PKCS#11 mechanism            | In-HSM |
//! | -------------------------- | ---------------------------- | :----: |
//! | `hash`                     | `CKM_SHA256` / `SHA512`      | yes    |
//! | `hmac`                     | `CKM_SHA256_HMAC` / `SHA512` | yes    |
//! | `hkdf_extract` / `_expand` | `CKM_HKDF_DERIVE`            | yes    |
//! | `aead_encrypt` / `_decrypt`| `CKM_AES_GCM`                | yes    |
//! | `signature_key_gen`        | `CKM_EC_EDWARDS_KEY_PAIR_GEN` / `CKM_EC_KEY_PAIR_GEN` | yes |
//! | `sign` / `verify_signature`| `CKM_EDDSA` / `CKM_ECDSA`    | yes    |
//! | HPKE / DhKem25519+SHA256+AES128GCM | `CKM_ECDH1_DERIVE` + `CKM_SHA256_HMAC` + `CKM_AES_GCM` (RFC 9180) | yes |
//! | HPKE / all other suites    | `hpke-rs-rust-crypto` fallback | **no — Phase 2.1** |
//!
//! ## Signature key custody
//!
//! [`PqcTodayCrypto`] implements `signature_key_gen` by generating the key
//! pair **as a token object** in the HSM. The `Vec<u8>` returned to OpenMLS
//! as the "private key" is **not** raw key material — it is an opaque,
//! versioned `HsmKeyHandle` blob (slot id + CKA_ID) that this provider
//! knows how to resolve back to a PKCS#11 object handle on subsequent
//! `sign()` calls. Real signing material never leaves the HSM.
//!
//! ## What about PQ ciphersuites?
//!
//! `draft-ietf-mls-pq-ciphersuites` is not yet registered upstream in
//! `openmls_traits::types::Ciphersuite`. When upstream lands the registry,
//! we'll wire `CKM_ML_DSA` / `CKM_ML_KEM_*` (already supported by
//! softhsmv3) through this provider. See README §Phase 2.

pub mod backend;
mod crypto;
mod error;
mod handle;
mod hpke;
pub mod persistence;
mod provider;
mod rand;
mod session;
mod signer;

pub use backend::PkcsOps;
#[cfg(not(target_arch = "wasm32"))]
pub use backend::CryptokiBackend;
#[cfg(target_arch = "wasm32")]
pub use backend::WasmPkcs11Backend;
pub use crypto::PqcTodayCrypto;
pub use error::PqcTodayError;
pub use provider::PqcTodayProvider;
pub use rand::PqcTodayRand;
pub use session::HsmConfig;
#[cfg(not(target_arch = "wasm32"))]
pub use session::HsmSession;
pub use signer::PqcTodayHsmSigner;
