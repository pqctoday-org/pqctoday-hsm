#[cfg(not(target_arch = "wasm32"))]
use cryptoki::error::Error as CryptokiError;
use openmls_traits::types::CryptoError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PqcTodayError {
    /// Native PKCS#11 error from the `cryptoki` crate (non-wasm32 only).
    #[cfg(not(target_arch = "wasm32"))]
    #[error("PKCS#11 error: {0}")]
    Pkcs11(#[from] CryptokiError),

    /// Raw PKCS#11 CK_RV error code (wasm32 only — `cryptoki` not available).
    #[cfg(target_arch = "wasm32")]
    #[error("PKCS#11 CK_RV: 0x{0:08x}")]
    Pkcs11Raw(u32),

    #[error("HSM session not initialised")]
    NotInitialised,

    #[error("ciphersuite not supported by this provider: {0:?}")]
    UnsupportedCiphersuite(openmls_traits::types::Ciphersuite),

    #[error("signature scheme not supported: {0:?}")]
    UnsupportedSignatureScheme(openmls_traits::types::SignatureScheme),

    #[error("AEAD algorithm not supported: {0:?}")]
    UnsupportedAead(openmls_traits::types::AeadType),

    #[error("hash algorithm not supported: {0:?}")]
    UnsupportedHash(openmls_traits::types::HashType),

    #[error("malformed HSM key handle")]
    MalformedKeyHandle,

    #[error("PKCS#11 object not found for handle")]
    ObjectNotFound,

    #[error("HPKE: {0}")]
    Hpke(String),
}

impl From<PqcTodayError> for CryptoError {
    fn from(e: PqcTodayError) -> Self {
        match e {
            PqcTodayError::UnsupportedCiphersuite(_) => CryptoError::UnsupportedCiphersuite,
            PqcTodayError::UnsupportedSignatureScheme(_) => CryptoError::UnsupportedSignatureScheme,
            PqcTodayError::UnsupportedAead(_) => CryptoError::UnsupportedAeadAlgorithm,
            PqcTodayError::UnsupportedHash(_) => CryptoError::UnsupportedHashAlgorithm,
            _ => CryptoError::CryptoLibraryError,
        }
    }
}
