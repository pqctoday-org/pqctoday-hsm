//! `HsmKeyHandle` — opaque, versioned reference to a signing key that lives
//! in the HSM as a token object.
//!
//! This blob is what we hand to OpenMLS in place of the "private key" bytes
//! it expects from `signature_key_gen`. OpenMLS persists it in its
//! `StorageProvider` like any other key material; on every `sign()` call we
//! decode it back to a PKCS#11 object handle via `C_FindObjects` and run
//! the signing operation inside the HSM. Real key bytes never leave the
//! token.
//!
//! Wire format (intentionally small + versioned so it can evolve later):
//!
//! ```text
//! ┌────────┬─────────┬──────────┬──────────────┬────────────┐
//! │ "PQTH" │ ver (1) │ sig sch. │ cka_id_len   │  cka_id    │
//! │  4 B   │   1 B   │   2 B    │     2 B      │   N bytes  │
//! └────────┴─────────┴──────────┴──────────────┴────────────┘
//! ```

use serde::{Deserialize, Serialize};

use crate::error::PqcTodayError;

/// Stable, serialisable reference to a private key that lives in the HSM.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct HsmKeyHandle {
    /// PKCS#11 `CKA_ID` assigned at key generation.
    pub(crate) cka_id: Vec<u8>,
    /// Signature scheme of the key (drives mechanism selection on `sign`).
    /// Stored as the `u16` repr of `openmls_traits::types::SignatureScheme`.
    pub(crate) scheme: u16,
}

impl HsmKeyHandle {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(9 + self.cka_id.len());
        out.extend_from_slice(b"PQTH"); // pqctoday handle
        out.push(1);
        out.extend_from_slice(&self.scheme.to_be_bytes());
        out.extend_from_slice(&(self.cka_id.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.cka_id);
        out
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, PqcTodayError> {
        if bytes.len() < 9 || &bytes[..4] != b"PQTH" || bytes[4] != 1 {
            return Err(PqcTodayError::MalformedKeyHandle);
        }
        let scheme = u16::from_be_bytes([bytes[5], bytes[6]]);
        let id_len = u16::from_be_bytes([bytes[7], bytes[8]]) as usize;
        if bytes.len() != 9 + id_len {
            return Err(PqcTodayError::MalformedKeyHandle);
        }
        Ok(Self {
            cka_id: bytes[9..9 + id_len].to_vec(),
            scheme,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let h = HsmKeyHandle {
            cka_id: vec![1, 2, 3, 4, 5, 6, 7, 8],
            scheme: 0x0807, // ED25519
        };
        let encoded = h.encode();
        assert_eq!(&encoded[..4], b"PQTH");
        let decoded = HsmKeyHandle::decode(&encoded).unwrap();
        assert_eq!(decoded, h);
    }

    #[test]
    fn rejects_bad_magic() {
        let bad = b"XXXX\x01\x08\x07\x00\x00";
        assert!(HsmKeyHandle::decode(bad).is_err());
    }

    #[test]
    fn rejects_truncated() {
        let h = HsmKeyHandle { cka_id: vec![1, 2, 3], scheme: 0x0403 };
        let mut encoded = h.encode();
        encoded.pop();
        assert!(HsmKeyHandle::decode(&encoded).is_err());
    }
}
