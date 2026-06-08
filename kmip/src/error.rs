//! KMIP error type — maps to KMIP 3.0 `Result Reason` enumeration on the wire.
//!
//! Codepoints verified against
//! `spec/oasis-kmip-3.0/kmip-spec-3.0-tags-enums.json` (`Result Reason` enum)
//! which itself was extracted from the OASIS KMIP 3.0 HTML spec
//! (sha256-pinned). KMIP 3.0 §9.2.x defines the enumeration.

use thiserror::Error;

/// KMIP 3.0 `Result Reason` codepoint subset used by Phase 5 op handlers.
/// The wire encoding is `Enumeration` (item type `0x05`) with the `u32`
/// value below.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u32)]
pub enum ResultReason {
    ItemNotFound          = 0x0000_0001,
    OperationNotSupported = 0x0000_0005,
    MissingData           = 0x0000_0006,
    InvalidField          = 0x0000_0007,
    CryptographicFailure  = 0x0000_000a,
    PermissionDenied      = 0x0000_000c,
    ObjectArchived        = 0x0000_000d,
    ObjectAlreadyExists   = 0x0000_0018,
    InvalidAttribute      = 0x0000_002c,
    InvalidAttributeValue = 0x0000_002d,
    GeneralFailure        = 0x0000_0100,
}

impl ResultReason {
    pub const fn to_wire_value(self) -> u32 {
        self as u32
    }
}

#[derive(Debug, Error)]
pub enum KmipError {
    #[error("KMIP {reason:?} (0x{code:08x}): {msg}")]
    Failed {
        reason: ResultReason,
        code: u32,
        msg: String,
    },

    #[error("not yet implemented: {0}")]
    NotImplemented(&'static str),

    #[error("internal error: {0}")]
    Internal(String),

    #[error("PKCS#11 bridge: {0}")]
    Bridge(#[from] crate::pkcs11bridge::BridgeError),
}

impl KmipError {
    pub fn failed(reason: ResultReason, msg: impl Into<String>) -> Self {
        let code = reason.to_wire_value();
        Self::Failed {
            reason,
            code,
            msg: msg.into(),
        }
    }

    pub fn permission_denied(msg: impl Into<String>) -> Self {
        Self::failed(ResultReason::PermissionDenied, msg)
    }
    pub fn not_found(uid: &str) -> Self {
        Self::failed(ResultReason::ItemNotFound, format!("UID {uid:?} not found"))
    }
    pub fn invalid_field(msg: impl Into<String>) -> Self {
        Self::failed(ResultReason::InvalidField, msg)
    }
    pub fn invalid_attribute(msg: impl Into<String>) -> Self {
        Self::failed(ResultReason::InvalidAttribute, msg)
    }
    pub fn invalid_attribute_value(msg: impl Into<String>) -> Self {
        Self::failed(ResultReason::InvalidAttributeValue, msg)
    }
    pub fn missing_data(msg: impl Into<String>) -> Self {
        Self::failed(ResultReason::MissingData, msg)
    }
    pub fn object_archived(uid: &str) -> Self {
        Self::failed(
            ResultReason::ObjectArchived,
            format!("UID {uid:?} not in usable lifecycle state"),
        )
    }
    pub fn cryptographic_failure(msg: impl Into<String>) -> Self {
        Self::failed(ResultReason::CryptographicFailure, msg)
    }
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }

    /// `ResultReason` for response builders; `None`-equivalent reasons
    /// (`NotImplemented`, `Internal`, `Bridge`) surface as `GeneralFailure`.
    pub fn result_reason(&self) -> ResultReason {
        match self {
            Self::Failed { reason, .. } => *reason,
            Self::Bridge(_) | Self::Internal(_) | Self::NotImplemented(_) => {
                ResultReason::GeneralFailure
            }
        }
    }
}

pub type Result<T> = std::result::Result<T, KmipError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn result_reason_codepoints_match_oasis_spec() {
        // Cross-check against kmip-spec-3.0-tags-enums.json (`Result Reason`).
        assert_eq!(ResultReason::ItemNotFound.to_wire_value(),          0x0000_0001);
        assert_eq!(ResultReason::OperationNotSupported.to_wire_value(), 0x0000_0005);
        assert_eq!(ResultReason::MissingData.to_wire_value(),           0x0000_0006);
        assert_eq!(ResultReason::InvalidField.to_wire_value(),          0x0000_0007);
        assert_eq!(ResultReason::CryptographicFailure.to_wire_value(),  0x0000_000a);
        assert_eq!(ResultReason::PermissionDenied.to_wire_value(),      0x0000_000c);
        assert_eq!(ResultReason::ObjectArchived.to_wire_value(),        0x0000_000d);
        assert_eq!(ResultReason::ObjectAlreadyExists.to_wire_value(),   0x0000_0018);
        assert_eq!(ResultReason::InvalidAttribute.to_wire_value(),      0x0000_002c);
        assert_eq!(ResultReason::InvalidAttributeValue.to_wire_value(), 0x0000_002d);
    }

    #[test]
    fn helpers_carry_correct_reason() {
        assert_eq!(KmipError::not_found("u1").result_reason(), ResultReason::ItemNotFound);
        assert_eq!(KmipError::permission_denied("x").result_reason(), ResultReason::PermissionDenied);
        assert_eq!(KmipError::object_archived("u1").result_reason(), ResultReason::ObjectArchived);
    }
}
