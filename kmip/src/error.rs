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
    ResponseTooLarge      = 0x0000_0002,
    AuthenticationNotSuccessful = 0x0000_0003,
    InvalidMessage        = 0x0000_0004,
    OperationNotSupported = 0x0000_0005,
    MissingData           = 0x0000_0006,
    InvalidField          = 0x0000_0007,
    CryptographicFailure  = 0x0000_000a,
    PermissionDenied      = 0x0000_000c,
    ObjectArchived        = 0x0000_000d,
    ObjectAlreadyExists   = 0x0000_0018,
    InvalidAttribute      = 0x0000_002c,
    InvalidAttributeValue = 0x0000_002d,
    /// `Non Unique Name Attribute` — KMIP 3.0 §11. Surfaced when a
    /// Register/Create supplies a `Name` already present on another
    /// managed object.
    NonUniqueNameAttribute = 0x0000_0035,
    /// `Wrong Key Lifecycle State` — KMIP 3.0 §11. The crypto op
    /// (Encrypt/Decrypt/Sign/etc.) requires `Active` but the object
    /// is in `Deactivated` / `Compromised`. Distinct from
    /// `ObjectArchived` which is reserved for `Destroyed` states.
    WrongKeyLifecycleState = 0x0000_0043,
    /// `Incompatible Cryptographic Usage Mask` — KMIP 3.0 §11. The
    /// op requires a `CryptographicUsageMask` flag the key doesn't
    /// carry (e.g. `Check` against a key whose mask lacks
    /// `ProcessStart`). Distinct from generic `PermissionDenied`.
    IncompatibleCryptographicUsageMask = 0x0000_0029,
    /// `Attribute Read Only` — KMIP 3.0 §11. ModifyAttribute /
    /// AddAttribute / SetAttribute against an attribute the server
    /// owns (UniqueIdentifier, ObjectType, State, InitialDate,
    /// LastChangeDate, OriginalCreationDate, Digest, …) per §11
    /// attribute table. Distinct from generic `InvalidField` so the
    /// client knows the request is rejected because the *attribute*
    /// is read-only rather than the *value* being malformed. BL-M-7
    /// step #2 pins this code.
    AttributeReadOnly      = 0x0000_0022,
    /// `Object Not Found` — KMIP 3.0 §11. The referenced managed
    /// object (UID) does not exist in the server's store. Distinct
    /// from `ItemNotFound` (0x01) which signals an attribute /
    /// item missing inside a request payload. BL-M-4 step #5
    /// (Get against a UID the server never minted) pins this code.
    ObjectNotFound         = 0x0000_0037,
    /// `Object Destroyed` — KMIP 3.0 §11. The referenced object has
    /// transitioned to `Destroyed` (or `DestroyedCompromised`); the
    /// metadata still exists for audit but the cryptographic
    /// material is gone. Distinct from `ObjectArchived` (0x0d),
    /// which signals a separately-managed archival store. BL-M-8
    /// step #5 (Get against a Destroyed UID) pins this code.
    ObjectDestroyed        = 0x0000_0036,
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
        // KMIP 3.0 §11: `Item Not Found` is the spec's default for a
        // missing-thing error — including the post-Obliterate
        // GetAttributes path (BL-M-20). The `Get`-specific
        // `Object Not Found` (0x37) case is reachable via
        // [`Self::object_not_found`].
        Self::failed(ResultReason::ItemNotFound, format!("UID {uid:?} not found"))
    }
    pub fn object_not_found(uid: &str) -> Self {
        // KMIP 3.0 §11 + §6.1.23 — `Get` against an unknown UID
        // returns `Object Not Found` (0x37), not the generic
        // `Item Not Found` (0x01). BL-M-4 step #5 pins this code.
        Self::failed(ResultReason::ObjectNotFound, format!("UID {uid:?} not found"))
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
    pub fn object_destroyed(uid: &str) -> Self {
        Self::failed(
            ResultReason::ObjectDestroyed,
            format!("UID {uid:?} has been destroyed"),
        )
    }
    pub fn wrong_key_lifecycle_state(uid: &str, state: &str) -> Self {
        Self::failed(
            ResultReason::WrongKeyLifecycleState,
            format!("UID {uid:?} is in {state} — op requires Active"),
        )
    }
    pub fn attribute_read_only(attr: &str) -> Self {
        Self::failed(
            ResultReason::AttributeReadOnly,
            format!("attribute {attr} is Read-Only"),
        )
    }
    pub fn non_unique_name_attribute(name: &str) -> Self {
        Self::failed(
            ResultReason::NonUniqueNameAttribute,
            format!("Name {name:?} already assigned to another managed object"),
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
        assert_eq!(ResultReason::AttributeReadOnly.to_wire_value(),     0x0000_0022);
        assert_eq!(ResultReason::WrongKeyLifecycleState.to_wire_value(), 0x0000_0043);
        assert_eq!(ResultReason::NonUniqueNameAttribute.to_wire_value(), 0x0000_0035);
    }

    #[test]
    fn helpers_carry_correct_reason() {
        assert_eq!(KmipError::not_found("u1").result_reason(), ResultReason::ItemNotFound);
        assert_eq!(KmipError::object_not_found("u1").result_reason(), ResultReason::ObjectNotFound);
        assert_eq!(KmipError::permission_denied("x").result_reason(), ResultReason::PermissionDenied);
        assert_eq!(KmipError::object_archived("u1").result_reason(), ResultReason::ObjectArchived);
    }
}
