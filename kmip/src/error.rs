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
    /// `ObjectArchived`, which signals the object is in archival
    /// storage (recoverable via Recover, §6.1.4) rather than in a
    /// wrong lifecycle state.
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
    /// `Attribute Single Valued` — KMIP 3.0 §11. AddAttribute / Set
    /// against a single-valued attribute that already has a value
    /// (vs `NonUniqueNameAttribute` which is name-uniqueness scope).
    /// BL-M-5 step #4 pins this for a duplicate Description add.
    AttributeSingleValued  = 0x0000_0023,
    /// `Key Format Type Not Supported` — KMIP 3.0 §11. The client
    /// asked for a `KeyFormatType` (Get / Register) the server cannot
    /// produce or accept for that object's algorithm.
    KeyFormatTypeNotSupported = 0x0000_0010,
    /// `Sensitive` — KMIP 3.0 §11. The request tried to read key
    /// material (or an attribute) marked Sensitive; maps from
    /// PKCS#11 `CKR_ATTRIBUTE_SENSITIVE`.
    Sensitive              = 0x0000_0016,
    /// `Not Extractable` — KMIP 3.0 §11. The key material cannot
    /// leave the cryptographic boundary; maps from PKCS#11
    /// `CKR_KEY_UNEXTRACTABLE` / `CKR_KEY_NOT_WRAPPABLE`.
    NotExtractable         = 0x0000_0017,
    /// `Invalid Data Type` — KMIP 3.0 §11. A field carried a TTLV
    /// item type other than the one the spec mandates for its tag.
    InvalidDataType        = 0x0000_001c,
    /// `Unsupported Cryptographic Parameters` — KMIP 3.0 §11. The
    /// CryptographicParameters combination (mode / padding / hash) is
    /// recognised but not supported; maps from PKCS#11
    /// `CKR_MECHANISM_PARAM_INVALID`.
    UnsupportedCryptographicParameters = 0x0000_003e,
    /// `Unsupported Protocol Version` — KMIP 3.0 §11. The request
    /// header's ProtocolVersion is one the server does not speak
    /// (we only accept 3.0). Distinct from `InvalidMessage` (0x04),
    /// which signals a malformed frame.
    UnsupportedProtocolVersion = 0x0000_003f,
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
    pub fn key_format_type_not_supported(msg: impl Into<String>) -> Self {
        Self::failed(ResultReason::KeyFormatTypeNotSupported, msg)
    }
    pub fn sensitive(msg: impl Into<String>) -> Self {
        Self::failed(ResultReason::Sensitive, msg)
    }
    pub fn not_extractable(msg: impl Into<String>) -> Self {
        Self::failed(ResultReason::NotExtractable, msg)
    }
    pub fn invalid_data_type(msg: impl Into<String>) -> Self {
        Self::failed(ResultReason::InvalidDataType, msg)
    }
    pub fn unsupported_cryptographic_parameters(msg: impl Into<String>) -> Self {
        Self::failed(ResultReason::UnsupportedCryptographicParameters, msg)
    }
    pub fn unsupported_protocol_version(major: i32, minor: i32) -> Self {
        Self::failed(
            ResultReason::UnsupportedProtocolVersion,
            format!("KMIP protocol version {major}.{minor} not supported (server speaks 3.0)"),
        )
    }
    pub fn general_failure(msg: impl Into<String>) -> Self {
        Self::failed(ResultReason::GeneralFailure, msg)
    }
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }

    /// `ResultReason` for response builders; `None`-equivalent reasons
    /// (`NotImplemented`, `Internal`) surface as `GeneralFailure`.
    pub fn result_reason(&self) -> ResultReason {
        match self {
            Self::Failed { reason, .. } => *reason,
            Self::Internal(_) | Self::NotImplemented(_) => ResultReason::GeneralFailure,
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
        // K1 additions — `Result Reason` rows in the OASIS enums JSON.
        assert_eq!(ResultReason::KeyFormatTypeNotSupported.to_wire_value(), 0x0000_0010);
        assert_eq!(ResultReason::Sensitive.to_wire_value(),             0x0000_0016);
        assert_eq!(ResultReason::NotExtractable.to_wire_value(),        0x0000_0017);
        assert_eq!(ResultReason::InvalidDataType.to_wire_value(),       0x0000_001c);
        assert_eq!(ResultReason::UnsupportedCryptographicParameters.to_wire_value(), 0x0000_003e);
        assert_eq!(ResultReason::UnsupportedProtocolVersion.to_wire_value(), 0x0000_003f);
        assert_eq!(ResultReason::GeneralFailure.to_wire_value(),        0x0000_0100);
    }

    #[test]
    fn helpers_carry_correct_reason() {
        assert_eq!(KmipError::not_found("u1").result_reason(), ResultReason::ItemNotFound);
        assert_eq!(KmipError::object_not_found("u1").result_reason(), ResultReason::ObjectNotFound);
        assert_eq!(KmipError::permission_denied("x").result_reason(), ResultReason::PermissionDenied);
        assert_eq!(KmipError::object_archived("u1").result_reason(), ResultReason::ObjectArchived);
        assert_eq!(
            KmipError::key_format_type_not_supported("x").result_reason(),
            ResultReason::KeyFormatTypeNotSupported
        );
        assert_eq!(KmipError::sensitive("x").result_reason(), ResultReason::Sensitive);
        assert_eq!(KmipError::not_extractable("x").result_reason(), ResultReason::NotExtractable);
        assert_eq!(KmipError::invalid_data_type("x").result_reason(), ResultReason::InvalidDataType);
        assert_eq!(
            KmipError::unsupported_cryptographic_parameters("x").result_reason(),
            ResultReason::UnsupportedCryptographicParameters
        );
        assert_eq!(
            KmipError::unsupported_protocol_version(2, 1).result_reason(),
            ResultReason::UnsupportedProtocolVersion
        );
        assert_eq!(KmipError::general_failure("x").result_reason(), ResultReason::GeneralFailure);
    }
}
