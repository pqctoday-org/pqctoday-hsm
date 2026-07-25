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
    /// `Feature Not Supported` — KMIP 3.0 §9.2 / §11. The request is
    /// well-formed and the operation is implemented, but it asks for a
    /// capability this server does not provide (e.g. Set Endpoint Role
    /// requesting the §6.2 role switch — K19). Listed in the §6.1.61
    /// Table 433 error table.
    FeatureNotSupported   = 0x0000_0008,
    CryptographicFailure  = 0x0000_000a,
    /// `Usage Limit Exceeded` — KMIP 3.0 §11. A Get Usage Allocation
    /// (§6.1.29, Table 331) asked for more Usage Limits Units than the
    /// object's remaining `Usage Limits Count` can grant.
    UsageLimitExceeded    = 0x0000_001a,
    /// `Invalid Ticket` — KMIP 3.0 §11 / §6.1.37 Table 357. Logout's
    /// ticket doesn't name a live session (unknown, already logged
    /// out, or expired).
    InvalidTicket          = 0x0000_0019,
    /// `Operation Canceled By Requester` — KMIP 3.0 §11. Phase 4: a
    /// `Cancel` (§6.1.5) against a job that had not yet started
    /// executing succeeded, so a later `Poll` (§6.1.45) on the same
    /// Asynchronous Correlation Value reports this instead of a real
    /// result. Codepoint verified from `kmip-spec-3.0-tags-enums.json`
    /// (`Result Reason` 0x09).
    OperationCanceledByRequester = 0x0000_0009,
    /// `Invalid Asynchronous Correlation Value` — KMIP 3.0 §11. Phase
    /// 4: `Poll` / `Cancel` / `Process` (§6.1.45/§6.1.5/§6.1.46) named
    /// a correlation value this server never issued (or already
    /// forgot). Codepoint verified from `kmip-spec-3.0-tags-enums.json`
    /// (`Result Reason` 0x2b).
    InvalidAsynchronousCorrelationValue = 0x0000_002b,
    /// `Attribute Not Found` — KMIP 3.0 §11. The operation requires an
    /// attribute the object does not carry (e.g. Get Usage Allocation
    /// against an object with no Usage Limits attribute — §6.1.29
    /// Table 331 error table).
    AttributeNotFound     = 0x0000_0021,
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
    /// `Key Value Not Present` — KMIP 3.0 §11. The operation needs the
    /// raw key bytes but the managed object carries none the server
    /// can reach (K20 — Derive Key §6.1.19 Table 304 lists this for a
    /// base key whose material is neither in the KMIP store nor
    /// reachable through an engine primitive for the chosen method).
    /// Codepoint verified from `kmip-spec-3.0-tags-enums.json`.
    KeyValueNotPresent     = 0x0000_0013,
    /// `Bad Cryptographic Parameters` — KMIP 3.0 §11. The supplied
    /// CryptographicParameters are inconsistent with the operation /
    /// object (e.g. Derive Key HASH method without the §7.13-REQUIRED
    /// Hashing Algorithm). Distinct from
    /// `UnsupportedCryptographicParameters` (0x3e) — there the combo
    /// is coherent but unimplemented. Codepoint verified from
    /// `kmip-spec-3.0-tags-enums.json`.
    BadCryptographicParameters = 0x0000_0024,
    /// `Invalid Object Type` — KMIP 3.0 §11. The operation cannot act
    /// on the requested / referenced Object Type (e.g. Derive Key for
    /// anything but SymmetricKey / SecretData per §6.1.19). Codepoint
    /// verified from `kmip-spec-3.0-tags-enums.json`.
    InvalidObjectType      = 0x0000_0030,
    /// `Unsupported Protocol Version` — KMIP 3.0 §11. The request
    /// header's ProtocolVersion is one the server does not speak
    /// (we only accept 3.0). Distinct from `InvalidMessage` (0x04),
    /// which signals a malformed frame.
    UnsupportedProtocolVersion = 0x0000_003f,
    /// `Wrapping Object Archived` — KMIP 3.0 §11. The KEK named by a
    /// Get `KeyWrappingSpecification` (K16, §6.1.25) or a Register
    /// `KeyWrappingData` (K17, §6.1.50) has been moved off-line by the
    /// `Archive` op and must be `Recover`-ed before it can wrap/unwrap.
    /// Distinct from the data object's own `ObjectArchived` (0x0d) —
    /// this names the *wrapping* object. Codepoint verified from
    /// `kmip-spec-3.0-tags-enums.json` (`Result Reason` 0x40).
    WrappingObjectArchived = 0x0000_0040,
    /// `Wrapping Object Destroyed` — KMIP 3.0 §11. The wrap/unwrap KEK
    /// has transitioned to `Destroyed` / `DestroyedCompromised`; its
    /// cryptographic material is gone. Distinct from the data object's
    /// `ObjectDestroyed` (0x36). Codepoint verified from
    /// `kmip-spec-3.0-tags-enums.json` (`Result Reason` 0x41).
    WrappingObjectDestroyed = 0x0000_0041,
    /// `Wrapping Object Not Found` — KMIP 3.0 §11. The KEK UID named by
    /// a `KeyWrappingSpecification` / `KeyWrappingData` does not resolve
    /// to a managed object. Distinct from the data object's
    /// `ObjectNotFound` (0x37). Codepoint verified from
    /// `kmip-spec-3.0-tags-enums.json` (`Result Reason` 0x42).
    WrappingObjectNotFound = 0x0000_0042,
    /// `Circular Link Error` — KMIP 3.0 §11. An Add/Modify/Set of a
    /// `Link` attribute (§6.1.x attribute mutation) would create a
    /// cycle in the object-link graph: a self-link (A→A) or a direct
    /// reciprocal 2-cycle (A→B while B→A already exists). Distinct from
    /// the generic `InvalidAttributeValue` (0x2d). Codepoint verified
    /// from `kmip-spec-3.0-tags-enums.json` (`Result Reason` 0x4d).
    CircularLinkError = 0x0000_004d,
    /// `Invalid CSR` — KMIP 3.0 §11. The Certificate Request Value
    /// supplied to a §6.1.6 Certify / §6.1.52 Re-certify request could
    /// not be parsed as the declared `Certificate Request Type`, or its
    /// embedded self-signature failed to verify (a tampered / malformed
    /// PKCS#10 CSR). Codepoint `0x2f` verified from
    /// `kmip-spec-3.0-tags-enums.json` (`Result Reason` → `Invalid CSR`)
    /// and the §6.1.6.1 / §6.1.50.1 error-handling tables.
    InvalidCsr            = 0x0000_002f,
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
    pub fn invalid_ticket(msg: impl Into<String>) -> Self {
        Self::failed(ResultReason::InvalidTicket, msg)
    }
    /// Phase 4 — `Poll` / `Cancel` / `Process` against an unknown
    /// Asynchronous Correlation Value.
    pub fn invalid_asynchronous_correlation_value() -> Self {
        Self::failed(
            ResultReason::InvalidAsynchronousCorrelationValue,
            "unknown Asynchronous Correlation Value",
        )
    }
    /// Phase 4 — a later `Poll` on a job that `Cancel` removed before
    /// it started executing.
    pub fn operation_canceled_by_requester() -> Self {
        Self::failed(
            ResultReason::OperationCanceledByRequester,
            "canceled by requester before it began processing",
        )
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
        // KMIP 3.0 §11 + §6.1.25 — `Get` against an unknown UID
        // returns `Object Not Found` (0x37), not the generic
        // `Item Not Found` (0x01). BL-M-4 step #5 pins this code.
        Self::failed(ResultReason::ObjectNotFound, format!("UID {uid:?} not found"))
    }
    /// A batch item references `$IDPlaceholder` (§6.1 preamble) but no earlier item
    /// in this batch has produced a UID yet — typically because the item
    /// that was supposed to (e.g. `CreateKeyPair`) failed. Same wire code
    /// as [`Self::object_not_found`] (0x37 — nothing by that name exists
    /// in the store either way); only the message differs, so a client
    /// sees why instead of the raw `$IDPlaceholder` sentinel.
    pub fn id_placeholder_unset() -> Self {
        Self::failed(
            ResultReason::ObjectNotFound,
            "ID Placeholder not set — no earlier item in this batch produced a UID \
             (an earlier item likely failed)",
        )
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
        // KMIP 3.0 §11 `Object Archived`: "The object SHALL be
        // recovered from the archive before performing the operation."
        Self::failed(
            ResultReason::ObjectArchived,
            format!("UID {uid:?} is archived; Recover it before performing this operation"),
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
    pub fn feature_not_supported(msg: impl Into<String>) -> Self {
        Self::failed(ResultReason::FeatureNotSupported, msg)
    }
    pub fn usage_limit_exceeded(msg: impl Into<String>) -> Self {
        Self::failed(ResultReason::UsageLimitExceeded, msg)
    }
    pub fn attribute_not_found(msg: impl Into<String>) -> Self {
        Self::failed(ResultReason::AttributeNotFound, msg)
    }
    pub fn key_value_not_present(msg: impl Into<String>) -> Self {
        Self::failed(ResultReason::KeyValueNotPresent, msg)
    }
    pub fn bad_cryptographic_parameters(msg: impl Into<String>) -> Self {
        Self::failed(ResultReason::BadCryptographicParameters, msg)
    }
    pub fn invalid_object_type(msg: impl Into<String>) -> Self {
        Self::failed(ResultReason::InvalidObjectType, msg)
    }
    /// KMIP 3.0 §6.1.6.1 / §6.1.50.1 — `Invalid CSR` (0x2f): the
    /// Certificate Request Value is malformed, of an unexpected
    /// `Certificate Request Type`, or its self-signature is invalid.
    pub fn invalid_csr(msg: impl Into<String>) -> Self {
        Self::failed(ResultReason::InvalidCsr, msg)
    }
    pub fn wrapping_object_not_found(uid: &str) -> Self {
        // KMIP 3.0 §11 — the *wrapping* object (KEK) UID does not
        // resolve. Distinct from the data object's `ObjectNotFound`.
        Self::failed(
            ResultReason::WrappingObjectNotFound,
            format!("wrapping key (KEK) UID {uid:?} not found"),
        )
    }
    pub fn wrapping_object_archived(uid: &str) -> Self {
        Self::failed(
            ResultReason::WrappingObjectArchived,
            format!("wrapping key (KEK) UID {uid:?} is archived; Recover it before wrapping/unwrapping"),
        )
    }
    pub fn wrapping_object_destroyed(uid: &str) -> Self {
        Self::failed(
            ResultReason::WrappingObjectDestroyed,
            format!("wrapping key (KEK) UID {uid:?} has been destroyed"),
        )
    }
    pub fn circular_link_error(msg: impl Into<String>) -> Self {
        Self::failed(ResultReason::CircularLinkError, msg)
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
        // K14 — `Authentication Not Successful` (spec Table 584).
        assert_eq!(ResultReason::AuthenticationNotSuccessful.to_wire_value(), 0x0000_0003);
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
        // K19 additions — `Result Reason` rows in the OASIS enums JSON.
        assert_eq!(ResultReason::FeatureNotSupported.to_wire_value(),   0x0000_0008);
        // K20 — Derive Key (§6.1.19 Table 304) error-table reasons.
        assert_eq!(ResultReason::KeyValueNotPresent.to_wire_value(),    0x0000_0013);
        assert_eq!(ResultReason::BadCryptographicParameters.to_wire_value(), 0x0000_0024);
        assert_eq!(ResultReason::InvalidObjectType.to_wire_value(),     0x0000_0030);
        assert_eq!(ResultReason::UsageLimitExceeded.to_wire_value(),    0x0000_001a);
        assert_eq!(ResultReason::InvalidTicket.to_wire_value(),         0x0000_0019);
        assert_eq!(ResultReason::AttributeNotFound.to_wire_value(),     0x0000_0021);
        // P2.4 additions — `Result Reason` rows in the OASIS enums JSON.
        assert_eq!(ResultReason::WrappingObjectArchived.to_wire_value(),  0x0000_0040);
        assert_eq!(ResultReason::WrappingObjectDestroyed.to_wire_value(), 0x0000_0041);
        assert_eq!(ResultReason::WrappingObjectNotFound.to_wire_value(),  0x0000_0042);
        assert_eq!(ResultReason::CircularLinkError.to_wire_value(),       0x0000_004d);
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
        assert_eq!(
            KmipError::wrapping_object_not_found("u1").result_reason(),
            ResultReason::WrappingObjectNotFound
        );
        assert_eq!(
            KmipError::wrapping_object_archived("u1").result_reason(),
            ResultReason::WrappingObjectArchived
        );
        assert_eq!(
            KmipError::wrapping_object_destroyed("u1").result_reason(),
            ResultReason::WrappingObjectDestroyed
        );
        assert_eq!(
            KmipError::circular_link_error("x").result_reason(),
            ResultReason::CircularLinkError
        );
    }
}
