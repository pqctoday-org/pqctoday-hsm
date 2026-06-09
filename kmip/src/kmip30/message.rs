//! KMIP 3.0 message envelope types — Request/Response Message + Header +
//! Batch Item per OASIS KMIP 3.0 §8.1 and §8.2.
//!
//! ## Spec-verified shape (verified 2026-06-07 against
//! `spec/oasis-kmip-3.0/kmip-spec-v3.0.pdf`)
//!
//! - **§8.1.1 Request Message** = Request Header + one or more Batch Item
//! - **§8.1.2 Request Header** = Protocol Version + (optional fields:
//!   Maximum Response Size, Client/Server Correlation Value, Asynchronous
//!   Indicator, Attestation Capable Indicator, Attestation Type,
//!   Authentication, Batch Error Continuation Option, Time Stamp)
//! - **§8.1.3 Request Batch Item** = Operation + (optional Ephemeral) +
//!   Request Payload + (optional Message Extension)
//! - **§8.2.1 Response Message** = Response Header + one or more Batch Item
//! - **§8.2.2 Response Header** = Protocol Version + Time Stamp + (optional
//!   fields, none required for v0.1)
//! - **§8.2.3 Response Batch Item** = (Operation echo) + Result Status +
//!   (Result Reason if failure) + (Result Message) + (Response Payload if
//!   not failure)
//!
//! **KMIP 3.0 simplification from 2.x:** the spec **removed** `Batch Count`
//! (was 0x42000d in 2.x) and `Unique Batch Item ID` (was 0x420093). Batch
//! items are now correlated by position only. Confirmed by inspecting
//! §8.1.2 / §8.1.3 / §8.2.3 in the PDF — those tags are reserved/absent
//! in our spec extraction (`spec/oasis-kmip-3.0/kmip-spec-3.0-tags-enums.json`).
//!
//! ## v0.1 simplifying assumptions
//!
//! - **One batch item per message.** The wire codec handles a single
//!   Batch Item child of the Request/Response Message structure. Multi-op
//!   batching is a spec feature deferred to v0.2.
//! - **Protocol Version hardcoded `3.0`** (major=3, minor=0) — this is
//!   the only version the engine speaks.
//! - **Optional header fields omitted** — no Maximum Response Size,
//!   Correlation Value, Asynchronous Indicator, Attestation, Authentication
//!   in v0.1.

use time::OffsetDateTime;

use super::ops::Operation;

/// KMIP 3.0 Protocol Version `(3, 0)` — the only one this engine speaks.
pub const KMIP_VERSION_MAJOR: i32 = 3;
pub const KMIP_VERSION_MINOR: i32 = 0;

/// §8.1.1 Request Message — top-level wire envelope inbound to the server.
#[derive(Clone, Debug, PartialEq)]
pub struct RequestMessage {
    pub header: RequestHeader,
    /// v0.1 ships one batch item per message; the field type is `Vec` to
    /// match the spec shape so v0.2 multi-op batching is an additive change.
    pub batch_items: Vec<RequestBatchItem>,
}

/// §8.1.2 Request Header.
#[derive(Clone, Debug, PartialEq)]
pub struct RequestHeader {
    pub protocol_version_major: i32,
    pub protocol_version_minor: i32,
    pub time_stamp: Option<OffsetDateTime>,
}

impl RequestHeader {
    /// `3.0` header with no optional fields.
    pub fn v3() -> Self {
        Self {
            protocol_version_major: KMIP_VERSION_MAJOR,
            protocol_version_minor: KMIP_VERSION_MINOR,
            time_stamp: None,
        }
    }
}

/// §8.1.3 Request Batch Item — wraps one operation's request payload.
#[derive(Clone, Debug, PartialEq)]
pub struct RequestBatchItem {
    pub operation: Operation,
    /// Variant-typed payload — the concrete struct shape per op (see
    /// [`super::ops`]). v0.1 uses a typed enum so the dispatcher pattern-
    /// matches without re-decoding.
    pub payload: RequestPayload,
}

/// §8.2.1 Response Message.
#[derive(Clone, Debug, PartialEq)]
pub struct ResponseMessage {
    pub header: ResponseHeader,
    pub batch_items: Vec<ResponseBatchItem>,
}

/// §8.2.2 Response Header — minimal v0.1 shape.
#[derive(Clone, Debug, PartialEq)]
pub struct ResponseHeader {
    pub protocol_version_major: i32,
    pub protocol_version_minor: i32,
    pub time_stamp: OffsetDateTime,
}

impl ResponseHeader {
    pub fn v3_now() -> Self {
        Self {
            protocol_version_major: KMIP_VERSION_MAJOR,
            protocol_version_minor: KMIP_VERSION_MINOR,
            time_stamp: OffsetDateTime::now_utc(),
        }
    }
}

/// §8.2.3 Response Batch Item.
#[derive(Clone, Debug, PartialEq)]
pub struct ResponseBatchItem {
    /// Echoes the request's Operation when known (§8.2.3 "Yes, if
    /// specified in Request Batch Item").
    pub operation: Option<Operation>,
    pub result_status: ResultStatus,
    /// REQUIRED if `result_status == Failure`, otherwise omitted.
    pub result_reason: Option<u32>,
    pub result_message: Option<String>,
    /// REQUIRED on success, omitted on failure.
    pub payload: Option<ResponsePayload>,
}

/// §6.1 / §11.5 Result Status — wire-format Enumeration codepoint.
/// Codepoints verified from `kmip-spec-3.0-tags-enums.json` (`Result Status`
/// enum).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum ResultStatus {
    Success         = 0x0000_0000,
    OperationFailed = 0x0000_0001,
    OperationPending = 0x0000_0002,
    OperationUndone = 0x0000_0003,
}

impl ResultStatus {
    pub const fn to_wire_value(self) -> u32 {
        self as u32
    }
    pub const fn from_wire_value(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::Success),
            1 => Some(Self::OperationFailed),
            2 => Some(Self::OperationPending),
            3 => Some(Self::OperationUndone),
            _ => None,
        }
    }
}

/// Typed request payload — one variant per supported op.
#[derive(Clone, Debug, PartialEq)]
pub enum RequestPayload {
    Query(super::ops::QueryRequest),
    Create(super::ops::CreateRequest),
    CreateKeyPair(super::ops::CreateKeyPairRequest),
    Get(super::ops::GetRequest),
    GetAttributes(super::ops::GetAttributesRequest),
    GetAttributeList(super::ops::GetAttributeListRequest),
    AddAttribute(super::ops::AddAttributeRequest),
    ModifyAttribute(super::ops::ModifyAttributeRequest),
    DeleteAttribute(super::ops::DeleteAttributeRequest),
    SetAttribute(super::ops::SetAttributeRequest),
    AdjustAttribute(super::ops::AdjustAttributeRequest),
    Locate(super::ops::LocateRequest),
    Activate(super::ops::ActivateRequest),
    Revoke(super::ops::RevokeRequest),
    Destroy(super::ops::DestroyRequest),
    Encrypt(super::ops::EncryptRequest),
    Decrypt(super::ops::DecryptRequest),
    Sign(super::ops::SignRequest),
    SignatureVerify(super::ops::SignatureVerifyRequest),
    Interop(super::ops::InteropRequest),
    Register(super::ops::RegisterRequest),
    Import(super::ops::ImportRequest),
    Export(super::ops::ExportRequest),
    Deactivate(super::ops::DeactivateRequest),
    Check(super::ops::CheckRequest),
    Archive(super::ops::ArchiveRequest),
    Recover(super::ops::RecoverRequest),
    Obliterate(super::ops::ObliterateRequest),
    DiscoverVersions(super::ops::DiscoverVersionsRequest),
    Ping(super::ops::PingRequest),
}

/// Typed response payload — one variant per supported op.
#[derive(Clone, Debug, PartialEq)]
pub enum ResponsePayload {
    Query(super::ops::QueryResponse),
    Create(super::ops::CreateResponse),
    CreateKeyPair(super::ops::CreateKeyPairResponse),
    Get(super::ops::GetResponse),
    GetAttributes(super::ops::GetAttributesResponse),
    GetAttributeList(super::ops::GetAttributeListResponse),
    AddAttribute(super::ops::AddAttributeResponse),
    ModifyAttribute(super::ops::ModifyAttributeResponse),
    DeleteAttribute(super::ops::DeleteAttributeResponse),
    SetAttribute(super::ops::SetAttributeResponse),
    AdjustAttribute(super::ops::AdjustAttributeResponse),
    Locate(super::ops::LocateResponse),
    Activate(super::ops::ActivateResponse),
    Revoke(super::ops::RevokeResponse),
    Destroy(super::ops::DestroyResponse),
    Encrypt(super::ops::EncryptResponse),
    Decrypt(super::ops::DecryptResponse),
    Sign(super::ops::SignResponse),
    SignatureVerify(super::ops::SignatureVerifyResponse),
    Interop(super::ops::InteropResponse),
    Register(super::ops::RegisterResponse),
    Import(super::ops::ImportResponse),
    Export(super::ops::ExportResponse),
    Deactivate(super::ops::DeactivateResponse),
    Check(super::ops::CheckResponse),
    Archive(super::ops::ArchiveResponse),
    Recover(super::ops::RecoverResponse),
    Obliterate(super::ops::ObliterateResponse),
    DiscoverVersions(super::ops::DiscoverVersionsResponse),
    Ping(super::ops::PingResponse),
}

impl RequestPayload {
    /// Operation codepoint that goes in the Batch Item's Operation field.
    pub fn operation(&self) -> Operation {
        match self {
            Self::Query(_)            => Operation::Query,
            Self::Create(_)           => Operation::Create,
            Self::CreateKeyPair(_)    => Operation::CreateKeyPair,
            Self::Get(_)              => Operation::Get,
            Self::GetAttributes(_)    => Operation::GetAttributes,
            Self::GetAttributeList(_) => Operation::GetAttributeList,
            Self::AddAttribute(_)     => Operation::AddAttribute,
            Self::ModifyAttribute(_)  => Operation::ModifyAttribute,
            Self::DeleteAttribute(_)  => Operation::DeleteAttribute,
            Self::SetAttribute(_)     => Operation::SetAttribute,
            Self::AdjustAttribute(_)  => Operation::AdjustAttribute,
            Self::Locate(_)           => Operation::Locate,
            Self::Activate(_)         => Operation::Activate,
            Self::Revoke(_)           => Operation::Revoke,
            Self::Destroy(_)          => Operation::Destroy,
            Self::Encrypt(_)          => Operation::Encrypt,
            Self::Decrypt(_)          => Operation::Decrypt,
            Self::Sign(_)             => Operation::Sign,
            Self::SignatureVerify(_)  => Operation::SignatureVerify,
            Self::Interop(_)          => Operation::Interop,
            Self::Register(_)         => Operation::Register,
            Self::Import(_)           => Operation::Import,
            Self::Export(_)           => Operation::Export,
            Self::Deactivate(_)       => Operation::Deactivate,
            Self::Check(_)            => Operation::Check,
            Self::Archive(_)          => Operation::Archive,
            Self::Recover(_)          => Operation::Recover,
            Self::Obliterate(_)       => Operation::Obliterate,
            Self::DiscoverVersions(_) => Operation::DiscoverVersions,
            Self::Ping(_)             => Operation::Ping,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn result_status_codepoints() {
        assert_eq!(ResultStatus::Success.to_wire_value(),         0);
        assert_eq!(ResultStatus::OperationFailed.to_wire_value(), 1);
        assert_eq!(ResultStatus::OperationPending.to_wire_value(),2);
        assert_eq!(ResultStatus::OperationUndone.to_wire_value(), 3);
    }

    #[test]
    fn protocol_version_pinned_to_three_zero() {
        assert_eq!(KMIP_VERSION_MAJOR, 3);
        assert_eq!(KMIP_VERSION_MINOR, 0);
    }
}
