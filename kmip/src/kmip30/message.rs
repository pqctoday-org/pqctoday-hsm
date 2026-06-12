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
    /// KMIP 3.0 §9.5 `Batch Error Continuation Option`. Per spec: "If
    /// not specified, then Stop is assumed." We carry `None` to mean
    /// the field was absent, and the dispatcher applies the Stop
    /// default at the consumer site so the absent-vs-explicitly-Stop
    /// distinction is preserved for logging.
    pub batch_error_continuation_option: Option<BatchErrorContinuationOption>,
    /// KMIP 3.0 §9.10 `Maximum Response Size` (bytes). When set, the
    /// server MUST return `OperationFailed / ResponseTooLarge` if
    /// the encoded ResponseMessage would exceed it. `None` ≡ no
    /// limit.
    pub maximum_response_size: Option<i32>,
    /// KMIP 3.0 §8.1.2 `Asynchronous Indicator` Enumeration. This
    /// server has no asynchronous capability, so `Mandatory` fails
    /// every batch item with `OperationNotSupported`; `Optional` /
    /// `Prohibited` / absent all process synchronously (K4).
    pub asynchronous_indicator: Option<AsynchronousIndicator>,
    /// KMIP 3.0 §8.1.2 / §9.4 `Authentication` Structure — "Credential,
    /// MAY be repeated" (spec Table 504). Empty ≡ the Authentication
    /// field was absent from the header. K14: the dispatcher verifies
    /// these against the config-backed credential store when auth is
    /// configured; in open-auth mode (no users configured) they are
    /// carried but ignored.
    pub authentication: Vec<Credential>,
}

/// KMIP 3.0 §9.9 `Credential` — "a structure used for client
/// identification purposes" carried inside the request header's
/// `Authentication` structure. Shape per spec Table 509:
/// `Credential Type` (Enumeration, required) + `Credential Value`
/// (varies by type, required).
///
/// K14 supports verification of `Username and Password` (0x01) only;
/// every other published Credential Type (Device 0x02, Attestation
/// 0x03, One Time Password 0x04, Hashed Password 0x05, Ticket 0x06,
/// Password 0x07, Certificate 0x08 — per
/// `kmip-spec-3.0-tags-enums.json` `Credential Type`) is decoded and
/// carried as [`Credential::Unsupported`] so the header decode never
/// fails on a credential we merely can't verify.
#[derive(Clone, Debug, PartialEq)]
pub enum Credential {
    /// Credential Type `Username and Password` (0x01). Credential
    /// Value per spec Table 510: `Username` (TextString, required) +
    /// `Password` (TextString, optional).
    UsernameAndPassword {
        username: String,
        password: Option<String>,
    },
    /// Any other Credential Type — tolerated on decode, never
    /// verifiable, so under configured auth it fails verification.
    Unsupported { credential_type: u32 },
}

/// KMIP 3.0 §8.1.2 `Asynchronous Indicator` enum (an Enumeration as of
/// KMIP 3.0; it was a Boolean in 1.x/2.x). Codepoints verified against
/// `kmip-spec-3.0-tags-enums.json`:
/// - `Mandatory  = 0x01`: client requires asynchronous processing
/// - `Optional   = 0x02`: server may choose sync or async
/// - `Prohibited = 0x03`: server MUST process synchronously
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum AsynchronousIndicator {
    Mandatory  = 0x0000_0001,
    Optional   = 0x0000_0002,
    Prohibited = 0x0000_0003,
}

impl AsynchronousIndicator {
    pub const fn to_wire_value(self) -> u32 { self as u32 }
    pub const fn from_wire_value(v: u32) -> Option<Self> {
        match v {
            0x01 => Some(Self::Mandatory),
            0x02 => Some(Self::Optional),
            0x03 => Some(Self::Prohibited),
            _ => None,
        }
    }
}

/// KMIP 3.0 §9.5 enum. Codepoints (verified against
/// `kmip-spec-3.0-tags-enums.json`):
/// - `Continue = 0x01`: process every item even after a failure
/// - `Stop     = 0x02`: halt after the first failure; later items are
///                       NOT processed and NOT returned (default)
/// - `Undo     = 0x03`: halt after the first failure AND roll back
///                       earlier successful items, reporting them with
///                       `ResultStatus::OperationUndone`
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum BatchErrorContinuationOption {
    Continue = 0x0000_0001,
    Stop     = 0x0000_0002,
    Undo     = 0x0000_0003,
}

impl BatchErrorContinuationOption {
    pub const fn to_wire_value(self) -> u32 { self as u32 }
    pub const fn from_wire_value(v: u32) -> Option<Self> {
        match v {
            0x01 => Some(Self::Continue),
            0x02 => Some(Self::Stop),
            0x03 => Some(Self::Undo),
            _ => None,
        }
    }
}

impl RequestHeader {
    /// `3.0` header with no optional fields.
    pub fn v3() -> Self {
        Self {
            protocol_version_major: KMIP_VERSION_MAJOR,
            protocol_version_minor: KMIP_VERSION_MINOR,
            time_stamp: None,
            batch_error_continuation_option: None,
            maximum_response_size: None,
            asynchronous_indicator: None,
            authentication: Vec::new(),
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
///
/// `ServerCorrelationValue` is opaque server-generated text included in
/// every response — KMIP Profiles v3.0 §5.1.2 item 11.l ("Baseline
/// Server" capability set) requires support; §4.1.1 item 18 designates
/// its value as a Permitted Test Case Variation so the comparator
/// accepts whatever we emit. We currently emit a monotonic
/// `pqctoday-<unix-nanos>` token; clients echo it via Client
/// Correlation Value if they choose.
#[derive(Clone, Debug, PartialEq)]
pub struct ResponseHeader {
    pub protocol_version_major: i32,
    pub protocol_version_minor: i32,
    pub time_stamp: OffsetDateTime,
    pub server_correlation_value: Option<String>,
}

impl ResponseHeader {
    pub fn v3_now() -> Self {
        let now = OffsetDateTime::now_utc();
        Self {
            protocol_version_major: KMIP_VERSION_MAJOR,
            protocol_version_minor: KMIP_VERSION_MINOR,
            time_stamp: now,
            server_correlation_value: Some(format!(
                "pqctoday-{}",
                now.unix_timestamp_nanos()
            )),
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
    Mac(super::ops::MacRequest),
    MacVerify(super::ops::MacVerifyRequest),
    Hash(super::ops::HashRequest),
    CreateCredential(super::ops::CreateCredentialRequest),
    CreateGroup(super::ops::CreateGroupRequest),
    CreateUser(super::ops::CreateUserRequest),
    Log(super::ops::LogRequest),
    Login(super::ops::LoginRequest),
    Logout(super::ops::LogoutRequest),
    RngRetrieve(super::ops::RngRetrieveRequest),
    RngSeed(super::ops::RngSeedRequest),
    Pkcs11(super::ops::Pkcs11Request),
    // K19 — Baseline client-to-server ops (§6.1.26/27/58/59).
    GetUsageAllocation(super::ops::GetUsageAllocationRequest),
    GetConstraints(super::ops::GetConstraintsRequest),
    SetDefaults(super::ops::SetDefaultsRequest),
    SetEndpointRole(super::ops::SetEndpointRoleRequest),
    /// K20 — §6.1.18 Derive Key.
    DeriveKey(super::ops::DeriveKeyRequest),
    /// R7 Phase 1 sentinel — emitted by `decode_request_message` when
    /// a per-BatchItem payload fails to decode but the outer envelope
    /// is intact. The dispatcher recognises it and emits a per-item
    /// `OperationFailed / InvalidMessage` ResponseBatchItem with the
    /// `operation_echo` (when readable) per KMIP 3.0 §8.2.3.
    DecodeFailed {
        operation_echo: Option<super::ops::Operation>,
        message: String,
        /// K8 — the Result Reason the dispatcher emits for this item.
        /// `InvalidMessage` for generic decode failures; specific
        /// reasons when the spec names one (e.g. `Key Format Type Not
        /// Supported (0x10)` for an unknown KeyFormatType codepoint).
        reason: crate::error::ResultReason,
    },
    /// K3 marker — the Operation codepoint is a published KMIP 3.0
    /// value (the message is well-formed) but this server has no
    /// handler for it. The dispatcher fails the batch item with
    /// `OperationFailed / OperationNotSupported (0x05)` per §9.2,
    /// so Batch Error Continuation applies and sibling items still
    /// process. Truly-unknown codepoints keep the
    /// [`Self::DecodeFailed`] → `InvalidMessage` path.
    Unsupported(super::ops::Operation),
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
    Mac(super::ops::MacResponse),
    MacVerify(super::ops::MacVerifyResponse),
    Hash(super::ops::HashResponse),
    CreateCredential(super::ops::CreateCredentialResponse),
    CreateGroup(super::ops::CreateGroupResponse),
    CreateUser(super::ops::CreateUserResponse),
    Log(super::ops::LogResponse),
    Login(super::ops::LoginResponse),
    Logout(super::ops::LogoutResponse),
    RngRetrieve(super::ops::RngRetrieveResponse),
    RngSeed(super::ops::RngSeedResponse),
    Pkcs11(super::ops::Pkcs11Response),
    // K19 — Baseline client-to-server ops (§6.1.26/27/58/59).
    GetUsageAllocation(super::ops::GetUsageAllocationResponse),
    GetConstraints(super::ops::GetConstraintsResponse),
    SetDefaults(super::ops::SetDefaultsResponse),
    /// K20 — §6.1.18 Derive Key.
    DeriveKey(super::ops::DeriveKeyResponse),
    SetEndpointRole(super::ops::SetEndpointRoleResponse),
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
            Self::Mac(_)              => Operation::MAC,
            Self::MacVerify(_)        => Operation::MACVerify,
            Self::Hash(_)             => Operation::Hash,
            Self::CreateCredential(_) => Operation::CreateCredential,
            Self::CreateGroup(_)      => Operation::CreateGroup,
            Self::CreateUser(_)       => Operation::CreateUser,
            Self::Log(_)              => Operation::Log,
            Self::Login(_)            => Operation::Login,
            Self::Logout(_)           => Operation::Logout,
            Self::RngRetrieve(_)      => Operation::RNGRetrieve,
            Self::RngSeed(_)          => Operation::RNGSeed,
            Self::Pkcs11(_)           => Operation::Pkcs11,
            Self::GetUsageAllocation(_) => Operation::GetUsageAllocation,
            Self::GetConstraints(_)   => Operation::GetConstraints,
            Self::SetDefaults(_)      => Operation::SetDefaults,
            Self::SetEndpointRole(_)  => Operation::SetEndpointRole,
            Self::DeriveKey(_)        => Operation::DeriveKey,
            // Echo the original Operation when we were able to read it
            // before the payload decode failed; fall back to `Ping`
            // (whose handler we already special-case in the
            // dispatcher) so callers always see a valid Operation.
            Self::DecodeFailed { operation_echo, .. } => {
                operation_echo.unwrap_or(Operation::Ping)
            }
            // Recognized-but-unsupported — echo the real Operation so
            // the §8.2.3 response Batch Item names what the client sent.
            Self::Unsupported(op) => *op,
        }
    }

    /// UIDs the op consumes as input. The dispatcher's R7 Phase 4
    /// (§9.5 Undo) wave snapshots these BEFORE the op runs so it can
    /// roll them back on a later failure. Read-only ops (Query / Get
    /// / Locate / Sign / Verify / …) return an empty slice — they
    /// have no side effect to revert.
    pub fn touched_uids(&self) -> Vec<&str> {
        match self {
            Self::Activate(r)         => vec![r.uid.as_str()],
            Self::Revoke(r)           => vec![r.uid.as_str()],
            Self::Destroy(r)          => vec![r.uid.as_str()],
            Self::Deactivate(r)       => vec![r.uid.as_str()],
            Self::Archive(r)          => vec![r.uid.as_str()],
            Self::Recover(r)          => vec![r.uid.as_str()],
            Self::Obliterate(r)       => vec![r.uid.as_str()],
            Self::AddAttribute(r)     => vec![r.uid.as_str()],
            Self::ModifyAttribute(r)  => vec![r.uid.as_str()],
            Self::DeleteAttribute(r)  => vec![r.uid.as_str()],
            Self::SetAttribute(r)     => vec![r.uid.as_str()],
            Self::AdjustAttribute(r)  => vec![r.uid.as_str()],
            // Import always carries an explicit UID. Register MAY
            // — the server-allocated case is captured post-hoc in
            // `created_uids_after`.
            Self::Import(r)           => vec![r.uid.as_str()],
            // K19 — GetUsageAllocation decrements the object's
            // remaining Usage Limits Count; snapshot for §9.5 Undo.
            Self::GetUsageAllocation(r) => vec![r.uid.as_str()],
            // K20 — Derive Key writes a `Derived Object Link` onto
            // every base object (§6.1.18); snapshot them for Undo.
            Self::DeriveKey(r) => r.uids.iter().map(|s| s.as_str()).collect(),
            // Read-only / output-only — no rollback needed.
            _ => Vec::new(),
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
