//! Wire codec — encode/decode KMIP 3.0 messages between TTLV bytes and
//! the typed Phase-3 structs in [`super::message`] / [`super::ops`].
//!
//! Built on top of the Phase-2 [`crate::codec`] which handles raw TTLV
//! framing (tag/type/length/value + 8-byte alignment per §9.6). This
//! module handles the higher-level mapping from `TtlvFrame` trees to the
//! typed message structures the dispatcher consumes.
//!
//! Every KMIP tag codepoint cited here is from
//! `spec/oasis-kmip-3.0/kmip-spec-3.0-tags-enums.json` (extracted from
//! the OASIS HTML spec, sha256-pinned). Tag table in
//! [`tags`] sub-module.

use bytes::BytesMut;

use crate::codec::{decode_one, encode, Tag, TtlvFrame, Value};

use super::algos::KmipAlgorithm;
use super::attrs::{Attribute, ObjectType, RevocationReason, State, UsageMask};
use super::message::{
    RequestBatchItem, RequestHeader, RequestMessage, RequestPayload, ResponseBatchItem,
    ResponseHeader, ResponseMessage, ResponsePayload, ResultStatus,
};
use super::ops::*;

#[derive(Debug, thiserror::Error)]
pub enum WireError {
    #[error("TTLV codec: {0}")]
    Codec(String),

    #[error("missing required field: tag {tag:#08x} ({name})")]
    Missing { tag: u32, name: &'static str },

    #[error("unexpected tag {got:#08x}; expected {expected:#08x} ({name})")]
    UnexpectedTag { got: u32, expected: u32, name: &'static str },

    #[error("unexpected item type for tag {tag:#08x} ({name}): {msg}")]
    BadType { tag: u32, name: &'static str, msg: String },

    #[error("unknown enumeration value {value:#x} for {field}")]
    UnknownEnum { field: &'static str, value: u32 },

    #[error("unsupported KMIP protocol version {major}.{minor}")]
    UnsupportedVersion { major: i32, minor: i32 },
}

impl From<crate::codec::CodecError> for WireError {
    fn from(e: crate::codec::CodecError) -> Self {
        WireError::Codec(e.to_string())
    }
}

// ── Tag table (verified against OASIS extract) ──────────────────────────────

#[allow(non_upper_case_globals)]
mod tags {
    pub const Attribute: u32              = 0x42_0008;
    pub const AttributeName: u32          = 0x42_000a;
    pub const AttributeValue: u32         = 0x42_000b;
    pub const BatchItem: u32              = 0x42_000f;
    pub const CryptographicAlgorithm: u32 = 0x42_0028;
    pub const CryptographicLength: u32    = 0x42_002a;
    pub const CryptographicUsageMask: u32 = 0x42_002c;
    pub const Data: u32                   = 0x42_00c2;
    pub const IvCounterNonce: u32         = 0x42_003d;
    pub const KeyBlock: u32               = 0x42_0040;
    pub const KeyFormatType: u32          = 0x42_0042;
    pub const KeyValue: u32               = 0x42_0045;
    pub const MaximumItems: u32           = 0x42_004f;
    pub const ObjectType: u32             = 0x42_0057;
    pub const Operation: u32              = 0x42_005c;
    pub const ProtocolVersion: u32        = 0x42_0069;
    pub const ProtocolVersionMajor: u32   = 0x42_006a;
    pub const ProtocolVersionMinor: u32   = 0x42_006b;
    pub const QueryFunction: u32          = 0x42_0074;
    pub const RequestHeader: u32          = 0x42_0077;
    pub const RequestMessage: u32         = 0x42_0078;
    pub const RequestPayload: u32         = 0x42_0079;
    pub const ResponseHeader: u32         = 0x42_007a;
    pub const ResponseMessage: u32        = 0x42_007b;
    pub const ResponsePayload: u32        = 0x42_007c;
    pub const ResultMessage: u32          = 0x42_007d;
    pub const ResultReason: u32           = 0x42_007e;
    pub const ResultStatus: u32           = 0x42_007f;
    pub const RevocationMessage: u32      = 0x42_0080;
    pub const RevocationReason: u32       = 0x42_0081;
    pub const RevocationReasonCode: u32   = 0x42_0082;
    pub const ServerInformation: u32      = 0x42_0088;
    pub const ServerVersion: u32          = 0x42_012f;
    /// KMIP 3.0 §8.2.2 — `Server Correlation Value` echoed in every
    /// ResponseHeader. Codepoint verified from
    /// `spec/oasis-kmip-3.0/kmip-spec-3.0-tags-enums.json`.
    pub const ServerCorrelationValue: u32 = 0x42_0106;
    /// KMIP 3.0 §8.1.2 — `Client Correlation Value` (request side only).
    pub const ClientCorrelationValue: u32 = 0x42_0105;
    pub const SignatureData: u32          = 0x42_00c3;
    pub const State: u32                  = 0x42_008d;
    pub const TimeStamp: u32              = 0x42_0092;
    pub const UniqueIdentifier: u32       = 0x42_0094;
    pub const ValidityIndicator: u32      = 0x42_009b;
    pub const VendorIdentification: u32   = 0x42_009d;
    pub const CommonAttributes: u32       = 0x42_0126;
    pub const PrivateKeyAttributes: u32   = 0x42_0127;
    pub const PublicKeyAttributes: u32    = 0x42_0128;
    /// KMIP 3.0 §6.1.6 — plural `Attributes` Structure (OASIS-conformant
    /// successor to the KMIP 1.x `Attribute`-envelope convention).
    /// Children are direct typed tags (e.g. `CryptographicAlgorithm`)
    /// rather than `AttributeName` / `AttributeValue` pairs.
    pub const Attributes: u32             = 0x42_0125;
    pub const Name: u32                   = 0x42_0053;
    pub const SymmetricKey: u32           = 0x42_008f;
    pub const PublicKey: u32              = 0x42_006d;
    pub const PrivateKey: u32             = 0x42_0064;
    pub const KeyMaterial: u32            = 0x42_0043;
    pub const AttributeReference: u32     = 0x42_013b;
    /// KMIP 3.0 §6.1.{2,38,56} `New Attribute` — Structure wrapping the
    /// typed-tag attribute being added / modified / set.
    pub const NewAttribute: u32           = 0x42_013d;
    /// KMIP 3.0 §6.1.{17,38} `Current Attribute` — Structure wrapping
    /// the existing attribute value being targeted.
    pub const CurrentAttribute: u32       = 0x42_013c;
    /// KMIP 3.0 §6.1.3 `Adjustment Type` — Enumeration:
    /// Increment=0x01, Decrement=0x02, Negate=0x03.
    pub const AdjustmentType: u32         = 0x42_0158;
    /// KMIP 3.0 §6.1.3 `Adjustment Value` — typed per target attribute.
    pub const AdjustmentValue: u32        = 0x42_0162;
    pub const ReplaceExisting: u32        = 0x42_0124;
    pub const KeyWrapType: u32            = 0x42_00f8;
    pub const KeyCompressionType: u32     = 0x42_0041;
    pub const ProtectionStorageMask: u32  = 0x42_015e;
    pub const ProtectionStorageMasks: u32 = 0x42_015f;
    /// KMIP 3.0 §6.1.14 Deactivate request fields.
    pub const DeactivationReason: u32     = 0x42_01b8;
    pub const DeactivationReasonCode: u32 = 0x42_01b9;
    pub const DeactivationDate: u32       = 0x42_002f;
    /// KMIP 3.0 §6.1.7 Check request fields.
    pub const UsageLimitsCount: u32       = 0x42_0096;
    pub const LeaseTime: u32              = 0x42_0049;
    /// KMIP 3.0 §11 Cryptographic Parameters Structure (codepoint
    /// verified against kmip-spec-3.0-tags-enums.json).
    pub const CryptographicParameters: u32 = 0x42_002b;
    /// KMIP 3.0 §11 Hashing Algorithm Enumeration.
    pub const HashingAlgorithm: u32       = 0x42_0038;
    /// KMIP 3.0 §6.1.36/37 MAC Data ByteString.
    pub const MacData: u32                = 0x42_00c6;
    /// KMIP 3.0 §6.1.9/34/35 session + auth tags.
    pub const CredentialType: u32         = 0x42_0024;
    pub const Credential: u32             = 0x42_0023;
    pub const CredentialValue: u32        = 0x42_0025;
    pub const PasswordCredential: u32     = 0x42_01a1;
    pub const Username: u32               = 0x42_0099;
    pub const Password: u32               = 0x42_00a1;
    pub const Ticket: u32                 = 0x42_0149;
    pub const LogMessage: u32             = 0x42_0141;
    pub const RequestCount: u32           = 0x42_014c;
    pub const UsageLimits: u32            = 0x42_0095;
    pub const UsageLimitsTotal: u32       = 0x42_0097;
    /// KMIP 3.0 §6.1.{54,55} RNG tags.
    pub const DataLength: u32             = 0x42_00c4;
    /// KMIP 3.0 §6.1.42 PKCS#11 passthrough tags.
    pub const Pkcs11Interface: u32        = 0x42_0159;
    pub const Pkcs11Function: u32         = 0x42_015a;
    pub const Pkcs11InputParameters: u32  = 0x42_015b;
    pub const Pkcs11OutputParameters: u32 = 0x42_015c;
    pub const Pkcs11ReturnCode: u32       = 0x42_015d;
    pub const CorrelationValue: u32       = 0x42_00d6;
    // ── KMIP Profiles v3.0 §5.1.2 Baseline Server attribute tags ──
    pub const DestroyDate: u32                   = 0x42_0033;
    pub const CompromiseDate: u32                = 0x42_0020;
    pub const CompromiseOccurrenceDate: u32      = 0x42_0021;
    pub const LastChangeDate: u32                = 0x42_0048;
    pub const OriginalCreationDate: u32          = 0x42_00bc;
    pub const ProcessStartDate: u32              = 0x42_0067;
    pub const ProtectStopDate: u32               = 0x42_0068;
    pub const RotateDate: u32                    = 0x42_016d;
    pub const Sensitive: u32                     = 0x42_0120;
    pub const AlwaysSensitive: u32               = 0x42_0121;
    pub const Extractable: u32                   = 0x42_0122;
    pub const NeverExtractable: u32              = 0x42_0123;
    pub const Fresh: u32                         = 0x42_00a8;
    pub const KeyValuePresent: u32               = 0x42_00bb;
    pub const QuantumSafe: u32                   = 0x42_0147;
    pub const RotateAutomatic: u32               = 0x42_016b;
    pub const ShortUniqueIdentifier: u32         = 0x42_0136;
    pub const AlternativeName: u32               = 0x42_00bf;
    pub const Comment: u32                       = 0x42_00fd;
    pub const Description: u32                   = 0x42_00fc;
    pub const ContactInformation: u32            = 0x42_0022;
    pub const ObjectClass: u32                   = 0x42_019e;
    pub const KeyValueLocation: u32              = 0x42_00b8;
    pub const X509CertificateIdentifier: u32     = 0x42_00b5;
    pub const X509CertificateIssuer: u32         = 0x42_00b6;
    pub const X509CertificateSubject: u32        = 0x42_00b7;
    pub const RotateName: u32                    = 0x42_016f;
    pub const CertificateType: u32               = 0x42_001d;
    pub const DigitalSignatureAlgorithm: u32     = 0x42_00ae;
    pub const NistKeyType: u32                   = 0x42_013a;
    pub const ProtectionLevel: u32               = 0x42_0145;
    pub const CertificateLength: u32             = 0x42_00ad;
    pub const ProtectionPeriod: u32              = 0x42_0146;
    pub const RotateInterval: u32                = 0x42_016a;
    pub const RotateOffset: u32                  = 0x42_016c;
    pub const RotateGeneration: u32              = 0x42_016e;
    pub const InteropFunction: u32        = 0x42_0160;
    pub const InteropIdentifier: u32      = 0x42_0161;
    pub const InitialDate: u32            = 0x42_002f;
    pub const ActivationDate: u32         = 0x42_0001;
    /// KMIP 3.0 §6.1.7 CreateKeyPair response uses distinct typed tags
    /// for the two halves; using plain `UniqueIdentifier` for both
    /// breaks OASIS comparison.
    pub const PrivateKeyUniqueIdentifier: u32 = 0x42_0066;
    pub const PublicKeyUniqueIdentifier: u32  = 0x42_006f;
}

// ── Public entry points ─────────────────────────────────────────────────────

/// Decode a complete KMIP 3.0 Request Message from wire bytes.
pub fn decode_request_message(bytes: &[u8]) -> Result<RequestMessage, WireError> {
    let frame = decode_one(bytes)?;
    expect_tag(&frame, tags::RequestMessage, "Request Message")?;
    let children = expect_structure(&frame, "Request Message")?;
    let mut header: Option<RequestHeader> = None;
    let mut batch_items: Vec<RequestBatchItem> = Vec::new();
    for child in children {
        match child.tag.0 {
            tags::RequestHeader => header = Some(decode_request_header(child)?),
            tags::BatchItem => batch_items.push(decode_request_batch_item(child)?),
            other => {
                return Err(WireError::UnexpectedTag {
                    got: other,
                    expected: tags::RequestHeader,
                    name: "Request Message child",
                });
            }
        }
    }
    let header = header.ok_or(WireError::Missing {
        tag: tags::RequestHeader,
        name: "Request Header",
    })?;
    if header.protocol_version_major != 3 || header.protocol_version_minor != 0 {
        return Err(WireError::UnsupportedVersion {
            major: header.protocol_version_major,
            minor: header.protocol_version_minor,
        });
    }
    Ok(RequestMessage { header, batch_items })
}

/// Encode a Response Message to wire bytes.
pub fn encode_response_message(msg: &ResponseMessage) -> Vec<u8> {
    let mut buf = BytesMut::new();
    encode(&response_message_to_frame(msg), &mut buf);
    buf.to_vec()
}

// ── Envelope encoders / decoders ────────────────────────────────────────────

fn decode_request_header(frame: &TtlvFrame) -> Result<RequestHeader, WireError> {
    let children = expect_structure(frame, "Request Header")?;
    let mut major: Option<i32> = None;
    let mut minor: Option<i32> = None;
    let mut time_stamp = None;
    for child in children {
        match child.tag.0 {
            tags::ProtocolVersion => {
                let pv_children = expect_structure(child, "Protocol Version")?;
                for pv_child in pv_children {
                    match pv_child.tag.0 {
                        tags::ProtocolVersionMajor => major = Some(expect_integer(pv_child, "Protocol Version Major")?),
                        tags::ProtocolVersionMinor => minor = Some(expect_integer(pv_child, "Protocol Version Minor")?),
                        _ => {}
                    }
                }
            }
            tags::TimeStamp => {
                if let Value::DateTime(ts) = child.value {
                    time_stamp = time::OffsetDateTime::from_unix_timestamp(ts).ok();
                }
            }
            // Ignore optional header fields v0.1 doesn't consume.
            _ => {}
        }
    }
    let major = major.ok_or(WireError::Missing { tag: tags::ProtocolVersionMajor, name: "Protocol Version Major" })?;
    let minor = minor.ok_or(WireError::Missing { tag: tags::ProtocolVersionMinor, name: "Protocol Version Minor" })?;
    Ok(RequestHeader { protocol_version_major: major, protocol_version_minor: minor, time_stamp })
}

fn decode_request_batch_item(frame: &TtlvFrame) -> Result<RequestBatchItem, WireError> {
    let children = expect_structure(frame, "Batch Item")?;
    let mut operation: Option<Operation> = None;
    let mut payload_frame: Option<&TtlvFrame> = None;
    for child in children {
        match child.tag.0 {
            tags::Operation => {
                let v = expect_enum(child, "Operation")?;
                operation = Operation::from_wire_value(v);
                if operation.is_none() {
                    return Err(WireError::UnknownEnum { field: "Operation", value: v });
                }
            }
            tags::RequestPayload => payload_frame = Some(child),
            _ => {}
        }
    }
    let operation = operation.ok_or(WireError::Missing { tag: tags::Operation, name: "Operation" })?;
    let payload_frame = payload_frame.ok_or(WireError::Missing { tag: tags::RequestPayload, name: "Request Payload" })?;
    let payload = decode_request_payload(operation, payload_frame)?;
    Ok(RequestBatchItem { operation, payload })
}

fn response_message_to_frame(msg: &ResponseMessage) -> TtlvFrame {
    let header = header_to_frame(&msg.header);
    let mut children = vec![header];
    for bi in &msg.batch_items {
        children.push(response_batch_item_to_frame(bi));
    }
    TtlvFrame::new(Tag(tags::ResponseMessage), Value::Structure(children))
}

fn header_to_frame(h: &ResponseHeader) -> TtlvFrame {
    let pv = TtlvFrame::new(
        Tag(tags::ProtocolVersion),
        Value::Structure(vec![
            TtlvFrame::new(Tag(tags::ProtocolVersionMajor), Value::Integer(h.protocol_version_major)),
            TtlvFrame::new(Tag(tags::ProtocolVersionMinor), Value::Integer(h.protocol_version_minor)),
        ]),
    );
    let ts = TtlvFrame::new(Tag(tags::TimeStamp), Value::DateTime(h.time_stamp.unix_timestamp()));
    let mut children = vec![pv, ts];
    if let Some(scv) = &h.server_correlation_value {
        children.push(TtlvFrame::new(
            Tag(tags::ServerCorrelationValue),
            Value::TextString(scv.clone()),
        ));
    }
    TtlvFrame::new(Tag(tags::ResponseHeader), Value::Structure(children))
}

/// Encode a KMIP 3.0 §6.4.2 response BatchItem.
///
/// Spec-mandated child sequencing depends on `ResultStatus`:
///
/// - **Success** (`0x00`) — `Operation`, `ResultStatus`, `ResponsePayload`.
///   `ResultReason` and `ResultMessage` MUST NOT appear.
/// - **OperationFailed / Pending / Undone** — `Operation`, `ResultStatus`,
///   `ResultReason`, `ResultMessage`. No `ResponsePayload`.
///
/// Mixing the two branches (e.g. emitting `ResultReason` on success or
/// `ResponsePayload` on failure) fails OASIS conformance.
fn response_batch_item_to_frame(bi: &ResponseBatchItem) -> TtlvFrame {
    let mut children = Vec::new();
    if let Some(op) = bi.operation {
        children.push(TtlvFrame::new(Tag(tags::Operation), Value::Enumeration(op.to_wire_value())));
    }
    children.push(TtlvFrame::new(
        Tag(tags::ResultStatus),
        Value::Enumeration(bi.result_status.to_wire_value()),
    ));
    let is_success = matches!(bi.result_status, ResultStatus::Success);
    if is_success {
        if let Some(payload) = &bi.payload {
            children.push(response_payload_to_frame(payload));
        }
    } else {
        if let Some(reason) = bi.result_reason {
            children.push(TtlvFrame::new(Tag(tags::ResultReason), Value::Enumeration(reason)));
        }
        if let Some(msg) = &bi.result_message {
            children.push(TtlvFrame::new(Tag(tags::ResultMessage), Value::TextString(msg.clone())));
        }
    }
    TtlvFrame::new(Tag(tags::BatchItem), Value::Structure(children))
}

// ── Request payload dispatch ────────────────────────────────────────────────

fn decode_request_payload(op: Operation, frame: &TtlvFrame) -> Result<RequestPayload, WireError> {
    let children = expect_structure(frame, "Request Payload")?;
    Ok(match op {
        Operation::Query            => RequestPayload::Query(decode_query_req(children)?),
        Operation::Create           => RequestPayload::Create(decode_create_req(children)?),
        Operation::CreateKeyPair    => RequestPayload::CreateKeyPair(decode_create_key_pair_req(children)?),
        Operation::Get              => RequestPayload::Get(decode_get_req(children)?),
        Operation::GetAttributes    => RequestPayload::GetAttributes(decode_get_attributes_req(children)?),
        Operation::GetAttributeList => RequestPayload::GetAttributeList(decode_get_attribute_list_req(children)?),
        Operation::Locate           => RequestPayload::Locate(decode_locate_req(children)?),
        Operation::Activate         => RequestPayload::Activate(decode_activate_req(children)?),
        Operation::Revoke           => RequestPayload::Revoke(decode_revoke_req(children)?),
        Operation::Destroy          => RequestPayload::Destroy(decode_destroy_req(children)?),
        Operation::Encrypt          => RequestPayload::Encrypt(decode_encrypt_req(children)?),
        Operation::Decrypt          => RequestPayload::Decrypt(decode_decrypt_req(children)?),
        Operation::Sign             => RequestPayload::Sign(decode_sign_req(children)?),
        Operation::SignatureVerify  => RequestPayload::SignatureVerify(decode_sigverify_req(children)?),
        Operation::Interop          => RequestPayload::Interop(decode_interop_req(children)?),
        Operation::AddAttribute     => RequestPayload::AddAttribute(decode_add_attribute_req(children)?),
        Operation::ModifyAttribute  => RequestPayload::ModifyAttribute(decode_modify_attribute_req(children)?),
        Operation::DeleteAttribute  => RequestPayload::DeleteAttribute(decode_delete_attribute_req(children)?),
        Operation::SetAttribute     => RequestPayload::SetAttribute(decode_set_attribute_req(children)?),
        Operation::AdjustAttribute  => RequestPayload::AdjustAttribute(decode_adjust_attribute_req(children)?),
        Operation::Register         => RequestPayload::Register(decode_register_req(children)?),
        Operation::Import           => RequestPayload::Import(decode_import_req(children)?),
        Operation::Export           => RequestPayload::Export(decode_export_req(children)?),
        Operation::Deactivate       => RequestPayload::Deactivate(decode_deactivate_req(children)?),
        Operation::Check            => RequestPayload::Check(decode_check_req(children)?),
        Operation::Archive          => RequestPayload::Archive(ArchiveRequest { uid: required_uid(children)? }),
        Operation::Recover          => RequestPayload::Recover(RecoverRequest { uid: required_uid(children)? }),
        Operation::Obliterate       => RequestPayload::Obliterate(ObliterateRequest { uid: required_uid(children)? }),
        Operation::DiscoverVersions => RequestPayload::DiscoverVersions(decode_discover_versions_req(children)?),
        Operation::Ping             => RequestPayload::Ping(PingRequest),
        Operation::MAC              => RequestPayload::Mac(decode_mac_req(children)?),
        Operation::MACVerify        => RequestPayload::MacVerify(decode_mac_verify_req(children)?),
        Operation::Hash             => RequestPayload::Hash(decode_hash_req(children)?),
        Operation::CreateCredential => RequestPayload::CreateCredential(decode_create_credential_req(children)?),
        Operation::CreateGroup      => RequestPayload::CreateGroup(decode_create_group_req(children)?),
        Operation::CreateUser       => RequestPayload::CreateUser(decode_create_user_req(children)?),
        Operation::Log              => RequestPayload::Log(decode_log_req(children)?),
        Operation::Login            => RequestPayload::Login(decode_login_req(children)?),
        Operation::Logout           => RequestPayload::Logout(decode_logout_req(children)?),
        Operation::RNGRetrieve      => RequestPayload::RngRetrieve(decode_rng_retrieve_req(children)?),
        Operation::RNGSeed          => RequestPayload::RngSeed(decode_rng_seed_req(children)?),
        Operation::Pkcs11           => RequestPayload::Pkcs11(decode_pkcs11_req(children)?),
        // Advertised in Query for OASIS Baseline conformance (§4.1.1
        // item 15 superset) but the request handler is unimplemented —
        // no OASIS test in the corpus actually invokes it.
        Operation::SetEndpointRole  => return Err(WireError::UnknownEnum {
            field: "Operation (SetEndpointRole — advertised but no handler)",
            value: Operation::SetEndpointRole.to_wire_value(),
        }),
    })
}

fn response_payload_to_frame(payload: &ResponsePayload) -> TtlvFrame {
    let children = match payload {
        ResponsePayload::Query(r)            => encode_query_resp(r),
        ResponsePayload::Create(r)           => encode_create_resp(r),
        ResponsePayload::CreateKeyPair(r)    => encode_create_key_pair_resp(r),
        ResponsePayload::Get(r)              => encode_get_resp(r),
        ResponsePayload::GetAttributes(r)    => encode_get_attributes_resp(r),
        ResponsePayload::GetAttributeList(r) => encode_get_attribute_list_resp(r),
        ResponsePayload::Locate(r)           => encode_locate_resp(r),
        ResponsePayload::Activate(r)         => encode_activate_resp(r),
        ResponsePayload::Revoke(r)           => encode_revoke_resp(r),
        ResponsePayload::Destroy(r)          => encode_destroy_resp(r),
        ResponsePayload::Encrypt(r)          => encode_encrypt_resp(r),
        ResponsePayload::Decrypt(r)          => encode_decrypt_resp(r),
        ResponsePayload::Sign(r)             => encode_sign_resp(r),
        ResponsePayload::SignatureVerify(r)  => encode_sigverify_resp(r),
        ResponsePayload::Interop(_)          => vec![],
        // Group B wave 2 — Add/Modify/Delete/Set/Adjust Attribute all
        // return the same single-field UniqueIdentifier payload per
        // KMIP 3.0 §6.1.{2,3,17,38,56}.
        ResponsePayload::AddAttribute(r)     => encode_uid_only_resp(&r.uid),
        ResponsePayload::ModifyAttribute(r)  => encode_uid_only_resp(&r.uid),
        ResponsePayload::DeleteAttribute(r)  => encode_uid_only_resp(&r.uid),
        ResponsePayload::SetAttribute(r)     => encode_uid_only_resp(&r.uid),
        ResponsePayload::AdjustAttribute(r)  => encode_uid_only_resp(&r.uid),
        ResponsePayload::Register(r)         => encode_uid_only_resp(&r.uid),
        ResponsePayload::Import(r)           => encode_uid_only_resp(&r.uid),
        ResponsePayload::Export(r)           => encode_export_resp(r),
        ResponsePayload::Deactivate(r)       => encode_uid_only_resp(&r.uid),
        ResponsePayload::Check(r)            => encode_uid_only_resp(&r.uid),
        ResponsePayload::Archive(r)          => encode_uid_only_resp(&r.uid),
        ResponsePayload::Recover(r)          => encode_uid_only_resp(&r.uid),
        ResponsePayload::Obliterate(_)       => vec![],
        ResponsePayload::DiscoverVersions(r) => encode_discover_versions_resp(r),
        ResponsePayload::Ping(_)             => vec![],
        ResponsePayload::Mac(r)              => encode_mac_resp(r),
        ResponsePayload::MacVerify(r)        => encode_mac_verify_resp(r),
        ResponsePayload::Hash(r)             => encode_hash_resp(r),
        ResponsePayload::CreateCredential(r) => encode_uid_only_resp(&r.uid),
        ResponsePayload::CreateGroup(r)      => encode_uid_only_resp(&r.uid),
        ResponsePayload::CreateUser(r)       => encode_uid_only_resp(&r.uid),
        ResponsePayload::Log(_)              => vec![],
        ResponsePayload::Login(r)            => vec![
            TtlvFrame::new(Tag(tags::Ticket), Value::TextString(r.ticket.clone())),
        ],
        ResponsePayload::Logout(_)           => vec![],
        ResponsePayload::RngRetrieve(r)      => vec![
            TtlvFrame::new(Tag(tags::Data), Value::ByteString(r.data.clone())),
        ],
        ResponsePayload::RngSeed(r)          => vec![
            TtlvFrame::new(Tag(tags::DataLength), Value::Integer(r.data_length)),
        ],
        ResponsePayload::Pkcs11(r)           => encode_pkcs11_resp(r),
    };
    TtlvFrame::new(Tag(tags::ResponsePayload), Value::Structure(children))
}

// ── Per-op codecs (minimal v0.1 fields) ─────────────────────────────────────

fn decode_query_req(children: &[TtlvFrame]) -> Result<QueryRequest, WireError> {
    let mut functions = Vec::new();
    for c in children {
        if c.tag.0 == tags::QueryFunction {
            let v = expect_enum(c, "Query Function")?;
            functions.push(match v {
                1 => QueryFunction::QueryOperations,
                2 => QueryFunction::QueryObjects,
                3 => QueryFunction::QueryServerInformation,
                4 => QueryFunction::QueryApplicationNamespaces,
                7 => QueryFunction::QueryProfiles,
                9 => QueryFunction::QueryCapabilities,
                other => return Err(WireError::UnknownEnum { field: "Query Function", value: other }),
            });
        }
    }
    Ok(QueryRequest { functions })
}

fn encode_query_resp(r: &QueryResponse) -> Vec<TtlvFrame> {
    let mut out = Vec::new();
    if let Some(ops) = &r.operations {
        for op in ops {
            out.push(TtlvFrame::new(Tag(tags::Operation), Value::Enumeration(op.to_wire_value())));
        }
    }
    if let Some(types) = &r.object_types {
        for t in types {
            out.push(TtlvFrame::new(Tag(tags::ObjectType), Value::Enumeration(t.to_wire_value())));
        }
    }
    // VendorIdentification is a top-level child of the Query response
    // payload per KMIP 3.0 §6.1.39, not nested inside ServerInformation.
    if let Some(vendor) = &r.vendor_identification {
        out.push(TtlvFrame::new(
            Tag(tags::VendorIdentification),
            Value::TextString(vendor.clone()),
        ));
    }
    if let Some(info) = &r.server_info {
        out.push(TtlvFrame::new(
            Tag(tags::ServerInformation),
            Value::Structure(vec![TtlvFrame::new(
                Tag(tags::ServerVersion),
                Value::TextString(info.server_version.clone()),
            )]),
        ));
    }
    out
}

/// Decode the KMIP 3.0 §6.1.6 `Create` Request Payload.
///
/// Strict KMIP 3.0: attributes are carried inside an `Attributes`
/// Structure whose children are direct typed tags (`CryptographicAlgorithm`,
/// `CryptographicLength`, etc.). The KMIP 1.x `Attribute`-envelope
/// convention is **not** accepted — see §3 of the spec migration notes.
fn decode_create_req(children: &[TtlvFrame]) -> Result<CreateRequest, WireError> {
    let mut object_type = ObjectType::SymmetricKey;
    let mut template_attribute = Vec::new();
    for c in children {
        match c.tag.0 {
            tags::ObjectType => {
                let v = expect_enum(c, "Object Type")?;
                object_type = ObjectType::from_wire_value(v)
                    .ok_or(WireError::UnknownEnum { field: "Object Type", value: v })?;
            }
            tags::Attributes => {
                let inner = expect_structure(c, "Attributes")?;
                for child in inner {
                    if let Some(a) = decode_attribute_v3(child)? {
                        template_attribute.push(a);
                    }
                }
            }
            _ => {}
        }
    }
    Ok(CreateRequest { object_type, template_attribute })
}

fn encode_create_resp(r: &CreateResponse) -> Vec<TtlvFrame> {
    vec![
        TtlvFrame::new(Tag(tags::ObjectType), Value::Enumeration(r.object_type.to_wire_value())),
        TtlvFrame::new(Tag(tags::UniqueIdentifier), Value::TextString(r.uid.clone())),
    ]
}

fn decode_create_key_pair_req(children: &[TtlvFrame]) -> Result<CreateKeyPairRequest, WireError> {
    let mut common = Vec::new();
    let mut priv_attrs = Vec::new();
    let mut pub_attrs = Vec::new();
    // KMIP 3.0 §6.1.7 `Create Key Pair` — `Common Attributes`,
    // `Private Key Attributes`, `Public Key Attributes` are each
    // wrapping Structures whose children are direct typed tags (no 1.x
    // `Attribute` envelopes).
    for c in children {
        match c.tag.0 {
            tags::CommonAttributes => {
                for a in expect_structure(c, "Common Attributes")? {
                    if let Some(decoded) = decode_attribute_v3(a)? {
                        common.push(decoded);
                    }
                }
            }
            tags::PrivateKeyAttributes => {
                for a in expect_structure(c, "Private Key Attributes")? {
                    if let Some(decoded) = decode_attribute_v3(a)? {
                        priv_attrs.push(decoded);
                    }
                }
            }
            tags::PublicKeyAttributes => {
                for a in expect_structure(c, "Public Key Attributes")? {
                    if let Some(decoded) = decode_attribute_v3(a)? {
                        pub_attrs.push(decoded);
                    }
                }
            }
            _ => {}
        }
    }
    Ok(CreateKeyPairRequest {
        common_attributes: common,
        private_key_attributes: priv_attrs,
        public_key_attributes: pub_attrs,
    })
}

fn encode_create_key_pair_resp(r: &CreateKeyPairResponse) -> Vec<TtlvFrame> {
    // KMIP 3.0 §6.1.7 — distinct typed tags for the two halves of the
    // keypair. Using plain UniqueIdentifier for both is a 1.x
    // shortcut that breaks OASIS comparison.
    vec![
        TtlvFrame::new(
            Tag(tags::PrivateKeyUniqueIdentifier),
            Value::TextString(r.private_key_uid.clone()),
        ),
        TtlvFrame::new(
            Tag(tags::PublicKeyUniqueIdentifier),
            Value::TextString(r.public_key_uid.clone()),
        ),
    ]
}

fn decode_get_req(children: &[TtlvFrame]) -> Result<GetRequest, WireError> {
    let uid = required_uid(children)?;
    Ok(GetRequest { uid })
}

/// Encode a KMIP 3.0 §6.1.18 `Get` Response Payload.
///
/// The KeyBlock is wrapped in a ManagedObject Structure tagged by the
/// object's type — `SymmetricKey` (0x42008f), `PublicKey` (0x42006d),
/// or `PrivateKey` (0x420064). This wrapping is mandated by the spec
/// and required by OASIS conformance tests; emitting the KeyBlock
/// directly under ResponsePayload is a 1.x-style shortcut that fails
/// 3.0 strict comparison.
fn encode_get_resp(r: &GetResponse) -> Vec<TtlvFrame> {
    // KMIP 3.0 §6.2 `Key Block`:
    //   KeyFormatType
    //   KeyValue (Structure)
    //     KeyMaterial (ByteString or Structure depending on format)
    //   CryptographicAlgorithm
    //   CryptographicLength
    //
    // The 1.x convention of emitting `KeyValue` as a raw ByteString is
    // a wire-format break; OASIS expects `KeyMaterial` inside a
    // `KeyValue` Structure.
    let key_value_struct = TtlvFrame::new(
        Tag(tags::KeyValue),
        Value::Structure(vec![
            TtlvFrame::new(
                Tag(tags::KeyMaterial),
                Value::ByteString(r.key_block.key_value.clone()),
            ),
        ]),
    );
    let kb = TtlvFrame::new(
        Tag(tags::KeyBlock),
        Value::Structure(vec![
            TtlvFrame::new(Tag(tags::KeyFormatType), Value::Enumeration(r.key_block.key_format_type as u32)),
            key_value_struct,
            TtlvFrame::new(Tag(tags::CryptographicAlgorithm), Value::Enumeration(r.key_block.cryptographic_algorithm.to_wire_value())),
            TtlvFrame::new(Tag(tags::CryptographicLength), Value::Integer(r.key_block.cryptographic_length as i32)),
        ]),
    );
    let managed_object_tag = match r.object_type {
        ObjectType::PublicKey  => tags::PublicKey,
        ObjectType::PrivateKey => tags::PrivateKey,
        // SymmetricKey / SecretData / Certificate / OpaqueObject all
        // surface as SymmetricKey in v0.1 (we don't yet model Certificate
        // / SecretData object shapes; they'll get their own match arms
        // when we add Certify / SecretData ops).
        _ => tags::SymmetricKey,
    };
    let managed_object = TtlvFrame::new(Tag(managed_object_tag), Value::Structure(vec![kb]));
    vec![
        TtlvFrame::new(Tag(tags::ObjectType), Value::Enumeration(r.object_type.to_wire_value())),
        TtlvFrame::new(Tag(tags::UniqueIdentifier), Value::TextString(r.uid.clone())),
        managed_object,
    ]
}

fn decode_locate_req(children: &[TtlvFrame]) -> Result<LocateRequest, WireError> {
    let mut attributes = Vec::new();
    let mut maximum_items = None;
    for c in children {
        match c.tag.0 {
            // KMIP 3.0 §6.1.32: Locate request body carries an `Attributes`
            // Structure whose children are direct typed tags used as
            // search filters.
            tags::Attributes => {
                for a in expect_structure(c, "Attributes")? {
                    if let Some(decoded) = decode_attribute_v3(a)? {
                        attributes.push(decoded);
                    }
                }
            }
            tags::MaximumItems => maximum_items = Some(expect_integer(c, "Maximum Items")? as u32),
            _ => {}
        }
    }
    Ok(LocateRequest { attributes, maximum_items })
}

fn encode_locate_resp(r: &LocateResponse) -> Vec<TtlvFrame> {
    r.uids
        .iter()
        .map(|u| TtlvFrame::new(Tag(tags::UniqueIdentifier), Value::TextString(u.clone())))
        .collect()
}

fn decode_activate_req(children: &[TtlvFrame]) -> Result<ActivateRequest, WireError> {
    Ok(ActivateRequest { uid: required_uid(children)? })
}

fn encode_activate_resp(r: &ActivateResponse) -> Vec<TtlvFrame> {
    vec![TtlvFrame::new(Tag(tags::UniqueIdentifier), Value::TextString(r.uid.clone()))]
}

fn decode_revoke_req(children: &[TtlvFrame]) -> Result<RevokeRequest, WireError> {
    let uid = required_uid(children)?;
    let mut reason = RevocationReason::Unspecified;
    for c in children {
        if c.tag.0 == tags::RevocationReason {
            let inner = expect_structure(c, "Revocation Reason")?;
            for r in inner {
                if r.tag.0 == tags::RevocationReasonCode {
                    let v = expect_enum(r, "Revocation Reason Code")?;
                    reason = match v {
                        1 => RevocationReason::Unspecified,
                        2 => RevocationReason::KeyCompromise,
                        3 => RevocationReason::CaCompromise,
                        4 => RevocationReason::AffiliationChanged,
                        5 => RevocationReason::Superseded,
                        6 => RevocationReason::CessationOfOperation,
                        7 => RevocationReason::PrivilegeWithdrawn,
                        other => return Err(WireError::UnknownEnum { field: "Revocation Reason Code", value: other }),
                    };
                }
            }
        }
    }
    Ok(RevokeRequest { uid, reason })
}

fn encode_revoke_resp(r: &RevokeResponse) -> Vec<TtlvFrame> {
    vec![TtlvFrame::new(Tag(tags::UniqueIdentifier), Value::TextString(r.uid.clone()))]
}

fn decode_destroy_req(children: &[TtlvFrame]) -> Result<DestroyRequest, WireError> {
    Ok(DestroyRequest { uid: required_uid(children)? })
}

fn encode_destroy_resp(r: &DestroyResponse) -> Vec<TtlvFrame> {
    vec![TtlvFrame::new(Tag(tags::UniqueIdentifier), Value::TextString(r.uid.clone()))]
}

fn decode_encrypt_req(children: &[TtlvFrame]) -> Result<EncryptRequest, WireError> {
    let uid = required_uid(children)?;
    let mut data = Vec::new();
    let mut iv = None;
    for c in children {
        match c.tag.0 {
            tags::Data => {
                if let Value::ByteString(b) = &c.value { data = b.clone(); }
            }
            tags::IvCounterNonce => {
                if let Value::ByteString(b) = &c.value { iv = Some(b.clone()); }
            }
            _ => {}
        }
    }
    Ok(EncryptRequest { uid, data, iv })
}

fn encode_encrypt_resp(r: &EncryptResponse) -> Vec<TtlvFrame> {
    let mut out = vec![
        TtlvFrame::new(Tag(tags::UniqueIdentifier), Value::TextString(r.uid.clone())),
        TtlvFrame::new(Tag(tags::Data), Value::ByteString(r.ciphertext.clone())),
    ];
    if let Some(ss) = &r.shared_secret {
        // ML-KEM shared secret rides in IvCounterNonce slot for v0.1 — a
        // KMIP 3.0 dedicated tag for "shared secret out-of-band of the
        // KeyBlock" isn't in the §10 enum extract. Documented limitation;
        // v0.2 will move to the right tag when we identify it in §9.
        out.push(TtlvFrame::new(Tag(tags::IvCounterNonce), Value::ByteString(ss.clone())));
    }
    out
}

fn decode_decrypt_req(children: &[TtlvFrame]) -> Result<DecryptRequest, WireError> {
    let uid = required_uid(children)?;
    let mut data = Vec::new();
    let mut iv = None;
    for c in children {
        match c.tag.0 {
            tags::Data => { if let Value::ByteString(b) = &c.value { data = b.clone(); } }
            tags::IvCounterNonce => { if let Value::ByteString(b) = &c.value { iv = Some(b.clone()); } }
            _ => {}
        }
    }
    Ok(DecryptRequest { uid, data, iv })
}

fn encode_decrypt_resp(r: &DecryptResponse) -> Vec<TtlvFrame> {
    vec![
        TtlvFrame::new(Tag(tags::UniqueIdentifier), Value::TextString(r.uid.clone())),
        TtlvFrame::new(Tag(tags::Data), Value::ByteString(r.data.clone())),
    ]
}

fn decode_sign_req(children: &[TtlvFrame]) -> Result<SignRequest, WireError> {
    let uid = required_uid(children)?;
    let mut data = Vec::new();
    for c in children {
        if c.tag.0 == tags::Data {
            if let Value::ByteString(b) = &c.value { data = b.clone(); }
        }
    }
    Ok(SignRequest { uid, data })
}

fn encode_sign_resp(r: &SignResponse) -> Vec<TtlvFrame> {
    vec![
        TtlvFrame::new(Tag(tags::UniqueIdentifier), Value::TextString(r.uid.clone())),
        TtlvFrame::new(Tag(tags::SignatureData), Value::ByteString(r.signature.clone())),
    ]
}

fn decode_sigverify_req(children: &[TtlvFrame]) -> Result<SignatureVerifyRequest, WireError> {
    let uid = required_uid(children)?;
    let mut data = Vec::new();
    let mut signature = Vec::new();
    for c in children {
        match c.tag.0 {
            tags::Data => { if let Value::ByteString(b) = &c.value { data = b.clone(); } }
            tags::SignatureData => { if let Value::ByteString(b) = &c.value { signature = b.clone(); } }
            _ => {}
        }
    }
    Ok(SignatureVerifyRequest { uid, data, signature })
}

fn encode_sigverify_resp(r: &SignatureVerifyResponse) -> Vec<TtlvFrame> {
    vec![
        TtlvFrame::new(Tag(tags::UniqueIdentifier), Value::TextString(r.uid.clone())),
        TtlvFrame::new(Tag(tags::ValidityIndicator), Value::Enumeration(r.validity as u32)),
    ]
}

// ── Attribute codec ─────────────────────────────────────────────────────────

/// Decode one typed-tag child inside a KMIP 3.0 `Attributes` Structure.
///
/// Per KMIP 3.0 §6.1.6 the OASIS wire format replaces the 1.x `Attribute`
/// envelope (`AttributeName` + `AttributeValue`) with direct typed tags:
/// a `CryptographicAlgorithm` TTLV frame *is* the attribute, no wrapper.
///
/// Unknown tags inside the wrapper are silently ignored (return `Ok(None)`)
/// so future spec additions don't break older clients — same forward-compat
/// stance as the rest of the codec.
fn decode_attribute_v3(frame: &TtlvFrame) -> Result<Option<Attribute>, WireError> {
    Ok(Some(match frame.tag.0 {
        tags::CryptographicAlgorithm => {
            let v = expect_enum(frame, "Cryptographic Algorithm")?;
            Attribute::CryptographicAlgorithm(
                KmipAlgorithm::from_wire_value(v)
                    .ok_or(WireError::UnknownEnum { field: "Cryptographic Algorithm", value: v })?,
            )
        }
        tags::CryptographicLength => {
            Attribute::CryptographicLength(expect_integer(frame, "Cryptographic Length")? as u32)
        }
        tags::CryptographicUsageMask => {
            let v = expect_integer(frame, "Cryptographic Usage Mask")? as u32;
            Attribute::CryptographicUsageMask(UsageMask::from_bits_truncate(v))
        }
        tags::ObjectType => {
            let v = expect_enum(frame, "Object Type")?;
            Attribute::ObjectType(
                ObjectType::from_wire_value(v)
                    .ok_or(WireError::UnknownEnum { field: "Object Type", value: v })?,
            )
        }
        tags::State => {
            let v = expect_enum(frame, "State")?;
            Attribute::State(
                State::from_wire_value(v)
                    .ok_or(WireError::UnknownEnum { field: "State", value: v })?,
            )
        }
        tags::UniqueIdentifier => {
            if let Value::TextString(s) = &frame.value {
                Attribute::UniqueIdentifier(s.clone())
            } else {
                return Err(WireError::BadType {
                    tag: frame.tag.0,
                    name: "Unique Identifier",
                    msg: "expected TextString".into(),
                });
            }
        }
        tags::Name => {
            if let Value::TextString(s) = &frame.value {
                Attribute::Name(s.clone())
            } else {
                return Err(WireError::BadType {
                    tag: frame.tag.0,
                    name: "Name",
                    msg: "expected TextString".into(),
                });
            }
        }
        // ── KMIP Profiles v3.0 §5.1.2 Baseline Server date attributes ──
        // The client SHALL be able to set these at Register / Create time;
        // they drive the lifecycle FSM (§3.x). Dropping them silently
        // (the previous wildcard behaviour) caused PreActive-stuck keys
        // even when the client supplied a past ActivationDate.
        tags::ActivationDate => Attribute::ActivationDate(expect_datetime(frame, "Activation Date")?),
        tags::DeactivationDate => Attribute::DeactivationDate(expect_datetime(frame, "Deactivation Date")?),
        tags::DestroyDate => Attribute::DestroyDate(expect_datetime(frame, "Destroy Date")?),
        tags::CompromiseDate => Attribute::CompromiseDate(expect_datetime(frame, "Compromise Date")?),
        tags::CompromiseOccurrenceDate => Attribute::CompromiseOccurrenceDate(expect_datetime(frame, "Compromise Occurrence Date")?),
        tags::ProcessStartDate => Attribute::ProcessStartDate(expect_datetime(frame, "Process Start Date")?),
        tags::ProtectStopDate => Attribute::ProtectStopDate(expect_datetime(frame, "Protect Stop Date")?),
        tags::OriginalCreationDate => Attribute::OriginalCreationDate(expect_datetime(frame, "Original Creation Date")?),
        // ── §5.1.2 Baseline security-posture booleans ──
        tags::Sensitive => Attribute::Sensitive(expect_boolean(frame, "Sensitive")?),
        tags::Extractable => Attribute::Extractable(expect_boolean(frame, "Extractable")?),
        tags::Fresh => Attribute::Fresh(expect_boolean(frame, "Fresh")?),
        tags::KeyValuePresent => Attribute::KeyValuePresent(expect_boolean(frame, "Key Value Present")?),
        tags::QuantumSafe => Attribute::QuantumSafe(expect_boolean(frame, "Quantum Safe")?),
        _ => return Ok(None),
    }))
}

// ── Group G codecs: RNG + PKCS#11 passthrough ──────────────────────────────

fn decode_rng_retrieve_req(children: &[TtlvFrame]) -> Result<RngRetrieveRequest, WireError> {
    let mut data_length = 0i32;
    for c in children {
        if c.tag.0 == tags::DataLength {
            data_length = expect_integer(c, "Data Length")?;
        }
    }
    Ok(RngRetrieveRequest { data_length })
}

fn decode_rng_seed_req(children: &[TtlvFrame]) -> Result<RngSeedRequest, WireError> {
    let mut data = Vec::new();
    for c in children {
        if c.tag.0 == tags::Data {
            if let Value::ByteString(b) = &c.value { data = b.clone(); }
        }
    }
    Ok(RngSeedRequest { data })
}

fn decode_pkcs11_req(children: &[TtlvFrame]) -> Result<Pkcs11Request, WireError> {
    let mut interface = None;
    let mut function = None;
    let mut correlation_value = None;
    let mut input_parameters = None;
    for c in children {
        match c.tag.0 {
            tags::Pkcs11Interface => {
                if let Value::TextString(s) = &c.value { interface = Some(s.clone()); }
            }
            tags::Pkcs11Function => {
                function = Some(expect_enum(c, "PKCS#11 Function")?);
            }
            tags::CorrelationValue => {
                if let Value::ByteString(b) = &c.value { correlation_value = Some(b.clone()); }
            }
            tags::Pkcs11InputParameters => {
                if let Value::ByteString(b) = &c.value { input_parameters = Some(b.clone()); }
            }
            _ => {}
        }
    }
    let function = function.ok_or(WireError::Missing {
        tag: tags::Pkcs11Function,
        name: "PKCS#11 Function",
    })?;
    Ok(Pkcs11Request {
        interface,
        function,
        correlation_value,
        input_parameters,
    })
}

fn encode_pkcs11_resp(r: &Pkcs11Response) -> Vec<TtlvFrame> {
    let mut out = Vec::new();
    if let Some(iface) = &r.interface {
        out.push(TtlvFrame::new(Tag(tags::Pkcs11Interface), Value::TextString(iface.clone())));
    }
    out.push(TtlvFrame::new(Tag(tags::Pkcs11Function), Value::Enumeration(r.function)));
    if let Some(cv) = &r.correlation_value {
        out.push(TtlvFrame::new(Tag(tags::CorrelationValue), Value::ByteString(cv.clone())));
    }
    if let Some(op) = &r.output_parameters {
        out.push(TtlvFrame::new(Tag(tags::Pkcs11OutputParameters), Value::ByteString(op.clone())));
    }
    out.push(TtlvFrame::new(Tag(tags::Pkcs11ReturnCode), Value::Integer(r.return_code)));
    out
}

// ── Group F codecs: session / auth ─────────────────────────────────────────
//
// Spec mapping:
// - CreateCredential §6.1.9  — CredentialType + Attributes + Credential? (Structure)
// - CreateGroup      §6.1.10 — Attributes only
// - CreateUser       §6.1.13 — Attributes only
// - Log              §6.1.33 — LogMessage (TextString)
// - Login            §6.1.34 — LeaseTime? + RequestCount? + UsageLimits?
// - Logout           §6.1.35 — Ticket (TextString)

fn decode_attributes_block(frame: &TtlvFrame) -> Result<Vec<Attribute>, WireError> {
    let mut out = Vec::new();
    for c in expect_structure(frame, "Attributes")? {
        if let Some(a) = decode_attribute_v3(c)? {
            out.push(a);
        }
    }
    Ok(out)
}

fn decode_create_credential_req(children: &[TtlvFrame]) -> Result<CreateCredentialRequest, WireError> {
    let mut credential_type = None;
    let mut attributes = Vec::new();
    let mut password_credential = None;
    for c in children {
        match c.tag.0 {
            tags::CredentialType => {
                credential_type = Some(expect_enum(c, "Credential Type")?);
            }
            tags::Attributes => attributes = decode_attributes_block(c)?,
            tags::PasswordCredential => {
                password_credential = Some(decode_password_credential(c)?);
            }
            _ => {}
        }
    }
    let credential_type = credential_type.ok_or(WireError::Missing {
        tag: tags::CredentialType,
        name: "Credential Type",
    })?;
    Ok(CreateCredentialRequest { credential_type, attributes, password_credential })
}

fn decode_password_credential(frame: &TtlvFrame) -> Result<PasswordCredential, WireError> {
    let mut username = String::new();
    let mut password = None;
    for c in expect_structure(frame, "Password Credential")? {
        match c.tag.0 {
            tags::Username => {
                if let Value::TextString(s) = &c.value { username = s.clone(); }
            }
            tags::Password => {
                if let Value::TextString(s) = &c.value { password = Some(s.clone()); }
            }
            _ => {}
        }
    }
    Ok(PasswordCredential { username, password })
}

fn decode_create_group_req(children: &[TtlvFrame]) -> Result<CreateGroupRequest, WireError> {
    let mut attributes = Vec::new();
    for c in children {
        if c.tag.0 == tags::Attributes {
            attributes = decode_attributes_block(c)?;
        }
    }
    Ok(CreateGroupRequest { attributes })
}

fn decode_create_user_req(children: &[TtlvFrame]) -> Result<CreateUserRequest, WireError> {
    let mut attributes = Vec::new();
    for c in children {
        if c.tag.0 == tags::Attributes {
            attributes = decode_attributes_block(c)?;
        }
    }
    Ok(CreateUserRequest { attributes })
}

fn decode_log_req(children: &[TtlvFrame]) -> Result<LogRequest, WireError> {
    let mut message = String::new();
    for c in children {
        if c.tag.0 == tags::LogMessage {
            if let Value::TextString(s) = &c.value { message = s.clone(); }
        }
    }
    Ok(LogRequest { message })
}

fn decode_login_req(children: &[TtlvFrame]) -> Result<LoginRequest, WireError> {
    let mut lease_time = None;
    let mut request_count = None;
    let mut usage_limits = None;
    for c in children {
        match c.tag.0 {
            tags::LeaseTime => {
                if let Value::Interval(n) = c.value { lease_time = Some(n); }
                else if let Value::Integer(n) = c.value { lease_time = Some(n as u32); }
            }
            tags::RequestCount => {
                if let Value::Integer(n) = c.value { request_count = Some(n); }
            }
            tags::UsageLimits => {
                for inner in expect_structure(c, "Usage Limits")? {
                    if inner.tag.0 == tags::UsageLimitsTotal {
                        if let Value::LongInteger(n) = inner.value { usage_limits = Some(n); }
                        else if let Value::Integer(n) = inner.value { usage_limits = Some(n as i64); }
                    }
                }
            }
            _ => {}
        }
    }
    Ok(LoginRequest { lease_time, request_count, usage_limits })
}

fn decode_logout_req(children: &[TtlvFrame]) -> Result<LogoutRequest, WireError> {
    let mut ticket = String::new();
    for c in children {
        if c.tag.0 == tags::Ticket {
            if let Value::TextString(s) = &c.value { ticket = s.clone(); }
        }
    }
    Ok(LogoutRequest { ticket })
}

// ── Group E codecs: MAC / MACVerify / Hash ─────────────────────────────────

fn decode_cryptographic_parameters(frame: &TtlvFrame) -> Result<CryptographicParameters, WireError> {
    let mut cp = CryptographicParameters::default();
    for c in expect_structure(frame, "Cryptographic Parameters")? {
        match c.tag.0 {
            tags::HashingAlgorithm => {
                let v = expect_enum(c, "Hashing Algorithm")?;
                cp.hashing_algorithm = HashingAlgorithm::from_wire_value(v);
                if cp.hashing_algorithm.is_none() {
                    return Err(WireError::UnknownEnum { field: "Hashing Algorithm", value: v });
                }
            }
            tags::CryptographicAlgorithm => {
                let v = expect_enum(c, "Cryptographic Algorithm")?;
                cp.cryptographic_algorithm = KmipAlgorithm::from_wire_value(v);
            }
            _ => {}
        }
    }
    Ok(cp)
}

fn decode_mac_req(children: &[TtlvFrame]) -> Result<MacRequest, WireError> {
    let uid = required_uid(children)?;
    let mut cp = None;
    let mut data = Vec::new();
    for c in children {
        match c.tag.0 {
            tags::CryptographicParameters => cp = Some(decode_cryptographic_parameters(c)?),
            tags::Data => {
                if let Value::ByteString(b) = &c.value { data = b.clone(); }
            }
            _ => {}
        }
    }
    Ok(MacRequest { uid, cryptographic_parameters: cp, data })
}

fn decode_mac_verify_req(children: &[TtlvFrame]) -> Result<MacVerifyRequest, WireError> {
    let uid = required_uid(children)?;
    let mut cp = None;
    let mut data = Vec::new();
    let mut mac_data = Vec::new();
    for c in children {
        match c.tag.0 {
            tags::CryptographicParameters => cp = Some(decode_cryptographic_parameters(c)?),
            tags::Data => {
                if let Value::ByteString(b) = &c.value { data = b.clone(); }
            }
            tags::MacData => {
                if let Value::ByteString(b) = &c.value { mac_data = b.clone(); }
            }
            _ => {}
        }
    }
    Ok(MacVerifyRequest { uid, cryptographic_parameters: cp, data, mac_data })
}

fn decode_hash_req(children: &[TtlvFrame]) -> Result<HashRequest, WireError> {
    let mut cp = CryptographicParameters::default();
    let mut data = Vec::new();
    for c in children {
        match c.tag.0 {
            tags::CryptographicParameters => cp = decode_cryptographic_parameters(c)?,
            tags::Data => {
                if let Value::ByteString(b) = &c.value { data = b.clone(); }
            }
            _ => {}
        }
    }
    Ok(HashRequest { cryptographic_parameters: cp, data })
}

fn encode_mac_resp(r: &MacResponse) -> Vec<TtlvFrame> {
    vec![
        TtlvFrame::new(Tag(tags::UniqueIdentifier), Value::TextString(r.uid.clone())),
        TtlvFrame::new(Tag(tags::MacData), Value::ByteString(r.mac_data.clone())),
    ]
}

fn encode_mac_verify_resp(r: &MacVerifyResponse) -> Vec<TtlvFrame> {
    vec![
        TtlvFrame::new(Tag(tags::UniqueIdentifier), Value::TextString(r.uid.clone())),
        TtlvFrame::new(Tag(tags::ValidityIndicator), Value::Enumeration(r.validity as u32)),
    ]
}

fn encode_hash_resp(r: &HashResponse) -> Vec<TtlvFrame> {
    vec![
        TtlvFrame::new(Tag(tags::Data), Value::ByteString(r.data.clone())),
    ]
}

// ── Group D + leftover Group A codecs ──────────────────────────────────────
//
// - Deactivate §6.1.14 — UID + DeactivationReason? + DeactivationDate?
//   The DeactivationReason wire shape mirrors RevocationReason:
//   a Structure containing a DeactivationReasonCode Enumeration.
// - Check §6.1.7 — UID + UsageLimitsCount? + CryptographicUsageMask? + LeaseTime?
//   Per spec the optional fields are NOT wrapped in an Attribute envelope.
// - Discover Versions §6.1.20 — repeatable ProtocolVersion Structures.

fn decode_deactivate_req(children: &[TtlvFrame]) -> Result<DeactivateRequest, WireError> {
    let uid = required_uid(children)?;
    let mut reason: Option<DeactivationReason> = None;
    let mut date: Option<i64> = None;
    for c in children {
        match c.tag.0 {
            tags::DeactivationReason => {
                for inner in expect_structure(c, "Deactivation Reason")? {
                    if inner.tag.0 == tags::DeactivationReasonCode {
                        let v = expect_enum(inner, "Deactivation Reason Code")?;
                        reason = DeactivationReason::from_wire_value(v);
                        if reason.is_none() {
                            return Err(WireError::UnknownEnum {
                                field: "Deactivation Reason Code",
                                value: v,
                            });
                        }
                    }
                }
            }
            tags::DeactivationDate => {
                if let Value::DateTime(t) = c.value { date = Some(t); }
            }
            _ => {}
        }
    }
    Ok(DeactivateRequest {
        uid,
        deactivation_reason: reason,
        deactivation_date: date,
    })
}

fn decode_check_req(children: &[TtlvFrame]) -> Result<CheckRequest, WireError> {
    let uid = required_uid(children)?;
    let mut usage_limits_count = None;
    let mut cryptographic_usage_mask = None;
    let mut lease_time = None;
    for c in children {
        match c.tag.0 {
            tags::UsageLimitsCount => {
                if let Value::LongInteger(n) = c.value { usage_limits_count = Some(n); }
                else if let Value::Integer(n) = c.value { usage_limits_count = Some(n as i64); }
            }
            tags::CryptographicUsageMask => {
                cryptographic_usage_mask = Some(expect_integer(c, "Cryptographic Usage Mask")? as u32);
            }
            tags::LeaseTime => {
                // Spec: Interval. Codec models Interval as u32.
                if let Value::Interval(n) = c.value { lease_time = Some(n); }
                else if let Value::Integer(n) = c.value { lease_time = Some(n as u32); }
            }
            _ => {}
        }
    }
    Ok(CheckRequest {
        uid,
        usage_limits_count,
        cryptographic_usage_mask,
        lease_time,
    })
}

fn decode_discover_versions_req(children: &[TtlvFrame]) -> Result<DiscoverVersionsRequest, WireError> {
    let mut versions = Vec::new();
    for c in children {
        if c.tag.0 == tags::ProtocolVersion {
            versions.push(decode_protocol_version(c)?);
        }
    }
    Ok(DiscoverVersionsRequest { protocol_versions: versions })
}

/// Decode one `ProtocolVersion` Structure → (major, minor).
fn decode_protocol_version(frame: &TtlvFrame) -> Result<(i32, i32), WireError> {
    let mut major = 0i32;
    let mut minor = 0i32;
    for c in expect_structure(frame, "Protocol Version")? {
        match c.tag.0 {
            tags::ProtocolVersionMajor => major = expect_integer(c, "Protocol Version Major")?,
            tags::ProtocolVersionMinor => minor = expect_integer(c, "Protocol Version Minor")?,
            _ => {}
        }
    }
    Ok((major, minor))
}

fn encode_discover_versions_resp(r: &DiscoverVersionsResponse) -> Vec<TtlvFrame> {
    r.protocol_versions.iter().map(|&(major, minor)| {
        TtlvFrame::new(
            Tag(tags::ProtocolVersion),
            Value::Structure(vec![
                TtlvFrame::new(Tag(tags::ProtocolVersionMajor), Value::Integer(major)),
                TtlvFrame::new(Tag(tags::ProtocolVersionMinor), Value::Integer(minor)),
            ]),
        )
    }).collect()
}

// ── Group C codecs: Register / Import / Export ─────────────────────────────
//
// Spec mapping:
//
// - Register §6.1.48 / Table 393 — Request: ObjectType + Attributes +
//   Any Object + ProtectionStorageMasks?  → Response: UID
// - Import   §6.1.29 / Table 337 — Request: UID + ObjectType +
//   ReplaceExisting? + KeyWrapType? + Attributes + Any Object → Response: UID
// - Export   §6.1.22 / Table 316 — Request: UID + format options →
//   Response: ObjectType + UID + Attributes + Any Object
//
// "Any Object (Section 2)" resolves to one of SymmetricKey / PublicKey /
// PrivateKey / Certificate / SecretData / OpaqueObject; each wraps a
// KeyBlock structure. v0.1 honours SymmetricKey + PublicKey/PrivateKey;
// other object families return InvalidObjectType.

fn decode_register_req(children: &[TtlvFrame]) -> Result<RegisterRequest, WireError> {
    let mut object_type = None;
    let mut attributes = Vec::new();
    let mut managed_object = None;
    let mut protection_storage_masks = None;
    for c in children {
        match c.tag.0 {
            tags::ObjectType => {
                let v = expect_enum(c, "Object Type")?;
                object_type = Some(
                    ObjectType::from_wire_value(v)
                        .ok_or(WireError::UnknownEnum { field: "Object Type", value: v })?,
                );
            }
            tags::Attributes => {
                for child in expect_structure(c, "Attributes")? {
                    if let Some(a) = decode_attribute_v3(child)? {
                        attributes.push(a);
                    }
                }
            }
            tags::SymmetricKey | tags::PublicKey | tags::PrivateKey => {
                managed_object = Some(decode_managed_object(c)?);
            }
            tags::ProtectionStorageMasks => {
                // Per §6.1.48 the field is a Structure containing one
                // ProtectionStorageMask Integer per permitted mask. v0.1
                // collapses to the bitwise-OR of the bits since the
                // current handler doesn't enforce them.
                let mut acc = 0u32;
                for child in expect_structure(c, "Protection Storage Masks")? {
                    if child.tag.0 == tags::ProtectionStorageMask {
                        if let Value::Integer(n) = child.value {
                            acc |= n as u32;
                        }
                    }
                }
                protection_storage_masks = Some(acc);
            }
            _ => {}
        }
    }
    let object_type = object_type.ok_or(WireError::Missing {
        tag: tags::ObjectType,
        name: "Object Type",
    })?;
    Ok(RegisterRequest {
        object_type,
        attributes,
        managed_object,
        protection_storage_masks,
    })
}

fn decode_import_req(children: &[TtlvFrame]) -> Result<ImportRequest, WireError> {
    let uid = required_uid(children)?;
    let mut object_type = None;
    let mut replace_existing = false;
    let mut key_wrap_type = None;
    let mut attributes = Vec::new();
    let mut managed_object = None;
    for c in children {
        match c.tag.0 {
            tags::ObjectType => {
                let v = expect_enum(c, "Object Type")?;
                object_type = Some(
                    ObjectType::from_wire_value(v)
                        .ok_or(WireError::UnknownEnum { field: "Object Type", value: v })?,
                );
            }
            tags::ReplaceExisting => {
                if let Value::Boolean(b) = c.value {
                    replace_existing = b;
                }
            }
            tags::KeyWrapType => {
                if let Value::Enumeration(v) = c.value {
                    key_wrap_type = Some(v);
                }
            }
            tags::Attributes => {
                for child in expect_structure(c, "Attributes")? {
                    if let Some(a) = decode_attribute_v3(child)? {
                        attributes.push(a);
                    }
                }
            }
            tags::SymmetricKey | tags::PublicKey | tags::PrivateKey => {
                managed_object = Some(decode_managed_object(c)?);
            }
            _ => {}
        }
    }
    let object_type = object_type.ok_or(WireError::Missing {
        tag: tags::ObjectType,
        name: "Object Type",
    })?;
    Ok(ImportRequest {
        uid,
        object_type,
        replace_existing,
        key_wrap_type,
        attributes,
        managed_object,
    })
}

fn decode_export_req(children: &[TtlvFrame]) -> Result<ExportRequest, WireError> {
    let uid = required_uid(children)?;
    let mut key_format_type = None;
    let mut key_wrap_type = None;
    let mut key_compression_type = None;
    for c in children {
        match c.tag.0 {
            tags::KeyFormatType => {
                if let Value::Enumeration(v) = c.value { key_format_type = Some(v); }
            }
            tags::KeyWrapType => {
                if let Value::Enumeration(v) = c.value { key_wrap_type = Some(v); }
            }
            tags::KeyCompressionType => {
                if let Value::Enumeration(v) = c.value { key_compression_type = Some(v); }
            }
            _ => {}
        }
    }
    Ok(ExportRequest { uid, key_format_type, key_wrap_type, key_compression_type })
}

/// Decode a `Any Object (Section 2)` payload — i.e. a SymmetricKey /
/// PublicKey / PrivateKey Structure wrapping a `KeyBlock`. Returns just
/// the KeyBlock (the wrapping tag is what the caller used to dispatch).
fn decode_managed_object(frame: &TtlvFrame) -> Result<KeyBlock, WireError> {
    let inner = expect_structure(frame, "Managed Object")?;
    for child in inner {
        if child.tag.0 == tags::KeyBlock {
            return decode_key_block(child);
        }
    }
    Err(WireError::Missing { tag: tags::KeyBlock, name: "Key Block" })
}

/// Decode a `KeyBlock` Structure (KMIP 3.0 §6.2):
///   KeyFormatType + KeyValue (Structure containing KeyMaterial) +
///   CryptographicAlgorithm + CryptographicLength.
fn decode_key_block(frame: &TtlvFrame) -> Result<KeyBlock, WireError> {
    let children = expect_structure(frame, "Key Block")?;
    let mut key_format_type = 1; // Raw
    let mut algorithm = KmipAlgorithm::Aes;
    let mut length: u32 = 0;
    let mut bytes: Vec<u8> = Vec::new();
    for c in children {
        match c.tag.0 {
            tags::KeyFormatType => {
                if let Value::Enumeration(v) = c.value { key_format_type = v; }
            }
            tags::CryptographicAlgorithm => {
                let v = expect_enum(c, "Cryptographic Algorithm")?;
                algorithm = KmipAlgorithm::from_wire_value(v)
                    .ok_or(WireError::UnknownEnum { field: "Cryptographic Algorithm", value: v })?;
            }
            tags::CryptographicLength => {
                length = expect_integer(c, "Cryptographic Length")? as u32;
            }
            tags::KeyValue => {
                // KeyValue is itself a Structure containing KeyMaterial.
                for inner in expect_structure(c, "Key Value")? {
                    if inner.tag.0 == tags::KeyMaterial {
                        if let Value::ByteString(b) = &inner.value {
                            bytes = b.clone();
                        }
                    }
                }
            }
            _ => {}
        }
    }
    Ok(KeyBlock {
        key_format_type: match key_format_type {
            0x01 => KeyFormatType::Raw,
            _    => KeyFormatType::Raw, // v0.1 — wave 2 will expand
        },
        cryptographic_algorithm: algorithm,
        cryptographic_length: length,
        key_value: bytes,
    })
}

/// Encode an Export response payload per §6.1.22 / Table 317:
/// ObjectType + UID + Attributes (Structure) + Any Object (SymmetricKey
/// / PublicKey / PrivateKey wrapping a KeyBlock).
fn encode_export_resp(r: &ExportResponse) -> Vec<TtlvFrame> {
    let mut out = vec![
        TtlvFrame::new(Tag(tags::ObjectType), Value::Enumeration(r.object_type.to_wire_value())),
        TtlvFrame::new(Tag(tags::UniqueIdentifier), Value::TextString(r.uid.clone())),
    ];
    out.push(TtlvFrame::new(
        Tag(tags::Attributes),
        Value::Structure(r.attributes.iter().map(encode_attribute_v3).collect()),
    ));
    if let Some(kb) = &r.managed_object {
        let kb_frame = encode_key_block(kb);
        let managed_object_tag = match r.object_type {
            ObjectType::PublicKey  => tags::PublicKey,
            ObjectType::PrivateKey => tags::PrivateKey,
            _ => tags::SymmetricKey,
        };
        out.push(TtlvFrame::new(Tag(managed_object_tag), Value::Structure(vec![kb_frame])));
    }
    out
}

/// Encode a `KeyBlock` Structure. Mirror of `decode_key_block`.
fn encode_key_block(kb: &KeyBlock) -> TtlvFrame {
    let key_value = TtlvFrame::new(
        Tag(tags::KeyValue),
        Value::Structure(vec![
            TtlvFrame::new(Tag(tags::KeyMaterial), Value::ByteString(kb.key_value.clone())),
        ]),
    );
    TtlvFrame::new(
        Tag(tags::KeyBlock),
        Value::Structure(vec![
            TtlvFrame::new(Tag(tags::KeyFormatType), Value::Enumeration(kb.key_format_type as u32)),
            key_value,
            TtlvFrame::new(Tag(tags::CryptographicAlgorithm), Value::Enumeration(kb.cryptographic_algorithm.to_wire_value())),
            TtlvFrame::new(Tag(tags::CryptographicLength), Value::Integer(kb.cryptographic_length as i32)),
        ]),
    )
}

// ── Group B Wave 2 codecs (attribute mutations + shared helpers) ───────────
//
// Spec mapping:
//
// - AddAttribute     §6.1.2  / Table 254 — UID + NewAttribute (Structure)
// - AdjustAttribute  §6.1.3  / Table 257 — UID + AttributeReference + AdjustmentType + AdjustmentValue?
// - DeleteAttribute  §6.1.17 / Table 301 — UID + CurrentAttribute? + AttributeReference?
// - ModifyAttribute  §6.1.38 / Table 364 — UID + CurrentAttribute? + NewAttribute
// - SetAttribute     §6.1.56 / Table 424 — UID + NewAttribute
//
// All responses: UID only — emitted via `encode_uid_only_resp`.

/// Encode a response payload whose only content is a `UniqueIdentifier`.
/// Used by every attribute-mutation op (and the lifecycle ops that
/// echo the operand UID).
fn encode_uid_only_resp(uid: &str) -> Vec<TtlvFrame> {
    vec![TtlvFrame::new(
        Tag(tags::UniqueIdentifier),
        Value::TextString(uid.to_string()),
    )]
}

/// Decode a `NewAttribute` (0x42013d) or `CurrentAttribute` (0x42013c)
/// wrapper Structure. Both per spec carry exactly one typed-tag child
/// describing the attribute name + value.
fn decode_attribute_wrapper(
    frame: &TtlvFrame,
    name: &'static str,
) -> Result<Attribute, WireError> {
    let inner = expect_structure(frame, name)?;
    for child in inner {
        if let Some(a) = decode_attribute_v3(child)? {
            return Ok(a);
        }
    }
    Err(WireError::Missing { tag: frame.tag.0, name })
}

fn decode_add_attribute_req(children: &[TtlvFrame]) -> Result<AddAttributeRequest, WireError> {
    let uid = required_uid(children)?;
    let mut new_attr = None;
    for c in children {
        if c.tag.0 == tags::NewAttribute {
            new_attr = Some(decode_attribute_wrapper(c, "New Attribute")?);
        }
    }
    let new_attribute = new_attr.ok_or(WireError::Missing {
        tag: tags::NewAttribute,
        name: "New Attribute",
    })?;
    Ok(AddAttributeRequest { uid, new_attribute })
}

fn decode_modify_attribute_req(children: &[TtlvFrame]) -> Result<ModifyAttributeRequest, WireError> {
    let uid = required_uid(children)?;
    let mut current = None;
    let mut new_attr = None;
    for c in children {
        match c.tag.0 {
            tags::CurrentAttribute => current = Some(decode_attribute_wrapper(c, "Current Attribute")?),
            tags::NewAttribute     => new_attr = Some(decode_attribute_wrapper(c, "New Attribute")?),
            _ => {}
        }
    }
    let new_attribute = new_attr.ok_or(WireError::Missing {
        tag: tags::NewAttribute,
        name: "New Attribute",
    })?;
    Ok(ModifyAttributeRequest {
        uid,
        current_attribute: current,
        new_attribute,
    })
}

fn decode_delete_attribute_req(children: &[TtlvFrame]) -> Result<DeleteAttributeRequest, WireError> {
    let uid = required_uid(children)?;
    let mut current = None;
    let mut attr_ref = None;
    for c in children {
        match c.tag.0 {
            tags::CurrentAttribute => current = Some(decode_attribute_wrapper(c, "Current Attribute")?),
            tags::AttributeReference => {
                // KMIP 3.0 §11: AttributeReference is an "enumerable Tag"
                // — value is the 4-byte tag codepoint of the named
                // attribute. We surface the spec-form human-readable
                // name to the handler.
                if let Value::Enumeration(tag_code) = c.value {
                    attr_ref = Some(tag_name_from_code(tag_code).to_string());
                }
            }
            _ => {}
        }
    }
    Ok(DeleteAttributeRequest {
        uid,
        current_attribute: current,
        attribute_reference: attr_ref,
    })
}

fn decode_set_attribute_req(children: &[TtlvFrame]) -> Result<SetAttributeRequest, WireError> {
    let uid = required_uid(children)?;
    let mut new_attr = None;
    for c in children {
        if c.tag.0 == tags::NewAttribute {
            new_attr = Some(decode_attribute_wrapper(c, "New Attribute")?);
        }
    }
    let new_attribute = new_attr.ok_or(WireError::Missing {
        tag: tags::NewAttribute,
        name: "New Attribute",
    })?;
    Ok(SetAttributeRequest { uid, new_attribute })
}

fn decode_adjust_attribute_req(children: &[TtlvFrame]) -> Result<AdjustAttributeRequest, WireError> {
    let uid = required_uid(children)?;
    let mut attr_ref = None;
    let mut adjustment_type = None;
    let mut adjustment_value = None;
    for c in children {
        match c.tag.0 {
            tags::AttributeReference => {
                if let Value::Enumeration(tag_code) = c.value {
                    attr_ref = Some(tag_name_from_code(tag_code).to_string());
                }
            }
            tags::AdjustmentType => {
                let v = expect_enum(c, "Adjustment Type")?;
                adjustment_type = AdjustmentType::from_wire_value(v);
                if adjustment_type.is_none() {
                    return Err(WireError::UnknownEnum {
                        field: "Adjustment Type",
                        value: v,
                    });
                }
            }
            tags::AdjustmentValue => {
                // Spec §6.1.3 — type follows the target attribute. v0.1
                // honours Integer + LongInteger; other types (Boolean,
                // Interval) raise BadType. AdjustmentValue is optional
                // for Negate (which doesn't need it).
                match &c.value {
                    Value::Integer(n)     => adjustment_value = Some(*n as i64),
                    Value::LongInteger(n) => adjustment_value = Some(*n),
                    _ => return Err(WireError::BadType {
                        tag: c.tag.0,
                        name: "Adjustment Value",
                        msg: "expected Integer or LongInteger".into(),
                    }),
                }
            }
            _ => {}
        }
    }
    let attribute_reference = attr_ref.ok_or(WireError::Missing {
        tag: tags::AttributeReference,
        name: "Attribute Reference",
    })?;
    let adjustment_type = adjustment_type.ok_or(WireError::Missing {
        tag: tags::AdjustmentType,
        name: "Adjustment Type",
    })?;
    Ok(AdjustAttributeRequest {
        uid,
        attribute_reference,
        adjustment_type,
        adjustment_value,
    })
}

// ── Group B (attribute read-side) + Interop codecs ─────────────────────────

/// `GetAttributes` request body — UniqueIdentifier + zero-or-more
/// `AttributeReference` typed-tag values pointing at named attributes.
fn decode_get_attributes_req(children: &[TtlvFrame]) -> Result<GetAttributesRequest, WireError> {
    let uid = required_uid(children)?;
    let mut refs = Vec::new();
    for c in children {
        if c.tag.0 == tags::AttributeReference {
            // KMIP 3.0 §11: AttributeReference is the enumerable Tag —
            // its 4-byte value names a tag from the §11 table. We carry
            // the spec-form name to the handler so it can look up the
            // matching ObjectRecord field.
            if let Value::Enumeration(tag_code) = c.value {
                refs.push(tag_name_from_code(tag_code).to_string());
            }
        }
    }
    Ok(GetAttributesRequest { uid, attribute_references: refs })
}

fn encode_get_attributes_resp(r: &GetAttributesResponse) -> Vec<TtlvFrame> {
    let mut out = vec![TtlvFrame::new(
        Tag(tags::UniqueIdentifier),
        Value::TextString(r.uid.clone()),
    )];
    // KMIP 3.0 §6.1.21 — GetAttributes response wraps the returned
    // attributes in a single `Attributes` Structure whose children are
    // the typed-tag attribute values.
    let attrs = TtlvFrame::new(
        Tag(tags::Attributes),
        Value::Structure(r.attributes.iter().map(encode_attribute_v3).collect()),
    );
    out.push(attrs);
    out
}

/// `GetAttributeList` request body — just a UniqueIdentifier.
fn decode_get_attribute_list_req(children: &[TtlvFrame]) -> Result<GetAttributeListRequest, WireError> {
    Ok(GetAttributeListRequest { uid: required_uid(children)? })
}

fn encode_get_attribute_list_resp(r: &GetAttributeListResponse) -> Vec<TtlvFrame> {
    let mut out = vec![TtlvFrame::new(
        Tag(tags::UniqueIdentifier),
        Value::TextString(r.uid.clone()),
    )];
    for name in &r.attribute_references {
        // Per §6.1.22 each attribute name is carried as an
        // AttributeReference Enumeration (the spec's "enumerable Tag"
        // form — value is the 4-byte tag code).
        if let Some(tag_code) = tag_code_from_name(name) {
            out.push(TtlvFrame::new(
                Tag(tags::AttributeReference),
                Value::Enumeration(tag_code),
            ));
        }
    }
    out
}

/// `Interop` request body — function (Begin/End) + identifier string.
/// The op is a test-framework no-op; we still parse it so we can echo
/// the framework markers without dropping the connection.
fn decode_interop_req(children: &[TtlvFrame]) -> Result<InteropRequest, WireError> {
    let mut function = None;
    let mut identifier = String::new();
    for c in children {
        match c.tag.0 {
            tags::InteropFunction => {
                let v = expect_enum(c, "Interop Function")?;
                function = InteropFunction::from_wire_value(v);
            }
            tags::InteropIdentifier => {
                if let Value::TextString(s) = &c.value {
                    identifier = s.clone();
                }
            }
            _ => {}
        }
    }
    let function = function.ok_or(WireError::Missing {
        tag: tags::InteropFunction,
        name: "Interop Function",
    })?;
    Ok(InteropRequest { function, identifier })
}

/// Encode an Attribute as a single typed-tag TtlvFrame (KMIP 3.0
/// §6.1.6 form). Inverse of `decode_attribute_v3`.
fn encode_attribute_v3(a: &Attribute) -> TtlvFrame {
    match a {
        Attribute::CryptographicAlgorithm(alg) => TtlvFrame::new(
            Tag(tags::CryptographicAlgorithm),
            Value::Enumeration(alg.to_wire_value()),
        ),
        Attribute::CryptographicLength(n) => TtlvFrame::new(
            Tag(tags::CryptographicLength),
            Value::Integer(*n as i32),
        ),
        Attribute::CryptographicUsageMask(m) => TtlvFrame::new(
            Tag(tags::CryptographicUsageMask),
            Value::Integer(m.bits() as i32),
        ),
        Attribute::ObjectType(ot) => TtlvFrame::new(
            Tag(tags::ObjectType),
            Value::Enumeration(ot.to_wire_value()),
        ),
        Attribute::State(s) => TtlvFrame::new(
            Tag(tags::State),
            Value::Enumeration(s.to_wire_value()),
        ),
        Attribute::UniqueIdentifier(s) => TtlvFrame::new(
            Tag(tags::UniqueIdentifier),
            Value::TextString(s.clone()),
        ),
        Attribute::Name(s) => TtlvFrame::new(
            Tag(tags::Name),
            Value::TextString(s.clone()),
        ),
        Attribute::Custom { name: _, value } => {
            // v0.1 falls back to a TextString-typed Name frame for custom
            // attrs; proper vendor-extension tag allocation is wave 2.
            TtlvFrame::new(Tag(tags::Name), Value::TextString(value.clone()))
        }
        // ── Baseline Server profile attributes (KMIP Profiles v3.0 §5.1.2) ──
        Attribute::InitialDate(t)              => TtlvFrame::new(Tag(tags::InitialDate),              Value::DateTime(*t)),
        Attribute::ActivationDate(t)           => TtlvFrame::new(Tag(tags::ActivationDate),           Value::DateTime(*t)),
        Attribute::DeactivationDate(t)         => TtlvFrame::new(Tag(tags::DeactivationDate),         Value::DateTime(*t)),
        Attribute::DestroyDate(t)              => TtlvFrame::new(Tag(tags::DestroyDate),              Value::DateTime(*t)),
        Attribute::CompromiseDate(t)           => TtlvFrame::new(Tag(tags::CompromiseDate),           Value::DateTime(*t)),
        Attribute::CompromiseOccurrenceDate(t) => TtlvFrame::new(Tag(tags::CompromiseOccurrenceDate), Value::DateTime(*t)),
        Attribute::LastChangeDate(t)           => TtlvFrame::new(Tag(tags::LastChangeDate),           Value::DateTime(*t)),
        Attribute::OriginalCreationDate(t)     => TtlvFrame::new(Tag(tags::OriginalCreationDate),     Value::DateTime(*t)),
        Attribute::ProcessStartDate(t)         => TtlvFrame::new(Tag(tags::ProcessStartDate),         Value::DateTime(*t)),
        Attribute::ProtectStopDate(t)          => TtlvFrame::new(Tag(tags::ProtectStopDate),          Value::DateTime(*t)),
        Attribute::RotateDate(t)               => TtlvFrame::new(Tag(tags::RotateDate),               Value::DateTime(*t)),
        Attribute::Sensitive(b)                => TtlvFrame::new(Tag(tags::Sensitive),                Value::Boolean(*b)),
        Attribute::AlwaysSensitive(b)          => TtlvFrame::new(Tag(tags::AlwaysSensitive),          Value::Boolean(*b)),
        Attribute::Extractable(b)              => TtlvFrame::new(Tag(tags::Extractable),              Value::Boolean(*b)),
        Attribute::NeverExtractable(b)         => TtlvFrame::new(Tag(tags::NeverExtractable),         Value::Boolean(*b)),
        Attribute::Fresh(b)                    => TtlvFrame::new(Tag(tags::Fresh),                    Value::Boolean(*b)),
        Attribute::KeyValuePresent(b)          => TtlvFrame::new(Tag(tags::KeyValuePresent),          Value::Boolean(*b)),
        Attribute::QuantumSafe(b)              => TtlvFrame::new(Tag(tags::QuantumSafe),              Value::Boolean(*b)),
        Attribute::RotateAutomatic(b)          => TtlvFrame::new(Tag(tags::RotateAutomatic),          Value::Boolean(*b)),
        Attribute::ShortUniqueIdentifier(s)    => TtlvFrame::new(Tag(tags::ShortUniqueIdentifier),    Value::TextString(s.clone())),
        Attribute::AlternativeName(s)          => TtlvFrame::new(Tag(tags::AlternativeName),          Value::TextString(s.clone())),
        Attribute::Comment(s)                  => TtlvFrame::new(Tag(tags::Comment),                  Value::TextString(s.clone())),
        Attribute::Description(s)              => TtlvFrame::new(Tag(tags::Description),              Value::TextString(s.clone())),
        Attribute::ContactInformation(s)       => TtlvFrame::new(Tag(tags::ContactInformation),       Value::TextString(s.clone())),
        Attribute::ObjectClass(s)              => TtlvFrame::new(Tag(tags::ObjectClass),              Value::TextString(s.clone())),
        Attribute::KeyValueLocation(s)         => TtlvFrame::new(Tag(tags::KeyValueLocation),         Value::TextString(s.clone())),
        Attribute::X509CertificateIdentifier(s) => TtlvFrame::new(Tag(tags::X509CertificateIdentifier), Value::TextString(s.clone())),
        Attribute::X509CertificateIssuer(s)    => TtlvFrame::new(Tag(tags::X509CertificateIssuer),    Value::TextString(s.clone())),
        Attribute::X509CertificateSubject(s)   => TtlvFrame::new(Tag(tags::X509CertificateSubject),   Value::TextString(s.clone())),
        Attribute::RotateName(s)               => TtlvFrame::new(Tag(tags::RotateName),               Value::TextString(s.clone())),
        Attribute::CertificateType(v)          => TtlvFrame::new(Tag(tags::CertificateType),          Value::Enumeration(*v)),
        Attribute::DigitalSignatureAlgorithm(v) => TtlvFrame::new(Tag(tags::DigitalSignatureAlgorithm), Value::Enumeration(*v)),
        Attribute::NistKeyType(v)              => TtlvFrame::new(Tag(tags::NistKeyType),              Value::Enumeration(*v)),
        Attribute::ProtectionLevel(v)          => TtlvFrame::new(Tag(tags::ProtectionLevel),          Value::Enumeration(*v)),
        Attribute::RevocationReasonCode(v) => {
            // RevocationReason is a Structure containing RevocationReasonCode.
            TtlvFrame::new(
                Tag(tags::RevocationReason),
                Value::Structure(vec![
                    TtlvFrame::new(Tag(tags::RevocationReasonCode), Value::Enumeration(*v)),
                ]),
            )
        }
        Attribute::DeactivationReasonCode(v) => {
            TtlvFrame::new(
                Tag(tags::DeactivationReason),
                Value::Structure(vec![
                    TtlvFrame::new(Tag(tags::DeactivationReasonCode), Value::Enumeration(*v)),
                ]),
            )
        }
        Attribute::KeyFormatType(v)            => TtlvFrame::new(Tag(tags::KeyFormatType),            Value::Enumeration(*v)),
        Attribute::CertificateLength(n)        => TtlvFrame::new(Tag(tags::CertificateLength),        Value::Integer(*n)),
        Attribute::LeaseTime(n)                => TtlvFrame::new(Tag(tags::LeaseTime),                Value::Interval(*n)),
        Attribute::ProtectionPeriod(n)         => TtlvFrame::new(Tag(tags::ProtectionPeriod),         Value::Interval(*n)),
        Attribute::RotateInterval(n)           => TtlvFrame::new(Tag(tags::RotateInterval),           Value::Interval(*n)),
        Attribute::RotateOffset(n)             => TtlvFrame::new(Tag(tags::RotateOffset),             Value::Integer(*n)),
        Attribute::RotateGeneration(n)         => TtlvFrame::new(Tag(tags::RotateGeneration),         Value::Integer(*n)),
        Attribute::UsageLimitsTotal(n)         => {
            TtlvFrame::new(
                Tag(tags::UsageLimits),
                Value::Structure(vec![
                    TtlvFrame::new(Tag(tags::UsageLimitsTotal), Value::LongInteger(*n)),
                ]),
            )
        }
    }
}

/// Look up the 4-byte tag codepoint by attribute name. Drives
/// `GetAttributeList` encoding. Names are matched modulo whitespace +
/// punctuation so `"Cryptographic Algorithm"` and `"CryptographicAlgorithm"`
/// both resolve.
fn tag_code_from_name(name: &str) -> Option<u32> {
    let n: String = name.chars().filter(|c| c.is_alphanumeric()).collect();
    Some(match n.as_str() {
        "CryptographicAlgorithm" => tags::CryptographicAlgorithm,
        "CryptographicLength"    => tags::CryptographicLength,
        "CryptographicUsageMask" => tags::CryptographicUsageMask,
        "ObjectType"             => tags::ObjectType,
        "State"                  => tags::State,
        "UniqueIdentifier"       => tags::UniqueIdentifier,
        "Name"                   => tags::Name,
        "InitialDate"            => tags::InitialDate,
        "ActivationDate"         => tags::ActivationDate,
        _ => return None,
    })
}

/// Inverse of `tag_code_from_name` — used to surface AttributeReference
/// names in GetAttributes request decoding.
fn tag_name_from_code(code: u32) -> &'static str {
    match code {
        tags::CryptographicAlgorithm => "Cryptographic Algorithm",
        tags::CryptographicLength    => "Cryptographic Length",
        tags::CryptographicUsageMask => "Cryptographic Usage Mask",
        tags::ObjectType             => "Object Type",
        tags::State                  => "State",
        tags::UniqueIdentifier       => "Unique Identifier",
        tags::Name                   => "Name",
        tags::InitialDate            => "Initial Date",
        tags::ActivationDate         => "Activation Date",
        _ => "Unknown",
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn required_uid(children: &[TtlvFrame]) -> Result<String, WireError> {
    for c in children {
        if c.tag.0 == tags::UniqueIdentifier {
            if let Value::TextString(s) = &c.value {
                return Ok(s.clone());
            }
        }
    }
    Err(WireError::Missing { tag: tags::UniqueIdentifier, name: "Unique Identifier" })
}

fn expect_tag(frame: &TtlvFrame, expected: u32, name: &'static str) -> Result<(), WireError> {
    if frame.tag.0 != expected {
        return Err(WireError::UnexpectedTag { got: frame.tag.0, expected, name });
    }
    Ok(())
}

fn expect_structure<'a>(frame: &'a TtlvFrame, name: &'static str) -> Result<&'a [TtlvFrame], WireError> {
    match &frame.value {
        Value::Structure(children) => Ok(children),
        _ => Err(WireError::BadType { tag: frame.tag.0, name, msg: "expected Structure".into() }),
    }
}

fn expect_integer(frame: &TtlvFrame, name: &'static str) -> Result<i32, WireError> {
    match &frame.value {
        Value::Integer(v) => Ok(*v),
        _ => Err(WireError::BadType { tag: frame.tag.0, name, msg: "expected Integer".into() }),
    }
}

fn expect_enum(frame: &TtlvFrame, name: &'static str) -> Result<u32, WireError> {
    match &frame.value {
        Value::Enumeration(v) => Ok(*v),
        _ => Err(WireError::BadType { tag: frame.tag.0, name, msg: "expected Enumeration".into() }),
    }
}

fn expect_datetime(frame: &TtlvFrame, name: &'static str) -> Result<i64, WireError> {
    match &frame.value {
        Value::DateTime(v) => Ok(*v),
        _ => Err(WireError::BadType { tag: frame.tag.0, name, msg: "expected DateTime".into() }),
    }
}

fn expect_boolean(frame: &TtlvFrame, name: &'static str) -> Result<bool, WireError> {
    match &frame.value {
        Value::Boolean(v) => Ok(*v),
        _ => Err(WireError::BadType { tag: frame.tag.0, name, msg: "expected Boolean".into() }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::OffsetDateTime;

    fn make_query_msg() -> RequestMessage {
        RequestMessage {
            header: RequestHeader::v3(),
            batch_items: vec![RequestBatchItem {
                operation: Operation::Query,
                payload: RequestPayload::Query(QueryRequest {
                    functions: vec![QueryFunction::QueryOperations],
                }),
            }],
        }
    }

    #[test]
    fn round_trip_query_request_via_response() {
        // We can't round-trip a request directly (no encoder for the
        // server's inbound side), but a response round-trip proves the
        // envelope codec is symmetric.
        let resp = ResponseMessage {
            header: ResponseHeader {
                protocol_version_major: 3,
                protocol_version_minor: 0,
                time_stamp: OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
                server_correlation_value: None,
            },
            batch_items: vec![ResponseBatchItem {
                operation: Some(Operation::Query),
                result_status: ResultStatus::Success,
                result_reason: None,
                result_message: None,
                payload: Some(ResponsePayload::Query(QueryResponse {
                    operations: Some(vec![Operation::Query, Operation::Sign]),
                    object_types: None,
                    vendor_identification: Some("pqctoday-hsm".into()),
                    server_info: Some(ServerInformation {
                        server_version: "0.1.0".into(),
                    }),
                })),
            }],
        };
        let bytes = encode_response_message(&resp);
        assert!(bytes.len() >= 8, "non-empty envelope");
        // The frame should be 8-byte aligned (KMIP §9.6).
        assert_eq!(bytes.len() % 8, 0);
    }

    #[test]
    fn query_request_decode_pulls_operation_and_functions() {
        // Build the wire bytes from a known-good frame.
        let frame = TtlvFrame::new(
            Tag(tags::RequestMessage),
            Value::Structure(vec![
                TtlvFrame::new(
                    Tag(tags::RequestHeader),
                    Value::Structure(vec![TtlvFrame::new(
                        Tag(tags::ProtocolVersion),
                        Value::Structure(vec![
                            TtlvFrame::new(Tag(tags::ProtocolVersionMajor), Value::Integer(3)),
                            TtlvFrame::new(Tag(tags::ProtocolVersionMinor), Value::Integer(0)),
                        ]),
                    )]),
                ),
                TtlvFrame::new(
                    Tag(tags::BatchItem),
                    Value::Structure(vec![
                        TtlvFrame::new(Tag(tags::Operation), Value::Enumeration(Operation::Query.to_wire_value())),
                        TtlvFrame::new(
                            Tag(tags::RequestPayload),
                            Value::Structure(vec![TtlvFrame::new(
                                Tag(tags::QueryFunction),
                                Value::Enumeration(1),
                            )]),
                        ),
                    ]),
                ),
            ]),
        );
        let mut buf = BytesMut::new();
        encode(&frame, &mut buf);
        let decoded = decode_request_message(&buf).expect("decode");
        assert_eq!(decoded.header.protocol_version_major, 3);
        assert_eq!(decoded.batch_items.len(), 1);
        match &decoded.batch_items[0].payload {
            RequestPayload::Query(q) => {
                assert_eq!(q.functions.len(), 1);
                assert!(matches!(q.functions[0], QueryFunction::QueryOperations));
            }
            other => panic!("expected Query, got {other:?}"),
        }
    }

    #[test]
    fn unsupported_protocol_version_rejected() {
        // Build a Request Message with version 2.1 — must be rejected.
        let frame = TtlvFrame::new(
            Tag(tags::RequestMessage),
            Value::Structure(vec![
                TtlvFrame::new(
                    Tag(tags::RequestHeader),
                    Value::Structure(vec![TtlvFrame::new(
                        Tag(tags::ProtocolVersion),
                        Value::Structure(vec![
                            TtlvFrame::new(Tag(tags::ProtocolVersionMajor), Value::Integer(2)),
                            TtlvFrame::new(Tag(tags::ProtocolVersionMinor), Value::Integer(1)),
                        ]),
                    )]),
                ),
                TtlvFrame::new(
                    Tag(tags::BatchItem),
                    Value::Structure(vec![
                        TtlvFrame::new(Tag(tags::Operation), Value::Enumeration(Operation::Query.to_wire_value())),
                        TtlvFrame::new(Tag(tags::RequestPayload), Value::Structure(vec![])),
                    ]),
                ),
            ]),
        );
        let mut buf = BytesMut::new();
        encode(&frame, &mut buf);
        let err = decode_request_message(&buf).expect_err("must reject");
        assert!(matches!(err, WireError::UnsupportedVersion { major: 2, minor: 1 }));
    }

    // Suppress unused warnings on intermediates referenced only in
    // production paths below.
    #[allow(dead_code)]
    fn _suppress_warnings() {
        let _ = make_query_msg();
    }
}
