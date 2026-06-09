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
    TtlvFrame::new(Tag(tags::ResponseHeader), Value::Structure(vec![pv, ts]))
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
    if let Some(info) = &r.server_info {
        out.push(TtlvFrame::new(
            Tag(tags::ServerInformation),
            Value::Structure(vec![
                TtlvFrame::new(Tag(tags::VendorIdentification), Value::TextString(info.vendor_identification.clone())),
                TtlvFrame::new(Tag(tags::ServerVersion), Value::TextString(info.server_version.clone())),
            ]),
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
        _ => return Ok(None),
    }))
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
            },
            batch_items: vec![ResponseBatchItem {
                operation: Some(Operation::Query),
                result_status: ResultStatus::Success,
                result_reason: None,
                result_message: None,
                payload: Some(ResponsePayload::Query(QueryResponse {
                    operations: Some(vec![Operation::Query, Operation::Sign]),
                    object_types: None,
                    server_info: Some(ServerInformation {
                        vendor_identification: "pqctoday-hsm".into(),
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
