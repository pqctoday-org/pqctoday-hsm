//! Plane 2 — KMIP 3.0 extension layer.
//!
//! Algorithm registry, attribute model, and operation request/response
//! struct definitions. Consumes the OASIS extraction in
//! `spec/oasis-kmip-3.0/kmip-spec-3.0-tags-enums.json` for wire-format
//! codepoints (see `docs/KMIP_3_0_DELTA.md` for the audit).
//!
//! Phase 3 (this commit) ships the typed surface; Phase 5 wires it into
//! op handlers; the codec layer ([`crate::codec`]) handles TTLV bytes ↔
//! these values per the spec's encoding rules.

pub mod algos;
pub mod attrs;
pub mod message;
pub mod ops;
pub mod wire;

pub use algos::{CkMechanismType, KmipAlgorithm, PkcsOp};
pub use attrs::{Attribute, ObjectType, RevocationReason, State, UsageMask};
pub use ops::{
    ActivateRequest, ActivateResponse,
    CreateKeyPairRequest, CreateKeyPairResponse,
    CreateRequest, CreateResponse,
    DecryptRequest, DecryptResponse,
    DestroyRequest, DestroyResponse,
    EncryptRequest, EncryptResponse,
    GetAttributeListRequest, GetAttributeListResponse,
    GetAttributesRequest, GetAttributesResponse,
    GetRequest, GetResponse,
    InteropFunction, InteropRequest, InteropResponse,
    KeyBlock, KeyFormatType,
    LocateRequest, LocateResponse,
    Operation,
    QueryFunction, QueryRequest, QueryResponse,
    RevokeRequest, RevokeResponse,
    ServerInformation,
    SignatureValidity,
    SignatureVerifyRequest, SignatureVerifyResponse,
    SignRequest, SignResponse,
};

pub use message::{
    RequestBatchItem, RequestHeader, RequestMessage, RequestPayload, ResponseBatchItem,
    ResponseHeader, ResponseMessage, ResponsePayload, ResultStatus, KMIP_VERSION_MAJOR,
    KMIP_VERSION_MINOR,
};
pub use wire::{decode_request_message, encode_response_message, WireError};
