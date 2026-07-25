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
pub mod vendor_tags;
pub mod wire;

pub use algos::{CkMechanismType, KmipAlgorithm, PkcsOp};
pub use attrs::{
    Attribute, CustomAttributeValue, DigestAttribute, ObjectType, RevocationReason, RngAttribute,
    State, UsageMask,
};
pub use ops::{
    ActivateRequest, ActivateResponse,
    AddAttributeRequest, AddAttributeResponse,
    AdjustAttributeRequest, AdjustAttributeResponse, AdjustmentType,
    CreateKeyPairRequest, CreateKeyPairResponse,
    CreateRequest, CreateResponse,
    DecryptRequest, DecryptResponse,
    EncapsulateRekeyInfo, EncapsulateRequest, EncapsulateResponse,
    DecapsulateRequest, DecapsulateResponse,
    DeleteAttributeRequest, DeleteAttributeResponse,
    DestroyRequest, DestroyResponse,
    EncryptRequest, EncryptResponse,
    GetAttributeListRequest, GetAttributeListResponse,
    GetAttributesRequest, GetAttributesResponse,
    GetRequest, GetResponse,
    InteropFunction, InteropRequest, InteropResponse,
    KeyBlock, KeyFormatType, KeyWrappingSpec,
    LocateRequest, LocateResponse,
    ModifyAttributeRequest, ModifyAttributeResponse,
    Operation,
    ProfileInformation, CapabilityInformation,
    QueryFunction, QueryRequest, QueryResponse,
    RevokeRequest, RevokeResponse,
    RngRetrieveRequest, RngRetrieveResponse,
    RngSeedRequest, RngSeedResponse,
    Pkcs11Request, Pkcs11Response,
    CreateCredentialRequest, CreateCredentialResponse,
    CreateGroupRequest, CreateGroupResponse,
    CreateUserRequest, CreateUserResponse,
    LogRequest, LogResponse,
    LoginRequest, LoginResponse,
    LogoutRequest, LogoutResponse,
    PasswordCredential,
    CryptographicParameters, HashingAlgorithm, KemAlgorithm,
    HashRequest, HashResponse,
    MacRequest, MacResponse,
    MacVerifyRequest, MacVerifyResponse,
    ArchiveRequest, ArchiveResponse,
    CheckRequest, CheckResponse,
    DeactivateRequest, DeactivateResponse, DeactivationReason,
    DiscoverVersionsRequest, DiscoverVersionsResponse,
    ExportRequest, ExportResponse,
    ImportRequest, ImportResponse,
    ObliterateRequest, ObliterateResponse,
    ObtainLeaseRequest, ObtainLeaseResponse,
    CreateSplitKeyRequest, CreateSplitKeyResponse,
    JoinSplitKeyRequest, JoinSplitKeyResponse,
    PingRequest, PingResponse,
    RecoverRequest, RecoverResponse,
    RegisterRequest, RegisterResponse,
    RekeyInfo,
    ServerInformation,
    SetAttributeRequest, SetAttributeResponse,
    SignatureValidity,
    SignatureVerifyRequest, SignatureVerifyResponse,
    SignRekeyInfo, SignRequest, SignResponse,
    ValidateRequest, ValidateResponse,
    // P2.3 — Certify (§6.1.6) / Re-certify (§6.1.52).
    CertificateRequestType,
    CertifyRequest, CertifyResponse,
    ReCertifyRequest, ReCertifyResponse,
    // K19 — Baseline client-to-server ops (§6.1.26/27/58/59).
    Constraint, EndpointRole, ObjectDefaults,
    GetConstraintsRequest, GetConstraintsResponse,
    GetUsageAllocationRequest, GetUsageAllocationResponse,
    SetConstraintsRequest, SetConstraintsResponse,
    SetDefaultsRequest, SetDefaultsResponse,
    SetEndpointRoleRequest, SetEndpointRoleResponse,
    // K20 — Derive Key (§6.1.19 / §7.13 / §11.15).
    DerivationMethod, DerivationParameters,
    DeriveKeyRequest, DeriveKeyResponse,
    // K21 — Re-key / Re-key Key Pair (§6.1.53 / §6.1.54).
    ReKeyKeyPairRequest, ReKeyKeyPairResponse, ReKeyRequest, ReKeyResponse,
    // Phase 4 — asynchronous subsystem (§6.1.5/§6.1.43/§6.1.44/§6.1.46).
    PollRequest,
    CancelRequest, CancelResponse,
    ProcessRequest, ProcessResponse,
    AsynchronousRequestInfo,
    QueryAsynchronousRequestsRequest, QueryAsynchronousRequestsResponse,
};

pub use message::{AsynchronousIndicator, BatchErrorContinuationOption, Credential, Ticket, TICKET_TYPE_LOGIN};
pub use message::{
    CancellationResult, ProcessingStage,
    RequestBatchItem, RequestHeader, RequestMessage, RequestPayload, ResponseBatchItem,
    ResponseHeader, ResponseMessage, ResponsePayload, ResultStatus, KMIP_VERSION_MAJOR,
    KMIP_VERSION_MINOR,
};
pub use wire::{
    decode_request_message, decode_transparent_rsa_private_key, decode_transparent_rsa_public_key,
    encode_request_message, encode_response_message, ttlv_decode_key_value, ttlv_encode_key_value,
    TransparentRsaPrivateKeyFields, TransparentRsaPublicKeyFields, WireError,
};
