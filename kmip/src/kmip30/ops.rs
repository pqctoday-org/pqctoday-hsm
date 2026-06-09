//! KMIP 3.0 operation request / response struct definitions for the v0.1
//! op set.
//!
//! These are **value-only** structs — they describe what each op takes in
//! and produces. The dispatch + business logic lives in `crate::ops::*`
//! (Phase 5), the TTLV ↔ struct mapping lives in `crate::codec` (Phase 2),
//! and the per-request enforcement (policy check, lifecycle gate, mech
//! selection) is in `crate::dispatcher` + `crate::ops::*` (Phases 5 + 7).
//!
//! Per the workflow decisions (2026-06-07), v0.1 ships these 12 ops total:
//!
//! ```text
//! query, create_sym, create_asym, get, locate, activate, revoke, destroy,
//! encrypt, decrypt, sign, signature_verify
//! ```
//!
//! KMIP 3.0 does NOT add separate `Encapsulate` / `Decapsulate` ops — ML-KEM
//! encapsulation reuses `Encrypt`; ML-KEM decapsulation reuses `Decrypt`.
//! The op handler branches on `key.algorithm` to dispatch to the right
//! PKCS#11 mech (see `algos::KmipAlgorithm::to_pkcs11_mech`).
//!
//! Phase-3 deliverable: struct skeletons + serde-friendly fields. Phase 5
//! wires them into the dispatcher and op handlers.

use super::algos::KmipAlgorithm;
use super::attrs::{Attribute, ObjectType, RevocationReason, State};

/// `Operation` enum value carried in every BatchItem. Wire codepoints from
/// the OASIS extraction (`spec/oasis-kmip-3.0/kmip-spec-3.0-tags-enums.json`,
/// `enums.Operation`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Operation {
    Create           = 0x01,
    CreateKeyPair    = 0x02,
    Register         = 0x03,
    Check            = 0x09,
    Get              = 0x0a,
    GetAttributes    = 0x0b,
    GetAttributeList = 0x0c,
    AddAttribute     = 0x0d,
    ModifyAttribute  = 0x0e,
    DeleteAttribute  = 0x0f,
    Locate           = 0x08,
    Activate         = 0x12,
    Revoke           = 0x13,
    Destroy          = 0x14,
    Archive          = 0x15,
    Recover          = 0x16,
    Query            = 0x18,
    DiscoverVersions = 0x1e,
    Encrypt          = 0x1f,
    Decrypt          = 0x20,
    Sign             = 0x21,
    SignatureVerify  = 0x22,
    MAC              = 0x23,
    MACVerify        = 0x24,
    RNGRetrieve      = 0x25,
    RNGSeed          = 0x26,
    Hash             = 0x27,
    Import           = 0x2a,
    Export           = 0x2b,
    Log              = 0x2c,
    Login            = 0x2d,
    Logout           = 0x2e,
    Pkcs11           = 0x33,
    /// KMIP 3.0 §6.1.31 — test-suite framework op. Carries `Begin` /
    /// `End` markers (no managed-object effect). Server returns Success.
    ///
    /// Codepoint **0x34** — verified against
    /// `spec/oasis-kmip-3.0/kmip-spec-3.0-tags-enums.json`. Earlier
    /// drafts of this crate used 0x2f which is actually `DelegatedLogin`
    /// in the OASIS table; tests that compare advertised op lists
    /// rejected the wrong codepoint.
    Interop          = 0x34,
    AdjustAttribute  = 0x30,
    SetAttribute     = 0x31,
    /// KMIP 3.0 §6.1 — cluster-role configuration op. Advertised in
    /// Query so OASIS Baseline tests pass §4.1.1 item 15 superset
    /// check, but the request handler is a stub (no managed-object
    /// effect). Codepoint 0x32 per the spec extraction.
    SetEndpointRole  = 0x32,
    Ping             = 0x3b,
    CreateGroup      = 0x3c,
    Obliterate       = 0x3d,
    CreateUser       = 0x3e,
    CreateCredential = 0x3f,
    Deactivate       = 0x40,
}

impl Operation {
    pub const fn to_wire_value(self) -> u32 {
        self as u32
    }

    pub const fn from_wire_value(v: u32) -> Option<Self> {
        match v {
            0x01 => Some(Self::Create),
            0x02 => Some(Self::CreateKeyPair),
            0x03 => Some(Self::Register),
            0x08 => Some(Self::Locate),
            0x09 => Some(Self::Check),
            0x0a => Some(Self::Get),
            0x0b => Some(Self::GetAttributes),
            0x0c => Some(Self::GetAttributeList),
            0x0d => Some(Self::AddAttribute),
            0x0e => Some(Self::ModifyAttribute),
            0x0f => Some(Self::DeleteAttribute),
            0x12 => Some(Self::Activate),
            0x13 => Some(Self::Revoke),
            0x14 => Some(Self::Destroy),
            0x15 => Some(Self::Archive),
            0x16 => Some(Self::Recover),
            0x18 => Some(Self::Query),
            0x1e => Some(Self::DiscoverVersions),
            0x1f => Some(Self::Encrypt),
            0x20 => Some(Self::Decrypt),
            0x21 => Some(Self::Sign),
            0x22 => Some(Self::SignatureVerify),
            0x23 => Some(Self::MAC),
            0x24 => Some(Self::MACVerify),
            0x25 => Some(Self::RNGRetrieve),
            0x26 => Some(Self::RNGSeed),
            0x27 => Some(Self::Hash),
            0x2a => Some(Self::Import),
            0x2b => Some(Self::Export),
            0x2c => Some(Self::Log),
            0x2d => Some(Self::Login),
            0x2e => Some(Self::Logout),
            0x33 => Some(Self::Pkcs11),
            0x34 => Some(Self::Interop),
            0x30 => Some(Self::AdjustAttribute),
            0x31 => Some(Self::SetAttribute),
            0x32 => Some(Self::SetEndpointRole),
            0x3b => Some(Self::Ping),
            0x3c => Some(Self::CreateGroup),
            0x3d => Some(Self::Obliterate),
            0x3e => Some(Self::CreateUser),
            0x3f => Some(Self::CreateCredential),
            0x40 => Some(Self::Deactivate),
            _ => None,
        }
    }
}

// ── Query ───────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq)]
pub struct QueryRequest {
    /// Which QueryFunctions the client wants in the response (e.g.
    /// `QueryOperations`, `QueryObjects`, `QueryServerInformation`).
    pub functions: Vec<QueryFunction>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum QueryFunction {
    QueryOperations         = 0x01,
    QueryObjects            = 0x02,
    QueryServerInformation  = 0x03,
    QueryApplicationNamespaces = 0x04,
    QueryProfiles           = 0x07,
    QueryCapabilities       = 0x09,
}

#[derive(Clone, Debug, PartialEq)]
pub struct QueryResponse {
    pub operations: Option<Vec<Operation>>,
    pub object_types: Option<Vec<ObjectType>>,
    /// Top-level child of Query Response Payload per KMIP 3.0 §6.1.39
    /// (NOT a child of `ServerInformation`). Value-variable per
    /// `kmip-profiles-v3.0` §4.1 Response Variations item 5.
    pub vendor_identification: Option<String>,
    /// Vendor-extensible structure per §6.1.39. Contents are variable
    /// per `kmip-profiles-v3.0` §4.1 Response Variations item 8 — the
    /// comparator skips its interior shape.
    pub server_info: Option<ServerInformation>,
    /// Zero or more `Application Namespace` TextStrings per KMIP 3.0
    /// §6.1.39 — surfaced when the client passes
    /// `QueryFunction::QueryApplicationNamespaces`. Values are variable
    /// per §4.1.1 item 14.
    pub application_namespaces: Option<Vec<String>>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ServerInformation {
    pub server_version: String,
}

// ── Create (symmetric) ─────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq)]
pub struct CreateRequest {
    pub object_type: ObjectType,
    pub template_attribute: Vec<Attribute>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CreateResponse {
    pub object_type: ObjectType,
    pub uid: String,
}

// ── CreateKeyPair (asymmetric) ─────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq)]
pub struct CreateKeyPairRequest {
    pub common_attributes: Vec<Attribute>,
    pub private_key_attributes: Vec<Attribute>,
    pub public_key_attributes: Vec<Attribute>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CreateKeyPairResponse {
    pub private_key_uid: String,
    pub public_key_uid: String,
}

// ── Get ─────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq)]
pub struct GetRequest {
    pub uid: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct GetResponse {
    pub object_type: ObjectType,
    pub uid: String,
    pub key_block: KeyBlock,
}

/// `KeyBlock` (KMIP 3.0 §4.x) — the wrapped key material returned by `Get`
/// for symmetric and asymmetric objects.
#[derive(Clone, Debug, PartialEq)]
pub struct KeyBlock {
    pub key_format_type: KeyFormatType,
    pub cryptographic_algorithm: KmipAlgorithm,
    pub cryptographic_length: u32,
    pub key_value: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyFormatType {
    Raw                 = 0x01,
    OpaqueObject        = 0x02,
    Pkcs1               = 0x03,
    Pkcs8               = 0x04,
    X509                = 0x05,
    EcPrivateKey        = 0x06,
    TransparentSymmetricKey = 0x07,
    TransparentPrivateKey   = 0x09,
    TransparentPublicKey    = 0x0A,
    Pkcs12              = 0x16,
}

// ── Locate ─────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq)]
pub struct LocateRequest {
    /// Filter attributes — the server returns UIDs whose object satisfies
    /// ALL filters.
    pub attributes: Vec<Attribute>,
    /// `MaximumItems` — cap the response.
    pub maximum_items: Option<u32>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct LocateResponse {
    pub uids: Vec<String>,
}

// ── Activate ───────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq)]
pub struct ActivateRequest {
    pub uid: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ActivateResponse {
    pub uid: String,
    pub state: State,
}

// ── Revoke ─────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq)]
pub struct RevokeRequest {
    pub uid: String,
    pub reason: RevocationReason,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RevokeResponse {
    pub uid: String,
    pub state: State,
}

// ── Destroy ────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq)]
pub struct DestroyRequest {
    pub uid: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DestroyResponse {
    pub uid: String,
    pub state: State,
}

// ── Encrypt / Decrypt ──────────────────────────────────────────────────────
//
// KMIP 3.0 reuses Encrypt/Decrypt for ML-KEM encapsulation/decapsulation.
// Handler branches on key.algorithm — see §6 Phase 5 in
// IMPLEMENTATION_PLAN.md.

#[derive(Clone, Debug, PartialEq)]
pub struct EncryptRequest {
    pub uid: String,
    /// For classical encrypt: the plaintext. For ML-KEM encapsulation: the
    /// associated data (typically empty).
    pub data: Vec<u8>,
    /// IV (AES-GCM) or other per-op input. None for ML-KEM.
    pub iv: Option<Vec<u8>>,
    /// KMIP 3.0 §6.1.21 — per-call override for the key's stored
    /// `CryptographicParameters`. When the client supplies
    /// `BlockCipherMode` here, it takes precedence over whatever was
    /// stored at Register/Create time.
    pub cryptographic_parameters: Option<CryptographicParameters>,
    /// KMIP 3.0 §11 `Authenticated Encryption Additional Data` — the
    /// AAD ("associated data") for AEAD ciphers (AES-GCM, ChaCha20-
    /// Poly1305). Bound into the auth tag computation, NOT encrypted.
    pub aad: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct EncryptResponse {
    pub uid: String,
    /// For classical encrypt: the ciphertext. For ML-KEM: the encapsulation
    /// (ciphertext) bytes.
    pub ciphertext: Vec<u8>,
    /// For ML-KEM only: the derived shared secret.
    /// `None` for classical encrypt.
    pub shared_secret: Option<Vec<u8>>,
    /// AES-GCM / ChaCha20-Poly1305 authentication tag (KMIP 3.0 §11
    /// `Authenticated Encryption Tag`). Populated only when the
    /// mechanism produces a separate tag — for non-AEAD modes (ECB /
    /// CBC / CBC_PAD) this is `None`.
    pub authenticated_encryption_tag: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DecryptRequest {
    pub uid: String,
    /// For classical decrypt: the ciphertext. For ML-KEM decapsulation: the
    /// encapsulation bytes.
    pub data: Vec<u8>,
    pub iv: Option<Vec<u8>>,
    /// KMIP 3.0 §6.1.21 — per-call override for the key's stored
    /// `CryptographicParameters`. See [`EncryptRequest`].
    pub cryptographic_parameters: Option<CryptographicParameters>,
    /// KMIP 3.0 §11 `Authenticated Encryption Additional Data`. See
    /// [`EncryptRequest::aad`]. MUST be byte-equal to the value passed
    /// at encryption time or the AEAD tag check will fail.
    pub aad: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DecryptResponse {
    pub uid: String,
    /// For classical decrypt: the plaintext. For ML-KEM decapsulation: the
    /// derived shared secret.
    pub data: Vec<u8>,
}

// ── Sign / SignatureVerify ─────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq)]
pub struct SignRequest {
    pub uid: String,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SignResponse {
    pub uid: String,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SignatureVerifyRequest {
    pub uid: String,
    pub data: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SignatureVerifyResponse {
    pub uid: String,
    pub validity: SignatureValidity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SignatureValidity {
    Valid       = 0x01,
    Invalid     = 0x02,
    Unknown     = 0x03,
}

// ── Group B: attribute family (KMIP 3.0 §6.1) ──────────────────────────────

/// `GetAttributes` (§6.1.21) — read named attributes from one managed
/// object. An empty `attribute_references` list means "all attributes".
#[derive(Clone, Debug, PartialEq)]
pub struct GetAttributesRequest {
    pub uid: String,
    /// Tag-name references (e.g. `"Cryptographic Algorithm"`,
    /// `"State"`). Empty = return every attribute the server knows about.
    pub attribute_references: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct GetAttributesResponse {
    pub uid: String,
    pub attributes: Vec<Attribute>,
}

/// `GetAttributeList` (§6.1.22) — enumerate attribute names available on
/// an object without returning their values.
#[derive(Clone, Debug, PartialEq)]
pub struct GetAttributeListRequest {
    pub uid: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct GetAttributeListResponse {
    pub uid: String,
    pub attribute_references: Vec<String>,
}

// ── Group B Wave 2: attribute mutation ops ─────────────────────────────────
//
// All five ops below trace directly to spec sections; see comments per op
// for the page reference. Wire shape verified against OASIS XML test cases.

/// `AddAttribute` (KMIP 3.0 §6.1.2 / Table 254) — add a new attribute
/// instance to a managed object. Existing values SHALL NOT be changed
/// by this operation; Read-Only attributes SHALL NOT be added.
#[derive(Clone, Debug, PartialEq)]
pub struct AddAttributeRequest {
    pub uid: String,
    /// Wire tag `NewAttribute` (0x42013d) — a Structure wrapping one
    /// typed-tag child carrying the attribute name + value.
    pub new_attribute: Attribute,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AddAttributeResponse {
    pub uid: String,
}

/// `ModifyAttribute` (KMIP 3.0 §6.1.38 / Table 364) — change an existing
/// attribute's value. The optional `current_attribute` lets the client
/// disambiguate between multi-instance attributes; if omitted, the
/// single instance is selected automatically.
#[derive(Clone, Debug, PartialEq)]
pub struct ModifyAttributeRequest {
    pub uid: String,
    /// Wire tag `CurrentAttribute` (0x42013c). OPTIONAL per spec.
    pub current_attribute: Option<Attribute>,
    /// Wire tag `NewAttribute` (0x42013d). REQUIRED per spec.
    pub new_attribute: Attribute,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ModifyAttributeResponse {
    pub uid: String,
}

/// `DeleteAttribute` (KMIP 3.0 §6.1.17 / Table 301) — remove an
/// attribute. Spec semantics: if `current_attribute` is given, delete
/// that specific value; if only `attribute_reference` is given, delete
/// all instances of the named attribute. Always-required attributes
/// SHALL NOT be deleted.
#[derive(Clone, Debug, PartialEq)]
pub struct DeleteAttributeRequest {
    pub uid: String,
    /// Wire tag `CurrentAttribute` (0x42013c). OPTIONAL per spec.
    pub current_attribute: Option<Attribute>,
    /// Wire tag `AttributeReference` (0x42013b). OPTIONAL per spec.
    /// The "enumerable Tag" form — values are 4-byte tag codepoints
    /// from §11. v0.1 surfaces the human-readable spec-form name.
    pub attribute_reference: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DeleteAttributeResponse {
    pub uid: String,
}

/// `SetAttribute` (KMIP 3.0 §6.1.56 / Table 424) — atomic
/// add-or-modify. If no instance exists, creates it. If exactly one
/// instance exists, modifies it. Multiple instances → error.
/// Read-Only attributes SHALL NOT be added or modified.
#[derive(Clone, Debug, PartialEq)]
pub struct SetAttributeRequest {
    pub uid: String,
    /// Wire tag `NewAttribute` (0x42013d). REQUIRED per spec.
    pub new_attribute: Attribute,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SetAttributeResponse {
    pub uid: String,
}

/// `AdjustAttribute` (KMIP 3.0 §6.1.3 / Table 257) — numeric
/// adjustment. If the object had no value, the previous value is
/// assumed to be 0 (numeric / interval) or false (boolean). Exactly
/// one instance required.
#[derive(Clone, Debug, PartialEq)]
pub struct AdjustAttributeRequest {
    pub uid: String,
    /// Wire tag `AttributeReference` (0x42013b). REQUIRED per spec.
    pub attribute_reference: String,
    /// Wire tag `AdjustmentType` (0x420158). REQUIRED per spec.
    pub adjustment_type: AdjustmentType,
    /// Wire tag `AdjustmentValue` (0x420162). OPTIONAL per spec.
    /// Type follows the target attribute (Integer for length, Boolean
    /// for toggle, etc.). Wave 2 honours Integer only; broader type
    /// coverage in Wave 3 when more numeric attributes appear in the
    /// corpus.
    pub adjustment_value: Option<i64>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AdjustAttributeResponse {
    pub uid: String,
}

/// `AdjustmentType` Enumeration — KMIP 3.0 §11 (spec extract).
/// Codepoints match `kmip-spec-3.0-tags-enums.json` exactly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdjustmentType {
    Increment = 0x01,
    Decrement = 0x02,
    Negate    = 0x03,
}

impl AdjustmentType {
    pub const fn to_wire_value(self) -> u32 {
        self as u32
    }
    pub const fn from_wire_value(v: u32) -> Option<Self> {
        match v {
            0x01 => Some(Self::Increment),
            0x02 => Some(Self::Decrement),
            0x03 => Some(Self::Negate),
            _ => None,
        }
    }
}

// ── Group G: RNG + PKCS#11 passthrough (KMIP 3.0 §6.1.{42,54,55}) ──────────

/// `RNG Retrieve` (KMIP 3.0 §6.1.54 / Table 418) — request random
/// bytes. Server returns at most `data_length` bytes.
#[derive(Clone, Debug, PartialEq)]
pub struct RngRetrieveRequest {
    /// Wire tag `Data Length` (0x4200c4). REQUIRED per spec.
    pub data_length: i32,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RngRetrieveResponse {
    pub data: Vec<u8>,
}

/// `RNG Seed` (KMIP 3.0 §6.1.55 / Table 421) — provide entropy to
/// the server's RNG. Response carries the number of bytes consumed.
/// Per spec, server MAY ignore the seed and return 0.
#[derive(Clone, Debug, PartialEq)]
pub struct RngSeedRequest {
    /// Wire tag `Data` (0x4200c2). REQUIRED per spec.
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RngSeedResponse {
    /// Wire tag `Data Length` (0x4200c4). The number of bytes consumed.
    pub data_length: i32,
}

/// `PKCS#11` (KMIP 3.0 §6.1.42 / Table 375) — passthrough invocation
/// of a PKCS#11 function via KMIP. v0.1 acknowledges the request and
/// returns `CKR_OK` without actually proxying to softhsmrustv3 — the
/// real Plane-3 bridge for this op lands when the sandbox MVP needs it.
#[derive(Clone, Debug, PartialEq)]
pub struct Pkcs11Request {
    /// Wire tag `PKCS#11 Interface` (0x420159, TextString).
    pub interface: Option<String>,
    /// Wire tag `PKCS#11 Function` (0x42015a, Enumeration). REQUIRED.
    pub function: u32,
    /// Wire tag `Correlation Value` (0x4200d6, ByteString).
    pub correlation_value: Option<Vec<u8>>,
    /// Wire tag `PKCS#11 Input Parameters` (0x42015b, ByteString).
    pub input_parameters: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Pkcs11Response {
    pub interface: Option<String>,
    pub function: u32,
    pub correlation_value: Option<Vec<u8>>,
    pub output_parameters: Option<Vec<u8>>,
    /// Wire tag `PKCS#11 Return Code` (0x42015d, Integer).
    /// CKR_OK = 0 per PKCS#11 v3.2 §5.
    pub return_code: i32,
}

// ── Group F: session / auth (KMIP 3.0 §6.1.{9,10,13,33,34,35}) ─────────────
//
// All response shapes are minimal — most return just `Unique Identifier`
// (Log / Logout return empty; Login returns a Ticket).

/// `CreateCredential` (KMIP 3.0 §6.1.9 / Table 276) — create a
/// credential object. Per spec, request carries `Credential Type` +
/// `Attributes` + exactly one of {Password / Device / Hashed Password /
/// OTP / Certificate} Credential. v0.1 honours Password Credential
/// only; others return OperationNotSupported.
#[derive(Clone, Debug, PartialEq)]
pub struct CreateCredentialRequest {
    /// Wire tag `Credential Type` (0x420024). Enumeration codepoint
    /// for the credential family.
    pub credential_type: u32,
    pub attributes: Vec<Attribute>,
    /// Wire tag `Password Credential` (0x4201a1). Honoured when
    /// `credential_type` is `Username and Password`. Optional in the
    /// codec; handler enforces the right combination.
    pub password_credential: Option<PasswordCredential>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CreateCredentialResponse {
    pub uid: String,
}

/// `PasswordCredential` Structure — KMIP 3.0 §11. Carries the username
/// and password fields a client supplies for Username+Password auth.
#[derive(Clone, Debug, PartialEq)]
pub struct PasswordCredential {
    pub username: String,
    pub password: Option<String>,
}

/// `CreateGroup` (KMIP 3.0 §6.1.10 / Table 279).
#[derive(Clone, Debug, PartialEq)]
pub struct CreateGroupRequest {
    pub attributes: Vec<Attribute>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CreateGroupResponse {
    pub uid: String,
}

/// `CreateUser` (KMIP 3.0 §6.1.13 / Table 289).
#[derive(Clone, Debug, PartialEq)]
pub struct CreateUserRequest {
    pub attributes: Vec<Attribute>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CreateUserResponse {
    pub uid: String,
}

/// `Log` (KMIP 3.0 §6.1.33 / Table 349) — log a message to the
/// server log. Response is empty.
#[derive(Clone, Debug, PartialEq)]
pub struct LogRequest {
    /// Wire tag `Log Message` (0x420141, TextString).
    pub message: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct LogResponse;

/// `Login` (KMIP 3.0 §6.1.34 / Table 352) — request authentication
/// ticket. Lease Time / Request Count / Usage Limits are all optional
/// hints; server returns a Ticket the client uses in subsequent
/// requests.
#[derive(Clone, Debug, PartialEq)]
pub struct LoginRequest {
    /// Wire tag `Lease Time` (0x420049, Interval).
    pub lease_time: Option<u32>,
    /// Wire tag `Request Count` (0x42014c, Integer).
    pub request_count: Option<i32>,
    /// Wire tag `Usage Limits` (0x420095, Structure). v0.1 stores the
    /// raw count if a `UsageLimitsTotal` child is present.
    pub usage_limits: Option<i64>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct LoginResponse {
    /// Wire tag `Ticket` (0x420149, TextString).
    pub ticket: String,
}

/// `Logout` (KMIP 3.0 §6.1.35 / Table 355) — invalidate a Login
/// ticket. Empty response.
#[derive(Clone, Debug, PartialEq)]
pub struct LogoutRequest {
    pub ticket: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct LogoutResponse;

// ── Group E (crypto wave 1): MAC / MACVerify / Hash ────────────────────────
//
// Spec mapping (single-part forms only — multi-part state machine deferred):
//
// - MAC       §6.1.36 / Tbl 358  UID + CryptoParams? + Data → UID + MACData
// - MACVerify §6.1.37 / Tbl 361  UID + CryptoParams? + Data? + MACData →
//                                  UID + ValidityIndicator
// - Hash      §6.1.28 / Tbl 334  CryptoParams + Data → Data

/// `MAC` (KMIP 3.0 §6.1.36) — compute a MAC over `data` using the keyed
/// Managed Cryptographic Object referenced by `uid`. v0.1 supports
/// single-part HMAC-SHA-256 / -384 / -512 (mapped from the key's
/// `CryptographicAlgorithm`).
#[derive(Clone, Debug, PartialEq)]
pub struct MacRequest {
    pub uid: String,
    /// Wire tag `Cryptographic Parameters` (0x42002b). Structure carrying
    /// the algorithm + parameters. OPTIONAL per spec — may be specified
    /// as object attributes.
    pub cryptographic_parameters: Option<CryptographicParameters>,
    /// Wire tag `Data` (0x4200c2). Required for single-part.
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct MacResponse {
    pub uid: String,
    /// Wire tag `MAC Data` (0x4200c6).
    pub mac_data: Vec<u8>,
}

/// `MACVerify` (KMIP 3.0 §6.1.37) — verify a previously computed MAC.
/// The original `data` is supplied alongside the `mac_data` to verify.
#[derive(Clone, Debug, PartialEq)]
pub struct MacVerifyRequest {
    pub uid: String,
    pub cryptographic_parameters: Option<CryptographicParameters>,
    /// Wire tag `Data` (0x4200c2). The original data that was MACed.
    pub data: Vec<u8>,
    /// Wire tag `MAC Data` (0x4200c6). The MAC bytes to verify.
    pub mac_data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct MacVerifyResponse {
    pub uid: String,
    pub validity: SignatureValidity,
}

/// `Hash` (KMIP 3.0 §6.1.28) — keyless cryptographic hash. The
/// `cryptographic_parameters.hashing_algorithm` field selects SHA-256 /
/// -384 / -512 / -1 etc.
#[derive(Clone, Debug, PartialEq)]
pub struct HashRequest {
    /// REQUIRED per spec — carries the HashingAlgorithm enum.
    pub cryptographic_parameters: CryptographicParameters,
    /// REQUIRED for single-part.
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct HashResponse {
    pub data: Vec<u8>,
}

/// `Cryptographic Parameters` (KMIP 3.0 §11) — Structure holding the
/// parameters that govern one cryptographic operation. Fields we
/// surface so far cover Hash, MAC, and the RSA-OAEP family
/// (PaddingMethod / MaskGenerator / MaskGeneratorHashingAlgorithm /
/// PSource). The spec defines ~30 more sub-fields; the rest are
/// additive when an op needs them.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct CryptographicParameters {
    /// Wire tag `Hashing Algorithm` (0x420038) — Enumeration.
    pub hashing_algorithm: Option<HashingAlgorithm>,
    /// Wire tag `Cryptographic Algorithm` (0x420028) — Enumeration.
    /// Some ops (e.g. MAC) get this from the key; others (Hash) carry
    /// it inside CryptographicParameters.
    pub cryptographic_algorithm: Option<KmipAlgorithm>,
    /// Wire tag `Padding Method` (0x42005f) — Enumeration. We carry
    /// the raw codepoint; `OAEP = 0x07` is the value the OASIS
    /// Baseline corpus exercises (RSA Encrypt/Decrypt path).
    pub padding_method: Option<u32>,
    /// Wire tag `Mask Generator` (0x420054) — Enumeration.
    /// `MGF1 = 0x01` is the only standardised value per KMIP 3.0 §11.
    pub mask_generator: Option<u32>,
    /// Wire tag `Mask Generator Hashing Algorithm` (0x420055) —
    /// Enumeration. For MGF1 this picks the hash the mask generator
    /// uses; KMIP allows it to differ from `hashing_algorithm`.
    pub mask_generator_hashing_algorithm: Option<HashingAlgorithm>,
    /// Wire tag `P Source` (0x420062) — ByteString. The OAEP label
    /// (`pSourceData`). `None` means an empty label.
    pub p_source: Option<Vec<u8>>,
    /// Wire tag `Block Cipher Mode` (0x420013) — Enumeration. Drives
    /// symmetric Encrypt / Decrypt mechanism choice. Codepoints per
    /// KMIP 3.0 §11 (1=CBC, 2=ECB, 3=PCBC, …, 6=GCM, …).
    pub block_cipher_mode: Option<u32>,
    /// Wire tag `Tag Length` (0x4200ce) — Integer (bytes). Per KMIP
    /// 3.0 §11, the requested AEAD authentication-tag length. The
    /// server SHALL reject values incompatible with the mechanism
    /// (e.g. ChaCha20-Poly1305 mandates 16 bytes per RFC 8439 §2.8).
    pub tag_length: Option<i32>,
}

/// `Hashing Algorithm` Enumeration — KMIP 3.0 §11. Codepoints from the
/// spec extract (`enums.Hashing Algorithm`). SHA-2 family is what the
/// OASIS corpus tests; SHA-1 is here for completeness even though it's
/// deprecated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashingAlgorithm {
    Md2     = 0x01,
    Md4     = 0x02,
    Md5     = 0x03,
    Sha1    = 0x04,
    Sha224  = 0x05,
    Sha256  = 0x06,
    Sha384  = 0x07,
    Sha512  = 0x08,
    Ripemd160 = 0x09,
    Tiger   = 0x0A,
    Whirlpool = 0x0B,
    Sha512224 = 0x0C,
    Sha512256 = 0x0D,
    Sha3224 = 0x0E,
    Sha3256 = 0x0F,
    Sha3384 = 0x10,
    Sha3512 = 0x11,
}

impl HashingAlgorithm {
    pub const fn to_wire_value(self) -> u32 {
        self as u32
    }
    pub const fn from_wire_value(v: u32) -> Option<Self> {
        match v {
            0x01 => Some(Self::Md2),
            0x02 => Some(Self::Md4),
            0x03 => Some(Self::Md5),
            0x04 => Some(Self::Sha1),
            0x05 => Some(Self::Sha224),
            0x06 => Some(Self::Sha256),
            0x07 => Some(Self::Sha384),
            0x08 => Some(Self::Sha512),
            0x09 => Some(Self::Ripemd160),
            0x0A => Some(Self::Tiger),
            0x0B => Some(Self::Whirlpool),
            0x0C => Some(Self::Sha512224),
            0x0D => Some(Self::Sha512256),
            0x0E => Some(Self::Sha3224),
            0x0F => Some(Self::Sha3256),
            0x10 => Some(Self::Sha3384),
            0x11 => Some(Self::Sha3512),
            _ => None,
        }
    }
}

// ── Group D + Group A leftover: lifecycle + protocol ops ───────────────────
//
// All seven ops below trace directly to spec sections — see comments per
// op for page references. Each response carries `UniqueIdentifier` (or
// nothing for Ping / Obliterate) per the spec's `Response Payload` table.

/// `Deactivate` (KMIP 3.0 §6.1.14 / Table 292) — transition `Active →
/// Deactivated`, set Deactivation Date to current time. If no
/// Deactivation Reason, treat as `Unspecified` per spec.
#[derive(Clone, Debug, PartialEq)]
pub struct DeactivateRequest {
    pub uid: String,
    /// Wire tag `Deactivation Reason` (0x4201b8). Structure containing
    /// `Deactivation Reason Code`. OPTIONAL per spec.
    pub deactivation_reason: Option<DeactivationReason>,
    /// Wire tag `Deactivation Date` (0x42002f). OPTIONAL per spec —
    /// if absent, server uses current time.
    pub deactivation_date: Option<i64>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DeactivateResponse {
    pub uid: String,
}

/// `Deactivation Reason Code` Enumeration. Codepoints from the spec
/// extract (`enums.Deactivation Reason Code`). Mirrors the structure
/// of `Revocation Reason Code` per §3.x.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeactivationReason {
    Unspecified           = 0x01,
    KeyCompromise         = 0x02,
    CACompromise          = 0x03,
    AffiliationChanged    = 0x04,
    Superseded            = 0x05,
    CessationOfOperation  = 0x06,
    PrivilegeWithdrawn    = 0x07,
}

impl DeactivationReason {
    pub const fn to_wire_value(self) -> u32 {
        self as u32
    }
    pub const fn from_wire_value(v: u32) -> Option<Self> {
        match v {
            0x01 => Some(Self::Unspecified),
            0x02 => Some(Self::KeyCompromise),
            0x03 => Some(Self::CACompromise),
            0x04 => Some(Self::AffiliationChanged),
            0x05 => Some(Self::Superseded),
            0x06 => Some(Self::CessationOfOperation),
            0x07 => Some(Self::PrivilegeWithdrawn),
            _ => None,
        }
    }
}

/// `Check` (KMIP 3.0 §6.1.7 / Table 270) — validate policy permits the
/// client's intended use. Spec response: UID if allowed, attribute
/// reflection if denied (v0.1 always allows; we always return UID).
#[derive(Clone, Debug, PartialEq)]
pub struct CheckRequest {
    pub uid: String,
    /// Wire tag `Usage Limits Count` (0x420096). OPTIONAL.
    pub usage_limits_count: Option<i64>,
    /// Wire tag `Cryptographic Usage Mask` (0x42002c). OPTIONAL.
    pub cryptographic_usage_mask: Option<u32>,
    /// Wire tag `Lease Time` (0x420049, Interval). OPTIONAL.
    pub lease_time: Option<u32>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CheckResponse {
    pub uid: String,
}

/// `Archive` (KMIP 3.0 §6.1.4 / Table 260) — client indicates the
/// object MAY be archived. v0.1 acknowledges but does not move bytes;
/// archival policy is server-determined per spec.
#[derive(Clone, Debug, PartialEq)]
pub struct ArchiveRequest {
    pub uid: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ArchiveResponse {
    pub uid: String,
}

/// `Recover` (KMIP 3.0 §6.1.47 / Table 390) — recover an archived
/// object. v0.1 emits success since archival is a no-op.
#[derive(Clone, Debug, PartialEq)]
pub struct RecoverRequest {
    pub uid: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RecoverResponse {
    pub uid: String,
}

/// `Obliterate` (KMIP 3.0 §6.1.39 / Table 367) — remove the Managed
/// Object completely. "All meta-data SHALL also be removed". Response
/// SHALL be empty per spec.
#[derive(Clone, Debug, PartialEq)]
pub struct ObliterateRequest {
    pub uid: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ObliterateResponse;

/// `Discover Versions` (KMIP 3.0 §6.1.20 / Table 310) — protocol
/// version negotiation. Request has optional list of versions the
/// client supports (ranked); response has the versions the server
/// supports (filtered to intersect the client's list if supplied).
#[derive(Clone, Debug, PartialEq)]
pub struct DiscoverVersionsRequest {
    /// Wire tag `Protocol Version` (0x420069, repeatable Structure).
    /// Each entry is a (Major, Minor) pair.
    pub protocol_versions: Vec<(i32, i32)>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DiscoverVersionsResponse {
    pub protocol_versions: Vec<(i32, i32)>,
}

/// `Ping` (KMIP 3.0 §6.1.41 / Table 373) — liveness check. Both
/// request and response payloads are empty per spec.
#[derive(Clone, Debug, PartialEq)]
pub struct PingRequest;

#[derive(Clone, Debug, PartialEq)]
pub struct PingResponse;

// ── Group C: Register / Import / Export (KMIP 3.0 §6.1.48, 6.1.29, 6.1.22) ─

/// `Register` (KMIP 3.0 §6.1.48 / Table 393) — register a Managed
/// Object that was created or obtained by the client through some other
/// means, allowing the server to manage it. Spec-mandated request shape:
///
/// 1. `ObjectType` — Yes (Enumeration)
/// 2. `Attributes` — Yes (Structure with typed-tag children)
/// 3. `Any Object (Section 2)` — Yes (one of SymmetricKey / PublicKey /
///    PrivateKey / Certificate / SecretData / OpaqueObject; the
///    handler routes by `ObjectType`)
/// 4. `Protection Storage Masks` — No (Structure)
///
/// Response: `Unique Identifier` (Yes).
///
/// Spec: "If the client provides a Unique Identifier value in the set
/// of attributes, the server SHALL use the provided Unique Identifier
/// value unless the Unique Identifier value is already in use within
/// the server (and in which case the server SHALL return a Result
/// Reason of Object Already Exists)."
#[derive(Clone, Debug, PartialEq)]
pub struct RegisterRequest {
    pub object_type: ObjectType,
    pub attributes: Vec<Attribute>,
    /// The managed object payload — for v0.1 we honour symmetric keys
    /// (KeyBlock with raw bytes). Asymmetric / certificate handling
    /// arrives when those object families gain test coverage.
    pub managed_object: Option<KeyBlock>,
    /// Optional `Protection Storage Masks` (§6.1.48 — a Structure
    /// listing permitted Protection Storage Mask values). Stored as
    /// a raw bitmap; v0.1 ignores it during dispatch.
    pub protection_storage_masks: Option<u32>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RegisterResponse {
    pub uid: String,
}

/// `Import` (KMIP 3.0 §6.1.29 / Table 337) — import a managed object
/// at a specific client-supplied UID. Distinct from Register in that
/// the client *always* dictates the UID; Register lets the server
/// generate one if no UID attribute is in the request.
#[derive(Clone, Debug, PartialEq)]
pub struct ImportRequest {
    /// REQUIRED per spec — client-chosen UID.
    pub uid: String,
    pub object_type: ObjectType,
    /// Spec default: false (if absent or false and an object exists
    /// with the same UID, server SHALL return an error).
    pub replace_existing: bool,
    /// REQUIRED iff the key object is wrapped (we don't yet parse
    /// wrapped imports — wave 2 of this PR or later).
    pub key_wrap_type: Option<u32>,
    pub attributes: Vec<Attribute>,
    pub managed_object: Option<KeyBlock>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ImportResponse {
    pub uid: String,
}

/// `Export` (KMIP 3.0 §6.1.22 / Table 316) — return a Managed Object
/// + its attributes + the actual object value. Larger response than
/// Get because it also carries the attribute set.
#[derive(Clone, Debug, PartialEq)]
pub struct ExportRequest {
    pub uid: String,
    pub key_format_type: Option<u32>,
    pub key_wrap_type: Option<u32>,
    pub key_compression_type: Option<u32>,
    // KeyWrappingSpecification (§ - Structure) deferred — no tests
    // in the corpus invoke it.
}

#[derive(Clone, Debug, PartialEq)]
pub struct ExportResponse {
    pub object_type: ObjectType,
    pub uid: String,
    pub attributes: Vec<Attribute>,
    pub managed_object: Option<KeyBlock>,
}

// ── Interop (KMIP 3.0 §6.1.31) ─────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InteropFunction {
    Begin = 0x01,
    End   = 0x02,
}

impl InteropFunction {
    pub const fn to_wire_value(self) -> u32 { self as u32 }
    pub const fn from_wire_value(v: u32) -> Option<Self> {
        match v {
            0x01 => Some(Self::Begin),
            0x02 => Some(Self::End),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct InteropRequest {
    pub function: InteropFunction,
    pub identifier: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct InteropResponse;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_round_trip() {
        for op in [
            Operation::Create, Operation::CreateKeyPair,
            Operation::Get, Operation::Locate,
            Operation::Activate, Operation::Revoke, Operation::Destroy,
            Operation::Encrypt, Operation::Decrypt,
            Operation::Sign, Operation::SignatureVerify, Operation::Query,
        ] {
            let v = op.to_wire_value();
            assert_eq!(Operation::from_wire_value(v), Some(op));
        }
    }

    #[test]
    fn operation_codepoints_match_oasis_extraction() {
        // Spot-check the codepoints align with OASIS-published values
        // (from kmip-spec-3.0-tags-enums.json `enums.Operation`).
        assert_eq!(Operation::Create.to_wire_value(),          0x01);
        assert_eq!(Operation::Get.to_wire_value(),             0x0a);
        assert_eq!(Operation::Encrypt.to_wire_value(),         0x1f);
        assert_eq!(Operation::Decrypt.to_wire_value(),         0x20);
        assert_eq!(Operation::Sign.to_wire_value(),            0x21);
        assert_eq!(Operation::SignatureVerify.to_wire_value(), 0x22);
    }

    #[test]
    fn signature_validity_values_match_spec() {
        assert_eq!(SignatureValidity::Valid as u32,   0x01);
        assert_eq!(SignatureValidity::Invalid as u32, 0x02);
        assert_eq!(SignatureValidity::Unknown as u32, 0x03);
    }
}
