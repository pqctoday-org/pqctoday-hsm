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
//! KMIP 3.0 WD19 (PQC Updates) DOES add native `Encapsulate` (0x41) /
//! `Decapsulate` (0x42) ops, and this server implements them (see the
//! Encapsulate/Decapsulate structs below and `ops::encapsulate` /
//! `ops::decapsulate`). For backward compatibility with pre-WD19 clients the
//! ML-KEM flow ALSO rides `Encrypt`/`Decrypt` (the handler branches on
//! `key.algorithm`; the shared secret is returned under the
//! `PQCToday-SharedSecret` vendor tag — see `docs/CONFORMANCE_REPORT.md`).

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
    /// KMIP 3.0 §6.1.59 — endpoint-role configuration op. K19: handled
    /// — `role=Server` is acknowledged (the server keeps the role it
    /// already has); `role=Client` (the §6.2 role switch) is rejected
    /// with `FeatureNotSupported` (see `ops::allocation_and_config`).
    /// Codepoint 0x32 per the spec extraction.
    SetEndpointRole  = 0x32,
    Ping             = 0x3b,
    CreateGroup      = 0x3c,
    Obliterate       = 0x3d,
    CreateUser       = 0x3e,
    CreateCredential = 0x3f,
    Deactivate       = 0x40,

    // ── KMIP 3.0 WD19 (PQC Updates) — KEM ops ─────────────────────────────
    // ML-KEM encapsulation / decapsulation as first-class operations.
    // Codepoints confirmed from the WD19 Operation enum (right after
    // Deactivate = 0x40).
    Encapsulate      = 0x41,
    Decapsulate      = 0x42,

    // ── KMIP 3.0 §11 — Advertised-only ops ────────────────────────────────
    // Operations the OASIS Baseline corpus requires the server to
    // enumerate in `Query` (per §4.1.1 items 15-16 superset rule) but
    // doesn't actually invoke. They have no dispatcher routes —
    // `decode_request_payload` rejects any inbound request with
    // `UnknownEnum` so a misdirected client gets a structured
    // `InvalidMessage` rather than a silent success. Codepoints
    // verified against `kmip-spec-3.0-tags-enums.json`.
    ReKey                     = 0x04,
    ReCertify                 = 0x07,
    ObtainLease               = 0x10,
    /// K19 — handled (§6.1.27): grants a usage allocation by
    /// decrementing the object's tracked `Usage Limits Count`.
    GetUsageAllocation        = 0x11,
    Validate                  = 0x17,
    Poll                      = 0x1a,
    Notify                    = 0x1b,
    Put                       = 0x1c,
    CreateSplitKey            = 0x28,
    SetConstraints            = 0x37,
    /// K19 — handled (§6.1.26): reports the static engine-backed
    /// constraint table.
    GetConstraints            = 0x38,
    QueryAsynchronousRequests = 0x39,
    Process                   = 0x3a,

    // ── K3 — remaining KMIP 3.0 §11 Operation codepoints ──────────────────
    // With these the enum covers all 64 published Operation values
    // (0x01–0x40, `kmip-spec-3.0-tags-enums.json` `enums.Operation`).
    // None has a dispatcher route — a recognized op without a handler
    // decodes to `RequestPayload::Unsupported(op)` and the dispatcher
    // fails that batch item with `OperationNotSupported (0x05)` per
    // KMIP 3.0 §9.2, leaving the rest of the message intact.
    DeriveKey                 = 0x05,
    Certify                   = 0x06,
    Cancel                    = 0x19,
    ReKeyKeyPair              = 0x1d,
    JoinSplitKey              = 0x29,
    DelegatedLogin            = 0x2f,
    ReProvision               = 0x35,
    /// K19 — handled (§6.1.58): stores per-Object-Type default
    /// attributes applied beneath client templates on Create /
    /// CreateKeyPair / Register.
    SetDefaults               = 0x36,
}

impl Operation {
    pub const fn to_wire_value(self) -> u32 {
        self as u32
    }

    /// Short stable label for Prometheus `operation` dimensions.
    pub const fn metric_label(self) -> &'static str {
        match self {
            Self::Create => "Create",
            Self::CreateKeyPair => "CreateKeyPair",
            Self::Register => "Register",
            Self::Get => "Get",
            Self::GetAttributes => "GetAttributes",
            Self::GetAttributeList => "GetAttributeList",
            Self::AddAttribute => "AddAttribute",
            Self::ModifyAttribute => "ModifyAttribute",
            Self::DeleteAttribute => "DeleteAttribute",
            Self::SetAttribute => "SetAttribute",
            Self::AdjustAttribute => "AdjustAttribute",
            Self::Locate => "Locate",
            Self::Activate => "Activate",
            Self::Revoke => "Revoke",
            Self::Destroy => "Destroy",
            Self::Archive => "Archive",
            Self::Recover => "Recover",
            Self::Query => "Query",
            Self::DiscoverVersions => "DiscoverVersions",
            Self::Encrypt => "Encrypt",
            Self::Decrypt => "Decrypt",
            Self::Sign => "Sign",
            Self::SignatureVerify => "SignatureVerify",
            Self::MAC => "MAC",
            Self::MACVerify => "MACVerify",
            Self::Hash => "Hash",
            Self::RNGRetrieve => "RNGRetrieve",
            Self::RNGSeed => "RNGSeed",
            Self::Import => "Import",
            Self::Export => "Export",
            Self::Encapsulate => "Encapsulate",
            Self::Decapsulate => "Decapsulate",
            Self::ReKey => "ReKey",
            Self::ReCertify => "ReCertify",
            Self::Certify => "Certify",
            Self::Validate => "Validate",
            Self::Ping => "Ping",
            Self::Check => "Check",
            _ => "Other",
        }
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
            0x41 => Some(Self::Encapsulate),
            0x42 => Some(Self::Decapsulate),
            0x04 => Some(Self::ReKey),
            0x07 => Some(Self::ReCertify),
            0x10 => Some(Self::ObtainLease),
            0x11 => Some(Self::GetUsageAllocation),
            0x17 => Some(Self::Validate),
            0x1a => Some(Self::Poll),
            0x1b => Some(Self::Notify),
            0x1c => Some(Self::Put),
            0x28 => Some(Self::CreateSplitKey),
            0x37 => Some(Self::SetConstraints),
            0x38 => Some(Self::GetConstraints),
            0x39 => Some(Self::QueryAsynchronousRequests),
            0x3a => Some(Self::Process),
            0x05 => Some(Self::DeriveKey),
            0x06 => Some(Self::Certify),
            0x19 => Some(Self::Cancel),
            0x1d => Some(Self::ReKeyKeyPair),
            0x29 => Some(Self::JoinSplitKey),
            0x2f => Some(Self::DelegatedLogin),
            0x35 => Some(Self::ReProvision),
            0x36 => Some(Self::SetDefaults),
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

/// `Query Function` Enumeration — KMIP 3.0 §11. Codepoints verified
/// against `kmip-spec-3.0-tags-enums.json` (`enums."Query Function"`):
/// Profiles = 0x0a, Capabilities = 0x0b (0x07/0x09 are Query
/// Attestation Types / Query Validations — earlier revisions of this
/// crate had those values wrong; fixed in K3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum QueryFunction {
    QueryOperations         = 0x01,
    QueryObjects            = 0x02,
    QueryServerInformation  = 0x03,
    QueryApplicationNamespaces = 0x04,
    QueryProfiles           = 0x0a,
    QueryCapabilities       = 0x0b,
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
    /// Zero or more `Profile Information` Structures (tag 0x4200eb)
    /// per KMIP 3.0 §6.1.45 — surfaced when the client passes
    /// `QueryFunction::QueryProfiles`. `Some(vec![])` is an explicit
    /// "no profiles claimed" answer (nothing emitted on the wire);
    /// the K13 decision on which profiles to formally claim is pending.
    pub profile_information: Option<Vec<ProfileInformation>>,
    /// `Capability Information` Structure (tag 0x4200f7) per KMIP 3.0
    /// §6.1.45 — surfaced when the client passes
    /// `QueryFunction::QueryCapabilities`.
    pub capability_information: Option<CapabilityInformation>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ServerInformation {
    pub server_version: String,
}

/// `Profile Information` Structure — KMIP 3.0 §11 (tag 0x4200eb).
/// Carries `Profile Name` (Enumeration, 0x4200ec) plus optional
/// `Profile Version` — only the name is modelled until K13 decides
/// which profiles the server formally claims.
#[derive(Clone, Debug, PartialEq)]
pub struct ProfileInformation {
    /// `Profile Name` enumeration codepoint (spec extract
    /// `enums."Profile Name"`).
    pub profile_name: u32,
}

/// `Capability Information` Structure — KMIP 3.0 §11 (tag 0x4200f7).
/// Honest server-capability report (compliance-audit K-11): the five
/// Boolean children the codec emits. Enumeration children (Unwrap
/// Mode / Destroy Action / Shredding Algorithm / RNG Mode) are
/// additive when the corresponding subsystems gain explicit policies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapabilityInformation {
    /// `Streaming Capability` (0x4200ef) — multi-part Encrypt/Decrypt
    /// via Init/Final indicators + Correlation Value is implemented.
    pub streaming_capability: bool,
    /// `Asynchronous Capability` (0x4200f0) — not supported; the
    /// server processes every batch item synchronously.
    pub asynchronous_capability: bool,
    /// `Attestation Capability` (0x4200f1) — not supported.
    pub attestation_capability: bool,
    /// `Batch Undo Capability` (0x4200f9) — §9.5 Undo rollback wave
    /// is implemented in the dispatcher.
    pub batch_undo_capability: bool,
    /// `Batch Continue Capability` (0x4200fa) — §9.5 Continue mode is
    /// implemented in the dispatcher.
    pub batch_continue_capability: bool,
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
    /// `Seed` (0x4201C6, KMIP 3.0 WD19) — ByteString. When present, the key
    /// pair is generated deterministically from this seed (FIPS 204 ξ /
    /// FIPS 203 d‖z / FIPS 205 SK.seed‖SK.prf‖PK.seed) instead of the RNG.
    pub seed: Option<Vec<u8>>,
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
    /// K8 — KMIP 3.0 §6.1.23 `Key Format Type`: the format the client
    /// wants the material returned in. Absent → stored format;
    /// requested == stored → as-is; convertible pair → convert;
    /// anything else → `Key Format Type Not Supported (0x10)`.
    /// Raw codepoint so unknown values reach the handler and fail
    /// with 0x10 instead of dying as a decode error.
    pub key_format_type: Option<u32>,
    /// KMIP 3.0 §6.1.23 — when present, the server returns the key
    /// material wrapped under the referenced wrapping key instead of
    /// in the clear. AX-M-2 pins WrappingMethod=Encrypt with
    /// BlockCipherMode=NISTKeyWrap (AES-KW, RFC 3394).
    pub key_wrapping_specification: Option<KeyWrappingSpec>,
}

/// KMIP 3.0 `Key Wrapping Specification` (request side) and
/// `Key Wrapping Data` (response side) share this shape — the response
/// echoes the specification that produced the wrapped KeyValue.
#[derive(Clone, Debug, PartialEq)]
pub struct KeyWrappingSpec {
    /// §11 `Wrapping Method` — only `Encrypt` (0x01) is supported.
    pub wrapping_method: u32,
    /// `Encryption Key Information / Unique Identifier` — the wrap key.
    pub encryption_key_uid: String,
    /// `Encryption Key Information / Cryptographic Parameters` —
    /// `BlockCipherMode=NISTKeyWrap` selects AES-KW.
    pub cryptographic_parameters: Option<CryptographicParameters>,
    /// §4.x `Encoding Option` — how the cleartext was encoded before
    /// wrapping: `0x01` No Encoding (raw key material), `0x02` TTLV
    /// Encoding (the spec default when absent). Values verified from
    /// the "Encoding Option" enum in `kmip-spec-3.0-tags-enums.json`.
    pub encoding_option: Option<u32>,
    /// K17 — `MAC/Signature Key Information` was present on an inbound
    /// `KeyWrappingData` (Register). Only Encrypt-method wrapping is
    /// supported; the unwrap path rejects this with
    /// `UnsupportedCryptographicParameters (0x3e)`.
    pub mac_signature_key_information_present: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct GetResponse {
    pub object_type: ObjectType,
    pub uid: String,
    pub key_block: KeyBlock,
    /// KMIP 3.0 §6.2 OpaqueObject pass-through — the client-supplied
    /// `OpaqueDataType` codepoint stashed at Register time, echoed
    /// in the Get response wrapper. `None` for non-Opaque objects.
    pub opaque_data_type: Option<u32>,
    /// KMIP 3.0 §6.2 `SecretDataType` for a `SecretData` object
    /// (Password = 0x01, Seed = 0x02). `None` renders as the Password
    /// default. Only meaningful when `object_type == SecretData`.
    pub secret_data_type: Option<u32>,
    /// KMIP 3.0 WD19 §3.4 — the generation seed, present only when the
    /// client requested `KeyFormatType=SeedPrivateKey`. The wire encoder
    /// emits the `KeyMaterial` as a `{ Seed, Key }` structure.
    pub seed: Option<Vec<u8>>,
}

/// `KeyBlock` (KMIP 3.0 §4.x) — the wrapped key material returned by `Get`
/// for symmetric and asymmetric objects.
#[derive(Clone, Debug, PartialEq)]
pub struct KeyBlock {
    pub key_format_type: KeyFormatType,
    pub cryptographic_algorithm: KmipAlgorithm,
    pub cryptographic_length: u32,
    pub key_value: Vec<u8>,
    /// KMIP 3.0 §4.x — present when `key_value` carries the AES-KW
    /// wrapped TTLV-encoded KeyValue rather than cleartext material.
    /// On the wire this flips `KeyValue` from Structure to ByteString
    /// and appends a `KeyWrappingData` structure (AX-M-2).
    pub key_wrapping_data: Option<KeyWrappingSpec>,
}

/// KMIP 3.0 §11 `Key Format Type` enumeration — names and codepoints
/// verified against the "Key Format Type" table in
/// `spec/oasis-kmip-3.0/kmip-spec-3.0-tags-enums.json` (K8 fixed the
/// previously mislabeled 0x09/0x0A variants: 0x09 is Transparent DSA
/// *Public* Key and 0x0A is Transparent RSA *Private* Key).
/// 0x0E–0x13 are (Reserved) in the spec table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyFormatType {
    Raw                      = 0x01,
    OpaqueObject             = 0x02,
    Pkcs1                    = 0x03,
    Pkcs8                    = 0x04,
    X509                     = 0x05,
    EcPrivateKey             = 0x06,
    TransparentSymmetricKey  = 0x07,
    TransparentDsaPrivateKey = 0x08,
    TransparentDsaPublicKey  = 0x09,
    TransparentRsaPrivateKey = 0x0A,
    TransparentRsaPublicKey  = 0x0B,
    TransparentDhPrivateKey  = 0x0C,
    TransparentDhPublicKey   = 0x0D,
    TransparentEcPrivateKey  = 0x14,
    TransparentEcPublicKey   = 0x15,
    Pkcs12                   = 0x16,
    Pkcs10                   = 0x17,
    /// KMIP 3.0 WD19 §3.4 (Table 575) — seed-based private-key format
    /// for algorithms with a deterministic seed (ML-DSA ξ, ML-KEM d‖z,
    /// SLH-DSA seed). `KeyMaterial` is a Structure of `Seed` + `Key`.
    SeedPrivateKey           = 0x18,
}

impl KeyFormatType {
    /// Map a wire codepoint to the typed variant. `None` for unknown /
    /// reserved codepoints — K8: callers MUST surface those as
    /// `Key Format Type Not Supported (0x10)` instead of silently
    /// coercing to `Raw`.
    pub fn from_wire_value(v: u32) -> Option<Self> {
        Some(match v {
            0x01 => Self::Raw,
            0x02 => Self::OpaqueObject,
            0x03 => Self::Pkcs1,
            0x04 => Self::Pkcs8,
            0x05 => Self::X509,
            0x06 => Self::EcPrivateKey,
            0x07 => Self::TransparentSymmetricKey,
            0x08 => Self::TransparentDsaPrivateKey,
            0x09 => Self::TransparentDsaPublicKey,
            0x0A => Self::TransparentRsaPrivateKey,
            0x0B => Self::TransparentRsaPublicKey,
            0x0C => Self::TransparentDhPrivateKey,
            0x0D => Self::TransparentDhPublicKey,
            0x14 => Self::TransparentEcPrivateKey,
            0x15 => Self::TransparentEcPublicKey,
            0x16 => Self::Pkcs12,
            0x17 => Self::Pkcs10,
            0x18 => Self::SeedPrivateKey,
            _ => return None,
        })
    }

    /// KMIP 3.0 §6.2.1 — formats whose `KeyMaterial` is a TTLV
    /// Structure of named fields rather than a ByteString leaf. For
    /// `TransparentSymmetricKey` the engine stores the inner `Key`
    /// bytes; for the other transparent forms the wire layer stores
    /// the TTLV-encoded `KeyMaterial` Structure verbatim so Get /
    /// Export can round-trip it byte-faithfully.
    pub fn is_transparent_structure(self) -> bool {
        matches!(
            self,
            Self::TransparentSymmetricKey
                | Self::TransparentDsaPrivateKey
                | Self::TransparentDsaPublicKey
                | Self::TransparentRsaPrivateKey
                | Self::TransparentRsaPublicKey
                | Self::TransparentDhPrivateKey
                | Self::TransparentDhPublicKey
                | Self::TransparentEcPrivateKey
                | Self::TransparentEcPublicKey
        )
    }
}

// ── Locate ─────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default, PartialEq)]
pub struct LocateRequest {
    /// Filter attributes — the server returns UIDs whose object satisfies
    /// ALL filters.
    pub attributes: Vec<Attribute>,
    /// `MaximumItems` — cap the response.
    pub maximum_items: Option<u32>,
    /// `Offset Items` (tag 0x4200d4, KMIP 3.0 §6.1.32) — number of
    /// matching identifiers to skip before filling the response page.
    pub offset_items: Option<u32>,
    /// `Storage Status Mask` (tag 0x42008e, §6.1.32 / §12.3 Table 608) —
    /// bit mask of storage classes to search: On-line 0x01, Archival
    /// 0x02, Destroyed 0x04. Omitted ⇒ On-line only.
    pub storage_status_mask: Option<u32>,
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

#[derive(Clone, Debug, Default, PartialEq)]
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
    /// KMIP 3.0 §6.1.21 multi-part streaming — `Init Indicator` opens a
    /// stream: the server returns a `Correlation Value` instead of
    /// finalising. CS-BC-M-GCM-3 pins the GCM streaming flow.
    pub init_indicator: Option<bool>,
    /// §6.1.21 — `Final Indicator` closes the stream identified by
    /// `correlation_value`; the response carries the AEAD tag.
    pub final_indicator: Option<bool>,
    /// §6.1.21 — server-issued handle chaining the parts of one stream.
    pub correlation_value: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct EncryptResponse {
    pub uid: String,
    /// For classical encrypt: the ciphertext. For ML-KEM: the encapsulation
    /// (ciphertext) bytes.
    pub ciphertext: Vec<u8>,
    /// For ML-KEM only: the derived shared secret.
    /// `None` for classical encrypt. On the wire this rides the
    /// `PQCToday-SharedSecret` vendor-extension tag (`0x540001`, see
    /// [`super::vendor_tags`]) — never `IVCounterNonce` (K10 / B-7).
    pub shared_secret: Option<Vec<u8>>,
    /// AES-GCM / ChaCha20-Poly1305 authentication tag (KMIP 3.0 §11
    /// `Authenticated Encryption Tag`). Populated only when the
    /// mechanism produces a separate tag — for non-AEAD modes (ECB /
    /// CBC / CBC_PAD) this is `None`.
    pub authenticated_encryption_tag: Option<Vec<u8>>,
    /// KMIP 3.0 §6.1.21 — the IV/Counter/Nonce the server generated when
    /// the key's `CryptographicParameters.RandomIV` was true. Echoed
    /// back so the client can use it for the subsequent Decrypt.
    /// `None` when the client supplied the IV (or the mech is keyless).
    pub iv_counter_nonce: Option<Vec<u8>>,
    /// §6.1.21 streaming — echoed on every non-final part so the client
    /// can chain the next request. `None` for single-part ops and on
    /// the final part.
    pub correlation_value: Option<Vec<u8>>,
    /// Set when the active policy triggered a transparent crypto-agility
    /// rekey during this Encrypt (`Decision::RekeyAndProceed` — AES-128 →
    /// AES-256): `uid` above is the freshly-minted replacement key. Internal-
    /// only, never encoded onto the wire. `None` on the ordinary path.
    pub rekeyed: Option<RekeyInfo>,
}

/// Crypto-agility rekey provenance surfaced on the response of a rekey-on-use
/// op (Encrypt / Encapsulate). The Sign path uses [`SignRekeyInfo`] (kept
/// distinct so the dispatcher's §9.5 Undo wave and wire encoders are
/// untouched). `new_public_key_uid` is set for asymmetric replacements.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct RekeyInfo {
    /// The original key's UID — now Deactivated + superseded.
    pub old_uid: String,
    /// The replacement's primary UID (symmetric key, or the private key of a pair).
    pub new_uid: String,
    /// The replacement public-key UID for an asymmetric rekey; `None` for symmetric.
    pub new_public_key_uid: Option<String>,
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

// ── Encapsulate / Decapsulate (KMIP 3.0 WD19, PQC Updates) ──────────────────
//
// First-class ML-KEM KEM operations. Unlike the Encrypt/Decrypt overload
// (which returns the shared secret inline), these create a NEW managed
// Secret-Data object holding the derived shared secret and return its UID;
// a subsequent Get on that UID retrieves the 32-byte shared secret.

/// `Encapsulate` request (KMIP 3.0 WD19) — the public/encapsulation key
/// UID plus, inside `CryptographicParameters`, the optional 32-byte
/// `InputKeyMaterial` (the FIPS 203 §7.2 coins `m`). When the coins are
/// present, encapsulation is deterministic (interop / KAT reproducibility);
/// when absent, the server samples `m` from its RNG.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct EncapsulateRequest {
    pub uid: String,
    /// `InputKeyMaterial` (0x4201C7, ByteString) — the 32-byte coins `m`.
    /// Nested inside `CryptographicParameters` on the wire; surfaced here
    /// hoisted for the handler's convenience.
    pub input_key_material: Option<Vec<u8>>,
    /// Per-op `CryptographicParameters` (carries the nested
    /// `InputKeyMaterial`). Retained so the handler can inspect any other
    /// KEM parameters the request supplied.
    pub cryptographic_parameters: Option<CryptographicParameters>,
}

/// `Encapsulate` response (KMIP 3.0 WD19) — the UID of the NEW managed
/// shared-secret object the server created, plus the ciphertext (the
/// encapsulation) in `Data`. A subsequent `Get` on `uid` returns the
/// shared secret as KeyMaterial.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct EncapsulateResponse {
    pub uid: String,
    /// `Data` (0x4200C2, ByteString) — the ML-KEM ciphertext / encapsulation.
    pub data: Vec<u8>,
    /// Set when the active policy triggered a transparent crypto-agility
    /// rekey (`Decision::RekeyAndProceed`) during this Encapsulate — mirrors
    /// [`SignResponse::rekeyed`]/[`SignRekeyInfo`] exactly (same rationale:
    /// lets the dispatcher's Undo wave find both new-key halves on
    /// rollback). `None` on the ordinary (no-rekey) path. Internal-only:
    /// never encoded onto the wire (see `wire.rs::encode_encapsulate_resp`,
    /// which reads only `uid` + `data`).
    pub rekeyed: Option<EncapsulateRekeyInfo>,
}

/// See [`EncapsulateResponse::rekeyed`].
#[derive(Clone, Debug, PartialEq)]
pub struct EncapsulateRekeyInfo {
    /// The original key pair's private-key UID — now Deactivated + superseded.
    pub old_uid: String,
    /// The new key pair's public-key UID (same value as `EncapsulateResponse::uid`'s
    /// target — Encapsulate operates on the public half).
    pub new_public_key_uid: String,
    pub new_private_key_uid: String,
}

/// `Decapsulate` request (KMIP 3.0 WD19) — the private/decapsulation key
/// UID plus the ciphertext (the encapsulation) in `Data`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DecapsulateRequest {
    pub uid: String,
    /// `Data` (0x4200C2, ByteString) — the ML-KEM ciphertext to decapsulate.
    pub data: Vec<u8>,
    /// Per-op `CryptographicParameters` (OPTIONAL).
    pub cryptographic_parameters: Option<CryptographicParameters>,
}

/// `Decapsulate` response (KMIP 3.0 WD19) — the UID of the NEW managed
/// shared-secret object the server created. A subsequent `Get` on `uid`
/// returns the recovered shared secret as KeyMaterial.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DecapsulateResponse {
    pub uid: String,
}

// ── Sign / SignatureVerify ─────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq)]
pub struct SignRequest {
    pub uid: String,
    pub data: Vec<u8>,
    /// Wire tag `Cryptographic Parameters` (0x42002b). OPTIONAL per
    /// §6.1.60 — when present, overrides the object's stored
    /// `CryptographicParameters` attribute for this op.
    pub cryptographic_parameters: Option<CryptographicParameters>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SignResponse {
    pub uid: String,
    pub signature: Vec<u8>,
    /// Set when the active policy triggered a transparent crypto-agility
    /// rekey (`Decision::RekeyAndProceed`) during this Sign — i.e. `uid`
    /// above is the freshly-minted replacement key, not the one the caller
    /// asked for. Lets the dispatcher's §9.5 Undo wave find and delete both
    /// halves of the new key pair on rollback. `None` on the ordinary
    /// (no-rekey) path. Internal-only: never encoded onto the wire (see
    /// `wire.rs::encode_sign_resp`, which reads only `uid` + `signature`).
    pub rekeyed: Option<SignRekeyInfo>,
}

/// See [`SignResponse::rekeyed`].
#[derive(Clone, Debug, PartialEq)]
pub struct SignRekeyInfo {
    /// The original key's UID — now Deactivated + superseded.
    pub old_uid: String,
    /// The new key pair's private-key UID (same value as `SignResponse::uid`).
    pub new_private_key_uid: String,
    pub new_public_key_uid: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SignatureVerifyRequest {
    pub uid: String,
    pub data: Vec<u8>,
    pub signature: Vec<u8>,
    /// Wire tag `Cryptographic Parameters` (0x42002b). OPTIONAL per
    /// §6.1.61 — when present, drives padding-method / hashing-algorithm
    /// selection (RSA-PKCS1v15 vs RSA-PSS, SHA-256 vs SHA-384, …). When
    /// absent, the server falls back to the object's stored
    /// `CryptographicParameters` attribute.
    pub cryptographic_parameters: Option<CryptographicParameters>,
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

// ── Validate (§6.1.62) ─────────────────────────────────────────────────────

/// `Validate` request (KMIP 3.0 §6.1.62, Table 440). The request MAY
/// carry inline `Certificate` DER blobs and/or `Unique Identifier`s of
/// stored Certificate objects — together they compose one certificate
/// chain to validate — plus an OPTIONAL `Validity Date`.
#[derive(Clone, Debug, PartialEq)]
pub struct ValidateRequest {
    /// Inline `Certificate` (0x420013) DER blobs supplied in the request
    /// (the `Certificate Value` of each — see `decode_validate_req`).
    /// MAY be repeated.
    pub certificates: Vec<Vec<u8>>,
    /// `Unique Identifier` (0x420094)s of stored Certificate objects.
    /// MAY be repeated.
    pub uids: Vec<String>,
    /// OPTIONAL `Validity Date` (0x42009a). When `None` the server
    /// assumes "now" per §6.1.62.
    pub validity_date: Option<time::OffsetDateTime>,
}

/// `Validate` response (KMIP 3.0 §6.1.62, Table 441) — a single
/// `Validity Indicator` (Valid / Invalid / Unknown). Reuses
/// [`SignatureValidity`] since it is the identical 0x42009b enum
/// (Valid=1 / Invalid=2 / Unknown=3).
#[derive(Clone, Debug, PartialEq)]
pub struct ValidateResponse {
    pub validity: SignatureValidity,
}

// ── Certify (§6.1.6) / Re-certify (§6.1.50) ────────────────────────────────

/// KMIP 3.0 §11 `Certificate Request Type` Enumeration — the encoding of
/// the inline `Certificate Request` ByteString. Values verified against
/// `spec/oasis-kmip-3.0/kmip-spec-3.0-tags-enums.json`
/// (`Certificate Request Type`: CRMF=1, PKCS#10=2, PEM=3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertificateRequestType {
    Crmf   = 0x01,
    Pkcs10 = 0x02,
    Pem    = 0x03,
}

impl CertificateRequestType {
    pub const fn to_wire_value(self) -> u32 {
        self as u32
    }
    pub const fn from_wire_value(v: u32) -> Option<Self> {
        Some(match v {
            0x01 => Self::Crmf,
            0x02 => Self::Pkcs10,
            0x03 => Self::Pem,
            _ => return None,
        })
    }
}

/// `Certify` request (KMIP 3.0 §6.1.6, Table 264). All items are
/// OPTIONAL: either supply a CSR (`certificate_request_type` +
/// `certificate_request`) to certify, or name an existing PublicKey /
/// CertificateRequest by `uid` to certify its key. `attributes` carries
/// desired object attributes (e.g. the requested validity window via
/// Activation/Deactivation Date).
#[derive(Clone, Debug, PartialEq, Default)]
pub struct CertifyRequest {
    /// `Unique Identifier` of the PublicKey (or CertificateRequest)
    /// being certified, when no inline CSR is supplied.
    pub uid: Option<String>,
    /// `Certificate Request Type` — REQUIRED if `certificate_request` is
    /// present.
    pub certificate_request_type: Option<CertificateRequestType>,
    /// `Certificate Request` ByteString — the inline CSR bytes.
    pub certificate_request: Option<Vec<u8>>,
    /// Desired object `Attributes` for the new Certificate.
    pub attributes: Vec<Attribute>,
}

/// `Certify` response (KMIP 3.0 §6.1.6, Table 265) — the UID of the
/// generated Certificate object.
#[derive(Clone, Debug, PartialEq)]
pub struct CertifyResponse {
    pub uid: String,
}

/// `Re-certify` request (KMIP 3.0 §6.1.50, Table 400). `uid` (REQUIRED)
/// names the existing Certificate being renewed. An OPTIONAL `offset`
/// (Interval, seconds) shifts the new Activation Date relative to the
/// new Initial Date per the §6.1.50 date table.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct ReCertifyRequest {
    /// `Unique Identifier` of the existing Certificate being renewed.
    pub uid: String,
    /// `Certificate Request Unique Identifier` — UID of a stored
    /// CertificateRequest (OPTIONAL).
    pub certificate_request_uid: Option<String>,
    /// `Certificate Request Type` — REQUIRED if a CSR is present.
    pub certificate_request_type: Option<CertificateRequestType>,
    /// Inline `Certificate Request` ByteString (OPTIONAL).
    pub certificate_request: Option<Vec<u8>>,
    /// `Offset` Interval (seconds) — difference between the new cert's
    /// Initial Date and its Activation Date.
    pub offset: Option<i64>,
    /// Desired object `Attributes` for the new Certificate.
    pub attributes: Vec<Attribute>,
}

/// `Re-certify` response (KMIP 3.0 §6.1.50, Table 401) — the UID of the
/// new Certificate object.
#[derive(Clone, Debug, PartialEq)]
pub struct ReCertifyResponse {
    pub uid: String,
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
    /// Wire tag `Ticket` (0x420149) — §7.40 Table 494 Structure
    /// (`Ticket Type` + `Ticket Value`), NOT a bare TextString (a
    /// pre-Phase-1.4 wire bug: the spec mandates the nested structure).
    pub ticket: crate::kmip30::Ticket,
}

/// `Logout` (KMIP 3.0 §6.1.35 / Table 355) — invalidate a Login
/// ticket. Empty response.
#[derive(Clone, Debug, PartialEq)]
pub struct LogoutRequest {
    pub ticket: crate::kmip30::Ticket,
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
#[derive(Clone, Debug, PartialEq, Default, serde::Serialize, serde::Deserialize)]
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
    /// Wire tag `Random IV` (0x42_00c5) — Boolean. KMIP 3.0 §11: when
    /// `true`, the server SHALL generate the IV/nonce itself for each
    /// Encrypt and return it via the response payload's
    /// `IVCounterNonce` field. CS-BC-M-13 pins this on AES-CBC-PAD.
    pub random_iv: Option<bool>,
    /// Wire tag `Salt Length` (0x42_0100) — Integer (bytes). KMIP 3.0
    /// §11: the RSA-PSS salt length (RFC 8017 sLen). K18 — when present
    /// on a PSS sign/verify, it is passed to the engine verbatim;
    /// absent keeps the PKCS#11 v3.2 §6.2 default (salt = hash length).
    /// Ignored for non-PSS mechanisms (CryptographicParameters is a
    /// grab-bag; irrelevant fields are not an error).
    pub salt_length: Option<i32>,
    // ── PQC fields (KMIP 3.0 WD19; tags 0x4201C4–0x4201CA) ──────────────
    /// `Deterministic` (0x4201C4) — Boolean. ML-DSA/SLH-DSA deterministic
    /// signing variant (rnd←0^32 / addrnd←PK.seed) when `true`.
    pub deterministic: Option<bool>,
    /// `Context String` (0x4201C5) — ByteString. FIPS 204/205 signing
    /// context (the `ctx` in the `(0‖|ctx|‖ctx)` framing).
    pub context_string: Option<Vec<u8>>,
    /// `Internal` (0x4201C8) — Boolean. When `true`, use the
    /// `*.Sign_internal` interface (no external domain framing).
    pub internal: Option<bool>,
    /// `External Mu` (0x4201C9) — Boolean. When `true`, the signing `Data`
    /// is the 64-byte message representative µ, not the message.
    pub external_mu: Option<bool>,
    /// `Random` (0x4201CA) — ByteString. Explicit signing randomizer for the
    /// hedged (non-deterministic) variant, making it reproducible.
    pub random: Option<Vec<u8>>,
    /// `KEM Algorithm` (0x4201C3) — Enumeration (KMIP 3.0 WD19 §11.26,
    /// Table 572). Disambiguates *which* KEM construction an `Encapsulate`/
    /// `Decapsulate` call is running — `DHKEM` (classical ephemeral-static
    /// ECDH), `MLKEM`, or `RSASVE`. See
    /// `kmip/spec/crossref/kem-encapsulate-decapsulate.yaml`.
    pub kem_algorithm: Option<KemAlgorithm>,
}

/// `KEM Algorithm` Enumeration — KMIP 3.0 WD19 §11.26, Table 572.
/// `DhKem` is the spec's own name for the classical ephemeral-static ECDH
/// construction (PKCS#11 v3.2 §6.3.17's `CKM_ECDH1_DERIVE`-under-
/// `C_EncapsulateKey` mode) — not a vendor extension.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum KemAlgorithm {
    RsaSve = 0x01,
    DhKem  = 0x02,
    MlKem  = 0x03,
}

impl KemAlgorithm {
    pub const fn to_wire_value(self) -> u32 {
        self as u32
    }
    pub const fn from_wire_value(v: u32) -> Option<Self> {
        match v {
            0x01 => Some(Self::RsaSve),
            0x02 => Some(Self::DhKem),
            0x03 => Some(Self::MlKem),
            _ => None,
        }
    }
}

/// `Hashing Algorithm` Enumeration — KMIP 3.0 §11. Codepoints from the
/// spec extract (`enums.Hashing Algorithm`). SHA-2 family is what the
/// OASIS corpus tests; SHA-1 is here for completeness even though it's
/// deprecated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
/// client's intended use: Cryptographic Usage Mask must be a subset of
/// the object's mask, Usage Limits Count must fit within the object's
/// remaining budget, and Lease Time must not exceed the object's Lease
/// Time cap (Phase 3.1 — real, not a v0.1 always-allow stub).
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

/// `Obtain Lease` (KMIP 3.0 §6.1.40 / Table 370-371) — grant/renew a
/// lease for `uid`, up to the object's `Lease Time` attribute cap
/// (§4.34 — server-set, client read-only). Response echoes the granted
/// interval + the object's current `Last Change Date` (so the client
/// can tell if its cached attributes are stale).
#[derive(Clone, Debug, PartialEq)]
pub struct ObtainLeaseRequest {
    pub uid: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ObtainLeaseResponse {
    pub uid: String,
    /// Wire tag `Lease Time` (0x420049, Interval, seconds).
    pub lease_time: u32,
    /// Wire tag `Last Change Date` (0x420048, DateTime, Unix seconds).
    pub last_change_date: i64,
}

/// `Create Split Key` (KMIP 3.0 §6.1.12 / Table 286) — Phase 3.3.
/// "The request contains attributes to be assigned to the objects...
/// The request MAY contain the Unique Identifier of an existing
/// cryptographic object that the client requests be split by the
/// server. If the attributes supplied in the request do not match
/// those of the key supplied, the attributes of the key take
/// precedence." — `uid` absent ⇒ generate a fresh key (per
/// `attributes`' CryptographicAlgorithm/Length) and split THAT.
#[derive(Clone, Debug, PartialEq)]
pub struct CreateSplitKeyRequest {
    pub object_type: ObjectType,
    /// The key to split, if the client is splitting an existing one.
    pub uid: Option<String>,
    pub split_key_parts: u32,
    pub split_key_threshold: u32,
    /// §11.54 wire value.
    pub split_key_method: u32,
    /// `Prime Field Size` (Big Integer, OPTIONAL) — this server fixes
    /// the Prime Field modulus at 2^521-1 (see
    /// `softhsmrustv3::crypto::split_key`); a supplied value is only
    /// checked for compatibility (must fit under that modulus), not
    /// used to select a different one.
    pub prime_field_size: Option<Vec<u8>>,
    pub attributes: Vec<Attribute>,
    pub protection_storage_masks: Option<u32>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CreateSplitKeyResponse {
    pub uids: Vec<String>,
}

/// `Join Split Key` (KMIP 3.0 §6.1.31 / Table 343) — Phase 3.3.
#[derive(Clone, Debug, PartialEq)]
pub struct JoinSplitKeyRequest {
    pub object_type: ObjectType,
    /// The Split Key part UIDs to combine — MUST be at least the
    /// parts' own Split Key Threshold (checked by the handler, not
    /// the wire decoder).
    pub uids: Vec<String>,
    pub secret_data_type: Option<u32>,
    pub attributes: Vec<Attribute>,
    pub protection_storage_masks: Option<u32>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct JoinSplitKeyResponse {
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
    /// Optional `Certificate` payload (§6.2 / §11). When `object_type`
    /// is `Certificate` the client supplies an outer `Certificate`
    /// Structure carrying `CertificateType` + `CertificateValue`
    /// (DER bytes). We surface them paired here so the handler can
    /// populate `certificate_value` / `certificate_length` /
    /// `certificate_subject_cn` in one place.
    pub certificate_payload: Option<(u32, Vec<u8>)>,
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
    /// K16 — KMIP 3.0 §6.1.22 `Key Wrapping Specification`: when
    /// present, the exported key material is returned wrapped under
    /// the referenced wrapping key, exactly like `Get` (AX-M-2 shape:
    /// WrappingMethod=Encrypt + BlockCipherMode=NISTKeyWrap / AES-KW).
    pub key_wrapping_specification: Option<KeyWrappingSpec>,
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

// ── K19 — Baseline client-to-server ops (§5.1.2 item 9) ────────────────────

/// `Get Usage Allocation` (KMIP 3.0 §6.1.27 / Table 329) — obtain an
/// allocation from the object's current `Usage Limits` value before
/// applying cryptographic protection with it.
#[derive(Clone, Debug, PartialEq)]
pub struct GetUsageAllocationRequest {
    /// "The Unique Identifier of the object." REQUIRED per Table 329
    /// (the §6.4 ID-placeholder enumeration form is also accepted).
    pub uid: String,
    /// `Usage Limits Count` (0x420096, LongInteger) — "The number of
    /// Usage Limits Units to be protected." REQUIRED per Table 329.
    pub usage_limits_count: i64,
}

/// §6.1.27 / Table 330 — UID-only response.
#[derive(Clone, Debug, PartialEq)]
pub struct GetUsageAllocationResponse {
    pub uid: String,
}

/// `Get Constraints` (KMIP 3.0 §6.1.26 / Table 326) — the request
/// payload is empty per the spec table.
#[derive(Clone, Debug, PartialEq)]
pub struct GetConstraintsRequest;

/// §6.1.26 / Table 327 — response carries the `Constraints` Structure
/// (0x420168, §7.7 Table 458): a set of `Constraint` Structures.
#[derive(Clone, Debug, PartialEq)]
pub struct GetConstraintsResponse {
    pub constraints: Vec<Constraint>,
}

/// `Constraint` Structure (KMIP 3.0 §7.6 / Table 457) — "details of a
/// constraint that is applied to operations that create Managed
/// Objects". Children: `Object Types` (§7.25, optional), `Object
/// Groups` (optional — not modelled; this server tracks no object
/// groups) and `Attributes` (optional).
#[derive(Clone, Debug, PartialEq)]
pub struct Constraint {
    /// `Object Types` (0x420167) — empty ⇒ omitted on the wire.
    pub object_types: Vec<ObjectType>,
    /// `Attributes` (0x420125) — the constrained attribute values.
    pub attributes: Vec<Attribute>,
}

/// `Set Constraints` (KMIP 3.0 §6.1.57 / Table 427) — "set the
/// constraints that will be applied to Managed Objects during
/// operations." Replaces the stored set entirely (mirrors Set
/// Defaults' replace semantics, §6.1.58) — Get Constraints (§6.1.26)
/// reads it back.
#[derive(Clone, Debug, PartialEq)]
pub struct SetConstraintsRequest {
    pub constraints: Vec<Constraint>,
}

/// §6.1.57 / Table 428 — empty response payload.
#[derive(Clone, Debug, PartialEq)]
pub struct SetConstraintsResponse;

/// `Set Defaults` (KMIP 3.0 §6.1.58 / Table 428) — "set the default
/// attributes that will be applied to Managed Objects during factory
/// operations if the client does not supply values".
#[derive(Clone, Debug, PartialEq)]
pub struct SetDefaultsRequest {
    /// `Defaults Information` (0x420152, §7.12 Table 464) — the set of
    /// Object Defaults to begin using. `None` ⇒ "remove all Object
    /// Defaults from the server" per Table 428.
    pub defaults_information: Option<Vec<ObjectDefaults>>,
}

/// §6.1.58 / Table 429 — the response payload is empty per the spec.
#[derive(Clone, Debug, PartialEq)]
pub struct SetDefaultsResponse;

/// `Object Defaults` Structure (KMIP 3.0 §7.23 / Table 475) — the
/// attribute values the server uses when the client omits them on
/// factory methods, keyed by Object Type. The spec allows either a
/// single `Object Type` Enumeration or an `Object Types` Structure
/// ("Object Type | ObjectTypes — Enumeration | Structure — Yes");
/// both decode into `object_types`. `Object Groups` (optional) is not
/// modelled — this server tracks no object groups.
#[derive(Clone, Debug, PartialEq)]
pub struct ObjectDefaults {
    pub object_types: Vec<ObjectType>,
    /// `Attributes` (0x420125) — REQUIRED per Table 475.
    pub attributes: Vec<Attribute>,
}

// ── Derive Key (K20 — KMIP 3.0 §6.1.18) ────────────────────────────────────

/// `Derivation Method` Enumeration (KMIP 3.0 §11.15 Table 547). All
/// ten codepoints verified against `kmip-spec-3.0-tags-enums.json`
/// `enums."Derivation Method"`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DerivationMethod {
    /// PKCS#5 / RFC 2898 password-based KDF.
    Pbkdf2        = 0x01,
    /// "derives a key by computing a hash over the derivation key or
    /// the derivation data" (Table 546).
    Hash          = 0x02,
    /// "derives a key by computing an HMAC over the derivation data"
    /// (Table 546).
    Hmac          = 0x03,
    /// "derives a key by encrypting the derivation data" (Table 546).
    Encrypt       = 0x04,
    /// SP 800-108 KDF in Counter Mode.
    Nist800_108C  = 0x05,
    /// SP 800-108 KDF in Feedback Mode.
    Nist800_108F  = 0x06,
    /// SP 800-108 KDF in Double-Pipeline Iteration Mode.
    Nist800_108Dpi = 0x07,
    /// Asymmetric key agreement between a private and public key.
    AsymmetricKey = 0x08,
    /// AWS Signature Version 4 signing-key derivation.
    AwsSigV4      = 0x09,
    /// RFC 5869 HMAC-based Extract-and-Expand KDF.
    Hkdf          = 0x0a,
}

impl DerivationMethod {
    pub const fn to_wire_value(self) -> u32 { self as u32 }
    pub const fn from_wire_value(v: u32) -> Option<Self> {
        match v {
            0x01 => Some(Self::Pbkdf2),
            0x02 => Some(Self::Hash),
            0x03 => Some(Self::Hmac),
            0x04 => Some(Self::Encrypt),
            0x05 => Some(Self::Nist800_108C),
            0x06 => Some(Self::Nist800_108F),
            0x07 => Some(Self::Nist800_108Dpi),
            0x08 => Some(Self::AsymmetricKey),
            0x09 => Some(Self::AwsSigV4),
            0x0a => Some(Self::Hkdf),
            _ => None,
        }
    }
}

/// `Derivation Parameters` Structure (KMIP 3.0 §7.13 Table 465) —
/// "the parameters needed by the specified derivation method".
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DerivationParameters {
    /// `Cryptographic Parameters` (0x42002b) — "identify the
    /// Pseudorandom Function (PRF) or the mode of operation of the
    /// PRF" (§7.13). "No, depends on the PRF" per Table 465.
    pub cryptographic_parameters: Option<CryptographicParameters>,
    /// `Initialization Vector` (0x42003a) — "No, depends on the PRF
    /// … an empty IV is assumed if not provided" (Table 465). Decoded
    /// for completeness; none of the implemented methods (PBKDF2 /
    /// HASH / HMAC / NIST800-108-C) consume an IV.
    pub initialization_vector: Option<Vec<u8>>,
    /// `Derivation Data` (0x420030) — "the data to be encrypted,
    /// hashed, or HMACed" (§7.13). "Yes, unless the Unique Identifier
    /// of a Secret Data object is provided. May be repeated" — the
    /// decoder concatenates repeats in wire order.
    pub derivation_data: Option<Vec<u8>>,
    /// `Salt` (0x420084) — "Yes if Derivation method is PBKDF2".
    pub salt: Option<Vec<u8>>,
    /// `Iteration Count` (0x42003c) — "Yes if Derivation method is
    /// PBKDF2".
    pub iteration_count: Option<i32>,
}

/// `Derive Key` request payload (KMIP 3.0 §6.1.18 Table 302).
#[derive(Clone, Debug, PartialEq)]
pub struct DeriveKeyRequest {
    /// `Object Type` — "Determines the type of object to be created"
    /// (SymmetricKey or SecretData per §6.1.18 body text).
    pub object_type: ObjectType,
    /// `Unique Identifier` — "Determines the object or objects to be
    /// used to derive a new key" ("MAY be repeated").
    pub uids: Vec<String>,
    /// `Derivation Method` — REQUIRED Enumeration.
    pub derivation_method: DerivationMethod,
    /// `Derivation Parameters` — REQUIRED Structure.
    pub derivation_parameters: DerivationParameters,
    /// `Attributes` — "Specifies desired attributes to be associated
    /// with the new object; the length and algorithm SHALL always be
    /// specified for the creation of a symmetric key".
    pub template_attribute: Vec<Attribute>,
}

/// §6.1.18 Table 303 — "The Unique Identifier of the newly derived
/// key or Secret Data object".
#[derive(Clone, Debug, PartialEq)]
pub struct DeriveKeyResponse {
    pub uid: String,
}

// ── Re-key / Re-key Key Pair (K21 — KMIP 3.0 §6.1.51 / §6.1.52) ────────────

/// `Re-key` request payload (KMIP 3.0 §6.1.51 Table 405).
///
/// > "This request is used to generate a replacement key for an
/// > existing symmetric key. It is analogous to the Create operation,
/// > except that attributes of the replacement key are copied from the
/// > existing key, with the exception of the attributes listed in
/// > Re-key Attribute Requirements." (Table 404)
#[derive(Clone, Debug, PartialEq)]
pub struct ReKeyRequest {
    /// `Unique Identifier` — "Determines the existing Symmetric Key
    /// being re-keyed." REQUIRED per Table 405 (the §6.4
    /// ID-placeholder enumeration form is also accepted).
    pub uid: String,
    /// `Offset` (0x420058, Interval seconds) — "indicating the
    /// difference between the Initial Date and the Activation Date of
    /// the replacement key to be created." OPTIONAL per Table 405.
    pub offset: Option<u32>,
    /// `Attributes` — "Specifies desired object attributes." OPTIONAL;
    /// overrides the values inherited from the existing key.
    pub template_attribute: Vec<Attribute>,
}

/// §6.1.51 Table 406 — "The Unique Identifier of the newly-created
/// replacement Symmetric Key."
#[derive(Clone, Debug, PartialEq)]
pub struct ReKeyResponse {
    pub uid: String,
}

/// `Re-key Key Pair` request payload (KMIP 3.0 §6.1.52 Table 410).
///
/// > "This request is used to generate a replacement key pair for an
/// > existing public/private key pair. It is analogous to the Create
/// > Key Pair operation, except that attributes of the replacement key
/// > pair are copied from the existing key pair …"
///
/// Attribute baskets mirror Create Key Pair: `Common Attributes` apply
/// to both halves, `Private Key Attributes` / `Public Key Attributes`
/// to one half each.
#[derive(Clone, Debug, PartialEq)]
pub struct ReKeyKeyPairRequest {
    /// `Unique Identifier` — "Determines the existing Asymmetric key
    /// pair to be re-keyed." REQUIRED per Table 410. This server
    /// resolves either half but the canonical handle is the PRIVATE
    /// key UID (§6.4: the pair response's first UID — the Private Key
    /// Unique Identifier — is the placeholder value).
    pub uid: String,
    /// `Offset` (0x420058, Interval seconds) — same semantics as
    /// Re-key (Table 408 date computation). OPTIONAL.
    pub offset: Option<u32>,
    pub common_attributes: Vec<Attribute>,
    pub private_key_attributes: Vec<Attribute>,
    pub public_key_attributes: Vec<Attribute>,
}

/// §6.1.52 Table 411 — the UIDs of the newly created replacement
/// Private / Public Key objects (both REQUIRED).
#[derive(Clone, Debug, PartialEq)]
pub struct ReKeyKeyPairResponse {
    pub private_key_uid: String,
    pub public_key_uid: String,
}

/// `Endpoint Role` Enumeration (KMIP 3.0 §11; codepoints verified
/// against `kmip-spec-3.0-tags-enums.json` `enums."Endpoint Role"`:
/// Client = 0x01, Server = 0x02).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointRole {
    Client = 0x01,
    Server = 0x02,
}

impl EndpointRole {
    pub const fn to_wire_value(self) -> u32 { self as u32 }
    pub const fn from_wire_value(v: u32) -> Option<Self> {
        match v {
            0x01 => Some(Self::Client),
            0x02 => Some(Self::Server),
            _ => None,
        }
    }
}

/// `Set Endpoint Role` (KMIP 3.0 §6.1.59 / Table 431) — request that
/// the server apply the given endpoint role for subsequent traffic on
/// the current channel ("After successful completion of the operation
/// the server assumes the client role, and the client assumes the
/// server role").
#[derive(Clone, Debug, PartialEq)]
pub struct SetEndpointRoleRequest {
    /// "The endpoint role for the server to apply." REQUIRED.
    pub endpoint_role: EndpointRole,
}

/// §6.1.59 / Table 432 — "The accepted endpoint role as applied by
/// the server." REQUIRED.
#[derive(Clone, Debug, PartialEq)]
pub struct SetEndpointRoleResponse {
    pub endpoint_role: EndpointRole,
}

// ── Phase 4 — asynchronous subsystem (§6.1.5 Cancel / §6.1.43 Poll /
// §6.1.44 Process / §6.1.46 Query Asynchronous Requests) ───────────────

/// `Poll` (KMIP 3.0 §6.1.43 / Table 376). Has no `PollResponse` type —
/// per spec its response "SHALL be identical to the response that
/// would have been sent if the operation had completed synchronously"
/// (or, if not yet complete, the same no-payload/Pending shape the
/// original enqueuing response used) — `dispatcher::handle_poll`
/// builds a [`super::message::ResponseBatchItem`] directly rather than
/// going through a typed per-op response.
#[derive(Clone, Debug, PartialEq)]
pub struct PollRequest {
    pub asynchronous_correlation_value: Vec<u8>,
}

/// `Cancel` (KMIP 3.0 §6.1.5 / Table 261-262).
#[derive(Clone, Debug, PartialEq)]
pub struct CancelRequest {
    pub asynchronous_correlation_value: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CancelResponse {
    pub asynchronous_correlation_value: Vec<u8>,
    pub cancellation_result: super::message::CancellationResult,
}

/// `Process` (KMIP 3.0 §6.1.44 / Table 378-379). Empty response
/// payload per spec (Table 379 lists no items) — the struct exists so
/// `Process` still fits this codebase's one-typed-struct-per-op
/// pattern rather than a bare `()`.
#[derive(Clone, Debug, PartialEq)]
pub struct ProcessRequest {
    pub asynchronous_correlation_value: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Default)]
pub struct ProcessResponse {}

/// `Query Asynchronous Requests` (KMIP 3.0 §6.1.46 / Table 385-386).
/// Both filters are optional; an empty request reports every
/// outstanding job. Non-empty filters combine as OR-within-field,
/// AND-across-fields (a job matches if its correlation value is
/// absent-or-listed AND its operation is absent-or-listed).
#[derive(Clone, Debug, PartialEq, Default)]
pub struct QueryAsynchronousRequestsRequest {
    pub asynchronous_correlation_values: Vec<Vec<u8>>,
    pub operations: Vec<Operation>,
}

/// §7.2 `Asynchronous Request` Structure (Table 453) — one row of the
/// Query Asynchronous Requests response.
#[derive(Clone, Debug, PartialEq)]
pub struct AsynchronousRequestInfo {
    pub asynchronous_correlation_value: Vec<u8>,
    pub operation: Operation,
    pub submission_date: i64,
    pub processing_stage: super::message::ProcessingStage,
}

#[derive(Clone, Debug, PartialEq, Default)]
pub struct QueryAsynchronousRequestsResponse {
    pub requests: Vec<AsynchronousRequestInfo>,
}

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
        // K3 additions — values from `enums.Operation`.
        assert_eq!(Operation::DeriveKey.to_wire_value(),       0x05);
        assert_eq!(Operation::Certify.to_wire_value(),         0x06);
        assert_eq!(Operation::Cancel.to_wire_value(),          0x19);
        assert_eq!(Operation::ReKeyKeyPair.to_wire_value(),    0x1d);
        assert_eq!(Operation::JoinSplitKey.to_wire_value(),    0x29);
        assert_eq!(Operation::DelegatedLogin.to_wire_value(),  0x2f);
        assert_eq!(Operation::ReProvision.to_wire_value(),     0x35);
        assert_eq!(Operation::SetDefaults.to_wire_value(),     0x36);
    }

    /// K3 — every published KMIP 3.0 Operation codepoint (0x01–0x40,
    /// 64 total per `kmip-spec-3.0-tags-enums.json`) decodes, and
    /// every decode round-trips back to the same wire value. The WD19
    /// PQC-Updates KEM ops (`Encapsulate = 0x41`, `Decapsulate = 0x42`)
    /// also decode and round-trip; the first unknown codepoint is 0x43.
    #[test]
    fn operation_decodes_all_64_published_codepoints() {
        // Published KMIP 3.0 range.
        for v in 0x01u32..=0x40 {
            let op = Operation::from_wire_value(v)
                .unwrap_or_else(|| panic!("codepoint {v:#04x} must decode"));
            assert_eq!(op.to_wire_value(), v, "round-trip for {v:#04x}");
        }
        // WD19 PQC-Updates KEM ops.
        assert_eq!(Operation::from_wire_value(0x41), Some(Operation::Encapsulate));
        assert_eq!(Operation::from_wire_value(0x42), Some(Operation::Decapsulate));
        assert_eq!(Operation::Encapsulate.to_wire_value(), 0x41);
        assert_eq!(Operation::Decapsulate.to_wire_value(), 0x42);
        assert_eq!(Operation::from_wire_value(0x00), None);
        assert_eq!(Operation::from_wire_value(0x43), None);
    }

    /// K20 — `Derivation Method` Enumeration codepoints (§11.15
    /// Table 547; verified against `kmip-spec-3.0-tags-enums.json`).
    #[test]
    fn derivation_method_codepoints_match_spec() {
        use DerivationMethod as M;
        for (m, v) in [
            (M::Pbkdf2, 0x01u32), (M::Hash, 0x02), (M::Hmac, 0x03),
            (M::Encrypt, 0x04), (M::Nist800_108C, 0x05),
            (M::Nist800_108F, 0x06), (M::Nist800_108Dpi, 0x07),
            (M::AsymmetricKey, 0x08), (M::AwsSigV4, 0x09), (M::Hkdf, 0x0a),
        ] {
            assert_eq!(m.to_wire_value(), v);
            assert_eq!(DerivationMethod::from_wire_value(v), Some(m));
        }
        assert_eq!(DerivationMethod::from_wire_value(0x0b), None);
        assert_eq!(DerivationMethod::from_wire_value(0x00), None);
    }

    /// KMIP 3.0 §11 — Query Function codepoints (spec extract
    /// `enums."Query Function"`): Profiles = 0x0a, Capabilities = 0x0b.
    #[test]
    fn query_function_codepoints_match_spec() {
        assert_eq!(QueryFunction::QueryOperations as u32,            0x01);
        assert_eq!(QueryFunction::QueryObjects as u32,               0x02);
        assert_eq!(QueryFunction::QueryServerInformation as u32,     0x03);
        assert_eq!(QueryFunction::QueryApplicationNamespaces as u32, 0x04);
        assert_eq!(QueryFunction::QueryProfiles as u32,              0x0a);
        assert_eq!(QueryFunction::QueryCapabilities as u32,          0x0b);
    }

    #[test]
    fn signature_validity_values_match_spec() {
        assert_eq!(SignatureValidity::Valid as u32,   0x01);
        assert_eq!(SignatureValidity::Invalid as u32, 0x02);
        assert_eq!(SignatureValidity::Unknown as u32, 0x03);
    }
}
