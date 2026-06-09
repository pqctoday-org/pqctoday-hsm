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
    Get              = 0x0a,
    GetAttributes    = 0x0b,
    GetAttributeList = 0x0c,
    Locate           = 0x08,
    Activate         = 0x12,
    Revoke           = 0x13,
    Destroy          = 0x14,
    Query            = 0x18,
    Encrypt          = 0x1f,
    Decrypt          = 0x20,
    Sign             = 0x21,
    SignatureVerify  = 0x22,
    /// KMIP 3.0 §6.1.31 — test-suite framework op. Carries `Begin` /
    /// `End` markers (no managed-object effect). Server returns Success.
    Interop          = 0x2f,
}

impl Operation {
    pub const fn to_wire_value(self) -> u32 {
        self as u32
    }

    pub const fn from_wire_value(v: u32) -> Option<Self> {
        match v {
            0x01 => Some(Self::Create),
            0x02 => Some(Self::CreateKeyPair),
            0x08 => Some(Self::Locate),
            0x0a => Some(Self::Get),
            0x0b => Some(Self::GetAttributes),
            0x0c => Some(Self::GetAttributeList),
            0x12 => Some(Self::Activate),
            0x13 => Some(Self::Revoke),
            0x14 => Some(Self::Destroy),
            0x18 => Some(Self::Query),
            0x1f => Some(Self::Encrypt),
            0x20 => Some(Self::Decrypt),
            0x21 => Some(Self::Sign),
            0x22 => Some(Self::SignatureVerify),
            0x2f => Some(Self::Interop),
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
    pub server_info: Option<ServerInformation>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ServerInformation {
    pub vendor_identification: String,
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
}

#[derive(Clone, Debug, PartialEq)]
pub struct DecryptRequest {
    pub uid: String,
    /// For classical decrypt: the ciphertext. For ML-KEM decapsulation: the
    /// encapsulation bytes.
    pub data: Vec<u8>,
    pub iv: Option<Vec<u8>>,
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
