//! REST DTOs for the `Pkcs11V32` C_* mirror (plan RW0/RW1+).
//!
//! Same contract as the gRPC mirror: `ck_rv` is a response FIELD (JSON
//! number), not an HTTP status — HTTP status stays 200 for any call the
//! engine actually reached, and encodes only transport failures. Byte
//! fields are base64 (reusing the legacy DTOs' `b64` module). Raw CK
//! codepoints (mechanisms, attribute types, return codes) travel as JSON
//! numbers, no enums.

use pqctoday_pkcs11_remote_core::verbs_v32 as v32;
use serde::{Deserialize, Serialize};

use crate::dto::b64;

// ── sessions & login ───────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct OpenSessionReq {
    pub slot_id: u32,
    pub flags: u32,
}
#[derive(Serialize)]
pub struct OpenSessionResp {
    pub ck_rv: u32,
    pub session_handle: u32,
}
impl From<(u32, u32)> for OpenSessionResp {
    fn from((ck_rv, session_handle): (u32, u32)) -> Self {
        Self { ck_rv, session_handle }
    }
}

#[derive(Deserialize)]
pub struct LoginReq {
    pub session_handle: u32,
    pub user_type: u32,
    #[serde(with = "b64")]
    pub pin: Vec<u8>,
}

#[derive(Serialize)]
pub struct StatusResp {
    pub ck_rv: u32,
}
impl From<u32> for StatusResp {
    fn from(ck_rv: u32) -> Self {
        Self { ck_rv }
    }
}

#[derive(Serialize)]
pub struct BytesResp {
    pub ck_rv: u32,
    #[serde(with = "b64")]
    pub data: Vec<u8>,
}
impl From<(u32, Vec<u8>)> for BytesResp {
    fn from((ck_rv, data): (u32, Vec<u8>)) -> Self {
        Self { ck_rv, data }
    }
}

#[derive(Serialize)]
pub struct SessionInfoResp {
    pub ck_rv: u32,
    pub slot_id: u32,
    pub state: u32,
    pub flags: u32,
    pub device_error: u32,
}
impl From<(u32, v32::SessionInfo)> for SessionInfoResp {
    fn from((ck_rv, i): (u32, v32::SessionInfo)) -> Self {
        Self { ck_rv, slot_id: i.slot_id, state: i.state, flags: i.flags, device_error: i.device_error }
    }
}

#[derive(Serialize, Default)]
pub struct TokenInfoResp {
    pub ck_rv: u32,
    pub label: String,
    pub manufacturer: String,
    pub model: String,
    pub serial_number: String,
    pub flags: u32,
    pub session_count: u32,
    pub rw_session_count: u32,
    pub max_pin_len: u32,
    pub min_pin_len: u32,
    pub hardware_version_major: u32,
    pub hardware_version_minor: u32,
    pub firmware_version_major: u32,
    pub firmware_version_minor: u32,
}
impl From<(u32, Option<v32::TokenInfo>)> for TokenInfoResp {
    fn from((ck_rv, info): (u32, Option<v32::TokenInfo>)) -> Self {
        let mut r = TokenInfoResp { ck_rv, ..Default::default() };
        if let Some(i) = info {
            r.label = i.label;
            r.manufacturer = i.manufacturer;
            r.model = i.model;
            r.serial_number = i.serial_number;
            r.flags = i.flags;
            r.session_count = i.session_count;
            r.rw_session_count = i.rw_session_count;
            r.max_pin_len = i.max_pin_len;
            r.min_pin_len = i.min_pin_len;
            r.hardware_version_major = u32::from(i.hardware_version.0);
            r.hardware_version_minor = u32::from(i.hardware_version.1);
            r.firmware_version_major = u32::from(i.firmware_version.0);
            r.firmware_version_minor = u32::from(i.firmware_version.1);
        }
        r
    }
}

// ── discovery ──────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct MechanismListResp {
    pub ck_rv: u32,
    pub mechanisms: Vec<u64>,
}
impl From<(u32, Vec<u64>)> for MechanismListResp {
    fn from((ck_rv, mechanisms): (u32, Vec<u64>)) -> Self {
        Self { ck_rv, mechanisms }
    }
}

#[derive(Deserialize)]
pub struct MechanismInfoReq {
    pub slot_id: u32,
    pub mechanism: u64,
}
#[derive(Serialize)]
pub struct MechanismInfoResp {
    pub ck_rv: u32,
    pub min_key_size: u32,
    pub max_key_size: u32,
    pub flags: u32,
}

// ── random ─────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct GenerateRandomReq {
    pub session_handle: u32,
    pub length: u32,
}
#[derive(Deserialize)]
pub struct SeedRandomReq {
    pub session_handle: u32,
    #[serde(with = "b64")]
    pub seed: Vec<u8>,
}

// ── mechanism / data / keyed requests ──────────────────────────────────────

#[derive(Deserialize)]
pub struct V32MechanismDto {
    pub mechanism: u64,
    #[serde(with = "b64", default)]
    pub parameter: Vec<u8>,
}

#[derive(Deserialize)]
pub struct MechanismSessionReq {
    pub session_handle: u32,
    pub mechanism: V32MechanismDto,
}

#[derive(Deserialize)]
pub struct DataReq {
    pub session_handle: u32,
    #[serde(with = "b64")]
    pub data: Vec<u8>,
}

#[derive(Deserialize)]
pub struct DigestReq {
    pub session_handle: u32,
    pub mechanism: V32MechanismDto,
    #[serde(with = "b64")]
    pub data: Vec<u8>,
}

#[derive(Deserialize)]
pub struct KeyedInitReq {
    pub session_handle: u32,
    pub mechanism: V32MechanismDto,
    pub key_handle: u32,
}

#[derive(Deserialize)]
pub struct VerifyReq {
    pub session_handle: u32,
    #[serde(with = "b64")]
    pub data: Vec<u8>,
    #[serde(with = "b64")]
    pub signature: Vec<u8>,
}

#[derive(Deserialize)]
pub struct SignatureReq {
    pub session_handle: u32,
    #[serde(with = "b64")]
    pub signature: Vec<u8>,
}

// ── objects ────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct GetAttributeValueReq {
    pub session_handle: u32,
    pub object_handle: u32,
    pub attribute_types: Vec<u64>,
}
#[derive(Serialize)]
pub struct AttributeDto {
    pub attribute_type: u64,
    pub available: bool,
    #[serde(with = "b64")]
    pub value: Vec<u8>,
}
#[derive(Serialize)]
pub struct GetAttributeValueResp {
    pub ck_rv: u32,
    pub attributes: Vec<AttributeDto>,
}
impl From<(u32, Vec<v32::AttrOut>)> for GetAttributeValueResp {
    fn from((ck_rv, attrs): (u32, Vec<v32::AttrOut>)) -> Self {
        Self {
            ck_rv,
            attributes: attrs
                .into_iter()
                .map(|a| AttributeDto {
                    attribute_type: a.attribute_type,
                    available: a.available,
                    value: a.value,
                })
                .collect(),
        }
    }
}

#[derive(Deserialize)]
pub struct ObjectReq {
    pub session_handle: u32,
    pub object_handle: u32,
}

// ── keygen templates (RW2) ───────────────────────────────────────────────────

/// One template entry over the wire. Ulong-typed attribute VALUES
/// (CKA_CLASS, CKA_KEY_TYPE, CKA_PARAMETER_SET, ...) must be native
/// `CK_ULONG` width — 8 bytes little-endian on this LP64 server — the same
/// convention `get_attribute_value`'s OUTPUT already documents, applied
/// here on the input side.
#[derive(Deserialize)]
pub struct V32AttributeInDto {
    pub attribute_type: u64,
    #[serde(with = "b64")]
    pub value: Vec<u8>,
}

pub(crate) fn tmpl_parts(t: &[V32AttributeInDto]) -> Vec<v32::AttrIn> {
    t.iter().map(|a| (a.attribute_type, a.value.clone())).collect()
}

#[derive(Serialize)]
pub struct ObjectHandleResp {
    pub ck_rv: u32,
    pub object_handle: u32,
}
impl From<(u32, u32)> for ObjectHandleResp {
    fn from((ck_rv, object_handle): (u32, u32)) -> Self {
        Self { ck_rv, object_handle }
    }
}

#[derive(Deserialize)]
pub struct GenerateKeyReq {
    pub session_handle: u32,
    pub mechanism: V32MechanismDto,
    pub template: Vec<V32AttributeInDto>,
}

#[derive(Deserialize)]
pub struct GenerateKeyPairReq {
    pub session_handle: u32,
    pub mechanism: V32MechanismDto,
    pub public_key_template: Vec<V32AttributeInDto>,
    pub private_key_template: Vec<V32AttributeInDto>,
}
#[derive(Serialize)]
pub struct GenerateKeyPairResp {
    pub ck_rv: u32,
    pub public_handle: u32,
    pub private_handle: u32,
}
impl From<(u32, u32, u32)> for GenerateKeyPairResp {
    fn from((ck_rv, public_handle, private_handle): (u32, u32, u32)) -> Self {
        Self { ck_rv, public_handle, private_handle }
    }
}

#[derive(Deserialize)]
pub struct CreateObjectReq {
    pub session_handle: u32,
    pub template: Vec<V32AttributeInDto>,
}

#[derive(Deserialize)]
pub struct SetAttributeValueReq {
    pub session_handle: u32,
    pub object_handle: u32,
    pub template: Vec<V32AttributeInDto>,
}

#[derive(Deserialize)]
pub struct CopyObjectReq {
    pub session_handle: u32,
    pub object_handle: u32,
    pub template: Vec<V32AttributeInDto>,
}

#[derive(Serialize)]
pub struct GetObjectSizeResp {
    pub ck_rv: u32,
    pub size: u32,
}
impl From<(u32, u32)> for GetObjectSizeResp {
    fn from((ck_rv, size): (u32, u32)) -> Self {
        Self { ck_rv, size }
    }
}

#[derive(Deserialize)]
pub struct FindObjectsInitReq {
    pub session_handle: u32,
    pub template: Vec<V32AttributeInDto>,
}

#[derive(Deserialize)]
pub struct FindObjectsReq {
    pub session_handle: u32,
    pub max_object_count: u32,
}
#[derive(Serialize)]
pub struct FindObjectsResp {
    pub ck_rv: u32,
    pub object_handles: Vec<u32>,
}
impl From<(u32, Vec<u32>)> for FindObjectsResp {
    fn from((ck_rv, object_handles): (u32, Vec<u32>)) -> Self {
        Self { ck_rv, object_handles }
    }
}

// ── admin / info (RW6a) ──────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct GetSlotListReq {
    #[serde(default)]
    pub token_present: bool,
}
#[derive(Serialize)]
pub struct GetSlotListResp {
    pub ck_rv: u32,
    pub slot_ids: Vec<u32>,
}
impl From<(u32, Vec<u32>)> for GetSlotListResp {
    fn from((ck_rv, slot_ids): (u32, Vec<u32>)) -> Self {
        Self { ck_rv, slot_ids }
    }
}

#[derive(Deserialize)]
pub struct SlotEventReq {
    pub flags: u32,
}

#[derive(Deserialize)]
pub struct SessionFlagsReq {
    pub session_handle: u32,
    pub flags: u32,
}

// ── destructive-gated admin (RW6a) ───────────────────────────────────────

#[derive(Deserialize)]
pub struct InitTokenReq {
    pub slot_id: u32,
    #[serde(with = "b64")]
    pub pin: Vec<u8>,
    /// MUST be exactly 32 bytes — see `verbs_v32::init_token`'s doc.
    #[serde(with = "b64")]
    pub label: Vec<u8>,
}
#[derive(Deserialize)]
pub struct InitPinReq {
    pub session_handle: u32,
    #[serde(with = "b64")]
    pub pin: Vec<u8>,
}
#[derive(Deserialize)]
pub struct SetPinReq {
    pub session_handle: u32,
    #[serde(with = "b64")]
    pub old_pin: Vec<u8>,
    #[serde(with = "b64")]
    pub new_pin: Vec<u8>,
}

// ── honest-code stubs (RW6a) ─────────────────────────────────────────────

#[derive(Serialize)]
pub struct AsyncGetIdResp {
    pub ck_rv: u32,
    pub id: u32,
}
impl From<u32> for AsyncGetIdResp {
    fn from(ck_rv: u32) -> Self {
        Self { ck_rv, id: 0 }
    }
}
#[derive(Deserialize)]
pub struct AsyncJoinReq {
    pub session_handle: u32,
    pub id: u32,
    #[serde(with = "b64")]
    pub data: Vec<u8>,
}

// ── recover + verify-with-signature (RW6a) ───────────────────────────────

#[derive(Deserialize)]
pub struct VerifySignatureInitReq {
    pub session_handle: u32,
    pub mechanism: V32MechanismDto,
    pub key_handle: u32,
    #[serde(with = "b64")]
    pub signature: Vec<u8>,
}

// ── message sign / verify (RW6b) ─────────────────────────────────────────

#[derive(Deserialize)]
pub struct SignMessageNextReq {
    pub session_handle: u32,
    #[serde(with = "b64")]
    pub part: Vec<u8>,
    pub is_final: bool,
}
#[derive(Deserialize)]
pub struct VerifyMessageNextReq {
    pub session_handle: u32,
    #[serde(with = "b64")]
    pub part: Vec<u8>,
    pub is_final: bool,
    #[serde(with = "b64", default)]
    pub signature: Vec<u8>,
}

// ── message encrypt / decrypt (RW6b — CK_GCM_MESSAGE_PARAMS) ─────────────

#[derive(Deserialize)]
pub struct EncryptMessageReq {
    pub session_handle: u32,
    #[serde(with = "b64")]
    pub iv: Vec<u8>,
    #[serde(default)]
    pub iv_generator: u32,
    #[serde(with = "b64", default)]
    pub aad: Vec<u8>,
    #[serde(with = "b64")]
    pub plaintext: Vec<u8>,
    pub tag_bits: u32,
}
#[derive(Serialize)]
pub struct EncryptMessageResp {
    pub ck_rv: u32,
    #[serde(with = "b64")]
    pub ciphertext: Vec<u8>,
    #[serde(with = "b64")]
    pub tag: Vec<u8>,
    #[serde(with = "b64")]
    pub iv_used: Vec<u8>,
}
impl From<(u32, Vec<u8>, Vec<u8>, Vec<u8>)> for EncryptMessageResp {
    fn from((ck_rv, ciphertext, tag, iv_used): (u32, Vec<u8>, Vec<u8>, Vec<u8>)) -> Self {
        Self { ck_rv, ciphertext, tag, iv_used }
    }
}

#[derive(Deserialize)]
pub struct EncryptMessageBeginReq {
    pub session_handle: u32,
    #[serde(with = "b64")]
    pub iv: Vec<u8>,
    #[serde(default)]
    pub iv_generator: u32,
    #[serde(with = "b64", default)]
    pub aad: Vec<u8>,
    pub tag_bits: u32,
}
#[derive(Serialize)]
pub struct EncryptMessageBeginResp {
    pub ck_rv: u32,
    #[serde(with = "b64")]
    pub iv_used: Vec<u8>,
}
impl From<(u32, Vec<u8>)> for EncryptMessageBeginResp {
    fn from((ck_rv, iv_used): (u32, Vec<u8>)) -> Self {
        Self { ck_rv, iv_used }
    }
}

#[derive(Deserialize)]
pub struct EncryptMessageNextReq {
    pub session_handle: u32,
    #[serde(with = "b64")]
    pub plaintext_part: Vec<u8>,
    pub is_final: bool,
    #[serde(default)]
    pub tag_bits: u32,
}
#[derive(Serialize)]
pub struct EncryptMessageNextResp {
    pub ck_rv: u32,
    #[serde(with = "b64")]
    pub ciphertext_part: Vec<u8>,
    #[serde(with = "b64")]
    pub tag: Vec<u8>,
}
impl From<(u32, Vec<u8>, Option<Vec<u8>>)> for EncryptMessageNextResp {
    fn from((ck_rv, ciphertext_part, tag): (u32, Vec<u8>, Option<Vec<u8>>)) -> Self {
        Self { ck_rv, ciphertext_part, tag: tag.unwrap_or_default() }
    }
}

#[derive(Deserialize)]
pub struct DecryptMessageReq {
    pub session_handle: u32,
    #[serde(with = "b64")]
    pub iv: Vec<u8>,
    #[serde(with = "b64", default)]
    pub aad: Vec<u8>,
    #[serde(with = "b64")]
    pub ciphertext: Vec<u8>,
    pub tag_bits: u32,
    #[serde(with = "b64")]
    pub tag: Vec<u8>,
}
#[derive(Deserialize)]
pub struct DecryptMessageBeginReq {
    pub session_handle: u32,
    #[serde(with = "b64")]
    pub iv: Vec<u8>,
    #[serde(with = "b64", default)]
    pub aad: Vec<u8>,
    pub tag_bits: u32,
}
#[derive(Deserialize)]
pub struct DecryptMessageNextReq {
    pub session_handle: u32,
    #[serde(with = "b64")]
    pub ciphertext_part: Vec<u8>,
    pub is_final: bool,
    #[serde(default)]
    pub tag_bits: u32,
    #[serde(with = "b64", default)]
    pub tag: Vec<u8>,
}

// ── wrap / unwrap (RW4) ───────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct WrapKeyReq {
    pub session_handle: u32,
    pub mechanism: V32MechanismDto,
    pub wrapping_key_handle: u32,
    pub key_handle: u32,
}
#[derive(Deserialize)]
pub struct UnwrapKeyReq {
    pub session_handle: u32,
    pub mechanism: V32MechanismDto,
    pub unwrapping_key_handle: u32,
    #[serde(with = "b64")]
    pub wrapped_key: Vec<u8>,
    pub template: Vec<V32AttributeInDto>,
}
#[derive(Deserialize)]
pub struct WrapKeyAuthenticatedReq {
    pub session_handle: u32,
    pub mechanism: V32MechanismDto,
    pub wrapping_key_handle: u32,
    pub key_handle: u32,
    #[serde(with = "b64", default)]
    pub associated_data: Vec<u8>,
}
#[derive(Deserialize)]
pub struct UnwrapKeyAuthenticatedReq {
    pub session_handle: u32,
    pub mechanism: V32MechanismDto,
    pub unwrapping_key_handle: u32,
    #[serde(with = "b64")]
    pub wrapped_key: Vec<u8>,
    pub template: Vec<V32AttributeInDto>,
    #[serde(with = "b64", default)]
    pub associated_data: Vec<u8>,
}

// ── derive (RW4 — the RW-P derive-family variants) ────────────────────────
// Field names/types mirror `verbs_v32::derive_params`'s builder arguments
// exactly, same as the proto messages — see that module's doc for why the
// server (not the client) must own the native-layout marshaling.

#[derive(Deserialize)]
pub struct Ecdh1ParamsDto {
    pub kdf: u32,
    #[serde(with = "b64", default)]
    pub shared_data: Vec<u8>,
    #[serde(with = "b64", default)]
    pub public_data: Vec<u8>,
}
#[derive(Deserialize)]
pub struct HkdfParamsDto {
    pub extract: bool,
    pub expand: bool,
    pub prf_hash_mechanism: u64,
    pub salt_type: u32,
    #[serde(with = "b64", default)]
    pub salt: Vec<u8>,
    #[serde(default)]
    pub h_salt_key: u32,
    #[serde(with = "b64", default)]
    pub info: Vec<u8>,
}
#[derive(Deserialize)]
pub struct Pbkdf2ParamsDto {
    pub salt_source: u32,
    #[serde(with = "b64", default)]
    pub salt_source_data: Vec<u8>,
    pub iterations: u32,
    pub prf: u64,
    #[serde(with = "b64", default)]
    pub prf_data: Vec<u8>,
    #[serde(with = "b64", default)]
    pub password: Vec<u8>,
}
#[derive(Deserialize)]
pub struct Sp800108SegmentDto {
    pub prf_type: u32,
    #[serde(with = "b64", default)]
    pub value: Vec<u8>,
}
#[derive(Deserialize)]
pub struct Sp800108CounterParamsDto {
    pub prf_type: u64,
    pub segments: Vec<Sp800108SegmentDto>,
}
#[derive(Deserialize)]
pub struct Sp800108FeedbackParamsDto {
    pub prf_type: u64,
    pub segments: Vec<Sp800108SegmentDto>,
    #[serde(with = "b64", default)]
    pub iv: Vec<u8>,
}

/// Exactly one of these should be present per call — the raw-bytes
/// fallback for parameterless/already-raw mechanisms, or one structured
/// variant for everything else. Mirrors the proto's `oneof` plus its
/// `raw_parameter` sibling field.
#[derive(Deserialize)]
pub struct DeriveKeyReq {
    pub session_handle: u32,
    pub mechanism: u64,
    #[serde(default)]
    pub base_key_handle: u32,
    #[serde(default)]
    pub template: Vec<V32AttributeInDto>,
    #[serde(with = "b64", default)]
    pub raw_parameter: Vec<u8>,
    #[serde(default)]
    pub ecdh1: Option<Ecdh1ParamsDto>,
    #[serde(default)]
    pub hkdf: Option<HkdfParamsDto>,
    #[serde(default)]
    pub pbkdf2: Option<Pbkdf2ParamsDto>,
    #[serde(default)]
    pub sp800_108_counter: Option<Sp800108CounterParamsDto>,
    #[serde(default)]
    pub sp800_108_feedback: Option<Sp800108FeedbackParamsDto>,
}

// ── KEM key-object form (RW5) ─────────────────────────────────────────────

#[derive(Deserialize)]
pub struct EncapsulateKeyReq {
    pub session_handle: u32,
    pub mechanism: V32MechanismDto,
    pub key_handle: u32,
    #[serde(default)]
    pub template: Vec<V32AttributeInDto>,
}
#[derive(Serialize)]
pub struct EncapsulateKeyResp {
    pub ck_rv: u32,
    #[serde(with = "b64")]
    pub ciphertext: Vec<u8>,
    pub object_handle: u32,
}
impl From<(u32, Vec<u8>, u32)> for EncapsulateKeyResp {
    fn from((ck_rv, ciphertext, object_handle): (u32, Vec<u8>, u32)) -> Self {
        Self { ck_rv, ciphertext, object_handle }
    }
}
#[derive(Deserialize)]
pub struct DecapsulateKeyReq {
    pub session_handle: u32,
    pub mechanism: V32MechanismDto,
    pub private_key_handle: u32,
    #[serde(with = "b64")]
    pub ciphertext: Vec<u8>,
    #[serde(default)]
    pub template: Vec<V32AttributeInDto>,
}

// ── RW-T coverage-ledger audit finding ────────────────────────────────────

#[derive(Deserialize)]
pub struct GetSessionValidationFlagsReq {
    pub session_handle: u32,
    pub validation_type: u32,
}
#[derive(Serialize)]
pub struct GetSessionValidationFlagsResp {
    pub ck_rv: u32,
    pub flags: u32,
}
impl From<(u32, u32)> for GetSessionValidationFlagsResp {
    fn from((ck_rv, flags): (u32, u32)) -> Self {
        Self { ck_rv, flags }
    }
}
