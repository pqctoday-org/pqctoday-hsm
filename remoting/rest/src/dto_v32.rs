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
