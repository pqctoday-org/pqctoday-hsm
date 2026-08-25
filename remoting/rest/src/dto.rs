//! REST DTOs — JSON with base64-encoded byte fields (the idiomatic REST
//! cost is the point, per WP3). Mirrors the gRPC schema's field set
//! one-for-one so a benchmark client can build near-identical request
//! bodies for both transports.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use pqctoday_pkcs11_remote_core::Algorithm as CoreAlgorithm;
use serde::{Deserialize, Serialize};

pub mod b64 {
    use super::*;
    pub fn serialize<S: serde::Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&B64.encode(bytes))
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        B64.decode(s.as_bytes()).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Algorithm {
    Ed25519,
    MlDsa44,
    MlDsa65,
    MlDsa87,
    MlKem512,
    MlKem768,
    MlKem1024,
}

impl From<Algorithm> for CoreAlgorithm {
    fn from(a: Algorithm) -> Self {
        match a {
            Algorithm::Ed25519 => CoreAlgorithm::Ed25519,
            Algorithm::MlDsa44 => CoreAlgorithm::MlDsa44,
            Algorithm::MlDsa65 => CoreAlgorithm::MlDsa65,
            Algorithm::MlDsa87 => CoreAlgorithm::MlDsa87,
            Algorithm::MlKem512 => CoreAlgorithm::MlKem512,
            Algorithm::MlKem768 => CoreAlgorithm::MlKem768,
            Algorithm::MlKem1024 => CoreAlgorithm::MlKem1024,
        }
    }
}

#[derive(Serialize)]
pub struct HealthResponse {
    pub ok: bool,
    pub engine_version: String,
}

#[derive(Deserialize)]
pub struct OpenSessionRequest {
    pub user_pin: String,
}
#[derive(Serialize)]
pub struct OpenSessionResponse {
    pub session_handle: u32,
}

#[derive(Deserialize)]
pub struct GenerateKeyPairRequest {
    pub session_handle: u32,
    pub algorithm: Algorithm,
    #[serde(with = "b64")]
    pub cka_id: Vec<u8>,
    pub label: String,
}
#[derive(Serialize)]
pub struct GenerateKeyPairResponse {
    pub public_handle: u32,
    pub private_handle: u32,
}

#[derive(Deserialize)]
pub struct SignRequest {
    pub session_handle: u32,
    pub algorithm: Algorithm,
    #[serde(with = "b64")]
    pub data: Vec<u8>,
}
#[derive(Serialize)]
pub struct SignResponse {
    #[serde(with = "b64")]
    pub signature: Vec<u8>,
}

#[derive(Deserialize)]
pub struct VerifyRequest {
    pub session_handle: u32,
    pub algorithm: Algorithm,
    #[serde(with = "b64")]
    pub data: Vec<u8>,
    #[serde(with = "b64")]
    pub signature: Vec<u8>,
}
#[derive(Serialize)]
pub struct VerifyResponse {
    pub valid: bool,
}

#[derive(Deserialize)]
pub struct EncapsulateRequest {
    pub session_handle: u32,
    pub algorithm: Algorithm,
}
#[derive(Serialize)]
pub struct EncapsulateResponse {
    #[serde(with = "b64")]
    pub ciphertext: Vec<u8>,
    #[serde(with = "b64")]
    pub shared_secret: Vec<u8>,
}

#[derive(Deserialize)]
pub struct DecapsulateRequest {
    pub session_handle: u32,
    pub algorithm: Algorithm,
    #[serde(with = "b64")]
    pub ciphertext: Vec<u8>,
}
#[derive(Serialize)]
pub struct DecapsulateResponse {
    #[serde(with = "b64")]
    pub shared_secret: Vec<u8>,
}

/// WP5a error-mapping contract, REST half — mirrors `remoting/grpc/src/error.rs`'s
/// `Pkcs11ErrorDetail` field-for-field so both wires carry the same three facts.
#[derive(Serialize)]
pub struct ErrorBody {
    pub pkcs11_error: &'static str,
    pub raw_ck_rv: u32,
    pub message: String,
}
