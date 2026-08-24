use axum::extract::Path;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use pqctoday_pkcs11_remote_core::verbs;

use crate::dto::*;
use crate::error::ApiError;

pub fn router() -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/sessions", post(open_session))
        .route("/v1/sessions/{id}", delete(close_session))
        .route("/v1/keys", post(generate_key_pair))
        .route("/v1/keys/{id}/sign", post(sign))
        .route("/v1/keys/{id}/verify", post(verify))
        .route("/v1/keys/{id}/encapsulate", post(encapsulate))
        .route("/v1/keys/{id}/decapsulate", post(decapsulate))
}

async fn healthz() -> Json<HealthResponse> {
    let info = verbs::health();
    Json(HealthResponse { ok: info.ok, engine_version: info.remoting_core_version.to_string() })
}

async fn open_session(Json(req): Json<OpenSessionRequest>) -> Result<Json<OpenSessionResponse>, ApiError> {
    let handle = verbs::open_session(&req.user_pin)?;
    Ok(Json(OpenSessionResponse { session_handle: handle }))
}

async fn close_session(Path(id): Path<u32>) -> Result<(), ApiError> {
    verbs::close_session(id)?;
    Ok(())
}

async fn generate_key_pair(
    Json(req): Json<GenerateKeyPairRequest>,
) -> Result<Json<GenerateKeyPairResponse>, ApiError> {
    let (pub_h, prv_h) =
        verbs::generate_key_pair(req.session_handle, req.algorithm.into(), &req.cka_id, &req.label)?;
    Ok(Json(GenerateKeyPairResponse { public_handle: pub_h, private_handle: prv_h }))
}

/// `{id}` in the path is the private-key handle — carried for REST
/// resource-shape symmetry with `/v1/keys/{id}/...`; the body's
/// `session_handle` is what's actually used, matching the gRPC schema's
/// flat request shape one field at a time.
async fn sign(Path(id): Path<u32>, Json(req): Json<SignRequest>) -> Result<Json<SignResponse>, ApiError> {
    let sig = verbs::sign(req.session_handle, id, req.algorithm.into(), &req.data)?;
    Ok(Json(SignResponse { signature: sig }))
}

async fn verify(Path(id): Path<u32>, Json(req): Json<VerifyRequest>) -> Result<Json<VerifyResponse>, ApiError> {
    let valid = verbs::verify(req.session_handle, id, req.algorithm.into(), &req.data, &req.signature)?;
    Ok(Json(VerifyResponse { valid }))
}

async fn encapsulate(
    Path(id): Path<u32>,
    Json(req): Json<EncapsulateRequest>,
) -> Result<Json<EncapsulateResponse>, ApiError> {
    let (ct, ss) = verbs::encapsulate(req.session_handle, id, req.algorithm.into())?;
    Ok(Json(EncapsulateResponse { ciphertext: ct, shared_secret: ss }))
}

async fn decapsulate(
    Path(id): Path<u32>,
    Json(req): Json<DecapsulateRequest>,
) -> Result<Json<DecapsulateResponse>, ApiError> {
    let ss = verbs::decapsulate(req.session_handle, id, req.algorithm.into(), &req.ciphertext)?;
    Ok(Json(DecapsulateResponse { shared_secret: ss }))
}
