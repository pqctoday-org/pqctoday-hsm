//! REST routes for the `Pkcs11V32` C_* mirror (plan RW0/RW1+).
//!
//! Every handler returns HTTP 200 with a `ck_rv` field — the engine's own
//! return code as data, never an HTTP error (that stays reserved for
//! transport failures). Routes are flat `/v32/<c-function>` posts: the
//! mirror is an RPC surface, not a REST resource model, so it does not
//! reuse the legacy `/v1/keys/{id}/...` resource shape. State is
//! session-handle-keyed server-side, exactly like the C ABI.
//!
//! The `destructive` flag (C_DestroyObject etc.) is carried as axum shared
//! state so a deployed router can be built with it OFF while the
//! acceptance/gate router builds it ON.

use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use pqctoday_pkcs11_remote_core::verbs_v32 as v32;

use crate::dto_v32::*;

#[derive(Clone, Copy)]
pub struct V32State {
    pub destructive: bool,
}

pub fn router(state: V32State) -> Router {
    Router::new()
        .route("/v32/open-session", post(open_session))
        .route("/v32/close-session", post(close_session))
        .route("/v32/login", post(login))
        .route("/v32/logout", post(logout))
        .route("/v32/get-session-info", post(get_session_info))
        .route("/v32/get-token-info", post(get_token_info))
        .route("/v32/get-mechanism-list", post(get_mechanism_list))
        .route("/v32/get-mechanism-info", post(get_mechanism_info))
        .route("/v32/generate-random", post(generate_random))
        .route("/v32/seed-random", post(seed_random))
        .route("/v32/digest-init", post(digest_init))
        .route("/v32/digest-update", post(digest_update))
        .route("/v32/digest-final", post(digest_final))
        .route("/v32/digest", post(digest))
        .route("/v32/sign-init", post(sign_init))
        .route("/v32/sign", post(sign))
        .route("/v32/sign-update", post(sign_update))
        .route("/v32/sign-final", post(sign_final))
        .route("/v32/verify-init", post(verify_init))
        .route("/v32/verify", post(verify))
        .route("/v32/verify-update", post(verify_update))
        .route("/v32/verify-final", post(verify_final))
        .route("/v32/get-attribute-value", post(get_attribute_value))
        .route("/v32/destroy-object", post(destroy_object))
        .route("/v32/generate-key", post(generate_key))
        .route("/v32/generate-key-pair", post(generate_key_pair))
        .route("/v32/create-object", post(create_object))
        .route("/v32/set-attribute-value", post(set_attribute_value))
        .route("/v32/copy-object", post(copy_object))
        .route("/v32/get-object-size", post(get_object_size))
        .route("/v32/find-objects-init", post(find_objects_init))
        .route("/v32/find-objects", post(find_objects))
        .route("/v32/find-objects-final", post(find_objects_final))
        .with_state(state)
}

async fn open_session(Json(r): Json<OpenSessionReq>) -> Json<OpenSessionResp> {
    Json(v32::open_session(r.slot_id, r.flags).into())
}
async fn close_session(Json(r): Json<DatalessSession>) -> Json<StatusResp> {
    Json(v32::close_session(r.session_handle).into())
}
async fn login(Json(r): Json<LoginReq>) -> Json<StatusResp> {
    Json(v32::login(r.session_handle, r.user_type, &r.pin).into())
}
async fn logout(Json(r): Json<DatalessSession>) -> Json<StatusResp> {
    Json(v32::logout(r.session_handle).into())
}
async fn get_session_info(Json(r): Json<DatalessSession>) -> Json<SessionInfoResp> {
    Json(v32::get_session_info(r.session_handle).into())
}
async fn get_token_info(Json(r): Json<SlotReq>) -> Json<TokenInfoResp> {
    Json(v32::get_token_info(r.slot_id).into())
}
async fn get_mechanism_list(Json(r): Json<SlotReq>) -> Json<MechanismListResp> {
    Json(v32::get_mechanism_list(r.slot_id).into())
}
async fn get_mechanism_info(Json(r): Json<MechanismInfoReq>) -> Json<MechanismInfoResp> {
    let (ck_rv, min_key_size, max_key_size, flags) = v32::get_mechanism_info(r.slot_id, r.mechanism);
    Json(MechanismInfoResp { ck_rv, min_key_size, max_key_size, flags })
}
async fn generate_random(Json(r): Json<GenerateRandomReq>) -> Json<BytesResp> {
    Json(v32::generate_random(r.session_handle, r.length).into())
}
async fn seed_random(Json(r): Json<SeedRandomReq>) -> Json<StatusResp> {
    Json(v32::seed_random(r.session_handle, &r.seed).into())
}
async fn digest_init(Json(r): Json<MechanismSessionReq>) -> Json<StatusResp> {
    Json(v32::digest_init(r.session_handle, r.mechanism.mechanism, &r.mechanism.parameter).into())
}
async fn digest_update(Json(r): Json<DataReq>) -> Json<StatusResp> {
    Json(v32::digest_update(r.session_handle, &r.data).into())
}
async fn digest_final(Json(r): Json<DatalessSession>) -> Json<BytesResp> {
    Json(v32::digest_final(r.session_handle).into())
}
async fn digest(Json(r): Json<DigestReq>) -> Json<BytesResp> {
    Json(v32::digest(r.session_handle, r.mechanism.mechanism, &r.mechanism.parameter, &r.data).into())
}
async fn sign_init(Json(r): Json<KeyedInitReq>) -> Json<StatusResp> {
    Json(v32::sign_init(r.session_handle, r.mechanism.mechanism, &r.mechanism.parameter, r.key_handle).into())
}
async fn sign(Json(r): Json<DataReq>) -> Json<BytesResp> {
    Json(v32::sign(r.session_handle, &r.data).into())
}
async fn sign_update(Json(r): Json<DataReq>) -> Json<StatusResp> {
    Json(v32::sign_update(r.session_handle, &r.data).into())
}
async fn sign_final(Json(r): Json<DatalessSession>) -> Json<BytesResp> {
    Json(v32::sign_final(r.session_handle).into())
}
async fn verify_init(Json(r): Json<KeyedInitReq>) -> Json<StatusResp> {
    Json(v32::verify_init(r.session_handle, r.mechanism.mechanism, &r.mechanism.parameter, r.key_handle).into())
}
async fn verify(Json(r): Json<VerifyReq>) -> Json<StatusResp> {
    Json(v32::verify(r.session_handle, &r.data, &r.signature).into())
}
async fn verify_update(Json(r): Json<DataReq>) -> Json<StatusResp> {
    Json(v32::verify_update(r.session_handle, &r.data).into())
}
async fn verify_final(Json(r): Json<SignatureReq>) -> Json<StatusResp> {
    Json(v32::verify_final(r.session_handle, &r.signature).into())
}
async fn get_attribute_value(Json(r): Json<GetAttributeValueReq>) -> Json<GetAttributeValueResp> {
    Json(v32::get_attribute_value(r.session_handle, r.object_handle, &r.attribute_types).into())
}
async fn destroy_object(State(st): State<V32State>, Json(r): Json<ObjectReq>) -> Json<StatusResp> {
    if !st.destructive {
        return Json(StatusResp { ck_rv: v32::ck::CKR_FUNCTION_NOT_SUPPORTED });
    }
    Json(v32::destroy_object(r.session_handle, r.object_handle).into())
}

async fn generate_key(Json(r): Json<GenerateKeyReq>) -> Json<ObjectHandleResp> {
    let template = tmpl_parts(&r.template);
    Json(v32::generate_key(r.session_handle, r.mechanism.mechanism, &r.mechanism.parameter, &template).into())
}
async fn generate_key_pair(Json(r): Json<GenerateKeyPairReq>) -> Json<GenerateKeyPairResp> {
    let public_template = tmpl_parts(&r.public_key_template);
    let private_template = tmpl_parts(&r.private_key_template);
    Json(
        v32::generate_key_pair(
            r.session_handle,
            r.mechanism.mechanism,
            &r.mechanism.parameter,
            &public_template,
            &private_template,
        )
        .into(),
    )
}
async fn create_object(Json(r): Json<CreateObjectReq>) -> Json<ObjectHandleResp> {
    let template = tmpl_parts(&r.template);
    Json(v32::create_object(r.session_handle, &template).into())
}
async fn set_attribute_value(
    State(st): State<V32State>,
    Json(r): Json<SetAttributeValueReq>,
) -> Json<StatusResp> {
    if !st.destructive {
        return Json(StatusResp { ck_rv: v32::ck::CKR_FUNCTION_NOT_SUPPORTED });
    }
    let template = tmpl_parts(&r.template);
    Json(v32::set_attribute_value(r.session_handle, r.object_handle, &template).into())
}
async fn copy_object(Json(r): Json<CopyObjectReq>) -> Json<ObjectHandleResp> {
    let template = tmpl_parts(&r.template);
    Json(v32::copy_object(r.session_handle, r.object_handle, &template).into())
}
async fn get_object_size(Json(r): Json<ObjectReq>) -> Json<GetObjectSizeResp> {
    Json(v32::get_object_size(r.session_handle, r.object_handle).into())
}
async fn find_objects_init(Json(r): Json<FindObjectsInitReq>) -> Json<StatusResp> {
    let template = tmpl_parts(&r.template);
    Json(v32::find_objects_init(r.session_handle, &template).into())
}
async fn find_objects(Json(r): Json<FindObjectsReq>) -> Json<FindObjectsResp> {
    Json(v32::find_objects(r.session_handle, r.max_object_count).into())
}
async fn find_objects_final(Json(r): Json<DatalessSession>) -> Json<StatusResp> {
    Json(v32::find_objects_final(r.session_handle).into())
}

// Small shared request shapes used by several routes.
use serde::Deserialize;
#[derive(Deserialize)]
pub struct DatalessSession {
    pub session_handle: u32,
}
#[derive(Deserialize)]
pub struct SlotReq {
    pub slot_id: u32,
}
