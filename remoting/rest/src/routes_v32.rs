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
        .route("/v32/encrypt-init", post(encrypt_init))
        .route("/v32/encrypt", post(encrypt))
        .route("/v32/encrypt-update", post(encrypt_update))
        .route("/v32/encrypt-final", post(encrypt_final))
        .route("/v32/decrypt-init", post(decrypt_init))
        .route("/v32/decrypt", post(decrypt))
        .route("/v32/decrypt-update", post(decrypt_update))
        .route("/v32/decrypt-final", post(decrypt_final))
        .route("/v32/get-info", post(get_info))
        .route("/v32/get-slot-list", post(get_slot_list))
        .route("/v32/get-slot-info", post(get_slot_info))
        .route("/v32/wait-for-slot-event", post(wait_for_slot_event))
        .route("/v32/close-all-sessions", post(close_all_sessions))
        .route("/v32/session-cancel", post(session_cancel))
        .route("/v32/login-user", post(login_user))
        .route("/v32/init-token", post(init_token))
        .route("/v32/init-pin", post(init_pin))
        .route("/v32/set-pin", post(set_pin))
        .route("/v32/digest-key", post(digest_key))
        .route("/v32/get-operation-state", post(get_operation_state))
        .route("/v32/set-operation-state", post(set_operation_state))
        .route("/v32/get-function-status", post(get_function_status))
        .route("/v32/cancel-function", post(cancel_function))
        .route("/v32/async-complete", post(async_complete))
        .route("/v32/async-get-id", post(async_get_id))
        .route("/v32/async-join", post(async_join))
        .route("/v32/sign-recover-init", post(sign_recover_init))
        .route("/v32/sign-recover", post(sign_recover))
        .route("/v32/verify-recover-init", post(verify_recover_init))
        .route("/v32/verify-recover", post(verify_recover))
        .route("/v32/verify-signature-init", post(verify_signature_init))
        .route("/v32/verify-signature", post(verify_signature))
        .route("/v32/digest-encrypt-update", post(digest_encrypt_update))
        .route("/v32/decrypt-digest-update", post(decrypt_digest_update))
        .route("/v32/sign-encrypt-update", post(sign_encrypt_update))
        .route("/v32/decrypt-verify-update", post(decrypt_verify_update))
        .route("/v32/message-sign-init", post(message_sign_init))
        .route("/v32/sign-message", post(sign_message))
        .route("/v32/message-sign-final", post(message_sign_final))
        .route("/v32/sign-message-begin", post(sign_message_begin))
        .route("/v32/sign-message-next", post(sign_message_next))
        .route("/v32/message-verify-init", post(message_verify_init))
        .route("/v32/verify-message", post(verify_message))
        .route("/v32/message-verify-final", post(message_verify_final))
        .route("/v32/verify-message-begin", post(verify_message_begin))
        .route("/v32/verify-message-next", post(verify_message_next))
        .route("/v32/message-encrypt-init", post(message_encrypt_init))
        .route("/v32/encrypt-message", post(encrypt_message))
        .route("/v32/message-encrypt-final", post(message_encrypt_final))
        .route("/v32/encrypt-message-begin", post(encrypt_message_begin))
        .route("/v32/encrypt-message-next", post(encrypt_message_next))
        .route("/v32/message-decrypt-init", post(message_decrypt_init))
        .route("/v32/decrypt-message", post(decrypt_message))
        .route("/v32/message-decrypt-final", post(message_decrypt_final))
        .route("/v32/decrypt-message-begin", post(decrypt_message_begin))
        .route("/v32/decrypt-message-next", post(decrypt_message_next))
        .route("/v32/wrap-key", post(wrap_key))
        .route("/v32/unwrap-key", post(unwrap_key))
        .route("/v32/wrap-key-authenticated", post(wrap_key_authenticated))
        .route("/v32/unwrap-key-authenticated", post(unwrap_key_authenticated))
        .route("/v32/derive-key", post(derive_key))
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

async fn encrypt_init(Json(r): Json<KeyedInitReq>) -> Json<StatusResp> {
    Json(v32::encrypt_init(r.session_handle, r.mechanism.mechanism, &r.mechanism.parameter, r.key_handle).into())
}
async fn encrypt(Json(r): Json<DataReq>) -> Json<BytesResp> {
    Json(v32::encrypt(r.session_handle, &r.data).into())
}
async fn encrypt_update(Json(r): Json<DataReq>) -> Json<BytesResp> {
    Json(v32::encrypt_update(r.session_handle, &r.data).into())
}
async fn encrypt_final(Json(r): Json<DatalessSession>) -> Json<BytesResp> {
    Json(v32::encrypt_final(r.session_handle).into())
}
async fn decrypt_init(Json(r): Json<KeyedInitReq>) -> Json<StatusResp> {
    Json(v32::decrypt_init(r.session_handle, r.mechanism.mechanism, &r.mechanism.parameter, r.key_handle).into())
}
async fn decrypt(Json(r): Json<DataReq>) -> Json<BytesResp> {
    Json(v32::decrypt(r.session_handle, &r.data).into())
}
async fn decrypt_update(Json(r): Json<DataReq>) -> Json<BytesResp> {
    Json(v32::decrypt_update(r.session_handle, &r.data).into())
}
async fn decrypt_final(Json(r): Json<DatalessSession>) -> Json<BytesResp> {
    Json(v32::decrypt_final(r.session_handle).into())
}

async fn get_info() -> Json<BytesResp> {
    Json(v32::get_info().into())
}
async fn get_slot_list(Json(r): Json<GetSlotListReq>) -> Json<GetSlotListResp> {
    Json(v32::get_slot_list(r.token_present).into())
}
async fn get_slot_info(Json(r): Json<SlotReq>) -> Json<BytesResp> {
    Json(v32::get_slot_info(r.slot_id).into())
}
async fn wait_for_slot_event(Json(r): Json<SlotEventReq>) -> Json<StatusResp> {
    Json(v32::wait_for_slot_event(r.flags).into())
}
async fn close_all_sessions(Json(r): Json<SlotReq>) -> Json<StatusResp> {
    Json(v32::close_all_sessions(r.slot_id).into())
}
async fn session_cancel(Json(r): Json<SessionFlagsReq>) -> Json<StatusResp> {
    Json(v32::session_cancel(r.session_handle, r.flags).into())
}
async fn login_user(Json(r): Json<LoginReq>) -> Json<StatusResp> {
    Json(v32::login_user(r.session_handle, r.user_type, &r.pin).into())
}

async fn init_token(State(st): State<V32State>, Json(r): Json<InitTokenReq>) -> Json<StatusResp> {
    if !st.destructive {
        return Json(StatusResp { ck_rv: v32::ck::CKR_FUNCTION_NOT_SUPPORTED });
    }
    Json(v32::init_token(r.slot_id, &r.pin, &r.label).into())
}
async fn init_pin(State(st): State<V32State>, Json(r): Json<InitPinReq>) -> Json<StatusResp> {
    if !st.destructive {
        return Json(StatusResp { ck_rv: v32::ck::CKR_FUNCTION_NOT_SUPPORTED });
    }
    Json(v32::init_pin(r.session_handle, &r.pin).into())
}
async fn set_pin(State(st): State<V32State>, Json(r): Json<SetPinReq>) -> Json<StatusResp> {
    if !st.destructive {
        return Json(StatusResp { ck_rv: v32::ck::CKR_FUNCTION_NOT_SUPPORTED });
    }
    Json(v32::set_pin(r.session_handle, &r.old_pin, &r.new_pin).into())
}

async fn digest_key(Json(r): Json<ObjectReq>) -> Json<StatusResp> {
    Json(v32::digest_key(r.session_handle, r.object_handle).into())
}
async fn get_operation_state(Json(r): Json<DatalessSession>) -> Json<StatusResp> {
    Json(v32::get_operation_state(r.session_handle).into())
}
async fn set_operation_state(Json(r): Json<DatalessSession>) -> Json<StatusResp> {
    Json(v32::set_operation_state(r.session_handle).into())
}
async fn get_function_status(Json(r): Json<DatalessSession>) -> Json<StatusResp> {
    Json(v32::get_function_status(r.session_handle).into())
}
async fn cancel_function(Json(r): Json<DatalessSession>) -> Json<StatusResp> {
    Json(v32::cancel_function(r.session_handle).into())
}
async fn async_complete(Json(r): Json<DatalessSession>) -> Json<StatusResp> {
    Json(v32::async_complete(r.session_handle).into())
}
async fn async_get_id(Json(r): Json<DatalessSession>) -> Json<AsyncGetIdResp> {
    Json(v32::async_get_id(r.session_handle).into())
}
async fn async_join(Json(r): Json<AsyncJoinReq>) -> Json<StatusResp> {
    Json(v32::async_join(r.session_handle, r.id, &r.data).into())
}

async fn sign_recover_init(Json(r): Json<KeyedInitReq>) -> Json<StatusResp> {
    Json(v32::sign_recover_init(r.session_handle, r.mechanism.mechanism, &r.mechanism.parameter, r.key_handle).into())
}
async fn sign_recover(Json(r): Json<DataReq>) -> Json<BytesResp> {
    Json(v32::sign_recover(r.session_handle, &r.data).into())
}
async fn verify_recover_init(Json(r): Json<KeyedInitReq>) -> Json<StatusResp> {
    Json(v32::verify_recover_init(r.session_handle, r.mechanism.mechanism, &r.mechanism.parameter, r.key_handle).into())
}
async fn verify_recover(Json(r): Json<SignatureReq>) -> Json<BytesResp> {
    Json(v32::verify_recover(r.session_handle, &r.signature).into())
}
async fn verify_signature_init(Json(r): Json<VerifySignatureInitReq>) -> Json<StatusResp> {
    Json(
        v32::verify_signature_init(
            r.session_handle,
            r.mechanism.mechanism,
            &r.mechanism.parameter,
            r.key_handle,
            &r.signature,
        )
        .into(),
    )
}
async fn verify_signature(Json(r): Json<DataReq>) -> Json<StatusResp> {
    Json(v32::verify_signature(r.session_handle, &r.data).into())
}

async fn digest_encrypt_update(Json(r): Json<DataReq>) -> Json<BytesResp> {
    Json(v32::digest_encrypt_update(r.session_handle, &r.data).into())
}
async fn decrypt_digest_update(Json(r): Json<DataReq>) -> Json<BytesResp> {
    Json(v32::decrypt_digest_update(r.session_handle, &r.data).into())
}
async fn sign_encrypt_update(Json(r): Json<DataReq>) -> Json<BytesResp> {
    Json(v32::sign_encrypt_update(r.session_handle, &r.data).into())
}
async fn decrypt_verify_update(Json(r): Json<DataReq>) -> Json<BytesResp> {
    Json(v32::decrypt_verify_update(r.session_handle, &r.data).into())
}

async fn message_sign_init(Json(r): Json<KeyedInitReq>) -> Json<StatusResp> {
    Json(v32::message_sign_init(r.session_handle, r.mechanism.mechanism, &r.mechanism.parameter, r.key_handle).into())
}
async fn sign_message(Json(r): Json<DataReq>) -> Json<BytesResp> {
    Json(v32::sign_message(r.session_handle, &r.data).into())
}
async fn message_sign_final(Json(r): Json<DatalessSession>) -> Json<StatusResp> {
    Json(v32::message_sign_final(r.session_handle).into())
}
async fn sign_message_begin(Json(r): Json<DatalessSession>) -> Json<StatusResp> {
    Json(v32::sign_message_begin(r.session_handle).into())
}
async fn sign_message_next(Json(r): Json<SignMessageNextReq>) -> Json<BytesResp> {
    Json(v32::sign_message_next(r.session_handle, &r.part, r.is_final).into())
}

async fn message_verify_init(Json(r): Json<KeyedInitReq>) -> Json<StatusResp> {
    Json(v32::message_verify_init(r.session_handle, r.mechanism.mechanism, &r.mechanism.parameter, r.key_handle).into())
}
async fn verify_message(Json(r): Json<VerifyReq>) -> Json<StatusResp> {
    Json(v32::verify_message(r.session_handle, &r.data, &r.signature).into())
}
async fn message_verify_final(Json(r): Json<DatalessSession>) -> Json<StatusResp> {
    Json(v32::message_verify_final(r.session_handle).into())
}
async fn verify_message_begin(Json(r): Json<DatalessSession>) -> Json<StatusResp> {
    Json(v32::verify_message_begin(r.session_handle).into())
}
async fn verify_message_next(Json(r): Json<VerifyMessageNextReq>) -> Json<StatusResp> {
    let sig = if r.is_final { Some(r.signature.as_slice()) } else { None };
    Json(v32::verify_message_next(r.session_handle, &r.part, sig).into())
}

async fn message_encrypt_init(Json(r): Json<KeyedInitReq>) -> Json<StatusResp> {
    Json(v32::message_encrypt_init(r.session_handle, r.mechanism.mechanism, &r.mechanism.parameter, r.key_handle).into())
}
async fn encrypt_message(Json(r): Json<EncryptMessageReq>) -> Json<EncryptMessageResp> {
    Json(v32::encrypt_message(r.session_handle, &r.iv, r.iv_generator, &r.aad, &r.plaintext, r.tag_bits).into())
}
async fn message_encrypt_final(Json(r): Json<DatalessSession>) -> Json<StatusResp> {
    Json(v32::message_encrypt_final(r.session_handle).into())
}
async fn encrypt_message_begin(Json(r): Json<EncryptMessageBeginReq>) -> Json<EncryptMessageBeginResp> {
    Json(v32::encrypt_message_begin(r.session_handle, &r.iv, r.iv_generator, &r.aad, r.tag_bits).into())
}
async fn encrypt_message_next(Json(r): Json<EncryptMessageNextReq>) -> Json<EncryptMessageNextResp> {
    Json(v32::encrypt_message_next(r.session_handle, &r.plaintext_part, r.is_final, r.tag_bits).into())
}

async fn message_decrypt_init(Json(r): Json<KeyedInitReq>) -> Json<StatusResp> {
    Json(v32::message_decrypt_init(r.session_handle, r.mechanism.mechanism, &r.mechanism.parameter, r.key_handle).into())
}
async fn decrypt_message(Json(r): Json<DecryptMessageReq>) -> Json<BytesResp> {
    Json(v32::decrypt_message(r.session_handle, &r.iv, &r.aad, &r.ciphertext, r.tag_bits, &r.tag).into())
}
async fn message_decrypt_final(Json(r): Json<DatalessSession>) -> Json<StatusResp> {
    Json(v32::message_decrypt_final(r.session_handle).into())
}
async fn decrypt_message_begin(Json(r): Json<DecryptMessageBeginReq>) -> Json<StatusResp> {
    Json(v32::decrypt_message_begin(r.session_handle, &r.iv, &r.aad, r.tag_bits).into())
}
async fn decrypt_message_next(Json(r): Json<DecryptMessageNextReq>) -> Json<BytesResp> {
    Json(v32::decrypt_message_next(r.session_handle, &r.ciphertext_part, r.is_final, r.tag_bits, &r.tag).into())
}

async fn wrap_key(Json(r): Json<WrapKeyReq>) -> Json<BytesResp> {
    Json(v32::wrap_key(r.session_handle, r.mechanism.mechanism, &r.mechanism.parameter, r.wrapping_key_handle, r.key_handle).into())
}
async fn unwrap_key(Json(r): Json<UnwrapKeyReq>) -> Json<ObjectHandleResp> {
    let template = tmpl_parts(&r.template);
    Json(
        v32::unwrap_key(r.session_handle, r.mechanism.mechanism, &r.mechanism.parameter, r.unwrapping_key_handle, &r.wrapped_key, &template)
            .into(),
    )
}
async fn wrap_key_authenticated(Json(r): Json<WrapKeyAuthenticatedReq>) -> Json<BytesResp> {
    Json(
        v32::wrap_key_authenticated(
            r.session_handle, r.mechanism.mechanism, &r.mechanism.parameter, r.wrapping_key_handle, r.key_handle, &r.associated_data,
        )
        .into(),
    )
}
async fn unwrap_key_authenticated(Json(r): Json<UnwrapKeyAuthenticatedReq>) -> Json<ObjectHandleResp> {
    let template = tmpl_parts(&r.template);
    Json(
        v32::unwrap_key_authenticated(
            r.session_handle,
            r.mechanism.mechanism,
            &r.mechanism.parameter,
            r.unwrapping_key_handle,
            &r.wrapped_key,
            &template,
            &r.associated_data,
        )
        .into(),
    )
}

/// Same ownership contract as the gRPC handler's `derive_mechanism_params`
/// — a `v32::StructBuilder`'s bytes embed raw pointers into its own
/// `owned` buffers, so the builder itself (not a copy of its bytes) must
/// stay alive through the `derive_key` call. Mirrored here rather than
/// shared across crates since the REST DTO and proto message types differ.
enum DeriveParamBytes {
    Raw(Vec<u8>),
    Structured(v32::StructBuilder),
}
impl DeriveParamBytes {
    fn as_slice(&self) -> &[u8] {
        match self {
            DeriveParamBytes::Raw(v) => v,
            DeriveParamBytes::Structured(b) => b.as_slice(),
        }
    }
}

async fn derive_key(Json(r): Json<DeriveKeyReq>) -> Json<ObjectHandleResp> {
    let template = tmpl_parts(&r.template);
    let params = if let Some(p) = r.ecdh1 {
        DeriveParamBytes::Structured(v32::derive_params::ecdh1(p.kdf, &p.shared_data, &p.public_data))
    } else if let Some(p) = r.hkdf {
        DeriveParamBytes::Structured(v32::derive_params::hkdf(
            p.extract, p.expand, p.prf_hash_mechanism, p.salt_type, &p.salt, p.h_salt_key, &p.info,
        ))
    } else if let Some(p) = r.pbkdf2 {
        DeriveParamBytes::Structured(v32::derive_params::pbkd2(
            p.salt_source, &p.salt_source_data, p.iterations, p.prf, &p.prf_data, &p.password,
        ))
    } else if let Some(p) = r.sp800_108_counter {
        let segments = p.segments.into_iter().map(|s| v32::derive_params::Segment { prf_type: s.prf_type, value: s.value }).collect();
        DeriveParamBytes::Structured(v32::derive_params::sp800_108_counter(p.prf_type, segments))
    } else if let Some(p) = r.sp800_108_feedback {
        let segments = p.segments.into_iter().map(|s| v32::derive_params::Segment { prf_type: s.prf_type, value: s.value }).collect();
        DeriveParamBytes::Structured(v32::derive_params::sp800_108_feedback(p.prf_type, segments, &p.iv))
    } else {
        DeriveParamBytes::Raw(r.raw_parameter)
    };
    Json(v32::derive_key(r.session_handle, r.mechanism, params.as_slice(), r.base_key_handle, &template).into())
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
