//! `Pkcs11V32` gRPC service — the 1:1 C_* mirror (plan RW0/RW1+).
//!
//! Contract (proto's own doc block is normative): `ck_rv` is a response
//! FIELD; gRPC Status is transport-failure-only, so every handler here
//! returns `Ok(...)` with whatever code the engine produced. Engine
//! calls are dispatched through `spawn_blocking`: unlike the legacy
//! service's short fixed verbs, mirror calls include arbitrarily heavy
//! operations (multipart over big payloads), and blocking a tokio
//! worker for those starves unrelated RPCs.

use pqctoday_pkcs11_remote_core::verbs_v32 as v32;
use pqctoday_pkcs11_remote_proto::pkcs11_v32_server::Pkcs11V32;
use pqctoday_pkcs11_remote_proto::*;
use tonic::{Request, Response, Status};

/// `destructive`: gates C_DestroyObject (later: C_SetAttributeValue,
/// C_InitToken, C_InitPIN). OFF ⇒ those RPCs answer
/// CKR_FUNCTION_NOT_SUPPORTED — an honest PKCS#11 code, not a transport
/// error — per the plan's tests-ON / deployed-OFF posture decision.
pub struct Pkcs11V32Service {
    pub destructive: bool,
}

impl Default for Pkcs11V32Service {
    fn default() -> Self {
        // Default OFF: a deployment must opt in explicitly
        // (--enable-destructive / PKCS11_REMOTE_ENABLE_DESTRUCTIVE=1).
        Self { destructive: false }
    }
}

/// Run a blocking engine call off the async worker. A JoinError can only
/// mean panic/cancel inside the closure — that IS a transport-layer
/// failure, the one thing Status is for on this service.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, Status> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| Status::internal(format!("engine dispatch task failed: {e}")))
}

fn mech_parts(m: Option<&V32Mechanism>) -> (u64, Vec<u8>) {
    match m {
        Some(m) => (m.mechanism, m.parameter.clone()),
        None => (0, Vec::new()), // mechanism 0 matches nothing → the engine's own invalid-mechanism path
    }
}

fn tmpl_parts(t: &[V32AttributeIn]) -> Vec<v32::AttrIn> {
    t.iter().map(|a| (a.attribute_type, a.value.clone())).collect()
}

#[tonic::async_trait]
impl Pkcs11V32 for Pkcs11V32Service {
    async fn c_open_session(
        &self,
        request: Request<V32OpenSessionRequest>,
    ) -> Result<Response<V32OpenSessionResponse>, Status> {
        let req = request.into_inner();
        let (ck_rv, session_handle) = blocking(move || v32::open_session(req.slot_id, req.flags)).await?;
        Ok(Response::new(V32OpenSessionResponse { ck_rv, session_handle }))
    }

    async fn c_close_session(
        &self,
        request: Request<V32SessionRequest>,
    ) -> Result<Response<V32StatusResponse>, Status> {
        let req = request.into_inner();
        let ck_rv = blocking(move || v32::close_session(req.session_handle)).await?;
        Ok(Response::new(V32StatusResponse { ck_rv }))
    }

    async fn c_login(&self, request: Request<V32LoginRequest>) -> Result<Response<V32StatusResponse>, Status> {
        let req = request.into_inner();
        let ck_rv = blocking(move || v32::login(req.session_handle, req.user_type, &req.pin)).await?;
        Ok(Response::new(V32StatusResponse { ck_rv }))
    }

    async fn c_logout(&self, request: Request<V32SessionRequest>) -> Result<Response<V32StatusResponse>, Status> {
        let req = request.into_inner();
        let ck_rv = blocking(move || v32::logout(req.session_handle)).await?;
        Ok(Response::new(V32StatusResponse { ck_rv }))
    }

    async fn c_get_session_info(
        &self,
        request: Request<V32SessionRequest>,
    ) -> Result<Response<V32GetSessionInfoResponse>, Status> {
        let req = request.into_inner();
        let (ck_rv, info) = blocking(move || v32::get_session_info(req.session_handle)).await?;
        Ok(Response::new(V32GetSessionInfoResponse {
            ck_rv,
            slot_id: info.slot_id,
            state: info.state,
            flags: info.flags,
            device_error: info.device_error,
        }))
    }

    async fn c_get_token_info(
        &self,
        request: Request<V32SlotRequest>,
    ) -> Result<Response<V32GetTokenInfoResponse>, Status> {
        let req = request.into_inner();
        let (ck_rv, info) = blocking(move || v32::get_token_info(req.slot_id)).await?;
        let mut resp = V32GetTokenInfoResponse { ck_rv, ..Default::default() };
        if let Some(i) = info {
            resp.label = i.label;
            resp.manufacturer = i.manufacturer;
            resp.model = i.model;
            resp.serial_number = i.serial_number;
            resp.flags = i.flags;
            resp.session_count = i.session_count;
            resp.rw_session_count = i.rw_session_count;
            resp.max_pin_len = i.max_pin_len;
            resp.min_pin_len = i.min_pin_len;
            resp.hardware_version_major = u32::from(i.hardware_version.0);
            resp.hardware_version_minor = u32::from(i.hardware_version.1);
            resp.firmware_version_major = u32::from(i.firmware_version.0);
            resp.firmware_version_minor = u32::from(i.firmware_version.1);
        }
        Ok(Response::new(resp))
    }

    async fn c_get_mechanism_list(
        &self,
        request: Request<V32SlotRequest>,
    ) -> Result<Response<V32GetMechanismListResponse>, Status> {
        let req = request.into_inner();
        let (ck_rv, mechanisms) = blocking(move || v32::get_mechanism_list(req.slot_id)).await?;
        Ok(Response::new(V32GetMechanismListResponse { ck_rv, mechanisms }))
    }

    async fn c_get_mechanism_info(
        &self,
        request: Request<V32GetMechanismInfoRequest>,
    ) -> Result<Response<V32GetMechanismInfoResponse>, Status> {
        let req = request.into_inner();
        let (ck_rv, min_key_size, max_key_size, flags) =
            blocking(move || v32::get_mechanism_info(req.slot_id, req.mechanism)).await?;
        Ok(Response::new(V32GetMechanismInfoResponse { ck_rv, min_key_size, max_key_size, flags }))
    }

    async fn c_generate_random(
        &self,
        request: Request<V32GenerateRandomRequest>,
    ) -> Result<Response<V32BytesResponse>, Status> {
        let req = request.into_inner();
        let (ck_rv, data) = blocking(move || v32::generate_random(req.session_handle, req.length)).await?;
        Ok(Response::new(V32BytesResponse { ck_rv, data }))
    }

    async fn c_seed_random(
        &self,
        request: Request<V32SeedRandomRequest>,
    ) -> Result<Response<V32StatusResponse>, Status> {
        let req = request.into_inner();
        let ck_rv = blocking(move || v32::seed_random(req.session_handle, &req.seed)).await?;
        Ok(Response::new(V32StatusResponse { ck_rv }))
    }

    async fn c_digest_init(
        &self,
        request: Request<V32MechanismSessionRequest>,
    ) -> Result<Response<V32StatusResponse>, Status> {
        let req = request.into_inner();
        let (mech, param) = mech_parts(req.mechanism.as_ref());
        let ck_rv = blocking(move || v32::digest_init(req.session_handle, mech, &param)).await?;
        Ok(Response::new(V32StatusResponse { ck_rv }))
    }

    async fn c_digest_update(
        &self,
        request: Request<V32DataRequest>,
    ) -> Result<Response<V32StatusResponse>, Status> {
        let req = request.into_inner();
        let ck_rv = blocking(move || v32::digest_update(req.session_handle, &req.data)).await?;
        Ok(Response::new(V32StatusResponse { ck_rv }))
    }

    async fn c_digest_final(
        &self,
        request: Request<V32SessionRequest>,
    ) -> Result<Response<V32BytesResponse>, Status> {
        let req = request.into_inner();
        let (ck_rv, data) = blocking(move || v32::digest_final(req.session_handle)).await?;
        Ok(Response::new(V32BytesResponse { ck_rv, data }))
    }

    async fn c_digest(&self, request: Request<V32DigestRequest>) -> Result<Response<V32BytesResponse>, Status> {
        let req = request.into_inner();
        let (mech, param) = mech_parts(req.mechanism.as_ref());
        let (ck_rv, data) =
            blocking(move || v32::digest(req.session_handle, mech, &param, &req.data)).await?;
        Ok(Response::new(V32BytesResponse { ck_rv, data }))
    }

    async fn c_sign_init(
        &self,
        request: Request<V32KeyedInitRequest>,
    ) -> Result<Response<V32StatusResponse>, Status> {
        let req = request.into_inner();
        let (mech, param) = mech_parts(req.mechanism.as_ref());
        let ck_rv =
            blocking(move || v32::sign_init(req.session_handle, mech, &param, req.key_handle)).await?;
        Ok(Response::new(V32StatusResponse { ck_rv }))
    }

    async fn c_sign(&self, request: Request<V32DataRequest>) -> Result<Response<V32BytesResponse>, Status> {
        let req = request.into_inner();
        let (ck_rv, data) = blocking(move || v32::sign(req.session_handle, &req.data)).await?;
        Ok(Response::new(V32BytesResponse { ck_rv, data }))
    }

    async fn c_sign_update(
        &self,
        request: Request<V32DataRequest>,
    ) -> Result<Response<V32StatusResponse>, Status> {
        let req = request.into_inner();
        let ck_rv = blocking(move || v32::sign_update(req.session_handle, &req.data)).await?;
        Ok(Response::new(V32StatusResponse { ck_rv }))
    }

    async fn c_sign_final(
        &self,
        request: Request<V32SessionRequest>,
    ) -> Result<Response<V32BytesResponse>, Status> {
        let req = request.into_inner();
        let (ck_rv, data) = blocking(move || v32::sign_final(req.session_handle)).await?;
        Ok(Response::new(V32BytesResponse { ck_rv, data }))
    }

    async fn c_verify_init(
        &self,
        request: Request<V32KeyedInitRequest>,
    ) -> Result<Response<V32StatusResponse>, Status> {
        let req = request.into_inner();
        let (mech, param) = mech_parts(req.mechanism.as_ref());
        let ck_rv =
            blocking(move || v32::verify_init(req.session_handle, mech, &param, req.key_handle)).await?;
        Ok(Response::new(V32StatusResponse { ck_rv }))
    }

    async fn c_verify(&self, request: Request<V32VerifyRequest>) -> Result<Response<V32StatusResponse>, Status> {
        let req = request.into_inner();
        let ck_rv = blocking(move || v32::verify(req.session_handle, &req.data, &req.signature)).await?;
        Ok(Response::new(V32StatusResponse { ck_rv }))
    }

    async fn c_verify_update(
        &self,
        request: Request<V32DataRequest>,
    ) -> Result<Response<V32StatusResponse>, Status> {
        let req = request.into_inner();
        let ck_rv = blocking(move || v32::verify_update(req.session_handle, &req.data)).await?;
        Ok(Response::new(V32StatusResponse { ck_rv }))
    }

    async fn c_verify_final(
        &self,
        request: Request<V32SignatureRequest>,
    ) -> Result<Response<V32StatusResponse>, Status> {
        let req = request.into_inner();
        let ck_rv = blocking(move || v32::verify_final(req.session_handle, &req.signature)).await?;
        Ok(Response::new(V32StatusResponse { ck_rv }))
    }

    async fn c_get_attribute_value(
        &self,
        request: Request<V32GetAttributeValueRequest>,
    ) -> Result<Response<V32GetAttributeValueResponse>, Status> {
        let req = request.into_inner();
        let (ck_rv, attrs) = blocking(move || {
            v32::get_attribute_value(req.session_handle, req.object_handle, &req.attribute_types)
        })
        .await?;
        Ok(Response::new(V32GetAttributeValueResponse {
            ck_rv,
            attributes: attrs
                .into_iter()
                .map(|a| V32Attribute {
                    attribute_type: a.attribute_type,
                    available: a.available,
                    value: a.value,
                })
                .collect(),
        }))
    }

    async fn c_destroy_object(
        &self,
        request: Request<V32ObjectRequest>,
    ) -> Result<Response<V32StatusResponse>, Status> {
        if !self.destructive {
            return Ok(Response::new(V32StatusResponse {
                ck_rv: v32::ck::CKR_FUNCTION_NOT_SUPPORTED,
            }));
        }
        let req = request.into_inner();
        let ck_rv = blocking(move || v32::destroy_object(req.session_handle, req.object_handle)).await?;
        Ok(Response::new(V32StatusResponse { ck_rv }))
    }

    // ── object & keygen templates (RW2) ─────────────────────────────────

    async fn c_generate_key(
        &self,
        request: Request<V32GenerateKeyRequest>,
    ) -> Result<Response<V32ObjectHandleResponse>, Status> {
        let req = request.into_inner();
        let (mech, param) = mech_parts(req.mechanism.as_ref());
        let template = tmpl_parts(&req.template);
        let (ck_rv, object_handle) =
            blocking(move || v32::generate_key(req.session_handle, mech, &param, &template)).await?;
        Ok(Response::new(V32ObjectHandleResponse { ck_rv, object_handle }))
    }

    async fn c_generate_key_pair(
        &self,
        request: Request<V32GenerateKeyPairRequest>,
    ) -> Result<Response<V32GenerateKeyPairResponse>, Status> {
        let req = request.into_inner();
        let (mech, param) = mech_parts(req.mechanism.as_ref());
        let public_template = tmpl_parts(&req.public_key_template);
        let private_template = tmpl_parts(&req.private_key_template);
        let (ck_rv, public_handle, private_handle) = blocking(move || {
            v32::generate_key_pair(req.session_handle, mech, &param, &public_template, &private_template)
        })
        .await?;
        Ok(Response::new(V32GenerateKeyPairResponse { ck_rv, public_handle, private_handle }))
    }

    async fn c_create_object(
        &self,
        request: Request<V32CreateObjectRequest>,
    ) -> Result<Response<V32ObjectHandleResponse>, Status> {
        let req = request.into_inner();
        let template = tmpl_parts(&req.template);
        let (ck_rv, object_handle) =
            blocking(move || v32::create_object(req.session_handle, &template)).await?;
        Ok(Response::new(V32ObjectHandleResponse { ck_rv, object_handle }))
    }

    async fn c_set_attribute_value(
        &self,
        request: Request<V32SetAttributeValueRequest>,
    ) -> Result<Response<V32StatusResponse>, Status> {
        if !self.destructive {
            return Ok(Response::new(V32StatusResponse {
                ck_rv: v32::ck::CKR_FUNCTION_NOT_SUPPORTED,
            }));
        }
        let req = request.into_inner();
        let template = tmpl_parts(&req.template);
        let ck_rv =
            blocking(move || v32::set_attribute_value(req.session_handle, req.object_handle, &template))
                .await?;
        Ok(Response::new(V32StatusResponse { ck_rv }))
    }

    async fn c_copy_object(
        &self,
        request: Request<V32CopyObjectRequest>,
    ) -> Result<Response<V32ObjectHandleResponse>, Status> {
        let req = request.into_inner();
        let template = tmpl_parts(&req.template);
        let (ck_rv, object_handle) =
            blocking(move || v32::copy_object(req.session_handle, req.object_handle, &template)).await?;
        Ok(Response::new(V32ObjectHandleResponse { ck_rv, object_handle }))
    }

    async fn c_get_object_size(
        &self,
        request: Request<V32ObjectRequest>,
    ) -> Result<Response<V32GetObjectSizeResponse>, Status> {
        let req = request.into_inner();
        let (ck_rv, size) =
            blocking(move || v32::get_object_size(req.session_handle, req.object_handle)).await?;
        Ok(Response::new(V32GetObjectSizeResponse { ck_rv, size }))
    }

    async fn c_find_objects_init(
        &self,
        request: Request<V32FindObjectsInitRequest>,
    ) -> Result<Response<V32StatusResponse>, Status> {
        let req = request.into_inner();
        let template = tmpl_parts(&req.template);
        let ck_rv = blocking(move || v32::find_objects_init(req.session_handle, &template)).await?;
        Ok(Response::new(V32StatusResponse { ck_rv }))
    }

    async fn c_find_objects(
        &self,
        request: Request<V32FindObjectsRequest>,
    ) -> Result<Response<V32FindObjectsResponse>, Status> {
        let req = request.into_inner();
        let (ck_rv, object_handles) =
            blocking(move || v32::find_objects(req.session_handle, req.max_object_count)).await?;
        Ok(Response::new(V32FindObjectsResponse { ck_rv, object_handles }))
    }

    async fn c_find_objects_final(
        &self,
        request: Request<V32SessionRequest>,
    ) -> Result<Response<V32StatusResponse>, Status> {
        let req = request.into_inner();
        let ck_rv = blocking(move || v32::find_objects_final(req.session_handle)).await?;
        Ok(Response::new(V32StatusResponse { ck_rv }))
    }

    // ── encrypt / decrypt FSM + one-shot (RW3) ──────────────────────────

    async fn c_encrypt_init(
        &self,
        request: Request<V32KeyedInitRequest>,
    ) -> Result<Response<V32StatusResponse>, Status> {
        let req = request.into_inner();
        let (mech, param) = mech_parts(req.mechanism.as_ref());
        let ck_rv =
            blocking(move || v32::encrypt_init(req.session_handle, mech, &param, req.key_handle)).await?;
        Ok(Response::new(V32StatusResponse { ck_rv }))
    }

    async fn c_encrypt(&self, request: Request<V32DataRequest>) -> Result<Response<V32BytesResponse>, Status> {
        let req = request.into_inner();
        let (ck_rv, data) = blocking(move || v32::encrypt(req.session_handle, &req.data)).await?;
        Ok(Response::new(V32BytesResponse { ck_rv, data }))
    }

    async fn c_encrypt_update(
        &self,
        request: Request<V32DataRequest>,
    ) -> Result<Response<V32BytesResponse>, Status> {
        let req = request.into_inner();
        let (ck_rv, data) = blocking(move || v32::encrypt_update(req.session_handle, &req.data)).await?;
        Ok(Response::new(V32BytesResponse { ck_rv, data }))
    }

    async fn c_encrypt_final(
        &self,
        request: Request<V32SessionRequest>,
    ) -> Result<Response<V32BytesResponse>, Status> {
        let req = request.into_inner();
        let (ck_rv, data) = blocking(move || v32::encrypt_final(req.session_handle)).await?;
        Ok(Response::new(V32BytesResponse { ck_rv, data }))
    }

    async fn c_decrypt_init(
        &self,
        request: Request<V32KeyedInitRequest>,
    ) -> Result<Response<V32StatusResponse>, Status> {
        let req = request.into_inner();
        let (mech, param) = mech_parts(req.mechanism.as_ref());
        let ck_rv =
            blocking(move || v32::decrypt_init(req.session_handle, mech, &param, req.key_handle)).await?;
        Ok(Response::new(V32StatusResponse { ck_rv }))
    }

    async fn c_decrypt(&self, request: Request<V32DataRequest>) -> Result<Response<V32BytesResponse>, Status> {
        let req = request.into_inner();
        let (ck_rv, data) = blocking(move || v32::decrypt(req.session_handle, &req.data)).await?;
        Ok(Response::new(V32BytesResponse { ck_rv, data }))
    }

    async fn c_decrypt_update(
        &self,
        request: Request<V32DataRequest>,
    ) -> Result<Response<V32BytesResponse>, Status> {
        let req = request.into_inner();
        let (ck_rv, data) = blocking(move || v32::decrypt_update(req.session_handle, &req.data)).await?;
        Ok(Response::new(V32BytesResponse { ck_rv, data }))
    }

    async fn c_decrypt_final(
        &self,
        request: Request<V32SessionRequest>,
    ) -> Result<Response<V32BytesResponse>, Status> {
        let req = request.into_inner();
        let (ck_rv, data) = blocking(move || v32::decrypt_final(req.session_handle)).await?;
        Ok(Response::new(V32BytesResponse { ck_rv, data }))
    }

    // ── admin / info (RW6a) ──────────────────────────────────────────────

    async fn c_get_info(&self, _request: Request<V32Empty>) -> Result<Response<V32BytesResponse>, Status> {
        let (ck_rv, data) = blocking(v32::get_info).await?;
        Ok(Response::new(V32BytesResponse { ck_rv, data }))
    }

    async fn c_get_slot_list(
        &self,
        request: Request<V32GetSlotListRequest>,
    ) -> Result<Response<V32GetSlotListResponse>, Status> {
        let req = request.into_inner();
        let (ck_rv, slot_ids) = blocking(move || v32::get_slot_list(req.token_present)).await?;
        Ok(Response::new(V32GetSlotListResponse { ck_rv, slot_ids }))
    }

    async fn c_get_slot_info(
        &self,
        request: Request<V32SlotRequest>,
    ) -> Result<Response<V32BytesResponse>, Status> {
        let req = request.into_inner();
        let (ck_rv, data) = blocking(move || v32::get_slot_info(req.slot_id)).await?;
        Ok(Response::new(V32BytesResponse { ck_rv, data }))
    }

    async fn c_wait_for_slot_event(
        &self,
        request: Request<V32SlotEventRequest>,
    ) -> Result<Response<V32StatusResponse>, Status> {
        let req = request.into_inner();
        let ck_rv = blocking(move || v32::wait_for_slot_event(req.flags)).await?;
        Ok(Response::new(V32StatusResponse { ck_rv }))
    }

    async fn c_close_all_sessions(
        &self,
        request: Request<V32SlotRequest>,
    ) -> Result<Response<V32StatusResponse>, Status> {
        let req = request.into_inner();
        let ck_rv = blocking(move || v32::close_all_sessions(req.slot_id)).await?;
        Ok(Response::new(V32StatusResponse { ck_rv }))
    }

    async fn c_session_cancel(
        &self,
        request: Request<V32SessionFlagsRequest>,
    ) -> Result<Response<V32StatusResponse>, Status> {
        let req = request.into_inner();
        let ck_rv = blocking(move || v32::session_cancel(req.session_handle, req.flags)).await?;
        Ok(Response::new(V32StatusResponse { ck_rv }))
    }

    async fn c_login_user(
        &self,
        request: Request<V32LoginRequest>,
    ) -> Result<Response<V32StatusResponse>, Status> {
        let req = request.into_inner();
        let ck_rv =
            blocking(move || v32::login_user(req.session_handle, req.user_type, &req.pin)).await?;
        Ok(Response::new(V32StatusResponse { ck_rv }))
    }

    // ── destructive-gated admin (RW6a) ───────────────────────────────────

    async fn c_init_token(
        &self,
        request: Request<V32InitTokenRequest>,
    ) -> Result<Response<V32StatusResponse>, Status> {
        if !self.destructive {
            return Ok(Response::new(V32StatusResponse {
                ck_rv: v32::ck::CKR_FUNCTION_NOT_SUPPORTED,
            }));
        }
        let req = request.into_inner();
        let ck_rv =
            blocking(move || v32::init_token(req.slot_id, &req.pin, &req.label)).await?;
        Ok(Response::new(V32StatusResponse { ck_rv }))
    }

    async fn c_init_pin(
        &self,
        request: Request<V32InitPinRequest>,
    ) -> Result<Response<V32StatusResponse>, Status> {
        if !self.destructive {
            return Ok(Response::new(V32StatusResponse {
                ck_rv: v32::ck::CKR_FUNCTION_NOT_SUPPORTED,
            }));
        }
        let req = request.into_inner();
        let ck_rv = blocking(move || v32::init_pin(req.session_handle, &req.pin)).await?;
        Ok(Response::new(V32StatusResponse { ck_rv }))
    }

    async fn c_set_pin(
        &self,
        request: Request<V32SetPinRequest>,
    ) -> Result<Response<V32StatusResponse>, Status> {
        if !self.destructive {
            return Ok(Response::new(V32StatusResponse {
                ck_rv: v32::ck::CKR_FUNCTION_NOT_SUPPORTED,
            }));
        }
        let req = request.into_inner();
        let ck_rv =
            blocking(move || v32::set_pin(req.session_handle, &req.old_pin, &req.new_pin)).await?;
        Ok(Response::new(V32StatusResponse { ck_rv }))
    }

    // ── honest-code stubs (RW6a) ──────────────────────────────────────────

    async fn c_digest_key(
        &self,
        request: Request<V32ObjectRequest>,
    ) -> Result<Response<V32StatusResponse>, Status> {
        let req = request.into_inner();
        let ck_rv = blocking(move || v32::digest_key(req.session_handle, req.object_handle)).await?;
        Ok(Response::new(V32StatusResponse { ck_rv }))
    }
    async fn c_get_operation_state(
        &self,
        request: Request<V32SessionRequest>,
    ) -> Result<Response<V32StatusResponse>, Status> {
        let req = request.into_inner();
        let ck_rv = blocking(move || v32::get_operation_state(req.session_handle)).await?;
        Ok(Response::new(V32StatusResponse { ck_rv }))
    }
    async fn c_set_operation_state(
        &self,
        request: Request<V32SessionRequest>,
    ) -> Result<Response<V32StatusResponse>, Status> {
        let req = request.into_inner();
        let ck_rv = blocking(move || v32::set_operation_state(req.session_handle)).await?;
        Ok(Response::new(V32StatusResponse { ck_rv }))
    }
    async fn c_get_function_status(
        &self,
        request: Request<V32SessionRequest>,
    ) -> Result<Response<V32StatusResponse>, Status> {
        let req = request.into_inner();
        let ck_rv = blocking(move || v32::get_function_status(req.session_handle)).await?;
        Ok(Response::new(V32StatusResponse { ck_rv }))
    }
    async fn c_cancel_function(
        &self,
        request: Request<V32SessionRequest>,
    ) -> Result<Response<V32StatusResponse>, Status> {
        let req = request.into_inner();
        let ck_rv = blocking(move || v32::cancel_function(req.session_handle)).await?;
        Ok(Response::new(V32StatusResponse { ck_rv }))
    }
    async fn c_async_complete(
        &self,
        request: Request<V32SessionRequest>,
    ) -> Result<Response<V32StatusResponse>, Status> {
        let req = request.into_inner();
        let ck_rv = blocking(move || v32::async_complete(req.session_handle)).await?;
        Ok(Response::new(V32StatusResponse { ck_rv }))
    }
    async fn c_async_get_id(
        &self,
        request: Request<V32SessionRequest>,
    ) -> Result<Response<V32AsyncGetIdResponse>, Status> {
        let req = request.into_inner();
        let ck_rv = blocking(move || v32::async_get_id(req.session_handle)).await?;
        Ok(Response::new(V32AsyncGetIdResponse { ck_rv, id: 0 }))
    }
    async fn c_async_join(
        &self,
        request: Request<V32AsyncJoinRequest>,
    ) -> Result<Response<V32StatusResponse>, Status> {
        let req = request.into_inner();
        let ck_rv =
            blocking(move || v32::async_join(req.session_handle, req.id, &req.data)).await?;
        Ok(Response::new(V32StatusResponse { ck_rv }))
    }

    // ── recover + verify-with-signature (RW6a) ───────────────────────────

    async fn c_sign_recover_init(
        &self,
        request: Request<V32KeyedInitRequest>,
    ) -> Result<Response<V32StatusResponse>, Status> {
        let req = request.into_inner();
        let (mech, param) = mech_parts(req.mechanism.as_ref());
        let ck_rv = blocking(move || {
            v32::sign_recover_init(req.session_handle, mech, &param, req.key_handle)
        })
        .await?;
        Ok(Response::new(V32StatusResponse { ck_rv }))
    }
    async fn c_sign_recover(
        &self,
        request: Request<V32DataRequest>,
    ) -> Result<Response<V32BytesResponse>, Status> {
        let req = request.into_inner();
        let (ck_rv, data) = blocking(move || v32::sign_recover(req.session_handle, &req.data)).await?;
        Ok(Response::new(V32BytesResponse { ck_rv, data }))
    }
    async fn c_verify_recover_init(
        &self,
        request: Request<V32KeyedInitRequest>,
    ) -> Result<Response<V32StatusResponse>, Status> {
        let req = request.into_inner();
        let (mech, param) = mech_parts(req.mechanism.as_ref());
        let ck_rv = blocking(move || {
            v32::verify_recover_init(req.session_handle, mech, &param, req.key_handle)
        })
        .await?;
        Ok(Response::new(V32StatusResponse { ck_rv }))
    }
    async fn c_verify_recover(
        &self,
        request: Request<V32SignatureRequest>,
    ) -> Result<Response<V32BytesResponse>, Status> {
        let req = request.into_inner();
        let (ck_rv, data) =
            blocking(move || v32::verify_recover(req.session_handle, &req.signature)).await?;
        Ok(Response::new(V32BytesResponse { ck_rv, data }))
    }
    async fn c_verify_signature_init(
        &self,
        request: Request<V32VerifySignatureInitRequest>,
    ) -> Result<Response<V32StatusResponse>, Status> {
        let req = request.into_inner();
        let (mech, param) = mech_parts(req.mechanism.as_ref());
        let ck_rv = blocking(move || {
            v32::verify_signature_init(req.session_handle, mech, &param, req.key_handle, &req.signature)
        })
        .await?;
        Ok(Response::new(V32StatusResponse { ck_rv }))
    }
    async fn c_verify_signature(
        &self,
        request: Request<V32DataRequest>,
    ) -> Result<Response<V32StatusResponse>, Status> {
        let req = request.into_inner();
        let ck_rv = blocking(move || v32::verify_signature(req.session_handle, &req.data)).await?;
        Ok(Response::new(V32StatusResponse { ck_rv }))
    }

    // ── dual-function quartet (RW6a) ──────────────────────────────────────

    async fn c_digest_encrypt_update(
        &self,
        request: Request<V32DataRequest>,
    ) -> Result<Response<V32BytesResponse>, Status> {
        let req = request.into_inner();
        let (ck_rv, data) =
            blocking(move || v32::digest_encrypt_update(req.session_handle, &req.data)).await?;
        Ok(Response::new(V32BytesResponse { ck_rv, data }))
    }
    async fn c_decrypt_digest_update(
        &self,
        request: Request<V32DataRequest>,
    ) -> Result<Response<V32BytesResponse>, Status> {
        let req = request.into_inner();
        let (ck_rv, data) =
            blocking(move || v32::decrypt_digest_update(req.session_handle, &req.data)).await?;
        Ok(Response::new(V32BytesResponse { ck_rv, data }))
    }
    async fn c_sign_encrypt_update(
        &self,
        request: Request<V32DataRequest>,
    ) -> Result<Response<V32BytesResponse>, Status> {
        let req = request.into_inner();
        let (ck_rv, data) =
            blocking(move || v32::sign_encrypt_update(req.session_handle, &req.data)).await?;
        Ok(Response::new(V32BytesResponse { ck_rv, data }))
    }
    async fn c_decrypt_verify_update(
        &self,
        request: Request<V32DataRequest>,
    ) -> Result<Response<V32BytesResponse>, Status> {
        let req = request.into_inner();
        let (ck_rv, data) =
            blocking(move || v32::decrypt_verify_update(req.session_handle, &req.data)).await?;
        Ok(Response::new(V32BytesResponse { ck_rv, data }))
    }

    // ── message sign (RW6b) ──────────────────────────────────────────────

    async fn c_message_sign_init(
        &self,
        request: Request<V32KeyedInitRequest>,
    ) -> Result<Response<V32StatusResponse>, Status> {
        let req = request.into_inner();
        let (mech, param) = mech_parts(req.mechanism.as_ref());
        let ck_rv = blocking(move || {
            v32::message_sign_init(req.session_handle, mech, &param, req.key_handle)
        })
        .await?;
        Ok(Response::new(V32StatusResponse { ck_rv }))
    }
    async fn c_sign_message(&self, request: Request<V32DataRequest>) -> Result<Response<V32BytesResponse>, Status> {
        let req = request.into_inner();
        let (ck_rv, data) = blocking(move || v32::sign_message(req.session_handle, &req.data)).await?;
        Ok(Response::new(V32BytesResponse { ck_rv, data }))
    }
    async fn c_message_sign_final(
        &self,
        request: Request<V32SessionRequest>,
    ) -> Result<Response<V32StatusResponse>, Status> {
        let req = request.into_inner();
        let ck_rv = blocking(move || v32::message_sign_final(req.session_handle)).await?;
        Ok(Response::new(V32StatusResponse { ck_rv }))
    }
    async fn c_sign_message_begin(
        &self,
        request: Request<V32SessionRequest>,
    ) -> Result<Response<V32StatusResponse>, Status> {
        let req = request.into_inner();
        let ck_rv = blocking(move || v32::sign_message_begin(req.session_handle)).await?;
        Ok(Response::new(V32StatusResponse { ck_rv }))
    }
    async fn c_sign_message_next(
        &self,
        request: Request<V32SignMessageNextRequest>,
    ) -> Result<Response<V32BytesResponse>, Status> {
        let req = request.into_inner();
        let (ck_rv, data) = blocking(move || {
            v32::sign_message_next(req.session_handle, &req.part, req.is_final)
        })
        .await?;
        Ok(Response::new(V32BytesResponse { ck_rv, data }))
    }

    // ── message verify (RW6b) ────────────────────────────────────────────

    async fn c_message_verify_init(
        &self,
        request: Request<V32KeyedInitRequest>,
    ) -> Result<Response<V32StatusResponse>, Status> {
        let req = request.into_inner();
        let (mech, param) = mech_parts(req.mechanism.as_ref());
        let ck_rv = blocking(move || {
            v32::message_verify_init(req.session_handle, mech, &param, req.key_handle)
        })
        .await?;
        Ok(Response::new(V32StatusResponse { ck_rv }))
    }
    async fn c_verify_message(
        &self,
        request: Request<V32VerifyRequest>,
    ) -> Result<Response<V32StatusResponse>, Status> {
        let req = request.into_inner();
        let ck_rv =
            blocking(move || v32::verify_message(req.session_handle, &req.data, &req.signature)).await?;
        Ok(Response::new(V32StatusResponse { ck_rv }))
    }
    async fn c_message_verify_final(
        &self,
        request: Request<V32SessionRequest>,
    ) -> Result<Response<V32StatusResponse>, Status> {
        let req = request.into_inner();
        let ck_rv = blocking(move || v32::message_verify_final(req.session_handle)).await?;
        Ok(Response::new(V32StatusResponse { ck_rv }))
    }
    async fn c_verify_message_begin(
        &self,
        request: Request<V32SessionRequest>,
    ) -> Result<Response<V32StatusResponse>, Status> {
        let req = request.into_inner();
        let ck_rv = blocking(move || v32::verify_message_begin(req.session_handle)).await?;
        Ok(Response::new(V32StatusResponse { ck_rv }))
    }
    async fn c_verify_message_next(
        &self,
        request: Request<V32VerifyMessageNextRequest>,
    ) -> Result<Response<V32StatusResponse>, Status> {
        let req = request.into_inner();
        let ck_rv = blocking(move || {
            let sig = if req.is_final { Some(req.signature.as_slice()) } else { None };
            v32::verify_message_next(req.session_handle, &req.part, sig)
        })
        .await?;
        Ok(Response::new(V32StatusResponse { ck_rv }))
    }

    // ── message encrypt (RW6b) ───────────────────────────────────────────

    async fn c_message_encrypt_init(
        &self,
        request: Request<V32KeyedInitRequest>,
    ) -> Result<Response<V32StatusResponse>, Status> {
        let req = request.into_inner();
        let (mech, param) = mech_parts(req.mechanism.as_ref());
        let ck_rv = blocking(move || {
            v32::message_encrypt_init(req.session_handle, mech, &param, req.key_handle)
        })
        .await?;
        Ok(Response::new(V32StatusResponse { ck_rv }))
    }
    async fn c_encrypt_message(
        &self,
        request: Request<V32EncryptMessageRequest>,
    ) -> Result<Response<V32EncryptMessageResponse>, Status> {
        let req = request.into_inner();
        let (ck_rv, ciphertext, tag, iv_used) = blocking(move || {
            v32::encrypt_message(req.session_handle, &req.iv, req.iv_generator, &req.aad, &req.plaintext, req.tag_bits)
        })
        .await?;
        Ok(Response::new(V32EncryptMessageResponse { ck_rv, ciphertext, tag, iv_used }))
    }
    async fn c_message_encrypt_final(
        &self,
        request: Request<V32SessionRequest>,
    ) -> Result<Response<V32StatusResponse>, Status> {
        let req = request.into_inner();
        let ck_rv = blocking(move || v32::message_encrypt_final(req.session_handle)).await?;
        Ok(Response::new(V32StatusResponse { ck_rv }))
    }
    async fn c_encrypt_message_begin(
        &self,
        request: Request<V32EncryptMessageBeginRequest>,
    ) -> Result<Response<V32EncryptMessageBeginResponse>, Status> {
        let req = request.into_inner();
        let (ck_rv, iv_used) = blocking(move || {
            v32::encrypt_message_begin(req.session_handle, &req.iv, req.iv_generator, &req.aad, req.tag_bits)
        })
        .await?;
        Ok(Response::new(V32EncryptMessageBeginResponse { ck_rv, iv_used }))
    }
    async fn c_encrypt_message_next(
        &self,
        request: Request<V32EncryptMessageNextRequest>,
    ) -> Result<Response<V32EncryptMessageNextResponse>, Status> {
        let req = request.into_inner();
        let (ck_rv, ciphertext_part, tag) = blocking(move || {
            v32::encrypt_message_next(req.session_handle, &req.plaintext_part, req.is_final, req.tag_bits)
        })
        .await?;
        Ok(Response::new(V32EncryptMessageNextResponse {
            ck_rv,
            ciphertext_part,
            tag: tag.unwrap_or_default(),
        }))
    }

    // ── message decrypt (RW6b) ───────────────────────────────────────────

    async fn c_message_decrypt_init(
        &self,
        request: Request<V32KeyedInitRequest>,
    ) -> Result<Response<V32StatusResponse>, Status> {
        let req = request.into_inner();
        let (mech, param) = mech_parts(req.mechanism.as_ref());
        let ck_rv = blocking(move || {
            v32::message_decrypt_init(req.session_handle, mech, &param, req.key_handle)
        })
        .await?;
        Ok(Response::new(V32StatusResponse { ck_rv }))
    }
    async fn c_decrypt_message(
        &self,
        request: Request<V32DecryptMessageRequest>,
    ) -> Result<Response<V32BytesResponse>, Status> {
        let req = request.into_inner();
        let (ck_rv, data) = blocking(move || {
            v32::decrypt_message(req.session_handle, &req.iv, &req.aad, &req.ciphertext, req.tag_bits, &req.tag)
        })
        .await?;
        Ok(Response::new(V32BytesResponse { ck_rv, data }))
    }
    async fn c_message_decrypt_final(
        &self,
        request: Request<V32SessionRequest>,
    ) -> Result<Response<V32StatusResponse>, Status> {
        let req = request.into_inner();
        let ck_rv = blocking(move || v32::message_decrypt_final(req.session_handle)).await?;
        Ok(Response::new(V32StatusResponse { ck_rv }))
    }
    async fn c_decrypt_message_begin(
        &self,
        request: Request<V32DecryptMessageBeginRequest>,
    ) -> Result<Response<V32StatusResponse>, Status> {
        let req = request.into_inner();
        let ck_rv = blocking(move || {
            v32::decrypt_message_begin(req.session_handle, &req.iv, &req.aad, req.tag_bits)
        })
        .await?;
        Ok(Response::new(V32StatusResponse { ck_rv }))
    }
    async fn c_decrypt_message_next(
        &self,
        request: Request<V32DecryptMessageNextRequest>,
    ) -> Result<Response<V32BytesResponse>, Status> {
        let req = request.into_inner();
        let (ck_rv, data) = blocking(move || {
            v32::decrypt_message_next(req.session_handle, &req.ciphertext_part, req.is_final, req.tag_bits, &req.tag)
        })
        .await?;
        Ok(Response::new(V32BytesResponse { ck_rv, data }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqctoday_pkcs11_remote_proto::V32ObjectRequest;

    // The OFF posture (deployed-container default): C_DestroyObject must
    // answer CKR_FUNCTION_NOT_SUPPORTED as a ck_rv FIELD — never a
    // transport error, and never actually destroying anything. The ON
    // posture is covered by the acceptance suite's v6 parity test.
    #[tokio::test]
    async fn destroy_object_off_posture_returns_function_not_supported() {
        let svc = Pkcs11V32Service { destructive: false };
        let resp = svc
            .c_destroy_object(tonic::Request::new(V32ObjectRequest { session_handle: 0, object_handle: 0 }))
            .await
            .expect("transport ok")
            .into_inner();
        assert_eq!(resp.ck_rv, v32::ck::CKR_FUNCTION_NOT_SUPPORTED);
    }

    #[tokio::test]
    async fn set_attribute_value_off_posture_returns_function_not_supported() {
        let svc = Pkcs11V32Service { destructive: false };
        let resp = svc
            .c_set_attribute_value(tonic::Request::new(V32SetAttributeValueRequest {
                session_handle: 0,
                object_handle: 0,
                template: vec![],
            }))
            .await
            .expect("transport ok")
            .into_inner();
        assert_eq!(resp.ck_rv, v32::ck::CKR_FUNCTION_NOT_SUPPORTED);
    }
}
