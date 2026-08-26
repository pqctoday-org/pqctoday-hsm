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

/// Same ownership contract as `derive_mechanism_params`'s `DeriveParamBytes`
/// below (G1 gap-remediation: `docs/remoting-pkcs11-v32-gap-remediation-
/// plan-2026-08-26.md`) — a `v32::StructBuilder`'s bytes embed raw
/// pointers into its own `owned` buffers, so the builder itself, not a
/// copy of its bytes, must stay alive through the FFI call. `V32Mechanism`
/// carries `parameter` (raw bytes) and an optional `structured` oneof
/// (`gcm`/`oaep`); exactly one is meaningful per call.
enum MechParamBytes {
    Raw(Vec<u8>),
    Structured(v32::StructBuilder),
}
impl MechParamBytes {
    fn as_slice(&self) -> &[u8] {
        match self {
            MechParamBytes::Raw(v) => v,
            MechParamBytes::Structured(b) => b.as_slice(),
        }
    }
}

fn mech_parts(m: Option<&V32Mechanism>) -> (u64, MechParamBytes) {
    use pqctoday_pkcs11_remote_proto::v32_mechanism::Structured;
    let Some(m) = m else {
        // mechanism 0 matches nothing → the engine's own invalid-mechanism path
        return (0, MechParamBytes::Raw(Vec::new()));
    };
    let bytes = match &m.structured {
        None => MechParamBytes::Raw(m.parameter.clone()),
        Some(Structured::Gcm(p)) => MechParamBytes::Structured(v32::cipher_params::gcm(&p.iv, &p.aad, p.tag_bits)),
        Some(Structured::Oaep(p)) => {
            MechParamBytes::Structured(v32::cipher_params::oaep(p.hash_alg, p.mgf, &p.source_data))
        }
    };
    (m.mechanism, bytes)
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
        let ck_rv = blocking(move || v32::digest_init(req.session_handle, mech, param.as_slice())).await?;
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
            blocking(move || v32::digest(req.session_handle, mech, param.as_slice(), &req.data)).await?;
        Ok(Response::new(V32BytesResponse { ck_rv, data }))
    }

    async fn c_sign_init(
        &self,
        request: Request<V32KeyedInitRequest>,
    ) -> Result<Response<V32StatusResponse>, Status> {
        let req = request.into_inner();
        let (mech, param) = mech_parts(req.mechanism.as_ref());
        let ck_rv =
            blocking(move || v32::sign_init(req.session_handle, mech, param.as_slice(), req.key_handle)).await?;
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
            blocking(move || v32::verify_init(req.session_handle, mech, param.as_slice(), req.key_handle)).await?;
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
            blocking(move || v32::generate_key(req.session_handle, mech, param.as_slice(), &template)).await?;
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
            v32::generate_key_pair(req.session_handle, mech, param.as_slice(), &public_template, &private_template)
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
            blocking(move || v32::encrypt_init(req.session_handle, mech, param.as_slice(), req.key_handle)).await?;
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
            blocking(move || v32::decrypt_init(req.session_handle, mech, param.as_slice(), req.key_handle)).await?;
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
            v32::sign_recover_init(req.session_handle, mech, param.as_slice(), req.key_handle)
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
            v32::verify_recover_init(req.session_handle, mech, param.as_slice(), req.key_handle)
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
            v32::verify_signature_init(req.session_handle, mech, param.as_slice(), req.key_handle, &req.signature)
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
            v32::message_sign_init(req.session_handle, mech, param.as_slice(), req.key_handle)
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
            v32::message_verify_init(req.session_handle, mech, param.as_slice(), req.key_handle)
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
            v32::message_encrypt_init(req.session_handle, mech, param.as_slice(), req.key_handle)
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
            v32::message_decrypt_init(req.session_handle, mech, param.as_slice(), req.key_handle)
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

    // ── wrap / unwrap (RW4) ──────────────────────────────────────────────

    async fn c_wrap_key(&self, request: Request<V32WrapKeyRequest>) -> Result<Response<V32BytesResponse>, Status> {
        let req = request.into_inner();
        let (mech, param) = mech_parts(req.mechanism.as_ref());
        let (ck_rv, data) = blocking(move || {
            v32::wrap_key(req.session_handle, mech, param.as_slice(), req.wrapping_key_handle, req.key_handle)
        })
        .await?;
        Ok(Response::new(V32BytesResponse { ck_rv, data }))
    }
    async fn c_unwrap_key(
        &self,
        request: Request<V32UnwrapKeyRequest>,
    ) -> Result<Response<V32ObjectHandleResponse>, Status> {
        let req = request.into_inner();
        let (mech, param) = mech_parts(req.mechanism.as_ref());
        let template = tmpl_parts(&req.template);
        let (ck_rv, object_handle) = blocking(move || {
            v32::unwrap_key(req.session_handle, mech, param.as_slice(), req.unwrapping_key_handle, &req.wrapped_key, &template)
        })
        .await?;
        Ok(Response::new(V32ObjectHandleResponse { ck_rv, object_handle }))
    }
    async fn c_wrap_key_authenticated(
        &self,
        request: Request<V32WrapKeyAuthenticatedRequest>,
    ) -> Result<Response<V32BytesResponse>, Status> {
        let req = request.into_inner();
        let (mech, param) = mech_parts(req.mechanism.as_ref());
        let (ck_rv, data) = blocking(move || {
            v32::wrap_key_authenticated(
                req.session_handle, mech, param.as_slice(), req.wrapping_key_handle, req.key_handle, &req.associated_data,
            )
        })
        .await?;
        Ok(Response::new(V32BytesResponse { ck_rv, data }))
    }
    async fn c_unwrap_key_authenticated(
        &self,
        request: Request<V32UnwrapKeyAuthenticatedRequest>,
    ) -> Result<Response<V32ObjectHandleResponse>, Status> {
        let req = request.into_inner();
        let (mech, param) = mech_parts(req.mechanism.as_ref());
        let template = tmpl_parts(&req.template);
        let (ck_rv, object_handle) = blocking(move || {
            v32::unwrap_key_authenticated(
                req.session_handle, mech, param.as_slice(), req.unwrapping_key_handle, &req.wrapped_key, &template, &req.associated_data,
            )
        })
        .await?;
        Ok(Response::new(V32ObjectHandleResponse { ck_rv, object_handle }))
    }

    // ── derive (RW4) ──────────────────────────────────────────────────────

    async fn c_derive_key(
        &self,
        request: Request<V32DeriveKeyRequest>,
    ) -> Result<Response<V32ObjectHandleResponse>, Status> {
        let req = request.into_inner();
        let template = tmpl_parts(&req.template);
        let (ck_rv, object_handle) = blocking(move || {
            // `params` (either variant) must outlive the `derive_key` call
            // below — see `DeriveParamBytes`'s own doc for why an
            // extracted `Vec<u8>` copy would NOT do (it would copy the
            // outer struct's bytes, embedded pointer values included,
            // without keeping what those pointers point to alive).
            let params = derive_mechanism_params(&req.raw_parameter, req.structured);
            v32::derive_key(req.session_handle, req.mechanism, params.as_slice(), req.base_key_handle, &template)
        })
        .await?;
        Ok(Response::new(V32ObjectHandleResponse { ck_rv, object_handle }))
    }

    // ── KEM key-object form (RW5) ─────────────────────────────────────────

    async fn c_encapsulate_key(
        &self,
        request: Request<V32EncapsulateKeyRequest>,
    ) -> Result<Response<V32EncapsulateKeyResponse>, Status> {
        let req = request.into_inner();
        let (mech, param) = mech_parts(req.mechanism.as_ref());
        let template = tmpl_parts(&req.template);
        let (ck_rv, ciphertext, object_handle) = blocking(move || {
            v32::encapsulate_key(req.session_handle, mech, param.as_slice(), req.key_handle, &template)
        })
        .await?;
        Ok(Response::new(V32EncapsulateKeyResponse { ck_rv, ciphertext, object_handle }))
    }

    async fn c_decapsulate_key(
        &self,
        request: Request<V32DecapsulateKeyRequest>,
    ) -> Result<Response<V32ObjectHandleResponse>, Status> {
        let req = request.into_inner();
        let (mech, param) = mech_parts(req.mechanism.as_ref());
        let template = tmpl_parts(&req.template);
        let (ck_rv, object_handle) = blocking(move || {
            v32::decapsulate_key(req.session_handle, mech, param.as_slice(), req.private_key_handle, &req.ciphertext, &template)
        })
        .await?;
        Ok(Response::new(V32ObjectHandleResponse { ck_rv, object_handle }))
    }

    // ── RW-T coverage-ledger audit finding ───────────────────────────────

    async fn c_verify_signature_update(
        &self,
        request: Request<V32DataRequest>,
    ) -> Result<Response<V32StatusResponse>, Status> {
        let req = request.into_inner();
        let ck_rv = blocking(move || v32::verify_signature_update(req.session_handle, &req.data)).await?;
        Ok(Response::new(V32StatusResponse { ck_rv }))
    }
    async fn c_verify_signature_final(
        &self,
        request: Request<V32SessionRequest>,
    ) -> Result<Response<V32StatusResponse>, Status> {
        let req = request.into_inner();
        let ck_rv = blocking(move || v32::verify_signature_final(req.session_handle)).await?;
        Ok(Response::new(V32StatusResponse { ck_rv }))
    }
    async fn c_get_session_validation_flags(
        &self,
        request: Request<V32GetSessionValidationFlagsRequest>,
    ) -> Result<Response<V32GetSessionValidationFlagsResponse>, Status> {
        let req = request.into_inner();
        let (ck_rv, flags) = blocking(move || {
            v32::get_session_validation_flags(req.session_handle, req.validation_type)
        })
        .await?;
        Ok(Response::new(V32GetSessionValidationFlagsResponse { ck_rv, flags }))
    }

    // ── G2 (gap-remediation) — Split Key, VENDOR EXTENSION (not pkcs11f.h) ──

    async fn split_key(
        &self,
        request: Request<V32SplitKeyRequest>,
    ) -> Result<Response<V32SplitKeyResponse>, Status> {
        let req = request.into_inner();
        let (ck_rv, shares) = blocking(move || {
            v32::split_key::split(
                req.session_handle, req.secret_handle, req.parts, req.threshold, req.method, req.polynomial,
                &req.cka_id_prefix, &req.label,
            )
        })
        .await?;
        let shares = shares
            .into_iter()
            .map(|(key_part_identifier, object_handle)| V32SplitKeyShare { key_part_identifier, object_handle })
            .collect();
        Ok(Response::new(V32SplitKeyResponse { ck_rv, shares }))
    }

    async fn join_key(
        &self,
        request: Request<V32JoinKeyRequest>,
    ) -> Result<Response<V32ObjectHandleResponse>, Status> {
        let req = request.into_inner();
        let shares: Vec<(u32, u32)> = req.shares.iter().map(|s| (s.key_part_identifier, s.object_handle)).collect();
        let (ck_rv, object_handle) = blocking(move || {
            v32::split_key::join(
                req.session_handle, &shares, req.threshold, req.method, req.polynomial, req.expected_len,
                &req.cka_id, &req.label,
            )
        })
        .await?;
        Ok(Response::new(V32ObjectHandleResponse { ck_rv, object_handle }))
    }
}

use pqctoday_pkcs11_remote_proto::v32_derive_key_request::Structured;

/// Either the request's raw parameter bytes, or a live `StructBuilder`
/// from one `v32::derive_params::*` call. Never collapsed to a bare
/// `Vec<u8>`: a `StructBuilder`'s bytes embed raw pointers into its own
/// `owned` buffers (see that type's doc), so the builder itself — not
/// just its bytes — must stay alive for exactly as long as the FFI call
/// that reads them. Keeping this as a named local through that call is
/// what makes the borrow checker enforce that automatically.
enum DeriveParamBytes<'a> {
    Raw(&'a [u8]),
    Structured(v32::StructBuilder),
}
impl DeriveParamBytes<'_> {
    fn as_slice(&self) -> &[u8] {
        match self {
            DeriveParamBytes::Raw(v) => v,
            DeriveParamBytes::Structured(b) => b.as_slice(),
        }
    }
}

/// Resolves a `V32DeriveKeyRequest`'s mechanism parameter: `raw_parameter`
/// as-is when `structured` is absent, or one `v32::derive_params::*`
/// builder call per `structured` variant.
fn derive_mechanism_params(raw_parameter: &[u8], structured: Option<Structured>) -> DeriveParamBytes<'_> {
    let Some(s) = structured else { return DeriveParamBytes::Raw(raw_parameter) };
    let builder = match s {
        Structured::Ecdh1(p) => v32::derive_params::ecdh1(p.kdf, &p.shared_data, &p.public_data),
        Structured::Hkdf(p) => v32::derive_params::hkdf(
            p.extract, p.expand, p.prf_hash_mechanism, p.salt_type, &p.salt, p.h_salt_key, &p.info,
        ),
        Structured::Pbkdf2(p) => v32::derive_params::pbkd2(
            p.salt_source, &p.salt_source_data, p.iterations, p.prf, &p.prf_data, &p.password,
        ),
        Structured::Sp800108Counter(p) => {
            let segments = p.segments.into_iter().map(|s| v32::derive_params::Segment { prf_type: s.prf_type, value: s.value }).collect();
            v32::derive_params::sp800_108_counter(p.prf_type, segments)
        }
        Structured::Sp800108Feedback(p) => {
            let segments = p.segments.into_iter().map(|s| v32::derive_params::Segment { prf_type: s.prf_type, value: s.value }).collect();
            v32::derive_params::sp800_108_feedback(p.prf_type, segments, &p.iv)
        }
    };
    DeriveParamBytes::Structured(builder)
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
