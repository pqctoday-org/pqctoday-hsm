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
