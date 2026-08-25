use pqctoday_pkcs11_remote_core::{verbs, Algorithm as CoreAlgorithm};
use pqctoday_pkcs11_remote_proto::pkcs11_remote_server::Pkcs11Remote;
use pqctoday_pkcs11_remote_proto::*;
use tonic::{Request, Response, Status};

use crate::error::to_status;

#[derive(Default)]
pub struct Pkcs11RemoteService;

fn to_core_algo(a: i32) -> Result<CoreAlgorithm, Status> {
    match Algorithm::try_from(a) {
        Ok(Algorithm::Ed25519) => Ok(CoreAlgorithm::Ed25519),
        Ok(Algorithm::MlDsa44) => Ok(CoreAlgorithm::MlDsa44),
        Ok(Algorithm::MlDsa65) => Ok(CoreAlgorithm::MlDsa65),
        Ok(Algorithm::MlDsa87) => Ok(CoreAlgorithm::MlDsa87),
        Ok(Algorithm::MlKem512) => Ok(CoreAlgorithm::MlKem512),
        Ok(Algorithm::MlKem768) => Ok(CoreAlgorithm::MlKem768),
        Ok(Algorithm::MlKem1024) => Ok(CoreAlgorithm::MlKem1024),
        _ => Err(Status::invalid_argument("unspecified or unknown Algorithm")),
    }
}

#[tonic::async_trait]
impl Pkcs11Remote for Pkcs11RemoteService {
    async fn health(&self, _request: Request<HealthRequest>) -> Result<Response<HealthResponse>, Status> {
        let info = verbs::health();
        Ok(Response::new(HealthResponse {
            ok: info.ok,
            engine_version: info.remoting_core_version.to_string(),
        }))
    }

    async fn open_session(
        &self,
        request: Request<OpenSessionRequest>,
    ) -> Result<Response<OpenSessionResponse>, Status> {
        let req = request.into_inner();
        let handle = verbs::open_session(&req.user_pin).map_err(to_status)?;
        Ok(Response::new(OpenSessionResponse { session_handle: handle }))
    }

    async fn close_session(
        &self,
        request: Request<CloseSessionRequest>,
    ) -> Result<Response<CloseSessionResponse>, Status> {
        let req = request.into_inner();
        verbs::close_session(req.session_handle).map_err(to_status)?;
        Ok(Response::new(CloseSessionResponse {}))
    }

    async fn generate_key_pair(
        &self,
        request: Request<GenerateKeyPairRequest>,
    ) -> Result<Response<GenerateKeyPairResponse>, Status> {
        let req = request.into_inner();
        let algo = to_core_algo(req.algorithm)?;
        let (pub_h, prv_h) =
            verbs::generate_key_pair(req.session_handle, algo, &req.cka_id, &req.label).map_err(to_status)?;
        Ok(Response::new(GenerateKeyPairResponse { public_handle: pub_h, private_handle: prv_h }))
    }

    async fn sign(&self, request: Request<SignRequest>) -> Result<Response<SignResponse>, Status> {
        let req = request.into_inner();
        let algo = to_core_algo(req.algorithm)?;
        let sig = verbs::sign(req.session_handle, req.private_handle, algo, &req.data).map_err(to_status)?;
        Ok(Response::new(SignResponse { signature: sig }))
    }

    async fn verify(&self, request: Request<VerifyRequest>) -> Result<Response<VerifyResponse>, Status> {
        let req = request.into_inner();
        let algo = to_core_algo(req.algorithm)?;
        let valid = verbs::verify(req.session_handle, req.public_handle, algo, &req.data, &req.signature)
            .map_err(to_status)?;
        Ok(Response::new(VerifyResponse { valid }))
    }

    async fn encapsulate(
        &self,
        request: Request<EncapsulateRequest>,
    ) -> Result<Response<EncapsulateResponse>, Status> {
        let req = request.into_inner();
        let algo = to_core_algo(req.algorithm)?;
        let (ct, ss) = verbs::encapsulate(req.session_handle, req.public_handle, algo).map_err(to_status)?;
        Ok(Response::new(EncapsulateResponse { ciphertext: ct, shared_secret: ss }))
    }

    async fn decapsulate(
        &self,
        request: Request<DecapsulateRequest>,
    ) -> Result<Response<DecapsulateResponse>, Status> {
        let req = request.into_inner();
        let algo = to_core_algo(req.algorithm)?;
        let ss =
            verbs::decapsulate(req.session_handle, req.private_handle, algo, &req.ciphertext).map_err(to_status)?;
        Ok(Response::new(DecapsulateResponse { shared_secret: ss }))
    }
}
