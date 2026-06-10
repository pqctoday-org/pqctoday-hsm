//! KMIP 3.0 §6.1.8 **Create** operation (symmetric keys only).
//!
//! > "This operation requests the server to generate a new symmetric key
//! > or generate Secret Data as a Managed Cryptographic Object."
//!
//! Op codepoint `0x01` (verified — `Create = 0x00000001`).
//!
//! Asymmetric key generation goes through KMIP `Create Key Pair`
//! (KMIP 3.0 §6.1.11) — see [`super::create_key_pair`].
//!
//! ## Plane mapping
//!
//! - **Plane 1** — engine.evaluate with op=`"Create"` so `algorithm_default`
//!   rules can supply `AES-256` when the application omits the algorithm.
//! - **Plane 2** — allocate a fresh KMIP UID, persist a `PreActive`
//!   symmetric key record.
//! - **Plane 3** — calls `C_GenerateKey` (PKCS#11 v3.2 §C.7.1).
//!   Signature verified at `rust/src/ffi.rs::C_GenerateKey`.

use std::collections::HashMap;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::{KmipError, Result, ResultReason};
use crate::kmip30::{
    Attribute, CreateRequest, CreateResponse, KmipAlgorithm, ObjectType, PkcsOp, UsageMask,
};
use crate::policy::{Decision, PolicyRequest};
use crate::store::ObjectRecord;

use super::deps::Deps;
use super::helpers::{emit_pkcs11, emit_request, emit_success, fail_err};

pub fn create(deps: &Deps, req: CreateRequest, correlation_id: &str) -> Result<CreateResponse> {
    let started = OffsetDateTime::now_utc();
    emit_request(
        deps,
        correlation_id,
        "Create",
        format!(
            "object_type={:?} attrs={}",
            req.object_type,
            req.template_attribute.len()
        ),
    );

    // KMIP 3.0 §6.1.8 — Create is for symmetric keys + secret data.
    // Asymmetric requests must use CreateKeyPair.
    if req.object_type != ObjectType::SymmetricKey && req.object_type != ObjectType::SecretData {
        return Err(fail_err(
            deps,
            correlation_id,
            "Create",
            KmipError::invalid_attribute_value(format!(
                "Create supports SymmetricKey | SecretData only; got {:?}",
                req.object_type
            )),
        ));
    }

    let (algorithm_in, key_length, usage_mask) = extract_template(&req.template_attribute);

    // Plane-1 policy gate.
    let empty: HashMap<String, String> = HashMap::new();
    let mut p_req =
        PolicyRequest::minimal("Create", algorithm_in.as_deref(), started, correlation_id, &empty);
    p_req.key_length = key_length;
    p_req.usage_mask = usage_mask;

    let resolved = match deps.engine.evaluate(&p_req) {
        Decision::Allow { algorithm_override, .. } => match algorithm_override.or(algorithm_in) {
            Some(a) => a,
            None => {
                return Err(fail_err(
                    deps,
                    correlation_id,
                    "Create",
                    KmipError::missing_data(
                        "no CryptographicAlgorithm in template and policy supplied no default",
                    ),
                ));
            }
        },
        Decision::Deny { human, .. } => {
            return Err(fail_err(
                deps,
                correlation_id,
                "Create",
                KmipError::permission_denied(human),
            ));
        }
        Decision::RekeyAndProceed { .. } => {
            return Err(fail_err(
                deps,
                correlation_id,
                "Create",
                KmipError::internal("RekeyAndProceed returned for Create"),
            ));
        }
    };

    let algo = parse_sym_algorithm(&resolved)?;

    // KMIP 3.0 §11 — reject `QuantumSafe=true` claims on non-PQC
    // algorithms. QS-M-2 pins this with AES + QuantumSafe=true →
    // `GeneralFailure` "NOT_SAFE".
    {
        let x = super::register_import_export::extract_attrs(&req.template_attribute);
        if matches!(x.quantum_safe, Some(true))
            && !super::register_import_export::algorithm_is_quantum_safe(algo)
        {
            return Err(fail_err(
                deps,
                correlation_id,
                "Create",
                KmipError::failed(
                    ResultReason::GeneralFailure,
                    format!("QuantumSafe=true claimed for non-PQC algorithm {algo:?}"),
                ),
            ));
        }
    }

    // Plane-3: emit (Phase 7 wires the real C_GenerateKey call).
    let mech = algo.to_pkcs11_mech(PkcsOp::KeyGen).ok_or_else(|| {
        KmipError::failed(
            ResultReason::OperationNotSupported,
            format!("symmetric algorithm {resolved} has no KeyGen mechanism"),
        )
    })?;
    emit_pkcs11(
        deps,
        correlation_id,
        "C_GenerateKey",
        Some(mech),
        0,
        "CKR_OK",
    );

    // Phase 7b: real bridge call when a session is wired.
    let cka_id_bytes = Uuid::new_v4().as_bytes().to_vec();
    if let Some(session) = deps.engine_session {
        let result = match algo {
            KmipAlgorithm::Aes => {
                let bits = key_length.unwrap_or(256);
                softhsmrustv3::native::generate_aes_key(session, bits, &cka_id_bytes, "kmip-aes")
            }
            KmipAlgorithm::HmacSha256 | KmipAlgorithm::HmacSha384 | KmipAlgorithm::HmacSha512 => {
                let bits = key_length.unwrap_or(256);
                softhsmrustv3::native::generate_generic_secret(
                    session,
                    bits,
                    &cka_id_bytes,
                    "kmip-hmac",
                )
            }
            _ => {
                return Err(fail_err(
                    deps,
                    correlation_id,
                    "Create",
                    KmipError::failed(
                        ResultReason::OperationNotSupported,
                        format!("Create: {:?} not supported by native API", algo),
                    ),
                ));
            }
        };
        if let Err(rv) = result {
            return Err(fail_err(
                deps,
                correlation_id,
                "Create",
                super::helpers::ck_rv_to_kmip_error(rv, "Create"),
            ));
        }
    }

    // Plane-2: persist. Lift `Name` + date attributes out of the
    // template. KMIP 3.0 Spec §3.x lifecycle FSM means a past
    // ActivationDate sets the object to Active immediately — see
    // `register_import_export::compute_initial_state`.
    let uid = format!("urn:pqctoday:obj:{}", Uuid::new_v4());
    let now = OffsetDateTime::now_utc();
    let x = super::register_import_export::extract_attrs(&req.template_attribute);
    let initial_state = super::register_import_export::compute_initial_state(now, &x);
    let cp = x.cryptographic_parameters.clone();
    deps.store.put(ObjectRecord {
        uid: uid.clone(),
        object_type: req.object_type,
        algorithm: algo,
        cryptographic_length: key_length.unwrap_or(0),
        usage_mask: usage_mask.unwrap_or_else(UsageMask::empty),
        state: initial_state,
        pkcs11_cka_id: cka_id_bytes,
        pkcs11_slot: deps.config.pkcs11_slot,
        initial_date: now,
        activation_date: x.activation_date,
        deactivation_date: x.deactivation_date,
        compromise_date: x.compromise_date,
        compromise_occurrence_date: x.compromise_date,
        last_change_date: Some(now),
        original_creation_date: Some(now),
        cryptographic_parameters: cp,
        supersedes: None,
        name: x.name.clone(),
        links: std::collections::HashMap::new(),
        custom_attributes: std::collections::HashMap::new(),

        key_material: None,

        key_format_type: None,
        // KMIP §11 Fresh = True for server-generated objects.
        fresh: Some(true),
    ..ObjectRecord::default()
})?;

    emit_success(deps, correlation_id, "Create");

    Ok(CreateResponse {
        object_type: req.object_type,
        uid,
    })
}

fn extract_template(attrs: &[Attribute]) -> (Option<String>, Option<u32>, Option<UsageMask>) {
    let mut algorithm: Option<String> = None;
    let mut length: Option<u32> = None;
    let mut usage: Option<UsageMask> = None;
    for a in attrs {
        match a {
            Attribute::CryptographicAlgorithm(alg) => {
                algorithm = Some(super::helpers::canonical_name(*alg));
            }
            Attribute::CryptographicLength(n) => length = Some(*n as u32),
            Attribute::CryptographicUsageMask(m) => usage = Some(*m),
            _ => {}
        }
    }
    (algorithm, length, usage)
}

/// Symmetric-only algorithm parse. AES + HMAC variants accepted; asymmetric
/// names are rejected (caller must use CreateKeyPair).
fn parse_sym_algorithm(s: &str) -> Result<KmipAlgorithm> {
    use KmipAlgorithm::*;
    let base = s.split('-').next().unwrap_or(s);
    Ok(match s {
        "HMAC-SHA-256" => HmacSha256,
        "HMAC-SHA-384" => HmacSha384,
        "HMAC-SHA-512" => HmacSha512,
        _ => match base {
            "AES" => Aes,
            _ => {
                return Err(KmipError::invalid_attribute_value(format!(
                    "Create: {s:?} is not a symmetric algorithm (use CreateKeyPair for asymmetric)"
                )))
            }
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auditlog::{AuditSink, RingSink};
    use crate::policy::{load_from_str, Engine};
    use crate::store::MemoryStore;
    use std::sync::Arc;

    fn deps_with(yaml: &str) -> Deps {
        let ring = Arc::new(RingSink::new(64));
        let sink: Arc<dyn AuditSink> = ring.clone();
        let engine = Engine::with_global_sink(sink.clone());
        engine.activate(load_from_str(yaml, std::path::Path::new("<t>")).unwrap()).unwrap();
        Deps::new(engine, Arc::new(MemoryStore::new()), sink, super::super::deps::DepsConfig::default())
    }

    const AES_DEFAULT: &str = r#"
schema_version: 1
metadata: { name: t, description: t, authority: t, effective: always }
rules:
  - type: algorithm_default
    ops: [Create]
    default_algorithm: AES-256
    reason: "AES-256 default"
"#;

    #[test]
    fn create_symmetric_with_policy_default() {
        let d = deps_with(AES_DEFAULT);
        let resp = create(&d, CreateRequest {
            object_type: ObjectType::SymmetricKey,
            template_attribute: vec![],
        }, "c").unwrap();
        let rec = d.store.get(&resp.uid).unwrap().unwrap();
        assert_eq!(rec.algorithm, KmipAlgorithm::Aes);
        assert_eq!(rec.object_type, ObjectType::SymmetricKey);
        assert_eq!(rec.state, crate::kmip30::State::PreActive);
    }

    #[test]
    fn create_rejects_asymmetric_object_type() {
        let d = deps_with(AES_DEFAULT);
        let err = create(&d, CreateRequest {
            object_type: ObjectType::PrivateKey,
            template_attribute: vec![],
        }, "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::InvalidAttributeValue);
    }

    #[test]
    fn create_rejects_asymmetric_algorithm() {
        let d = deps_with(AES_DEFAULT);
        let err = create(&d, CreateRequest {
            object_type: ObjectType::SymmetricKey,
            template_attribute: vec![Attribute::CryptographicAlgorithm(KmipAlgorithm::MlDsa87)],
        }, "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::InvalidAttributeValue);
    }

    #[test]
    fn create_hmac_explicit() {
        let d = deps_with("schema_version: 1\nmetadata: {name: t, description: t, authority: t, effective: always}\nrules: []\n");
        let resp = create(&d, CreateRequest {
            object_type: ObjectType::SymmetricKey,
            template_attribute: vec![
                Attribute::CryptographicAlgorithm(KmipAlgorithm::HmacSha256),
            ],
        }, "c").unwrap();
        let rec = d.store.get(&resp.uid).unwrap().unwrap();
        assert_eq!(rec.algorithm, KmipAlgorithm::HmacSha256);
    }
}
