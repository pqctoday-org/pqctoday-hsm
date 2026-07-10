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

use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::{KmipError, Result, ResultReason};
use crate::kmip30::{
    Attribute, CreateRequest, CreateResponse, KmipAlgorithm, ObjectType, PkcsOp, UsageMask,
};
use crate::policy::{Decision, PolicyRequest};
use crate::store::ObjectRecord;

use super::deps::Deps;
use super::helpers::{emit_request, emit_success, fail_err};

pub fn create(deps: &Deps, mut req: CreateRequest, correlation_id: &str) -> Result<CreateResponse> {
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

    // K19 — KMIP 3.0 §6.1.58 Set Defaults: fill attributes the client
    // omitted from the stored per-Object-Type defaults. Merge order:
    // client template > Set Defaults > the hardcoded fallbacks below
    // (policy algorithm_default, usage-mask default, …).
    super::allocation_and_config::apply_object_defaults(
        deps,
        req.object_type,
        &[],
        &mut req.template_attribute,
    );

    let (algorithm_in, key_length, usage_mask) = extract_template(&req.template_attribute);

    // Plane-1 policy gate. Y1: surface the request's custom attributes so
    // `require_custom_attribute` can actually see the classification tag.
    // Y3: qualify the bare algorithm name ("AES" → "AES-256") so size-specific
    // allow/deny rules match.
    let custom_attrs = super::helpers::custom_attrs_from(&req.template_attribute);
    let qualified_algo = algorithm_in
        .as_deref()
        .map(|a| super::helpers::qualify_algorithm_str(a, key_length));
    let mut p_req = PolicyRequest::minimal(
        "Create",
        qualified_algo.as_deref(),
        started,
        correlation_id,
        &custom_attrs,
    );
    p_req.key_length = key_length;
    p_req.usage_mask = usage_mask;
    // Label-pattern rules (`name_pattern`) match on the template's Name — the
    // label-only agility contract where the policy maps key classes to algos.
    let template_name = req.template_attribute.iter().find_map(|a| match a {
        crate::kmip30::Attribute::Name(n) => Some(n.as_str()),
        _ => None,
    });
    p_req.name = template_name;

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

    // The resolved string carries the policy's size choice ("AES-128" from a
    // name-patterned default); a label-only template has no length attribute,
    // so derive it — otherwise the generated key silently ignores the policy.
    let key_length = key_length.or_else(|| super::helpers::classical_length_from_name(&resolved));

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

    let mech = algo.to_pkcs11_mech(PkcsOp::KeyGen).ok_or_else(|| {
        KmipError::failed(
            ResultReason::OperationNotSupported,
            format!("symmetric algorithm {resolved} has no KeyGen mechanism"),
        )
    })?;

    // Plane-3: real bridge call when a session is wired. K15 — the
    // audit record is emitted after the generate call with its real rv.
    let cka_id_bytes = Uuid::new_v4().as_bytes().to_vec();
    let digest_value = engine_generate_symmetric(
        deps,
        correlation_id,
        "Create",
        algo,
        key_length,
        mech,
        &cka_id_bytes,
        usage_mask.unwrap_or_else(UsageMask::empty),
    )
    .map_err(|e| fail_err(deps, correlation_id, "Create", e))?;

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
        // Y1 — persist the request's custom attributes so use-time gates read
        // the classification tag off the stored symmetric key.
        custom_attributes: super::helpers::raw_custom_attrs(&req.template_attribute),
        object_groups: x.object_groups.clone(),

        key_material: None,

        key_format_type: None,
        digest_value,
        // KMIP §11 Fresh = True for server-generated objects.
        fresh: Some(true),
        application_specific_information: x.application_specific_information.clone(),
    ..ObjectRecord::default()
})?;

    emit_success(deps, correlation_id, "Create");

    Ok(CreateResponse {
        object_type: req.object_type,
        uid,
    })
}

/// Plane-3 symmetric keygen shared by Create (§6.1.8) and Re-key
/// (§6.1.51, K21). Generates the key inside the engine when a session
/// is wired (AES → `native::generate_aes_key`, HMAC →
/// `native::generate_generic_secret`) and returns the K-14 engine-
/// computed SHA-256 `Digest` over the fresh `CKA_VALUE`; without a
/// session it audits the soft placeholder path and returns `None`
/// (unit-test store record only). K15 — the `Pkcs11Call` audit record
/// is emitted after the native call with its real rv; `op` names the
/// calling KMIP operation in the error mapping.
pub(crate) fn engine_generate_symmetric(
    deps: &Deps,
    correlation_id: &str,
    op: &str,
    algo: KmipAlgorithm,
    key_length: Option<u32>,
    mech: u32,
    cka_id_bytes: &[u8],
    usage_mask: UsageMask,
) -> Result<Option<Vec<u8>>> {
    let mut digest_value: Option<Vec<u8>> = None;
    if let Some(session) = deps.engine_session {
        let (native_fn, result) = match algo {
            KmipAlgorithm::Aes => {
                let bits = key_length.unwrap_or(256);
                (
                    "native::generate_aes_key",
                    softhsmrustv3::native::generate_aes_key(
                        session,
                        bits,
                        cka_id_bytes,
                        "kmip-aes",
                    ),
                )
            }
            KmipAlgorithm::HmacSha256 | KmipAlgorithm::HmacSha384 | KmipAlgorithm::HmacSha512 => {
                let bits = key_length.unwrap_or(256);
                (
                    "native::generate_generic_secret",
                    softhsmrustv3::native::generate_generic_secret(
                        session,
                        bits,
                        cka_id_bytes,
                        "kmip-hmac",
                    ),
                )
            }
            _ => {
                return Err(KmipError::failed(
                    ResultReason::OperationNotSupported,
                    format!("{op}: {:?} not supported by native API", algo),
                ));
            }
        };
        super::helpers::emit_pkcs11_result(deps, correlation_id, native_fn, Some(mech), &result);
        match result {
            Ok(handle) => {
                digest_value = softhsmrustv3::native::get_value_digest_sha256(session, handle);
                // PKCS#11 v3.2 §4.8 Table 13 — restrict the engine key to the
                // mechanisms its KMIP usage mask implies, closing the
                // raw-PKCS#11 bypass. Best-effort: an empty list (no usage
                // bits set) means nothing to write, and a set_attribute
                // failure here doesn't unwind an already-created key —
                // logged via emit_pkcs11 same as any other bridge call.
                let mechs = algo.usage_mask_to_allowed_mechanisms(usage_mask);
                if !mechs.is_empty() {
                    let packed: Vec<u8> = mechs.iter().flat_map(|m| m.to_le_bytes()).collect();
                    let r = softhsmrustv3::native::set_attribute(
                        session,
                        handle,
                        softhsmrustv3::constants::CKA_ALLOWED_MECHANISMS,
                        packed,
                    );
                    super::helpers::emit_pkcs11_result(
                        deps,
                        correlation_id,
                        "native::set_attribute(CKA_ALLOWED_MECHANISMS)",
                        None,
                        &r,
                    );
                }
            }
            Err(rv) => {
                return Err(super::helpers::ck_rv_to_kmip_error(rv, op));
            }
        }
    } else {
        // S-2 hardening: NO engine session ⇒ no key material was generated.
        // Production (any non-test build, incl. the server bin and the wasm
        // bundle) MUST fail rather than persist a keyless phantom record and
        // return success. The store-only soft path survives only for the
        // crate's own unit tests, which don't bootstrap an engine. Matches the
        // fail-closed guard on Sign/Decrypt/Encapsulate.
        #[cfg(not(test))]
        {
            return Err(KmipError::failed(
                ResultReason::CryptographicFailure,
                "no engine session — cannot generate key material",
            ));
        }
        #[cfg(test)]
        {
            super::helpers::emit_pkcs11(deps, correlation_id, "soft::placeholder_generate_key", Some(mech), 0, "CKR_OK");
        }
    }
    Ok(digest_value)
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

    /// PKCS#11 v3.2 §4.8 Table 13 — Create on a symmetric key with
    /// UsageMask=ENCRYPT|DECRYPT auto-restricts the engine object's
    /// CKA_ALLOWED_MECHANISMS to CKM_AES_GCM (the only mechanism
    /// `to_pkcs11_mech(Aes, Encrypt|Decrypt)` resolves to). Verified two
    /// ways: the raw attribute bytes on the engine handle, AND that the
    /// restriction is actually enforced (CKM_AES_ECB now fails at the
    /// engine with CKR_MECHANISM_INVALID even though AES-ECB is otherwise
    /// a perfectly valid mechanism for an AES key).
    #[test]
    fn create_symmetric_auto_restricts_engine_key_from_usage_mask() {
        use softhsmrustv3::constants as c;
        use softhsmrustv3::native::session;
        let _guard_reset = session::finalize();
        session::init().expect("engine init");
        let sess = session::bootstrap_default_token(0, "so-pin", "user-pin", "create-restrict-test")
            .expect("bootstrap session");

        let d = deps_with("schema_version: 1\nmetadata: {name: t, description: t, authority: t, effective: always}\nrules: []\n")
            .with_engine_session(sess);

        let resp = create(&d, CreateRequest {
            object_type: ObjectType::SymmetricKey,
            template_attribute: vec![
                Attribute::CryptographicAlgorithm(KmipAlgorithm::Aes),
                Attribute::CryptographicLength(256),
                Attribute::CryptographicUsageMask(UsageMask::ENCRYPT | UsageMask::DECRYPT),
            ],
        }, "c").unwrap();
        let rec = d.store.get(&resp.uid).unwrap().unwrap();

        let handle =
            crate::ops::helpers::find_handle_for_object(sess, &rec.pkcs11_cka_id, rec.object_type)
                .expect("lookup ok")
                .expect("engine handle exists");

        let allowed = softhsmrustv3::native::get_attribute(sess, handle, c::CKA_ALLOWED_MECHANISMS)
            .expect("CKA_ALLOWED_MECHANISMS was set by Create");
        assert_eq!(allowed, c::CKM_AES_GCM.to_le_bytes().to_vec());

        // Enforcement, not just presence: AES-ECB is a real mechanism for
        // an AES key, but it isn't in this key's allowed list.
        let err = softhsmrustv3::native::encrypt(sess, handle, c::CKM_AES_ECB, b"0123456789012345", None)
            .unwrap_err();
        assert_eq!(err, c::CKR_MECHANISM_INVALID);
        // The mechanism the usage mask DID imply still works.
        let iv = [0u8; 12];
        assert!(softhsmrustv3::native::encrypt(sess, handle, c::CKM_AES_GCM, b"hi", Some(&iv)).is_ok());

        let _ = session::finalize();
    }
}
