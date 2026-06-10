//! KMIP 3.0 §6.1.11 **Create Key Pair** operation.
//!
//! > "This operation requests the server to generate a new public/private
//! > key pair and register the two corresponding new Managed Cryptographic
//! > Object instances."
//!
//! Op codepoint `0x02` (verified against KMIP 3.0 `Operation` enum
//! extract — `Create Key Pair = 0x00000002`).
//!
//! ## Plane mapping
//!
//! - **Plane 1** — engine.evaluate with op canonicalised by the caller
//!   (e.g. `"CreateKeyPair:Sign"`) so policy `algorithm_default` /
//!   `algorithm_substitution` rules can fire per-purpose. The engine's
//!   [`Decision::Allow { algorithm_override }`] tells us what algorithm
//!   to actually use; [`Decision::RekeyAndProceed`] is rejected here
//!   because there is no pre-existing object to rekey at create-time.
//! - **Plane 2** — allocate a fresh KMIP `Unique Identifier`, store the
//!   record with `State = PreActive` (KMIP 3.0 §3.x lifecycle FSM).
//! - **Plane 3** — would call `C_GenerateKeyPair`
//!   (PKCS#11 v3.2 §C.7.1; signature verified against
//!   `rust/src/ffi.rs::C_GenerateKeyPair`) with the mechanism returned by
//!   [`KmipAlgorithm::to_pkcs11_mech`]. v0.1 produces deterministic
//!   placeholder `CKA_ID`s — Phase 7 will wire the real session call.

use std::collections::HashMap;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::auditlog::{AuditEvent, EventPayload, KmipOpResult, Plane};
use crate::error::{KmipError, Result, ResultReason};
use crate::kmip30::{
    Attribute, CreateKeyPairRequest, CreateKeyPairResponse, KmipAlgorithm, ObjectType, PkcsOp,
    State, UsageMask,
};
use crate::policy::{Decision, PolicyRequest};
use crate::store::ObjectRecord;

use super::deps::Deps;

/// Handle a `CreateKeyPair` request. `op_canonical` is the dispatcher-
/// supplied op string (`"CreateKeyPair:Sign"` / `"CreateKeyPair:Encrypt"`
/// / `"CreateKeyPair:KeyAgreement"`) — see `policies/README.md` for the
/// canonicalisation convention.
pub fn create_key_pair(
    deps: &Deps,
    req: CreateKeyPairRequest,
    op_canonical: &str,
    correlation_id: &str,
) -> Result<CreateKeyPairResponse> {
    let started = OffsetDateTime::now_utc();
    deps.sink.emit(AuditEvent::at(
        started,
        Plane::Kmip,
        correlation_id,
        EventPayload::KmipRequestReceived {
            op: op_canonical.into(),
            request_summary: format!(
                "common={} priv={} pub={}",
                req.common_attributes.len(),
                req.private_key_attributes.len(),
                req.public_key_attributes.len(),
            ),
            client_cn: None,
        },
    ));

    // KMIP 3.0 Spec §6.1.10 CreateKeyPair — three distinct attribute
    // baskets: `CommonAttributes` is merged into BOTH halves;
    // `PrivateKeyAttributes` applies only to the private record;
    // `PublicKeyAttributes` only to the public record. The previous
    // implementation flattened all three lists with `.chain()` so a
    // private-half `<CryptographicUsageMask value="Sign"/>` collided
    // with the public-half `<CryptographicUsageMask value="Verify"/>`
    // — last write won, both halves received the same mask. AKLC-M-*
    // / SKLC-M-* exercised that collision.
    let priv_attrs: Vec<Attribute> = req
        .common_attributes
        .iter()
        .chain(req.private_key_attributes.iter())
        .cloned()
        .collect();
    let pub_attrs: Vec<Attribute> = req
        .common_attributes
        .iter()
        .chain(req.public_key_attributes.iter())
        .cloned()
        .collect();
    let priv_x = super::register_import_export::extract_attrs(&priv_attrs);
    let pub_x = super::register_import_export::extract_attrs(&pub_attrs);

    // Algorithm + length should be the same on both halves (carried in
    // CommonAttributes per the spec; private/public mismatch would be
    // a client bug). Pull from whichever side has it first.
    let (algorithm_in, key_length, usage_mask) = extract_template(&req);
    let _ = (priv_x.algorithm, pub_x.algorithm); // silence unused; merged via extract_template

    // ── Plane 1: policy gate ────────────────────────────────────────────
    let empty_attrs: HashMap<String, String> = HashMap::new();
    let mut p_req = PolicyRequest::minimal(
        op_canonical,
        algorithm_in.as_deref(),
        started,
        correlation_id,
        &empty_attrs,
    );
    p_req.key_length = key_length;
    p_req.usage_mask = usage_mask;

    let resolved_algorithm = match deps.engine.evaluate(&p_req) {
        Decision::Allow { algorithm_override, .. } => match algorithm_override.or(algorithm_in) {
            Some(a) => a,
            None => {
                return fail(
                    deps,
                    correlation_id,
                    op_canonical,
                    KmipError::missing_data(
                        "no CryptographicAlgorithm in template and policy supplied no default",
                    ),
                );
            }
        },
        Decision::Deny { human, .. } => {
            return fail(
                deps,
                correlation_id,
                op_canonical,
                KmipError::permission_denied(human),
            );
        }
        Decision::RekeyAndProceed { .. } => {
            // RekeyAndProceed only makes sense for ops that target an
            // existing object. CreateKeyPair allocates a fresh handle —
            // we should never reach this branch.
            return fail(
                deps,
                correlation_id,
                op_canonical,
                KmipError::internal("RekeyAndProceed returned for CreateKeyPair"),
            );
        }
    };

    let kmip_algo = parse_algorithm(&resolved_algorithm)?;

    // ── Plane 3: would call C_GenerateKeyPair ───────────────────────────
    // PKCS#11 v3.2 §C.7.1 — signature in pkcs11f.h:
    //   C_GenerateKeyPair(hSession, pMechanism,
    //                     pPublicKeyTemplate, ulPublicKeyAttributeCount,
    //                     pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
    //                     phPublicKey, phPrivateKey)
    // softhsmrustv3 export verified at rust/src/ffi.rs::C_GenerateKeyPair.
    let mech = kmip_algo.to_pkcs11_mech(PkcsOp::KeyGen).ok_or_else(|| {
        KmipError::failed(
            ResultReason::OperationNotSupported,
            format!("algorithm {resolved_algorithm} has no KeyGen mechanism"),
        )
    })?;

    // Phase 7b: real bridge call when a session is wired. Falls back to
    // placeholder UUIDs for unit tests.
    let mech_name = format!("CKM_0x{mech:04X}");
    let (pkcs11_cka_id_priv, pkcs11_cka_id_pub) = if let Some(session) = deps.engine_session {
        // Both halves of the keypair share the same CKA_ID so
        // `find_by_cka_id` recovers both handles for subsequent ops.
        let cka_id = Uuid::new_v4().as_bytes().to_vec();
        match native_generate_keypair(session, kmip_algo, &cka_id) {
            Ok(()) => (cka_id.clone(), cka_id),
            Err(err) => return fail(deps, correlation_id, op_canonical, err),
        }
    } else {
        // Unit-test fallback — UUIDs as before, no real keys generated.
        (
            Uuid::new_v4().as_bytes().to_vec(),
            Uuid::new_v4().as_bytes().to_vec(),
        )
    };

    deps.sink.emit(AuditEvent::at(
        OffsetDateTime::now_utc(),
        Plane::Pkcs11,
        correlation_id,
        EventPayload::Pkcs11Call {
            function: "C_GenerateKeyPair".into(),
            mechanism: Some(mech_name),
            slot: Some(deps.config.pkcs11_slot),
            session: None,
            rv: 0, // placeholder until Phase 7 wires the real call
            rv_name: "CKR_OK".into(),
            latency_ms: 0,
        },
    ));

    // ── Plane 2: allocate UIDs + store records ──────────────────────────
    let priv_uid = format!("urn:pqctoday:obj:{}", Uuid::new_v4());
    let pub_uid = format!("urn:pqctoday:obj:{}", Uuid::new_v4());

    let now = OffsetDateTime::now_utc();
    let priv_usage = priv_x.usage.unwrap_or_else(UsageMask::empty);
    let pub_usage = pub_x.usage.unwrap_or_else(UsageMask::empty);
    let priv_state = super::register_import_export::compute_initial_state(now, &priv_x);
    let pub_state = super::register_import_export::compute_initial_state(now, &pub_x);
    let _ = (usage_mask, key_length); // silence unused warnings
    deps.store.put(ObjectRecord {
        uid: priv_uid.clone(),
        object_type: ObjectType::PrivateKey,
        algorithm: kmip_algo,
        cryptographic_length: priv_x.length.unwrap_or(0),
        usage_mask: priv_usage,
        state: priv_state,
        pkcs11_cka_id: pkcs11_cka_id_priv,
        pkcs11_slot: deps.config.pkcs11_slot,
        initial_date: now,
        activation_date: priv_x.activation_date,
        deactivation_date: priv_x.deactivation_date,
        compromise_date: priv_x.compromise_date,
        compromise_occurrence_date: priv_x.compromise_date,
        last_change_date: Some(now),
        original_creation_date: Some(now),
        supersedes: None,
            name: priv_x.name.clone(),

            // KMIP §11 `Public Key Link` — UID of the matching
            // public-key half on the private record (AKLC-O-1
            // step #3 reads it back via GetAttributes).
            links: {
                let mut m = std::collections::HashMap::new();
                m.insert("PublicKeyLink".to_string(), pub_uid.clone());
                m
            },

            custom_attributes: std::collections::HashMap::new(),


            key_material: None,


            // KMIP 3.0 §6.2 — default `KeyFormatType` depends on algo.
            // For RSA the OASIS Baseline test corpus expects PKCS#1
            // (codepoint 0x03) on both halves of a CreateKeyPair-
            // generated keypair.
            key_format_type: match kmip_algo {
                crate::kmip30::KmipAlgorithm::Rsa => Some(0x03),
                _ => None,
            },
            // KMIP §11 Fresh = True for server-generated objects.
            fresh: Some(true),
    ..ObjectRecord::default()
})?;
    deps.store.put(ObjectRecord {
        uid: pub_uid.clone(),
        object_type: ObjectType::PublicKey,
        algorithm: kmip_algo,
        cryptographic_length: pub_x.length.unwrap_or(0),
        usage_mask: pub_usage,
        state: pub_state,
        pkcs11_cka_id: pkcs11_cka_id_pub,
        pkcs11_slot: deps.config.pkcs11_slot,
        initial_date: now,
        activation_date: pub_x.activation_date,
        deactivation_date: pub_x.deactivation_date,
        compromise_date: pub_x.compromise_date,
        compromise_occurrence_date: pub_x.compromise_date,
        last_change_date: Some(now),
        original_creation_date: Some(now),
        supersedes: None,
            name: pub_x.name.clone(),

            // KMIP §11 `Private Key Link` — UID of the matching
            // private-key half on the public record.
            links: {
                let mut m = std::collections::HashMap::new();
                m.insert("PrivateKeyLink".to_string(), priv_uid.clone());
                m
            },

            custom_attributes: std::collections::HashMap::new(),


            key_material: None,


            // KMIP 3.0 §6.2 — default `KeyFormatType` depends on algo.
            // For RSA the OASIS Baseline test corpus expects PKCS#1
            // (codepoint 0x03) on both halves of a CreateKeyPair-
            // generated keypair.
            key_format_type: match kmip_algo {
                crate::kmip30::KmipAlgorithm::Rsa => Some(0x03),
                _ => None,
            },
            // KMIP §11 Fresh = True for server-generated objects.
            fresh: Some(true),
    ..ObjectRecord::default()
})?;

    deps.sink.emit(AuditEvent::at(
        OffsetDateTime::now_utc(),
        Plane::Kmip,
        correlation_id,
        EventPayload::KmipResponseSent {
            op: op_canonical.into(),
            result: KmipOpResult::Success,
            latency_ms: 0,
        },
    ));

    Ok(CreateKeyPairResponse {
        private_key_uid: priv_uid,
        public_key_uid: pub_uid,
    })
}

/// Pull (algorithm, length, usage) out of the merged template attributes.
/// KMIP 3.0 §4.x — `CryptographicAlgorithm`, `CryptographicLength`, and
/// `CryptographicUsageMask` are the three attributes the dispatcher
/// canonicalises for the engine.
fn extract_template(req: &CreateKeyPairRequest) -> (Option<String>, Option<u32>, Option<UsageMask>) {
    let mut algorithm: Option<String> = None;
    let mut length: Option<u32> = None;
    let mut usage: Option<UsageMask> = None;
    for a in req
        .common_attributes
        .iter()
        .chain(req.private_key_attributes.iter())
        .chain(req.public_key_attributes.iter())
    {
        match a {
            Attribute::CryptographicAlgorithm(alg) => {
                algorithm = Some(canonical_name(*alg));
            }
            Attribute::CryptographicLength(n) => {
                length = Some(*n as u32);
            }
            Attribute::CryptographicUsageMask(m) => {
                usage = Some(*m);
            }
            _ => {}
        }
    }
    (algorithm, length, usage)
}

/// Canonical algorithm string used by the policy engine. Mirrors the
/// `KmipAlgorithm` enum variant names in `policies/*.yaml`.
fn canonical_name(a: KmipAlgorithm) -> String {
    use KmipAlgorithm::*;
    match a {
        Aes        => "AES",
        Rsa        => "RSA",
        Ecdsa      => "ECDSA",
        HmacSha256 => "HMAC-SHA-256",
        HmacSha384 => "HMAC-SHA-384",
        HmacSha512 => "HMAC-SHA-512",
        Ecdh       => "ECDH",
        ChaCha20         => "ChaCha20",
        ChaCha20Poly1305 => "ChaCha20-Poly1305",
        MlKem512   => "ML-KEM-512",
        MlKem768   => "ML-KEM-768",
        MlKem1024  => "ML-KEM-1024",
        MlDsa44    => "ML-DSA-44",
        MlDsa65    => "ML-DSA-65",
        MlDsa87    => "ML-DSA-87",
        SlhDsaSha2_128s => "SLH-DSA-SHA2-128s",
        SlhDsaSha2_128f => "SLH-DSA-SHA2-128f",
        SlhDsaSha2_192s => "SLH-DSA-SHA2-192s",
        SlhDsaSha2_192f => "SLH-DSA-SHA2-192f",
        SlhDsaSha2_256s => "SLH-DSA-SHA2-256s",
        SlhDsaSha2_256f => "SLH-DSA-SHA2-256f",
        SlhDsaShake128s => "SLH-DSA-SHAKE-128s",
        SlhDsaShake128f => "SLH-DSA-SHAKE-128f",
        SlhDsaShake192s => "SLH-DSA-SHAKE-192s",
        SlhDsaShake192f => "SLH-DSA-SHAKE-192f",
        SlhDsaShake256s => "SLH-DSA-SHAKE-256s",
        SlhDsaShake256f => "SLH-DSA-SHAKE-256f",
    }
    .into()
}

/// Reverse mapping. Accepts the size-suffixed canonical names policies use
/// (e.g. `"AES-256"`, `"ECDSA-P256"`) by stripping the suffix when needed.
fn parse_algorithm(s: &str) -> Result<KmipAlgorithm> {
    use KmipAlgorithm::*;
    let base = s
        .split('-')
        .next()
        .ok_or_else(|| KmipError::invalid_attribute_value(format!("algorithm {s:?}")))?;
    Ok(match s {
        "ML-KEM-512" => MlKem512,
        "ML-KEM-768" => MlKem768,
        "ML-KEM-1024" => MlKem1024,
        "ML-DSA-44" => MlDsa44,
        "ML-DSA-65" => MlDsa65,
        "ML-DSA-87" => MlDsa87,
        "SLH-DSA-SHA2-128s" => SlhDsaSha2_128s,
        "SLH-DSA-SHA2-128f" => SlhDsaSha2_128f,
        "SLH-DSA-SHA2-192s" => SlhDsaSha2_192s,
        "SLH-DSA-SHA2-192f" => SlhDsaSha2_192f,
        "SLH-DSA-SHA2-256s" => SlhDsaSha2_256s,
        "SLH-DSA-SHA2-256f" => SlhDsaSha2_256f,
        "SLH-DSA-SHAKE-128s" => SlhDsaShake128s,
        "SLH-DSA-SHAKE-128f" => SlhDsaShake128f,
        "SLH-DSA-SHAKE-192s" => SlhDsaShake192s,
        "SLH-DSA-SHAKE-192f" => SlhDsaShake192f,
        "SLH-DSA-SHAKE-256s" => SlhDsaShake256s,
        "SLH-DSA-SHAKE-256f" => SlhDsaShake256f,
        // Size-suffixed classical algos collapse to their base enum.
        _ => match base {
            "AES" => Aes,
            "RSA" => Rsa,
            "ECDSA" => Ecdsa,
            "ECDH" => Ecdh,
            _ => {
                return Err(KmipError::invalid_attribute_value(format!(
                    "unrecognised CryptographicAlgorithm {s:?}"
                )))
            }
        },
    })
}

/// Phase 7b — call `softhsmrustv3::native::generate_*_keypair` for the
/// right family. Engine stores the key bytes in OBJECTS keyed by handle;
/// subsequent ops (Sign, Encrypt, etc.) recover handles via
/// `find_by_cka_id(cka_id)`.
fn native_generate_keypair(
    session: u32,
    algo: crate::kmip30::KmipAlgorithm,
    cka_id: &[u8],
) -> std::result::Result<(), KmipError> {
    use crate::kmip30::KmipAlgorithm::*;
    use softhsmrustv3::native;
    let label = "kmip-generated";

    let result: std::result::Result<(u32, u32), u32> = match algo {
        MlKem512 | MlKem768 | MlKem1024 => {
            let ps = super::helpers::native_parameter_set(algo).ok_or_else(|| {
                KmipError::failed(
                    ResultReason::OperationNotSupported,
                    format!("no parameter-set codepoint for {:?}", algo),
                )
            })?;
            native::generate_ml_kem_keypair(session, ps, cka_id, label)
        }
        MlDsa44 | MlDsa65 | MlDsa87 => {
            let ps = super::helpers::native_parameter_set(algo).unwrap();
            native::generate_ml_dsa_keypair(session, ps, cka_id, label)
        }
        SlhDsaSha2_128s | SlhDsaSha2_128f | SlhDsaSha2_192s | SlhDsaSha2_192f
        | SlhDsaSha2_256s | SlhDsaSha2_256f | SlhDsaShake128s | SlhDsaShake128f
        | SlhDsaShake192s | SlhDsaShake192f | SlhDsaShake256s | SlhDsaShake256f => {
            let ps = super::helpers::native_parameter_set(algo).unwrap();
            native::generate_slh_dsa_keypair(session, ps, cka_id, label)
        }
        Rsa => {
            // v0.1: default to RSA-2048. Phase 9 — read CKA_MODULUS_BITS
            // from template if provided.
            native::generate_rsa_keypair(session, 2048, cka_id, label)
        }
        Ecdsa => {
            // v0.1: default to P-256. Phase 9 — read CKA_EC_PARAMS from
            // template to pick the curve.
            native::generate_ecdsa_keypair(session, native::EccCurve::P256, cka_id, label)
        }
        _ => {
            return Err(KmipError::failed(
                ResultReason::OperationNotSupported,
                format!("CreateKeyPair: {:?} not supported by native API", algo),
            ));
        }
    };
    result
        .map(|_handles| ())
        .map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "CreateKeyPair"))
}

fn fail<T>(deps: &Deps, correlation_id: &str, op: &str, err: KmipError) -> Result<T> {
    deps.sink.emit(AuditEvent::at(
        OffsetDateTime::now_utc(),
        Plane::Kmip,
        correlation_id,
        EventPayload::KmipResponseSent {
            op: op.into(),
            result: KmipOpResult::OperationFailed {
                reason: format!("{:?}", err.result_reason()),
            },
            latency_ms: 0,
        },
    ));
    Err(err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auditlog::RingSink;
    use crate::policy::{load_from_str, Engine};
    use crate::store::MemoryStore;
    use std::sync::Arc;

    const PQC_DEFAULTS: &str = r#"
schema_version: 1
metadata:
  name: pqc
  description: PQC defaults
  authority: test
  effective: "always"
rules:
  - type: algorithm_default
    ops: ["CreateKeyPair:Sign"]
    default_algorithm: ML-DSA-87
    reason: "PQC sig default"
  - type: algorithm_default
    ops: ["CreateKeyPair:KeyAgreement"]
    default_algorithm: ML-KEM-1024
    reason: "PQC KEM default"
"#;

    fn deps_with(yaml: &str) -> (Arc<RingSink>, Deps) {
        let ring = Arc::new(RingSink::new(64));
        let sink: Arc<dyn crate::auditlog::AuditSink> = ring.clone();
        let engine = Engine::with_global_sink(sink.clone());
        engine
            .activate(load_from_str(yaml, std::path::Path::new("<test>")).unwrap())
            .unwrap();
        (
            ring,
            Deps::new(
                engine,
                Arc::new(MemoryStore::new()),
                sink,
                super::super::deps::DepsConfig::default(),
            ),
        )
    }

    fn empty_req() -> CreateKeyPairRequest {
        CreateKeyPairRequest {
            common_attributes: vec![],
            private_key_attributes: vec![],
            public_key_attributes: vec![],
        }
    }

    #[test]
    fn defaults_pqc_signing_under_pqc_policy() {
        let (ring, d) = deps_with(PQC_DEFAULTS);
        let resp = create_key_pair(&d, empty_req(), "CreateKeyPair:Sign", "corr-1").unwrap();
        let priv_record = d.store.get(&resp.private_key_uid).unwrap().unwrap();
        assert_eq!(priv_record.algorithm, KmipAlgorithm::MlDsa87);
        // Audit: 1 RequestReceived (p2) + 1 PolicyDecided (p1) + 1 Pkcs11Call (p3)
        //      + 1 ResponseSent (p2)  +  the activation event (p1)
        assert!(ring.filter_plane(Plane::Pkcs11).len() >= 1);
        assert!(ring.filter_plane(Plane::Kmip).len() >= 2);
    }

    #[test]
    fn defaults_pqc_kem_under_pqc_policy() {
        let (_ring, d) = deps_with(PQC_DEFAULTS);
        let resp =
            create_key_pair(&d, empty_req(), "CreateKeyPair:KeyAgreement", "corr-2").unwrap();
        let priv_record = d.store.get(&resp.private_key_uid).unwrap().unwrap();
        assert_eq!(priv_record.algorithm, KmipAlgorithm::MlKem1024);
    }

    #[test]
    fn fails_when_no_algo_and_no_default() {
        let (_ring, d) = deps_with(
            r#"
schema_version: 1
metadata: { name: empty, description: empty, authority: t, effective: "always" }
rules: []
"#,
        );
        let err = create_key_pair(&d, empty_req(), "CreateKeyPair:Sign", "corr-3").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::MissingData);
    }

    #[test]
    fn parse_algorithm_round_trip() {
        // PQC names round-trip exact.
        assert_eq!(parse_algorithm("ML-DSA-87").unwrap(), KmipAlgorithm::MlDsa87);
        assert_eq!(parse_algorithm("ML-KEM-1024").unwrap(), KmipAlgorithm::MlKem1024);
        // Classical sized names collapse to base.
        assert_eq!(parse_algorithm("AES-256").unwrap(), KmipAlgorithm::Aes);
        assert_eq!(parse_algorithm("ECDSA-P256").unwrap(), KmipAlgorithm::Ecdsa);
    }
}
