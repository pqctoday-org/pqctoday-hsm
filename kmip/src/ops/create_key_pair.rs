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
//! - **Plane 3** — calls `softhsmrustv3::native::generate_*_keypair`
//!   for the resolved family. K15: the `Pkcs11Call` audit record is
//!   emitted after the call with its real rv, naming the actual native
//!   entry point (`native::generate_ml_dsa_keypair`, …). Without an
//!   engine session (unit tests) the soft fallback allocates UUIDs and
//!   is audited as `soft::placeholder_generate_keypair`.

use std::collections::HashMap;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::auditlog::{AuditEvent, EventPayload, KmipOpResult, Plane};
use crate::error::{KmipError, Result, ResultReason};
use crate::kmip30::{
    Attribute, CreateKeyPairRequest, CreateKeyPairResponse, KmipAlgorithm, ObjectType, PkcsOp,
    UsageMask,
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
    mut req: CreateKeyPairRequest,
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

    // K19 — KMIP 3.0 §6.1.58 Set Defaults: fill attributes the client
    // omitted from the stored per-Object-Type defaults, per half. A
    // default yields to a client attribute of the same kind in either
    // the half-specific basket OR the Common Attributes basket.
    super::allocation_and_config::apply_object_defaults(
        deps,
        ObjectType::PrivateKey,
        &req.common_attributes,
        &mut req.private_key_attributes,
    );
    super::allocation_and_config::apply_object_defaults(
        deps,
        ObjectType::PublicKey,
        &req.common_attributes,
        &mut req.public_key_attributes,
    );

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
    let generated = match engine_generate_keypair(
        deps,
        correlation_id,
        kmip_algo,
        key_length,
        mech,
        req.seed.as_deref(),
    ) {
        Ok(g) => g,
        Err(err) => return fail(deps, correlation_id, op_canonical, err),
    };
    let GeneratedKeyPair {
        cka_id_priv: pkcs11_cka_id_priv,
        cka_id_pub: pkcs11_cka_id_pub,
        digest_priv,
        digest_pub,
    } = generated;

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

            digest_value: digest_priv,

            // KMIP 3.0 §6.2 — default `KeyFormatType` depends on algo.
            // For RSA the OASIS Baseline test corpus expects PKCS#1
            // (codepoint 0x03) on both halves of a CreateKeyPair-
            // generated keypair.
            key_format_type: match kmip_algo {
                crate::kmip30::KmipAlgorithm::Rsa => Some(0x03),
                _ => None,
            },
            // KMIP 3.0 WD19 §3.4 — persist the deterministic seed so a
            // later Get(SeedPrivateKey) can return the {Seed,Key}
            // KeyMaterial. Only the seeded (interop) path carries one.
            pqc_seed: req.seed.clone(),
            // PQC interop profile: a seeded CreateKeyPair produces an
            // EXPORTABLE key pair (the KATs Get both Raw and SeedPrivateKey
            // forms to verify generation). Randomly-generated keys keep
            // the production default (Extractable unset → Get blocked).
            extractable: req.seed.as_ref().map(|_| true),
            sensitive: req.seed.as_ref().map(|_| false),
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

            digest_value: digest_pub,

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

/// Output of the Plane-3 keypair generation path shared by Create Key
/// Pair (§6.1.11) and Re-key Key Pair (§6.1.52, K21).
pub(crate) struct GeneratedKeyPair {
    pub cka_id_priv: Vec<u8>,
    pub cka_id_pub: Vec<u8>,
    pub digest_priv: Option<Vec<u8>>,
    pub digest_pub: Option<Vec<u8>>,
}

/// Plane-3 keypair generation shared by Create Key Pair and Re-key Key
/// Pair. With an engine session, generates the pair in-engine (both
/// halves share one fresh CKA_ID so `find_by_cka_id` recovers both
/// handles for subsequent ops) and returns the K-14 per-half engine-
/// computed SHA-256 `Digest` over each `CKA_VALUE` — this is how the
/// server surfaces a truthful Digest even for the non-extractable
/// private half (AKLC-M-1/2/3 read it back via GetAttributes). Without
/// a session: placeholder UUID CKA_IDs, audited honestly as
/// `soft::placeholder_generate_keypair` (K15).
pub(crate) fn engine_generate_keypair(
    deps: &Deps,
    correlation_id: &str,
    kmip_algo: KmipAlgorithm,
    key_length: Option<u32>,
    mech: u32,
    seed: Option<&[u8]>,
) -> std::result::Result<GeneratedKeyPair, KmipError> {
    if let Some(session) = deps.engine_session {
        // K15 — `native_generate_keypair` emits the Pkcs11Call audit
        // record itself, after the native call, with the real rv and
        // the actual entry-point name.
        let cka_id = Uuid::new_v4().as_bytes().to_vec();
        let (pub_h, prv_h) = native_generate_keypair(
            deps,
            correlation_id,
            session,
            kmip_algo,
            key_length,
            &cka_id,
            mech,
            seed,
        )?;
        Ok(GeneratedKeyPair {
            cka_id_priv: cka_id.clone(),
            cka_id_pub: cka_id,
            digest_priv: softhsmrustv3::native::get_value_digest_sha256(session, prv_h),
            digest_pub: softhsmrustv3::native::get_value_digest_sha256(session, pub_h),
        })
    } else {
        // S-2 hardening: NO engine session ⇒ no key pair was generated.
        // Production MUST fail rather than persist phantom public/private
        // records with fabricated CKA_IDs and no key material. The soft path
        // survives only for the crate's own (engine-less) unit tests.
        #[cfg(not(test))]
        {
            return Err(KmipError::failed(
                ResultReason::CryptographicFailure,
                "no engine session — cannot generate key pair material",
            ));
        }
        #[cfg(test)]
        {
            super::helpers::emit_pkcs11(
                deps,
                correlation_id,
                "soft::placeholder_generate_keypair",
                Some(mech),
                0,
                "CKR_OK",
            );
            Ok(GeneratedKeyPair {
                cka_id_priv: Uuid::new_v4().as_bytes().to_vec(),
                cka_id_pub: Uuid::new_v4().as_bytes().to_vec(),
                digest_priv: None,
                digest_pub: None,
            })
        }
    }
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
pub(crate) fn parse_algorithm(s: &str) -> Result<KmipAlgorithm> {
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
/// Returns the `(public_handle, private_handle)` pair so the caller can
/// derive per-half metadata (e.g. the KMIP §11 `Digest`) without
/// re-finding the objects.
///
/// `key_length` carries the KMIP `CryptographicLength` attribute when the
/// client supplied one. For RSA it's the modulus bit count (validated
/// 2048..=4096); for ECDSA it selects the NIST curve (256→P-256,
/// 384→P-384, 521→P-521). For PQC algorithms the parameter set fully
/// determines the size, so the attribute is ignored.
///
/// K15 — emits the `Pkcs11Call` audit record AFTER the native call with
/// the raw `CK_RV` (success or failure) and the actual entry-point name.
#[allow(clippy::too_many_arguments)]
fn native_generate_keypair(
    deps: &Deps,
    correlation_id: &str,
    session: u32,
    algo: crate::kmip30::KmipAlgorithm,
    key_length: Option<u32>,
    cka_id: &[u8],
    mech: u32,
    seed: Option<&[u8]>,
) -> std::result::Result<(u32, u32), KmipError> {
    use crate::kmip30::KmipAlgorithm::*;
    use softhsmrustv3::native;
    let label = "kmip-generated";

    let (native_fn, result): (&str, std::result::Result<(u32, u32), u32>) = match algo {
        MlKem512 | MlKem768 | MlKem1024 => {
            let ps = super::helpers::native_parameter_set(algo).ok_or_else(|| {
                KmipError::failed(
                    ResultReason::OperationNotSupported,
                    format!("no parameter-set codepoint for {:?}", algo),
                )
            })?;
            match seed {
                // Seeded keygen is the PQC interop profile: born extractable
                // so the generated material can be Got + checked byte-exact.
                Some(s) => (
                    "native::generate_ml_kem_keypair_from_seed_extractable",
                    native::generate_ml_kem_keypair_from_seed_extractable(session, ps, s, cka_id, label),
                ),
                None => (
                    "native::generate_ml_kem_keypair",
                    native::generate_ml_kem_keypair(session, ps, cka_id, label),
                ),
            }
        }
        MlDsa44 | MlDsa65 | MlDsa87 => {
            let ps = super::helpers::native_parameter_set(algo).unwrap();
            match seed {
                Some(s) => (
                    "native::generate_ml_dsa_keypair_from_seed_extractable",
                    native::generate_ml_dsa_keypair_from_seed_extractable(session, ps, s, cka_id, label),
                ),
                None => (
                    "native::generate_ml_dsa_keypair",
                    native::generate_ml_dsa_keypair(session, ps, cka_id, label),
                ),
            }
        }
        SlhDsaSha2_128s | SlhDsaSha2_128f | SlhDsaSha2_192s | SlhDsaSha2_192f
        | SlhDsaSha2_256s | SlhDsaSha2_256f | SlhDsaShake128s | SlhDsaShake128f
        | SlhDsaShake192s | SlhDsaShake192f | SlhDsaShake256s | SlhDsaShake256f => {
            let ps = super::helpers::native_parameter_set(algo).unwrap();
            match seed {
                Some(s) => (
                    "native::generate_slh_dsa_keypair_from_seed_extractable",
                    native::generate_slh_dsa_keypair_from_seed_extractable(session, ps, s, cka_id, label),
                ),
                None => (
                    "native::generate_slh_dsa_keypair",
                    native::generate_slh_dsa_keypair(session, ps, cka_id, label),
                ),
            }
        }
        Rsa => {
            let bits = key_length.unwrap_or(2048);
            if !(2048..=4096).contains(&bits) {
                return Err(KmipError::invalid_attribute_value(format!(
                    "RSA CryptographicLength {bits} out of supported range 2048..=4096"
                )));
            }
            (
                "native::generate_rsa_keypair",
                native::generate_rsa_keypair(session, bits, cka_id, label),
            )
        }
        Ecdsa => {
            let curve = ecdsa_curve_from_length(key_length)?;
            (
                "native::generate_ecdsa_keypair",
                native::generate_ecdsa_keypair(session, curve, cka_id, label),
            )
        }
        _ => {
            return Err(KmipError::failed(
                ResultReason::OperationNotSupported,
                format!("CreateKeyPair: {:?} not supported by native API", algo),
            ));
        }
    };
    super::helpers::emit_pkcs11_result(deps, correlation_id, native_fn, Some(mech), &result);
    result.map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "CreateKeyPair"))
}

/// Map KMIP `CryptographicLength` to a NIST curve. KMIP doesn't carry a
/// dedicated `Recommended Curve` attribute in our v0.1 surface, so we infer
/// from the length: 256 ⇒ P-256, 384 ⇒ P-384, 521 ⇒ P-521. Default (no
/// length supplied) is P-256.
fn ecdsa_curve_from_length(
    key_length: Option<u32>,
) -> std::result::Result<softhsmrustv3::native::EccCurve, KmipError> {
    use softhsmrustv3::native::EccCurve;
    match key_length {
        None | Some(256) => Ok(EccCurve::P256),
        Some(384) => Ok(EccCurve::P384),
        Some(521) => Ok(EccCurve::P521),
        Some(n) => Err(KmipError::invalid_attribute_value(format!(
            "ECDSA CryptographicLength {n} not supported (expected 256, 384, or 521)"
        ))),
    }
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
            seed: None,
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
    fn ecdsa_curve_from_length_maps_nist_sizes() {
        use softhsmrustv3::native::EccCurve;
        assert!(matches!(ecdsa_curve_from_length(None), Ok(EccCurve::P256)));
        assert!(matches!(ecdsa_curve_from_length(Some(256)), Ok(EccCurve::P256)));
        assert!(matches!(ecdsa_curve_from_length(Some(384)), Ok(EccCurve::P384)));
        assert!(matches!(ecdsa_curve_from_length(Some(521)), Ok(EccCurve::P521)));
    }

    #[test]
    fn ecdsa_curve_from_length_rejects_unknown_size() {
        let err = ecdsa_curve_from_length(Some(192)).unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::InvalidAttributeValue);
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
