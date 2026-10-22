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
    auth: &crate::server::auth::AuthContext,
    correlation_id: &str,
) -> Result<CreateKeyPairResponse> {
    // Part F §F7 — this tenant's own engine session (Single mode: the
    // one shared `engine_session`, unchanged; Auto/Strict: this
    // identity's own token). `.ok()` folds a resolution failure into
    // `None`, matching every existing "no engine session" fallback path
    // below exactly (including the engine-less unit-test placeholder).
    let session = deps.resolve_tenant_session(auth.identity.as_ref()).ok();
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

    // K19 — KMIP 3.0 §6.1.60 Set Defaults: fill attributes the client
    // omitted from the stored per-Object-Type defaults, per half. A
    // default yields to a client attribute of the same kind in either
    // the half-specific basket OR the Common Attributes basket.
    super::allocation_and_config::apply_object_defaults(
        deps,
        ObjectType::PrivateKey,
        &req.common_attributes,
        &mut req.private_key_attributes,
        auth,
    );
    super::allocation_and_config::apply_object_defaults(
        deps,
        ObjectType::PublicKey,
        &req.common_attributes,
        &mut req.public_key_attributes,
        auth,
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
    let (algorithm_in, algo_enum, key_length, usage_mask, recommended_curve) = extract_template(&req);
    let _ = (priv_x.algorithm, pub_x.algorithm); // silence unused; merged via extract_template

    // ── Plane 1: policy gate ────────────────────────────────────────────
    // Y1: custom attributes may ride on any of the three attribute groups —
    // combine them so `require_custom_attribute` sees the classification tag.
    // Y3: qualify the bare algorithm ("RSA" → "RSA-3072", "ECDSA" → "ECDSA-P384").
    let all_attrs: Vec<Attribute> = req
        .common_attributes
        .iter()
        .chain(req.private_key_attributes.iter())
        .chain(req.public_key_attributes.iter())
        .cloned()
        .collect();
    let custom_attrs = super::helpers::custom_attrs_from(&all_attrs);
    let qualified_algo = algorithm_in
        .as_deref()
        .map(|a| super::helpers::qualify_algorithm_str(a, key_length));
    let mut p_req = PolicyRequest::minimal(
        op_canonical,
        qualified_algo.as_deref(),
        started,
        correlation_id,
        &custom_attrs,
    );
    p_req.key_length = key_length;
    p_req.usage_mask = usage_mask;
    // Label-pattern rules (`name_pattern`) match on the template's Name — the
    // Migration tab's label-only contract, where the policy maps a business
    // key name to an algorithm. `Name` is not `Custom`, so it isn't in
    // `custom_attrs`; pull it straight off the merged template.
    let template_name = all_attrs.iter().find_map(|a| match a {
        Attribute::Name(n) => Some(n.as_str()),
        _ => None,
    });
    p_req.name = template_name;
    // Surface the mechanism dimension so `mechanism_allowlist`/`_denylist`
    // rules scoped to `Create`/`CreateKeyPair` (e.g.
    // pkcs11-mechanism-lockdown.yaml) actually gate keygen instead of
    // silently no-op'ing. Only meaningful when the client named an
    // algorithm — a template-omitted algorithm relies on policy's own
    // `algorithm_default`, which hasn't run yet at this point.
    if let Some(a) = algo_enum {
        p_req.mechanism = super::helpers::mechanism_params_from_cp(a, PkcsOp::KeyGen, None);
    }

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
        Decision::Deny { kmip_reason, human, .. } => {
            return fail(
                deps,
                correlation_id,
                op_canonical,
                KmipError::failed(kmip_reason.to_result_reason(), human),
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

    // Gap-remediation Phase E, Finding #13 — KMIP 3.0 §11 — reject
    // `QuantumSafe=true` claims on non-PQC algorithms, same check
    // `create.rs` already performs (QS-M-2 pins this with AES +
    // QuantumSafe=true → `GeneralFailure` "NOT_SAFE"). QuantumSafe MAY
    // ride on any of the three attribute baskets (Common/Private/Public),
    // so check the full merged set like the Y1 custom-attribute lookup
    // above does, not just one half.
    {
        let x = super::register_import_export::extract_attrs(&all_attrs);
        if matches!(x.quantum_safe, Some(true))
            && !super::register_import_export::algorithm_is_quantum_safe(kmip_algo)
        {
            return fail(
                deps,
                correlation_id,
                op_canonical,
                KmipError::failed(
                    ResultReason::GeneralFailure,
                    format!("QuantumSafe=true claimed for non-PQC algorithm {kmip_algo:?}"),
                ),
            );
        }
    }

    // Label-only Montgomery KEM: when the policy resolved the algorithm to
    // `X25519`/`X448` (a name, not a template CryptographicDomainParameters),
    // supply the matching RecommendedCurve + §6.7 mech-info length here so the
    // engine generates the right curve and `qualified_name` renders the stored
    // key distinctly (255 → X25519, 448 → X448) instead of colliding with
    // real P-curves as `ECDH-P256`.
    let (recommended_curve, montgomery_length) = {
        use crate::kmip30::algos::recommended_curve as rc;
        match resolved_algorithm.as_str() {
            "X25519" => (Some(rc::CURVE25519), Some(255u32)),
            "X448" => (Some(rc::CURVE448), Some(448u32)),
            _ => (recommended_curve, None),
        }
    };
    // Size the record from the policy-resolved name on the label-only path
    // (`RSA-2048` → 2048, `ECDSA-P384` → 384) so the stored key carries its
    // real length — otherwise a label-only key persisted length 0 and the UI /
    // GetAttributes reported no size. Montgomery curves get their §6.7 length
    // above; PQC parameter sets encode their own size (None here).
    let stored_length = key_length
        .or(montgomery_length)
        .or_else(|| super::helpers::classical_length_from_name(&resolved_algorithm));

    // ── Plane 3: would call C_GenerateKeyPair ───────────────────────────
    // PKCS#11 v3.2 §C.7.1 — signature in pkcs11f.h:
    //   C_GenerateKeyPair(hSession, pMechanism,
    //                     pPublicKeyTemplate, ulPublicKeyAttributeCount,
    //                     pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
    //                     phPublicKey, phPrivateKey)
    // softhsmrustv3 export verified at rust/src/ffi.rs::C_GenerateKeyPair.
    // K6 — hybrid KEMs have no single PKCS#11 mechanism. The ENGINE generates
    // TWO non-extractable keypairs (classical + ML-KEM) under two CKA_IDs and
    // returns their private handles + the assembled public wire share. The
    // private record stores NO key_material (its two halves live in the engine,
    // so Get refuses it via CKA_SENSITIVE); the public record stores the wire
    // share inline (it is public). `hybrid_secondary_cka_id` is the classical
    // half's CKA_ID, recorded on the private object so Decapsulate can resolve
    // both handles.
    let (generated, hybrid_pub_material, hybrid_priv_material, hybrid_secondary_cka_id) =
        if let Some(hybrid) = kmip_algo.hybrid_kem() {
            match session {
                Some(session) => {
                    let mlkem_cka_id = Uuid::new_v4().as_bytes().to_vec();
                    let classical_cka_id = Uuid::new_v4().as_bytes().to_vec();
                    let kg = match softhsmrustv3::native::hybrid::keygen(
                        session,
                        hybrid,
                        &mlkem_cka_id,
                        &classical_cka_id,
                    ) {
                        Ok(kg) => kg,
                        Err(rv) => {
                            return fail(
                                deps,
                                correlation_id,
                                op_canonical,
                                super::helpers::ck_rv_to_kmip_error(rv, "hybrid keygen"),
                            )
                        }
                    };
                    super::helpers::emit_pkcs11(deps, correlation_id, "soft::hybrid_kem_keygen", None, 0, "CKR_OK");
                    (
                        GeneratedKeyPair {
                            cka_id_priv: mlkem_cka_id,
                            cka_id_pub: Vec::new(),
                            digest_priv: None,
                            digest_pub: None,
                        },
                        Some(kg.public),        // public wire share (inline)
                        None,                   // private key_material NONE — the non-extractability fix
                        Some(classical_cka_id), // secondary CKA_ID on the private record
                    )
                }
                None => {
                    // S-2 hardening: no engine session ⇒ no hybrid material.
                    // Production MUST fail; the soft path survives only for the
                    // crate's own engine-less unit tests.
                    #[cfg(not(test))]
                    {
                        return fail(
                            deps,
                            correlation_id,
                            op_canonical,
                            KmipError::failed(
                                ResultReason::CryptographicFailure,
                                "no engine session — cannot generate hybrid key pair".to_string(),
                            ),
                        );
                    }
                    #[cfg(test)]
                    {
                        super::helpers::emit_pkcs11(deps, correlation_id, "soft::placeholder_hybrid_keygen", None, 0, "CKR_OK");
                        (
                            GeneratedKeyPair {
                                cka_id_priv: Uuid::new_v4().as_bytes().to_vec(),
                                cka_id_pub: Vec::new(),
                                digest_priv: None,
                                digest_pub: None,
                            },
                            None,
                            None,
                            Some(Uuid::new_v4().as_bytes().to_vec()),
                        )
                    }
                }
            }
        } else {
            // Every other algorithm, the LAMPS composites included: a
            // composite key pair is ONE engine key pair
            // (`CKM_COMP_SIG_KEY_PAIR_GEN` / `CKM_COMP_KEM_KEY_PAIR_GEN`,
            // PKCS#11 v3.3 working draft) under one CKA_ID, exactly like
            // ML-DSA / ML-KEM. Only the TLS hybrid groups above keep two
            // component keys.
            let mech = kmip_algo.to_pkcs11_mech(PkcsOp::KeyGen).ok_or_else(|| {
                KmipError::failed(
                    ResultReason::OperationNotSupported,
                    format!("algorithm {resolved_algorithm} has no KeyGen mechanism"),
                )
            })?;
            // Phase 7b: real bridge call when a session is wired. Falls back to
            // placeholder UUIDs for unit tests.
            match engine_generate_keypair(
                deps,
                correlation_id,
                session,
                kmip_algo,
                key_length,
                mech,
                req.seed.as_deref(),
                recommended_curve,
                pub_x.usage.unwrap_or_else(UsageMask::empty),
                priv_x.usage.unwrap_or_else(UsageMask::empty),
            ) {
                Ok(g) => (g, None, None, None),
                Err(err) => return fail(deps, correlation_id, op_canonical, err),
            }
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
    deps.store.put(super::helpers::stamp_owner(ObjectRecord {
        uid: priv_uid.clone(),
        object_type: ObjectType::PrivateKey,
        algorithm: kmip_algo,
        cryptographic_length: priv_x.length.or(stored_length).unwrap_or(0),
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
            rotate_automatic: priv_x.rotate_automatic,
            rotate_interval: priv_x.rotate_interval,
            rotate_offset: priv_x.rotate_offset,
            rotate_name: priv_x.rotate_name.clone(),

            // KMIP §11 `Public Key Link` — UID of the matching
            // public-key half on the private record (AKLC-O-1
            // step #3 reads it back via GetAttributes).
            links: {
                let mut m = std::collections::HashMap::new();
                m.insert("PublicKeyLink".to_string(), pub_uid.clone());
                m
            },

            // Y1 — persist the request's custom attributes (e.g. the CNSA
            // classification tag) on the private key so use-time policy gates
            // (Sign/Encrypt) can read the classification back off the object.
            custom_attributes: super::helpers::raw_custom_attrs(&all_attrs),

            // Gap-remediation Phase E, Finding #5 — `create.rs`,
            // `register_import_export.rs`, and `derive_key.rs` all
            // persist this field; `create_key_pair.rs` never read it off
            // `priv_x`/`pub_x`, so a key's declared default padding/hash
            // (e.g. PSS/SHA-384) was silently lost and a later bare
            // Sign/Verify fell back to the mechanism default.
            cryptographic_parameters: priv_x.cryptographic_parameters.clone(),


            // K6 — hybrid private keys are engine-backed (two handles behind
            // pkcs11_cka_id + pkcs11_cka_id_secondary); no material here, so Get
            // refuses them. None for every non-hybrid engine key too.
            key_material: hybrid_priv_material,

            // K6 — classical half's CKA_ID for a hybrid private key (None otherwise).
            pkcs11_cka_id_secondary: hybrid_secondary_cka_id,

            // KMIP 3.0 §4.16 — Recommended Curve chosen for an EC/ECDH key,
            // reported back via the Cryptographic Domain Parameters attribute.
            recommended_curve,

            digest_value: digest_priv,

            // KMIP 3.0 §6.2 — default `KeyFormatType` depends on algo.
            // For RSA the OASIS Baseline test corpus expects PKCS#1
            // (codepoint 0x03) on both halves of a CreateKeyPair-
            // generated keypair.
            key_format_type: match kmip_algo {
                crate::kmip30::KmipAlgorithm::Rsa => Some(0x03),
                _ => None,
            },
            // KMIP 3.0 CSD02 §3.4 — persist the deterministic seed so a
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
            protection_storage_mask: Some(0x01),
            lease_time: Some(3600),
    ..ObjectRecord::default()
}, auth))?;
    deps.store.put(super::helpers::stamp_owner(ObjectRecord {
        uid: pub_uid.clone(),
        object_type: ObjectType::PublicKey,
        algorithm: kmip_algo,
        cryptographic_length: pub_x.length.or(stored_length).unwrap_or(0),
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
            rotate_automatic: pub_x.rotate_automatic,
            rotate_interval: pub_x.rotate_interval,
            rotate_offset: pub_x.rotate_offset,
            rotate_name: pub_x.rotate_name.clone(),

            // KMIP §11 `Private Key Link` — UID of the matching
            // private-key half on the public record.
            links: {
                let mut m = std::collections::HashMap::new();
                m.insert("PrivateKeyLink".to_string(), priv_uid.clone());
                m
            },

            custom_attributes: std::collections::HashMap::new(),

            // Gap-remediation Phase E, Finding #5 — same fix as the
            // private half above; the public half has its own
            // independently-templated CryptographicParameters basket.
            cryptographic_parameters: pub_x.cryptographic_parameters.clone(),

            // K6 — composite public key material for a hybrid KEM.
            key_material: hybrid_pub_material,

            // Public keys are never hybrid-engine-backed here (the wire share is
            // stored inline above); no secondary CKA_ID.
            pkcs11_cka_id_secondary: None,

            // KMIP 3.0 §4.16 — the public half carries the same domain params.
            recommended_curve,

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
            protection_storage_mask: Some(0x01),
            lease_time: Some(3600),
    ..ObjectRecord::default()
}, auth))?;

    deps.sink.emit(AuditEvent::at(
        OffsetDateTime::now_utc(),
        Plane::Kmip,
        correlation_id,
        EventPayload::KmipResponseSent {
            op: op_canonical.into(),
            result: KmipOpResult::Success,
            latency_ms: deps.take_request_latency_ms(correlation_id),
        },
    ));

    Ok(CreateKeyPairResponse {
        private_key_uid: priv_uid,
        public_key_uid: pub_uid,
    })
}

/// Output of the Plane-3 keypair generation path shared by Create Key
/// Pair (§6.1.11) and Re-key Key Pair (§6.1.54, K21).
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
    session: Option<u32>,
    kmip_algo: KmipAlgorithm,
    key_length: Option<u32>,
    mech: u32,
    seed: Option<&[u8]>,
    recommended_curve: Option<u32>,
    usage_pub: UsageMask,
    usage_priv: UsageMask,
) -> std::result::Result<GeneratedKeyPair, KmipError> {
    // Part F §F7 — `session` is the CALLER's resolved per-tenant engine
    // session (`Deps::resolve_tenant_session`), not the raw shared
    // `deps.engine_session` — see the plan's dispatcher-wiring note.
    if let Some(session) = session {
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
            recommended_curve,
        )?;
        // PKCS#11 v3.2 §4.8 Table 13 — restrict each half to the mechanisms
        // ITS OWN usage mask implies (PublicKeyAttributes/
        // PrivateKeyAttributes can carry different masks — e.g. a private
        // key restricted to SIGN while the public key is restricted to
        // VERIFY; both resolve to the same mechanism via
        // `usage_mask_to_allowed_mechanisms`, but they don't have to).
        // Best-effort posture, same as the symmetric path in `create.rs`.
        for (label, handle, usage) in
            [("public", pub_h, usage_pub), ("private", prv_h, usage_priv)]
        {
            let mechs = kmip_algo.usage_mask_to_allowed_mechanisms(usage);
            if mechs.is_empty() {
                continue;
            }
            let packed = crate::kmip30::algos::pack_allowed_mechanisms(&mechs);
            let r = softhsmrustv3::native::set_attribute(
                session,
                handle,
                softhsmrustv3::constants::CKA_ALLOWED_MECHANISMS,
                packed,
            );
            super::helpers::emit_pkcs11_result(
                deps,
                correlation_id,
                &format!("native::set_attribute(CKA_ALLOWED_MECHANISMS, {label})"),
                None,
                &r,
            );
        }
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
fn extract_template(
    req: &CreateKeyPairRequest,
) -> (Option<String>, Option<KmipAlgorithm>, Option<u32>, Option<UsageMask>, Option<u32>) {
    let mut algorithm: Option<String> = None;
    let mut algo_enum: Option<KmipAlgorithm> = None;
    let mut length: Option<u32> = None;
    let mut usage: Option<UsageMask> = None;
    // KMIP 3.0 §4.16 — the curve is carried inside Cryptographic Domain
    // Parameters (the compliant surface), NOT a standalone attribute.
    let mut recommended_curve: Option<u32> = None;
    for a in req
        .common_attributes
        .iter()
        .chain(req.private_key_attributes.iter())
        .chain(req.public_key_attributes.iter())
    {
        match a {
            Attribute::CryptographicAlgorithm(alg) => {
                algorithm = Some(canonical_name(*alg));
                algo_enum = Some(*alg);
            }
            Attribute::CryptographicLength(n) => {
                length = Some(*n as u32);
            }
            Attribute::CryptographicUsageMask(m) => {
                usage = Some(*m);
            }
            Attribute::CryptographicDomainParameters { recommended_curve: rc, .. } => {
                if let Some(c) = rc {
                    recommended_curve = Some(*c);
                }
            }
            _ => {}
        }
    }
    (algorithm, algo_enum, length, usage, recommended_curve)
}

/// Canonical algorithm string used by the policy engine — the one table in
/// `ops/helpers.rs` (this file used to keep an identical copy).
fn canonical_name(a: KmipAlgorithm) -> String {
    super::helpers::canonical_name(a)
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
        // K6 hybrid KEMs (no '-' split; exact names).
        "X25519MLKEM768" => X25519MlKem768,
        "SecP256r1MLKEM768" => SecP256r1MlKem768,
        "SecP384r1MLKEM1024" => SecP384r1MlKem1024,
        // P1 (2026-07-05): Ed25519 has no size/curve suffix — exact name.
        "Ed25519" => Ed25519,
        // Mirrors Ed25519 exactly — no size/curve suffix.
        "Ed448" => Ed448,
        // Montgomery key-agreement curves collapse to `Ecdh` at the enum layer;
        // the caller (create_key_pair) turns these names into ECDH +
        // RecommendedCurve CURVE25519/CURVE448 so the label-only policy default
        // path (`default_algorithm: X25519`) can create them. Without this arm
        // a policy naming X25519/X448 failed to parse (the engine expected the
        // curve only in the request template's CryptographicDomainParameters).
        "X25519" | "X448" => Ecdh,
        // BSI TR-02102-1 §2.4.1 — the bare policy-facing name doesn't
        // distinguish AES vs SHAKE (see `canonical_name`, which collapses
        // both to this same string). A bare "FrodoKEM-976" therefore can't
        // round-trip to a unique variant; defaults to the AES matrix-
        // generation variant (the more commonly deployed one, given
        // widespread AES-NI hardware support). A caller that needs the
        // SHAKE variant specifically must go through the fully-qualified
        // wire `CryptographicAlgorithm` value directly, not this string path.
        "FrodoKEM-640" => FrodoKem640Aes,
        "FrodoKEM-976" => FrodoKem976Aes,
        "FrodoKEM-1344" => FrodoKem1344Aes,
        // BSI TR-02102-1 §2.4.2 — all 10 parameter sets are separate
        // `KmipAlgorithm` variants (implementation plan 2026-09-08, §3.2),
        // each with its own unique `canonical_name` string, so unlike
        // FrodoKEM's AES/SHAKE collapse above there is no ambiguity to
        // resolve here.
        "Classic-McEliece-6688128" => ClassicMcEliece6688128,
        "Classic-McEliece-6960119" => ClassicMcEliece6960119,
        "Classic-McEliece-8192128" => ClassicMcEliece8192128,
        "Classic-McEliece-348864" => ClassicMcEliece348864,
        "Classic-McEliece-348864f" => ClassicMcEliece348864F,
        "Classic-McEliece-460896" => ClassicMcEliece460896,
        "Classic-McEliece-460896f" => ClassicMcEliece460896F,
        "Classic-McEliece-6688128f" => ClassicMcEliece6688128F,
        "Classic-McEliece-6960119f" => ClassicMcEliece6960119F,
        "Classic-McEliece-8192128f" => ClassicMcEliece8192128F,
        // LAMPS composites (18 signature + 12 KEM sets): exact
        // `spec_name()` strings, resolved from `KmipAlgorithm::ALL` so this
        // stays in step with the enum.
        _ if KmipAlgorithm::composite_from_spec_name(s).is_some_and(|c| c.spec_name() == s) => {
            KmipAlgorithm::composite_from_spec_name(s).expect("guard")
        }
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
    recommended_curve: Option<u32>,
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
        FrodoKem640Aes | FrodoKem640Shake | FrodoKem976Aes
        | FrodoKem976Shake | FrodoKem1344Aes | FrodoKem1344Shake => {
            // BSI TR-02102-1 §2.4.1. No seeded/deterministic keygen exists
            // for FrodoKEM in this engine (no PQC-interop profile need for
            // it, unlike ML-KEM) — reject rather than silently ignore a
            // caller-supplied seed.
            if seed.is_some() {
                return Err(KmipError::failed(
                    ResultReason::OperationNotSupported,
                    format!("seeded keygen is not supported for {:?}", algo),
                ));
            }
            let ps = super::helpers::native_parameter_set(algo).ok_or_else(|| {
                KmipError::failed(
                    ResultReason::OperationNotSupported,
                    format!("no parameter-set codepoint for {:?}", algo),
                )
            })?;
            (
                "native::generate_frodokem_keypair",
                native::generate_frodokem_keypair(session, ps, cka_id, label),
            )
        }
        ClassicMcEliece348864 | ClassicMcEliece348864F
        | ClassicMcEliece460896 | ClassicMcEliece460896F
        | ClassicMcEliece6688128 | ClassicMcEliece6688128F
        | ClassicMcEliece6960119 | ClassicMcEliece6960119F
        | ClassicMcEliece8192128 | ClassicMcEliece8192128F => {
            // BSI TR-02102-1 §2.4.2. No seeded/deterministic keygen exists
            // for Classic McEliece in this engine, for any of the 10
            // parameter sets.
            if seed.is_some() {
                return Err(KmipError::failed(
                    ResultReason::OperationNotSupported,
                    format!("seeded keygen is not supported for {:?}", algo),
                ));
            }
            let ps = super::helpers::native_parameter_set(algo).ok_or_else(|| {
                KmipError::failed(
                    ResultReason::OperationNotSupported,
                    format!("no parameter-set codepoint for {:?}", algo),
                )
            })?;
            (
                "native::generate_classic_mceliece_keypair",
                native::generate_classic_mceliece_keypair(session, ps, cka_id, label),
            )
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
        // `Ecdh` (wire 0x0e). KMIP 3.0 §4.16 — the curve is chosen by the
        // `Recommended Curve` inside Cryptographic Domain Parameters. X25519 /
        // X448 key agreement is modelled here as ECDH + CURVE25519 / CURVE448
        // (there is no standalone X25519/X448 algorithm codepoint). When no
        // Recommended Curve is supplied we keep the length-based NIST inference
        // for back-compat.
        Ecdh => {
            use crate::kmip30::algos::recommended_curve as rc;
            match recommended_curve {
                Some(rc::CURVE25519) => (
                    "native::generate_x25519_keypair",
                    native::generate_x25519_keypair(session, cka_id, label),
                ),
                Some(rc::CURVE448) => (
                    "native::generate_x448_keypair",
                    native::generate_x448_keypair(session, cka_id, label),
                ),
                Some(rc::P_256) => (
                    "native::generate_ecdh_keypair",
                    native::generate_ecdh_keypair(session, native::EccCurve::P256, cka_id, label),
                ),
                Some(rc::P_384) => (
                    "native::generate_ecdh_keypair",
                    native::generate_ecdh_keypair(session, native::EccCurve::P384, cka_id, label),
                ),
                Some(rc::P_521) => (
                    "native::generate_ecdh_keypair",
                    native::generate_ecdh_keypair(session, native::EccCurve::P521, cka_id, label),
                ),
                Some(other) => {
                    return Err(KmipError::invalid_attribute_value(format!(
                        "ECDH RecommendedCurve 0x{other:08x} not supported"
                    )));
                }
                None => {
                    let curve = ecdsa_curve_from_length(key_length)?;
                    (
                        "native::generate_ecdh_keypair",
                        native::generate_ecdh_keypair(session, curve, cka_id, label),
                    )
                }
            }
        }
        // LAMPS composites — one CKK_COMP_SIG / CKK_COMP_KEM engine object
        // per half, the parameter set from the engine table
        // (`KmipAlgorithm::composite_ckp`). The drafts' private key is the
        // ML seed plus the traditional key, so there is no separate seeded
        // keygen: a caller seed is refused, not ignored.
        a if a.is_composite() => {
            if seed.is_some() {
                return Err(KmipError::failed(
                    ResultReason::OperationNotSupported,
                    format!("seeded keygen is not supported for {}", a.spec_name()),
                ));
            }
            let (key_type, ckp) = match (a.composite_key_type(), a.composite_ckp()) {
                (Some(t), Some((_, ckp))) => (t, ckp),
                _ => unreachable!("is_composite() implies a key type and set"),
            };
            (
                "native::composite_ops::generate_keypair",
                native::composite_ops::generate_keypair(session, key_type, ckp, cka_id, label),
            )
        }
        // P1 (2026-07-05): Ed25519 — no curve/size parameter, single fixed
        // curve. Keygen/sign/verify all pre-existed at the PKCS#11 layer
        // (ffi.rs CKM_EC_EDWARDS_KEY_PAIR_GEN / CKM_EDDSA); this is the
        // missing KMIP-layer plumbing.
        Ed25519 => (
            "native::generate_ed25519_keypair",
            native::generate_ed25519_keypair(session, cka_id, label),
        ),
        // Mirrors Ed25519 exactly — no curve/size parameter, single fixed
        // curve. `Sign`/`SignatureVerify` need no dispatch changes at all
        // (CKM_EDDSA already covers both curves, length-dispatched inside
        // the engine); this keygen call was the only missing piece.
        Ed448 => (
            "native::generate_ed448_keypair",
            native::generate_ed448_keypair(session, cka_id, label),
        ),
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
            latency_ms: deps.take_request_latency_ms(correlation_id),
        },
    ));
    Err(err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auditlog::RingSink;
    use crate::policy::{load_from_str, Engine};
    use crate::server::auth::AuthContext;
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
            .replace_all(load_from_str(yaml, std::path::Path::new("<test>")).unwrap())
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
        let resp = create_key_pair(&d, empty_req(), "CreateKeyPair:Sign", &AuthContext::open(), "corr-1").unwrap();
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
            create_key_pair(&d, empty_req(), "CreateKeyPair:KeyAgreement", &AuthContext::open(), "corr-2").unwrap();
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
        let err = create_key_pair(&d, empty_req(), "CreateKeyPair:Sign", &AuthContext::open(), "corr-3").unwrap_err();
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

    #[test]
    fn composite_sig_names_round_trip_through_canonical_name_and_parse_algorithm() {
        let composites: Vec<_> = KmipAlgorithm::ALL.iter().copied().filter(|a| a.is_composite()).collect();
        assert_eq!(composites.len(), 30);
        for a in composites {
            let name = canonical_name(a);
            assert_eq!(parse_algorithm(&name).unwrap(), a, "{name}");
            assert_eq!(name, a.spec_name());
            // Exact names only, as for every other algorithm here.
            assert!(parse_algorithm(&name.to_ascii_lowercase()).is_err(), "{name}");
        }
    }

    const PERMISSIVE_POLICY: &str = r#"
schema_version: 1
metadata: { name: t, description: t, authority: t, effective: "always" }
rules: []
"#;

    /// Gap-remediation Phase E, Finding #5 — a key's declared default
    /// `CryptographicParameters` (e.g. PSS/SHA-384) must survive onto
    /// BOTH halves' stored `ObjectRecord`, independently per half, not
    /// silently dropped (`create.rs`/`register_import_export.rs`/
    /// `derive_key.rs` all persist this field already; `create_key_pair`
    /// previously never read it off `priv_x`/`pub_x`).
    #[test]
    fn create_key_pair_persists_cryptographic_parameters_on_both_halves() {
        let (_ring, d) = deps_with(PERMISSIVE_POLICY);
        let priv_cp = crate::kmip30::ops::CryptographicParameters {
            padding_method: Some(0x0a), // PSS
            hashing_algorithm: Some(crate::kmip30::ops::HashingAlgorithm::Sha384),
            ..Default::default()
        };
        let pub_cp = crate::kmip30::ops::CryptographicParameters {
            padding_method: Some(0x0a),
            hashing_algorithm: Some(crate::kmip30::ops::HashingAlgorithm::Sha256),
            ..Default::default()
        };
        let req = CreateKeyPairRequest {
            common_attributes: vec![Attribute::CryptographicAlgorithm(KmipAlgorithm::Rsa)],
            private_key_attributes: vec![Attribute::CryptographicParameters(priv_cp.clone())],
            public_key_attributes: vec![Attribute::CryptographicParameters(pub_cp.clone())],
            seed: None,
        };
        let resp = create_key_pair(&d, req, "CreateKeyPair:Sign", &AuthContext::open(), "corr-cp").unwrap();
        let priv_record = d.store.get(&resp.private_key_uid).unwrap().unwrap();
        let pub_record = d.store.get(&resp.public_key_uid).unwrap().unwrap();
        assert_eq!(priv_record.cryptographic_parameters, Some(priv_cp));
        assert_eq!(pub_record.cryptographic_parameters, Some(pub_cp));
    }

    /// Gap-remediation Phase E, Finding #13 — `QuantumSafe=true` on a
    /// non-PQC algorithm must be rejected, matching `create.rs`'s
    /// existing check for the same scenario (QS-M-2).
    #[test]
    fn create_key_pair_quantum_safe_true_on_rsa_is_rejected() {
        let (_ring, d) = deps_with(PERMISSIVE_POLICY);
        let req = CreateKeyPairRequest {
            common_attributes: vec![
                Attribute::CryptographicAlgorithm(KmipAlgorithm::Rsa),
                Attribute::QuantumSafe(true),
            ],
            private_key_attributes: vec![],
            public_key_attributes: vec![],
            seed: None,
        };
        let err = create_key_pair(&d, req, "CreateKeyPair:Sign", &AuthContext::open(), "corr-qs").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::GeneralFailure);
    }

    /// A genuinely PQC algorithm with `QuantumSafe=true` must still
    /// succeed — the check only rejects the false claim, not the
    /// attribute itself.
    #[test]
    fn create_key_pair_quantum_safe_true_on_ml_dsa_succeeds() {
        let (_ring, d) = deps_with(PERMISSIVE_POLICY);
        let req = CreateKeyPairRequest {
            common_attributes: vec![
                Attribute::CryptographicAlgorithm(KmipAlgorithm::MlDsa87),
                Attribute::QuantumSafe(true),
            ],
            private_key_attributes: vec![],
            public_key_attributes: vec![],
            seed: None,
        };
        create_key_pair(&d, req, "CreateKeyPair:Sign", &AuthContext::open(), "corr-qs-ok").unwrap();
    }

    /// `deps_with` plus a real engine session — same pattern as
    /// `validate.rs`'s own `deps_with_session` (crate-wide
    /// `engine_lock()` held for the guard's lifetime; see that file's
    /// doc for why a per-file lock isn't enough).
    fn deps_with_engine(yaml: &str) -> (Arc<RingSink>, Deps, std::sync::MutexGuard<'static, ()>) {
        use softhsmrustv3::native::session::{bootstrap_default_token, finalize, init};
        let guard = super::super::helpers::engine_lock();
        let _ = finalize();
        init().expect("engine init");
        let session = bootstrap_default_token(0, "so", "user", "create-key-pair-composite-test")
            .expect("bootstrap session");
        let (ring, d) = deps_with(yaml);
        (ring, d.with_engine_session(session), guard)
    }

    /// A composite key pair through the real `CreateKeyPair` handler is ONE
    /// engine key pair (PKCS#11 v3.3 working draft `CKK_COMP_SIG`, owner
    /// decision D4): both records share one CKA_ID, neither has a secondary
    /// CKA_ID or cached material, Get of the public key returns the engine's
    /// composite SPKI, and the key both acts as a CA (CreateKeyPair →
    /// bootstrap root) and certifies a second composite leaf whose chain
    /// validates; a tampered leaf does not.
    #[test]
    fn composite_create_key_pair_is_one_engine_object_and_certifies() {
        use crate::kmip30::ops::CertifyRequest;
        use crate::kmip30::{KeyFormatType, SignatureValidity};
        use softhsmrustv3::constants as c;

        let (_ring, mut d, _guard) = deps_with_engine(PERMISSIVE_POLICY);
        let session = d.engine_session.unwrap();
        let algo = KmipAlgorithm::CompositeMlDsa65EcdsaP256Sha512;
        let make = |d: &Deps| {
            let req = CreateKeyPairRequest {
                common_attributes: vec![Attribute::CryptographicAlgorithm(algo)],
                private_key_attributes: vec![],
                public_key_attributes: vec![],
                seed: None,
            };
            create_key_pair(d, req, "CreateKeyPair:Sign", &AuthContext::open(), "corr").unwrap()
        };

        // ── CA: a CreateKeyPair-generated composite key, its root minted by
        // the production bootstrap.
        let ca = make(&d);
        super::super::certify::bootstrap_ca_certificate(&d, &ca.private_key_uid, "urn:test:composite-ca-cert", "Composite E2E Root", 3650)
            .expect("bootstrap composite CA cert");
        d.config.ca_key = Some(super::super::deps::CaKeyDesignation {
            private_key_uid: ca.private_key_uid.clone(),
            certificate_uid: "urn:test:composite-ca-cert".into(),
        });

        // ── Leaf: the object model.
        let resp = make(&d);
        let priv_record = d.store.get(&resp.private_key_uid).unwrap().unwrap();
        let pub_record = d.store.get(&resp.public_key_uid).unwrap().unwrap();
        assert_eq!(priv_record.algorithm, algo);
        assert_eq!(pub_record.algorithm, algo);
        assert!(!priv_record.pkcs11_cka_id.is_empty());
        assert_eq!(priv_record.pkcs11_cka_id, pub_record.pkcs11_cka_id, "one key pair, one CKA_ID");
        assert_eq!(priv_record.pkcs11_cka_id_secondary, None, "no two-handle form");
        assert_eq!(pub_record.pkcs11_cka_id_secondary, None);
        assert!(priv_record.key_material.is_none() && pub_record.key_material.is_none());
        for (uid, class) in [(&resp.private_key_uid, ObjectType::PrivateKey), (&resp.public_key_uid, ObjectType::PublicKey)] {
            let rec = d.store.get(uid).unwrap().unwrap();
            let h = super::super::helpers::find_handle_for_object(session, &rec.pkcs11_cka_id, class).unwrap().unwrap();
            assert_eq!(softhsmrustv3::native::get_attribute_u32(session, h, c::CKA_KEY_TYPE), Some(c::CKK_COMP_SIG));
            assert_eq!(
                softhsmrustv3::native::get_attribute_u32(session, h, c::CKA_PARAMETER_SET),
                Some(algo.composite_ckp().unwrap().1)
            );
        }

        // Get of the public key → the composite SPKI (X_509).
        let got = super::super::get::get(
            &d,
            crate::kmip30::GetRequest { uid: resp.public_key_uid.clone(), key_format_type: None, key_wrapping_specification: None },
            &AuthContext::open(),
            "corr-get",
        )
        .unwrap();
        assert_eq!(got.key_block.key_format_type, KeyFormatType::X509);
        let pub_h = super::super::helpers::find_handle_for_object(session, &pub_record.pkcs11_cka_id, ObjectType::PublicKey)
            .unwrap()
            .unwrap();
        assert_eq!(Some(got.key_block.key_value.clone()), softhsmrustv3::native::get_attribute(session, pub_h, c::CKA_PUBLIC_KEY_INFO));
        {
            use der::Decode;
            let spki = spki::SubjectPublicKeyInfoOwned::from_der(&got.key_block.key_value).unwrap();
            assert_eq!(spki.algorithm.oid.to_string(), algo.composite_params().unwrap().oid());
        }

        // ── Certify the leaf under the composite CA and validate the chain.
        let certify_resp = super::super::certify::certify(
            &d,
            CertifyRequest { uid: Some(resp.public_key_uid.clone()), ..CertifyRequest::default() },
            &AuthContext::open(),
            "corr-certify-leaf",
        )
        .expect("Certify the composite leaf under the composite CA");
        let leaf = d.store.get(&certify_resp.uid).unwrap().unwrap().certificate_value.unwrap();
        let ca_cert = d.store.get("urn:test:composite-ca-cert").unwrap().unwrap().certificate_value.unwrap();
        assert_eq!(
            super::super::validate::validate_chain(d.engine_session, &[leaf.clone(), ca_cert.clone()], time::OffsetDateTime::now_utc()),
            SignatureValidity::Valid,
        );
        let mut tampered = leaf;
        let last = tampered.len() - 1;
        tampered[last] ^= 0xff;
        assert_eq!(
            super::super::validate::validate_chain(d.engine_session, &[tampered, ca_cert], time::OffsetDateTime::now_utc()),
            SignatureValidity::Invalid,
        );
    }
}
