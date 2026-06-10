//! KMIP 3.0 Group C: Register / Import / Export.
//!
//! Spec mapping:
//!
//! - Register §6.1.48 — register a managed object the client created
//!   elsewhere; server assigns a UID (or honors a client-supplied one
//!   if not already in use).
//! - Import   §6.1.29 — like Register but the client always specifies
//!   the UID; ReplaceExisting flag controls overwrite semantics.
//! - Export   §6.1.22 — return a managed object + all of its
//!   attributes (richer than Get, which omits the attribute set).
//!
//! All three honor the spec-mandated error reasons listed in their
//! respective Error Handling tables.

use std::collections::HashMap;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::{KmipError, Result, ResultReason};
use crate::kmip30::{
    Attribute, ExportRequest, ExportResponse, ImportRequest, ImportResponse, KeyBlock,
    KeyFormatType, ObjectType, RegisterRequest, RegisterResponse, State, UsageMask,
};
#[allow(unused_imports)]
use ObjectType as _ObjectType;
use crate::policy::{Decision, PolicyRequest};
use crate::store::ObjectRecord;

use super::deps::Deps;
use super::helpers::{canonical_name, emit_request, emit_success, fail_err};

// ── Register ───────────────────────────────────────────────────────────────

pub fn register(
    deps: &Deps,
    req: RegisterRequest,
    correlation_id: &str,
) -> Result<RegisterResponse> {
    let started = OffsetDateTime::now_utc();
    emit_request(
        deps,
        correlation_id,
        "Register",
        format!("object_type={:?} attrs={}", req.object_type, req.attributes.len()),
    );

    // Per §6.1.48 Table 395: if the object is cryptographic, certain
    // attributes are REQUIRED. CryptographicAlgorithm + Length may be
    // omitted only if encapsulated in the KeyBlock. Our handler accepts
    // either form.
    let x = extract_attrs(&req.attributes);
    let (algorithm, length, usage_mask, name, supplied_uid) =
        (x.algorithm, x.length, x.usage, x.name.clone(), x.uid.clone());

    let key_block = req.managed_object.as_ref();
    let resolved_algorithm = algorithm.or(key_block.map(|kb| kb.cryptographic_algorithm));
    let resolved_length = length.or(key_block.map(|kb| kb.cryptographic_length));

    // Plane-1 policy gate. Treat Register as Create from a policy POV —
    // the engine evaluates Algorithm + UsageMask the same way.
    let empty: HashMap<String, String> = HashMap::new();
    let algo_str = resolved_algorithm.map(canonical_name);
    let mut p_req = PolicyRequest::minimal(
        "Register",
        algo_str.as_deref(),
        started,
        correlation_id,
        &empty,
    );
    p_req.key_length = resolved_length;
    p_req.usage_mask = usage_mask;
    if let Decision::Deny { human, .. } = deps.engine.evaluate(&p_req) {
        return Err(fail_err(deps, correlation_id, "Register", KmipError::permission_denied(human)));
    }

    // KMIP 3.0 §6.1.48 — Certificate / OpaqueObject Registers are not
    // required to carry CryptographicAlgorithm (the object itself is
    // not a cryptographic key in the §11 attribute-table sense). All
    // other ObjectTypes (Symmetric/Public/Private/Secret) MUST supply
    // the algorithm either in the Attributes bag or the KeyBlock.
    let kmip_algorithm = match resolved_algorithm {
        Some(a) => a,
        None if matches!(
            req.object_type,
            ObjectType::Certificate | ObjectType::SecretData | ObjectType::OpaqueObject
        ) => {
            // Sentinel: the algorithm slot is required by ObjectRecord
            // but isn't surfaced in Certificate / SecretData / OpaqueObject
            // GetAttributes responses (CryptographicAlgorithm is not in
            // their §11 attribute table). Rsa is harmless; never inspected.
            crate::kmip30::KmipAlgorithm::Rsa
        }
        None => return Err(fail_err(deps, correlation_id, "Register", KmipError::failed(
            ResultReason::MissingData,
            "Register requires CryptographicAlgorithm (in Attributes or KeyBlock)".to_string(),
        ))),
    };

    // KMIP 3.0 §6.1.48 + §11 Result Reason — `Name` MUST be unique
    // across the server's managed objects; a duplicate yields
    // `NonUniqueNameAttribute` (0x35), NOT a generic `InvalidField`.
    // BL-M-8 exercises this with a deliberate duplicate Register.
    if let Some(ref n) = name {
        let dup = deps
            .store
            .find(&|r| r.name.as_deref() == Some(n.as_str()))
            .unwrap_or_default();
        if !dup.is_empty() {
            return Err(fail_err(
                deps,
                correlation_id,
                "Register",
                KmipError::non_unique_name_attribute(n),
            ));
        }
    }

    // Per §6.1.48: honor a client-supplied UniqueIdentifier (must be
    // unique) — else allocate one.
    let uid = if let Some(client_uid) = supplied_uid {
        if deps.store.get(&client_uid)?.is_some() {
            return Err(fail_err(deps, correlation_id, "Register", KmipError::failed(
                ResultReason::ObjectAlreadyExists,
                format!("UID {client_uid:?} already exists"),
            )));
        }
        client_uid
    } else {
        format!("urn:pqctoday:obj:{}", Uuid::new_v4())
    };

    // Initial Date SHALL be set to current time per §6.1.48.
    let now = OffsetDateTime::now_utc();
    // Stable CKA_ID for this object so the KMIP layer can locate the
    // engine handle later via `find_by_cka_id` (Sign/Decrypt path).
    let cka_id_bytes = Uuid::new_v4().as_bytes().to_vec();
    let key_format_type = key_block.map(|kb| kb.key_format_type as u32);
    let key_material = key_block.map(|kb| kb.key_value.clone());

    // KMIP 3.0 §6.1.48 + §6.2 — when the client supplies an RSA
    // private key in PKCS#1 (KeyFormatType=0x03) or PKCS#8 form, we
    // create a real engine object so subsequent Sign / Decrypt can
    // find the handle. CS-AC-M-{1..6,8} pin this flow.
    //
    // KeyFormatType codepoints (KMIP §11): 3 = PKCS_1, 4 = PKCS_8.
    if let (Some(material), Some(fmt), Some(session)) =
        (key_material.as_ref(), key_format_type, deps.engine_session)
    {
        match (req.object_type, kmip_algorithm) {
            (ObjectType::PrivateKey, crate::kmip30::KmipAlgorithm::Rsa) => {
                // PKCS_1 = 3 (RSAPrivateKey), PKCS_8 = 4
                // (PrivateKeyInfo). Both surface in `sign_rsa` via
                // `RsaPrivateKey::from_pkcs8_der`.
                let pkcs8_bytes: Option<Vec<u8>> = match fmt {
                    3 => {
                        use rsa::pkcs1::DecodeRsaPrivateKey;
                        use rsa::pkcs8::EncodePrivateKey;
                        rsa::RsaPrivateKey::from_pkcs1_der(material)
                            .ok()
                            .and_then(|k| k.to_pkcs8_der().ok().map(|d| d.as_bytes().to_vec()))
                    }
                    4 => Some(material.clone()),
                    _ => None,
                };
                if let Some(pkcs8) = pkcs8_bytes {
                    let _ = softhsmrustv3::native::register_rsa_private_key_pkcs8(
                        session, &pkcs8, &cka_id_bytes, "kmip-register",
                    );
                }
            }
            (ObjectType::PublicKey, crate::kmip30::KmipAlgorithm::Rsa) => {
                // PKCS_1 RSAPublicKey or PKCS_8 SubjectPublicKeyInfo —
                // store the DER as-is; `verify_rsa` extracts the
                // modulus/exponent from CKA_VALUE.
                let _ = softhsmrustv3::native::register_rsa_public_key_der(
                    session, material, &cka_id_bytes, "kmip-register-pub",
                );
            }
            (ObjectType::SymmetricKey, alg)
                if matches!(
                    alg,
                    crate::kmip30::KmipAlgorithm::HmacSha256
                        | crate::kmip30::KmipAlgorithm::HmacSha384
                        | crate::kmip30::KmipAlgorithm::HmacSha512,
                ) =>
            {
                // HMAC keys are raw bytes; the shim's MAC path reads
                // them from CKA_VALUE.
                let _ = softhsmrustv3::native::register_generic_secret_bytes(
                    session, material, &cka_id_bytes, "kmip-register-hmac",
                );
            }
            _ => {}
        }
    }

    // KMIP 3.0 Spec §3.x lifecycle — Register honours any date
    // attributes the client supplied (ActivationDate / DeactivationDate
    // / CompromiseDate). A past Activation Date means the object is
    // born `Active`, not `PreActive`, so a subsequent Encrypt/Sign
    // succeeds without an explicit `Activate` round-trip. OASIS uses
    // `$NOW-3600` for this in the cryptographic-op conformance tests.
    let initial_state = compute_initial_state(now, &x);

    // KMIP 3.0 §6.1.2 / §11 — preserve client-supplied Custom
    // attributes (vendor-extension envelope) so GetAttributes can
    // surface them. BL-M-14 / SKFF-M-{9..11} step #0 supply
    // `<Attribute>` envelopes inside `<Attributes>`.
    let mut custom_attributes: HashMap<String, String> = HashMap::new();
    let mut links: HashMap<String, String> = HashMap::new();
    for a in &req.attributes {
        match a {
            Attribute::Custom { name, value } => {
                custom_attributes.insert(name.clone(), value.clone());
            }
            // KMIP §11 Link family — UID references the Register
            // request can stamp onto the new object. SASED-M-2
            // pins GroupLink; CS-AC tests use PublicKey/PrivateKeyLink.
            Attribute::GroupLink(uid)      => { links.insert("GroupLink".into(), uid.clone()); }
            Attribute::NextLink(uid)       => { links.insert("NextLink".into(), uid.clone()); }
            Attribute::PreviousLink(uid)   => { links.insert("PreviousLink".into(), uid.clone()); }
            Attribute::PublicKeyLink(uid)  => { links.insert("PublicKeyLink".into(), uid.clone()); }
            Attribute::PrivateKeyLink(uid) => { links.insert("PrivateKeyLink".into(), uid.clone()); }
            _ => {}
        }
    }

    // KMIP 3.0 §6.2 Certificate payload — populate cert-specific
    // attributes from the wire `Certificate` Structure (DER bytes +
    // type). `CertificateLength` is the DER byte count; the §11
    // attribute-table marks both `CertificateLength` and
    // `CertificateSubjectCN` as server-set (Read-Only).
    // certificate_payload is reused for OpaqueObject's OpaqueDataType
    // pass-through (no DER, no length, no CN). The wire decoder sets
    // `der.is_empty()` for that path.
    let (certificate_type, certificate_value, certificate_length, certificate_subject_cn) =
        match (&req.certificate_payload, req.object_type) {
            (Some((wire_ct, der)), ObjectType::Certificate) => {
                let len = der.len() as i32;
                let cn = super::der_x509::extract_subject_cn(der);
                (Some(*wire_ct), Some(der.clone()), Some(len), cn)
            }
            (Some((wire_ct, _)), ObjectType::OpaqueObject) => {
                (Some(*wire_ct), None, None, None)
            }
            _ => (None, None, None, None),
        };

    deps.store.put(ObjectRecord {
        uid: uid.clone(),
        object_type: req.object_type,
        algorithm: kmip_algorithm,
        cryptographic_length: resolved_length.unwrap_or(0),
        usage_mask: usage_mask.unwrap_or_else(UsageMask::empty),
        state: initial_state,
        pkcs11_cka_id: cka_id_bytes,
        pkcs11_slot: deps.config.pkcs11_slot,
        initial_date: now,
        activation_date: x.activation_date,
        deactivation_date: x.deactivation_date,
        compromise_date: x.compromise_date,
        compromise_occurrence_date: x.compromise_date,
        process_start_date: x.process_start_date,
        protect_stop_date: x.protect_stop_date,
        usage_limits_total: x.usage_limits_total,
        usage_limits_remaining: x.usage_limits_total,
        application_specific_information: x.application_specific_information.clone(),
        last_change_date: Some(now),
        original_creation_date: Some(now),
        supersedes: None,
        name,
        links,
        custom_attributes,
        key_material,
        key_format_type,
        cryptographic_parameters: x.cryptographic_parameters.clone(),
        certificate_type,
        certificate_value,
        certificate_length,
        certificate_subject_cn,
        ..ObjectRecord::default()
    })?;

    emit_success(deps, correlation_id, "Register");
    Ok(RegisterResponse { uid })
}

// ── Import ─────────────────────────────────────────────────────────────────

pub fn import_object(
    deps: &Deps,
    req: ImportRequest,
    correlation_id: &str,
) -> Result<ImportResponse> {
    let started = OffsetDateTime::now_utc();
    emit_request(
        deps,
        correlation_id,
        "Import",
        format!(
            "uid={} object_type={:?} replace={}",
            req.uid, req.object_type, req.replace_existing
        ),
    );

    let (algorithm, length, usage_mask, name, _) = extract_attributes(&req.attributes);
    let key_block = req.managed_object.as_ref();
    let resolved_algorithm = algorithm.or(key_block.map(|kb| kb.cryptographic_algorithm));
    let resolved_length = length.or(key_block.map(|kb| kb.cryptographic_length));

    let empty: HashMap<String, String> = HashMap::new();
    let algo_str = resolved_algorithm.map(canonical_name);
    let mut p_req = PolicyRequest::minimal(
        "Import",
        algo_str.as_deref(),
        started,
        correlation_id,
        &empty,
    );
    p_req.key_length = resolved_length;
    p_req.usage_mask = usage_mask;
    if let Decision::Deny { human, .. } = deps.engine.evaluate(&p_req) {
        return Err(fail_err(deps, correlation_id, "Import", KmipError::permission_denied(human)));
    }

    let kmip_algorithm = resolved_algorithm.ok_or_else(|| {
        fail_err(deps, correlation_id, "Import", KmipError::failed(
            ResultReason::MissingData,
            "Import requires CryptographicAlgorithm".to_string(),
        ))
    })?;

    // Per §6.1.29: "If absent or false [for ReplaceExisting] and an
    // object exists with the same Unique Identifier then an error
    // SHALL be returned."
    let existing = deps.store.get(&req.uid)?;
    if existing.is_some() {
        if req.replace_existing {
            deps.store.remove(&req.uid)?;
        } else {
            return Err(fail_err(deps, correlation_id, "Import", KmipError::failed(
                ResultReason::ObjectAlreadyExists,
                format!("UID {:?} already exists and ReplaceExisting was not set", req.uid),
            )));
        }
    }

    let now = OffsetDateTime::now_utc();
    let key_material = key_block.map(|kb| kb.key_value.clone());
    let key_format_type = key_block.map(|kb| kb.key_format_type as u32);

    deps.store.put(ObjectRecord {
        uid: req.uid.clone(),
        object_type: req.object_type,
        algorithm: kmip_algorithm,
        cryptographic_length: resolved_length.unwrap_or(0),
        usage_mask: usage_mask.unwrap_or_else(UsageMask::empty),
        state: State::PreActive,
        pkcs11_cka_id: Uuid::new_v4().as_bytes().to_vec(),
        pkcs11_slot: deps.config.pkcs11_slot,
        initial_date: now,
        activation_date: None,
        supersedes: None,
        name,
        links: HashMap::new(),
        custom_attributes: HashMap::new(),
        key_material,
        key_format_type,
        ..ObjectRecord::default()
    })?;

    emit_success(deps, correlation_id, "Import");
    Ok(ImportResponse { uid: req.uid })
}

// ── Export ─────────────────────────────────────────────────────────────────

pub fn export(
    deps: &Deps,
    req: ExportRequest,
    correlation_id: &str,
) -> Result<ExportResponse> {
    emit_request(deps, correlation_id, "Export", format!("uid={}", req.uid));

    let obj = deps.store.get(&req.uid)?.ok_or_else(|| {
        fail_err(deps, correlation_id, "Export", KmipError::not_found(&req.uid))
    })?;

    // Per §6.1.22: "If the Managed Object has been Destroyed then the
    // key material for the specified managed object SHALL not be
    // returned in the response." We still return the attributes —
    // only the KeyBlock is suppressed.
    let key_material = if matches!(obj.state, State::Destroyed | State::DestroyedCompromised) {
        None
    } else {
        obj.key_material.clone()
    };

    // Build the Attributes set the same way GetAttributes does — keep
    // this in sync if either side adds new attribute surfaces.
    let mut attributes = vec![
        Attribute::UniqueIdentifier(obj.uid.clone()),
        Attribute::ObjectType(obj.object_type),
        Attribute::CryptographicAlgorithm(obj.algorithm),
        Attribute::CryptographicUsageMask(obj.usage_mask),
        Attribute::State(obj.state),
    ];
    if obj.cryptographic_length > 0 {
        attributes.push(Attribute::CryptographicLength(obj.cryptographic_length));
    }
    if let Some(name) = &obj.name {
        attributes.push(Attribute::Name(name.clone()));
    }

    let managed_object = key_material.map(|bytes| KeyBlock {
        key_format_type: match obj.key_format_type {
            Some(0x01) | None => KeyFormatType::Raw,
            Some(_)           => KeyFormatType::Raw,
        },
        cryptographic_algorithm: obj.algorithm,
        cryptographic_length: obj.cryptographic_length,
        key_value: bytes,
    });

    emit_success(deps, correlation_id, "Export");
    Ok(ExportResponse {
        object_type: obj.object_type,
        uid: req.uid,
        attributes,
        managed_object,
    })
}

// ── Helpers ────────────────────────────────────────────────────────────────

/// Pull algorithm / length / usage mask / name / UID out of the
/// request's Attributes block. Returned tuple ordering mirrors the
/// spec's Table 395 (Register Attribute Requirements).
/// Bundle of attributes pulled from a Register/Create-style template.
///
/// `activation_date` / `deactivation_date` / `compromise_date` drive the
/// initial lifecycle state per KMIP 3.0 Spec §3.x; see
/// [`compute_initial_state`].
pub(crate) struct ExtractedAttrs {
    pub algorithm: Option<crate::kmip30::KmipAlgorithm>,
    pub length: Option<u32>,
    pub usage: Option<UsageMask>,
    pub name: Option<String>,
    pub uid: Option<String>,
    pub activation_date: Option<OffsetDateTime>,
    pub deactivation_date: Option<OffsetDateTime>,
    pub compromise_date: Option<OffsetDateTime>,
    pub process_start_date: Option<OffsetDateTime>,
    pub protect_stop_date: Option<OffsetDateTime>,
    /// KMIP §11 `Usage Limits Total` — encrypt-byte budget set at
    /// Register / Create time. `None` = unlimited. CS-BC-M-7 pins
    /// a 16-byte budget that the second Encrypt should exhaust.
    pub usage_limits_total: Option<i64>,
    /// KMIP §11 `Application Specific Information` — `(namespace,
    /// data)` pair. TL-M-2 creates a SymmetricKey with one, TL-M-3
    /// finds it via a Locate filter.
    pub application_specific_information: Option<(String, String)>,
    /// Per-key `CryptographicParameters` (KMIP §11) — the OAEP /
    /// PSS / MAC handshake parameters attached to the managed object
    /// at Register time. Read back by Encrypt / Decrypt / Sign /
    /// Verify in place of any request-time override.
    pub cryptographic_parameters: Option<crate::kmip30::CryptographicParameters>,
    /// `Quantum Safe` (KMIP §11) — client claim. The server SHALL
    /// reject the request when the claim contradicts the actual
    /// algorithm (e.g. AES + `QuantumSafe=true`). QS-M-2 pins this.
    pub quantum_safe: Option<bool>,
}

pub(crate) fn extract_attrs(attrs: &[Attribute]) -> ExtractedAttrs {
    let mut out = ExtractedAttrs {
        algorithm: None, length: None, usage: None, name: None, uid: None,
        activation_date: None, deactivation_date: None, compromise_date: None,
        process_start_date: None, protect_stop_date: None,
        cryptographic_parameters: None, quantum_safe: None,
        usage_limits_total: None,
        application_specific_information: None,
    };
    for a in attrs {
        match a {
            Attribute::CryptographicAlgorithm(alg) => out.algorithm = Some(*alg),
            Attribute::CryptographicLength(n)      => out.length = Some(*n),
            Attribute::CryptographicUsageMask(m)   => out.usage = Some(*m),
            Attribute::Name(n)                     => out.name = Some(n.clone()),
            Attribute::UniqueIdentifier(u)         => out.uid = Some(u.clone()),
            Attribute::ActivationDate(t)   => out.activation_date   = OffsetDateTime::from_unix_timestamp(*t).ok(),
            Attribute::DeactivationDate(t) => out.deactivation_date = OffsetDateTime::from_unix_timestamp(*t).ok(),
            Attribute::CompromiseDate(t)   => out.compromise_date   = OffsetDateTime::from_unix_timestamp(*t).ok(),
            Attribute::ProcessStartDate(t) => out.process_start_date = OffsetDateTime::from_unix_timestamp(*t).ok(),
            Attribute::ProtectStopDate(t)  => out.protect_stop_date  = OffsetDateTime::from_unix_timestamp(*t).ok(),
            Attribute::CryptographicParameters(cp) => out.cryptographic_parameters = Some(cp.clone()),
            Attribute::QuantumSafe(b)              => out.quantum_safe = Some(*b),
            Attribute::UsageLimitsTotal(n)         => out.usage_limits_total = Some(*n),
            Attribute::ApplicationSpecificInformation { namespace, data } => {
                out.application_specific_information = Some((namespace.clone(), data.clone()));
            }
            _ => {}
        }
    }
    out
}

/// KMIP 3.0 §11 attribute table — `Quantum Safe = true` is a
/// server claim that the wrapped key's algorithm is resistant to
/// quantum attack. ML-DSA / ML-KEM / SLH-DSA / XMSS{MT} qualify;
/// classical AES / RSA / ECDSA / DSA / EdDSA do not. QS-M-2 pins
/// this — a Create with AES + `QuantumSafe=true` must fail.
pub(crate) fn algorithm_is_quantum_safe(a: crate::kmip30::KmipAlgorithm) -> bool {
    use crate::kmip30::KmipAlgorithm::*;
    matches!(a,
        MlKem512 | MlKem768 | MlKem1024
        | MlDsa44 | MlDsa65 | MlDsa87
        | SlhDsaSha2_128s | SlhDsaSha2_128f
        | SlhDsaSha2_192s | SlhDsaSha2_192f
        | SlhDsaSha2_256s | SlhDsaSha2_256f
    )
}

/// KMIP 3.0 Spec §3.x — derive a managed-object's lifecycle state from
/// the date attributes the client supplied at Register/Create time.
///
/// Precedence (highest first):
///   1. Compromise Date ≤ now  → `Compromised`
///   2. Deactivation Date ≤ now → `Deactivated`
///   3. Activation Date ≤ now   → `Active`
///   4. otherwise              → `PreActive`
///
/// Future dates are stored verbatim but DO NOT advance the state until
/// the time arrives (a polling layer outside the scope of v0.1 would
/// re-evaluate this transition; tests in the OASIS corpus use past
/// `$NOW-3600` values exclusively, so the synchronous gate suffices).
pub(crate) fn compute_initial_state(now: OffsetDateTime, x: &ExtractedAttrs) -> State {
    if x.compromise_date.map_or(false, |t| t <= now) { State::Compromised }
    else if x.deactivation_date.map_or(false, |t| t <= now) { State::Deactivated }
    else if x.activation_date.map_or(false, |t| t <= now) { State::Active }
    else { State::PreActive }
}

// Backwards-compat shim retained while callers migrate.
fn extract_attributes(
    attrs: &[Attribute],
) -> (Option<crate::kmip30::KmipAlgorithm>, Option<u32>, Option<UsageMask>, Option<String>, Option<String>) {
    let x = extract_attrs(attrs);
    (x.algorithm, x.length, x.usage, x.name, x.uid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auditlog::{AuditSink, RingSink};
    use crate::kmip30::KmipAlgorithm;
    use crate::policy::{load_from_str, Engine};
    use crate::store::MemoryStore;
    use std::sync::Arc;

    fn deps_with() -> Deps {
        let ring = Arc::new(RingSink::new(64));
        let sink: Arc<dyn AuditSink> = ring.clone();
        let engine = Engine::with_global_sink(sink.clone());
        engine.activate(load_from_str(
            "schema_version: 1\nmetadata: {name: t, description: t, authority: t, effective: always}\nrules: []\n",
            std::path::Path::new("<t>"),
        ).unwrap()).unwrap();
        Deps::new(engine, Arc::new(MemoryStore::new()), sink, super::super::deps::DepsConfig::default())
    }

    fn raw_aes128_kb() -> KeyBlock {
        KeyBlock {
            key_format_type: KeyFormatType::Raw,
            cryptographic_algorithm: KmipAlgorithm::Aes,
            cryptographic_length: 128,
            key_value: vec![0x01; 16],
        }
    }

    #[test]
    fn register_persists_record_with_uid_and_key_bytes() {
        let d = deps_with();
        let resp = register(&d, RegisterRequest {
            object_type: ObjectType::SymmetricKey,
            attributes: vec![
                Attribute::CryptographicAlgorithm(KmipAlgorithm::Aes),
                Attribute::CryptographicLength(128),
                Attribute::CryptographicUsageMask(UsageMask::ENCRYPT | UsageMask::DECRYPT),
                Attribute::Name("test".into()),
            ],
            managed_object: Some(raw_aes128_kb()),
            protection_storage_masks: None,
            certificate_payload: None,
        }, "c").unwrap();
        let rec = d.store.get(&resp.uid).unwrap().unwrap();
        assert_eq!(rec.algorithm, KmipAlgorithm::Aes);
        assert_eq!(rec.cryptographic_length, 128);
        assert_eq!(rec.name.as_deref(), Some("test"));
        assert_eq!(rec.key_material.as_deref(), Some(&[0x01; 16][..]));
    }

    #[test]
    fn register_with_client_uid_rejects_duplicate() {
        let d = deps_with();
        let req = || RegisterRequest {
            object_type: ObjectType::SymmetricKey,
            attributes: vec![
                Attribute::UniqueIdentifier("urn:fixed".into()),
                Attribute::CryptographicAlgorithm(KmipAlgorithm::Aes),
                Attribute::CryptographicLength(128),
                Attribute::CryptographicUsageMask(UsageMask::ENCRYPT),
            ],
            managed_object: Some(raw_aes128_kb()),
            protection_storage_masks: None,
            certificate_payload: None,
        };
        let resp = register(&d, req(), "c").unwrap();
        assert_eq!(resp.uid, "urn:fixed");
        let err = register(&d, req(), "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::ObjectAlreadyExists);
    }

    #[test]
    fn import_rejects_existing_uid_without_replace() {
        let d = deps_with();
        // First create via Register.
        register(&d, RegisterRequest {
            object_type: ObjectType::SymmetricKey,
            attributes: vec![
                Attribute::UniqueIdentifier("u".into()),
                Attribute::CryptographicAlgorithm(KmipAlgorithm::Aes),
                Attribute::CryptographicLength(128),
                Attribute::CryptographicUsageMask(UsageMask::ENCRYPT),
            ],
            managed_object: Some(raw_aes128_kb()),
            protection_storage_masks: None,
            certificate_payload: None,
        }, "c").unwrap();

        let err = import_object(&d, ImportRequest {
            uid: "u".into(),
            object_type: ObjectType::SymmetricKey,
            replace_existing: false,
            key_wrap_type: None,
            attributes: vec![
                Attribute::CryptographicAlgorithm(KmipAlgorithm::Aes),
                Attribute::CryptographicUsageMask(UsageMask::ENCRYPT),
            ],
            managed_object: Some(raw_aes128_kb()),
        }, "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::ObjectAlreadyExists);
    }

    #[test]
    fn import_with_replace_overwrites_existing() {
        let d = deps_with();
        register(&d, RegisterRequest {
            object_type: ObjectType::SymmetricKey,
            attributes: vec![
                Attribute::UniqueIdentifier("u".into()),
                Attribute::CryptographicAlgorithm(KmipAlgorithm::Aes),
                Attribute::CryptographicLength(128),
                Attribute::CryptographicUsageMask(UsageMask::ENCRYPT),
            ],
            managed_object: Some(raw_aes128_kb()),
            protection_storage_masks: None,
            certificate_payload: None,
        }, "c").unwrap();

        let new_kb = KeyBlock { key_value: vec![0xAA; 16], ..raw_aes128_kb() };
        import_object(&d, ImportRequest {
            uid: "u".into(),
            object_type: ObjectType::SymmetricKey,
            replace_existing: true,
            key_wrap_type: None,
            attributes: vec![
                Attribute::CryptographicAlgorithm(KmipAlgorithm::Aes),
                Attribute::CryptographicUsageMask(UsageMask::ENCRYPT),
            ],
            managed_object: Some(new_kb),
        }, "c").unwrap();

        let rec = d.store.get("u").unwrap().unwrap();
        assert_eq!(rec.key_material.unwrap(), vec![0xAA; 16]);
    }

    #[test]
    fn export_returns_attributes_and_key_material() {
        let d = deps_with();
        let r = register(&d, RegisterRequest {
            object_type: ObjectType::SymmetricKey,
            attributes: vec![
                Attribute::CryptographicAlgorithm(KmipAlgorithm::Aes),
                Attribute::CryptographicLength(128),
                Attribute::CryptographicUsageMask(UsageMask::ENCRYPT),
                Attribute::Name("named".into()),
            ],
            managed_object: Some(raw_aes128_kb()),
            protection_storage_masks: None,
            certificate_payload: None,
        }, "c").unwrap();
        let exp = export(&d, ExportRequest {
            uid: r.uid.clone(),
            key_format_type: None,
            key_wrap_type: None,
            key_compression_type: None,
        }, "c").unwrap();
        assert_eq!(exp.uid, r.uid);
        assert_eq!(exp.object_type, ObjectType::SymmetricKey);
        assert!(exp.attributes.iter().any(|a| matches!(a, Attribute::Name(n) if n == "named")));
        assert!(exp.managed_object.is_some());
    }

    #[test]
    fn export_on_destroyed_omits_key_material() {
        let d = deps_with();
        let r = register(&d, RegisterRequest {
            object_type: ObjectType::SymmetricKey,
            attributes: vec![
                Attribute::CryptographicAlgorithm(KmipAlgorithm::Aes),
                Attribute::CryptographicLength(128),
                Attribute::CryptographicUsageMask(UsageMask::ENCRYPT),
            ],
            managed_object: Some(raw_aes128_kb()),
            protection_storage_masks: None,
            certificate_payload: None,
        }, "c").unwrap();
        // Force Destroyed state via store.
        let mut rec = d.store.get(&r.uid).unwrap().unwrap();
        rec.state = State::Destroyed;
        d.store.update(rec).unwrap();
        let exp = export(&d, ExportRequest {
            uid: r.uid,
            key_format_type: None,
            key_wrap_type: None,
            key_compression_type: None,
        }, "c").unwrap();
        assert!(exp.managed_object.is_none(), "Destroyed objects MUST NOT return key material");
    }
}
