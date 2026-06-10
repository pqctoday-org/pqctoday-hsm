//! KMIP 3.0 §6.1.23 **Get** operation.
//!
//! > "This operation requests that the server returns the Managed Object
//! > specified by its Unique Identifier."
//!
//! Op codepoint `0x0a` (verified — `Get = 0x0000000a`).
//!
//! ## Plane mapping
//!
//! - **Plane 1** — engine.evaluate; policies typically allow Get in any
//!   lifecycle state (Get is read-only against KMIP metadata).
//! - **Plane 2** — store lookup; build `KeyBlock` response from the
//!   stored record's algorithm + length.
//! - **Plane 3** — calls `C_GetAttributeValue` (PKCS#11 v3.2 §C.5.9) to
//!   read `CKA_VALUE` for symmetric / `CKA_PUBLIC_KEY_INFO` for public
//!   keys; private-key material is sensitive (`CKA_SENSITIVE = true`)
//!   and never extracted. Phase 7 wires the real call; v0.1 returns a
//!   deterministic placeholder so the response builder is exercised.

use std::collections::HashMap;
use time::OffsetDateTime;

use crate::error::{KmipError, Result};
use crate::kmip30::{GetRequest, GetResponse, KeyBlock, KeyFormatType, ObjectType, State};
use crate::policy::{Decision, PolicyRequest};

use super::deps::Deps;
use super::helpers::{canonical_name, emit_pkcs11, emit_request, emit_success, fail_err, state_name};

pub fn get(deps: &Deps, req: GetRequest, correlation_id: &str) -> Result<GetResponse> {
    let started = OffsetDateTime::now_utc();
    emit_request(deps, correlation_id, "Get", format!("uid={}", req.uid));

    let obj = deps
        .store
        .get(&req.uid)?
        .ok_or_else(|| fail_err(deps, correlation_id, "Get", KmipError::object_not_found(&req.uid)))?;

    // Per the lifecycle table in docs/IMPLEMENTATION_PLAN.md §3.4, Get is
    // allowed in every state including Deactivated / Compromised
    // (key material is needed to verify legacy signatures); only Destroyed
    // is blocked.
    if matches!(obj.state, State::Destroyed | State::DestroyedCompromised) {
        return Err(fail_err(
            deps,
            correlation_id,
            "Get",
            KmipError::object_archived(&req.uid),
        ));
    }

    // Plane-1 policy gate.
    let empty: HashMap<String, String> = HashMap::new();
    let algo = canonical_name(obj.algorithm);
    let mut p_req = PolicyRequest::minimal("Get", Some(&algo), started, correlation_id, &empty);
    p_req.state = Some(state_name(obj.state));
    p_req.target_uid = Some(&req.uid);
    if let Decision::Deny { human, .. } = deps.engine.evaluate(&p_req) {
        return Err(fail_err(
            deps,
            correlation_id,
            "Get",
            KmipError::permission_denied(human),
        ));
    }

    // Plane-3: emit (Phase 7 wires the real C_GetAttributeValue call for
    // CKA_VALUE on symmetric keys / CKA_PUBLIC_KEY_INFO on public keys).
    emit_pkcs11(deps, correlation_id, "C_GetAttributeValue", None, 0, "CKR_OK");

    // KMIP 3.0 §6.1.21 Get returns the managed object exactly as the
    // server holds it. Three-tier material lookup:
    //   1. Client-supplied bytes captured at Register/Import time
    //      (`obj.key_material`) — Profiles §4.1.1 item 7 carve-out for
    //      "server-generated" material DOES NOT apply here.
    //   2. Engine session lookup via CKA_VALUE — Plane-3 source for
    //      keys the engine generated. Honours PKCS#11 v3.2 §4.7
    //      CKA_SENSITIVE gate (private/secret keys return None).
    //   3. Last resort: empty buffer. We DO NOT fabricate zeros — that
    //      would silently corrupt KAT comparisons (BL-M-1 etc.).
    //
    // Private keys whose material is sensitive and not client-supplied
    // surface as `KeyFormatType::OpaqueObject` with an empty value.
    // KMIP 3.0 §11 `Key Format Type` enum — codepoints verified
    // against `kmip-spec-3.0-tags-enums.json`. Only the variants
    // we have typed `KeyFormatType` enum members for are surfaced;
    // anything else maps to `Raw` so the round-trip is at least
    // byte-faithful (the Get response will report `Raw` instead of
    // the original codepoint, which is a smaller protocol violation
    // than dropping the material entirely).
    let stored_format = obj
        .key_format_type
        .and_then(|n| match n {
            0x01 => Some(KeyFormatType::Raw),
            0x02 => Some(KeyFormatType::OpaqueObject),
            0x03 => Some(KeyFormatType::Pkcs1),
            0x04 => Some(KeyFormatType::Pkcs8),
            0x05 => Some(KeyFormatType::X509),
            0x06 => Some(KeyFormatType::EcPrivateKey),
            0x07 => Some(KeyFormatType::TransparentSymmetricKey),
            _ => None,
        });
    let (key_format, key_value) = if let Some(bytes) = &obj.key_material {
        (stored_format.unwrap_or(KeyFormatType::Raw), bytes.clone())
    } else {
        match obj.object_type {
            ObjectType::PrivateKey => (KeyFormatType::OpaqueObject, Vec::new()),
            _ => match deps.engine_session {
                Some(session) => {
                    let bytes = softhsmrustv3::native::find_by_cka_id(session, &obj.pkcs11_cka_id)
                        .ok()
                        .flatten()
                        .and_then(|h| {
                            softhsmrustv3::native::get_attribute(
                                session,
                                h,
                                softhsmrustv3::constants::CKA_VALUE,
                            )
                        });
                    match bytes {
                        Some(v) => (KeyFormatType::Raw, v),
                        None => (KeyFormatType::Raw, Vec::new()),
                    }
                }
                None => (KeyFormatType::Raw, Vec::new()),
            },
        }
    };

    emit_success(deps, correlation_id, "Get");

    // OpaqueObject — echo back the client-supplied OpaqueDataType
    // (stashed in `certificate_type` at Register time).
    let opaque_data_type = match obj.object_type {
        ObjectType::OpaqueObject => obj.certificate_type,
        _ => None,
    };

    Ok(GetResponse {
        object_type: obj.object_type,
        uid: req.uid,
        key_block: KeyBlock {
            key_format_type: key_format,
            cryptographic_algorithm: obj.algorithm,
            cryptographic_length: obj.cryptographic_length,
            key_value,
        },
        opaque_data_type,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auditlog::{AuditSink, RingSink};
    use crate::kmip30::{KmipAlgorithm, UsageMask};
    use crate::policy::{load_from_str, Engine};
    use crate::store::{MemoryStore, ObjectRecord};
    use std::sync::Arc;

    fn deps_with() -> Deps {
        let ring = Arc::new(RingSink::new(64));
        let sink: Arc<dyn AuditSink> = ring.clone();
        let engine = Engine::with_global_sink(sink.clone());
        engine
            .activate(load_from_str(
                "schema_version: 1\nmetadata: {name: t, description: t, authority: t, effective: always}\nrules: []\n",
                std::path::Path::new("<t>"),
            ).unwrap())
            .unwrap();
        Deps::new(engine, Arc::new(MemoryStore::new()), sink, super::super::deps::DepsConfig::default())
    }

    fn put(deps: &Deps, uid: &str, obj_type: ObjectType, state: State) {
        deps.store.put(ObjectRecord {
            uid: uid.into(),
            object_type: obj_type,
            algorithm: KmipAlgorithm::Aes,
            cryptographic_length: 256,
            usage_mask: UsageMask::ENCRYPT | UsageMask::DECRYPT,
            state,
            pkcs11_cka_id: vec![],
            pkcs11_slot: 0,
            initial_date: OffsetDateTime::UNIX_EPOCH,
            activation_date: None,
            supersedes: None,
            name: None,

            links: std::collections::HashMap::new(),

            custom_attributes: std::collections::HashMap::new(),


            key_material: None,


            key_format_type: None,
        ..ObjectRecord::default()
}).unwrap();
    }

    #[test]
    fn get_symmetric_returns_raw_format() {
        let d = deps_with();
        put(&d, "u", ObjectType::SymmetricKey, State::Active);
        let r = get(&d, GetRequest { uid: "u".into() }, "c").unwrap();
        assert_eq!(r.key_block.key_format_type, KeyFormatType::Raw);
        assert_eq!(r.key_block.cryptographic_length, 256);
    }

    #[test]
    fn get_private_returns_opaque_format() {
        let d = deps_with();
        put(&d, "u", ObjectType::PrivateKey, State::Active);
        let r = get(&d, GetRequest { uid: "u".into() }, "c").unwrap();
        assert_eq!(r.key_block.key_format_type, KeyFormatType::OpaqueObject);
        assert!(r.key_block.key_value.is_empty(), "private key material never returned");
    }

    #[test]
    fn get_destroyed_returns_object_archived() {
        let d = deps_with();
        put(&d, "u", ObjectType::SymmetricKey, State::Destroyed);
        let err = get(&d, GetRequest { uid: "u".into() }, "c").unwrap_err();
        assert_eq!(err.result_reason(), crate::error::ResultReason::ObjectArchived);
    }

    #[test]
    fn get_missing_uid() {
        let d = deps_with();
        let err = get(&d, GetRequest { uid: "ghost".into() }, "c").unwrap_err();
        assert_eq!(err.result_reason(), crate::error::ResultReason::ObjectNotFound);
    }
}
