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
        // KMIP 3.0 §11 — `Object Destroyed` (0x36) is the spec-defined
        // reason for accessing a Destroyed-state object via Get.
        // BL-M-8 step #5 pins this code (vs the generic 0x0d
        // `ObjectArchived` which is for the Archive op family).
        return Err(fail_err(
            deps,
            correlation_id,
            "Get",
            KmipError::object_destroyed(&req.uid),
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

    // KMIP 3.0 §11 — `Extractable=false` blocks ALL key-material export,
    // wrapped or not: `Not Extractable` (0x17). Checked before Sensitive
    // because it is unconditional (a KeyWrappingSpecification does not
    // lift it).
    if obj.extractable == Some(false) {
        return Err(fail_err(
            deps,
            correlation_id,
            "Get",
            KmipError::not_extractable(format!("object {} is not Extractable", req.uid)),
        ));
    }
    // KMIP 3.0 §11 — `Sensitive=true` blocks only PLAINTEXT export:
    // `Sensitive` (0x16). With a KeyWrappingSpecification the material
    // leaves wrapped under the named KEK, which is the point of wrapping
    // (BL-M-12 pins the 0x16 reason on an unwrapped Get of a
    // Sensitive=true object).
    if obj.sensitive == Some(true) && req.key_wrapping_specification.is_none() {
        return Err(fail_err(
            deps,
            correlation_id,
            "Get",
            KmipError::sensitive(format!(
                "object {} is Sensitive; Get requires a Key Wrapping Specification",
                req.uid
            )),
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
    // FAIL with `Sensitive`/`NotExtractable` (see below) — never a
    // zero-length KeyValue (compliance-audit B-4).
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
            // Engine-held private key: the material lives behind the
            // PKCS#11 CKA_SENSITIVE gate and is never extractable in
            // the clear. compliance-audit B-4: fail instead of the old
            // zero-length OpaqueObject KeyValue hack. Not corpus-pinned:
            // no transcript Gets an engine-held private key (BL-M-13
            // Gets a Registered DSA key whose material is
            // client-supplied, and is skipped as deprecated anyway).
            ObjectType::PrivateKey => {
                return Err(fail_err(
                    deps,
                    correlation_id,
                    "Get",
                    if obj.sensitive == Some(true) {
                        KmipError::sensitive(format!(
                            "private key {} material is held by the engine and is Sensitive",
                            req.uid
                        ))
                    } else {
                        KmipError::not_extractable(format!(
                            "private key {} material is held by the engine and is not extractable",
                            req.uid
                        ))
                    },
                ));
            }
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

    // KMIP 3.0 §6.1.23 — `Key Wrapping Specification`: return the key
    // material wrapped under the referenced wrap key. AX-M-2 pins
    // WrappingMethod=Encrypt + BlockCipherMode=NISTKeyWrap (AES-KW,
    // RFC 3394) over the TTLV-encoded KeyValue (default Encoding
    // Option = TTLV Encoding).
    let (key_value, key_wrapping_data) = match &req.key_wrapping_specification {
        None => (key_value, None),
        Some(spec) => {
            let wrapped = wrap_key_value(deps, spec, &key_value, correlation_id)?;
            (wrapped, Some(spec.clone()))
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
            key_wrapping_data,
        },
        opaque_data_type,
    })
}

/// AES-KW wrap of the TTLV-encoded KeyValue under the wrap key named by
/// the request's `KeyWrappingSpecification`.
fn wrap_key_value(
    deps: &Deps,
    spec: &crate::kmip30::KeyWrappingSpec,
    key_material: &[u8],
    correlation_id: &str,
) -> Result<Vec<u8>> {
    use crate::error::ResultReason;
    // §11 Wrapping Method — only `Encrypt` (0x01) is implemented.
    if spec.wrapping_method != 0x01 {
        return Err(fail_err(deps, correlation_id, "Get",
            KmipError::failed(
                ResultReason::OperationNotSupported,
                format!("Wrapping Method {:#x} not supported (only Encrypt)", spec.wrapping_method),
            )));
    }
    // §11 Block Cipher Mode — NISTKeyWrap (0x0d) selects AES-KW. Absent
    // CP defaults to NISTKeyWrap as well (the only supported wrap mode).
    let mode = spec
        .cryptographic_parameters
        .as_ref()
        .and_then(|cp| cp.block_cipher_mode)
        .unwrap_or(0x0d);
    if mode != 0x0d {
        return Err(fail_err(deps, correlation_id, "Get",
            KmipError::failed(
                ResultReason::OperationNotSupported,
                format!("Block Cipher Mode {mode:#x} not supported for wrapping (only NISTKeyWrap)"),
            )));
    }
    let wrap_key = deps
        .store
        .get(&spec.encryption_key_uid)?
        .ok_or_else(|| fail_err(deps, correlation_id, "Get",
            KmipError::object_not_found(&spec.encryption_key_uid)))?;
    // §3.4 lifecycle + §11 usage — the wrap key must be usable for WrapKey.
    if wrap_key.state != State::Active {
        return Err(fail_err(deps, correlation_id, "Get",
            super::helpers::non_active_state_error(&spec.encryption_key_uid, wrap_key.state)));
    }
    if !wrap_key.usage_mask.contains(crate::kmip30::UsageMask::WRAP_KEY) {
        return Err(fail_err(deps, correlation_id, "Get",
            KmipError::permission_denied(
                format!("wrap key {} lacks WrapKey usage", spec.encryption_key_uid),
            )));
    }
    // KEK lookup mirrors Get's material tiers: Register-supplied bytes
    // first, then the engine (Create-generated keys live behind
    // CKA_VALUE — AX-M-2's wrap key is Created, not Registered).
    let kek: Vec<u8> = match &wrap_key.key_material {
        Some(bytes) => bytes.clone(),
        None => deps
            .engine_session
            .and_then(|session| {
                softhsmrustv3::native::find_by_cka_id(session, &wrap_key.pkcs11_cka_id)
                    .ok()
                    .flatten()
                    .and_then(|h| {
                        softhsmrustv3::native::get_attribute(
                            session,
                            h,
                            softhsmrustv3::constants::CKA_VALUE,
                        )
                    })
            })
            .ok_or_else(|| {
                fail_err(deps, correlation_id, "Get",
                    KmipError::failed(
                        ResultReason::OperationNotSupported,
                        "wrap key has no exportable material".to_string(),
                    ))
            })?,
    };
    // Wrap target: TTLV-encoded KeyValue (default TTLV Encoding Option);
    // TTLV framing pads to 8 bytes, satisfying AES-KW's input contract.
    let plaintext = crate::kmip30::ttlv_encode_key_value(key_material);
    emit_pkcs11(deps, correlation_id, "C_WrapKey",
        Some(softhsmrustv3::constants::CKM_AES_KEY_WRAP), 0, "CKR_OK");
    softhsmrustv3::native::aes_key_wrap(&kek, &plaintext)
        .map_err(|rv| fail_err(deps, correlation_id, "Get",
            super::helpers::ck_rv_to_kmip_error(rv, "Get:wrap")))
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
        let r = get(&d, GetRequest { uid: "u".into(), key_wrapping_specification: None }, "c").unwrap();
        assert_eq!(r.key_block.key_format_type, KeyFormatType::Raw);
        assert_eq!(r.key_block.cryptographic_length, 256);
    }

    #[test]
    fn get_engine_held_private_key_fails_not_empty_keyblock() {
        // compliance-audit B-4: engine-held private key material must
        // FAIL, never surface as a zero-length OpaqueObject KeyValue.
        let d = deps_with();
        put(&d, "u", ObjectType::PrivateKey, State::Active);
        let err = get(&d, GetRequest { uid: "u".into(), key_wrapping_specification: None }, "c").unwrap_err();
        assert_eq!(err.result_reason(), crate::error::ResultReason::NotExtractable);
    }

    #[test]
    fn get_engine_held_sensitive_private_key_fails_sensitive() {
        let d = deps_with();
        put(&d, "u", ObjectType::PrivateKey, State::Active);
        let mut obj = d.store.get("u").unwrap().unwrap();
        obj.sensitive = Some(true);
        d.store.update(obj).unwrap();
        let err = get(&d, GetRequest { uid: "u".into(), key_wrapping_specification: None }, "c").unwrap_err();
        assert_eq!(err.result_reason(), crate::error::ResultReason::Sensitive);
    }

    #[test]
    fn get_sensitive_without_wrapping_fails_0x16() {
        let d = deps_with();
        put(&d, "u", ObjectType::SymmetricKey, State::Active);
        let mut obj = d.store.get("u").unwrap().unwrap();
        obj.sensitive = Some(true);
        obj.key_material = Some(vec![0x11; 32]);
        d.store.update(obj).unwrap();
        let err = get(&d, GetRequest { uid: "u".into(), key_wrapping_specification: None }, "c").unwrap_err();
        assert_eq!(err.result_reason(), crate::error::ResultReason::Sensitive);
    }

    #[test]
    fn get_sensitive_with_wrapping_succeeds_wrapped() {
        let d = deps_with();
        // Target key: Sensitive=true with client-supplied material.
        put(&d, "u", ObjectType::SymmetricKey, State::Active);
        let mut obj = d.store.get("u").unwrap().unwrap();
        obj.sensitive = Some(true);
        obj.key_material = Some(vec![0x11; 32]);
        d.store.update(obj).unwrap();
        // Wrap key (KEK): Active with WrapKey usage + material.
        put(&d, "kek", ObjectType::SymmetricKey, State::Active);
        let mut kek = d.store.get("kek").unwrap().unwrap();
        kek.usage_mask = UsageMask::WRAP_KEY;
        kek.key_material = Some(vec![0x22; 32]);
        d.store.update(kek).unwrap();
        let spec = crate::kmip30::KeyWrappingSpec {
            wrapping_method: 0x01,
            encryption_key_uid: "kek".into(),
            cryptographic_parameters: None,
        };
        let r = get(&d, GetRequest { uid: "u".into(), key_wrapping_specification: Some(spec.clone()) }, "c").unwrap();
        assert_eq!(r.key_block.key_wrapping_data, Some(spec));
        assert!(!r.key_block.key_value.is_empty(), "wrapped material returned");
        // AES-KW output = TTLV(KeyValue) length + 8-byte integrity block.
        assert_ne!(r.key_block.key_value, vec![0x11; 32], "material must not leave in the clear");
    }

    #[test]
    fn get_not_extractable_fails_0x17_even_with_wrapping() {
        let d = deps_with();
        put(&d, "u", ObjectType::SymmetricKey, State::Active);
        let mut obj = d.store.get("u").unwrap().unwrap();
        obj.extractable = Some(false);
        obj.key_material = Some(vec![0x11; 32]);
        d.store.update(obj).unwrap();
        // Without wrapping.
        let err = get(&d, GetRequest { uid: "u".into(), key_wrapping_specification: None }, "c").unwrap_err();
        assert_eq!(err.result_reason(), crate::error::ResultReason::NotExtractable);
        // With wrapping — Extractable=false is unconditional.
        let spec = crate::kmip30::KeyWrappingSpec {
            wrapping_method: 0x01,
            encryption_key_uid: "kek".into(),
            cryptographic_parameters: None,
        };
        let err = get(&d, GetRequest { uid: "u".into(), key_wrapping_specification: Some(spec) }, "c").unwrap_err();
        assert_eq!(err.result_reason(), crate::error::ResultReason::NotExtractable);
    }

    #[test]
    fn get_destroyed_returns_object_destroyed() {
        let d = deps_with();
        put(&d, "u", ObjectType::SymmetricKey, State::Destroyed);
        let err = get(&d, GetRequest { uid: "u".into(), key_wrapping_specification: None }, "c").unwrap_err();
        assert_eq!(err.result_reason(), crate::error::ResultReason::ObjectDestroyed);
    }

    #[test]
    fn get_missing_uid() {
        let d = deps_with();
        let err = get(&d, GetRequest { uid: "ghost".into(), key_wrapping_specification: None }, "c").unwrap_err();
        assert_eq!(err.result_reason(), crate::error::ResultReason::ObjectNotFound);
    }
}
