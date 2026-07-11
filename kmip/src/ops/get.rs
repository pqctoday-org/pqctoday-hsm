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
//!   and never extracted. The handler performs the real engine read via
//!   `softhsmrustv3::native::get_attribute(CKA_VALUE)`.

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

    // K22 — storage status gate. §6.1.47 Recover: "Once the response
    // is received, the object is now on-line, and MAY be obtained
    // (e.g., via a Get operation)" — i.e. while in Archival storage
    // the material is off-line and NOT obtainable. The §11 description
    // of `Object Archived` (0x0d) is the permitting text: "The object
    // SHALL be recovered from the archive before performing the
    // operation." (Get's own §6.1.23.1 error table only lists the
    // Wrapping variant, but this server emulates material that is
    // genuinely off-line, so the honest answer is 0x0d — never an
    // auto-recover or fabricated bytes.)
    if obj.archived {
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
    if let Decision::Deny { kmip_reason, human, .. } = deps.engine.evaluate(&p_req) {
        return Err(fail_err(
            deps,
            correlation_id,
            "Get",
            KmipError::failed(kmip_reason.to_result_reason(), human),
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
    // against `kmip-spec-3.0-tags-enums.json`. K8: the typed enum now
    // carries every spec codepoint and the wire decoder rejects
    // unknown values at Register/Import time with 0x10, so the stored
    // format is surfaced faithfully — no silent `Raw` re-labeling.
    let stored_format = obj.key_format_type.and_then(KeyFormatType::from_wire_value);
    let (key_format, key_value) = if obj.object_type == ObjectType::Certificate {
        // WP-2 remediation — a Certificate's authoritative DER always
        // lives in `certificate_value`, regardless of creation path:
        // `Certify` sets both `key_material` and `certificate_value`
        // identically, but `Register` only ever sets `certificate_value`.
        // Reading it directly here (instead of falling through to the
        // key-material three-tier lookup below, which the Register path
        // never populates) makes `Get` agree with `GetAttributes
        // (CertificateValue)` for both creation paths, and removes the
        // dependency on the best-effort engine projection succeeding.
        let der = obj.certificate_value.clone().unwrap_or_default();
        (stored_format.unwrap_or(KeyFormatType::X509), der)
    } else if let Some(bytes) = &obj.key_material {
        (stored_format.unwrap_or(KeyFormatType::Raw), bytes.clone())
    } else {
        // Engine-held private key: the material lives behind the PKCS#11
        // CKA_SENSITIVE gate and is normally never extractable in the
        // clear (compliance-audit B-4: fail instead of the old
        // zero-length OpaqueObject hack). The KMIP 3.0 WD19 PQC interop
        // profile is the carve-out: a CreateKeyPair-from-seed key is
        // marked Extractable && !Sensitive (KMIP §4 Extractable), so its
        // generated material can be Got for byte-exact verification.
        if obj.object_type == ObjectType::PrivateKey
            && !(obj.extractable == Some(true) && obj.sensitive != Some(true))
        {
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
        match deps.engine_session {
            Some(session) => {
                // CreateKeyPair stores BOTH halves under one shared CKA_ID,
                // so a bare `find_by_cka_id` would return whichever the
                // engine enumerates first (the public key). Resolve the
                // handle by the object's PKCS#11 class so a PrivateKey Get
                // returns the private material (2560-byte ML-DSA-44 sk),
                // not the 1312-byte public key. (Sign uses the same
                // class-aware helper.)
                let bytes = super::helpers::find_handle_for_object(
                    session,
                    &obj.pkcs11_cka_id,
                    obj.object_type,
                )
                .ok()
                .flatten()
                .and_then(|h| {
                    softhsmrustv3::native::get_attribute(
                        session,
                        h,
                        softhsmrustv3::constants::CKA_VALUE,
                    )
                });
                // K15 — audit the engine read after it happened
                // (only when a value actually came back; the API
                // surfaces sensitive/absent values as None, not a
                // CK_RV we could log truthfully).
                if bytes.is_some() {
                    emit_pkcs11(
                        deps,
                        correlation_id,
                        "native::get_attribute(CKA_VALUE)",
                        None,
                        0,
                        "CKR_OK",
                    );
                }
                match bytes {
                    Some(v) => (KeyFormatType::Raw, v),
                    None => (KeyFormatType::Raw, Vec::new()),
                }
            }
            None => (KeyFormatType::Raw, Vec::new()),
        }
    };

    // K8 — KMIP 3.0 §6.1.23 `Key Format Type`: honor the requested
    // output format. Absent → stored; same → as-is; convertible pair
    // (Raw ↔ TransparentSymmetricKey, PKCS#1 ↔ PKCS#8 for RSA) →
    // convert; otherwise `Key Format Type Not Supported (0x10)`.
    //
    // SeedPrivateKey (KMIP 3.0 WD19 §3.4) is handled here rather than in
    // `convert_key_format` because its `KeyMaterial` pairs the engine's
    // raw private bytes (the `Key` leaf) with the generation `Seed`
    // stored on the record — `convert_key_format` only sees the bytes.
    let seed_export = req.key_format_type == Some(KeyFormatType::SeedPrivateKey as u32);
    let (key_format, key_value, seed) = if seed_export {
        let seed = obj.pqc_seed.clone().ok_or_else(|| {
            fail_err(
                deps,
                correlation_id,
                "Get",
                KmipError::key_format_type_not_supported(format!(
                    "object {} has no stored seed to satisfy a SeedPrivateKey Get",
                    req.uid
                )),
            )
        })?;
        (KeyFormatType::SeedPrivateKey, key_value, Some(seed))
    } else {
        let (f, v) = super::helpers::convert_key_format(
            key_format,
            key_value,
            req.key_format_type,
            obj.algorithm,
            obj.object_type,
        )
        .map_err(|e| fail_err(deps, correlation_id, "Get", e))?;
        (f, v, None)
    };

    // KMIP 3.0 §6.2 CryptographicLength — a CreateKeyPair-from-seed
    // record stores no explicit length, so fall back to the actual
    // material length for asymmetric keys (e.g. ML-DSA-44 private =
    // 2560 B → 20480 bits, the value the OASIS PQC KATs expect). The
    // `Key` leaf drives the length even for SeedPrivateKey. SecretData
    // keeps its 0 sentinel (no crypto metadata in the KeyBlock).
    let crypto_len = if obj.cryptographic_length == 0
        && matches!(obj.object_type, ObjectType::PrivateKey | ObjectType::PublicKey)
    {
        (key_value.len() * 8) as u32
    } else {
        obj.cryptographic_length
    };

    // KMIP 3.0 §6.1.23 — `Key Wrapping Specification`: return the key
    // material wrapped under the referenced wrap key. AX-M-2 pins
    // WrappingMethod=Encrypt + BlockCipherMode=NISTKeyWrap (AES-KW,
    // RFC 3394) over the TTLV-encoded KeyValue (default Encoding
    // Option = TTLV Encoding).
    let (key_value, key_wrapping_data) = match &req.key_wrapping_specification {
        None => (key_value, None),
        Some(spec) => {
            // K16 — the wrapping machinery (KEK lifecycle / usage-mask
            // checks, TTLV KeyValue encode, AES-KW) is shared with
            // Export via `helpers::wrap_key_value`.
            let wrapped =
                super::helpers::wrap_key_value(deps, "Get", spec, &key_value, correlation_id)?;
            (wrapped, Some(spec.clone()))
        }
    };

    // KMIP 3.0 §11 `Fresh` — True only until the object's material has
    // been exported once. A successful Get is an export, so a
    // server-generated object stops being Fresh after its first Get
    // (TL-M-3 pins False on a key that was Created then Got in TL-M-2).
    if obj.fresh == Some(true) {
        let mut updated = obj.clone();
        updated.fresh = Some(false);
        let _ = deps.store.update(updated);
    }

    emit_success(deps, correlation_id, "Get");

    // OpaqueObject — echo back the client-supplied OpaqueDataType
    // (stashed in `certificate_type` at Register time).
    let opaque_data_type = match obj.object_type {
        ObjectType::OpaqueObject => obj.certificate_type,
        _ => None,
    };

    // KMIP 3.0 §6.2 — echo the stored SecretDataType for SecretData
    // objects (ML-KEM shared secrets carry Seed = 0x02).
    let secret_data_type = match obj.object_type {
        ObjectType::SecretData => obj.secret_data_type,
        _ => None,
    };

    Ok(GetResponse {
        object_type: obj.object_type,
        uid: req.uid,
        key_block: KeyBlock {
            key_format_type: key_format,
            cryptographic_algorithm: obj.algorithm,
            cryptographic_length: crypto_len,
            key_value,
            key_wrapping_data,
        },
        opaque_data_type,
        secret_data_type,
        seed,
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

    /// K22 — archived material is off-line: Get fails `ObjectArchived`
    /// (0x0d, §11: "The object SHALL be recovered from the archive
    /// before performing the operation"); once back On-line (§6.1.47)
    /// Get works again.
    #[test]
    fn get_archived_object_fails_object_archived_until_recovered() {
        let d = deps_with();
        put(&d, "u", ObjectType::SymmetricKey, State::Active);
        let mut rec = d.store.get("u").unwrap().unwrap();
        rec.archived = true;
        d.store.update(rec).unwrap();
        let err = get(&d, GetRequest {
            uid: "u".into(), key_format_type: None, key_wrapping_specification: None,
        }, "c").unwrap_err();
        assert_eq!(err.result_reason(), crate::error::ResultReason::ObjectArchived);
        // Recover semantics: storage status back On-line → Get succeeds.
        let mut rec = d.store.get("u").unwrap().unwrap();
        rec.archived = false;
        d.store.update(rec).unwrap();
        assert!(get(&d, GetRequest {
            uid: "u".into(), key_format_type: None, key_wrapping_specification: None,
        }, "c").is_ok());
    }

    #[test]
    fn get_symmetric_returns_raw_format() {
        let d = deps_with();
        put(&d, "u", ObjectType::SymmetricKey, State::Active);
        let r = get(&d, GetRequest { uid: "u".into(), key_format_type: None, key_wrapping_specification: None }, "c").unwrap();
        assert_eq!(r.key_block.key_format_type, KeyFormatType::Raw);
        assert_eq!(r.key_block.cryptographic_length, 256);
    }

    #[test]
    fn get_engine_held_private_key_fails_not_empty_keyblock() {
        // compliance-audit B-4: engine-held private key material must
        // FAIL, never surface as a zero-length OpaqueObject KeyValue.
        let d = deps_with();
        put(&d, "u", ObjectType::PrivateKey, State::Active);
        let err = get(&d, GetRequest { uid: "u".into(), key_format_type: None, key_wrapping_specification: None }, "c").unwrap_err();
        assert_eq!(err.result_reason(), crate::error::ResultReason::NotExtractable);
    }

    #[test]
    fn get_engine_held_sensitive_private_key_fails_sensitive() {
        let d = deps_with();
        put(&d, "u", ObjectType::PrivateKey, State::Active);
        let mut obj = d.store.get("u").unwrap().unwrap();
        obj.sensitive = Some(true);
        d.store.update(obj).unwrap();
        let err = get(&d, GetRequest { uid: "u".into(), key_format_type: None, key_wrapping_specification: None }, "c").unwrap_err();
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
        let err = get(&d, GetRequest { uid: "u".into(), key_format_type: None, key_wrapping_specification: None }, "c").unwrap_err();
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
            encoding_option: None,
            mac_signature_key_information_present: false,
        };
        let r = get(&d, GetRequest { uid: "u".into(), key_format_type: None, key_wrapping_specification: Some(spec.clone()) }, "c").unwrap();
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
        let err = get(&d, GetRequest { uid: "u".into(), key_format_type: None, key_wrapping_specification: None }, "c").unwrap_err();
        assert_eq!(err.result_reason(), crate::error::ResultReason::NotExtractable);
        // With wrapping — Extractable=false is unconditional.
        let spec = crate::kmip30::KeyWrappingSpec {
            wrapping_method: 0x01,
            encryption_key_uid: "kek".into(),
            cryptographic_parameters: None,
            encoding_option: None,
            mac_signature_key_information_present: false,
        };
        let err = get(&d, GetRequest { uid: "u".into(), key_format_type: None, key_wrapping_specification: Some(spec) }, "c").unwrap_err();
        assert_eq!(err.result_reason(), crate::error::ResultReason::NotExtractable);
    }

    #[test]
    fn get_destroyed_returns_object_destroyed() {
        let d = deps_with();
        put(&d, "u", ObjectType::SymmetricKey, State::Destroyed);
        let err = get(&d, GetRequest { uid: "u".into(), key_format_type: None, key_wrapping_specification: None }, "c").unwrap_err();
        assert_eq!(err.result_reason(), crate::error::ResultReason::ObjectDestroyed);
    }

    #[test]
    fn get_missing_uid() {
        let d = deps_with();
        let err = get(&d, GetRequest { uid: "ghost".into(), key_format_type: None, key_wrapping_specification: None }, "c").unwrap_err();
        assert_eq!(err.result_reason(), crate::error::ResultReason::ObjectNotFound);
    }

    // ── K8 — requested Key Format Type on Get ───────────────────────

    fn put_with_material(d: &Deps, uid: &str, stored_format: u32) {
        put(d, uid, ObjectType::SymmetricKey, State::Active);
        let mut obj = d.store.get(uid).unwrap().unwrap();
        obj.key_material = Some(vec![0x42; 32]);
        obj.key_format_type = Some(stored_format);
        d.store.update(obj).unwrap();
    }

    fn get_fmt(d: &Deps, uid: &str, requested: Option<u32>) -> Result<GetResponse> {
        get(d, GetRequest {
            uid: uid.into(),
            key_format_type: requested,
            key_wrapping_specification: None,
        }, "c")
    }

    #[test]
    fn get_requested_format_absent_returns_stored() {
        let d = deps_with();
        put_with_material(&d, "u", 0x07);
        let r = get_fmt(&d, "u", None).unwrap();
        assert_eq!(r.key_block.key_format_type, KeyFormatType::TransparentSymmetricKey);
        assert_eq!(r.key_block.key_value, vec![0x42; 32]);
    }

    #[test]
    fn get_converts_raw_to_transparent_symmetric_key() {
        let d = deps_with();
        put_with_material(&d, "u", 0x01);
        let r = get_fmt(&d, "u", Some(0x07)).unwrap();
        assert_eq!(r.key_block.key_format_type, KeyFormatType::TransparentSymmetricKey);
        assert_eq!(r.key_block.key_value, vec![0x42; 32], "same bytes, different wrapping");
    }

    #[test]
    fn get_converts_transparent_symmetric_key_to_raw() {
        let d = deps_with();
        put_with_material(&d, "u", 0x07);
        let r = get_fmt(&d, "u", Some(0x01)).unwrap();
        assert_eq!(r.key_block.key_format_type, KeyFormatType::Raw);
        assert_eq!(r.key_block.key_value, vec![0x42; 32]);
    }

    #[test]
    fn get_unsupported_conversion_fails_0x10() {
        // Raw symmetric material cannot become PKCS#8.
        let d = deps_with();
        put_with_material(&d, "u", 0x01);
        let err = get_fmt(&d, "u", Some(0x04)).unwrap_err();
        assert_eq!(err.result_reason(), crate::error::ResultReason::KeyFormatTypeNotSupported);
    }

    #[test]
    fn get_unknown_requested_codepoint_fails_0x10() {
        // 0x0E is (Reserved) in the §11 Key Format Type table.
        let d = deps_with();
        put_with_material(&d, "u", 0x01);
        let err = get_fmt(&d, "u", Some(0x0E)).unwrap_err();
        assert_eq!(err.result_reason(), crate::error::ResultReason::KeyFormatTypeNotSupported);
    }

    #[test]
    fn get_pkcs8_to_pkcs1_conversion_for_rsa_private_key() {
        use rsa::pkcs1::EncodeRsaPrivateKey;
        use rsa::pkcs8::EncodePrivateKey;
        let d = deps_with();
        put(&d, "u", ObjectType::PrivateKey, State::Active);
        let key = crate::ops::test_rsa_fixture::rsa_key();
        let mut obj = d.store.get("u").unwrap().unwrap();
        obj.algorithm = KmipAlgorithm::Rsa;
        obj.key_material = Some(key.to_pkcs8_der().unwrap().as_bytes().to_vec());
        obj.key_format_type = Some(0x04);
        d.store.update(obj).unwrap();
        let r = get_fmt(&d, "u", Some(0x03)).unwrap();
        assert_eq!(r.key_block.key_format_type, KeyFormatType::Pkcs1);
        assert_eq!(r.key_block.key_value, key.to_pkcs1_der().unwrap().as_bytes().to_vec());
    }
}
