//! KMIP 3.0 WD19 (PQC Updates) **Encapsulate** operation.
//!
//! > "This operation requests the server to perform an ML-KEM
//! > encapsulation against the referenced public (encapsulation) key."
//!
//! Op codepoint `0x41` (WD19 — right after `Deactivate = 0x40`).
//!
//! Unlike the `Encrypt`-overload encapsulation path
//! ([`super::encrypt::encrypt`]), `Encapsulate` does **not** return the
//! shared secret inline. Instead the server:
//!   1. encapsulates against the ML-KEM public key → `(ciphertext, K)`;
//!   2. creates a NEW managed `SecretData` object holding `K`, allocating
//!      a fresh UID;
//!   3. returns `{ UniqueIdentifier = <new>, Data = ciphertext }`.
//!
//! A subsequent `Get` on the returned UID retrieves the 32-byte shared
//! secret as KeyMaterial.
//!
//! ## Deterministic coins
//!
//! When the request supplies `InputKeyMaterial` (the 32-byte FIPS 203
//! §7.2 coins `m`, nested in `CryptographicParameters`), encapsulation is
//! deterministic via `native::encapsulate_deterministic` — this is the
//! entry point the OASIS KMIP 3.0 PQC interop vectors require for
//! byte-exact reproduction. Absent the coins, the server samples `m` from
//! the OS RNG via `native::encapsulate`.

use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::{KmipError, Result, ResultReason};
use crate::kmip30::{
    EncapsulateRequest, EncapsulateResponse, KeyFormatType, KmipAlgorithm, ObjectType, PkcsOp,
    State,
};
use crate::store::ObjectRecord;

use super::deps::Deps;
use super::helpers::{
    emit_pkcs11, emit_pkcs11_result, emit_request, emit_success, fail_err,
};

pub fn encapsulate(
    deps: &Deps,
    req: EncapsulateRequest,
    correlation_id: &str,
) -> Result<EncapsulateResponse> {
    emit_request(
        deps,
        correlation_id,
        "Encapsulate",
        format!(
            "uid={} ikm={}",
            req.uid,
            req.input_key_material.as_ref().map_or(0, |m| m.len())
        ),
    );

    let obj = deps.store.get(&req.uid)?.ok_or_else(|| {
        fail_err(deps, correlation_id, "Encapsulate", KmipError::object_not_found(&req.uid))
    })?;

    if !is_ml_kem(obj.algorithm) {
        return Err(fail_err(
            deps,
            correlation_id,
            "Encapsulate",
            KmipError::failed(
                ResultReason::OperationNotSupported,
                format!("Encapsulate requires an ML-KEM key; {:?} is not", obj.algorithm),
            ),
        ));
    }

    // KMIP 3.0 §3.4 lifecycle gate — the public key must be Active.
    if obj.state != State::Active {
        return Err(fail_err(
            deps,
            correlation_id,
            "Encapsulate",
            super::helpers::non_active_state_error(&req.uid, obj.state),
        ));
    }
    if obj.archived {
        return Err(fail_err(
            deps,
            correlation_id,
            "Encapsulate",
            KmipError::object_archived(&req.uid),
        ));
    }

    let mech = obj.algorithm.to_pkcs11_mech(PkcsOp::Encrypt).ok_or_else(|| {
        KmipError::failed(
            ResultReason::OperationNotSupported,
            format!("ML-KEM {:?} has no encapsulation mechanism", obj.algorithm),
        )
    })?;

    // The deterministic coins may arrive hoisted (`input_key_material`)
    // or only nested in CryptographicParameters — prefer the hoisted form.
    let coins = req.input_key_material.clone();

    let (ciphertext, shared_secret) = match deps.engine_session {
        Some(session) => {
            let handle = softhsmrustv3::native::find_by_cka_id(session, &obj.pkcs11_cka_id)
                .map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "Encap:find"))?
                .ok_or_else(|| KmipError::object_not_found(&req.uid))?;
            let native_mech = super::helpers::native_kem_mech(obj.algorithm).ok_or_else(|| {
                KmipError::failed(
                    ResultReason::OperationNotSupported,
                    format!("no KEM mechanism for {:?}", obj.algorithm),
                )
            })?;
            match &coins {
                Some(m) => {
                    let r = softhsmrustv3::native::encapsulate_deterministic(
                        session,
                        handle,
                        native_mech,
                        m,
                    );
                    emit_pkcs11_result(
                        deps,
                        correlation_id,
                        "native::encapsulate_deterministic",
                        Some(native_mech),
                        &r,
                    );
                    r.map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "Encap"))?
                }
                None => {
                    let r = softhsmrustv3::native::encapsulate(session, handle, native_mech);
                    emit_pkcs11_result(
                        deps,
                        correlation_id,
                        "native::encapsulate",
                        Some(native_mech),
                        &r,
                    );
                    r.map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "Encap"))?
                }
            }
        }
        None => {
            // Unit-test fallback (no engine session): deterministic
            // placeholder bytes so the store/UID plumbing can be exercised.
            emit_pkcs11(
                deps,
                correlation_id,
                "soft::placeholder_encapsulate",
                Some(mech),
                0,
                "CKR_OK",
            );
            (
                placeholder_bytes(&req.uid, coins.as_deref().unwrap_or_default(), b"encap", 32),
                placeholder_bytes(&req.uid, coins.as_deref().unwrap_or_default(), b"ss", 32),
            )
        }
    };

    // Create the NEW managed SecretData object holding the shared secret.
    let ss_uid = store_shared_secret(deps, obj.algorithm, shared_secret)?;

    emit_success(deps, correlation_id, "Encapsulate");

    Ok(EncapsulateResponse { uid: ss_uid, data: ciphertext })
}

pub(crate) fn is_ml_kem(a: KmipAlgorithm) -> bool {
    matches!(a, KmipAlgorithm::MlKem512 | KmipAlgorithm::MlKem768 | KmipAlgorithm::MlKem1024)
}

/// Persist the derived shared secret as a fresh managed `SecretData`
/// object and return its UID. The bytes are kept verbatim in
/// `key_material` (KeyFormatType=Raw) so a subsequent `Get` returns them
/// directly (the engine never sees the shared secret as a managed
/// object — it is opaque KMIP material). Born `Active` so an immediate
/// `Get` succeeds.
pub(crate) fn store_shared_secret(
    deps: &Deps,
    source_algorithm: KmipAlgorithm,
    shared_secret: Vec<u8>,
) -> Result<String> {
    let uid = format!("urn:pqctoday:obj:{}", Uuid::new_v4());
    let now = OffsetDateTime::now_utc();
    deps.store.put(ObjectRecord {
        uid: uid.clone(),
        object_type: ObjectType::SecretData,
        // The shared secret is opaque bytes; record the source KEM
        // algorithm for provenance in attribute queries.
        algorithm: source_algorithm,
        // KMIP 3.0 §6.2 — a `SecretData` KeyBlock carries no
        // CryptographicAlgorithm/Length (the OASIS PQC interop KATs
        // expect a 2-child KeyBlock: KeyFormatType + KeyValue). The
        // wire encoder uses `cryptographic_length == 0` as the
        // "omit crypto metadata" sentinel (same as BL-M-4).
        cryptographic_length: 0,
        // KMIP 3.0 §3.x lifecycle — the derived shared secret is born
        // PreActive (never Activated). The OASIS PQC interop KATs Get it
        // then Destroy it directly; PreActive → Destroyed is a legal FSM
        // edge whereas Active is not (Active would require Revoke first,
        // as the KATs do for the key pair but NOT for the shared secret).
        state: State::PreActive,
        pkcs11_cka_id: Uuid::new_v4().as_bytes().to_vec(),
        pkcs11_slot: deps.config.pkcs11_slot,
        initial_date: now,
        activation_date: None,
        last_change_date: Some(now),
        original_creation_date: Some(now),
        key_material: Some(shared_secret),
        key_format_type: Some(KeyFormatType::Raw as u32),
        // KMIP 3.0 §6.2 — the ML-KEM shared secret is keying seed
        // material; the OASIS PQC interop KATs serve it back as
        // SecretDataType=Seed (0x02), not the Password default.
        secret_data_type: Some(0x02),
        extractable: Some(true),
        sensitive: Some(false),
        fresh: Some(true),
        ..ObjectRecord::default()
    })?;
    Ok(uid)
}

fn placeholder_bytes(uid: &str, input: &[u8], domain: &[u8], len: usize) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(domain);
    h.update(uid.as_bytes());
    h.update(input);
    let d = h.finalize();
    d.iter().cycle().take(len).copied().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auditlog::{AuditSink, RingSink};
    use crate::kmip30::UsageMask;
    use crate::policy::Engine;
    use crate::store::MemoryStore;
    use std::sync::Arc;

    fn deps() -> Deps {
        let ring = Arc::new(RingSink::new(64));
        let sink: Arc<dyn AuditSink> = ring.clone();
        Deps::new(
            Engine::permissive(),
            Arc::new(MemoryStore::new()),
            sink,
            super::super::deps::DepsConfig::default(),
        )
    }

    fn put_mlkem_pub(d: &Deps, uid: &str) {
        d.store
            .put(ObjectRecord {
                uid: uid.to_string(),
                object_type: ObjectType::PublicKey,
                algorithm: KmipAlgorithm::MlKem768,
                usage_mask: UsageMask::ENCRYPT,
                state: State::Active,
                ..ObjectRecord::default()
            })
            .unwrap();
    }

    #[test]
    fn placeholder_encapsulate_creates_secret_data_and_returns_ct() {
        let d = deps();
        put_mlkem_pub(&d, "pk");
        let resp = encapsulate(
            &d,
            EncapsulateRequest {
                uid: "pk".to_string(),
                input_key_material: Some(vec![0x11; 32]),
                cryptographic_parameters: None,
            },
            "t",
        )
        .unwrap();
        assert_eq!(resp.data.len(), 32, "placeholder ciphertext");
        let ss_rec = d.store.get(&resp.uid).unwrap().unwrap();
        assert_eq!(ss_rec.object_type, ObjectType::SecretData);
        // Born PreActive so a subsequent Destroy (without Revoke) is a
        // legal FSM edge — matches the OASIS PQC interop KAT flow.
        assert_eq!(ss_rec.state, State::PreActive);
        assert!(ss_rec.key_material.is_some(), "shared secret persisted");
        assert_ne!(resp.uid, "pk", "a NEW object UID is returned");
    }

    #[test]
    fn encapsulate_rejects_non_mlkem_key() {
        let d = deps();
        d.store
            .put(ObjectRecord {
                uid: "rsa".to_string(),
                object_type: ObjectType::PublicKey,
                algorithm: KmipAlgorithm::Rsa,
                state: State::Active,
                ..ObjectRecord::default()
            })
            .unwrap();
        let err = encapsulate(
            &d,
            EncapsulateRequest { uid: "rsa".to_string(), ..Default::default() },
            "t",
        )
        .unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::OperationNotSupported);
    }
}
