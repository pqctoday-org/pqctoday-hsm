//! Part F §F9 (rust-hsm-perf-bench-scenario-plan-07182026.md, workspace
//! root) — end-to-end proof that per-tenant KMIP sessions (§F7.1/F7.2)
//! plus the engine-side isolation gate (§F2–F5) actually keep two KMIP
//! clients apart, driven through the REAL dispatcher
//! (`dispatch_with_transport_identity`) with two distinct authenticated
//! identities — not by calling op handlers directly with a hand-built
//! `AuthContext`.
//!
//! STATUS (2026-07-18, rev 3 — Encrypt/Decrypt wired, §J): the two
//! gates compose. Every by-UID handler wired so far (§F7's dispatcher
//! slice, plus §J's addition: `CreateKeyPair`, `Sign`, `Encapsulate`,
//! `Decapsulate`, `ReKey`, `ReKeyKeyPair`, `Get`, `GetAttributes`,
//! `GetAttributeList`, `Destroy`, `Locate`, `Encrypt`, `Decrypt`) does
//! an owner check (`helpers::authorize_object` / Locate's predicate
//! filter) against the KMIP store BEFORE anything else, using the SAME
//! not-found error each operation already used for a genuinely missing
//! UID — so "exists but not yours" and "doesn't exist" are
//! indistinguishable, satisfying the anti-oracle requirement at the
//! KMIP layer, not just the engine layer. `Sign`/`Encapsulate`/
//! `Decapsulate`/`Encrypt`/`Decrypt` additionally still hit the
//! ENGINE's own token-scoped handle lookup (§F2–F5) as a second,
//! independent barrier — defense in depth, verified below by checking
//! that the fully-wired path denies at the FIRST gate (the KMIP owner
//! check), not by relying on the engine gate alone.
//!
//! ~17 of the original ~28 `deps.engine_session`-reading files remain
//! unwired for SESSION resolution (Certify, the composite/hybrid-cert
//! family, split_key, derive_key's own creation path, attribute
//! mutation, mac/hash, rng/pkcs11, register/import) — see the plan's
//! §H3/§J for the exact list. This file only asserts properties of the
//! operations it actually exercises.

#[cfg(test)]
mod tests {
    use crate::auditlog::RingSink;
    use crate::dispatcher::{dispatch_with_transport_identity, one_off_request};
    use crate::error::ResultReason;
    use crate::kmip30::{
        ActivateRequest, AsynchronousIndicator, Attribute, CreateKeyPairRequest, CreateRequest,
        CryptographicParameters, DecryptRequest, EncryptRequest, GetAttributesRequest,
        HashRequest, HashingAlgorithm, KmipAlgorithm, ObjectType, PollRequest,
        QueryAsynchronousRequestsRequest, RequestBatchItem, RequestHeader, RequestMessage,
        RequestPayload, ResponsePayload, ResultStatus, SignRequest, UsageMask,
    };
    use crate::ops::deps::{Deps, DepsConfig, StrictTenantConfig, TenancyMode};
    use crate::ops::helpers::engine_lock;
    use crate::policy::Engine;
    use crate::server::auth::Identity;
    use crate::store::MemoryStore;
    use std::sync::Arc;

    /// Two tenants, `Strict` mode, on dedicated PKCS#11 slots (90/91 —
    /// outside every range used elsewhere in this crate's test suite:
    /// slot 0 for the many single-session fixtures, 60–72 for
    /// `ops::deps::tests`). No `finalize()` here (see the note on
    /// `ops::deps::tests::strict_mode_provisions_configured_tenant_and_caches_it`
    /// for why that call is itself a cross-test hazard) — `engine_lock()`
    /// below serialises this test against every other `src/ops/*.rs`
    /// internal test that shares the same lock.
    fn two_tenant_deps() -> (Deps, Identity, Identity) {
        let alice = Identity { username: "alice-f9".into() };
        let bob = Identity { username: "bob-f9".into() };
        let config = DepsConfig {
            tenancy_mode: TenancyMode::Strict,
            strict_tenants: vec![
                StrictTenantConfig {
                    identity: alice.clone(),
                    slot: 90,
                    so_pin: "so-pin-90".into(),
                    user_pin: "user-pin-90".into(),
                },
                StrictTenantConfig {
                    identity: bob.clone(),
                    slot: 91,
                    so_pin: "so-pin-91".into(),
                    user_pin: "user-pin-91".into(),
                },
            ],
            ..DepsConfig::default()
        };
        let sink: Arc<dyn crate::auditlog::AuditSink> = Arc::new(RingSink::new(256));
        let deps = Deps::new(Engine::permissive(), Arc::new(MemoryStore::new()), sink, config);
        (deps, alice, bob)
    }

    #[test]
    fn cross_tenant_sign_fails_closed_but_metadata_get_still_leaks() {
        let _guard = engine_lock();
        let (deps, alice, bob) = two_tenant_deps();

        // ── Alice creates her own ML-DSA-65 signing key pair, through
        // the REAL dispatcher — this is what auto-provisions her token
        // on slot 90 on first use. ──────────────────────────────────────
        let create_req = one_off_request(RequestPayload::CreateKeyPair(CreateKeyPairRequest {
            common_attributes: vec![
                Attribute::CryptographicAlgorithm(KmipAlgorithm::MlDsa65),
                Attribute::CryptographicUsageMask(UsageMask::SIGN | UsageMask::VERIFY),
            ],
            private_key_attributes: vec![],
            public_key_attributes: vec![],
            seed: None,
        }));
        let create_resp = dispatch_with_transport_identity(&deps, create_req, Some(alice.clone()));
        assert_eq!(
            create_resp.batch_items[0].result_status,
            ResultStatus::Success,
            "Alice creates her own key pair: {:?}",
            create_resp.batch_items[0].result_reason
        );
        let ResponsePayload::CreateKeyPair(ckp) = create_resp.batch_items[0].payload.clone().unwrap() else {
            panic!("expected CreateKeyPair response");
        };

        // Activate the private key (freshly-created keys are PreActive;
        // Sign requires Active).
        let activate_req = one_off_request(RequestPayload::Activate(ActivateRequest {
            uid: ckp.private_key_uid.clone(),
        }));
        let activate_resp = dispatch_with_transport_identity(&deps, activate_req, Some(alice.clone()));
        assert_eq!(activate_resp.batch_items[0].result_status, ResultStatus::Success);

        // ── Alice signs with her OWN key — must succeed. Proves her own
        // tenant session works end-to-end through the real dispatcher
        // (auto-provisioned token, real engine sign). ──────────────────
        let sign_req = one_off_request(RequestPayload::Sign(SignRequest {
            uid: ckp.private_key_uid.clone(),
            data: b"alice's data".to_vec(),
            cryptographic_parameters: None,
        }));
        let alice_sign_resp = dispatch_with_transport_identity(&deps, sign_req, Some(alice.clone()));
        assert_eq!(
            alice_sign_resp.batch_items[0].result_status,
            ResultStatus::Success,
            "Alice can sign with her own key: {:?}",
            alice_sign_resp.batch_items[0].result_reason
        );

        // ── Bob attempts to Sign using ALICE's private key UID. ─────────
        // His request resolves to HIS OWN engine session (slot 91, a
        // different PKCS#11 token than Alice's slot 90). As of rev 2,
        // TWO independent gates now deny this: (1) the KMIP-store owner
        // check (`helpers::authorize_object`, §F7.4) — Bob's identity
        // doesn't match the record's owner, so the lookup itself fails
        // before Sign does anything else; (2) even if (1) didn't exist,
        // resolving the record's engine handle via
        // `helpers::find_handle_for_object(bob_session, cka_id, ...)` is
        // scoped to Bob's slot by the engine's OWN isolation gate (§F2–
        // F5, shipped earlier and independently tested in
        // softhsmrustv3's own suite) — Alice's handle isn't visible
        // there either. Sign hits gate (1) first.
        let bob_sign_req = one_off_request(RequestPayload::Sign(SignRequest {
            uid: ckp.private_key_uid.clone(),
            data: b"bob trying to sign with alice's key".to_vec(),
            cryptographic_parameters: None,
        }));
        let bob_sign_resp = dispatch_with_transport_identity(&deps, bob_sign_req, Some(bob.clone()));
        assert_eq!(
            bob_sign_resp.batch_items[0].result_status,
            ResultStatus::OperationFailed,
            "Bob must NOT be able to sign with Alice's key"
        );
        assert_eq!(
            bob_sign_resp.batch_items[0].result_reason,
            Some(ResultReason::ObjectNotFound.to_wire_value()),
            "cross-tenant Sign fails as ObjectNotFound — anti-oracle: indistinguishable from a UID \
             that doesn't exist at all, matching the user's Item-Not-Found decision (§A2/rev 5) even \
             though this specific denial is the ENGINE's token-scoping, not yet a KMIP-layer owner check"
        );

        // ── GAP CLOSED (rev 2, F7.3/F7.4): Bob's GetAttributes on
        // Alice's private-key UID now fails too. Deliberately NOT `Get`
        // (which fails for a totally different, benign reason for ANY
        // caller, including Alice herself: ML-DSA private keys are
        // CKA_SENSITIVE by default, so `Get` always refuses to return
        // material — that's a pre-existing sensitivity gate, not
        // tenancy; `get_owner_check_denies_before_engine_is_even_reached`
        // below isolates the ownership property on a non-sensitive
        // object instead). `GetAttributes` returns metadata only, never
        // key material, and never touches the engine — so this is a
        // clean, unconfounded proof that the KMIP STORE itself is now
        // owner-filtered, not just the engine. ──────────────────────────
        let get_attrs_req = one_off_request(RequestPayload::GetAttributes(GetAttributesRequest {
            uid: ckp.private_key_uid.clone(),
            attribute_references: vec![],
        }));
        let bob_get_attrs_resp = dispatch_with_transport_identity(&deps, get_attrs_req, Some(bob.clone()));
        assert_eq!(
            bob_get_attrs_resp.batch_items[0].result_status,
            ResultStatus::OperationFailed,
            "Bob must NOT be able to read Alice's key's metadata"
        );
        assert_eq!(
            bob_get_attrs_resp.batch_items[0].result_reason,
            Some(ResultReason::ItemNotFound.to_wire_value()),
            "cross-tenant GetAttributes fails as ItemNotFound — the SAME reason this operation \
             already used for a genuinely missing UID (OASIS BL-M-20-30.xml), so a foreign tenant's \
             object stays indistinguishable from a nonexistent one at the KMIP layer, not just the \
             engine layer"
        );

        // Alice's own GetAttributes on her own key still works — the
        // owner check is a real gate, not an accidental blanket deny.
        let alice_get_attrs_req = one_off_request(RequestPayload::GetAttributes(GetAttributesRequest {
            uid: ckp.private_key_uid.clone(),
            attribute_references: vec![],
        }));
        let alice_get_attrs_resp =
            dispatch_with_transport_identity(&deps, alice_get_attrs_req, Some(alice.clone()));
        assert_eq!(
            alice_get_attrs_resp.batch_items[0].result_status,
            ResultStatus::Success,
            "Alice can still read her own key's metadata: {:?}",
            alice_get_attrs_resp.batch_items[0].result_reason
        );

        // ── Destroy is owner-checked too: Bob cannot destroy Alice's key. ──
        let bob_destroy_req = one_off_request(RequestPayload::Destroy(crate::kmip30::DestroyRequest {
            uid: ckp.private_key_uid.clone(),
        }));
        let bob_destroy_resp = dispatch_with_transport_identity(&deps, bob_destroy_req, Some(bob));
        assert_eq!(
            bob_destroy_resp.batch_items[0].result_status,
            ResultStatus::OperationFailed,
            "Bob must NOT be able to destroy Alice's key"
        );
        assert_eq!(
            bob_destroy_resp.batch_items[0].result_reason,
            Some(ResultReason::ObjectNotFound.to_wire_value()),
            "cross-tenant Destroy fails as ObjectNotFound — this handler's own pre-existing \
             not-found reason, now also covering the owner mismatch"
        );

        // The key survives Bob's failed attempt — Alice can still get its
        // metadata (proves Destroy didn't partially execute before the
        // owner check, and that the owner check runs BEFORE any mutation).
        let alice_get_attrs_req2 = one_off_request(RequestPayload::GetAttributes(GetAttributesRequest {
            uid: ckp.private_key_uid.clone(),
            attribute_references: vec![],
        }));
        let alice_get_attrs_resp2 =
            dispatch_with_transport_identity(&deps, alice_get_attrs_req2, Some(alice));
        assert_eq!(
            alice_get_attrs_resp2.batch_items[0].result_status,
            ResultStatus::Success,
            "the key must still exist after Bob's rejected Destroy attempt"
        );
    }

    /// Isolates the ownership property on `Get` specifically, using a
    /// non-sensitive `SymmetricKey` so the pre-existing sensitivity gate
    /// (which would fail `Get` for ANY caller on a sensitive private
    /// key, tenancy aside — see the comment in the test above) can't
    /// confound the result. A real engine session is not needed here:
    /// `Create` on a symmetric key with no engine wired falls back to
    /// the crate's engine-less placeholder path (existing, pre-F7
    /// behavior), which is enough to prove the OWNERSHIP gate — the
    /// property this test is actually about — fires before anything
    /// else. Single mode (no tenancy config) so `Create`'s `auth` is a
    /// deliberately DIFFERENT open/anonymous context per call — proving
    /// that even within nominally "no tenancy configured" behavior, an
    /// object stamped with a real owner (because ITS creator happened to
    /// have an identity) is still protected from a later anonymous or
    /// differently-identified caller.
    #[test]
    fn get_owner_check_denies_before_engine_is_even_reached() {
        let _guard = engine_lock();
        let alice = Identity { username: "alice-get-only".into() };
        let bob = Identity { username: "bob-get-only".into() };
        let sink: Arc<dyn crate::auditlog::AuditSink> = Arc::new(RingSink::new(64));
        let deps = Deps::new(Engine::permissive(), Arc::new(MemoryStore::new()), sink, DepsConfig::default());

        let create_req = one_off_request(RequestPayload::Create(crate::kmip30::CreateRequest {
            object_type: crate::kmip30::ObjectType::SymmetricKey,
            template_attribute: vec![
                Attribute::CryptographicAlgorithm(KmipAlgorithm::Aes),
                Attribute::CryptographicLength(256),
                Attribute::CryptographicUsageMask(UsageMask::ENCRYPT | UsageMask::DECRYPT),
            ],
        }));
        let create_resp = dispatch_with_transport_identity(&deps, create_req, Some(alice.clone()));
        assert_eq!(create_resp.batch_items[0].result_status, ResultStatus::Success);
        let ResponsePayload::Create(created) = create_resp.batch_items[0].payload.clone().unwrap() else {
            panic!("expected Create response");
        };

        let bob_get = one_off_request(RequestPayload::Get(crate::kmip30::GetRequest {
            uid: created.uid.clone(),
            key_format_type: None,
            key_wrapping_specification: None,
        }));
        let bob_get_resp = dispatch_with_transport_identity(&deps, bob_get, Some(bob));
        assert_eq!(
            bob_get_resp.batch_items[0].result_status,
            ResultStatus::OperationFailed,
            "Bob must not be able to Get Alice's symmetric key"
        );
        assert_eq!(
            bob_get_resp.batch_items[0].result_reason,
            Some(ResultReason::ObjectNotFound.to_wire_value())
        );

        let alice_get = one_off_request(RequestPayload::Get(crate::kmip30::GetRequest {
            uid: created.uid,
            key_format_type: None,
            key_wrapping_specification: None,
        }));
        let alice_get_resp = dispatch_with_transport_identity(&deps, alice_get, Some(alice));
        assert_eq!(
            alice_get_resp.batch_items[0].result_status,
            ResultStatus::Success,
            "Alice can still Get her own symmetric key: {:?}",
            alice_get_resp.batch_items[0].result_reason
        );
    }

    /// Locate results are filtered per tenant: each identity sees only
    /// the objects it created, never the other's — even when both exist
    /// in the same shared store side by side.
    #[test]
    fn locate_is_scoped_to_the_requesters_own_objects() {
        let _guard = engine_lock();
        let alice = Identity { username: "alice-locate".into() };
        let bob = Identity { username: "bob-locate".into() };
        let sink: Arc<dyn crate::auditlog::AuditSink> = Arc::new(RingSink::new(64));
        let deps = Deps::new(Engine::permissive(), Arc::new(MemoryStore::new()), sink, DepsConfig::default());

        let make_key = |identity: &Identity, name: &str| {
            let req = one_off_request(RequestPayload::Create(crate::kmip30::CreateRequest {
                object_type: crate::kmip30::ObjectType::SymmetricKey,
                template_attribute: vec![
                    Attribute::CryptographicAlgorithm(KmipAlgorithm::Aes),
                    Attribute::CryptographicLength(256),
                    Attribute::CryptographicUsageMask(UsageMask::ENCRYPT | UsageMask::DECRYPT),
                    Attribute::Name(name.to_string()),
                ],
            }));
            let resp = dispatch_with_transport_identity(&deps, req, Some(identity.clone()));
            assert_eq!(resp.batch_items[0].result_status, ResultStatus::Success);
            let ResponsePayload::Create(created) = resp.batch_items[0].payload.clone().unwrap() else {
                panic!("expected Create response");
            };
            created.uid
        };

        let alice_uid = make_key(&alice, "alice-only-key");
        let bob_uid = make_key(&bob, "bob-only-key");
        assert_ne!(alice_uid, bob_uid);

        let locate_req = || one_off_request(RequestPayload::Locate(crate::kmip30::LocateRequest::default()));

        let alice_locate = dispatch_with_transport_identity(&deps, locate_req(), Some(alice.clone()));
        assert_eq!(alice_locate.batch_items[0].result_status, ResultStatus::Success);
        let ResponsePayload::Locate(alice_found) = alice_locate.batch_items[0].payload.clone().unwrap() else {
            panic!("expected Locate response");
        };
        assert!(alice_found.uids.contains(&alice_uid), "Alice must see her own key");
        assert!(
            !alice_found.uids.contains(&bob_uid),
            "Alice must NOT see Bob's key in her Locate results"
        );

        let bob_locate = dispatch_with_transport_identity(&deps, locate_req(), Some(bob));
        assert_eq!(bob_locate.batch_items[0].result_status, ResultStatus::Success);
        let ResponsePayload::Locate(bob_found) = bob_locate.batch_items[0].payload.clone().unwrap() else {
            panic!("expected Locate response");
        };
        assert!(bob_found.uids.contains(&bob_uid), "Bob must see his own key");
        assert!(
            !bob_found.uids.contains(&alice_uid),
            "Bob must NOT see Alice's key in his Locate results"
        );
    }

    /// §J (Encrypt/Decrypt now wired) — two real engine sessions again
    /// (Strict mode, slots 90/91, via `two_tenant_deps`), proving BOTH
    /// gates now apply to the symmetric-crypto path the way they
    /// already did for Sign: Bob's Encrypt/Decrypt against Alice's key
    /// UID fails at the KMIP owner check (`authorize_object`) before
    /// `resolve_tenant_session` or the engine's own token-scoping is
    /// ever reached, and Alice's own round trip through the real
    /// engine still works end to end.
    #[test]
    fn cross_tenant_encrypt_and_decrypt_fail_closed() {
        let _guard = engine_lock();
        let (deps, alice, bob) = two_tenant_deps();

        let create_req = one_off_request(RequestPayload::Create(CreateRequest {
            object_type: ObjectType::SymmetricKey,
            template_attribute: vec![
                Attribute::CryptographicAlgorithm(KmipAlgorithm::Aes),
                Attribute::CryptographicLength(256),
                Attribute::CryptographicUsageMask(UsageMask::ENCRYPT | UsageMask::DECRYPT),
            ],
        }));
        let create_resp = dispatch_with_transport_identity(&deps, create_req, Some(alice.clone()));
        assert_eq!(
            create_resp.batch_items[0].result_status,
            ResultStatus::Success,
            "Alice creates her own AES key: {:?}",
            create_resp.batch_items[0].result_reason
        );
        let ResponsePayload::Create(created) = create_resp.batch_items[0].payload.clone().unwrap() else {
            panic!("expected Create response");
        };
        let activate_req = one_off_request(RequestPayload::Activate(ActivateRequest {
            uid: created.uid.clone(),
        }));
        let activate_resp = dispatch_with_transport_identity(&deps, activate_req, Some(alice.clone()));
        assert_eq!(activate_resp.batch_items[0].result_status, ResultStatus::Success);

        // Alice encrypts with her own key through her own real engine
        // session (slot 90) — proves the wiring works end to end, not
        // just that it compiles.
        let iv = vec![0x11u8; 12];
        let alice_enc_req = one_off_request(RequestPayload::Encrypt(EncryptRequest {
            uid: created.uid.clone(),
            data: b"alice's secret".to_vec(),
            iv: Some(iv.clone()),
            cryptographic_parameters: None,
            aad: None,
            init_indicator: None,
            final_indicator: None,
            correlation_value: None,
        }));
        let alice_enc_resp = dispatch_with_transport_identity(&deps, alice_enc_req, Some(alice.clone()));
        assert_eq!(
            alice_enc_resp.batch_items[0].result_status,
            ResultStatus::Success,
            "Alice can Encrypt with her own key: {:?}",
            alice_enc_resp.batch_items[0].result_reason
        );
        let ResponsePayload::Encrypt(alice_enc) = alice_enc_resp.batch_items[0].payload.clone().unwrap() else {
            panic!("expected Encrypt response");
        };

        // Bob attempts to Encrypt using ALICE's key UID — denied at the
        // KMIP owner check (authorize_object), the same ObjectNotFound
        // this handler already used for a genuinely missing UID.
        let bob_enc_req = one_off_request(RequestPayload::Encrypt(EncryptRequest {
            uid: created.uid.clone(),
            data: b"bob trying to use alice's key".to_vec(),
            iv: Some(iv.clone()),
            cryptographic_parameters: None,
            aad: None,
            init_indicator: None,
            final_indicator: None,
            correlation_value: None,
        }));
        let bob_enc_resp = dispatch_with_transport_identity(&deps, bob_enc_req, Some(bob.clone()));
        assert_eq!(
            bob_enc_resp.batch_items[0].result_status,
            ResultStatus::OperationFailed,
            "Bob must NOT be able to Encrypt with Alice's key"
        );
        assert_eq!(
            bob_enc_resp.batch_items[0].result_reason,
            Some(ResultReason::ObjectNotFound.to_wire_value())
        );

        // Bob attempts to Decrypt Alice's own ciphertext using her key
        // UID — same denial, before his session (slot 91) ever gets
        // near it.
        let mut ct_and_tag = alice_enc.ciphertext.clone();
        if let Some(tag) = &alice_enc.authenticated_encryption_tag {
            ct_and_tag.extend_from_slice(tag);
        }
        let bob_dec_req = one_off_request(RequestPayload::Decrypt(DecryptRequest {
            uid: created.uid.clone(),
            data: ct_and_tag.clone(),
            iv: Some(iv.clone()),
            cryptographic_parameters: None,
            aad: None,
        }));
        let bob_dec_resp = dispatch_with_transport_identity(&deps, bob_dec_req, Some(bob));
        assert_eq!(
            bob_dec_resp.batch_items[0].result_status,
            ResultStatus::OperationFailed,
            "Bob must NOT be able to Decrypt with Alice's key"
        );
        assert_eq!(
            bob_dec_resp.batch_items[0].result_reason,
            Some(ResultReason::ObjectNotFound.to_wire_value())
        );

        // Alice's own Decrypt of her own ciphertext still works — the
        // owner check is a real gate, not a blanket deny, and the round
        // trip through the real engine is intact end to end.
        let alice_dec_req = one_off_request(RequestPayload::Decrypt(DecryptRequest {
            uid: created.uid,
            data: ct_and_tag,
            iv: Some(iv),
            cryptographic_parameters: None,
            aad: None,
        }));
        let alice_dec_resp = dispatch_with_transport_identity(&deps, alice_dec_req, Some(alice));
        assert_eq!(
            alice_dec_resp.batch_items[0].result_status,
            ResultStatus::Success,
            "Alice can still Decrypt her own ciphertext: {:?}",
            alice_dec_resp.batch_items[0].result_reason
        );
        let ResponsePayload::Decrypt(alice_dec) = alice_dec_resp.batch_items[0].payload.clone().unwrap() else {
            panic!("expected Decrypt response");
        };
        assert_eq!(alice_dec.data, b"alice's secret");
    }

    /// §L (Register/Export wired) — Register stamps the caller as owner,
    /// and Export (the one MATERIAL-RETURNING by-UID handler missed by
    /// the original F7.4 enumeration, found in the §L audit) is
    /// owner-checked: Bob can neither Export nor Get Alice's registered
    /// key, while Alice's own Export round-trips her exact bytes. Store-
    /// backed raw material — no engine session involved, so this
    /// isolates the OWNERSHIP property with no tenancy-provisioning
    /// confound (plain Single-mode deps, identities only).
    #[test]
    fn register_stamps_owner_and_export_is_owner_checked() {
        let _guard = engine_lock();
        let alice = Identity { username: "alice-export".into() };
        let bob = Identity { username: "bob-export".into() };
        let sink: Arc<dyn crate::auditlog::AuditSink> = Arc::new(RingSink::new(64));
        let deps = Deps::new(Engine::permissive(), Arc::new(MemoryStore::new()), sink, DepsConfig::default());

        let key_bytes = vec![0xA5u8; 32];
        let register_req = one_off_request(RequestPayload::Register(crate::kmip30::RegisterRequest {
            object_type: ObjectType::SymmetricKey,
            attributes: vec![
                Attribute::CryptographicAlgorithm(KmipAlgorithm::Aes),
                Attribute::CryptographicLength(256),
                Attribute::CryptographicUsageMask(UsageMask::ENCRYPT | UsageMask::DECRYPT),
            ],
            managed_object: Some(crate::kmip30::KeyBlock {
                key_format_type: crate::kmip30::KeyFormatType::Raw,
                cryptographic_algorithm: KmipAlgorithm::Aes,
                cryptographic_length: 256,
                key_value: key_bytes.clone(),
                key_wrapping_data: None,
            }),
            protection_storage_masks: None,
            certificate_payload: None,
            secret_data_type: None,
        }));
        let register_resp = dispatch_with_transport_identity(&deps, register_req, Some(alice.clone()));
        assert_eq!(
            register_resp.batch_items[0].result_status,
            ResultStatus::Success,
            "Alice registers her own key: {:?}",
            register_resp.batch_items[0].result_reason
        );
        let ResponsePayload::Register(registered) = register_resp.batch_items[0].payload.clone().unwrap() else {
            panic!("expected Register response");
        };

        let export_req = |uid: &str| {
            one_off_request(RequestPayload::Export(crate::kmip30::ExportRequest {
                uid: uid.to_string(),
                key_format_type: None,
                key_wrap_type: None,
                key_compression_type: None,
                key_wrapping_specification: None,
            }))
        };

        let bob_export = dispatch_with_transport_identity(&deps, export_req(&registered.uid), Some(bob));
        assert_eq!(
            bob_export.batch_items[0].result_status,
            ResultStatus::OperationFailed,
            "Bob must NOT be able to Export Alice's key material"
        );
        assert_eq!(
            bob_export.batch_items[0].result_reason,
            Some(ResultReason::ObjectNotFound.to_wire_value()),
            "cross-tenant Export fails as ObjectNotFound — anti-oracle"
        );

        let alice_export = dispatch_with_transport_identity(&deps, export_req(&registered.uid), Some(alice));
        assert_eq!(
            alice_export.batch_items[0].result_status,
            ResultStatus::Success,
            "Alice can still Export her own key: {:?}",
            alice_export.batch_items[0].result_reason
        );
        let ResponsePayload::Export(exported) = alice_export.batch_items[0].payload.clone().unwrap() else {
            panic!("expected Export response");
        };
        assert_eq!(
            exported.managed_object.expect("Alice's export carries her key material").key_value,
            key_bytes,
            "Alice's Export must round-trip her exact registered bytes"
        );
    }

    /// §L (KEK owner check in `resolve_kek`) — a wrap key referenced by
    /// UID inside a KeyWrappingSpecification is itself a by-UID key
    /// reference, and using a FOREIGN tenant's KEK must fail exactly
    /// like a nonexistent one (`Wrapping Object Not Found`, the same
    /// reason a genuinely missing KEK UID produces). Before §L, any
    /// tenant could wrap/unwrap under another tenant's KEK by knowing
    /// its UID. All store-backed raw material — no engine sessions.
    #[test]
    fn cross_tenant_kek_is_invisible_for_wrapping() {
        let _guard = engine_lock();
        let alice = Identity { username: "alice-kek".into() };
        let bob = Identity { username: "bob-kek".into() };
        let sink: Arc<dyn crate::auditlog::AuditSink> = Arc::new(RingSink::new(64));
        let deps = Deps::new(Engine::permissive(), Arc::new(MemoryStore::new()), sink, DepsConfig::default());

        let register = |identity: &Identity, usage: UsageMask, activation_past: bool, bytes: Vec<u8>| {
            let mut attrs = vec![
                Attribute::CryptographicAlgorithm(KmipAlgorithm::Aes),
                Attribute::CryptographicLength(256),
                Attribute::CryptographicUsageMask(usage),
            ];
            if activation_past {
                // Past ActivationDate ⇒ born Active (compute_initial_state)
                // — resolve_kek requires an Active KEK.
                attrs.push(Attribute::ActivationDate(
                    time::OffsetDateTime::now_utc().unix_timestamp() - 3600,
                ));
            }
            let req = one_off_request(RequestPayload::Register(crate::kmip30::RegisterRequest {
                object_type: ObjectType::SymmetricKey,
                attributes: attrs,
                managed_object: Some(crate::kmip30::KeyBlock {
                    key_format_type: crate::kmip30::KeyFormatType::Raw,
                    cryptographic_algorithm: KmipAlgorithm::Aes,
                    cryptographic_length: 256,
                    key_value: bytes,
                    key_wrapping_data: None,
                }),
                protection_storage_masks: None,
                certificate_payload: None,
                secret_data_type: None,
            }));
            let resp = dispatch_with_transport_identity(&deps, req, Some(identity.clone()));
            assert_eq!(resp.batch_items[0].result_status, ResultStatus::Success);
            let ResponsePayload::Register(r) = resp.batch_items[0].payload.clone().unwrap() else {
                panic!("expected Register response");
            };
            r.uid
        };

        // Alice's KEK (Active, WrapKey usage) and Bob's own data key.
        let alice_kek_uid = register(&alice, UsageMask::WRAP_KEY, true, vec![0x11u8; 32]);
        let bob_key_uid = register(&bob, UsageMask::ENCRYPT | UsageMask::DECRYPT, false, vec![0x22u8; 32]);

        let wrapped_get = |key_uid: &str, kek_uid: &str| {
            one_off_request(RequestPayload::Get(crate::kmip30::GetRequest {
                uid: key_uid.to_string(),
                key_format_type: None,
                key_wrapping_specification: Some(crate::kmip30::KeyWrappingSpec {
                    wrapping_method: 0x01, // Encrypt
                    encryption_key_uid: kek_uid.to_string(),
                    cryptographic_parameters: None, // defaults to NISTKeyWrap
                    encoding_option: None,
                    mac_signature_key_information_present: false,
                }),
            }))
        };

        // Bob requests HIS OWN key wrapped under ALICE's KEK — the data
        // key is his, so the object gate passes; the KEK gate must not.
        let bob_get = dispatch_with_transport_identity(&deps, wrapped_get(&bob_key_uid, &alice_kek_uid), Some(bob.clone()));
        assert_eq!(
            bob_get.batch_items[0].result_status,
            ResultStatus::OperationFailed,
            "Bob must NOT be able to wrap under Alice's KEK"
        );
        assert_eq!(
            bob_get.batch_items[0].result_reason,
            Some(ResultReason::WrappingObjectNotFound.to_wire_value()),
            "a foreign KEK fails as Wrapping Object Not Found — the SAME reason a \
             genuinely missing KEK UID produces (anti-oracle at the KEK layer)"
        );

        // Alice wrapping her own... key under her own KEK works — the KEK
        // owner check is a real gate, not a blanket deny. (Her KEK wraps
        // ITSELF here — a legal, if unusual, request that avoids needing
        // a second Alice-owned object.)
        let alice_get = dispatch_with_transport_identity(&deps, wrapped_get(&alice_kek_uid, &alice_kek_uid), Some(alice));
        assert_eq!(
            alice_get.batch_items[0].result_status,
            ResultStatus::Success,
            "Alice can wrap under her own KEK: {:?}",
            alice_get.batch_items[0].result_reason
        );
    }

    /// §M (final sweep — MAC + attribute mutation wired) — the two
    /// remaining non-crypto-material by-UID op families are owner-checked
    /// too: Bob can neither MAC with Alice's registered HMAC key nor
    /// mutate its attributes, while Alice's own MAC and AddAttribute
    /// succeed. Store-backed HMAC material (no engine session), so this
    /// isolates the ownership property with no provisioning confound.
    #[test]
    fn cross_tenant_mac_and_attribute_ops_are_owner_checked() {
        let _guard = engine_lock();
        let alice = Identity { username: "alice-mac".into() };
        let bob = Identity { username: "bob-mac".into() };
        let sink: Arc<dyn crate::auditlog::AuditSink> = Arc::new(RingSink::new(64));
        let deps = Deps::new(Engine::permissive(), Arc::new(MemoryStore::new()), sink, DepsConfig::default());

        // Alice registers a store-backed HMAC key, born Active (past
        // ActivationDate), with MAC_GENERATE|MAC_VERIFY usage.
        let register_req = one_off_request(RequestPayload::Register(crate::kmip30::RegisterRequest {
            object_type: ObjectType::SymmetricKey,
            attributes: vec![
                Attribute::CryptographicAlgorithm(KmipAlgorithm::HmacSha256),
                Attribute::CryptographicLength(256),
                Attribute::CryptographicUsageMask(UsageMask::MAC_GENERATE | UsageMask::MAC_VERIFY),
                Attribute::ActivationDate(time::OffsetDateTime::now_utc().unix_timestamp() - 3600),
            ],
            managed_object: Some(crate::kmip30::KeyBlock {
                key_format_type: crate::kmip30::KeyFormatType::Raw,
                cryptographic_algorithm: KmipAlgorithm::HmacSha256,
                cryptographic_length: 256,
                key_value: vec![0x5Au8; 32],
                key_wrapping_data: None,
            }),
            protection_storage_masks: None,
            certificate_payload: None,
            secret_data_type: None,
        }));
        let register_resp = dispatch_with_transport_identity(&deps, register_req, Some(alice.clone()));
        assert_eq!(
            register_resp.batch_items[0].result_status,
            ResultStatus::Success,
            "Alice registers her HMAC key: {:?}",
            register_resp.batch_items[0].result_reason
        );
        let ResponsePayload::Register(registered) = register_resp.batch_items[0].payload.clone().unwrap() else {
            panic!("expected Register response");
        };

        let mac_req = |uid: &str| {
            one_off_request(RequestPayload::Mac(crate::kmip30::MacRequest {
                uid: uid.to_string(),
                cryptographic_parameters: None,
                data: b"authenticate me".to_vec(),
            }))
        };

        // Bob's MAC with Alice's key — denied at the owner check.
        let bob_mac = dispatch_with_transport_identity(&deps, mac_req(&registered.uid), Some(bob.clone()));
        assert_eq!(
            bob_mac.batch_items[0].result_status,
            ResultStatus::OperationFailed,
            "Bob must NOT be able to MAC with Alice's key"
        );
        assert_eq!(
            bob_mac.batch_items[0].result_reason,
            Some(ResultReason::ObjectNotFound.to_wire_value())
        );

        // Alice's own MAC works.
        let alice_mac = dispatch_with_transport_identity(&deps, mac_req(&registered.uid), Some(alice.clone()));
        assert_eq!(
            alice_mac.batch_items[0].result_status,
            ResultStatus::Success,
            "Alice can MAC with her own key: {:?}",
            alice_mac.batch_items[0].result_reason
        );

        // Bob's AddAttribute on Alice's key — denied.
        let bob_add = one_off_request(RequestPayload::AddAttribute(crate::kmip30::AddAttributeRequest {
            uid: registered.uid.clone(),
            new_attribute: Attribute::Name("bob-was-here".into()),
        }));
        let bob_add_resp = dispatch_with_transport_identity(&deps, bob_add, Some(bob));
        assert_eq!(
            bob_add_resp.batch_items[0].result_status,
            ResultStatus::OperationFailed,
            "Bob must NOT be able to mutate Alice's key's attributes"
        );
        assert_eq!(
            bob_add_resp.batch_items[0].result_reason,
            Some(ResultReason::ObjectNotFound.to_wire_value())
        );

        // Alice's own AddAttribute works — a real gate, not a blanket deny.
        let alice_add = one_off_request(RequestPayload::AddAttribute(crate::kmip30::AddAttributeRequest {
            uid: registered.uid,
            new_attribute: Attribute::Name("alices-mac-key".into()),
        }));
        let alice_add_resp = dispatch_with_transport_identity(&deps, alice_add, Some(alice));
        assert_eq!(
            alice_add_resp.batch_items[0].result_status,
            ResultStatus::Success,
            "Alice can add an attribute to her own key: {:?}",
            alice_add_resp.batch_items[0].result_reason
        );
    }

    /// §F7.5 (async_jobs owner-scoped) — the sharpest edge: `Poll`
    /// returns the deferred operation's FULL response payload, so a
    /// foreign tenant Polling another's async correlation value would
    /// receive that tenant's result (for a deferred Get/Export/Decrypt,
    /// key material). Bob can neither Poll nor see (via
    /// QueryAsynchronousRequests) Alice's async job; Alice's own Poll
    /// works. Driven through the real dispatcher with a Mandatory-async
    /// Hash — the correlation values are monotonic/predictable, so this
    /// is a real guess-the-CV attack, not a theoretical one.
    #[test]
    fn cross_tenant_async_poll_and_query_are_owner_scoped() {
        let _guard = engine_lock();
        let alice = Identity { username: "alice-async".into() };
        let bob = Identity { username: "bob-async".into() };
        let sink: Arc<dyn crate::auditlog::AuditSink> = Arc::new(RingSink::new(64));
        let deps = Deps::new(Engine::permissive(), Arc::new(MemoryStore::new()), sink, DepsConfig::default());

        // A Mandatory-async Hash enqueues a real job (Hash is
        // async-eligible) and returns OperationPending + a correlation
        // value, per §8.1.2.
        let async_hash = || {
            let payload = RequestPayload::Hash(HashRequest {
                cryptographic_parameters: CryptographicParameters {
                    hashing_algorithm: Some(HashingAlgorithm::Sha256),
                    ..Default::default()
                },
                data: b"defer me".to_vec(),
            });
            RequestMessage {
                header: RequestHeader {
                    asynchronous_indicator: Some(AsynchronousIndicator::Mandatory),
                    ..RequestHeader::v3()
                },
                batch_items: vec![RequestBatchItem {
                    operation: payload.operation(),
                    payload,
                }],
            }
        };

        let alice_enqueue = dispatch_with_transport_identity(&deps, async_hash(), Some(alice.clone()));
        assert_eq!(
            alice_enqueue.batch_items[0].result_status,
            ResultStatus::OperationPending,
            "Mandatory-async Hash enqueues: {:?}",
            alice_enqueue.batch_items[0].result_reason
        );
        let alice_cv = alice_enqueue.batch_items[0]
            .asynchronous_correlation_value
            .clone()
            .expect("async job returns a correlation value");

        let poll = |cv: &[u8]| {
            one_off_request(RequestPayload::Poll(PollRequest {
                asynchronous_correlation_value: cv.to_vec(),
            }))
        };

        // Bob polls Alice's correlation value — MUST fail as an invalid
        // correlation value, indistinguishable from a nonexistent one
        // (anti-oracle). This is what stops him reading her deferred
        // result.
        let bob_poll = dispatch_with_transport_identity(&deps, poll(&alice_cv), Some(bob.clone()));
        assert_eq!(
            bob_poll.batch_items[0].result_status,
            ResultStatus::OperationFailed,
            "Bob must NOT be able to Poll Alice's async job"
        );
        assert_eq!(
            bob_poll.batch_items[0].result_reason,
            Some(ResultReason::InvalidAsynchronousCorrelationValue.to_wire_value()),
            "cross-tenant Poll fails as InvalidAsynchronousCorrelationValue — same as a \
             genuinely unknown correlation value"
        );

        // Bob's QueryAsynchronousRequests must not list Alice's job.
        let bob_query = dispatch_with_transport_identity(
            &deps,
            one_off_request(RequestPayload::QueryAsynchronousRequests(
                QueryAsynchronousRequestsRequest::default(),
            )),
            Some(bob),
        );
        let ResponsePayload::QueryAsynchronousRequests(bob_jobs) =
            bob_query.batch_items[0].payload.clone().unwrap()
        else {
            panic!("expected QueryAsynchronousRequests response");
        };
        assert!(
            bob_jobs.requests.iter().all(|r| r.asynchronous_correlation_value != alice_cv),
            "Bob must NOT see Alice's job in his async-request listing"
        );

        // Alice polls her own job — succeeds (the job may still be
        // pending or already complete; either is a Poll SUCCESS-shape
        // for HER, never the InvalidAsynchronousCorrelationValue Bob
        // got). The owner check is a real gate, not a blanket deny.
        let alice_poll = dispatch_with_transport_identity(&deps, poll(&alice_cv), Some(alice));
        assert_ne!(
            alice_poll.batch_items[0].result_reason,
            Some(ResultReason::InvalidAsynchronousCorrelationValue.to_wire_value()),
            "Alice's own Poll must NOT be rejected as an invalid correlation value: {:?}",
            alice_poll.batch_items[0].result_status
        );
    }

    /// §F7.5 (object_defaults per-tenant) — one tenant's Set Defaults
    /// affects only its own factory operations. Alice sets a default
    /// Name for SymmetricKey; her later Create picks it up, Bob's does
    /// not. Store-backed (no engine session): Create with no session
    /// still persists a record with the merged template, so the applied
    /// default is observable on the stored object.
    #[test]
    fn set_defaults_is_per_tenant() {
        let _guard = engine_lock();
        let alice = Identity { username: "alice-defaults".into() };
        let bob = Identity { username: "bob-defaults".into() };
        let sink: Arc<dyn crate::auditlog::AuditSink> = Arc::new(RingSink::new(64));
        let deps = Deps::new(Engine::permissive(), Arc::new(MemoryStore::new()), sink, DepsConfig::default());

        // Alice sets a per-Object-Type default Name for symmetric keys.
        let set_req = one_off_request(RequestPayload::SetDefaults(crate::kmip30::SetDefaultsRequest {
            defaults_information: Some(vec![crate::kmip30::ObjectDefaults {
                object_types: vec![ObjectType::SymmetricKey],
                attributes: vec![Attribute::Name("alice-default-name".into())],
            }]),
        }));
        let set_resp = dispatch_with_transport_identity(&deps, set_req, Some(alice.clone()));
        assert_eq!(set_resp.batch_items[0].result_status, ResultStatus::Success);

        let create_aes = || {
            one_off_request(RequestPayload::Create(CreateRequest {
                object_type: ObjectType::SymmetricKey,
                template_attribute: vec![
                    Attribute::CryptographicAlgorithm(KmipAlgorithm::Aes),
                    Attribute::CryptographicLength(256),
                    Attribute::CryptographicUsageMask(UsageMask::ENCRYPT | UsageMask::DECRYPT),
                ],
            }))
        };

        // Alice's Create inherits her default Name.
        let alice_create = dispatch_with_transport_identity(&deps, create_aes(), Some(alice));
        let ResponsePayload::Create(alice_obj) = alice_create.batch_items[0].payload.clone().unwrap() else {
            panic!("expected Create response");
        };
        let alice_rec = deps.store.get(&alice_obj.uid).unwrap().unwrap();
        assert_eq!(
            alice_rec.name.as_deref(),
            Some("alice-default-name"),
            "Alice's Create must inherit her own Set Defaults Name"
        );

        // Bob's Create — same request, but he set no defaults — gets no
        // Name (Alice's default is invisible to him).
        let bob_create = dispatch_with_transport_identity(&deps, create_aes(), Some(bob));
        let ResponsePayload::Create(bob_obj) = bob_create.batch_items[0].payload.clone().unwrap() else {
            panic!("expected Create response");
        };
        let bob_rec = deps.store.get(&bob_obj.uid).unwrap().unwrap();
        assert_eq!(
            bob_rec.name, None,
            "Bob must NOT inherit Alice's per-tenant default"
        );
    }
}
