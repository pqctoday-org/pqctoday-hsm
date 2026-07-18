//! Part F §F9 (rust-hsm-perf-bench-scenario-plan-07182026.md, workspace
//! root) — end-to-end proof that per-tenant KMIP sessions (§F7.1/F7.2)
//! plus the engine-side isolation gate (§F2–F5) actually keep two KMIP
//! clients apart, driven through the REAL dispatcher
//! (`dispatch_with_transport_identity`) with two distinct authenticated
//! identities — not by calling op handlers directly with a hand-built
//! `AuthContext`.
//!
//! STATUS (2026-07-18): this proves what is ACTUALLY wired today.
//! `CreateKeyPair`, `Activate`, `Sign`, and `Encapsulate` resolve their
//! own tenant's engine session (the §F7-scoped dispatcher-wiring slice —
//! see the plan's §G3 for the ~24 remaining op handlers not yet
//! migrated). It ALSO honestly documents the residual gap the same
//! section flags: KMIP-level object METADATA (`Get`, `GetAttributes`,
//! `Locate`) is not yet owner-filtered (§F7.3/F7.4 not built), so while
//! a cross-tenant `Sign` genuinely fails closed (proven below, via the
//! engine's own token-scoped handle lookup — not a KMIP-layer check),
//! a cross-tenant `Get` on the same UID still succeeds today, leaking
//! the object's existence and metadata. Both facts are asserted, not
//! just one — this file must fail loudly (not silently pass) the day
//! either behavior changes without deliberate intent.

#[cfg(test)]
mod tests {
    use crate::auditlog::RingSink;
    use crate::dispatcher::{dispatch_with_transport_identity, one_off_request};
    use crate::error::ResultReason;
    use crate::kmip30::{
        ActivateRequest, Attribute, CreateKeyPairRequest, GetAttributesRequest, KmipAlgorithm,
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
        // different PKCS#11 token than Alice's slot 90). The KMIP-store
        // lookup by UID still finds Alice's ObjectRecord (F7.3/F7.4 owner
        // tracking is not built — see the module doc), but resolving
        // that record's engine handle goes through
        // `helpers::find_handle_for_object(bob_session, cka_id, ...)`,
        // which is scoped to Bob's slot by the engine's OWN isolation
        // gate (Part F, already shipped and independently tested in
        // softhsmrustv3's own suite) — Alice's private-key handle simply
        // isn't visible there, so the lookup finds nothing and the
        // operation fails closed BEFORE any cryptographic material could
        // be touched.
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

        // ── Honest residual-gap check. ───────────────────────────────────
        // Bob's GetAttributes on Alice's private-key UID — deliberately
        // NOT `Get` (which fails for a totally different, benign reason
        // for ANY caller, including Alice herself: ML-DSA private keys
        // are CKA_SENSITIVE by default, so `Get` always refuses to
        // return material — that's a pre-existing sensitivity gate, not
        // tenancy). `GetAttributes` only returns metadata (Cryptographic
        // Algorithm, State, …), never key material, and — per
        // `get_attributes.rs` — never touches `deps.engine_session` at
        // all, so it is a clean, unconfounded test of whether the KMIP
        // STORE itself is owner-filtered. It is not (F7.3 not built), so
        // this metadata read still succeeds today, revealing that the
        // object exists and its algorithm/state. This assertion
        // documents TODAY'S actual (undesired) state, not the desired
        // end state — when F7.3/F7.4 lands, this must flip to
        // OperationFailed/ItemNotFound and this comment updated, exactly
        // like the two P0b-era gap tests in softhsmrustv3's own suite
        // were flipped once its gate landed.
        let get_attrs_req = one_off_request(RequestPayload::GetAttributes(GetAttributesRequest {
            uid: ckp.private_key_uid.clone(),
            attribute_references: vec![],
        }));
        let bob_get_attrs_resp = dispatch_with_transport_identity(&deps, get_attrs_req, Some(bob));
        assert_eq!(
            bob_get_attrs_resp.batch_items[0].result_status,
            ResultStatus::Success,
            "KNOWN GAP (§F7.3/F7.4, not yet built): KMIP-level GetAttributes is not owner-filtered — \
             Bob can still read Alice's key's metadata even though he cannot use the key \
             cryptographically: {:?}",
            bob_get_attrs_resp.batch_items[0].result_reason
        );
    }
}
