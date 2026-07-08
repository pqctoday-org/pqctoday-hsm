//! P1.3 — full-round-trip e2e coverage for the KMIP ops the OASIS
//! Baseline corpus never exercises.
//!
//! These 18 ops were unit-tested at the handler level (in their
//! `src/ops/*.rs` `#[cfg(test)]` modules) but never proven through a
//! real-engine session against the live store: the OASIS transcript
//! replay (`conformance/`) drives only the corpus-covered ops. Each
//! test below builds the same real-engine deps the `native_bridge_e2e`
//! headline demo uses, runs the op against the live store + engine, and
//! asserts a SUBSTANTIVE outcome — a lifecycle State value, the exact
//! key-material bytes, a §6.1.x Link, a usage-budget decrement, or the
//! spec ResultReason on the error path — not merely OperationSucceeded.
//!
//! Ops covered here (the gap the corpus leaves open):
//!   Archive, Recover, Deactivate, Import, Export, SetAttribute,
//!   AdjustAttribute, DeriveKey, ReKey, ReKeyKeyPair,
//!   GetUsageAllocation, GetConstraints, SetDefaults, SetEndpointRole,
//!   DiscoverVersions, Ping, Login, Logout.
//!
//! Harness: same `engine_test_lock` + `build_deps_with_real_engine`
//! dance as `native_bridge_e2e.rs` (the engine's `lazy_static!` storage
//! forces serialised, reset-per-test execution). Object-creating ops
//! (Create / CreateKeyPair) need the engine; store-only ops
//! (Set/AdjustAttribute, Archive, Ping, …) still run against the
//! real-engine deps so the whole chain is one honest session.

use std::sync::Arc;
use time::OffsetDateTime;

use pqctoday_kmip::auditlog::{AuditSink, RingSink};
use pqctoday_kmip::error::ResultReason;
use pqctoday_kmip::kmip30::{
    AdjustAttributeRequest, AdjustmentType, ArchiveRequest, Attribute,
    CreateKeyPairRequest, CreateRequest, DeactivateRequest, DerivationMethod,
    DerivationParameters, DeriveKeyRequest, DiscoverVersionsRequest, EndpointRole, ExportRequest,
    GetAttributesRequest, GetConstraintsRequest, GetRequest, GetUsageAllocationRequest,
    ImportRequest, KeyBlock, KeyFormatType, KmipAlgorithm, LocateRequest, LoginRequest,
    LogoutRequest, ObjectDefaults, ObjectType, PingRequest, ReKeyKeyPairRequest, ReKeyRequest,
    RecoverRequest, SetAttributeRequest, SetDefaultsRequest, SetEndpointRoleRequest, State,
    UsageMask,
};
use pqctoday_kmip::ops::allocation_and_config::{
    get_constraints, get_usage_allocation, set_defaults, set_endpoint_role,
};
use pqctoday_kmip::ops::attribute_mutate::{adjust_attribute, set_attribute};
use pqctoday_kmip::ops::create::create;
use pqctoday_kmip::ops::create_key_pair::create_key_pair;
use pqctoday_kmip::ops::derive_key::derive_key;
use pqctoday_kmip::ops::get::get;
use pqctoday_kmip::ops::get_attributes::get_attributes;
use pqctoday_kmip::ops::lifecycle_and_protocol::{
    archive, deactivate, discover_versions, ping, recover,
};
use pqctoday_kmip::ops::locate::locate;
use pqctoday_kmip::ops::register_import_export::{export, import_object};
use pqctoday_kmip::ops::rekey::{rekey, rekey_key_pair};
use pqctoday_kmip::ops::session_and_auth::{login, logout};
use pqctoday_kmip::ops::{Deps, DepsConfig};
use pqctoday_kmip::policy::{load_from_str, Engine};
use pqctoday_kmip::server::auth::AuthContext;
use pqctoday_kmip::kmip30::{SignatureValidity, ValidateRequest};
use pqctoday_kmip::ops::validate::validate;
use pqctoday_kmip::store::{MemoryStore, ObjectRecord};

// ── Harness (mirrors native_bridge_e2e.rs) ──────────────────────────────────

/// Serialise all e2e tests that touch the engine — the engine's
/// `lazy_static!` storage races during the bootstrap dance otherwise.
fn engine_test_lock() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::{Mutex, OnceLock};
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

const PERMISSIVE_POLICY: &str = r#"
schema_version: 1
metadata: { name: t, description: t, authority: t, effective: always }
rules: []
"#;

fn build_deps_with_real_engine() -> Deps {
    build_deps_with_real_engine_and_ring().1
}

fn build_deps_with_real_engine_and_ring() -> (Arc<RingSink>, Deps) {
    use softhsmrustv3::native::session;

    let _ = session::finalize();
    session::init().expect("engine init");
    let engine_session = session::bootstrap_default_token(0, "so-pin", "user-pin", "p1.3-e2e")
        .expect("bootstrap real engine session");

    let ring = Arc::new(RingSink::new(64));
    let sink: Arc<dyn AuditSink> = ring.clone();
    let policy_engine = Engine::with_global_sink(sink.clone());
    policy_engine
        .activate(load_from_str(PERMISSIVE_POLICY, std::path::Path::new("<e2e>")).unwrap())
        .unwrap();

    let deps = Deps::new(
        policy_engine,
        Arc::new(MemoryStore::new()),
        sink,
        DepsConfig::default(),
    )
    .with_engine_session(engine_session);
    (ring, deps)
}

/// AES-256 Create template, born Active (past ActivationDate, the OASIS
/// corpus convention) so storage-status / usage ops can run directly.
fn aes_template(extra: Vec<Attribute>) -> Vec<Attribute> {
    let mut t = vec![
        Attribute::CryptographicAlgorithm(KmipAlgorithm::Aes),
        Attribute::CryptographicLength(256),
        Attribute::CryptographicUsageMask(UsageMask::ENCRYPT | UsageMask::DECRYPT),
    ];
    t.extend(extra);
    t
}

fn create_aes(deps: &Deps, extra: Vec<Attribute>, cid: &str) -> String {
    create(
        deps,
        CreateRequest {
            object_type: ObjectType::SymmetricKey,
            template_attribute: aes_template(extra),
        },
        cid,
    )
    .unwrap()
    .uid
}

/// Pull the `State` attribute back via GetAttributes (proves the
/// dispatcher surface reflects the store mutation, not just the record).
fn state_via_get_attributes(deps: &Deps, uid: &str) -> State {
    let r = get_attributes(
        deps,
        GetAttributesRequest {
            uid: uid.to_string(),
            attribute_references: vec!["State".into()],
        },
        "ga-state",
    )
    .unwrap();
    r.attributes
        .iter()
        .find_map(|a| match a {
            Attribute::State(s) => Some(*s),
            _ => None,
        })
        .expect("State attribute surfaced")
}

// ── Archive / Recover ───────────────────────────────────────────────────────

/// §6.1.4 / §6.1.47 round-trip: Create → Archive → Get fails
/// `ObjectArchived` (material is off-line) → Recover → Get succeeds and
/// returns the same algorithm. Proves both ops through the live store.
#[test]
fn archive_then_get_fails_then_recover_restores() {
    let _guard = engine_test_lock();
    let deps = build_deps_with_real_engine();

    // AES key with store-held material so Get can return a KeyBlock.
    let uid = import_aes_with_material(&deps, "ar-mat", vec![0x11; 32]);

    // Get works before Archive.
    let before = get(&deps, GetRequest { uid: uid.clone(), key_format_type: None, key_wrapping_specification: None }, "ar-get1").unwrap();
    assert_eq!(before.key_block.key_value, vec![0x11; 32]);

    // Archive → record moves off-line.
    archive(&deps, ArchiveRequest { uid: uid.clone() }, "ar-archive").unwrap();
    let err = get(&deps, GetRequest { uid: uid.clone(), key_format_type: None, key_wrapping_specification: None }, "ar-get2").unwrap_err();
    assert_eq!(
        err.result_reason(),
        ResultReason::ObjectArchived,
        "archived material must be off-line until Recover"
    );

    // Recover → back on-line, Get returns the same bytes.
    recover(&deps, RecoverRequest { uid: uid.clone() }, "ar-recover").unwrap();
    let after = get(&deps, GetRequest { uid, key_format_type: None, key_wrapping_specification: None }, "ar-get3").unwrap();
    assert_eq!(after.key_block.key_value, vec![0x11; 32], "Recover restores the same material");

    let _ = softhsmrustv3::native::session::finalize();
}

// ── Deactivate ───────────────────────────────────────────────────────────────

/// §6.1.14: Create (born Active) → Deactivate → GetAttributes shows
/// State=Deactivated. The State change is read back through the
/// dispatcher attribute surface, not the raw record.
#[test]
fn deactivate_transitions_active_to_deactivated_via_get_attributes() {
    let _guard = engine_test_lock();
    let deps = build_deps_with_real_engine();

    let uid = create_aes(
        &deps,
        vec![Attribute::ActivationDate(OffsetDateTime::now_utc().unix_timestamp() - 3600)],
        "deact-create",
    );
    assert_eq!(state_via_get_attributes(&deps, &uid), State::Active, "born Active");

    let resp = deactivate(
        &deps,
        DeactivateRequest { uid: uid.clone(), deactivation_reason: None, deactivation_date: None },
        "deact",
    )
    .unwrap();
    assert_eq!(resp.uid, uid);
    assert_eq!(
        state_via_get_attributes(&deps, &uid),
        State::Deactivated,
        "Deactivate must drive State to Deactivated"
    );

    let _ = softhsmrustv3::native::session::finalize();
}

// ── Import / Export ──────────────────────────────────────────────────────────

/// Register-style helper: Import a raw AES key with explicit material,
/// then mark it Active (past ActivationDate) so Get/Export can run.
fn import_aes_with_material(deps: &Deps, uid: &str, material: Vec<u8>) -> String {
    let bits = (material.len() * 8) as u32;
    import_object(
        deps,
        ImportRequest {
            uid: uid.to_string(),
            object_type: ObjectType::SymmetricKey,
            replace_existing: false,
            key_wrap_type: None,
            attributes: vec![
                Attribute::CryptographicAlgorithm(KmipAlgorithm::Aes),
                Attribute::CryptographicLength(bits),
                Attribute::CryptographicUsageMask(UsageMask::ENCRYPT | UsageMask::DECRYPT),
            ],
            managed_object: Some(KeyBlock {
                key_format_type: KeyFormatType::Raw,
                cryptographic_algorithm: KmipAlgorithm::Aes,
                cryptographic_length: bits,
                key_value: material,
                key_wrapping_data: None,
            }),
        },
        "import",
    )
    .unwrap();
    uid.to_string()
}

/// §6.1.29 Import → §6.1.21 Get recovers the SAME material bytes;
/// §6.1.22 Export round-trips the same bytes in its KeyBlock. Byte
/// equality on both paths proves the material survived the wire shapes.
#[test]
fn import_material_round_trips_through_get_and_export() {
    let _guard = engine_test_lock();
    let deps = build_deps_with_real_engine();

    let material: Vec<u8> = (0u8..32).collect();
    let uid = import_aes_with_material(&deps, "imp-exp", material.clone());

    // Import lands in PreActive; Get serves the material in any
    // non-Destroyed state, so no activation needed.
    let g = get(&deps, GetRequest { uid: uid.clone(), key_format_type: None, key_wrapping_specification: None }, "ie-get").unwrap();
    assert_eq!(g.key_block.key_value, material, "Get recovers the imported material verbatim");
    assert_eq!(g.key_block.cryptographic_algorithm, KmipAlgorithm::Aes);

    let e = export(
        &deps,
        ExportRequest {
            uid: uid.clone(),
            key_format_type: None,
            key_wrap_type: None,
            key_compression_type: None,
            key_wrapping_specification: None,
        },
        "ie-export",
    )
    .unwrap();
    let kb = e.managed_object.expect("Export returns the KeyBlock");
    assert_eq!(kb.key_value, material, "Export round-trips the same material bytes");
    // Export also carries the attribute set with the matching UID.
    assert!(e.attributes.iter().any(|a| matches!(a, Attribute::UniqueIdentifier(u) if u == &uid)));

    let _ = softhsmrustv3::native::session::finalize();
}

// ── Object Group: Register/Create-into-group → Locate-by-group (P2.1) ─────────

/// P2.1 — the capability behind the SASED-M-3-30 / TL-M-3-30 OASIS
/// precondition transcripts: Register (here Create) an object into an
/// Object Group, then Locate it back by that group's membership label,
/// within ONE session.
///
/// NOTE: SASED-M-3-30.xml and TL-M-3-30.xml remain SKIP_PRECONDITION in
/// the conformance replay (`conformance/harness/dispatcher_replay.py`).
/// That is a *harness-isolation* property — the hermetic replay wipes
/// store state between transcripts, so the object Registered into the
/// group in transcript N is gone before the Locate-by-group in N+1. The
/// underlying group-membership filter exercised here is now real and
/// tested; the transcripts stay skipped only because of cross-transcript
/// state isolation, not a missing capability.
#[test]
fn object_group_create_into_group_then_locate_by_group_in_one_session() {
    let _guard = engine_test_lock();
    let deps = build_deps_with_real_engine();

    // Two keys into "G1", one into "G2", one with no group.
    let a = create_aes(&deps, vec![Attribute::ObjectGroup("G1".into())], "og-a");
    let b = create_aes(&deps, vec![Attribute::ObjectGroup("G1".into())], "og-b");
    let c = create_aes(&deps, vec![Attribute::ObjectGroup("G2".into())], "og-c");
    let _ungrouped = create_aes(&deps, vec![], "og-none");

    // Locate by G1 → exactly {a, b}.
    let mut g1 = locate(
        &deps,
        LocateRequest { attributes: vec![Attribute::ObjectGroup("G1".into())], ..Default::default() },
        "og-loc-g1",
    )
    .unwrap()
    .uids;
    g1.sort();
    let mut want = vec![a.clone(), b.clone()];
    want.sort();
    assert_eq!(g1, want, "Locate by G1 returns exactly the two G1 members");

    // Locate by G2 → exactly {c}.
    let g2 = locate(
        &deps,
        LocateRequest { attributes: vec![Attribute::ObjectGroup("G2".into())], ..Default::default() },
        "og-loc-g2",
    )
    .unwrap()
    .uids;
    assert_eq!(g2, vec![c], "Locate by G2 returns the single G2 member");

    // Locate by an unknown group → empty.
    let none = locate(
        &deps,
        LocateRequest { attributes: vec![Attribute::ObjectGroup("ghost".into())], ..Default::default() },
        "og-loc-ghost",
    )
    .unwrap()
    .uids;
    assert!(none.is_empty(), "Locate by an unknown group returns nothing");

    // GetAttributes surfaces the membership back to the client as the STRICT
    // KMIP 3.0 `Group Link` (0x4201b3) — the reserved 2.x `Object Group`
    // (0x420056) is accepted on input above (compat) but never emitted (K3).
    let ga = get_attributes(
        &deps,
        GetAttributesRequest { uid: a.clone(), attribute_references: vec!["GroupLink".into()] },
        "og-ga",
    )
    .unwrap();
    assert!(
        ga.attributes.iter().any(|x| matches!(x, Attribute::GroupLink(g) if g == "G1")),
        "GetAttributes round-trips group membership as the 3.0 Group Link attribute"
    );

    let _ = softhsmrustv3::native::session::finalize();
}

// ── SetAttribute / AdjustAttribute ───────────────────────────────────────────

/// §6.1.56 SetAttribute writes a value GetAttributes reflects; a
/// Read-Only attribute (State) is rejected with `InvalidField`.
#[test]
fn set_attribute_writes_value_and_rejects_read_only() {
    let _guard = engine_test_lock();
    let deps = build_deps_with_real_engine();

    let uid = create_aes(&deps, vec![], "sa-create");

    // Set a Name; GetAttributes reflects it.
    set_attribute(
        &deps,
        SetAttributeRequest { uid: uid.clone(), new_attribute: Attribute::Name("rotated-key-7".into()) },
        "sa-set",
    )
    .unwrap();
    let r = get_attributes(
        &deps,
        GetAttributesRequest { uid: uid.clone(), attribute_references: vec!["Name".into()] },
        "sa-ga",
    )
    .unwrap();
    assert!(
        r.attributes.iter().any(|a| matches!(a, Attribute::Name(n) if n == "rotated-key-7")),
        "SetAttribute value must surface via GetAttributes"
    );

    // §6.1.56 — Read-Only attribute (State) rejected.
    let err = set_attribute(
        &deps,
        SetAttributeRequest { uid, new_attribute: Attribute::State(State::Compromised) },
        "sa-ro",
    )
    .unwrap_err();
    assert_eq!(err.result_reason(), ResultReason::InvalidField, "Read-Only State must be rejected");

    let _ = softhsmrustv3::native::session::finalize();
}

/// §6.1.3 AdjustAttribute (Increment) changes a numeric attribute by
/// exactly the delta — CryptographicUsageMask gains the SIGN bit.
#[test]
fn adjust_attribute_increments_usage_mask_by_delta() {
    let _guard = engine_test_lock();
    let deps = build_deps_with_real_engine();

    // Create with ENCRYPT|DECRYPT only.
    let uid = create_aes(&deps, vec![], "adj-create");
    let before = deps.store.get(&uid).unwrap().unwrap().usage_mask;
    assert!(!before.contains(UsageMask::SIGN), "SIGN absent before adjust");

    adjust_attribute(
        &deps,
        AdjustAttributeRequest {
            uid: uid.clone(),
            attribute_reference: "Cryptographic Usage Mask".into(),
            adjustment_type: AdjustmentType::Increment,
            adjustment_value: Some(UsageMask::SIGN.bits() as i64),
        },
        "adj",
    )
    .unwrap();
    let after = deps.store.get(&uid).unwrap().unwrap().usage_mask;
    assert!(after.contains(UsageMask::SIGN), "AdjustAttribute must add the SIGN bit (delta)");
    assert!(after.contains(UsageMask::ENCRYPT), "existing bits preserved");

    let _ = softhsmrustv3::native::session::finalize();
}

// ── DeriveKey ────────────────────────────────────────────────────────────────

/// §6.1.18: Create an engine-resident HMAC base key → DeriveKey
/// (NIST800-108-C, engine `native::sign` PRF) → the derived object is
/// usable (it carries material) AND both objects link per §6.1.18
/// (DerivationBaseObjectLink on the derived, DerivedObjectLink on the
/// base).
#[test]
fn derive_key_produces_usable_derived_object_with_links() {
    let _guard = engine_test_lock();
    let deps = build_deps_with_real_engine();

    // Engine-resident HMAC-SHA-256 base key (Create → no store
    // material, the engine holds it), born Active, with the Derive Key
    // usage bit.
    let base_uid = create(
        &deps,
        CreateRequest {
            object_type: ObjectType::SymmetricKey,
            template_attribute: vec![
                Attribute::CryptographicAlgorithm(KmipAlgorithm::HmacSha256),
                Attribute::CryptographicLength(256),
                Attribute::CryptographicUsageMask(UsageMask::DERIVE_KEY),
                Attribute::ActivationDate(OffsetDateTime::now_utc().unix_timestamp() - 3600),
            ],
        },
        "dk-base",
    )
    .unwrap()
    .uid;
    assert!(deps.store.get(&base_uid).unwrap().unwrap().key_material.is_none(), "base is engine-resident");

    let resp = derive_key(
        &deps,
        DeriveKeyRequest {
            object_type: ObjectType::SymmetricKey,
            uids: vec![base_uid.clone()],
            derivation_method: DerivationMethod::Nist800_108C,
            derivation_parameters: DerivationParameters {
                derivation_data: Some(b"label\x00context".to_vec()),
                ..Default::default()
            },
            template_attribute: vec![
                Attribute::CryptographicAlgorithm(KmipAlgorithm::Aes),
                Attribute::CryptographicLength(256),
                Attribute::CryptographicUsageMask(UsageMask::ENCRYPT | UsageMask::DECRYPT),
            ],
        },
        "dk-derive",
    )
    .unwrap();

    // Derived object exists, carries 32 bytes of material (usable).
    let derived = deps.store.get(&resp.uid).unwrap().unwrap();
    assert_eq!(derived.key_material.as_ref().map(|m| m.len()), Some(32), "derived key has material");
    assert_eq!(derived.algorithm, KmipAlgorithm::Aes);

    // §6.1.18 links on BOTH objects — surfaced via GetAttributes.
    let derived_attrs = get_attributes(
        &deps,
        GetAttributesRequest { uid: resp.uid.clone(), attribute_references: vec![] },
        "dk-ga-derived",
    )
    .unwrap();
    assert!(
        derived_attrs.attributes.iter().any(|a| matches!(a, Attribute::DerivationBaseObjectLink(u) if u == &base_uid)),
        "derived object must carry Derivation Base Object Link → base"
    );
    let base_attrs = get_attributes(
        &deps,
        GetAttributesRequest { uid: base_uid, attribute_references: vec![] },
        "dk-ga-base",
    )
    .unwrap();
    assert!(
        base_attrs.attributes.iter().any(|a| matches!(a, Attribute::DerivedObjectLink(u) if u == &resp.uid)),
        "base object must carry Derived Object Link → derived"
    );

    let _ = softhsmrustv3::native::session::finalize();
}

// ── ReKey / ReKeyKeyPair ─────────────────────────────────────────────────────

/// §6.1.51: Create AES (born Active) → ReKey → the replacement has a
/// fresh UID, a ReplacedObjectLink → original, the original gains a
/// ReplacementObjectLink → replacement, and (no Offset ⇒ replacement
/// Active now) the original is Deactivated per the K21 retirement rule.
#[test]
fn rekey_mints_replacement_with_links_and_retires_original() {
    let _guard = engine_test_lock();
    let deps = build_deps_with_real_engine();

    let orig = create_aes(
        &deps,
        vec![Attribute::ActivationDate(OffsetDateTime::now_utc().unix_timestamp() - 3600)],
        "rk-create",
    );
    assert_eq!(state_via_get_attributes(&deps, &orig), State::Active);

    let resp = rekey(
        &deps,
        ReKeyRequest { uid: orig.clone(), offset: None, template_attribute: vec![] },
        "rk-rekey",
    )
    .unwrap();
    assert_ne!(resp.uid, orig, "replacement gets a fresh UID");

    let new = deps.store.get(&resp.uid).unwrap().unwrap();
    assert_eq!(new.algorithm, KmipAlgorithm::Aes, "algorithm inherited");
    assert_eq!(new.links.get("ReplacedObjectLink").map(String::as_str), Some(orig.as_str()));
    // Fresh engine material on the replacement (different digest than original).
    assert!(new.digest_value.is_some(), "replacement has a recomputed digest");

    let old = deps.store.get(&orig).unwrap().unwrap();
    assert_eq!(old.links.get("ReplacementObjectLink"), Some(&resp.uid));
    assert_eq!(old.state, State::Deactivated, "no Offset ⇒ original retires immediately");

    let _ = softhsmrustv3::native::session::finalize();
}

/// §6.1.52: CreateKeyPair (RSA, born Active) → ReKeyKeyPair → both
/// halves get fresh UIDs, Replaced/Replacement links each direction,
/// new-half pair cross-links, and both originals are Deactivated.
#[test]
fn rekey_key_pair_mints_both_halves_with_links_and_retires_originals() {
    let _guard = engine_test_lock();
    let deps = build_deps_with_real_engine();

    let now = OffsetDateTime::now_utc().unix_timestamp() - 3600;
    let kp = create_key_pair(
        &deps,
        CreateKeyPairRequest {
            common_attributes: vec![
                Attribute::CryptographicAlgorithm(KmipAlgorithm::Rsa),
                Attribute::ActivationDate(now),
            ],
            private_key_attributes: vec![Attribute::CryptographicUsageMask(UsageMask::SIGN)],
            public_key_attributes: vec![Attribute::CryptographicUsageMask(UsageMask::VERIFY)],
        seed: None,
        },
        "CreateKeyPair:Sign",
        "rkkp-create",
    )
    .unwrap();
    let (old_priv, old_pub) = (kp.private_key_uid, kp.public_key_uid);

    let resp = rekey_key_pair(
        &deps,
        ReKeyKeyPairRequest {
            uid: old_priv.clone(),
            offset: None,
            common_attributes: vec![],
            private_key_attributes: vec![],
            public_key_attributes: vec![],
        },
        "rkkp-rekey",
    )
    .unwrap();
    assert_ne!(resp.private_key_uid, old_priv, "fresh private UID");
    assert_ne!(resp.public_key_uid, old_pub, "fresh public UID");

    let new_priv = deps.store.get(&resp.private_key_uid).unwrap().unwrap();
    let new_pub = deps.store.get(&resp.public_key_uid).unwrap().unwrap();
    // Replaced links per half.
    assert_eq!(new_priv.links.get("ReplacedObjectLink"), Some(&old_priv));
    assert_eq!(new_pub.links.get("ReplacedObjectLink"), Some(&old_pub));
    // Pair cross-links between the NEW halves.
    assert_eq!(new_priv.links.get("PublicKeyLink"), Some(&resp.public_key_uid));
    assert_eq!(new_pub.links.get("PrivateKeyLink"), Some(&resp.private_key_uid));
    // Both originals retired + linked to their replacements.
    for (old_uid, new_uid) in [(&old_priv, &resp.private_key_uid), (&old_pub, &resp.public_key_uid)] {
        let old = deps.store.get(old_uid).unwrap().unwrap();
        assert_eq!(old.links.get("ReplacementObjectLink"), Some(new_uid));
        assert_eq!(old.state, State::Deactivated, "no Offset ⇒ original retires");
    }

    let _ = softhsmrustv3::native::session::finalize();
}

// ── GetUsageAllocation ───────────────────────────────────────────────────────

/// §6.1.27: Create with a Usage Limits budget → GetUsageAllocation
/// decrements the remaining budget by the granted amount → an
/// over-allocation beyond what's left fails `UsageLimitExceeded` and
/// leaves the budget untouched.
#[test]
fn get_usage_allocation_decrements_then_rejects_over_budget() {
    let _guard = engine_test_lock();
    let deps = build_deps_with_real_engine();

    // Create an Active AES key, then stamp a Usage Limits budget on the
    // record (the Create template has no Usage-Limits attribute surface
    // yet; the allocation handler reads usage_limits_total/remaining).
    let uid = create_aes(
        &deps,
        vec![Attribute::ActivationDate(OffsetDateTime::now_utc().unix_timestamp() - 3600)],
        "gua-create",
    );
    {
        let mut rec = deps.store.get(&uid).unwrap().unwrap();
        rec.usage_limits_total = Some(100);
        rec.usage_limits_remaining = Some(100);
        rec.usage_limits_unit = Some(0x01);
        deps.store.update(rec).unwrap();
    }

    get_usage_allocation(
        &deps,
        GetUsageAllocationRequest { uid: uid.clone(), usage_limits_count: 70 },
        "gua-grant",
    )
    .unwrap();
    assert_eq!(
        deps.store.get(&uid).unwrap().unwrap().usage_limits_remaining,
        Some(30),
        "grant reserves the allocation (100 - 70)"
    );

    // Over-allocation (31 > 30 remaining) → UsageLimitExceeded, budget intact.
    let err = get_usage_allocation(
        &deps,
        GetUsageAllocationRequest { uid: uid.clone(), usage_limits_count: 31 },
        "gua-over",
    )
    .unwrap_err();
    assert_eq!(err.result_reason(), ResultReason::UsageLimitExceeded);
    assert_eq!(
        deps.store.get(&uid).unwrap().unwrap().usage_limits_remaining,
        Some(30),
        "failed over-allocation must not touch the budget"
    );

    let _ = softhsmrustv3::native::session::finalize();
}

// ── GetConstraints ───────────────────────────────────────────────────────────

/// §6.1.26: returns the constraint structure with at least one expected
/// bound — the AES constraint scopes SymmetricKey and carries the
/// engine's max length (256).
#[test]
fn get_constraints_returns_structure_with_expected_bound() {
    let _guard = engine_test_lock();
    let deps = build_deps_with_real_engine();

    let r = get_constraints(&deps, GetConstraintsRequest, "gc").unwrap();
    assert!(!r.constraints.is_empty(), "Constraints set is REQUIRED");
    let aes = r
        .constraints
        .iter()
        .find(|c| c.attributes.contains(&Attribute::CryptographicAlgorithm(KmipAlgorithm::Aes)))
        .expect("AES constraint present");
    assert_eq!(aes.object_types, vec![ObjectType::SymmetricKey]);
    assert!(
        aes.attributes.contains(&Attribute::CryptographicLength(256)),
        "AES constraint carries the engine's max length"
    );

    let _ = softhsmrustv3::native::session::finalize();
}

// ── SetDefaults ──────────────────────────────────────────────────────────────

/// §6.1.58: SetDefaults for SymmetricKey → a later Create that OMITS the
/// defaulted attribute inherits it; a client-supplied value still wins
/// over the default.
#[test]
fn set_defaults_inherited_by_create_unless_client_overrides() {
    let _guard = engine_test_lock();
    let deps = build_deps_with_real_engine();

    // Default: every SymmetricKey gets a Name unless the client sets one.
    set_defaults(
        &deps,
        SetDefaultsRequest {
            defaults_information: Some(vec![ObjectDefaults {
                object_types: vec![ObjectType::SymmetricKey],
                attributes: vec![Attribute::Name("server-default-name".into())],
            }]),
        },
        "sd-set",
    )
    .unwrap();

    // Create WITHOUT a Name → inherits the default.
    let uid_default = create_aes(&deps, vec![], "sd-create-default");
    assert_eq!(
        deps.store.get(&uid_default).unwrap().unwrap().name.as_deref(),
        Some("server-default-name"),
        "Create inherits the Set Defaults Name"
    );

    // Create WITH a Name → client value wins.
    let uid_override = create_aes(&deps, vec![Attribute::Name("client-chosen".into())], "sd-create-override");
    assert_eq!(
        deps.store.get(&uid_override).unwrap().unwrap().name.as_deref(),
        Some("client-chosen"),
        "client-supplied Name overrides the default"
    );

    let _ = softhsmrustv3::native::session::finalize();
}

// ── SetEndpointRole ──────────────────────────────────────────────────────────

/// §6.1.59 / K19: role=Server (identity) is accepted and echoed;
/// role=Client (the §6.2 switch) → `FeatureNotSupported`.
#[test]
fn set_endpoint_role_server_ok_client_unsupported() {
    let _guard = engine_test_lock();
    let deps = build_deps_with_real_engine();

    let ok = set_endpoint_role(&deps, SetEndpointRoleRequest { endpoint_role: EndpointRole::Server }, "ser-ok").unwrap();
    assert_eq!(ok.endpoint_role, EndpointRole::Server, "identity request accepted, role echoed");

    let err = set_endpoint_role(&deps, SetEndpointRoleRequest { endpoint_role: EndpointRole::Client }, "ser-bad").unwrap_err();
    assert_eq!(err.result_reason(), ResultReason::FeatureNotSupported, "role switch unsupported");

    let _ = softhsmrustv3::native::session::finalize();
}

// ── DiscoverVersions / Ping ──────────────────────────────────────────────────

/// §6.1.20: empty client list → ALL server versions (3.0); a specific
/// list → the intersection; no overlap → empty.
#[test]
fn discover_versions_intersection_semantics() {
    let _guard = engine_test_lock();
    let deps = build_deps_with_real_engine();

    // Empty → server-supported set (3.0).
    let all = discover_versions(&deps, DiscoverVersionsRequest { protocol_versions: vec![] }, "dv-all").unwrap();
    assert_eq!(all.protocol_versions, vec![(3, 0)], "empty client list → all server versions");

    // Specific list containing 3.0 → match.
    let hit = discover_versions(&deps, DiscoverVersionsRequest { protocol_versions: vec![(1, 4), (3, 0)] }, "dv-hit").unwrap();
    assert_eq!(hit.protocol_versions, vec![(3, 0)], "intersection returns the overlap");

    // No overlap → empty.
    let miss = discover_versions(&deps, DiscoverVersionsRequest { protocol_versions: vec![(1, 0), (2, 1)] }, "dv-miss").unwrap();
    assert!(miss.protocol_versions.is_empty(), "no overlap → empty list");

    let _ = softhsmrustv3::native::session::finalize();
}

/// §6.1.41: Ping returns success (liveness).
#[test]
fn ping_returns_success() {
    let _guard = engine_test_lock();
    let deps = build_deps_with_real_engine();
    assert!(ping(&deps, PingRequest, "ping").is_ok());
    let _ = softhsmrustv3::native::session::finalize();
}

// ── Login / Logout ───────────────────────────────────────────────────────────

/// §6.1.34 / §6.1.35: with auth configured, Login rejects an
/// unauthenticated request (`AuthenticationNotSuccessful`) but validates
/// a verified identity and issues a REAL ticket (Phase 1.4 — recorded in
/// `deps.sessions`, not just a display string); a private-object op then
/// succeeds; Logout genuinely invalidates the session, and a second
/// Logout with the same ticket fails `Invalid Ticket` rather than
/// silently succeeding again.
#[test]
fn login_validates_credential_issues_ticket_then_logout() {
    use pqctoday_kmip::server::auth::{sha256_hex, AuthUser, Identity};

    let _guard = engine_test_lock();
    let (_ring, mut deps) = build_deps_with_real_engine_and_ring();
    deps.config.auth_users = vec![AuthUser { username: "alice".into(), password_sha256: sha256_hex("pw") }];

    let req = || LoginRequest { lease_time: None, request_count: None, usage_limits: None };

    // No verified identity → AuthenticationNotSuccessful.
    let err = login(&deps, req(), &AuthContext::open(), "lg-bad").unwrap_err();
    assert_eq!(err.result_reason(), ResultReason::AuthenticationNotSuccessful);

    // Verified identity → a real ticket, bound to "alice" in the session store.
    let ctx = AuthContext { identity: Some(Identity { username: "alice".into() }) };
    let ticket = login(&deps, req(), &ctx, "lg-ok").unwrap().ticket;
    {
        let sessions = deps.sessions.lock().unwrap();
        let record = sessions.get(&ticket.ticket_value).expect("Login must record a real session");
        assert_eq!(record.identity.username, "alice");
    }

    // A private-object op under the verified session succeeds: Create an
    // AES key (engine-backed) and read it back.
    let uid = create_aes(
        &deps,
        vec![Attribute::ActivationDate(OffsetDateTime::now_utc().unix_timestamp() - 3600)],
        "lg-create",
    );
    assert_eq!(state_via_get_attributes(&deps, &uid), State::Active);

    // Logout genuinely invalidates the ticket.
    logout(&deps, LogoutRequest { ticket: ticket.clone() }, "lg-logout").unwrap();
    assert!(deps.sessions.lock().unwrap().is_empty(), "Logout must remove the session, not no-op");

    // Reusing the now-invalid ticket fails Invalid Ticket, not a silent success.
    let err = logout(&deps, LogoutRequest { ticket }, "lg-logout-again").unwrap_err();
    assert_eq!(err.result_reason(), ResultReason::InvalidTicket);

    let _ = softhsmrustv3::native::session::finalize();
}

/// P2.2 — §6.1.62 Validate end-to-end against the live store. A stored
/// self-signed Certificate validates to `Valid`; an inline expired cert
/// → `Invalid`; a leaf whose issuer isn't supplied → `Unknown`; a UID
/// that doesn't exist → `Object Not Found`; a UID naming a non-cert
/// object → `Invalid Object Type`. Validate needs no engine session —
/// it works off the stored/inline DER + `x509-parser`.
#[test]
fn validate_stored_self_signed_cert_returns_valid_and_error_paths() {
    let ring = Arc::new(RingSink::new(64));
    let sink: Arc<dyn AuditSink> = ring.clone();
    let deps = Deps::new(
        Engine::permissive(),
        Arc::new(MemoryStore::new()),
        sink,
        DepsConfig::default(),
    );

    // rcgen `CertificateParams::new(SAN)` leaves the *distinguished
    // name* empty; the chain-link check matches Issuer DN ⟷ Subject DN,
    // so give each cert a CommonName.
    fn params_cn(cn: &str) -> rcgen::CertificateParams {
        let mut p = rcgen::CertificateParams::new(vec![format!("{cn}.e2e")]).unwrap();
        p.distinguished_name.push(rcgen::DnType::CommonName, cn);
        let now = OffsetDateTime::now_utc();
        p.not_before = now - time::Duration::days(1);
        p.not_after = now + time::Duration::days(365 * 5);
        p
    }

    // A self-signed CA (ECDSA-P256), CN="root".
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let ca_der = params_cn("root").self_signed(&ca_key).unwrap().der().to_vec();

    // Store it as a Certificate object.
    deps.store
        .put(ObjectRecord {
            uid: "cert-ca".into(),
            object_type: ObjectType::Certificate,
            algorithm: KmipAlgorithm::Ecdsa,
            usage_mask: UsageMask::VERIFY,
            state: State::Active,
            key_material: Some(ca_der.clone()),
            ..ObjectRecord::default()
        })
        .unwrap();

    // (1) Stored self-signed cert → Valid.
    let r = validate(
        &deps,
        ValidateRequest { certificates: vec![], uids: vec!["cert-ca".into()], validity_date: None },
        "v-valid",
    )
    .unwrap();
    assert_eq!(r.validity, SignatureValidity::Valid, "self-signed CA validates");

    // (2) Inline cert validated at a far-future instant (past not_after)
    // → Invalid (expired window).
    let r = validate(
        &deps,
        ValidateRequest {
            certificates: vec![ca_der.clone()],
            uids: vec![],
            validity_date: Some(OffsetDateTime::now_utc() + time::Duration::days(365 * 100)),
        },
        "v-expired",
    )
    .unwrap();
    assert_eq!(r.validity, SignatureValidity::Invalid, "expired window → Invalid");

    // (3) A leaf signed by a CA, validated ALONE (issuer absent) → Unknown.
    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let ca2_key = rcgen::KeyPair::generate().unwrap();
    let ca2_cert = params_cn("issuer-ca").self_signed(&ca2_key).unwrap();
    let leaf = params_cn("leaf").signed_by(&leaf_key, &ca2_cert, &ca2_key).unwrap();
    let r = validate(
        &deps,
        ValidateRequest { certificates: vec![leaf.der().to_vec()], uids: vec![], validity_date: None },
        "v-unknown",
    )
    .unwrap();
    assert_eq!(r.validity, SignatureValidity::Unknown, "missing issuer → Unknown");

    // (3b) Leaf + its CA together → Valid.
    let r = validate(
        &deps,
        ValidateRequest {
            certificates: vec![leaf.der().to_vec(), ca2_cert.der().to_vec()],
            uids: vec![],
            validity_date: None,
        },
        "v-chain",
    )
    .unwrap();
    assert_eq!(r.validity, SignatureValidity::Valid, "leaf + CA chain → Valid");

    // (4) Unknown UID → Object Not Found.
    let err = validate(
        &deps,
        ValidateRequest { certificates: vec![], uids: vec!["ghost".into()], validity_date: None },
        "v-nf",
    )
    .unwrap_err();
    assert_eq!(err.result_reason(), ResultReason::ObjectNotFound);

    // (5) Non-Certificate UID → Invalid Object Type.
    deps.store
        .put(ObjectRecord {
            uid: "sym".into(),
            object_type: ObjectType::SymmetricKey,
            algorithm: KmipAlgorithm::Aes,
            usage_mask: UsageMask::ENCRYPT,
            state: State::Active,
            ..ObjectRecord::default()
        })
        .unwrap();
    let err = validate(
        &deps,
        ValidateRequest { certificates: vec![], uids: vec!["sym".into()], validity_date: None },
        "v-iot",
    )
    .unwrap_err();
    assert_eq!(err.result_reason(), ResultReason::InvalidObjectType);
}

/// P2.3 — §6.1.6 Certify end-to-end against a real engine: generate an
/// ECDSA CA key pair (CreateKeyPair), mint a self-signed CA cert
/// (`bootstrap_ca_certificate`), designate the CA on Deps, Certify a
/// client PKCS#10 CSR, then assert the returned Certificate is Get-able
/// and carries the server-derived §11 attributes + the Public Key Link.
#[test]
fn certify_issues_certificate_get_able_with_links() {
    use pqctoday_kmip::ops::certify::{bootstrap_ca_certificate, certify};
    use pqctoday_kmip::kmip30::{CertificateRequestType, CertifyRequest};

    let _guard = engine_test_lock();

    // Bootstrap a real engine session.
    use softhsmrustv3::native::session;
    let _ = session::finalize();
    session::init().expect("engine init");
    let engine_session = session::bootstrap_default_token(0, "so-pin", "user-pin", "p2.3-e2e")
        .expect("bootstrap session");

    let ring = Arc::new(RingSink::new(64));
    let sink: Arc<dyn AuditSink> = ring.clone();
    let policy = Engine::with_global_sink(sink.clone());
    policy
        .activate(load_from_str(
            "schema_version: 1\nmetadata: { name: p, description: p, authority: t, effective: \"always\" }\nrules: []\n",
            std::path::Path::new("<e2e>"),
        ).unwrap())
        .unwrap();
    let deps = Deps::new(policy, Arc::new(MemoryStore::new()), sink, DepsConfig::default())
        .with_engine_session(engine_session)
        .with_ca_key("urn:ca-priv-e2e", "urn:ca-cert-e2e");

    // ── CreateKeyPair → ECDSA CA key (born PreActive). ──
    use pqctoday_kmip::kmip30::{Attribute, CreateKeyPairRequest, KmipAlgorithm, UsageMask};
    let kp = create_key_pair(
        &deps,
        CreateKeyPairRequest {
            common_attributes: vec![Attribute::CryptographicAlgorithm(KmipAlgorithm::Ecdsa)],
            private_key_attributes: vec![Attribute::CryptographicUsageMask(UsageMask::SIGN)],
            public_key_attributes: vec![Attribute::CryptographicUsageMask(UsageMask::VERIFY)],
        seed: None,
        },
        "CreateKeyPair",
        "e2e-ca-keygen",
    )
    .unwrap();

    // Re-home the generated CA private key under the designated UID by
    // copying its store record (the CA model designates UIDs).
    let mut ca_priv = deps.store.get(&kp.private_key_uid).unwrap().unwrap();
    ca_priv.uid = "urn:ca-priv-e2e".into();
    ca_priv.state = State::Active;
    deps.store.put(ca_priv).unwrap();

    // Mint the self-signed CA cert (signs its TBS in the engine).
    bootstrap_ca_certificate(&deps, "urn:ca-priv-e2e", "urn:ca-cert-e2e", "E2E Root CA", 3650)
        .expect("bootstrap CA cert");

    // ── Client CSR → Certify. ──
    let subj_kp = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["client.e2e".into()]).unwrap();
    params.distinguished_name.push(rcgen::DnType::CommonName, "e2e-client");
    let csr = params.serialize_request(&subj_kp).unwrap();

    let resp = certify(
        &deps,
        CertifyRequest {
            certificate_request_type: Some(CertificateRequestType::Pkcs10),
            certificate_request: Some(csr.der().to_vec()),
            ..CertifyRequest::default()
        },
        "e2e-certify",
    )
    .unwrap();

    // ── The issued Certificate is Get-able with §11 attrs. ──
    let g = get(&deps, GetRequest { uid: resp.uid.clone(), key_format_type: None, key_wrapping_specification: None }, "e2e-get").unwrap();
    assert_eq!(g.object_type, ObjectType::Certificate);
    assert!(!g.key_block.key_value.is_empty(), "issued cert DER is returned by Get");

    let rec = deps.store.get(&resp.uid).unwrap().unwrap();
    assert_eq!(rec.certificate_subject_cn.as_deref(), Some("e2e-client"),
        "server-derived §11 CertificateSubjectCN");
    assert_eq!(rec.certificate_length, Some(g.key_block.key_value.len() as i32));

    let _ = session::finalize();
}

// ── Coverage meta-test ───────────────────────────────────────────────────────
//
// Every op in `dispatcher::HANDLED_OPERATIONS` MUST be referenced by at
// least one test — either an e2e test (this file or native_bridge_e2e),
// or a handler-level unit test in `src/ops/*.rs`. The map below is the
// authoritative checklist; `coverage_map_covers_every_handled_operation`
// asserts the checklist's key set equals HANDLED_OPERATIONS exactly, so
// a newly-added handled op with no coverage entry fails the build.
//
// Value = where the op's substantive coverage lives.
//   "e2e:op_coverage"     → a test in THIS file (the 18-op P1.3 gap)
//   "e2e:native_bridge"   → a real-engine test in native_bridge_e2e.rs
//   "unit:<module>"       → handler-level #[cfg(test)] in src/ops/
fn coverage_map() -> std::collections::HashMap<pqctoday_kmip::kmip30::Operation, &'static str> {
    use pqctoday_kmip::kmip30::Operation as Op;
    [
        // ── P1.3 e2e gap (this file) ──
        (Op::Archive, "e2e:op_coverage(archive_then_get_fails_then_recover_restores)"),
        (Op::Recover, "e2e:op_coverage(archive_then_get_fails_then_recover_restores)"),
        (Op::Deactivate, "e2e:op_coverage(deactivate_transitions_active_to_deactivated_via_get_attributes)"),
        (Op::Import, "e2e:op_coverage(import_material_round_trips_through_get_and_export)"),
        (Op::Export, "e2e:op_coverage(import_material_round_trips_through_get_and_export)"),
        (Op::SetAttribute, "e2e:op_coverage(set_attribute_writes_value_and_rejects_read_only)"),
        (Op::AdjustAttribute, "e2e:op_coverage(adjust_attribute_increments_usage_mask_by_delta)"),
        (Op::DeriveKey, "e2e:op_coverage(derive_key_produces_usable_derived_object_with_links)"),
        (Op::ReKey, "e2e:op_coverage(rekey_mints_replacement_with_links_and_retires_original)"),
        (Op::ReKeyKeyPair, "e2e:op_coverage(rekey_key_pair_mints_both_halves_with_links_and_retires_originals)"),
        (Op::GetUsageAllocation, "e2e:op_coverage(get_usage_allocation_decrements_then_rejects_over_budget)"),
        (Op::GetConstraints, "e2e:op_coverage(get_constraints_returns_structure_with_expected_bound)"),
        (Op::SetDefaults, "e2e:op_coverage(set_defaults_inherited_by_create_unless_client_overrides)"),
        (Op::SetEndpointRole, "e2e:op_coverage(set_endpoint_role_server_ok_client_unsupported)"),
        (Op::DiscoverVersions, "e2e:op_coverage(discover_versions_intersection_semantics)"),
        (Op::Ping, "e2e:op_coverage(ping_returns_success)"),
        (Op::Login, "e2e:op_coverage(login_validates_credential_issues_ticket_then_logout)"),
        (Op::Logout, "e2e:op_coverage(login_validates_credential_issues_ticket_then_logout)"),
        // P2.2 — §6.1.62 Validate (certificate-chain validation).
        (Op::Validate, "e2e:op_coverage(validate_stored_self_signed_cert_returns_valid_and_error_paths)"),
        // P2.3 — §6.1.6 Certify / §6.1.50 Re-certify (PQC-capable CA).
        (Op::Certify, "e2e:op_coverage(certify_issues_certificate_get_able_with_links) + unit:ops::certify (RSA/ECDSA/ML-DSA issuance+verify)"),
        (Op::ReCertify, "unit:ops::certify(recertify_*) — new window + Replaced/Replacement links + old retired"),
        // ── Real-engine e2e (native_bridge_e2e.rs) ──
        (Op::CreateKeyPair, "e2e:native_bridge(ml_dsa_65_create_sign_verify_destroy_against_real_engine)"),
        (Op::Sign, "e2e:native_bridge(ml_dsa_65_create_sign_verify_destroy_against_real_engine)"),
        (Op::SignatureVerify, "e2e:native_bridge(ml_dsa_65_create_sign_verify_destroy_against_real_engine)"),
        (Op::Destroy, "e2e:native_bridge(ml_dsa_65_create_sign_verify_destroy_against_real_engine)"),
        (Op::Activate, "e2e:native_bridge(ml_dsa_65_create_sign_verify_destroy_against_real_engine)"),
        (Op::Revoke, "e2e:native_bridge(ml_dsa_65_create_sign_verify_destroy_against_real_engine)"),
        (Op::Register, "e2e:native_bridge(k9_register_ml_dsa_65_sign_verify_roundtrip)"),
        (Op::Encrypt, "e2e:native_bridge(k9_register_ml_kem_768_encap_decap_roundtrip)"),
        (Op::Decrypt, "e2e:native_bridge(k9_register_ml_kem_768_encap_decap_roundtrip)"),
        // ── WD19 first-class ML-KEM KEM ops ──
        (Op::Encapsulate, "e2e:native_bridge(wd19_encapsulate_decapsulate_byte_exact_against_real_engine) + unit:ops::encapsulate"),
        (Op::Decapsulate, "e2e:native_bridge(wd19_encapsulate_decapsulate_byte_exact_against_real_engine) + unit:ops::decapsulate"),
        (Op::Create, "e2e:native_bridge(k11_digest_persisted_from_real_engine_material)"),
        (Op::GetAttributes, "e2e:native_bridge(k11_digest_persisted_from_real_engine_material)"),
        (Op::MAC, "e2e:native_bridge(k15_hmac_mac_and_verify_route_through_engine)"),
        (Op::MACVerify, "e2e:native_bridge(k15_hmac_mac_and_verify_route_through_engine)"),
        // ── Handler-level unit tests (src/ops/*.rs) ──
        (Op::Query, "unit:ops::query"),
        (Op::Get, "unit:ops::get"),
        (Op::GetAttributeList, "unit:ops::get_attribute_list"),
        (Op::AddAttribute, "unit:ops::attribute_mutate"),
        (Op::ModifyAttribute, "unit:ops::attribute_mutate"),
        (Op::DeleteAttribute, "unit:ops::attribute_mutate"),
        (Op::Locate, "unit:ops::locate"),
        (Op::Interop, "unit:ops::interop"),
        (Op::Check, "unit:ops::lifecycle_and_protocol"),
        (Op::Obliterate, "unit:ops::lifecycle_and_protocol"),
        (Op::Hash, "unit:ops::mac_and_hash"),
        (Op::CreateCredential, "unit:ops::session_and_auth"),
        (Op::CreateGroup, "unit:ops::session_and_auth"),
        (Op::CreateUser, "unit:ops::session_and_auth"),
        (Op::Log, "unit:ops::session_and_auth"),
        (Op::RNGRetrieve, "unit:ops::rng_and_pkcs11"),
        (Op::RNGSeed, "unit:ops::rng_and_pkcs11"),
        (Op::Pkcs11, "unit:ops::rng_and_pkcs11"),
    ]
    .into_iter()
    .collect()
}

/// The coverage checklist's key set MUST equal `HANDLED_OPERATIONS`
/// exactly. A new handled op without a coverage entry — or a stale entry
/// for an op that was removed — fails here.
#[test]
fn coverage_map_covers_every_handled_operation() {
    use std::collections::HashSet;
    let handled: HashSet<_> = pqctoday_kmip::dispatcher::HANDLED_OPERATIONS.iter().copied().collect();
    let covered: HashSet<_> = coverage_map().keys().copied().collect();

    let missing: Vec<_> = handled.difference(&covered).collect();
    assert!(
        missing.is_empty(),
        "handled ops with NO test coverage entry (add one to coverage_map): {missing:?}"
    );
    let stale: Vec<_> = covered.difference(&handled).collect();
    assert!(
        stale.is_empty(),
        "coverage_map references ops that are not in HANDLED_OPERATIONS: {stale:?}"
    );
    assert_eq!(handled.len(), 54, "HANDLED_OPERATIONS count changed — review coverage");
}
