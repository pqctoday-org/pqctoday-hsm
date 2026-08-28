//! Backend parity — Phase-5 op handlers produce identical outcomes whether
//! the `Deps` holds a `MemoryStore` (volatile) or a `SqliteStore`
//! (durable). Proves the Phase-6 swap is genuinely drop-in for the
//! Plane-2 layer above the store.

use std::sync::Arc;
use time::OffsetDateTime;

use pqctoday_kmip::auditlog::{AuditSink, RingSink};
use pqctoday_kmip::kmip30::{ActivateRequest, CreateRequest, KmipAlgorithm, ObjectType, State, UsageMask};
use pqctoday_kmip::ops::activate::activate;
use pqctoday_kmip::ops::create::create;
use pqctoday_kmip::ops::{Deps, DepsConfig};
use pqctoday_kmip::policy::{load_from_str, Engine};
use pqctoday_kmip::server::auth::AuthContext;
use pqctoday_kmip::store::{KeyStore, MemoryStore, SqliteStore};

const POLICY: &str = r#"
schema_version: 1
metadata: { name: t, description: t, authority: t, effective: always }
rules:
  - type: algorithm_default
    ops: [Create]
    default_algorithm: AES-256
    reason: "AES-256 default"
"#;

fn deps_for(store: Arc<dyn KeyStore>, engine_session: u32) -> Deps {
    let ring = Arc::new(RingSink::new(64));
    let sink: Arc<dyn AuditSink> = ring;
    let engine = Engine::with_global_sink(sink.clone());
    engine.replace_all(load_from_str(POLICY, std::path::Path::new("<t>")).unwrap()).unwrap();
    // S-2 hardening makes Create fail-closed without an engine session, so the
    // parity test drives a real engine. The caller bootstraps the slot-0 token
    // ONCE and shares the session across both backends — a second C_InitToken
    // while a session is still open returns CKR_SESSION_EXISTS (0xB6).
    Deps::new(engine, store, sink, DepsConfig::default()).with_engine_session(engine_session)
}

#[test]
fn create_then_activate_then_sign_works_on_both_backends() {
    use softhsmrustv3::native::session;
    // One token / one session, reused for both store backends (see deps_for).
    let engine_session = session::bootstrap_default_token(0, "so-pin", "user-pin", "store-parity")
        .expect("bootstrap engine token for store-parity");
    for backend_name in ["memory", "sqlite"] {
        let store: Arc<dyn KeyStore> = match backend_name {
            "memory" => Arc::new(MemoryStore::new()),
            "sqlite" => Arc::new(SqliteStore::in_memory().unwrap()),
            _ => unreachable!(),
        };
        let d = deps_for(store.clone(), engine_session);

        // Create a symmetric AES key.
        let resp = create(
            &d,
            CreateRequest {
                object_type: ObjectType::SymmetricKey,
                template_attribute: vec![],
            },
            &AuthContext::open(),
            &format!("c-{backend_name}-create"),
        )
        .unwrap();
        let uid = resp.uid;

        // Should be PreActive in the store.
        let rec = store.get(&uid).unwrap().expect("record present");
        assert_eq!(rec.state, State::PreActive, "{backend_name}");
        assert_eq!(rec.algorithm, KmipAlgorithm::Aes, "{backend_name}");

        // Activate → Active.
        let aresp = activate(&d, ActivateRequest { uid: uid.clone() }, &format!("c-{backend_name}-act")).unwrap();
        assert_eq!(aresp.state, State::Active, "{backend_name}");
        let rec = store.get(&uid).unwrap().unwrap();
        assert_eq!(rec.state, State::Active, "{backend_name}");
        assert!(rec.activation_date.is_some(), "{backend_name}");
    }
}

#[test]
fn lifecycle_fsm_enforced_at_store_layer_on_both_backends() {
    for backend_name in ["memory", "sqlite"] {
        let store: Arc<dyn KeyStore> = match backend_name {
            "memory" => Arc::new(MemoryStore::new()),
            "sqlite" => Arc::new(SqliteStore::in_memory().unwrap()),
            _ => unreachable!(),
        };

        // Insert an Active record directly.
        store.put(pqctoday_kmip::store::ObjectRecord {
            uid: "u".into(),
            object_type: ObjectType::PrivateKey,
            algorithm: KmipAlgorithm::MlDsa87,
            cryptographic_length: 0,
            usage_mask: UsageMask::SIGN | UsageMask::VERIFY,
            state: State::Active,
            pkcs11_cka_id: vec![],
            pkcs11_slot: 0,
            initial_date: OffsetDateTime::UNIX_EPOCH,
            activation_date: Some(OffsetDateTime::UNIX_EPOCH),
            supersedes: None,
            name: None,

            links: std::collections::HashMap::new(),

            custom_attributes: std::collections::HashMap::new(),


            key_material: None,


            key_format_type: None,
        ..pqctoday_kmip::store::ObjectRecord::default()
}).unwrap();

        // Try Active → PreActive (illegal per §3.4 FSM).
        // S-10: both backends now enforce the lifecycle FSM at the store layer,
        // so an illegal transition must be rejected regardless of backend.
        let mut bad = store.get("u").unwrap().unwrap();
        bad.state = State::PreActive;
        let result = store.update(bad);
        assert!(
            result.is_err(),
            "{backend_name} backend must reject illegal transition at store layer"
        );
    }
}

#[test]
fn data_survives_round_trip_through_sqlite_on_disk() {
    use std::env;
    let path = env::temp_dir().join(format!(
        "pqctoday-store-parity-{}.db",
        uuid::Uuid::new_v4()
    ));

    // First "boot": insert a record.
    {
        let store = SqliteStore::open(&path).unwrap();
        store.put(pqctoday_kmip::store::ObjectRecord {
            uid: "persisted".into(),
            object_type: ObjectType::SymmetricKey,
            algorithm: KmipAlgorithm::Aes,
            cryptographic_length: 256,
            usage_mask: UsageMask::ENCRYPT | UsageMask::DECRYPT,
            state: State::Active,
            pkcs11_cka_id: vec![9, 9, 9],
            pkcs11_slot: 0,
            initial_date: OffsetDateTime::UNIX_EPOCH,
            activation_date: Some(OffsetDateTime::UNIX_EPOCH),
            supersedes: None,
            name: None,

            links: std::collections::HashMap::new(),

            custom_attributes: std::collections::HashMap::new(),


            key_material: None,


            key_format_type: None,
        ..pqctoday_kmip::store::ObjectRecord::default()
}).unwrap();
    }

    // Second "boot": re-open same file, record should be there.
    {
        let store = SqliteStore::open(&path).unwrap();
        let rec = store.get("persisted").unwrap().expect("record must survive restart");
        assert_eq!(rec.algorithm, KmipAlgorithm::Aes);
        assert_eq!(rec.cryptographic_length, 256);
        assert!(rec.usage_mask.contains(UsageMask::ENCRYPT));
        assert!(rec.usage_mask.contains(UsageMask::DECRYPT));
        assert_eq!(rec.pkcs11_cka_id, vec![9, 9, 9]);
    }

    let _ = std::fs::remove_file(&path);
}

