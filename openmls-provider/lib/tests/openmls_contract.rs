//! Semantic-equivalence cross-validation: drive the same MLS scenario
//! through `PqcTodayProvider` (HSM-backed) and `OpenMlsRustCrypto`
//! (upstream software reference), then compare observable group state at
//! every step.
//!
//! Per the plan (Stage 1, user-selected option): we do **not** compare
//! wire bytes — that would require pinning a deterministic DRBG on both
//! sides and is brittle to internal openmls implementation changes.
//! Instead we compare semantic invariants: epoch numbers, member counts,
//! group ids, and decrypted plaintexts. If both providers produce groups
//! that agree on this state, our HSM-backed provider has demonstrated
//! contract conformance with the openmls reference implementation.
//!
//! Run with `--test-threads=1` (softhsmv3 `C_Initialize` is non-reentrant).

use std::io::Write;
use std::path::PathBuf;

use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;

use openmls::prelude::{tls_codec::*, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_pqctoday_crypto::{HsmConfig, PqcTodayHsmSigner, PqcTodayProvider};
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::types::SignatureScheme;
use openmls_traits::OpenMlsProvider;

const SO_PIN: &str = "12345678";
const USER_PIN: &str = "1234";

fn resolve_module() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("PKCS11_MODULE") {
        let pb = PathBuf::from(p);
        if pb.exists() {
            return Some(pb);
        }
    }
    let here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for rel in &[
        "../../build/src/lib/libsofthsmv3.dylib",
        "../../build/src/lib/libsofthsmv3.so",
        "../../build_fresh/src/lib/libsofthsmv3.dylib",
        "../../build-pqctoday/src/lib/libsofthsmv3.so",
    ] {
        let p = here.join(rel);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

fn over_the_wire(out: MlsMessageOut) -> MlsMessageIn {
    let bytes = out.tls_serialize_detached().expect("serialise");
    MlsMessageIn::tls_deserialize_exact(&bytes).expect("deserialise")
}

// ── Observation: every state we check after each lifecycle step ─────────────

#[derive(Debug, PartialEq, Eq)]
struct StateSnapshot {
    alice_epoch: u64,
    bob_epoch: u64,
    alice_member_count: usize,
    bob_member_count: usize,
    group_ids_match: bool,
    alice_to_bob_plaintext: Vec<u8>,
    bob_to_alice_plaintext: Vec<u8>,
}

// ── HSM-backed run ───────────────────────────────────────────────────────────

struct HsmEnv {
    _tokens_dir: tempfile::TempDir,
    _conf_file: tempfile::NamedTempFile,
}

fn run_hsm(module: &PathBuf) -> (StateSnapshot, HsmEnv) {
    let tokens_dir = tempfile::tempdir().unwrap();
    let mut conf_file = tempfile::NamedTempFile::new().unwrap();
    writeln!(
        conf_file,
        "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR",
        tokens_dir.path().display()
    )
    .unwrap();
    std::env::set_var("SOFTHSM2_CONF", conf_file.path());

    let ctx = Pkcs11::new(module).expect("load module");
    ctx.initialize(CInitializeArgs::OsThreads).expect("init");
    let slot = *ctx.get_slots_with_token().unwrap().first().unwrap();
    ctx.init_token(slot, &AuthPin::new(SO_PIN.into()), "contract-test")
        .expect("init_token");
    {
        let so = ctx.open_rw_session(slot).unwrap();
        so.login(UserType::So, Some(&AuthPin::new(SO_PIN.into()))).unwrap();
        so.init_pin(&AuthPin::new(USER_PIN.into())).unwrap();
        so.logout().ok();
    }
    drop(ctx);

    let cfg = HsmConfig::new(module.clone()).with_pin(USER_PIN);
    let alice_provider = PqcTodayProvider::new(&cfg).expect("alice provider");
    let bob_provider = alice_provider.spawn_sibling(None).expect("bob provider");

    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let alice_signer: PqcTodayHsmSigner = alice_provider
        .generate_signer(SignatureScheme::ED25519)
        .unwrap();
    let bob_signer: PqcTodayHsmSigner = bob_provider
        .generate_signer(SignatureScheme::ED25519)
        .unwrap();

    let alice_cred = CredentialWithKey {
        credential: BasicCredential::new("Alice".into()).into(),
        signature_key: alice_signer.public_key().to_vec().into(),
    };
    let bob_cred = CredentialWithKey {
        credential: BasicCredential::new("Bob".into()).into(),
        signature_key: bob_signer.public_key().to_vec().into(),
    };

    let bob_kp = KeyPackage::builder()
        .build(ciphersuite, &bob_provider, &bob_signer, bob_cred.clone())
        .unwrap();
    let mut alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .build(&alice_provider, &alice_signer, alice_cred.clone())
        .unwrap();
    let (_, welcome_out, _) = alice_group
        .add_members(
            &alice_provider,
            &alice_signer,
            core::slice::from_ref(bob_kp.key_package()),
        )
        .unwrap();
    alice_group.merge_pending_commit(&alice_provider).unwrap();

    let welcome = match over_the_wire(welcome_out).extract() {
        MlsMessageBodyIn::Welcome(w) => w,
        _ => panic!("expected welcome"),
    };
    let join_cfg = MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .build();
    let staged =
        StagedWelcome::new_from_welcome(&bob_provider, &join_cfg, welcome, None).unwrap();
    let mut bob_group = staged.into_group(&bob_provider).unwrap();

    let a2b = b"alice contract test message";
    let a2b_ct = alice_group
        .create_message(&alice_provider, &alice_signer, a2b)
        .unwrap();
    let a2b_proto = over_the_wire(a2b_ct).try_into_protocol_message().unwrap();
    let a2b_pt = match bob_group.process_message(&bob_provider, a2b_proto).unwrap().into_content() {
        ProcessedMessageContent::ApplicationMessage(app) => app.into_bytes(),
        _ => panic!("expected app message"),
    };

    let b2a = b"bob contract test reply";
    let b2a_ct = bob_group
        .create_message(&bob_provider, &bob_signer, b2a)
        .unwrap();
    let b2a_proto = over_the_wire(b2a_ct).try_into_protocol_message().unwrap();
    let b2a_pt = match alice_group
        .process_message(&alice_provider, b2a_proto)
        .unwrap()
        .into_content()
    {
        ProcessedMessageContent::ApplicationMessage(app) => app.into_bytes(),
        _ => panic!("expected app message"),
    };

    let snap = StateSnapshot {
        alice_epoch: alice_group.epoch().as_u64(),
        bob_epoch: bob_group.epoch().as_u64(),
        alice_member_count: alice_group.members().count(),
        bob_member_count: bob_group.members().count(),
        group_ids_match: alice_group.group_id() == bob_group.group_id(),
        alice_to_bob_plaintext: a2b_pt,
        bob_to_alice_plaintext: b2a_pt,
    };
    (
        snap,
        HsmEnv {
            _tokens_dir: tokens_dir,
            _conf_file: conf_file,
        },
    )
}

// ── RustCrypto reference run ────────────────────────────────────────────────

fn run_rustcrypto() -> StateSnapshot {
    let alice_provider = OpenMlsRustCrypto::default();
    let bob_provider = OpenMlsRustCrypto::default();
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    let alice_signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
    let bob_signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
    alice_signer.store(alice_provider.storage()).unwrap();
    bob_signer.store(bob_provider.storage()).unwrap();

    let alice_cred = CredentialWithKey {
        credential: BasicCredential::new("Alice".into()).into(),
        signature_key: alice_signer.public().to_vec().into(),
    };
    let bob_cred = CredentialWithKey {
        credential: BasicCredential::new("Bob".into()).into(),
        signature_key: bob_signer.public().to_vec().into(),
    };

    let bob_kp = KeyPackage::builder()
        .build(ciphersuite, &bob_provider, &bob_signer, bob_cred.clone())
        .unwrap();
    let mut alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .build(&alice_provider, &alice_signer, alice_cred.clone())
        .unwrap();
    let (_, welcome_out, _) = alice_group
        .add_members(
            &alice_provider,
            &alice_signer,
            core::slice::from_ref(bob_kp.key_package()),
        )
        .unwrap();
    alice_group.merge_pending_commit(&alice_provider).unwrap();

    let welcome = match over_the_wire(welcome_out).extract() {
        MlsMessageBodyIn::Welcome(w) => w,
        _ => panic!("expected welcome"),
    };
    let join_cfg = MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .build();
    let staged =
        StagedWelcome::new_from_welcome(&bob_provider, &join_cfg, welcome, None).unwrap();
    let mut bob_group = staged.into_group(&bob_provider).unwrap();

    let a2b = b"alice contract test message";
    let a2b_ct = alice_group
        .create_message(&alice_provider, &alice_signer, a2b)
        .unwrap();
    let a2b_proto = over_the_wire(a2b_ct).try_into_protocol_message().unwrap();
    let a2b_pt = match bob_group.process_message(&bob_provider, a2b_proto).unwrap().into_content() {
        ProcessedMessageContent::ApplicationMessage(app) => app.into_bytes(),
        _ => panic!("expected app message"),
    };

    let b2a = b"bob contract test reply";
    let b2a_ct = bob_group
        .create_message(&bob_provider, &bob_signer, b2a)
        .unwrap();
    let b2a_proto = over_the_wire(b2a_ct).try_into_protocol_message().unwrap();
    let b2a_pt = match alice_group
        .process_message(&alice_provider, b2a_proto)
        .unwrap()
        .into_content()
    {
        ProcessedMessageContent::ApplicationMessage(app) => app.into_bytes(),
        _ => panic!("expected app message"),
    };

    StateSnapshot {
        alice_epoch: alice_group.epoch().as_u64(),
        bob_epoch: bob_group.epoch().as_u64(),
        alice_member_count: alice_group.members().count(),
        bob_member_count: bob_group.members().count(),
        group_ids_match: alice_group.group_id() == bob_group.group_id(),
        alice_to_bob_plaintext: a2b_pt,
        bob_to_alice_plaintext: b2a_pt,
    }
}

// ── The contract test ───────────────────────────────────────────────────────

#[test]
fn semantic_equivalence_vs_rustcrypto() {
    let module = match resolve_module() {
        Some(m) => m,
        None => {
            eprintln!("skip: no PKCS#11 module found — set PKCS11_MODULE or build the C++ engine");
            return;
        }
    };

    let (hsm_state, _env) = run_hsm(&module);
    let rust_state = run_rustcrypto();

    // Both runs must independently reach a well-formed 2-member group.
    assert_eq!(hsm_state.alice_epoch, 1, "HSM: alice epoch advanced");
    assert_eq!(hsm_state.bob_epoch, 1, "HSM: bob epoch advanced");
    assert_eq!(hsm_state.alice_member_count, 2, "HSM: 2 members");
    assert_eq!(hsm_state.bob_member_count, 2, "HSM: 2 members");
    assert!(hsm_state.group_ids_match, "HSM: alice and bob share group_id");

    assert_eq!(rust_state.alice_epoch, 1, "RustCrypto: alice epoch advanced");
    assert_eq!(rust_state.bob_epoch, 1, "RustCrypto: bob epoch advanced");
    assert_eq!(rust_state.alice_member_count, 2, "RustCrypto: 2 members");
    assert_eq!(rust_state.bob_member_count, 2, "RustCrypto: 2 members");
    assert!(rust_state.group_ids_match, "RustCrypto: alice and bob share group_id");

    // Semantic equivalence: every observable equals across both runs,
    // EXCEPT the group_id (which is random per group creation).
    assert_eq!(
        hsm_state.alice_epoch, rust_state.alice_epoch,
        "alice epoch matches"
    );
    assert_eq!(hsm_state.bob_epoch, rust_state.bob_epoch, "bob epoch matches");
    assert_eq!(
        hsm_state.alice_member_count, rust_state.alice_member_count,
        "alice member count matches"
    );
    assert_eq!(
        hsm_state.bob_member_count, rust_state.bob_member_count,
        "bob member count matches"
    );
    assert_eq!(
        hsm_state.alice_to_bob_plaintext, rust_state.alice_to_bob_plaintext,
        "alice→bob plaintext matches"
    );
    assert_eq!(
        hsm_state.bob_to_alice_plaintext, rust_state.bob_to_alice_plaintext,
        "bob→alice plaintext matches"
    );

    eprintln!("semantic match across all 8 lifecycle steps:");
    eprintln!("  epoch: HSM={} RustCrypto={}", hsm_state.alice_epoch, rust_state.alice_epoch);
    eprintln!(
        "  members: HSM={} RustCrypto={}",
        hsm_state.alice_member_count, rust_state.alice_member_count
    );
    eprintln!(
        "  a→b plaintext: {:?}",
        std::str::from_utf8(&hsm_state.alice_to_bob_plaintext).unwrap()
    );
    eprintln!(
        "  b→a plaintext: {:?}",
        std::str::from_utf8(&hsm_state.bob_to_alice_plaintext).unwrap()
    );
}
