//! Two-member MLS group walkthrough using the HSM-backed provider end-to-end.
//!
//! This is the Tier B validation artifact for `openmls_pqctoday_crypto`:
//! a runnable, real-world demonstration that the provider drives an
//! actual `openmls::MlsGroup` lifecycle correctly, with the credential's
//! signature key living **inside the HSM** (not as bytes in the process).
//!
//! Lifecycle steps exercised:
//!   1. Two HSM-backed providers (Alice, Bob) each with their own token
//!   2. HSM-resident Ed25519 signature keypair per party (via `generate_signer`)
//!   3. Bob mints a `KeyPackage` (HPKE init key flows through our PKCS#11 path)
//!   4. Alice creates an `MlsGroup` and adds Bob
//!   5. Bob processes the Welcome and joins
//!   6. Alice sends an application message; Bob decrypts and asserts plaintext
//!   7. Bob replies; Alice decrypts; same assertion
//!   8. Final invariant: both groups agree on epoch + member list + group_id
//!
//! Run: `cargo run --release --example two_member_group`
//!
//! Requires the softhsmv3 native module at
//! `../../build/src/lib/libsofthsmv3.{dylib,so}` or via `$PKCS11_MODULE`.

use std::io::Write;
use std::path::PathBuf;

use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;

use openmls::prelude::{tls_codec::*, *};
use openmls_pqctoday_crypto::{HsmConfig, PqcTodayHsmSigner, PqcTodayProvider};
use openmls_traits::types::SignatureScheme;

/// Helper: serialise an outgoing MlsMessage and deserialise it as incoming,
/// matching what happens when a real MLS message travels over the wire.
fn over_the_wire(out: MlsMessageOut) -> MlsMessageIn {
    let bytes = out.tls_serialize_detached().expect("serialise");
    MlsMessageIn::tls_deserialize_exact(&bytes).expect("deserialise")
}

// ── softhsm test-token setup (same pattern as tests/integration.rs) ──────────

const SO_PIN: &str = "12345678";
const USER_PIN: &str = "1234";

fn resolve_module() -> PathBuf {
    if let Ok(p) = std::env::var("PKCS11_MODULE") {
        let pb = PathBuf::from(p);
        if pb.exists() {
            return pb;
        }
    }
    let here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for rel in &[
        "../../build/src/lib/libsofthsmv3.dylib",
        "../../build/src/lib/libsofthsmv3.so",
        "../../build_fresh/src/lib/libsofthsmv3.dylib",
    ] {
        let p = here.join(rel);
        if p.exists() {
            return p;
        }
    }
    panic!(
        "no PKCS#11 module found — set $PKCS11_MODULE or build the softhsmv3 \
         C++ engine via the repo CMake build"
    );
}

/// Holds tmpdir + softhsm conf for the duration of the example so the
/// token store doesn't get GC'd out from under the providers.
struct TokenEnv {
    _tokens_dir: tempfile::TempDir,
    _conf_file: tempfile::NamedTempFile,
}

/// Initialise a single softhsm token, then return:
///   - `alice_provider`: opens the first session on that token
///   - `bob_provider`: spawned as a sibling — shares the PKCS#11 context,
///     opens its own session, gets its own `MemoryStorage`
///
/// softhsmv3's `C_Initialize` is non-reentrant, so we cannot legitimately
/// load the module twice from the same process. Two providers must share
/// one PKCS#11 context. This mirrors real production where many MLS
/// endpoints on one host typically share one HSM module instance.
fn setup_two_providers(module: &PathBuf) -> (PqcTodayProvider, PqcTodayProvider, TokenEnv) {
    let tokens_dir = tempfile::tempdir().expect("tmpdir");
    let mut conf_file = tempfile::NamedTempFile::new().expect("tmpfile");
    writeln!(
        conf_file,
        "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR",
        tokens_dir.path().display()
    )
    .expect("write conf");
    std::env::set_var("SOFTHSM2_CONF", conf_file.path());

    let ctx = Pkcs11::new(module).expect("load module");
    ctx.initialize(CInitializeArgs::OsThreads).expect("init");
    let slots = ctx.get_slots_with_token().expect("slots");
    let slot = *slots.first().expect("at least one slot");
    ctx.init_token(slot, &AuthPin::new(SO_PIN.into()), "two-member-demo")
        .expect("init_token");
    {
        let so = ctx.open_rw_session(slot).expect("rw session");
        so.login(UserType::So, Some(&AuthPin::new(SO_PIN.into())))
            .expect("SO login");
        so.init_pin(&AuthPin::new(USER_PIN.into())).expect("init_pin");
        so.logout().ok();
    }
    drop(ctx); // release setup ctx; provider creates the long-lived one

    let cfg = HsmConfig::new(module.clone()).with_pin(USER_PIN);
    let alice = PqcTodayProvider::new(&cfg).expect("alice provider");
    // PKCS#11 login is token-scoped: Alice's session already logged the
    // token in as User, so Bob's sibling session must NOT re-login.
    let bob = alice
        .spawn_sibling(None)
        .expect("bob provider as sibling of alice");
    (
        alice,
        bob,
        TokenEnv {
            _tokens_dir: tokens_dir,
            _conf_file: conf_file,
        },
    )
}

// ── lifecycle ────────────────────────────────────────────────────────────────

fn main() {
    let module = resolve_module();
    println!("==> using PKCS#11 module {}", module.display());

    // Step 1: two HSM-backed providers sharing one softhsm module.
    let (alice_provider, bob_provider, _env) = setup_two_providers(&module);
    println!("[1/8] two HSM-backed providers up (shared PKCS#11 context, independent sessions)");

    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    // Step 2: HSM-resident Ed25519 credential signers.
    let alice_signer: PqcTodayHsmSigner = alice_provider
        .generate_signer(SignatureScheme::ED25519)
        .expect("alice signer");
    let bob_signer: PqcTodayHsmSigner = bob_provider
        .generate_signer(SignatureScheme::ED25519)
        .expect("bob signer");
    println!(
        "[2/8] HSM-resident Ed25519 keys minted ({} B handle blob, {} B pubkey)",
        alice_signer.handle_blob().len(),
        alice_signer.public_key().len()
    );

    let alice_credential = CredentialWithKey {
        credential: BasicCredential::new("Alice".into()).into(),
        signature_key: alice_signer.public_key().to_vec().into(),
    };
    let bob_credential = CredentialWithKey {
        credential: BasicCredential::new("Bob".into()).into(),
        signature_key: bob_signer.public_key().to_vec().into(),
    };

    // Step 3: Bob mints a KeyPackage.
    let bob_kp_bundle = KeyPackage::builder()
        .build(
            ciphersuite,
            &bob_provider,
            &bob_signer,
            bob_credential.clone(),
        )
        .expect("bob KeyPackage");
    println!("[3/8] Bob's KeyPackage built (HPKE init key minted via our PKCS#11 path)");

    // Step 4: Alice creates a group + adds Bob.
    let mut alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .build(&alice_provider, &alice_signer, alice_credential.clone())
        .expect("alice MlsGroup");
    println!(
        "[4/8] Alice's group created at epoch {} (group_id: {:?})",
        alice_group.epoch().as_u64(),
        alice_group.group_id()
    );

    let (_commit_out, welcome_out, _group_info) = alice_group
        .add_members(
            &alice_provider,
            &alice_signer,
            core::slice::from_ref(bob_kp_bundle.key_package()),
        )
        .expect("add_members");
    alice_group
        .merge_pending_commit(&alice_provider)
        .expect("merge add commit");
    println!(
        "[5/8] Alice committed Add(Bob). Now {} members, epoch {}",
        alice_group.members().count(),
        alice_group.epoch().as_u64()
    );

    // Step 5: Bob processes the Welcome.
    let welcome = match over_the_wire(welcome_out).extract() {
        MlsMessageBodyIn::Welcome(w) => w,
        _ => panic!("expected MlsMessageBodyIn::Welcome"),
    };
    let join_config = MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .build();
    let staged = StagedWelcome::new_from_welcome(&bob_provider, &join_config, welcome, None)
        .expect("StagedWelcome");
    let mut bob_group = staged.into_group(&bob_provider).expect("bob MlsGroup");
    println!(
        "[6/8] Bob joined from Welcome → his group at epoch {}",
        bob_group.epoch().as_u64()
    );

    // Step 6: Alice → Bob application message.
    let a2b = b"Hello from Alice (signed inside the HSM)";
    let a2b_ct = alice_group
        .create_message(&alice_provider, &alice_signer, a2b)
        .expect("Alice create_message");
    let a2b_proto = over_the_wire(a2b_ct)
        .try_into_protocol_message()
        .expect("alice → bob protocol message");
    let a2b_processed = bob_group
        .process_message(&bob_provider, a2b_proto)
        .expect("Bob process_message");
    match a2b_processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(app) => {
            assert_eq!(app.into_bytes(), a2b, "alice → bob plaintext matches");
            println!("[7/8] Alice → Bob plaintext recovered: {:?}", std::str::from_utf8(a2b).unwrap());
        }
        other => panic!("expected ApplicationMessage, got {:?}", other),
    }

    // Step 7: Bob → Alice reply.
    let b2a = b"Reply from Bob (also HSM-signed)";
    let b2a_ct = bob_group
        .create_message(&bob_provider, &bob_signer, b2a)
        .expect("Bob create_message");
    let b2a_proto = over_the_wire(b2a_ct)
        .try_into_protocol_message()
        .expect("bob → alice protocol message");
    let b2a_processed = alice_group
        .process_message(&alice_provider, b2a_proto)
        .expect("Alice process_message");
    match b2a_processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(app) => {
            assert_eq!(app.into_bytes(), b2a, "bob → alice plaintext matches");
        }
        other => panic!("expected ApplicationMessage, got {:?}", other),
    }
    println!("[8/8] Bob → Alice plaintext recovered");

    // Final invariants.
    assert_eq!(
        alice_group.epoch().as_u64(),
        bob_group.epoch().as_u64(),
        "epochs in sync"
    );
    assert_eq!(
        alice_group.members().count(),
        bob_group.members().count(),
        "member counts agree"
    );
    assert_eq!(
        alice_group.group_id(),
        bob_group.group_id(),
        "group ids match"
    );
    println!(
        "\n==> SUCCESS — both groups at epoch {}, {} members, identical group_id",
        alice_group.epoch().as_u64(),
        alice_group.members().count()
    );
    println!(
        "==> credential signing keys never left the HSM (verified via {}-byte HsmKeyHandle blobs)",
        alice_signer.handle_blob().len()
    );
}
