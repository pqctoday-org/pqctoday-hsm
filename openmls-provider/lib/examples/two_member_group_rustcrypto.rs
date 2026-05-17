//! Reference run of the same two-member MLS scenario as
//! `two_member_group`, but with the **upstream `OpenMlsRustCrypto`**
//! provider and software `SignatureKeyPair` credentials.
//!
//! This is the apples-to-apples baseline the cross-validation test in
//! `tests/openmls_contract.rs` compares our HSM-backed run against. When
//! both runs reach `epoch == 1`, agree on member count + group_id, and
//! successfully exchange application messages, our provider has
//! demonstrated semantic equivalence with the canonical software stack.
//!
//! Run: `cargo run --release --example two_member_group_rustcrypto`

use openmls::prelude::{tls_codec::*, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::types::SignatureScheme;

fn over_the_wire(out: MlsMessageOut) -> MlsMessageIn {
    let bytes = out.tls_serialize_detached().expect("serialise");
    MlsMessageIn::tls_deserialize_exact(&bytes).expect("deserialise")
}

fn generate_credential(
    identity: &str,
    scheme: SignatureScheme,
) -> (CredentialWithKey, SignatureKeyPair) {
    let keys = SignatureKeyPair::new(scheme).expect("signature keypair");
    let credential = CredentialWithKey {
        credential: BasicCredential::new(identity.into()).into(),
        signature_key: keys.public().to_vec().into(),
    };
    (credential, keys)
}

fn main() {
    let alice_provider = OpenMlsRustCrypto::default();
    let bob_provider = OpenMlsRustCrypto::default();
    println!("[1/8] two OpenMlsRustCrypto providers up (software, in-process)");

    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    let (alice_credential, alice_signer) = generate_credential("Alice", SignatureScheme::ED25519);
    let (bob_credential, bob_signer) = generate_credential("Bob", SignatureScheme::ED25519);
    println!(
        "[2/8] Ed25519 signature keypairs (software, {} B pubkey)",
        alice_signer.public().len()
    );

    let bob_kp_bundle = KeyPackage::builder()
        .build(
            ciphersuite,
            &bob_provider,
            &bob_signer,
            bob_credential.clone(),
        )
        .expect("bob KeyPackage");
    println!("[3/8] Bob's KeyPackage built");

    let mut alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .build(&alice_provider, &alice_signer, alice_credential.clone())
        .expect("alice MlsGroup");
    println!(
        "[4/8] Alice's group created at epoch {}",
        alice_group.epoch().as_u64()
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
        "[5/8] Alice committed Add(Bob) → {} members, epoch {}",
        alice_group.members().count(),
        alice_group.epoch().as_u64()
    );

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
    println!("[6/8] Bob joined → epoch {}", bob_group.epoch().as_u64());

    let a2b = b"Hello from Alice (software)";
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
            assert_eq!(app.into_bytes(), a2b);
            println!("[7/8] Alice → Bob plaintext recovered");
        }
        _ => panic!("expected ApplicationMessage"),
    }

    let b2a = b"Reply from Bob (software)";
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
            assert_eq!(app.into_bytes(), b2a);
            println!("[8/8] Bob → Alice plaintext recovered");
        }
        _ => panic!("expected ApplicationMessage"),
    }

    assert_eq!(alice_group.epoch(), bob_group.epoch());
    assert_eq!(alice_group.members().count(), bob_group.members().count());
    assert_eq!(alice_group.group_id(), bob_group.group_id());
    println!(
        "\n==> RUSTCRYPTO REFERENCE OK — epoch {}, {} members",
        alice_group.epoch().as_u64(),
        alice_group.members().count()
    );
}
