//! End-to-end smoke test: spin up the gRPC server on a free port, run a
//! generated tonic client against it, verify:
//!
//!   1. `Name` returns the documented identifier
//!   2. `SupportedCiphersuites` returns the documented list
//!   3. `CreateKeyPackage` returns a serialisable KeyPackage with our
//!      HSM-handle (`PQTH` magic) in `signature_priv` — proves the
//!      handler runs through `PqcTodayProvider::generate_signer`
//!   4. `CreateGroup` returns a fresh `state_id`, and a second call
//!      returns a different `state_id` — proves state mgmt works
//!   5. A stubbed RPC (`Commit`) still returns `Code::Unimplemented`
//!   6. `Free` succeeds

use std::net::SocketAddr;
use std::time::Duration;

use pqctoday_mls_interop::mls_client::mls_client_client::MlsClientClient;
use pqctoday_mls_interop::mls_client::mls_client_server::MlsClientServer;
use pqctoday_mls_interop::mls_client::{
    CommitRequest, CreateBranchRequest, CreateGroupRequest, CreateKeyPackageRequest, FreeRequest,
    NameRequest, SupportedCiphersuitesRequest,
};
use pqctoday_mls_interop::{PqcTodayInteropClient, IMPLEMENTATION_NAME, SUPPORTED_CIPHERSUITES};

#[tokio::test]
async fn ietf_grpc_contract_smoke() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    drop(listener);

    let server_addr = addr;
    tokio::spawn(async move {
        let service =
            PqcTodayInteropClient::new().expect("server must initialise (softhsm available?)");
        tonic::transport::Server::builder()
            .add_service(MlsClientServer::new(service))
            .serve(server_addr)
            .await
            .expect("server");
    });

    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut client = MlsClientClient::connect(format!("http://{}", server_addr))
        .await
        .expect("connect");

    // ── 1. Name ────────────────────────────────────────────────────────────
    let resp = client
        .name(NameRequest {})
        .await
        .expect("Name RPC")
        .into_inner();
    assert_eq!(resp.name, IMPLEMENTATION_NAME);

    // ── 2. SupportedCiphersuites ───────────────────────────────────────────
    let resp = client
        .supported_ciphersuites(SupportedCiphersuitesRequest {})
        .await
        .expect("SupportedCiphersuites RPC")
        .into_inner();
    assert_eq!(resp.ciphersuites, SUPPORTED_CIPHERSUITES.to_vec());

    // ── 3. CreateKeyPackage ────────────────────────────────────────────────
    let kp = client
        .create_key_package(CreateKeyPackageRequest {
            cipher_suite: 1, // MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            identity: b"alice".to_vec(),
        })
        .await
        .expect("CreateKeyPackage RPC")
        .into_inner();
    assert!(!kp.key_package.is_empty(), "key_package bytes returned");
    assert_ne!(kp.transaction_id, 0, "transaction_id minted");
    assert!(
        kp.signature_priv.starts_with(b"PQTH"),
        "signature_priv is an opaque HsmKeyHandle blob, not raw key material"
    );

    // ── 4. CreateGroup × 2: state_ids must differ ──────────────────────────
    let g1 = client
        .create_group(CreateGroupRequest {
            cipher_suite: 1,
            group_id: vec![0xaa; 16],
            identity: b"alice-group1".to_vec(),
            ..Default::default()
        })
        .await
        .expect("CreateGroup #1")
        .into_inner();
    let g2 = client
        .create_group(CreateGroupRequest {
            cipher_suite: 1,
            group_id: vec![0xbb; 16],
            identity: b"alice-group2".to_vec(),
            ..Default::default()
        })
        .await
        .expect("CreateGroup #2")
        .into_inner();
    assert_eq!(g1.state_id, 0);
    assert_eq!(g2.state_id, 1, "second group gets distinct state_id");

    // ── 5. A still-stubbed RPC returns UNIMPLEMENTED cleanly ───────────────
    let err = client
        .create_branch(CreateBranchRequest {
            state_id: g1.state_id,
            ..Default::default()
        })
        .await
        .expect_err("CreateBranch should still be stubbed");
    assert_eq!(err.code(), tonic::Code::Unimplemented);
    assert!(err.message().contains("CreateBranch"));

    // ── 6. Free ────────────────────────────────────────────────────────────
    client
        .free(FreeRequest {
            state_id: g1.state_id,
            ..Default::default()
        })
        .await
        .expect("Free RPC");
}

// ── Real welcome_join scenario over gRPC ────────────────────────────────────
//
// Alice and Bob are both served by the same `pqctoday-mls-grpc` server.
// We use the gRPC contract to drive a full Add-via-Welcome flow:
//
//   1. Bob: CreateKeyPackage
//   2. Alice: CreateGroup
//   3. Alice: AddProposal (Bob's KeyPackage)
//   4. Alice: Commit → produces commit + welcome
//   5. Alice: HandlePendingCommit → merges, returns epoch_authenticator
//   6. Bob:   JoinGroup with Alice's welcome → returns epoch_authenticator
//   7. Assert both epoch_authenticators match → identical group state
//
// This is the canonical IETF `welcome_join.json` scenario run end-to-end
// over the gRPC wire against our HSM-backed provider.

use pqctoday_mls_interop::mls_client::{
    AddProposalRequest, ExportRequest as ExportReq, ExternalJoinRequest, ExternalPskProposalRequest,
    GroupInfoRequest, HandleCommitRequest, HandlePendingCommitRequest, JoinGroupRequest,
    ProposalDescription, ProtectRequest, StateAuthRequest, StorePskRequest, UnprotectRequest,
};

#[tokio::test]
async fn welcome_join_e2e_over_grpc() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    drop(listener);

    tokio::spawn(async move {
        let service = PqcTodayInteropClient::new().expect("server initialise");
        tonic::transport::Server::builder()
            .add_service(MlsClientServer::new(service))
            .serve(addr)
            .await
            .expect("server");
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut client = MlsClientClient::connect(format!("http://{}", addr))
        .await
        .expect("connect");

    let cs: u32 = 1; // MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519

    // Step 1: Bob mints a KeyPackage.
    let bob_kp = client
        .create_key_package(CreateKeyPackageRequest {
            cipher_suite: cs,
            identity: b"bob".to_vec(),
        })
        .await
        .expect("Bob CreateKeyPackage")
        .into_inner();

    // Step 2: Alice creates a group.
    let alice = client
        .create_group(CreateGroupRequest {
            cipher_suite: cs,
            group_id: vec![0xa1; 16],
            identity: b"alice".to_vec(),
            encrypt_handshake: false,
        })
        .await
        .expect("Alice CreateGroup")
        .into_inner();

    // Step 3: Alice issues an Add proposal for Bob.
    let add_resp = client
        .add_proposal(AddProposalRequest {
            state_id: alice.state_id,
            key_package: bob_kp.key_package.clone(),
        })
        .await
        .expect("Alice AddProposal")
        .into_inner();
    assert!(!add_resp.proposal.is_empty(), "proposal bytes returned");

    // Step 4: Alice commits her pending proposals.
    let commit_resp = client
        .commit(CommitRequest {
            state_id: alice.state_id,
            by_reference: vec![add_resp.proposal.clone()],
            by_value: vec![],
            external_tree: false,
            force_path: false,
        })
        .await
        .expect("Alice Commit")
        .into_inner();
    assert!(!commit_resp.commit.is_empty(), "commit bytes returned");
    assert!(
        !commit_resp.welcome.is_empty(),
        "Welcome message produced for Bob"
    );

    // Step 5: Alice merges her own pending commit → her group at epoch 1.
    let alice_after = client
        .handle_pending_commit(HandlePendingCommitRequest {
            state_id: alice.state_id,
        })
        .await
        .expect("Alice HandlePendingCommit")
        .into_inner();

    // Step 6: Bob joins from Alice's Welcome.
    let bob_state = client
        .join_group(JoinGroupRequest {
            transaction_id: bob_kp.transaction_id,
            welcome: commit_resp.welcome.clone(),
            ratchet_tree: commit_resp.ratchet_tree.clone(),
            encrypt_handshake: false,
            identity: b"bob".to_vec(),
        })
        .await
        .expect("Bob JoinGroup")
        .into_inner();

    // Step 7: Both must report the same epoch_authenticator → identical
    // group state.
    assert!(
        !alice_after.epoch_authenticator.is_empty(),
        "Alice has an epoch_authenticator"
    );
    assert_eq!(
        alice_after.epoch_authenticator, bob_state.epoch_authenticator,
        "alice and bob agree on group state after Welcome+Commit round-trip"
    );
    assert_ne!(
        alice.state_id, bob_state.state_id,
        "Alice and Bob have distinct group handles"
    );
}

// ── Application message exchange over gRPC ──────────────────────────────────
//
// Picks up after the welcome_join flow finishes (Alice + Bob in a 2-member
// group at epoch 1). Verifies:
//   • Alice: Protect("hello bob") → ciphertext
//   • Bob:   Unprotect(ciphertext) → plaintext == "hello bob"
//   • Bob:   Protect("hi alice") with AAD
//   • Alice: Unprotect → plaintext + same AAD
//   • Both:  StateAuth → same secret as the welcome_join's epoch_authenticator
//
// All under one gRPC server. Exercises every MLS application-message
// codepath through our HSM-backed provider.

#[tokio::test]
async fn protect_unprotect_roundtrip_over_grpc() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    drop(listener);

    tokio::spawn(async move {
        let service = PqcTodayInteropClient::new().expect("server initialise");
        tonic::transport::Server::builder()
            .add_service(MlsClientServer::new(service))
            .serve(addr)
            .await
            .expect("server");
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut client = MlsClientClient::connect(format!("http://{}", addr))
        .await
        .expect("connect");

    let cs: u32 = 1;

    // ── Bring up alice + bob (same flow as welcome_join_e2e_over_grpc) ─────
    let bob_kp = client
        .create_key_package(CreateKeyPackageRequest {
            cipher_suite: cs,
            identity: b"bob".to_vec(),
        })
        .await
        .unwrap()
        .into_inner();
    let alice = client
        .create_group(CreateGroupRequest {
            cipher_suite: cs,
            group_id: vec![0xa2; 16],
            identity: b"alice".to_vec(),
            encrypt_handshake: true,
        })
        .await
        .unwrap()
        .into_inner();
    let add = client
        .add_proposal(AddProposalRequest {
            state_id: alice.state_id,
            key_package: bob_kp.key_package.clone(),
        })
        .await
        .unwrap()
        .into_inner();
    let commit = client
        .commit(CommitRequest {
            state_id: alice.state_id,
            by_reference: vec![add.proposal.clone()],
            by_value: vec![],
            external_tree: false,
            force_path: false,
        })
        .await
        .unwrap()
        .into_inner();
    let alice_after = client
        .handle_pending_commit(HandlePendingCommitRequest {
            state_id: alice.state_id,
        })
        .await
        .unwrap()
        .into_inner();
    let bob = client
        .join_group(JoinGroupRequest {
            transaction_id: bob_kp.transaction_id,
            welcome: commit.welcome.clone(),
            ratchet_tree: commit.ratchet_tree.clone(),
            encrypt_handshake: true,
            identity: b"bob".to_vec(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(alice_after.epoch_authenticator, bob.epoch_authenticator);

    // ── Alice → Bob application message ────────────────────────────────────
    let a2b_pt = b"hello bob, signed inside the HSM";
    let a2b_aad = b"alice-to-bob aad";
    let a2b_ct = client
        .protect(ProtectRequest {
            state_id: alice.state_id,
            authenticated_data: a2b_aad.to_vec(),
            plaintext: a2b_pt.to_vec(),
        })
        .await
        .expect("Alice Protect")
        .into_inner();
    assert!(!a2b_ct.ciphertext.is_empty());

    let a2b_decoded = client
        .unprotect(UnprotectRequest {
            state_id: bob.state_id,
            ciphertext: a2b_ct.ciphertext.clone(),
        })
        .await
        .expect("Bob Unprotect")
        .into_inner();
    assert_eq!(a2b_decoded.plaintext, a2b_pt);
    assert_eq!(a2b_decoded.authenticated_data, a2b_aad);

    // ── Bob → Alice reply ──────────────────────────────────────────────────
    let b2a_pt = b"hi alice, also HSM-signed";
    let b2a_ct = client
        .protect(ProtectRequest {
            state_id: bob.state_id,
            authenticated_data: vec![],
            plaintext: b2a_pt.to_vec(),
        })
        .await
        .expect("Bob Protect")
        .into_inner();
    let b2a_decoded = client
        .unprotect(UnprotectRequest {
            state_id: alice.state_id,
            ciphertext: b2a_ct.ciphertext.clone(),
        })
        .await
        .expect("Alice Unprotect")
        .into_inner();
    assert_eq!(b2a_decoded.plaintext, b2a_pt);

    // ── StateAuth: both sides report the same epoch authenticator ──────────
    let alice_sa = client
        .state_auth(StateAuthRequest {
            state_id: alice.state_id,
        })
        .await
        .unwrap()
        .into_inner();
    let bob_sa = client
        .state_auth(StateAuthRequest {
            state_id: bob.state_id,
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(alice_sa.state_auth_secret, bob_sa.state_auth_secret);
    // And it equals the post-welcome epoch_authenticator from earlier.
    assert_eq!(alice_sa.state_auth_secret, alice_after.epoch_authenticator);
}

// ── ExternalJoin scenario over gRPC ─────────────────────────────────────────
//
// Builds a 2-member group (Alice + Bob) via the welcome_join flow, then
// has Charlie join via ExternalJoin against Alice's exported GroupInfo —
// no Welcome involved on Charlie's side. After Alice processes Charlie's
// external commit, all three converge to the same epoch_authenticator
// and Export with a shared label produces identical secrets.

#[tokio::test]
async fn external_join_e2e_over_grpc() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    drop(listener);

    tokio::spawn(async move {
        let service = PqcTodayInteropClient::new().expect("server initialise");
        tonic::transport::Server::builder()
            .add_service(MlsClientServer::new(service))
            .serve(addr)
            .await
            .expect("server");
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut client = MlsClientClient::connect(format!("http://{}", addr))
        .await
        .expect("connect");

    let cs: u32 = 1;

    // ── Bring up alice + bob ──────────────────────────────────────────────
    let bob_kp = client
        .create_key_package(CreateKeyPackageRequest {
            cipher_suite: cs,
            identity: b"bob".to_vec(),
        })
        .await
        .unwrap()
        .into_inner();
    let alice = client
        .create_group(CreateGroupRequest {
            cipher_suite: cs,
            group_id: vec![0xa3; 16],
            identity: b"alice".to_vec(),
            encrypt_handshake: false,
        })
        .await
        .unwrap()
        .into_inner();
    let add_bob = client
        .add_proposal(AddProposalRequest {
            state_id: alice.state_id,
            key_package: bob_kp.key_package.clone(),
        })
        .await
        .unwrap()
        .into_inner();
    let commit_bob = client
        .commit(CommitRequest {
            state_id: alice.state_id,
            by_reference: vec![add_bob.proposal.clone()],
            by_value: vec![],
            external_tree: false,
            force_path: false,
        })
        .await
        .unwrap()
        .into_inner();
    client
        .handle_pending_commit(HandlePendingCommitRequest {
            state_id: alice.state_id,
        })
        .await
        .unwrap();
    let bob = client
        .join_group(JoinGroupRequest {
            transaction_id: bob_kp.transaction_id,
            welcome: commit_bob.welcome.clone(),
            ratchet_tree: commit_bob.ratchet_tree.clone(),
            encrypt_handshake: false,
            identity: b"bob".to_vec(),
        })
        .await
        .unwrap()
        .into_inner();
    // Sanity: alice + bob are aligned at epoch 1.
    let alice_after_bob = client
        .state_auth(StateAuthRequest {
            state_id: alice.state_id,
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(alice_after_bob.state_auth_secret, bob.epoch_authenticator);

    // ── Alice publishes GroupInfo for Charlie to join externally ──────────
    let gi = client
        .group_info(GroupInfoRequest {
            state_id: alice.state_id,
            external_tree: true, // include ratchet tree for Charlie
        })
        .await
        .expect("Alice GroupInfo")
        .into_inner();
    assert!(!gi.group_info.is_empty());
    assert!(
        !gi.ratchet_tree.is_empty(),
        "external_tree=true returns serialised tree"
    );

    // ── Charlie joins via ExternalJoin ────────────────────────────────────
    let charlie = client
        .external_join(ExternalJoinRequest {
            group_info: gi.group_info.clone(),
            ratchet_tree: gi.ratchet_tree.clone(),
            encrypt_handshake: false,
            identity: b"charlie".to_vec(),
            ..Default::default()
        })
        .await
        .expect("Charlie ExternalJoin")
        .into_inner();
    assert!(!charlie.commit.is_empty(), "external commit returned");
    assert!(!charlie.epoch_authenticator.is_empty());

    // ── Alice processes Charlie's external commit ─────────────────────────
    let alice_after_charlie = client
        .handle_commit(HandleCommitRequest {
            state_id: alice.state_id,
            proposal: vec![],
            commit: charlie.commit.clone(),
        })
        .await
        .expect("Alice HandleCommit on Charlie's external join")
        .into_inner();
    // Bob processes too, so the whole group converges.
    let bob_after_charlie = client
        .handle_commit(HandleCommitRequest {
            state_id: bob.state_id,
            proposal: vec![],
            commit: charlie.commit.clone(),
        })
        .await
        .expect("Bob HandleCommit on Charlie's external join")
        .into_inner();

    // ── All three must agree on the new epoch_authenticator ───────────────
    assert_eq!(
        alice_after_charlie.epoch_authenticator,
        charlie.epoch_authenticator,
        "Alice and Charlie agree on epoch_authenticator"
    );
    assert_eq!(
        alice_after_charlie.epoch_authenticator, bob_after_charlie.epoch_authenticator,
        "Alice and Bob agree on epoch_authenticator after Charlie's external join"
    );

    // ── Bonus: Export with a shared label gives the same secret across all ─
    let label = "interop-test";
    let context: &[u8] = b"external-join-scenario";
    let key_length: u32 = 32;
    let alice_exp = client
        .export(ExportReq {
            state_id: alice.state_id,
            label: label.to_string(),
            context: context.to_vec(),
            key_length,
        })
        .await
        .expect("Alice Export")
        .into_inner();
    let bob_exp = client
        .export(ExportReq {
            state_id: bob.state_id,
            label: label.to_string(),
            context: context.to_vec(),
            key_length,
        })
        .await
        .expect("Bob Export")
        .into_inner();
    let charlie_exp = client
        .export(ExportReq {
            state_id: charlie.state_id,
            label: label.to_string(),
            context: context.to_vec(),
            key_length,
        })
        .await
        .expect("Charlie Export")
        .into_inner();
    assert_eq!(alice_exp.exported_secret.len(), 32);
    assert_eq!(alice_exp.exported_secret, bob_exp.exported_secret);
    assert_eq!(alice_exp.exported_secret, charlie_exp.exported_secret);
}

// ── External-PSK scenario over gRPC ─────────────────────────────────────────
//
// Two-member group (Alice + Bob via welcome_join), then both StorePSK with
// the same psk_id + secret, then Alice ExternalPSKProposal + Commit, then
// Bob HandleCommit. Both must reach the same new epoch_authenticator —
// proving the PSK ratchet (RFC 9420 §8.2) folds the shared secret in
// identically through our HSM-routed key schedule.

#[tokio::test]
async fn external_psk_e2e_over_grpc() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    drop(listener);

    tokio::spawn(async move {
        let service = PqcTodayInteropClient::new().expect("server initialise");
        tonic::transport::Server::builder()
            .add_service(MlsClientServer::new(service))
            .serve(addr)
            .await
            .expect("server");
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut client = MlsClientClient::connect(format!("http://{}", addr))
        .await
        .expect("connect");

    let cs: u32 = 1;

    // ── 2-member group (alice + bob) via welcome_join ─────────────────────
    let bob_kp = client
        .create_key_package(CreateKeyPackageRequest {
            cipher_suite: cs,
            identity: b"bob".to_vec(),
        })
        .await
        .unwrap()
        .into_inner();
    let alice = client
        .create_group(CreateGroupRequest {
            cipher_suite: cs,
            group_id: vec![0xa4; 16],
            identity: b"alice".to_vec(),
            encrypt_handshake: false,
        })
        .await
        .unwrap()
        .into_inner();
    let add_bob = client
        .add_proposal(AddProposalRequest {
            state_id: alice.state_id,
            key_package: bob_kp.key_package.clone(),
        })
        .await
        .unwrap()
        .into_inner();
    let commit_bob = client
        .commit(CommitRequest {
            state_id: alice.state_id,
            by_reference: vec![add_bob.proposal.clone()],
            by_value: vec![],
            external_tree: false,
            force_path: false,
        })
        .await
        .unwrap()
        .into_inner();
    client
        .handle_pending_commit(HandlePendingCommitRequest {
            state_id: alice.state_id,
        })
        .await
        .unwrap();
    let bob = client
        .join_group(JoinGroupRequest {
            transaction_id: bob_kp.transaction_id,
            welcome: commit_bob.welcome.clone(),
            ratchet_tree: commit_bob.ratchet_tree.clone(),
            encrypt_handshake: false,
            identity: b"bob".to_vec(),
        })
        .await
        .unwrap()
        .into_inner();
    let alice_post_welcome = client
        .state_auth(StateAuthRequest {
            state_id: alice.state_id,
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(alice_post_welcome.state_auth_secret, bob.epoch_authenticator);
    let epoch_after_bob = alice_post_welcome.state_auth_secret;

    // ── Both sides StorePSK with the same secret ──────────────────────────
    let psk_id = b"interop-test-psk".to_vec();
    let psk_secret = b"32-byte-pre-shared-key-material!".to_vec();
    assert_eq!(psk_secret.len(), 32);
    client
        .store_psk(StorePskRequest {
            state_or_transaction_id: alice.state_id,
            psk_id: psk_id.clone(),
            psk_secret: psk_secret.clone(),
        })
        .await
        .expect("Alice StorePSK");
    client
        .store_psk(StorePskRequest {
            state_or_transaction_id: bob.state_id,
            psk_id: psk_id.clone(),
            psk_secret: psk_secret.clone(),
        })
        .await
        .expect("Bob StorePSK");

    // ── Alice issues an ExternalPSKProposal + Commit ──────────────────────
    let psk_proposal = client
        .external_psk_proposal(ExternalPskProposalRequest {
            state_id: alice.state_id,
            psk_id: psk_id.clone(),
        })
        .await
        .expect("Alice ExternalPSKProposal")
        .into_inner();
    assert!(!psk_proposal.proposal.is_empty());

    let psk_commit = client
        .commit(CommitRequest {
            state_id: alice.state_id,
            by_reference: vec![psk_proposal.proposal.clone()],
            by_value: vec![],
            external_tree: false,
            force_path: false,
        })
        .await
        .expect("Alice Commit psk")
        .into_inner();
    let alice_post_psk = client
        .handle_pending_commit(HandlePendingCommitRequest {
            state_id: alice.state_id,
        })
        .await
        .expect("Alice HandlePendingCommit psk")
        .into_inner();
    assert_ne!(
        alice_post_psk.epoch_authenticator, epoch_after_bob,
        "Alice's epoch advanced after PSK commit"
    );

    // ── Bob processes Alice's PSK commit (with the proposal by reference) ─
    let bob_post_psk = client
        .handle_commit(HandleCommitRequest {
            state_id: bob.state_id,
            proposal: vec![psk_proposal.proposal.clone()],
            commit: psk_commit.commit.clone(),
        })
        .await
        .expect("Bob HandleCommit psk")
        .into_inner();

    // ── Both must agree on the new epoch ──────────────────────────────────
    assert_eq!(
        alice_post_psk.epoch_authenticator, bob_post_psk.epoch_authenticator,
        "alice and bob agree on epoch_authenticator after external-PSK ratchet"
    );
}

// ── Commit.by_value inline Add scenario over gRPC ───────────────────────────
//
// Same outcome as welcome_join_e2e_over_grpc (Bob ends up in Alice's group)
// but the Add proposal is **inline in the Commit** via `by_value` rather
// than a separate `AddProposal` RPC. Verifies the by_value dispatch path.

#[tokio::test]
async fn commit_by_value_add_e2e_over_grpc() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    drop(listener);

    tokio::spawn(async move {
        let service = PqcTodayInteropClient::new().expect("server initialise");
        tonic::transport::Server::builder()
            .add_service(MlsClientServer::new(service))
            .serve(addr)
            .await
            .expect("server");
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut client = MlsClientClient::connect(format!("http://{}", addr))
        .await
        .expect("connect");

    let cs: u32 = 1;

    let bob_kp = client
        .create_key_package(CreateKeyPackageRequest {
            cipher_suite: cs,
            identity: b"bob".to_vec(),
        })
        .await
        .unwrap()
        .into_inner();
    let alice = client
        .create_group(CreateGroupRequest {
            cipher_suite: cs,
            group_id: vec![0xa5; 16],
            identity: b"alice".to_vec(),
            encrypt_handshake: false,
        })
        .await
        .unwrap()
        .into_inner();

    // No separate AddProposal — the Add proposal is inline in by_value.
    let commit_resp = client
        .commit(CommitRequest {
            state_id: alice.state_id,
            by_reference: vec![],
            by_value: vec![ProposalDescription {
                proposal_type: b"add".to_vec(),
                key_package: bob_kp.key_package.clone(),
                ..Default::default()
            }],
            external_tree: false,
            force_path: false,
        })
        .await
        .expect("Alice Commit with inline Add(Bob)")
        .into_inner();
    assert!(!commit_resp.welcome.is_empty(), "Welcome produced");

    let alice_after = client
        .handle_pending_commit(HandlePendingCommitRequest {
            state_id: alice.state_id,
        })
        .await
        .unwrap()
        .into_inner();
    let bob = client
        .join_group(JoinGroupRequest {
            transaction_id: bob_kp.transaction_id,
            welcome: commit_resp.welcome.clone(),
            ratchet_tree: commit_resp.ratchet_tree.clone(),
            encrypt_handshake: false,
            identity: b"bob".to_vec(),
        })
        .await
        .expect("Bob JoinGroup")
        .into_inner();

    assert_eq!(
        alice_after.epoch_authenticator, bob.epoch_authenticator,
        "alice and bob agree on epoch after inline-Add Commit"
    );
}

