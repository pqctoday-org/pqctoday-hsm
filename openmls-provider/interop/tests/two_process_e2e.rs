//! Cross-process interop: spawn two real `pqctoday-mls-grpc` binaries
//! on different `localhost` ports, then drive an MLS welcome_join
//! scenario between them via the gRPC wire.
//!
//! Each child process opens its OWN softhsm token (per-process tmpdir +
//! `SOFTHSM2_CONF`) and serves its own `MlsGroup` state. The test acts
//! as the "message bus" — it pulls Alice's commit/welcome bytes out of
//! server A and feeds them into server B's JoinGroup, the same role
//! the IETF test-runner plays in multi-vendor interop.
//!
//! No Docker. Two native binaries + one test process orchestrating
//! over loopback gRPC.

use std::net::TcpListener;
use std::process::Stdio;
use std::time::Duration;

use pqctoday_mls_interop::mls_client::mls_client_client::MlsClientClient;
use pqctoday_mls_interop::mls_client::{
    AddProposalRequest, CommitRequest, CreateGroupRequest, CreateKeyPackageRequest,
    HandlePendingCommitRequest, JoinGroupRequest, NameRequest, StateAuthRequest,
};
use tokio::process::{Child, Command};

/// Bind a TCP port on `127.0.0.1`, immediately release it, and return
/// the port number. There's an inherent race here (another process could
/// grab the port between us closing it and the child opening it) but
/// for local-only smoke tests the window is negligible.
fn pick_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

fn binary_path() -> &'static str {
    // Cargo sets this for every binary defined in the same crate as the
    // integration test, regardless of profile.
    env!("CARGO_BIN_EXE_pqctoday-mls-grpc")
}

/// Spawn the `pqctoday-mls-grpc` binary as a child, pinned to `port`.
/// Returns the live `Child` handle so the caller can kill it when the
/// test ends.
async fn spawn_server(port: u16) -> Child {
    Command::new(binary_path())
        .arg("--port")
        .arg(port.to_string())
        // Each child sets its own SOFTHSM2_CONF inside `setup_softhsm`,
        // so children don't share token state. Inherit stdio for log
        // visibility when running with `--nocapture`.
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn pqctoday-mls-grpc")
}

/// Poll `Name` until the server is responsive or we time out.
async fn wait_for_server(port: u16) -> MlsClientClient<tonic::transport::Channel> {
    let endpoint = format!("http://127.0.0.1:{port}");
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        if let Ok(mut client) = MlsClientClient::connect(endpoint.clone()).await {
            if client.name(NameRequest {}).await.is_ok() {
                return client;
            }
        }
        if std::time::Instant::now() > deadline {
            panic!("server on port {port} did not become ready within 15s");
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}

#[tokio::test]
async fn welcome_join_across_two_processes() {
    let alice_port = pick_port();
    let bob_port = pick_port();
    assert_ne!(alice_port, bob_port);

    // Spawn two real binaries, each on its own port + own softhsm token.
    let mut alice_proc = spawn_server(alice_port).await;
    let mut bob_proc = spawn_server(bob_port).await;

    // Use a scope guard pattern: kill children on every exit path so a
    // panic doesn't leave zombie processes.
    let result = async {
        let mut alice_client = wait_for_server(alice_port).await;
        let mut bob_client = wait_for_server(bob_port).await;
        let cs: u32 = 1; // MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519

        // ── Step 1: Bob mints a KeyPackage on server B ─────────────────
        let bob_kp = bob_client
            .create_key_package(CreateKeyPackageRequest {
                cipher_suite: cs,
                identity: b"bob@process-B".to_vec(),
            })
            .await
            .expect("Bob CreateKeyPackage")
            .into_inner();
        assert!(!bob_kp.key_package.is_empty());
        eprintln!("[B] Bob minted KeyPackage ({} bytes)", bob_kp.key_package.len());

        // ── Step 2: Alice creates a group on server A ──────────────────
        let alice = alice_client
            .create_group(CreateGroupRequest {
                cipher_suite: cs,
                group_id: vec![0xcc; 16],
                identity: b"alice@process-A".to_vec(),
                encrypt_handshake: false,
            })
            .await
            .expect("Alice CreateGroup")
            .into_inner();
        eprintln!("[A] Alice created group, state_id={}", alice.state_id);

        // ── Step 3: Alice issues an Add proposal for Bob's KeyPackage ──
        // (Bob's KeyPackage bytes from server B cross the loopback into
        // server A here — first real cross-process MLS message.)
        let add = alice_client
            .add_proposal(AddProposalRequest {
                state_id: alice.state_id,
                key_package: bob_kp.key_package.clone(),
            })
            .await
            .expect("Alice AddProposal")
            .into_inner();
        eprintln!("[A] Add proposal: {} bytes", add.proposal.len());

        // ── Step 4: Alice commits + merges ─────────────────────────────
        let commit = alice_client
            .commit(CommitRequest {
                state_id: alice.state_id,
                by_reference: vec![add.proposal.clone()],
                by_value: vec![],
                external_tree: false,
                force_path: false,
            })
            .await
            .expect("Alice Commit")
            .into_inner();
        assert!(!commit.welcome.is_empty(), "Welcome produced for Bob");
        eprintln!(
            "[A] Commit produced: commit={}B, welcome={}B, ratchet_tree={}B",
            commit.commit.len(),
            commit.welcome.len(),
            commit.ratchet_tree.len()
        );

        let alice_after = alice_client
            .handle_pending_commit(HandlePendingCommitRequest {
                state_id: alice.state_id,
            })
            .await
            .expect("Alice HandlePendingCommit")
            .into_inner();

        // ── Step 5: Welcome bytes cross loopback into server B ─────────
        let bob_joined = bob_client
            .join_group(JoinGroupRequest {
                transaction_id: bob_kp.transaction_id,
                welcome: commit.welcome.clone(),
                ratchet_tree: commit.ratchet_tree.clone(),
                encrypt_handshake: false,
                identity: b"bob@process-B".to_vec(),
            })
            .await
            .expect("Bob JoinGroup")
            .into_inner();
        eprintln!(
            "[B] Bob joined, state_id={}, epoch_authenticator={}B",
            bob_joined.state_id,
            bob_joined.epoch_authenticator.len()
        );

        // ── Step 6: The proof — both processes reach the same epoch ────
        assert_eq!(
            alice_after.epoch_authenticator, bob_joined.epoch_authenticator,
            "alice (process A) and bob (process B) must agree on epoch_authenticator \
             after cross-process Welcome+Commit"
        );

        // Sanity: StateAuth on both sides confirms it independently.
        let alice_sa = alice_client
            .state_auth(StateAuthRequest {
                state_id: alice.state_id,
            })
            .await
            .unwrap()
            .into_inner();
        let bob_sa = bob_client
            .state_auth(StateAuthRequest {
                state_id: bob_joined.state_id,
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(alice_sa.state_auth_secret, bob_sa.state_auth_secret);

        eprintln!(
            "==> cross-process MLS welcome_join succeeded — epoch_authenticator \
             ({} bytes) byte-identical between two independent processes",
            alice_sa.state_auth_secret.len()
        );
    }
    .await;

    // Clean up both children, regardless of test outcome. (If the async
    // block above panicked, the panic has already unwound — these kills
    // run during stack cleanup since we await up to this point.)
    let _ = alice_proc.kill().await;
    let _ = bob_proc.kill().await;
    let _ = result;
}
