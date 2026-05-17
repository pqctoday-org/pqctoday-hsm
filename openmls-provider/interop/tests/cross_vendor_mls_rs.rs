//! Cross-vendor interop: **pqctoday-mls** (HSM-backed, openmls under
//! the hood) ↔ **awslabs/mls-rs** (the open-source MLS impl AWS
//! Wickr's stack is built on). Two real binaries, native processes,
//! localhost gRPC — no Docker.
//!
//! The test acts as a small replacement for the IETF Go test-runner:
//! it pulls bytes out of one client and feeds them into the other,
//! orchestrating MLS scenarios over the IETF `mls_client.MLSClient`
//! protobuf contract.
//!
//! ## Findings
//!
//! The handshake (Name + SupportedCiphersuites + ciphersuite
//! negotiation) **passes end-to-end** — see
//! `cross_vendor_handshake`. The two implementations have a common
//! cipher_suite (X25519+SHA256+AES128GCM_Ed25519 = #1 and P-256
//! variant = #2) and speak the same IETF protobuf at the wire level.
//!
//! `welcome_join` in **either direction** is blocked by two real
//! spec-interpretation differences between openmls (the engine under
//! pqctoday-mls) and mls-rs — neither is our bug, and both are
//! documented as `#[ignore]`d tests below:
//!
//! 1. **Leaf-node lifetime range**. mls-rs's default is 365 days;
//!    openmls's hardcoded `MAX_LEAF_NODE_LIFETIME_RANGE_SECONDS` is
//!    ~84 days (3 × 28). Each side rejects the other's leaf node
//!    with "lifetime is not acceptable" when validating the
//!    incoming KeyPackage / ratchet tree.
//! 2. **(Fixed in our impl, but worth noting)** RFC 9420 §13.1 says
//!    leaf `capabilities.extensions` MUST NOT advertise the default
//!    extension types (≤ 0x0005). mls-rs's validator returns
//!    `MlsError::DefaultValueListed` when they appear. openmls's
//!    reference example happens to list them; we now skip them in
//!    our `CreateKeyPackage` handler.
//!
//! Genuine cross-impl welcome_join would need either openmls's
//! lifetime const relaxed, mls-rs's default tightened (via
//! `ClientBuilder::key_package_lifetime`), or a config knob exposed
//! through both gRPC harnesses.
//!
//! ## Running
//!
//! Build mls-rs's harness binary once:
//!
//! ```bash
//! export PROTOC=/path/to/protoc  # e.g. brew install protobuf, or use protoc-bin-vendored
//! git clone https://github.com/awslabs/mls-rs.git /tmp/mls-rs
//! cargo build --release \
//!     --manifest-path /tmp/mls-rs/mls-rs/test_harness_integration/Cargo.toml
//! ```
//!
//! Then point this test at it:
//!
//! ```bash
//! MLS_RS_HARNESS=/tmp/mls-rs/target/release/harness_client \
//!     cargo test --release --test cross_vendor_mls_rs -- --test-threads=1 --nocapture
//! ```
//!
//! If `$MLS_RS_HARNESS` is unset the test is **skipped** (printed,
//! no failure) — the rest of the workspace stays green on machines
//! without mls-rs built.

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use pqctoday_mls_interop::mls_client::mls_client_client::MlsClientClient;
use pqctoday_mls_interop::mls_client::{
    AddProposalRequest, CommitRequest, CreateGroupRequest, CreateKeyPackageRequest,
    HandlePendingCommitRequest, JoinGroupRequest, NameRequest, ProposalDescription,
    StateAuthRequest, SupportedCiphersuitesRequest,
};
use tokio::process::{Child, Command};

fn pick_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let port = l.local_addr().unwrap().port();
    drop(l);
    port
}

fn resolve_mls_rs_harness() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("MLS_RS_HARNESS") {
        let pb = PathBuf::from(p);
        if pb.exists() {
            return Some(pb);
        }
    }
    // Default discovery path: `git clone https://github.com/awslabs/mls-rs /tmp/mls-rs`
    // + `cargo build --release` builds the harness into target/release.
    let p = PathBuf::from("/tmp/mls-rs/target/release/harness_client");
    if p.exists() {
        return Some(p);
    }
    None
}

fn pqctoday_binary() -> &'static str {
    env!("CARGO_BIN_EXE_pqctoday-mls-grpc")
}

async fn wait_for_grpc(port: u16, name_hint: &str) -> MlsClientClient<tonic::transport::Channel> {
    let endpoint = format!("http://127.0.0.1:{port}");
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        if let Ok(mut client) = MlsClientClient::connect(endpoint.clone()).await {
            if let Ok(resp) = client.name(NameRequest {}).await {
                eprintln!(
                    "[{name_hint}] up on :{port}, identifies as {:?}",
                    resp.into_inner().name
                );
                return client;
            }
        }
        if std::time::Instant::now() > deadline {
            panic!("server on port {port} ({name_hint}) did not become ready within 20s");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Direction A — Alice on pqctoday-mls, Bob (joiner) on mls-rs.
///
/// **Currently fails**: openmls's KeyPackage validator rejects mls-rs's
/// 365-day default lifetime (openmls's hardcoded `MAX_LEAF_NODE_LIFETIME_RANGE_SECONDS`
/// is ~84 days). This is a known cross-impl friction at the spec layer
/// — not a bug in our HSM provider. Kept as `#[ignore]` documentation of
/// the finding; flip to `#[test]` when either openmls relaxes the bound
/// or mls-rs offers a shorter-lifetime config flag.
#[tokio::test]
#[ignore = "openmls's 84-day MAX_LEAF_NODE_LIFETIME rejects mls-rs's 365-day default — see module docs"]
async fn welcome_join_pqctoday_x_mls_rs() {
    let mls_rs_bin = match resolve_mls_rs_harness() {
        Some(p) => p,
        None => {
            eprintln!(
                "skip: mls-rs harness not found. Set MLS_RS_HARNESS or clone+build mls-rs at \
                 /tmp/mls-rs (see this file's module docs)."
            );
            return;
        }
    };
    eprintln!("[setup] mls-rs harness: {}", mls_rs_bin.display());

    let alice_port = pick_port(); // our binary
    let bob_port = pick_port(); // mls-rs

    let mut alice_proc: Child = Command::new(pqctoday_binary())
        .arg("--port")
        .arg(alice_port.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn pqctoday-mls-grpc");

    let mut bob_proc: Child = Command::new(&mls_rs_bin)
        .arg("--port")
        .arg(bob_port.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn mls-rs harness");

    let result = async {
        let mut alice = wait_for_grpc(alice_port, "pqctoday-mls").await;
        let mut bob = wait_for_grpc(bob_port, "mls-rs (Wickr MLS)").await;

        // ── Sanity: both speak the contract ───────────────────────────
        let alice_name = alice.name(NameRequest {}).await.unwrap().into_inner();
        let bob_name = bob.name(NameRequest {}).await.unwrap().into_inner();
        assert_eq!(alice_name.name, "pqctoday-mls");
        // mls-rs identifies as "Wickr MLS"
        assert!(
            bob_name.name.to_lowercase().contains("wickr")
                || bob_name.name.to_lowercase().contains("mls"),
            "unexpected mls-rs identity: {:?}",
            bob_name.name
        );
        eprintln!(
            "[contract] both clients responsive (alice={:?}, bob={:?})",
            alice_name.name, bob_name.name
        );

        // Find a ciphersuite both sides support.
        let alice_cs = alice
            .supported_ciphersuites(SupportedCiphersuitesRequest {})
            .await
            .unwrap()
            .into_inner()
            .ciphersuites;
        let bob_cs = bob
            .supported_ciphersuites(SupportedCiphersuitesRequest {})
            .await
            .unwrap()
            .into_inner()
            .ciphersuites;
        let common: Vec<u32> = alice_cs.iter().copied().filter(|c| bob_cs.contains(c)).collect();
        eprintln!(
            "[contract] alice cs={:?}, bob cs={:?}, common={:?}",
            alice_cs, bob_cs, common
        );
        let cs = *common
            .first()
            .expect("at least one common ciphersuite between pqctoday-mls and mls-rs");

        // ── Step 1: Bob (mls-rs) mints a KeyPackage ───────────────────
        let bob_kp = bob
            .create_key_package(CreateKeyPackageRequest {
                cipher_suite: cs,
                identity: b"bob@mls-rs".to_vec(),
            })
            .await
            .expect("[mls-rs] Bob CreateKeyPackage")
            .into_inner();
        assert!(!bob_kp.key_package.is_empty());
        eprintln!(
            "[mls-rs] Bob KeyPackage minted: {} bytes",
            bob_kp.key_package.len()
        );

        // ── Step 2: Alice (pqctoday) creates a group ──────────────────
        let alice_state = alice
            .create_group(CreateGroupRequest {
                cipher_suite: cs,
                group_id: vec![0xc0; 16],
                identity: b"alice@pqctoday".to_vec(),
                encrypt_handshake: false,
            })
            .await
            .expect("[pqctoday] Alice CreateGroup")
            .into_inner();
        eprintln!(
            "[pqctoday] Alice group created, state_id={}",
            alice_state.state_id
        );

        // ── Step 3: Alice proposes adding Bob ─────────────────────────
        // (Bob's KeyPackage bytes from mls-rs cross the loopback into
        //  pqctoday — first real cross-vendor MLS message.)
        let add = alice
            .add_proposal(AddProposalRequest {
                state_id: alice_state.state_id,
                key_package: bob_kp.key_package.clone(),
            })
            .await
            .expect("[pqctoday] Alice AddProposal");
        let add = add.into_inner();
        eprintln!("[pqctoday] Add proposal: {} bytes", add.proposal.len());

        // ── Step 4: Alice commits ─────────────────────────────────────
        let commit = alice
            .commit(CommitRequest {
                state_id: alice_state.state_id,
                by_reference: vec![add.proposal.clone()],
                by_value: vec![],
                external_tree: false,
                force_path: false,
            })
            .await
            .expect("[pqctoday] Alice Commit")
            .into_inner();
        assert!(!commit.welcome.is_empty(), "Welcome produced for mls-rs Bob");
        eprintln!(
            "[pqctoday] Commit: commit={}B, welcome={}B, ratchet_tree={}B",
            commit.commit.len(),
            commit.welcome.len(),
            commit.ratchet_tree.len()
        );

        let alice_after = alice
            .handle_pending_commit(HandlePendingCommitRequest {
                state_id: alice_state.state_id,
            })
            .await
            .expect("[pqctoday] Alice HandlePendingCommit")
            .into_inner();
        eprintln!(
            "[pqctoday] epoch_authenticator after merge: {} bytes",
            alice_after.epoch_authenticator.len()
        );

        // ── Step 5: Welcome bytes cross loopback into mls-rs ──────────
        let bob_joined = bob
            .join_group(JoinGroupRequest {
                transaction_id: bob_kp.transaction_id,
                welcome: commit.welcome.clone(),
                ratchet_tree: commit.ratchet_tree.clone(),
                encrypt_handshake: false,
                identity: b"bob@mls-rs".to_vec(),
            })
            .await
            .expect("[mls-rs] Bob JoinGroup against pqctoday's Welcome")
            .into_inner();
        eprintln!(
            "[mls-rs] Bob joined, state_id={}, epoch_authenticator={} bytes",
            bob_joined.state_id,
            bob_joined.epoch_authenticator.len()
        );

        // ── Step 6: The verdict ───────────────────────────────────────
        assert_eq!(
            alice_after.epoch_authenticator, bob_joined.epoch_authenticator,
            "pqctoday-mls (HSM-backed) and mls-rs (Wickr lineage) MUST agree on \
             epoch_authenticator after Welcome+Commit"
        );

        // Independent cross-check via StateAuth on both sides.
        let alice_sa = alice
            .state_auth(StateAuthRequest {
                state_id: alice_state.state_id,
            })
            .await
            .unwrap()
            .into_inner();
        let bob_sa = bob
            .state_auth(StateAuthRequest {
                state_id: bob_joined.state_id,
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(alice_sa.state_auth_secret, bob_sa.state_auth_secret);

        eprintln!(
            "\n==> CROSS-VENDOR INTEROP SUCCEEDED ⚓\n    \
                  pqctoday-mls (HSM-backed) ↔ mls-rs (Wickr MLS)\n    \
                  epoch_authenticator: {} bytes, byte-identical\n    \
                  state_auth_secret:   {} bytes, byte-identical",
            alice_sa.state_auth_secret.len(),
            bob_sa.state_auth_secret.len()
        );
    }
    .await;

    let _ = alice_proc.kill().await;
    let _ = bob_proc.kill().await;
    let _ = result;
}

/// Cross-vendor **gRPC contract handshake**: prove the two binaries
/// can talk to each other end-to-end at the IETF protobuf layer. They
/// resolve identities, enumerate ciphersuites, and find a common
/// ciphersuite that both support. This is the part that works today.
#[tokio::test]
async fn cross_vendor_handshake() {
    let mls_rs_bin = match resolve_mls_rs_harness() {
        Some(p) => p,
        None => {
            eprintln!("skip: mls-rs harness not found (set MLS_RS_HARNESS)");
            return;
        }
    };
    let our_port = pick_port();
    let their_port = pick_port();

    let mut our_proc: Child = Command::new(pqctoday_binary())
        .arg("--port").arg(our_port.to_string())
        .stdout(Stdio::null()).stderr(Stdio::inherit())
        .kill_on_drop(true).spawn().expect("spawn pqctoday-mls-grpc");
    let mut their_proc: Child = Command::new(&mls_rs_bin)
        .arg("--port").arg(their_port.to_string())
        .stdout(Stdio::null()).stderr(Stdio::inherit())
        .kill_on_drop(true).spawn().expect("spawn mls-rs harness");

    let result = async {
        let mut ours = wait_for_grpc(our_port, "pqctoday-mls").await;
        let mut theirs = wait_for_grpc(their_port, "mls-rs (Wickr MLS)").await;

        let our_name = ours.name(NameRequest {}).await.unwrap().into_inner();
        let their_name = theirs.name(NameRequest {}).await.unwrap().into_inner();
        assert_eq!(our_name.name, "pqctoday-mls");
        assert!(their_name.name.contains("Wickr") || their_name.name.contains("MLS"));

        let our_cs = ours.supported_ciphersuites(SupportedCiphersuitesRequest {})
            .await.unwrap().into_inner().ciphersuites;
        let their_cs = theirs.supported_ciphersuites(SupportedCiphersuitesRequest {})
            .await.unwrap().into_inner().ciphersuites;
        let common: Vec<u32> = our_cs.iter().copied().filter(|c| their_cs.contains(c)).collect();

        assert!(!common.is_empty(),
            "pqctoday-mls and mls-rs must share at least one ciphersuite");
        assert_eq!(our_cs, vec![1, 2], "we expose the two baseline suites");
        assert!(their_cs.len() >= 2, "mls-rs exposes at least two suites");

        eprintln!(
            "\n==> CROSS-VENDOR GRPC HANDSHAKE OK\n    \
                  pqctoday-mls: {:?}, suites={:?}\n    \
                  mls-rs:       {:?}, suites={:?}\n    \
                  common:       {:?}\n",
            our_name.name, our_cs, their_name.name, their_cs, common
        );
    }.await;

    let _ = our_proc.kill().await;
    let _ = their_proc.kill().await;
    let _ = result;
}

/// Direction B — Alice on **mls-rs** (group creator), Bob on
/// **pqctoday-mls** (joiner).
///
/// **Currently fails**: mls-rs builds the Welcome successfully and
/// hands it to pqctoday's Bob, but openmls (under the hood) rejects
/// Alice's own leaf node when validating the ratchet tree in the
/// Welcome — same `MAX_LEAF_NODE_LIFETIME_RANGE_SECONDS` check that
/// blocks direction A, just triggered on the receive side. Kept as
/// `#[ignore]` documentation of the cross-impl friction. To make this
/// pass: either openmls needs a runtime tunable on that const, or
/// mls-rs's harness needs to expose `key_package_lifetime` config.
#[tokio::test]
#[ignore = "openmls 84-day MAX_LEAF_NODE_LIFETIME rejects mls-rs's 365-day leaf — see module docs"]
async fn welcome_join_mls_rs_creates_pqctoday_joins() {
    let mls_rs_bin = match resolve_mls_rs_harness() {
        Some(p) => p,
        None => {
            eprintln!("skip: mls-rs harness not found (set MLS_RS_HARNESS)");
            return;
        }
    };

    let alice_port = pick_port(); // mls-rs
    let bob_port = pick_port(); // pqctoday

    let mut alice_proc: Child = Command::new(&mls_rs_bin)
        .arg("--port")
        .arg(alice_port.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn mls-rs harness");

    let mut bob_proc: Child = Command::new(pqctoday_binary())
        .arg("--port")
        .arg(bob_port.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn pqctoday-mls-grpc");

    let result = async {
        let mut alice = wait_for_grpc(alice_port, "mls-rs (Wickr MLS)").await;
        let mut bob = wait_for_grpc(bob_port, "pqctoday-mls").await;

        // Pick a common ciphersuite.
        let alice_cs = alice
            .supported_ciphersuites(SupportedCiphersuitesRequest {})
            .await
            .unwrap()
            .into_inner()
            .ciphersuites;
        let bob_cs = bob
            .supported_ciphersuites(SupportedCiphersuitesRequest {})
            .await
            .unwrap()
            .into_inner()
            .ciphersuites;
        let cs = *alice_cs
            .iter()
            .find(|c| bob_cs.contains(c))
            .expect("at least one shared ciphersuite");
        eprintln!(
            "[contract] alice (mls-rs) supports {} suites, bob (pqctoday) supports {} suites, \
             using cs={}",
            alice_cs.len(),
            bob_cs.len(),
            cs
        );

        // ── Bob (pqctoday) mints a KeyPackage ──────────────────────────
        let bob_kp = bob
            .create_key_package(CreateKeyPackageRequest {
                cipher_suite: cs,
                identity: b"bob@pqctoday".to_vec(),
            })
            .await
            .expect("[pqctoday] Bob CreateKeyPackage")
            .into_inner();
        eprintln!(
            "[pqctoday] Bob KeyPackage minted: {} bytes",
            bob_kp.key_package.len()
        );

        // ── Alice (mls-rs) creates a group ─────────────────────────────
        let alice_state = alice
            .create_group(CreateGroupRequest {
                cipher_suite: cs,
                group_id: vec![0xa1; 16],
                identity: b"alice@mls-rs".to_vec(),
                encrypt_handshake: false,
            })
            .await
            .expect("[mls-rs] Alice CreateGroup")
            .into_inner();
        eprintln!(
            "[mls-rs] Alice group created, state_id={}",
            alice_state.state_id
        );

        // mls-rs's commit_builder starts with empty proposals — it
        // doesn't auto-include the group's pending proposal queue. So
        // we use inline `by_value` (the "add" ProposalDescription type)
        // rather than a separate AddProposal + by_reference dance.
        let commit = alice
            .commit(CommitRequest {
                state_id: alice_state.state_id,
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
            .expect("[mls-rs] Alice Commit with inline Add(Bob)")
            .into_inner();
        assert!(!commit.welcome.is_empty(), "Welcome produced for pqctoday Bob");
        eprintln!(
            "[mls-rs] Commit: commit={}B, welcome={}B, ratchet_tree={}B",
            commit.commit.len(),
            commit.welcome.len(),
            commit.ratchet_tree.len()
        );

        let alice_after = alice
            .handle_pending_commit(HandlePendingCommitRequest {
                state_id: alice_state.state_id,
            })
            .await
            .expect("[mls-rs] Alice HandlePendingCommit")
            .into_inner();

        // ── Bob (pqctoday) processes the Welcome from mls-rs ───────────
        let bob_joined = bob
            .join_group(JoinGroupRequest {
                transaction_id: bob_kp.transaction_id,
                welcome: commit.welcome.clone(),
                ratchet_tree: commit.ratchet_tree.clone(),
                encrypt_handshake: false,
                identity: b"bob@pqctoday".to_vec(),
            })
            .await
            .expect("[pqctoday] Bob JoinGroup against mls-rs's Welcome")
            .into_inner();
        eprintln!(
            "[pqctoday] Bob joined: state_id={}, epoch_authenticator={} bytes",
            bob_joined.state_id,
            bob_joined.epoch_authenticator.len()
        );

        assert_eq!(
            alice_after.epoch_authenticator, bob_joined.epoch_authenticator,
            "mls-rs (Wickr lineage) and pqctoday-mls (HSM-backed) MUST agree on \
             epoch_authenticator across the gRPC wire"
        );

        let alice_sa = alice
            .state_auth(StateAuthRequest {
                state_id: alice_state.state_id,
            })
            .await
            .unwrap()
            .into_inner();
        let bob_sa = bob
            .state_auth(StateAuthRequest {
                state_id: bob_joined.state_id,
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(alice_sa.state_auth_secret, bob_sa.state_auth_secret);

        eprintln!(
            "\n==> CROSS-VENDOR INTEROP SUCCEEDED ⚓\n    \
                  mls-rs (Wickr MLS) creates ↔ pqctoday-mls (HSM-backed) joins\n    \
                  epoch_authenticator: {} bytes, byte-identical\n    \
                  state_auth_secret:   {} bytes, byte-identical",
            alice_sa.state_auth_secret.len(),
            bob_sa.state_auth_secret.len()
        );
    }
    .await;

    let _ = alice_proc.kill().await;
    let _ = bob_proc.kill().await;
    let _ = result;
}
