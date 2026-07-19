//! hsm-perf-bench harness — pkcs11-direct mode (plan §A4.1/§P4).
//!
//! Proves the harness mechanism end to end against the REAL engine,
//! through the REAL dlopen'd C ABI, before any threading/JSONL/algorithm-
//! matrix complexity is added: load the library, bootstrap two SEPARATE
//! tenant tokens via nothing but standard PKCS#11 v3.2 operations
//! (`C_GetSlotList`/`C_InitToken`/`C_OpenSession`/`C_Login`/`C_InitPIN`/
//! `C_Logout`/`C_CloseSession` — no vendor extensions), generate a real
//! Ed25519 key pair per tenant, sign, verify, and prove cross-tenant
//! isolation with a real spec-defined error code, not an assumption.
//! Proves one representative op from the other two axis categories —
//! X25519 ECDH key agreement and ML-KEM-768 encapsulate/decapsulate —
//! each with its own genuine cryptographic correctness self-check, not
//! just a bare `CKR_OK`. Then, per §A7 ("fixed-duration points... not
//! fixed-op-count"), runs a real fixed-duration multi-threaded
//! measurement point per op and emits one JSONL row per point (§A4.1's
//! output contract) to stdout.
//!
//! Topology B (§A4.1/§A4.2, "independent-N-instances"): `--instances N`
//! (N>1) turns this invocation into a PARENT that spawns N SEPARATE OS
//! PROCESSES of this same binary, each running the identical single-
//! instance measurement in complete isolation, and relays their JSONL
//! rows to its own stdout. Real process separation, not simulated —
//! `rust/src/state.rs`'s `TOKEN_STORE`/`OBJECTS`/`SESSIONS` are
//! `lazy_static!` (process-global, Mutex-guarded), confirmed by reading
//! that file before designing this: multiple OS THREADS in one process
//! genuinely share and contend on that state (exactly what
//! shared-1-instance measures), while multiple OS PROCESSES each get
//! their own independent copy purely from address-space separation — no
//! IPC or explicit reset needed for the isolation to be real. Children
//! are spawned via `Command::new(current_exe)` (a fresh process image),
//! not a raw POSIX `fork()`: forking a multi-threaded process is a
//! well-known hazard (only the forking thread survives in the child;
//! mutexes held by other threads at fork time stay locked forever) —
//! spawning a new process achieves the identical "separate process,
//! separate dlopen'd engine copy" independence this topology needs,
//! without that hazard.
//!
//! Scope note (this increment): 2 fixed tenants per instance,
//! pkcs11-direct access path only, 5 of the ~18-algorithm matrix (§A5).
//! The full algorithm matrix and kmip mode (§P2) are later, separately-
//! verified increments — not built here.

mod algos;
mod measure;
mod pkcs11;

use anyhow::{bail, Context, Result};
use clap::Parser;
use pkcs11::Engine;
use softhsmrustv3::ck_abi::{
    CK_ATTRIBUTE, CK_ATTRIBUTE_TYPE, CK_OBJECT_HANDLE, CK_SESSION_HANDLE, CK_SLOT_ID, CK_ULONG,
    CK_VOID_PTR,
};
use softhsmrustv3::constants::{CKA_EC_POINT, CKA_VALUE, CKR_KEY_HANDLE_INVALID, CKR_OBJECT_HANDLE_INVALID};
use std::io::Read;
use std::process::Stdio;
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(name = "bench-harness", about = "hsm-perf-bench PKCS#11-direct measurement harness")]
struct Cli {
    /// Path to the compiled softhsmrustv3 shared library.
    #[arg(long, default_value = "../target/release/libsofthsmrustv3.dylib")]
    library: String,
    /// Worker threads for the measured loop (§A4.2 axis — round-robin
    /// across the 2 tenants, each on its OWN session so concurrent ops
    /// don't race on one session's operation state, §6.5.1). Per §A4.2,
    /// this is PER INSTANCE: total concurrency under Topology B is
    /// `threads * instances`.
    #[arg(long, default_value_t = 4)]
    threads: u32,
    /// Measured window per point, seconds (§A6 "seconds-per-point", §A7
    /// "fixed-duration points").
    #[arg(long, default_value_t = 2.0)]
    duration_secs: f64,
    /// Unmeasured warm-up per point, seconds (§A7).
    #[arg(long, default_value_t = 0.5)]
    warmup_secs: f64,
    /// Topology B (§A4.2): number of independent instances, 1-4. `1`
    /// (default) is Topology A (shared-1-instance) — unchanged in-process
    /// behavior. `>1` makes this invocation the parent orchestrator.
    #[arg(long, default_value_t = 1)]
    instances: u32,
    /// INTERNAL — set by the parent orchestrator on every child it spawns
    /// so the child stamps its JSONL rows as one of an N-instance
    /// Topology-B run even though it always executes as a plain,
    /// single-instance measurement itself (`instances` is forced to `1`
    /// on the child's own invocation). Not meant to be set by hand.
    #[arg(long, hide = true)]
    topology_instances: Option<u32>,
}

/// One tenant's bootstrapped token + real, sanity-checked key material for
/// every op category this increment measures. Ed25519 keys sign/verify
/// their own sanity check inline; ML-KEM keys encapsulate/decapsulate
/// their own sanity check inline (`kem_ciphertext`/`kem_ss` are the
/// resulting pair, reused by the measured decapsulate loop so it doesn't
/// need a fresh encapsulate call per iteration). X25519 needs a REAL
/// peer, so its cross-tenant derive proof happens in `main` once both
/// tenants exist; `peer_kex_point` is filled in there too.
struct Tenant {
    slot: CK_SLOT_ID,
    session: CK_SESSION_HANDLE,
    pub_handle: CK_OBJECT_HANDLE,
    priv_handle: CK_OBJECT_HANDLE,
    kex_priv: CK_OBJECT_HANDLE,
    kex_pub_point: Vec<u8>,
    peer_kex_point: Vec<u8>,
    kem_pub: CK_OBJECT_HANDLE,
    kem_priv: CK_OBJECT_HANDLE,
    kem_ciphertext: Vec<u8>,
}

/// Claim the next free slot (standard §5.4 `C_GetSlotList` auto-replenish
/// — see `pkcs11.rs::get_slot_list`'s doc comment) and bring up a real
/// token with sanity-checked Ed25519, X25519, and ML-KEM-768 key material
/// on it, per-tenant PINs so each tenant's token stays independently
/// openable (matching the KMIP server's own per-tenant-PIN tenancy model).
fn provision_tenant(engine: &Engine, name: &str) -> Result<Tenant> {
    let slots_before = engine.get_slot_list().context("C_GetSlotList")?;
    let slot = *slots_before
        .last()
        .expect("engine always reports at least one slot (§5.4 auto-replenish)");

    let session = engine
        .bootstrap_token(slot, &format!("so-pin-{name}"), &format!("user-pin-{name}"), &format!("bench-{name}"))
        .with_context(|| format!("bootstrap_token(slot={slot}, tenant={name})"))?;

    // ── Ed25519 — self-contained sanity check (both keys are this
    // tenant's own). ────────────────────────────────────────────────────
    let sig_algo = algos::ED25519;
    let (pub_handle, priv_handle) = engine
        .generate_key_pair(session, sig_algo.keygen_mechanism, &mut [], &mut [])
        .with_context(|| format!("C_GenerateKeyPair({}, tenant={name})", sig_algo.name))?;
    let message = format!("hsm-perf-bench harness proof — tenant {name}").into_bytes();
    engine.sign_init(session, sig_algo.sign_mechanism, priv_handle).context("C_SignInit")?;
    let signature = engine.sign(session, &message).context("C_Sign")?;
    engine.verify_init(session, sig_algo.sign_mechanism, pub_handle).context("C_VerifyInit")?;
    let valid = engine.verify(session, &message, &signature).context("C_Verify")?;
    assert!(valid, "tenant {name}'s own {} signature must verify", sig_algo.name);

    // ── X25519 — keygen only here; the derive proof needs a real peer,
    // done in `main` once both tenants exist. ──────────────────────────
    let kex_algo = algos::X25519;
    let (kex_pub, kex_priv) = engine
        .generate_key_pair(session, kex_algo.keygen_mechanism, &mut [], &mut [])
        .with_context(|| format!("C_GenerateKeyPair({}, tenant={name})", kex_algo.name))?;
    let kex_pub_point = engine
        .get_attribute_value(session, kex_pub, CKA_EC_POINT)
        .with_context(|| format!("C_GetAttributeValue({} CKA_EC_POINT, tenant={name})", kex_algo.name))?;

    // ── ML-KEM-768 — self-contained sanity check (encapsulate against
    // this tenant's own public key, decapsulate with its own private
    // key). The resulting (ciphertext, shared secret) pair is kept:
    // the measured decapsulate loop reuses the SAME ciphertext every
    // iteration (ML-KEM decapsulate is deterministic given (sk, ct), so
    // this still exercises the real math each call — it just avoids
    // needing a fresh encapsulate call per measured iteration). ────────
    let kem_algo = algos::ML_KEM_768;
    let mut param_set_value: u32 = kem_algo.parameter_set;
    let mut kem_pub_template = [CK_ATTRIBUTE {
        attrType: algos::PARAMETER_SET_ATTR as CK_ATTRIBUTE_TYPE,
        pValue: &mut param_set_value as *mut u32 as CK_VOID_PTR,
        ulValueLen: std::mem::size_of::<u32>() as CK_ULONG,
    }];
    let (kem_pub, kem_priv) = engine
        .generate_key_pair(session, kem_algo.keygen_mechanism, &mut kem_pub_template, &mut [])
        .with_context(|| format!("C_GenerateKeyPair({}, tenant={name})", kem_algo.name))?;
    let (kem_ciphertext, encap_ss_handle) = engine
        .encapsulate_key(session, kem_algo.kem_mechanism, kem_pub, &mut [])
        .with_context(|| format!("C_EncapsulateKey(tenant={name})"))?;
    let decap_ss_handle = engine
        .decapsulate_key(session, kem_algo.kem_mechanism, kem_priv, &kem_ciphertext, &mut [])
        .with_context(|| format!("C_DecapsulateKey(tenant={name})"))?;
    let encap_ss = engine.get_attribute_value(session, encap_ss_handle, CKA_VALUE).context("C_GetAttributeValue(encap CKA_VALUE)")?;
    let decap_ss = engine.get_attribute_value(session, decap_ss_handle, CKA_VALUE).context("C_GetAttributeValue(decap CKA_VALUE)")?;
    assert_eq!(encap_ss, decap_ss, "tenant {name}'s {} decapsulate must recover the SAME shared secret encapsulate produced", kem_algo.name);
    assert_eq!(encap_ss.len(), 32, "{} shared secret must be 32 bytes (FIPS 203)", kem_algo.name);

    Ok(Tenant {
        slot, session, pub_handle, priv_handle,
        kex_priv, kex_pub_point, peer_kex_point: Vec::new(),
        kem_pub, kem_priv, kem_ciphertext,
    })
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.instances > 1 {
        return run_parent(&cli);
    }
    run_instance(&cli)
}

/// Topology B orchestrator: spawn `cli.instances` fresh child processes of
/// this same binary, each forced to `--instances 1` (so it runs the exact
/// same single-instance code path as Topology A) but stamped with
/// `--topology-instances N` so its JSONL rows self-report as one instance
/// of an N-instance independent topology. Each child's whole stdout is a
/// few short JSON lines (5 rows for this increment's algorithm set) —
/// well under any OS pipe buffer, so reading each child fully before
/// moving to the next cannot deadlock on a full pipe; this stays true as
/// long as no future increment makes a single instance's JSONL output
/// pipe-buffer-sized (megabytes) — if that changes, switch to draining
/// each child's stdout on its own thread instead of sequentially.
fn run_parent(cli: &Cli) -> Result<()> {
    let self_exe = std::env::current_exe().context("resolving current_exe for child re-exec")?;
    eprintln!(
        "[[parent]] topology B: spawning {} independent instances (separate processes, separate dlopen'd engine copies)",
        cli.instances
    );

    let mut children = Vec::new();
    for instance_id in 0..cli.instances {
        let child = std::process::Command::new(&self_exe)
            .arg("--library").arg(&cli.library)
            .arg("--threads").arg(cli.threads.to_string())
            .arg("--duration-secs").arg(cli.duration_secs.to_string())
            .arg("--warmup-secs").arg(cli.warmup_secs.to_string())
            .arg("--instances").arg("1")
            .arg("--topology-instances").arg(cli.instances.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .with_context(|| format!("spawning instance {instance_id}"))?;
        children.push(child);
    }

    for (instance_id, mut child) in children.into_iter().enumerate() {
        let mut jsonl = String::new();
        child.stdout.take().expect("piped stdout").read_to_string(&mut jsonl).context("reading child stdout")?;
        print!("{jsonl}");
        let status = child.wait().with_context(|| format!("waiting on instance {instance_id}"))?;
        if !status.success() {
            bail!("instance {instance_id} exited with {status}");
        }
    }
    eprintln!("[[parent]] all {} instances completed successfully", cli.instances);
    Ok(())
}

fn run_instance(cli: &Cli) -> Result<()> {
    let (topology, topology_instances): (&'static str, u32) = match cli.topology_instances {
        Some(n) => ("independent-n-instances", n),
        None => ("shared-1-instance", 1),
    };

    let engine = Engine::load(&cli.library).with_context(|| format!("loading engine library at {:?}", cli.library))?;
    engine.initialize().context("C_Initialize")?;
    eprintln!("[ok] engine initialized: {}", cli.library);

    // ── Two tenants, two real tokens, real Ed25519 keys, standard PKCS#11
    // v3.2 calls only. ──────────────────────────────────────────────────
    let mut alice = provision_tenant(&engine, "alice")?;
    eprintln!(
        "[ok] alice bootstrapped on slot {}: session={} pub={} priv={}",
        alice.slot, alice.session, alice.pub_handle, alice.priv_handle
    );
    let mut bob = provision_tenant(&engine, "bob")?;
    eprintln!(
        "[ok] bob bootstrapped on slot {}: session={} pub={} priv={}",
        bob.slot, bob.session, bob.pub_handle, bob.priv_handle
    );
    assert_ne!(alice.slot, bob.slot, "each tenant must land on its own slot");
    eprintln!("[ok] alice and bob each have their own token, own key pair, own signature round-trip");

    // ── Cross-tenant isolation, proven with a real PKCS#11 v3.2 error
    // code — not asserted, not assumed. Bob's session attempting to sign
    // with ALICE's private-key handle must fail: her handle is not
    // visible/usable from his session's token scope. §6.3.2/§6.3.3
    // (SignInit/Sign) list CKR_KEY_HANDLE_INVALID for exactly this case;
    // this engine's own object-handle validation (`can_access_object`,
    // hardened across this whole tenancy effort) may also surface the
    // more general CKR_OBJECT_HANDLE_INVALID — both are spec-defined,
    // and either is an honest "no", so both are accepted here. ─────────
    let cross_tenant_result = engine.sign_init(bob.session, algos::ED25519.sign_mechanism, alice.priv_handle);
    match cross_tenant_result {
        Ok(()) => {
            panic!(
                "SECURITY REGRESSION: Bob's session (slot {}) could SignInit with \
                 Alice's private key handle {} (her slot {}) — cross-tenant isolation failed",
                bob.slot, alice.priv_handle, alice.slot
            );
        }
        Err(e) => {
            let msg = e.to_string();
            let is_expected = msg.contains(&format!("0x{CKR_KEY_HANDLE_INVALID:x}"))
                || msg.contains(&format!("0x{CKR_OBJECT_HANDLE_INVALID:x}"));
            assert!(
                is_expected,
                "expected CKR_KEY_HANDLE_INVALID (0x{CKR_KEY_HANDLE_INVALID:x}) or \
                 CKR_OBJECT_HANDLE_INVALID (0x{CKR_OBJECT_HANDLE_INVALID:x}), got: {msg}"
            );
            eprintln!("[ok] cross-tenant isolation verified: Bob cannot use Alice's key handle ({msg})");
        }
    }

    // Bob's OWN key still works after the rejected cross-tenant attempt —
    // proves the isolation check is a real gate, not a session-poisoning
    // side effect.
    let message = b"bob signs after the rejected cross-tenant attempt";
    engine.sign_init(bob.session, algos::ED25519.sign_mechanism, bob.priv_handle).context("C_SignInit (bob, post-check)")?;
    let sig = engine.sign(bob.session, message).context("C_Sign (bob, post-check)")?;
    engine.verify_init(bob.session, algos::ED25519.sign_mechanism, bob.pub_handle).context("C_VerifyInit (bob, post-check)")?;
    let valid = engine.verify(bob.session, message, &sig).context("C_Verify (bob, post-check)")?;
    assert!(valid, "bob's own key must still work after the rejected cross-tenant attempt");
    eprintln!("[ok] bob's own key still works after the rejected cross-tenant attempt — real gate, not a blanket deny");

    // ── ECDH-derive category (X25519, PKCS#11 v3.2 §6.7) — genuine
    // two-party key agreement across alice's and bob's SEPARATE tokens,
    // each already holding her/his own X25519 keypair from
    // `provision_tenant`. The only real correctness check a DH exchange
    // offers: both sides must independently derive the IDENTICAL shared
    // secret. ────────────────────────────────────────────────────────
    let mut bob_point_for_alice = bob.kex_pub_point.clone();
    let mut alice_point_for_bob = alice.kex_pub_point.clone();
    let alice_shared_handle = engine.ecdh1_derive(alice.session, alice.kex_priv, &mut bob_point_for_alice).context("C_DeriveKey(ECDH1, alice)")?;
    let bob_shared_handle = engine.ecdh1_derive(bob.session, bob.kex_priv, &mut alice_point_for_bob).context("C_DeriveKey(ECDH1, bob)")?;
    let alice_shared = engine.get_attribute_value(alice.session, alice_shared_handle, CKA_VALUE).context("C_GetAttributeValue(alice shared CKA_VALUE)")?;
    let bob_shared = engine.get_attribute_value(bob.session, bob_shared_handle, CKA_VALUE).context("C_GetAttributeValue(bob shared CKA_VALUE)")?;
    assert_eq!(alice_shared, bob_shared, "X25519 ECDH must produce the SAME shared secret on both sides");
    assert_eq!(alice_shared.len(), 32, "X25519 shared secret must be 32 bytes (RFC 7748)");
    eprintln!(
        "[ok] {} key agreement verified: alice and bob independently derived the SAME {}-byte shared secret",
        algos::X25519.name, alice_shared.len()
    );
    alice.peer_kex_point = bob.kex_pub_point.clone();
    bob.peer_kex_point = alice.kex_pub_point.clone();

    eprintln!(
        "[ok] {} KEM round-trip verified for both tenants during provisioning: {}-byte ciphertexts, matching encap/decap shared secrets",
        algos::ML_KEM_768.name, alice.kem_ciphertext.len()
    );

    // ── Fixed-duration, multi-threaded measurement (§A7): one point per
    // op, `cli.threads` workers round-robin across the 2 tenants, each
    // worker on its OWN session (an operation's state — SignInit/Sign,
    // etc. — lives on the session, so concurrent workers sharing one
    // session would race each other's operation context). Login state
    // is per-TOKEN not per-session (verified against `ffi.rs::C_Login`
    // — `token.login_state` lives in `TOKEN_STORE` keyed by slot), so a
    // worker session on an already-logged-in tenant slot needs no
    // separate login; and `can_access_object` gates by slot, not by
    // creating session, so every worker can use its tenant's key
    // material without regenerating it. ─────────────────────────────────
    let tenants = [&alice, &bob];
    let mut worker_sessions: Vec<(CK_SESSION_HANDLE, usize)> = Vec::new();
    for w in 0..cli.threads {
        let tenant_idx = (w as usize) % tenants.len();
        let session = engine.open_session(tenants[tenant_idx].slot).with_context(|| format!("C_OpenSession (worker {w})"))?;
        worker_sessions.push((session, tenant_idx));
    }
    eprintln!("[ok] {} worker sessions opened across {} tenants", worker_sessions.len(), tenants.len());

    let engine = Arc::new(engine);
    let engine_version = engine.library_version().context("C_GetInfo")?;
    let common = |op: &'static str, category: &'static str, algorithm: &'static str, security_level: &'static str, total_ops: u64, latencies_ms: Vec<f64>, duration_s: f64| {
        let (p50_ms, p99_ms) = measure::percentiles_ms(latencies_ms);
        measure::ResultRow {
            access_path: "pkcs11-direct",
            topology,
            instances: topology_instances,
            tenants: tenants.len() as u32,
            threads: cli.threads,
            category, algorithm, security_level, op,
            ops_per_sec: total_ops as f64 / duration_s,
            p50_ms, p99_ms, duration_s, total_ops,
            engine_version: engine_version.clone(),
        }
    };
    let stdout = std::io::stdout();

    // sign (Ed25519, L1)
    {
        let workers: Vec<_> = worker_sessions.iter().map(|&(session, idx)| {
            let engine = Arc::clone(&engine);
            let priv_handle = tenants[idx].priv_handle;
            let mechanism = algos::ED25519.sign_mechanism;
            let message = format!("hsm-perf-bench measured sign — tenant {idx}").into_bytes();
            move || -> Result<()> {
                engine.sign_init(session, mechanism, priv_handle)?;
                engine.sign(session, &message)?;
                Ok(())
            }
        }).collect();
        let (total_ops, latencies_ms, duration_s) = measure::run_point(cli.duration_secs, cli.warmup_secs, workers)?;
        let row = common("sign", "signature", algos::ED25519.name, "L1", total_ops, latencies_ms, duration_s);
        eprintln!("[ok] measured {}/{}: {:.0} ops/sec over {:.2}s ({} ops)", row.algorithm, row.op, row.ops_per_sec, row.duration_s, row.total_ops);
        serde_json::to_writer(&stdout, &row)?;
        println!();
    }

    // verify (Ed25519, L1) — each worker signs ONE message once (setup,
    // unmeasured) then the timed loop repeatedly verifies that same
    // signature, exercising the real C_VerifyInit/C_Verify path only.
    {
        let workers: Vec<_> = worker_sessions.iter().map(|&(session, idx)| {
            let engine = Arc::clone(&engine);
            let (priv_handle, pub_handle) = (tenants[idx].priv_handle, tenants[idx].pub_handle);
            let mechanism = algos::ED25519.sign_mechanism;
            let message = format!("hsm-perf-bench measured verify — tenant {idx}").into_bytes();
            engine.sign_init(session, mechanism, priv_handle)?;
            let signature = engine.sign(session, &message)?;
            Ok::<_, anyhow::Error>(move || -> Result<()> {
                engine.verify_init(session, mechanism, pub_handle)?;
                engine.verify(session, &message, &signature)?;
                Ok(())
            })
        }).collect::<Result<Vec<_>>>()?;
        let (total_ops, latencies_ms, duration_s) = measure::run_point(cli.duration_secs, cli.warmup_secs, workers)?;
        let row = common("verify", "signature", algos::ED25519.name, "L1", total_ops, latencies_ms, duration_s);
        eprintln!("[ok] measured {}/{}: {:.0} ops/sec over {:.2}s ({} ops)", row.algorithm, row.op, row.ops_per_sec, row.duration_s, row.total_ops);
        serde_json::to_writer(&stdout, &row)?;
        println!();
    }

    // derive (X25519, L1)
    {
        let workers: Vec<_> = worker_sessions.iter().map(|&(session, idx)| {
            let engine = Arc::clone(&engine);
            let priv_handle = tenants[idx].kex_priv;
            let mut peer_point = tenants[idx].peer_kex_point.clone();
            move || -> Result<()> {
                engine.ecdh1_derive(session, priv_handle, &mut peer_point)?;
                Ok(())
            }
        }).collect();
        let (total_ops, latencies_ms, duration_s) = measure::run_point(cli.duration_secs, cli.warmup_secs, workers)?;
        let row = common("derive", "key_establishment", algos::X25519.name, "L1", total_ops, latencies_ms, duration_s);
        eprintln!("[ok] measured {}/{}: {:.0} ops/sec over {:.2}s ({} ops)", row.algorithm, row.op, row.ops_per_sec, row.duration_s, row.total_ops);
        serde_json::to_writer(&stdout, &row)?;
        println!();
    }

    // encapsulate / decapsulate (ML-KEM-768, L3)
    {
        let workers: Vec<_> = worker_sessions.iter().map(|&(session, idx)| {
            let engine = Arc::clone(&engine);
            let kem_pub = tenants[idx].kem_pub;
            move || -> Result<()> {
                engine.encapsulate_key(session, algos::ML_KEM_768.kem_mechanism, kem_pub, &mut [])?;
                Ok(())
            }
        }).collect();
        let (total_ops, latencies_ms, duration_s) = measure::run_point(cli.duration_secs, cli.warmup_secs, workers)?;
        let row = common("encapsulate", "key_establishment", algos::ML_KEM_768.name, "L3", total_ops, latencies_ms, duration_s);
        eprintln!("[ok] measured {}/{}: {:.0} ops/sec over {:.2}s ({} ops)", row.algorithm, row.op, row.ops_per_sec, row.duration_s, row.total_ops);
        serde_json::to_writer(&stdout, &row)?;
        println!();
    }
    {
        let workers: Vec<_> = worker_sessions.iter().map(|&(session, idx)| {
            let engine = Arc::clone(&engine);
            let kem_priv = tenants[idx].kem_priv;
            let ciphertext = tenants[idx].kem_ciphertext.clone();
            move || -> Result<()> {
                engine.decapsulate_key(session, algos::ML_KEM_768.kem_mechanism, kem_priv, &ciphertext, &mut [])?;
                Ok(())
            }
        }).collect();
        let (total_ops, latencies_ms, duration_s) = measure::run_point(cli.duration_secs, cli.warmup_secs, workers)?;
        let row = common("decapsulate", "key_establishment", algos::ML_KEM_768.name, "L3", total_ops, latencies_ms, duration_s);
        eprintln!("[ok] measured {}/{}: {:.0} ops/sec over {:.2}s ({} ops)", row.algorithm, row.op, row.ops_per_sec, row.duration_s, row.total_ops);
        serde_json::to_writer(&stdout, &row)?;
        println!();
    }

    for (session, _) in worker_sessions {
        engine.close_session(session).context("C_CloseSession (worker)")?;
    }
    engine.close_session(alice.session).context("C_CloseSession (alice)")?;
    engine.close_session(bob.session).context("C_CloseSession (bob)")?;
    engine.finalize().context("C_Finalize")?;
    eprintln!("[ok] mechanism + isolation proof + measurement complete — engine finalized cleanly");

    Ok(())
}
