//! hsm-perf-bench harness — pkcs11-direct mode (plan §A4.1/§P4).
//!
//! Proves the harness mechanism end to end against the REAL engine,
//! through the REAL dlopen'd C ABI: load the library, bootstrap two
//! SEPARATE tenant tokens via nothing but standard PKCS#11 v3.2
//! operations (`C_GetSlotList`/`C_InitToken`/`C_OpenSession`/`C_Login`/
//! `C_InitPIN`/`C_Logout`/`C_CloseSession` — no vendor extensions),
//! generate real key material per tenant, sign/verify/derive/encapsulate/
//! decapsulate, and prove cross-tenant isolation with a real spec-defined
//! error code, not an assumption. Then, per §A7 ("fixed-duration
//! points... not fixed-op-count"), runs a real fixed-duration
//! multi-threaded measurement point per (algorithm, op) and emits one
//! JSONL row per point (§A4.1's output contract) to stdout.
//!
//! Algorithm coverage (§A5, `algos.rs`): 9 signature algorithms (Ed25519,
//! ECDSA P-256/384/521, ML-DSA-44/65/87, SLH-DSA-SHA2-128s/256s behind
//! `--include-slow`), 4 key-agreement algorithms (X25519, ECDH
//! P-256/384/521), 3 KEMs (ML-KEM-512/768/1024) — 16 algorithms, every
//! mechanism/attribute verified against `rust/src/ffi.rs`'s real dispatch
//! before use (see `algos.rs`'s own doc comment for the two categories
//! deliberately NOT here: composite/hybrid signatures have no native
//! mechanism in this engine, "modeled not native" per §A5 itself; hybrid/
//! native KEMs like X25519MLKEM768 exist ONLY behind the KMIP server's
//! own tenant bookkeeping, unreachable from a pkcs11-direct harness).
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
//! pkcs11-direct access path only. kmip mode (§P2) is a later,
//! separately-verified increment — not built here.

mod algos;
mod measure;
mod pkcs11;

use anyhow::{bail, Context, Result};
use clap::Parser;
use pkcs11::Engine;
use softhsmrustv3::ck_abi::{CK_OBJECT_HANDLE, CK_SESSION_HANDLE, CK_SLOT_ID};
use softhsmrustv3::constants::{CKA_EC_POINT, CKA_VALUE, CKR_KEY_HANDLE_INVALID, CKR_OBJECT_HANDLE_INVALID};
use std::collections::HashMap;
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
    /// §A6 "Include-slow-algorithms toggle" — includes SLH-DSA-SHA2-128s/
    /// 256s (orders of magnitude slower to sign than everything else in
    /// the matrix).
    #[arg(long, default_value_t = false)]
    include_slow: bool,
    /// Print the configured (algorithm, op) matrix as JSON and exit —
    /// NO engine load, NO dlopen, NO C_Initialize. Lets a caller (e.g.
    /// the sandbox UI's job backend, hsm-perf-bench-ui-implementation-
    /// plan-07192026.md §2.4) learn the exact expected row count/labels
    /// up front from the harness's own real algorithm list, instead of
    /// duplicating it as a separately-maintained constant that could
    /// drift from `algos.rs`.
    #[arg(long, default_value_t = false)]
    list_algorithms: bool,
    /// INTERNAL — set by the parent orchestrator on every child it spawns
    /// so the child stamps its JSONL rows as one of an N-instance
    /// Topology-B run even though it always executes as a plain,
    /// single-instance measurement itself (`instances` is forced to `1`
    /// on the child's own invocation). Not meant to be set by hand.
    #[arg(long, hide = true)]
    topology_instances: Option<u32>,
    /// INTERNAL — set by the parent orchestrator alongside
    /// `--topology-instances`, distinct value per child (0..N), so each
    /// child's rows are individually attributable instead of all N
    /// children's rows carrying the same bare instance COUNT with no way
    /// to tell which instance produced which row. Not meant to be set by
    /// hand.
    #[arg(long, hide = true)]
    instance_id: Option<u32>,
}

struct SigMaterial {
    pub_handle: CK_OBJECT_HANDLE,
    priv_handle: CK_OBJECT_HANDLE,
}

struct KexMaterial {
    priv_handle: CK_OBJECT_HANDLE,
    own_point: Vec<u8>,
    peer_point: Vec<u8>,
}

struct KemMaterial {
    pub_handle: CK_OBJECT_HANDLE,
    priv_handle: CK_OBJECT_HANDLE,
    ciphertext: Vec<u8>,
}

/// One tenant's bootstrapped token + real, sanity-checked key material for
/// every algorithm in the configured matrix, keyed by algorithm name.
/// Signature keys sign/verify their own sanity check inline; KEM keys
/// encapsulate/decapsulate their own sanity check inline (the resulting
/// ciphertext is kept, reused by the measured decapsulate loop so it
/// doesn't need a fresh encapsulate call per iteration — decapsulate is
/// deterministic given (sk, ct), so this still exercises the real math
/// each call). Key-agreement keys need a REAL peer, so their cross-tenant
/// derive proof happens in `run_instance` once both tenants exist;
/// `peer_point` is filled in there too.
struct Tenant {
    slot: CK_SLOT_ID,
    session: CK_SESSION_HANDLE,
    sig: HashMap<&'static str, SigMaterial>,
    kex: HashMap<&'static str, KexMaterial>,
    kem: HashMap<&'static str, KemMaterial>,
}

/// Claim the next free slot (standard §5.4 `C_GetSlotList` auto-replenish
/// — see `pkcs11.rs::get_slot_list`'s doc comment) and bring up a real
/// token with sanity-checked key material for every algorithm in
/// `sig_algos`/`kex_algos`/`kem_algos`, per-tenant PINs so each tenant's
/// token stays independently openable (matching the KMIP server's own
/// per-tenant-PIN tenancy model).
///
/// Also returns this tenant's own real `C_GenerateKeyPair` wall-clock
/// time per algorithm (keyed by algo name — unique across sig/kex/kem,
/// so one map covers all three). This is ONLY used to report a `keygen`
/// JSONL row later; every timed sign/verify/derive/encapsulate/
/// decapsulate closure built from this tenant's material still excludes
/// keygen entirely (plan §A7: "Keys pre-generated per tenant before
/// timing — keygen excluded from the measured loop") — these are the
/// SAME keygen calls provisioning already had to make, timed in place,
/// not extra calls made just to produce a number.
fn provision_tenant(
    engine: &Engine,
    name: &str,
    sig_algos: &[algos::SignatureAlgo],
    kex_algos: &[algos::KeyAgreementAlgo],
    kem_algos: &[algos::KemAlgo],
) -> Result<(Tenant, HashMap<&'static str, f64>)> {
    let slots_before = engine.get_slot_list().context("C_GetSlotList")?;
    let slot = *slots_before
        .last()
        .expect("engine always reports at least one slot (§5.4 auto-replenish)");

    let session = engine
        .bootstrap_token(slot, &format!("so-pin-{name}"), &format!("user-pin-{name}"), &format!("bench-{name}"))
        .with_context(|| format!("bootstrap_token(slot={slot}, tenant={name})"))?;

    let mut keygen_ms: HashMap<&'static str, f64> = HashMap::new();

    let mut sig = HashMap::new();
    for algo in sig_algos {
        let keygen_start = std::time::Instant::now();
        let (pub_handle, priv_handle) = engine
            .generate_key_pair_with_param(session, algo.keygen_mechanism, algo.keygen_param)
            .with_context(|| format!("C_GenerateKeyPair({}, tenant={name})", algo.name))?;
        keygen_ms.insert(algo.name, keygen_start.elapsed().as_secs_f64() * 1000.0);
        // Self-contained sanity: this tenant's own key round-trips.
        let message = format!("hsm-perf-bench harness proof — {} — tenant {name}", algo.name).into_bytes();
        engine.sign_init(session, algo.sign_mechanism, priv_handle).with_context(|| format!("C_SignInit({})", algo.name))?;
        let signature = engine.sign(session, &message).with_context(|| format!("C_Sign({})", algo.name))?;
        engine.verify_init(session, algo.sign_mechanism, pub_handle).with_context(|| format!("C_VerifyInit({})", algo.name))?;
        let valid = engine.verify(session, &message, &signature).with_context(|| format!("C_Verify({})", algo.name))?;
        assert!(valid, "tenant {name}'s own {} signature must verify", algo.name);
        sig.insert(algo.name, SigMaterial { pub_handle, priv_handle });
    }

    let mut kex = HashMap::new();
    for algo in kex_algos {
        // Keygen only here; the derive proof needs a real peer, done in
        // `run_instance` once both tenants exist.
        let keygen_start = std::time::Instant::now();
        let (pub_handle, priv_handle) = engine
            .generate_key_pair_with_param(session, algo.keygen_mechanism, algo.keygen_param)
            .with_context(|| format!("C_GenerateKeyPair({}, tenant={name})", algo.name))?;
        keygen_ms.insert(algo.name, keygen_start.elapsed().as_secs_f64() * 1000.0);
        let own_point = engine
            .get_attribute_value(session, pub_handle, CKA_EC_POINT)
            .with_context(|| format!("C_GetAttributeValue({} CKA_EC_POINT, tenant={name})", algo.name))?;
        kex.insert(algo.name, KexMaterial { priv_handle, own_point, peer_point: Vec::new() });
    }

    let mut kem = HashMap::new();
    for algo in kem_algos {
        let keygen_start = std::time::Instant::now();
        let (pub_handle, priv_handle) = engine
            .generate_key_pair_with_param(session, algo.keygen_mechanism, algos::KeygenParam::ParameterSet(algo.parameter_set))
            .with_context(|| format!("C_GenerateKeyPair({}, tenant={name})", algo.name))?;
        keygen_ms.insert(algo.name, keygen_start.elapsed().as_secs_f64() * 1000.0);
        // Self-contained sanity: encapsulate against this tenant's own
        // public key, decapsulate with its own private key.
        let (ciphertext, encap_ss_handle) = engine
            .encapsulate_key(session, algo.kem_mechanism, pub_handle, &mut [])
            .with_context(|| format!("C_EncapsulateKey({}, tenant={name})", algo.name))?;
        let decap_ss_handle = engine
            .decapsulate_key(session, algo.kem_mechanism, priv_handle, &ciphertext, &mut [])
            .with_context(|| format!("C_DecapsulateKey({}, tenant={name})", algo.name))?;
        let encap_ss = engine.get_attribute_value(session, encap_ss_handle, CKA_VALUE).with_context(|| format!("C_GetAttributeValue(encap CKA_VALUE, {})", algo.name))?;
        let decap_ss = engine.get_attribute_value(session, decap_ss_handle, CKA_VALUE).with_context(|| format!("C_GetAttributeValue(decap CKA_VALUE, {})", algo.name))?;
        assert_eq!(encap_ss, decap_ss, "tenant {name}'s {} decapsulate must recover the SAME shared secret encapsulate produced", algo.name);
        assert_eq!(encap_ss.len(), 32, "{} shared secret must be 32 bytes (FIPS 203)", algo.name);
        kem.insert(algo.name, KemMaterial { pub_handle, priv_handle, ciphertext });
    }

    Ok((Tenant { slot, session, sig, kex, kem }, keygen_ms))
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.list_algorithms {
        return list_algorithms(&cli);
    }
    if cli.instances > 1 {
        return run_parent(&cli);
    }
    run_instance(&cli)
}

#[derive(serde::Serialize)]
struct AlgoCell {
    category: &'static str,
    algorithm: &'static str,
    security_level: &'static str,
    op: &'static str,
}

/// `--list-algorithms`: the configured matrix's exact (category,
/// algorithm, security_level, op) cells, in the same vocabulary
/// `measure::ResultRow` uses for those fields — so a caller can match
/// this list's entries directly against streamed JSONL rows with no
/// translation. Touches nothing but `algos.rs`'s own const data; no
/// `Engine::load` anywhere in this path.
fn list_algorithms(cli: &Cli) -> Result<()> {
    let sig_algos: Vec<algos::SignatureAlgo> = algos::SIGNATURE_ALGOS.iter().copied().filter(|a| cli.include_slow || !a.slow).collect();

    let mut cells = Vec::new();
    for algo in &sig_algos {
        for op in ["keygen", "sign", "verify"] {
            cells.push(AlgoCell { category: "signature", algorithm: algo.name, security_level: algo.security_level, op });
        }
    }
    for algo in algos::KEY_AGREEMENT_ALGOS {
        for op in ["keygen", "derive"] {
            cells.push(AlgoCell { category: "key_establishment", algorithm: algo.name, security_level: algo.security_level, op });
        }
    }
    for algo in algos::KEM_ALGOS {
        for op in ["keygen", "encapsulate", "decapsulate"] {
            cells.push(AlgoCell { category: "key_establishment", algorithm: algo.name, security_level: algo.security_level, op });
        }
    }
    println!("{}", serde_json::to_string(&cells)?);
    Ok(())
}

/// Topology B orchestrator: spawn `cli.instances` fresh child processes of
/// this same binary, each forced to `--instances 1` (so it runs the exact
/// same single-instance code path as Topology A) but stamped with
/// `--topology-instances N` so its JSONL rows self-report as one instance
/// of an N-instance independent topology. Each child's whole stdout is a
/// bounded number of short JSON lines — well under any OS pipe buffer, so
/// reading each child fully before moving to the next cannot deadlock on
/// a full pipe; if a future increment makes a single instance's JSONL
/// output pipe-buffer-sized (megabytes), switch to draining each child's
/// stdout on its own thread instead of sequentially.
fn run_parent(cli: &Cli) -> Result<()> {
    let self_exe = std::env::current_exe().context("resolving current_exe for child re-exec")?;
    eprintln!(
        "[[parent]] topology B: spawning {} independent instances (separate processes, separate dlopen'd engine copies)",
        cli.instances
    );

    let mut children = Vec::new();
    for instance_id in 0..cli.instances {
        let mut cmd = std::process::Command::new(&self_exe);
        cmd.arg("--library").arg(&cli.library)
            .arg("--threads").arg(cli.threads.to_string())
            .arg("--duration-secs").arg(cli.duration_secs.to_string())
            .arg("--warmup-secs").arg(cli.warmup_secs.to_string())
            .arg("--instances").arg("1")
            .arg("--topology-instances").arg(cli.instances.to_string())
            .arg("--instance-id").arg(instance_id.to_string());
        if cli.include_slow {
            cmd.arg("--include-slow");
        }
        let child = cmd
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
    // §1 of the telemetry plan: this instance's OWN identity within the
    // topology (0..topology_instances), set by the parent orchestrator
    // alongside --topology-instances. Always 0 under shared-1-instance
    // (there's only ever one instance to be).
    let this_instance_id = cli.instance_id.unwrap_or(0);

    let sig_algos: Vec<algos::SignatureAlgo> = algos::SIGNATURE_ALGOS.iter().copied().filter(|a| cli.include_slow || !a.slow).collect();
    let kex_algos: Vec<algos::KeyAgreementAlgo> = algos::KEY_AGREEMENT_ALGOS.to_vec();
    let kem_algos: Vec<algos::KemAlgo> = algos::KEM_ALGOS.to_vec();

    let engine = Engine::load(&cli.library).with_context(|| format!("loading engine library at {:?}", cli.library))?;
    engine.initialize().context("C_Initialize")?;
    eprintln!("[ok] engine initialized: {}", cli.library);
    eprintln!(
        "[ok] algorithm matrix: {} signature, {} key-agreement, {} KEM ({})",
        sig_algos.len(), kex_algos.len(), kem_algos.len(),
        if cli.include_slow { "including slow algorithms" } else { "slow algorithms excluded, pass --include-slow to add them" }
    );

    // ── Two tenants, two real tokens, standard PKCS#11 v3.2 calls only. ─
    let (mut alice, alice_keygen_ms) = provision_tenant(&engine, "alice", &sig_algos, &kex_algos, &kem_algos)?;
    eprintln!("[ok] alice bootstrapped on slot {}: session={}", alice.slot, alice.session);
    let (mut bob, bob_keygen_ms) = provision_tenant(&engine, "bob", &sig_algos, &kex_algos, &kem_algos)?;
    eprintln!("[ok] bob bootstrapped on slot {}: session={}", bob.slot, bob.session);
    assert_ne!(alice.slot, bob.slot, "each tenant must land on its own slot");
    eprintln!("[ok] alice and bob each have their own token and full key material, every algorithm's own sign/verify or encap/decap round-trip verified");

    // ── Cross-tenant isolation, proven with a real PKCS#11 v3.2 error
    // code — not asserted, not assumed. Bob's session attempting to sign
    // with ALICE's private-key handle (Ed25519, guaranteed present in
    // every matrix configuration) must fail: her handle is not
    // visible/usable from his session's token scope. §6.3.2/§6.3.3
    // (SignInit/Sign) list CKR_KEY_HANDLE_INVALID for exactly this case;
    // this engine's own object-handle validation (`can_access_object`,
    // hardened across this whole tenancy effort) may also surface the
    // more general CKR_OBJECT_HANDLE_INVALID — both are spec-defined,
    // and either is an honest "no", so both are accepted here. ─────────
    let alice_ed25519_priv = alice.sig[algos::ED25519.name].priv_handle;
    let bob_ed25519 = &bob.sig[algos::ED25519.name];
    let cross_tenant_result = engine.sign_init(bob.session, algos::ED25519.sign_mechanism, alice_ed25519_priv);
    match cross_tenant_result {
        Ok(()) => {
            panic!(
                "SECURITY REGRESSION: Bob's session (slot {}) could SignInit with \
                 Alice's private key handle {alice_ed25519_priv} (her slot {}) — cross-tenant isolation failed",
                bob.slot, alice.slot
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
    engine.sign_init(bob.session, algos::ED25519.sign_mechanism, bob_ed25519.priv_handle).context("C_SignInit (bob, post-check)")?;
    let sig = engine.sign(bob.session, message).context("C_Sign (bob, post-check)")?;
    engine.verify_init(bob.session, algos::ED25519.sign_mechanism, bob_ed25519.pub_handle).context("C_VerifyInit (bob, post-check)")?;
    let valid = engine.verify(bob.session, message, &sig).context("C_Verify (bob, post-check)")?;
    assert!(valid, "bob's own key must still work after the rejected cross-tenant attempt");
    eprintln!("[ok] bob's own key still works after the rejected cross-tenant attempt — real gate, not a blanket deny");

    // ── ECDH-derive category, every key-agreement algorithm — genuine
    // two-party key agreement across alice's and bob's SEPARATE tokens,
    // each already holding her/his own keypair from `provision_tenant`.
    // The only real correctness check a DH exchange offers: both sides
    // must independently derive the IDENTICAL shared secret. ──────────
    for algo in &kex_algos {
        let alice_own = alice.kex[algo.name].own_point.clone();
        let bob_own = bob.kex[algo.name].own_point.clone();
        let alice_priv = alice.kex[algo.name].priv_handle;
        let bob_priv = bob.kex[algo.name].priv_handle;

        let mut bob_point_for_alice = bob_own.clone();
        let mut alice_point_for_bob = alice_own.clone();
        let alice_shared_handle = engine.ecdh1_derive(alice.session, alice_priv, &mut bob_point_for_alice).with_context(|| format!("C_DeriveKey(ECDH1, {}, alice)", algo.name))?;
        let bob_shared_handle = engine.ecdh1_derive(bob.session, bob_priv, &mut alice_point_for_bob).with_context(|| format!("C_DeriveKey(ECDH1, {}, bob)", algo.name))?;
        let alice_shared = engine.get_attribute_value(alice.session, alice_shared_handle, CKA_VALUE).with_context(|| format!("C_GetAttributeValue(alice shared CKA_VALUE, {})", algo.name))?;
        let bob_shared = engine.get_attribute_value(bob.session, bob_shared_handle, CKA_VALUE).with_context(|| format!("C_GetAttributeValue(bob shared CKA_VALUE, {})", algo.name))?;
        assert_eq!(alice_shared, bob_shared, "{} ECDH must produce the SAME shared secret on both sides", algo.name);
        eprintln!("[ok] {} key agreement verified: alice and bob independently derived the SAME {}-byte shared secret", algo.name, alice_shared.len());

        alice.kex.get_mut(algo.name).unwrap().peer_point = bob_own;
        bob.kex.get_mut(algo.name).unwrap().peer_point = alice_own;
    }

    for algo in &kem_algos {
        eprintln!(
            "[ok] {} KEM round-trip verified for both tenants during provisioning: {}-byte ciphertexts, matching encap/decap shared secrets",
            algo.name, alice.kem[algo.name].ciphertext.len()
        );
    }

    // ── Fixed-duration, multi-threaded measurement (§A7): one point per
    // (algorithm, op), `cli.threads` workers round-robin across the 2
    // tenants, each worker on its OWN session (an operation's state —
    // SignInit/Sign, etc. — lives on the session, so concurrent workers
    // sharing one session would race each other's operation context).
    // Login state is per-TOKEN not per-session (verified against
    // `ffi.rs::C_Login` — `token.login_state` lives in `TOKEN_STORE`
    // keyed by slot), so a worker session on an already-logged-in tenant
    // slot needs no separate login; and `can_access_object` gates by
    // slot, not by creating session, so every worker can use its
    // tenant's key material without regenerating it. ────────────────────
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
            instance_id: this_instance_id,
            tenants: tenants.len() as u32,
            threads: cli.threads,
            category, algorithm, security_level, op,
            ops_per_sec: total_ops as f64 / duration_s,
            p50_ms, p99_ms, duration_s, total_ops,
            engine_version: engine_version.clone(),
        }
    };
    let stdout = std::io::stdout();
    let emit = |op: &'static str, category: &'static str, algorithm: &'static str, security_level: &'static str, total_ops: u64, latencies_ms: Vec<f64>, duration_s: f64| -> Result<()> {
        let row = common(op, category, algorithm, security_level, total_ops, latencies_ms, duration_s);
        eprintln!("[ok] measured {}/{}: {:.0} ops/sec over {:.2}s ({} ops)", row.algorithm, row.op, row.ops_per_sec, row.duration_s, row.total_ops);
        serde_json::to_writer(&stdout, &row)?;
        println!();
        Ok(())
    };

    // keygen — one real sample per tenant (2 total), NOT a hot loop:
    // these are the SAME `C_GenerateKeyPair` calls `provision_tenant`
    // already had to make, timed in place — no extra calls made just to
    // produce this row, and every sign/verify/derive/encapsulate/
    // decapsulate closure below still excludes keygen entirely (§A7).
    // `duration_s` here is the sum of the 2 real samples' wall-clock
    // time, not a fixed measurement window like the other rows.
    let emit_keygen = |category: &'static str, name: &'static str, security_level: &'static str| -> Result<()> {
        let latencies_ms = vec![alice_keygen_ms[name], bob_keygen_ms[name]];
        let duration_s = (latencies_ms.iter().sum::<f64>() / 1000.0).max(1e-9);
        emit("keygen", category, name, security_level, latencies_ms.len() as u64, latencies_ms, duration_s)
    };
    for algo in &sig_algos {
        emit_keygen("signature", algo.name, algo.security_level)?;
    }
    for algo in &kex_algos {
        emit_keygen("key_establishment", algo.name, algo.security_level)?;
    }
    for algo in &kem_algos {
        emit_keygen("key_establishment", algo.name, algo.security_level)?;
    }

    // sign + verify, every signature algorithm
    for algo in &sig_algos {
        {
            let workers: Vec<_> = worker_sessions.iter().map(|&(session, idx)| {
                let engine = Arc::clone(&engine);
                let priv_handle = tenants[idx].sig[algo.name].priv_handle;
                let mechanism = algo.sign_mechanism;
                let message = format!("hsm-perf-bench measured sign {} — tenant {idx}", algo.name).into_bytes();
                move || -> Result<()> {
                    engine.sign_init(session, mechanism, priv_handle)?;
                    engine.sign(session, &message)?;
                    Ok(())
                }
            }).collect();
            let (total_ops, latencies_ms, duration_s) = measure::run_point(cli.duration_secs, cli.warmup_secs, workers)?;
            emit("sign", "signature", algo.name, algo.security_level, total_ops, latencies_ms, duration_s)?;
        }
        // verify — each worker signs ONE message once (setup, unmeasured)
        // then the timed loop repeatedly verifies that same signature,
        // exercising the real C_VerifyInit/C_Verify path only.
        {
            let workers: Vec<_> = worker_sessions.iter().map(|&(session, idx)| {
                let engine = Arc::clone(&engine);
                let material = &tenants[idx].sig[algo.name];
                let (priv_handle, pub_handle) = (material.priv_handle, material.pub_handle);
                let mechanism = algo.sign_mechanism;
                let message = format!("hsm-perf-bench measured verify {} — tenant {idx}", algo.name).into_bytes();
                engine.sign_init(session, mechanism, priv_handle)?;
                let signature = engine.sign(session, &message)?;
                Ok::<_, anyhow::Error>(move || -> Result<()> {
                    engine.verify_init(session, mechanism, pub_handle)?;
                    engine.verify(session, &message, &signature)?;
                    Ok(())
                })
            }).collect::<Result<Vec<_>>>()?;
            let (total_ops, latencies_ms, duration_s) = measure::run_point(cli.duration_secs, cli.warmup_secs, workers)?;
            emit("verify", "signature", algo.name, algo.security_level, total_ops, latencies_ms, duration_s)?;
        }
    }

    // derive, every key-agreement algorithm
    for algo in &kex_algos {
        let workers: Vec<_> = worker_sessions.iter().map(|&(session, idx)| {
            let engine = Arc::clone(&engine);
            let priv_handle = tenants[idx].kex[algo.name].priv_handle;
            let mut peer_point = tenants[idx].kex[algo.name].peer_point.clone();
            move || -> Result<()> {
                engine.ecdh1_derive(session, priv_handle, &mut peer_point)?;
                Ok(())
            }
        }).collect();
        let (total_ops, latencies_ms, duration_s) = measure::run_point(cli.duration_secs, cli.warmup_secs, workers)?;
        emit("derive", "key_establishment", algo.name, algo.security_level, total_ops, latencies_ms, duration_s)?;
    }

    // encapsulate + decapsulate, every KEM
    for algo in &kem_algos {
        {
            let workers: Vec<_> = worker_sessions.iter().map(|&(session, idx)| {
                let engine = Arc::clone(&engine);
                let kem_pub = tenants[idx].kem[algo.name].pub_handle;
                let mechanism = algo.kem_mechanism;
                move || -> Result<()> {
                    engine.encapsulate_key(session, mechanism, kem_pub, &mut [])?;
                    Ok(())
                }
            }).collect();
            let (total_ops, latencies_ms, duration_s) = measure::run_point(cli.duration_secs, cli.warmup_secs, workers)?;
            emit("encapsulate", "key_establishment", algo.name, algo.security_level, total_ops, latencies_ms, duration_s)?;
        }
        {
            let workers: Vec<_> = worker_sessions.iter().map(|&(session, idx)| {
                let engine = Arc::clone(&engine);
                let material = &tenants[idx].kem[algo.name];
                let kem_priv = material.priv_handle;
                let ciphertext = material.ciphertext.clone();
                let mechanism = algo.kem_mechanism;
                move || -> Result<()> {
                    engine.decapsulate_key(session, mechanism, kem_priv, &ciphertext, &mut [])?;
                    Ok(())
                }
            }).collect();
            let (total_ops, latencies_ms, duration_s) = measure::run_point(cli.duration_secs, cli.warmup_secs, workers)?;
            emit("decapsulate", "key_establishment", algo.name, algo.security_level, total_ops, latencies_ms, duration_s)?;
        }
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
