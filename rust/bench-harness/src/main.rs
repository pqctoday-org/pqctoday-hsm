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

mod algos;
mod pkcs11;

use anyhow::{Context, Result};
use clap::Parser;
use pkcs11::Engine;
use softhsmrustv3::ck_abi::{CK_OBJECT_HANDLE, CK_SLOT_ID};
use softhsmrustv3::constants::{CKR_KEY_HANDLE_INVALID, CKR_OBJECT_HANDLE_INVALID};

#[derive(Parser, Debug)]
#[command(name = "bench-harness", about = "hsm-perf-bench PKCS#11-direct measurement harness")]
struct Cli {
    /// Path to the compiled softhsmrustv3 shared library.
    #[arg(long, default_value = "../target/release/libsofthsmrustv3.dylib")]
    library: String,
}

/// One tenant's bootstrapped token + a real Ed25519 key pair on it,
/// signed and verified once as a per-tenant sanity check.
struct Tenant {
    slot: CK_SLOT_ID,
    session: softhsmrustv3::ck_abi::CK_SESSION_HANDLE,
    pub_handle: CK_OBJECT_HANDLE,
    priv_handle: CK_OBJECT_HANDLE,
}

/// Claim the next free slot (standard §5.4 `C_GetSlotList` auto-replenish
/// — see `pkcs11.rs::get_slot_list`'s doc comment) and bring up a real
/// token + Ed25519 key pair on it, per-tenant PINs so each tenant's token
/// stays independently openable (matching the KMIP server's own
/// per-tenant-PIN tenancy model).
fn provision_tenant(engine: &Engine, name: &str) -> Result<Tenant> {
    let slots_before = engine.get_slot_list().context("C_GetSlotList")?;
    let slot = *slots_before
        .last()
        .expect("engine always reports at least one slot (§5.4 auto-replenish)");

    let session = engine
        .bootstrap_token(slot, &format!("so-pin-{name}"), &format!("user-pin-{name}"), &format!("bench-{name}"))
        .with_context(|| format!("bootstrap_token(slot={slot}, tenant={name})"))?;

    let algo = algos::ED25519;
    let (pub_handle, priv_handle) = engine
        .generate_key_pair(session, algo.keygen_mechanism, &mut [], &mut [])
        .with_context(|| format!("C_GenerateKeyPair(tenant={name})"))?;

    // Per-tenant sanity: this tenant's own key round-trips correctly.
    let message = format!("hsm-perf-bench harness proof — tenant {name}").into_bytes();
    engine.sign_init(session, algo.sign_mechanism, priv_handle).context("C_SignInit")?;
    let signature = engine.sign(session, &message).context("C_Sign")?;
    engine.verify_init(session, algo.sign_mechanism, pub_handle).context("C_VerifyInit")?;
    let valid = engine.verify(session, &message, &signature).context("C_Verify")?;
    assert!(valid, "tenant {name}'s own signature must verify");

    Ok(Tenant { slot, session, pub_handle, priv_handle })
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let engine = Engine::load(&cli.library).with_context(|| format!("loading engine library at {:?}", cli.library))?;
    engine.initialize().context("C_Initialize")?;
    eprintln!("[ok] engine initialized: {}", cli.library);

    // ── Two tenants, two real tokens, real Ed25519 keys, standard PKCS#11
    // v3.2 calls only. ──────────────────────────────────────────────────
    let alice = provision_tenant(&engine, "alice")?;
    eprintln!(
        "[ok] alice bootstrapped on slot {}: session={} pub={} priv={}",
        alice.slot, alice.session, alice.pub_handle, alice.priv_handle
    );
    let bob = provision_tenant(&engine, "bob")?;
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

    engine.close_session(alice.session).context("C_CloseSession (alice)")?;
    engine.close_session(bob.session).context("C_CloseSession (bob)")?;
    engine.finalize().context("C_Finalize")?;
    eprintln!("[ok] mechanism + isolation proof complete — engine finalized cleanly");

    Ok(())
}
