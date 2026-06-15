// SPDX-License-Identifier: CC0
//
// P0-SEQUOIA-PQC-05 — §5.4 LIVE HSM SMOKE TEST.
//
// GATE for the whole bridge migration. Proves softhsmv3 accepts a cryptoki-0.12
// `Mechanism::MlDsa` C_Sign and returns a 3309-byte ML-DSA-65 signature.
//
// The bridge's HSM-backed composite signing (§4) performs a real PKCS#11
// `C_Sign` with `Mechanism::MlDsa(SignAdditionalContext::new(...))`. The spike
// proved the *wire format* (algorithm ID 30) in software; this proves the *HSM
// dispatch path* end-to-end against the actual softhsmv3 module.
//
// Usage:
//   SOFTHSM2_CONF=.../smoke-softhsm2.conf \
//   cargo run -- <module.dylib> <token-label> <user-pin>
//
// It tries, in order, the three CK_SIGN_ADDITIONAL_CONTEXT param shapes the
// plan calls out, and reports which one softhsmv3 accepts plus the signature
// length. Expected: a ~3309-byte signature for at least one variant.

use anyhow::{anyhow, bail, Context, Result};
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::dsa::{HedgeType, SignAdditionalContext};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, KeyType, MlDsaParameterSetType, ObjectHandle, ParameterSetType};
use cryptoki::session::{Session, UserType};
use cryptoki::types::AuthPin;

const ML_DSA_65_SIG_LEN: usize = 3309;

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let module = args
        .next()
        .ok_or_else(|| anyhow!("usage: smoke-mldsa <module> <token-label> <user-pin>"))?;
    let label = args.next().unwrap_or_else(|| "test".to_string());
    let pin = args.next().unwrap_or_else(|| "1234".to_string());

    println!("=== P0-SEQUOIA-PQC-05 §5.4 LIVE HSM SMOKE TEST ===");
    println!("module : {module}");
    println!("token  : {label}");
    println!("cryptoki: 0.12  (Mechanism::MlDsa -> CKM_ML_DSA = 0x1D)");

    // 1) Open + initialize the PKCS#11 context against the softhsmv3 module.
    let pkcs11 = Pkcs11::new(&module).context("Pkcs11::new (dlopen of module) failed")?;
    pkcs11
        .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .context("C_Initialize failed")?;

    // 2) Find the slot whose token has the requested label.
    let slot = find_slot(&pkcs11, &label)?;
    println!("[1] found slot {slot:?} with token label '{label}'");

    // 3) Open RW session, log in as user.
    let session = pkcs11.open_rw_session(slot).context("open_rw_session failed")?;
    session
        .login(UserType::User, Some(&AuthPin::new(pin.clone().into())))
        .context("C_Login (user) failed")?;
    println!("[2] opened RW session, logged in as user");

    // 4) Generate an ML-DSA-65 keypair in the token.
    let (_pub_handle, priv_handle) = gen_mldsa65(&session)
        .context("ML-DSA-65 key generation (CKM_ML_DSA_KEY_PAIR_GEN) failed")?;
    println!("[3] generated ML-DSA-65 keypair (priv handle {priv_handle:?})");

    // 5) The message hash to sign.  softhsmv3's ML-DSA path signs the message
    //    directly (pure mode); use a fixed test message.
    let message = b"pqctoday smoke: prove HSM CKM_ML_DSA C_Sign returns 3309 bytes";

    // Try the three param shapes the plan (§5.4) lists, in order.
    let attempts: &[(&str, Mechanism)] = &[
        (
            "Mechanism::MlDsa(SignAdditionalContext::new(Preferred, Some(&[])))  [empty ctx, 12-byte CK_SIGN_ADDITIONAL_CONTEXT]",
            Mechanism::MlDsa(SignAdditionalContext::new(HedgeType::Preferred, Some(&[]))),
        ),
        (
            "Mechanism::MlDsa(SignAdditionalContext::new(Preferred, None))       [null param, pParameter=NULL]",
            Mechanism::MlDsa(SignAdditionalContext::new(HedgeType::Preferred, None)),
        ),
        (
            "Mechanism::MlDsa(SignAdditionalContext::new(DeterministicRequired, Some(&[])))",
            Mechanism::MlDsa(SignAdditionalContext::new(
                HedgeType::DeterministicRequired,
                Some(&[]),
            )),
        ),
    ];

    let mut winner: Option<(&str, usize)> = None;
    for (desc, mech) in attempts {
        print!("[4] C_Sign attempt: {desc}\n      -> ");
        match session.sign(mech, priv_handle, message) {
            Ok(sig) => {
                println!("OK, signature length = {} bytes", sig.len());
                if winner.is_none() {
                    winner = Some((desc, sig.len()));
                }
            }
            Err(e) => {
                println!("FAILED: {e}");
            }
        }
    }

    println!("\n=== ASSERTION ===");
    match winner {
        Some((desc, len)) if len == ML_DSA_65_SIG_LEN => {
            println!("PASS: softhsmv3 returned a {len}-byte ML-DSA-65 signature.");
            println!("      Accepted param shape: {desc}");
            Ok(())
        }
        Some((desc, len)) => {
            // A signature came back but the length is unexpected. Still record it.
            println!(
                "PARTIAL: softhsmv3 signed (param shape: {desc}) but returned {len} bytes, \
                 expected {ML_DSA_65_SIG_LEN}."
            );
            bail!("unexpected signature length {len} (expected {ML_DSA_65_SIG_LEN})")
        }
        None => {
            bail!("FAIL: all C_Sign param shapes were rejected by softhsmv3");
        }
    }
}

fn find_slot(pkcs11: &Pkcs11, label: &str) -> Result<cryptoki::slot::Slot> {
    for slot in pkcs11.get_slots_with_token()? {
        if let Ok(ti) = pkcs11.get_token_info(slot) {
            if ti.label().trim() == label {
                return Ok(slot);
            }
        }
    }
    Err(anyhow!("no slot found with token label '{label}'"))
}

/// Generate an ML-DSA-65 keypair using the standard PKCS#11 v3.2 mechanism
/// `CKM_ML_DSA_KEY_PAIR_GEN` (0x1C) with `CKA_PARAMETER_SET = CKP_ML_DSA_65`.
fn gen_mldsa65(session: &Session) -> Result<(ObjectHandle, ObjectHandle)> {
    let param_set: ParameterSetType = MlDsaParameterSetType::ML_DSA_65.into();

    let pub_template = vec![
        Attribute::Token(false),
        Attribute::Verify(true),
        Attribute::KeyType(KeyType::ML_DSA),
        Attribute::ParameterSet(param_set),
        Attribute::Label(b"smoke-mldsa65-pub".to_vec()),
    ];
    let priv_template = vec![
        Attribute::Token(false),
        Attribute::Private(true),
        Attribute::Sign(true),
        Attribute::KeyType(KeyType::ML_DSA),
        Attribute::Label(b"smoke-mldsa65-priv".to_vec()),
    ];

    session
        .generate_key_pair(&Mechanism::MlDsaKeyPairGen, &pub_template, &priv_template)
        .map_err(|e| anyhow!("generate_key_pair(MlDsaKeyPairGen) failed: {e}"))
}
