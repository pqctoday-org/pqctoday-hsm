//! I0 — softhsmrustv3 engine reproduces the OASIS KMIP 3.0 PQC interop answers
//! BYTE-EXACT, at the `native`/`crypto` level (NO KMIP, NO dispatcher).
//!
//! ── Why this exists (FOUNDATION) ────────────────────────────────────────────
//! The 1452-case OASIS KMIP 3.0 PQC interop set (2025 plugfest, kmip-interop.org)
//! carries CONCRETE deterministic (input → expected-output) pairs:
//!   * keygen — `Seed` → expected public-key (and expanded private-key) bytes
//!   * siggen — sk + Data + ContextString + `Deterministic=true` → expected sig
//!   * sigver — pk + Data + sig + ContextString → Valid/Invalid
//!   * decap  — dk + ct → expected shared secret
//!   * encap  — ek + InputKeyMaterial (coins `m`) → expected ct + ss
//!
//! A KMIP transcript can only pass if the engine reproduces these values
//! byte-for-byte. This test proves the engine does, in isolation — the ceiling
//! for the later KMIP transcript pass rate (I1+). It EXTENDS P1.2's
//! `acvp_roundtrip.rs` (which drove `softhsmrustv3::native` against generic NIST
//! ACVP vectors) to the SPECIFIC vectors THIS interop set uses, closing P1.2's
//! deferred caveats:
//!   * ML-DSA deterministic siggen byte-exact (P1.2 only did sigVer)
//!   * SLH-DSA deterministic siggen byte-exact, all 12 param sets (P1.2 deferred,
//!     suspecting a generator-specific addrnd divergence — RE-TESTED here against
//!     the interop set's `Deterministic=true` vectors)
//!   * ML-KEM encaps-with-coins (P1.2's plan flagged this as possibly needing a
//!     new engine entry point — added as `native::encapsulate_deterministic`)
//!
//! ── Vectors ─────────────────────────────────────────────────────────────────
//! `kat/pqc-interop/pqc_interop_engine_vectors.json` was extracted from the 1452
//! XML transcripts by `scripts/extract_pqc_interop_vectors.py` (strip `#` lines →
//! XML-parse → pull the Seed/Data/Deterministic/ContextString/KeyMaterial/
//! SignatureData/ValidityIndicator/InputKeyMaterial hex by KMIP tag). keygen,
//! decap, and encap are vendored in FULL (270/30/75); siggen/sigver are a
//! per-parameter-set representative subset (the large ML-DSA/SLH-DSA signatures
//! make full vendoring multi-megabyte — the extractor regenerates the complete
//! set on demand). Every reported pass count is the HONEST count actually run.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::Value;

use softhsmrustv3::constants::*;
use softhsmrustv3::crypto::{
    sign_ml_dsa_external_mu, sign_ml_dsa_external_rnd, sign_ml_dsa_internal,
    sign_slh_dsa_external_rnd, sign_slh_dsa_internal, verify_ml_dsa, verify_ml_dsa_external_mu,
    verify_ml_dsa_internal, verify_slh_dsa, verify_slh_dsa_internal,
};
use softhsmrustv3::native::{
    self, decapsulate, encapsulate_deterministic, generate_ml_dsa_keypair_from_seed,
    generate_ml_kem_keypair_from_seed, generate_slh_dsa_keypair_from_seed, get_attribute,
    register_ml_kem_private_key, register_ml_kem_public_key, session,
};

// ── Helpers ──────────────────────────────────────────────────────────────────

fn vectors() -> Value {
    // Default: the vendored representative subset (CI-runnable, no corpus).
    // Override with INTEROP_VECTORS=<path> to run the FULL regenerated 1452 set.
    let p: PathBuf = match std::env::var("INTEROP_VECTORS") {
        Ok(v) => PathBuf::from(v),
        Err(_) => Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("kat/pqc-interop/pqc_interop_engine_vectors.json"),
    };
    let bytes = std::fs::read(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()));
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("parse {}: {e}", p.display()))
}

fn hexd(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap_or_else(|e| panic!("hex decode (len {}): {e}", s.len()))
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or_else(|| panic!("missing field {k} in {v}"))
}

fn ml_dsa_ps(fam: &str) -> u32 {
    match fam {
        "ML-DSA-44" => CKP_ML_DSA_44,
        "ML-DSA-65" => CKP_ML_DSA_65,
        "ML-DSA-87" => CKP_ML_DSA_87,
        other => panic!("unknown ML-DSA family {other}"),
    }
}

fn ml_kem_ps(fam: &str) -> u32 {
    match fam {
        "ML-KEM-512" => CKP_ML_KEM_512,
        "ML-KEM-768" => CKP_ML_KEM_768,
        "ML-KEM-1024" => CKP_ML_KEM_1024,
        other => panic!("unknown ML-KEM family {other}"),
    }
}

fn slh_dsa_ps(fam: &str) -> u32 {
    match fam {
        "SLH-DSA-SHA2-128s" => CKP_SLH_DSA_SHA2_128S,
        "SLH-DSA-SHA2-128f" => CKP_SLH_DSA_SHA2_128F,
        "SLH-DSA-SHA2-192s" => CKP_SLH_DSA_SHA2_192S,
        "SLH-DSA-SHA2-192f" => CKP_SLH_DSA_SHA2_192F,
        "SLH-DSA-SHA2-256s" => CKP_SLH_DSA_SHA2_256S,
        "SLH-DSA-SHA2-256f" => CKP_SLH_DSA_SHA2_256F,
        "SLH-DSA-SHAKE-128s" => CKP_SLH_DSA_SHAKE_128S,
        "SLH-DSA-SHAKE-128f" => CKP_SLH_DSA_SHAKE_128F,
        "SLH-DSA-SHAKE-192s" => CKP_SLH_DSA_SHAKE_192S,
        "SLH-DSA-SHAKE-192f" => CKP_SLH_DSA_SHAKE_192F,
        "SLH-DSA-SHAKE-256s" => CKP_SLH_DSA_SHAKE_256S,
        "SLH-DSA-SHAKE-256f" => CKP_SLH_DSA_SHAKE_256F,
        other => panic!("unknown SLH-DSA family {other}"),
    }
}

fn is_ml_dsa(f: &str) -> bool {
    f.starts_with("ML-DSA")
}
fn is_ml_kem(f: &str) -> bool {
    f.starts_with("ML-KEM")
}
fn is_slh_dsa(f: &str) -> bool {
    f.starts_with("SLH-DSA")
}

// Engine state is process-global; serialise the whole interop suite onto one
// session so keygen/decap/encap object registration don't race each other.
fn engine_lock() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::{Mutex, OnceLock};
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().unwrap_or_else(|e| e.into_inner())
}

fn boot() -> u32 {
    let _ = session::finalize();
    session::bootstrap_default_token(0, "so-pin", "user-pin", "pqc-interop")
        .expect("bootstrap engine session")
}

/// Per-(family,category) running tally, reported at the end of each test.
#[derive(Default)]
struct Tally {
    pass: usize,
    fail: usize,
    failures: Vec<String>,
}
impl Tally {
    fn ok(&mut self) {
        self.pass += 1;
    }
    fn bad(&mut self, why: String) {
        self.fail += 1;
        if self.failures.len() < 8 {
            self.failures.push(why);
        }
    }
}

// ── keygen (270): generate_*_keypair_from_seed → expected public key bytes ────
//
// The public key (Raw KeyMaterial) is the byte-exact target readable at the
// integration boundary; PQC private-key CKA_VALUE is policy-blocked from export
// (CKA_SENSITIVE), and is proven byte-exact separately by the in-crate unit KAT
// `keygen::tests::ml_dsa_keygen_from_seed_matches_acvp_kats` / `slh_dsa_...`,
// which read the private object via the crate-internal getter. Here we assert
// the public key — the value a `Get(Raw, PublicKey)` transcript compares.
#[test]
fn keygen_from_seed_byte_exact() {
    let _g = engine_lock();
    let sess = boot();
    let doc = vectors();
    let mut by_fam: BTreeMap<String, Tally> = BTreeMap::new();
    let mut idx = 0u32;
    for v in doc["vectors"].as_array().unwrap() {
        if v["category"] != "keygen" {
            continue;
        }
        let fam = s(v, "family").to_string();
        let seed = hexd(s(v, "seed"));
        let want_pk = hexd(s(v, "pk"));
        idx += 1;
        let id = idx.to_be_bytes();
        let res = if is_ml_dsa(&fam) {
            generate_ml_dsa_keypair_from_seed(sess, ml_dsa_ps(&fam), &seed, &id, "kg")
        } else if is_ml_kem(&fam) {
            generate_ml_kem_keypair_from_seed(sess, ml_kem_ps(&fam), &seed, &id, "kg")
        } else {
            generate_slh_dsa_keypair_from_seed(sess, slh_dsa_ps(&fam), &seed, &id, "kg")
        };
        let t = by_fam.entry(fam.clone()).or_default();
        match res {
            Ok((pub_h, _prv_h)) => {
                let got = get_attribute(sess, pub_h, CKA_VALUE).unwrap_or_default();
                if got == want_pk {
                    t.ok();
                } else {
                    t.bad(format!("{}: pk mismatch ({} vs want {} bytes)", s(v, "name"), got.len(), want_pk.len()));
                }
            }
            Err(e) => t.bad(format!("{}: keygen err 0x{e:x}", s(v, "name"))),
        }
    }
    let _ = session::finalize();
    report("keygen", &by_fam);
}

// ── siggen (606): sign → expected signature, all modes byte-exact ─────────────
//
// Covers the full ACVP/OASIS matrix:
//  • interface: external / internal (Sign_internal, no framing) / external-µ;
//  • randomizer: deterministic (ML-DSA rnd←0^32, SLH-DSA addrnd←PK.seed) AND
//    hedged (the explicit <Random> value threaded through so the hedged
//    signature is byte-exactly reproducible).
// SLH-DSA's deterministic variant — the one P1.2 suspected of generator
// divergence — is confirmed byte-exact here across all 12 parameter sets.
/// Sign one siggen vector and compare to the expected signature.
/// Returns (family, Ok(()) on byte-exact, else Err(reason)).
fn siggen_one(v: &Value) -> (String, Result<(), String>) {
    let fam = s(v, "family").to_string();
    let sk = hexd(s(v, "sk"));
    let msg = hexd(s(v, "msg"));
    let ctx = hexd(s(v, "context"));
    let want = hexd(s(v, "sig"));
    let deterministic = v["deterministic"].as_bool().unwrap_or(false);
    let internal = v["internal"].as_bool().unwrap_or(false);
    let external_mu = v["external_mu"].as_bool().unwrap_or(false);
    // Signing randomizer: deterministic ⇒ none; hedged ⇒ the explicit <Random>.
    // ML-DSA wants a 32-byte rnd ([0;32] when det); SLH-DSA wants addrnd = None
    // when det, Some(bytes) when hedged.
    let random = v.get("random").and_then(Value::as_str).map(hexd);
    let res = if is_ml_dsa(&fam) {
        let mut rnd = [0u8; 32];
        if !deterministic {
            let r = random.as_ref().expect("hedged ML-DSA siggen missing <Random>");
            rnd.copy_from_slice(r);
        }
        if external_mu {
            sign_ml_dsa_external_mu(ml_dsa_ps(&fam), &sk, &msg, rnd)
        } else if internal {
            sign_ml_dsa_internal(ml_dsa_ps(&fam), &sk, &msg, &ctx, rnd)
        } else {
            sign_ml_dsa_external_rnd(ml_dsa_ps(&fam), &sk, &msg, &ctx, rnd)
        }
    } else {
        let addrnd: Option<&[u8]> = if deterministic { None } else { random.as_deref() };
        if internal {
            sign_slh_dsa_internal(slh_dsa_ps(&fam), &sk, &msg, addrnd)
        } else {
            sign_slh_dsa_external_rnd(slh_dsa_ps(&fam), &sk, &msg, &ctx, addrnd)
        }
    };
    let r = match res {
        Ok(sig) if sig == want => Ok(()),
        Ok(sig) => Err(format!("{}: sig mismatch ({} vs want {} bytes)", s(v, "name"), sig.len(), want.len())),
        Err(e) => Err(format!("{}: sign err 0x{e:x}", s(v, "name"))),
    };
    (fam, r)
}

/// Verify one sigver vector and compare to the expected ValidityIndicator.
fn sigver_one(v: &Value) -> (String, Result<(), String>) {
    let fam = s(v, "family").to_string();
    let pk = hexd(s(v, "pk"));
    let msg = hexd(s(v, "msg"));
    let ctx = hexd(s(v, "context"));
    let sig = hexd(s(v, "sig"));
    let want_valid = v["valid"].as_bool().unwrap();
    let internal = v["internal"].as_bool().unwrap_or(false);
    let external_mu = v["external_mu"].as_bool().unwrap_or(false);
    let got_valid = if is_ml_dsa(&fam) {
        if external_mu {
            verify_ml_dsa_external_mu(ml_dsa_ps(&fam), &pk, &msg, &sig).is_ok()
        } else if internal {
            verify_ml_dsa_internal(ml_dsa_ps(&fam), &pk, &msg, &sig, &ctx).is_ok()
        } else {
            verify_ml_dsa(CKM_ML_DSA, ml_dsa_ps(&fam), &pk, &msg, &sig, &ctx).is_ok()
        }
    } else if internal {
        verify_slh_dsa_internal(slh_dsa_ps(&fam), &pk, &msg, &sig).is_ok()
    } else {
        verify_slh_dsa(CKM_SLH_DSA, slh_dsa_ps(&fam), &pk, &msg, &sig, &ctx).is_ok()
    };
    let r = if got_valid == want_valid {
        Ok(())
    } else {
        Err(format!("{}: validity got={got_valid} want={want_valid}", s(v, "name")))
    };
    (fam, r)
}

/// Run a pure-crypto category (`siggen`/`sigver`) across all cores. These
/// vectors touch no global engine state, so they parallelize cleanly with
/// `thread::scope` — chunk the vectors, tally per chunk, merge. Cuts the
/// SLH-DSA-dominated wall-clock from one-core-bound to ~1/N.
fn run_parallel(cat: &str, doc: &Value, one: fn(&Value) -> (String, Result<(), String>)) {
    let vs: Vec<&Value> = doc["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|v| v["category"] == cat)
        .collect();
    let nthreads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
    let chunk = ((vs.len() + nthreads - 1) / nthreads).max(1);
    let mut by_fam: BTreeMap<String, Tally> = BTreeMap::new();
    std::thread::scope(|scope| {
        let handles: Vec<_> = vs
            .chunks(chunk)
            .map(|c| {
                scope.spawn(move || {
                    let mut local: BTreeMap<String, Tally> = BTreeMap::new();
                    for v in c {
                        let (fam, r) = one(v);
                        let t = local.entry(fam).or_default();
                        match r {
                            Ok(()) => t.ok(),
                            Err(m) => t.bad(m),
                        }
                    }
                    local
                })
            })
            .collect();
        for h in handles {
            for (fam, t) in h.join().unwrap() {
                let e = by_fam.entry(fam).or_default();
                e.pass += t.pass;
                e.fail += t.fail;
                for f in t.failures {
                    if e.failures.len() < 8 {
                        e.failures.push(f);
                    }
                }
            }
        }
    });
    report(cat, &by_fam);
}

// ── siggen (606) & sigver (471): all interface×randomizer modes byte-exact ────
#[test]
fn siggen_byte_exact() {
    run_parallel("siggen", &vectors(), siggen_one);
}

#[test]
fn sigver_matches_validity() {
    run_parallel("sigver", &vectors(), sigver_one);
}

// ── decap (30): decapsulate(dk, ct) → expected shared secret ──────────────────
#[test]
fn decap_byte_exact() {
    let _g = engine_lock();
    let sess = boot();
    let doc = vectors();
    let mut by_fam: BTreeMap<String, Tally> = BTreeMap::new();
    let mut idx = 0u32;
    for v in doc["vectors"].as_array().unwrap() {
        if v["category"] != "decap" {
            continue;
        }
        let fam = s(v, "family").to_string();
        let dk = hexd(s(v, "dk"));
        let ct = hexd(s(v, "ct"));
        let want_ss = hexd(s(v, "ss"));
        idx += 1;
        let id = format!("decap-{idx}");
        let t = by_fam.entry(fam.clone()).or_default();
        match register_ml_kem_private_key(sess, ml_kem_ps(&fam), &dk, id.as_bytes(), "decap") {
            Ok(h) => match decapsulate(sess, h, CKM_ML_KEM, &ct) {
                Ok(ss) if ss == want_ss => t.ok(),
                Ok(ss) => t.bad(format!("{}: ss mismatch ({} vs {} bytes)", s(v, "name"), ss.len(), want_ss.len())),
                Err(e) => t.bad(format!("{}: decap err 0x{e:x}", s(v, "name"))),
            },
            Err(e) => t.bad(format!("{}: register dk err 0x{e:x}", s(v, "name"))),
        }
    }
    let _ = session::finalize();
    report("decap", &by_fam);
}

// ── encap (75): encapsulate_deterministic(ek, coins) → expected ct + ss ───────
//
// The interop Encapsulate request supplies `InputKeyMaterial` = the 32-byte
// coins `m`; the randomized `native::encapsulate` cannot reproduce a fixed ct,
// so I0 added `native::encapsulate_deterministic` (FIPS 203 §7.2
// ML-KEM.Encaps_internal(ek, m)) backed by the ml-kem crate's
// `EncapsulateDeterministic`. This was the plan's flagged "possibly needs new
// engine work" category — it is now a real engine capability, not a workaround.
#[test]
fn encap_deterministic_byte_exact() {
    let _g = engine_lock();
    let sess = boot();
    let doc = vectors();
    let mut by_fam: BTreeMap<String, Tally> = BTreeMap::new();
    let mut idx = 0u32;
    for v in doc["vectors"].as_array().unwrap() {
        if v["category"] != "encap" {
            continue;
        }
        let fam = s(v, "family").to_string();
        let ek = hexd(s(v, "ek"));
        let coins = hexd(s(v, "coins"));
        let want_ct = hexd(s(v, "ct"));
        let want_ss = hexd(s(v, "ss"));
        idx += 1;
        let id = format!("encap-{idx}");
        let t = by_fam.entry(fam.clone()).or_default();
        match register_ml_kem_public_key(sess, ml_kem_ps(&fam), &ek, id.as_bytes(), "encap") {
            Ok(h) => match encapsulate_deterministic(sess, h, CKM_ML_KEM, &coins) {
                Ok((ct, ss)) if ct == want_ct && ss == want_ss => t.ok(),
                Ok((ct, ss)) => t.bad(format!(
                    "{}: ct/ss mismatch (ct {}={}, ss {}={})",
                    s(v, "name"),
                    ct.len(),
                    ct == want_ct,
                    ss.len(),
                    ss == want_ss
                )),
                Err(e) => t.bad(format!("{}: encap err 0x{e:x}", s(v, "name"))),
            },
            Err(e) => t.bad(format!("{}: register ek err 0x{e:x}", s(v, "name"))),
        }
    }
    let _ = session::finalize();
    report("encap", &by_fam);
}

/// Print the honest per-family pass/fail tally and assert zero failures.
/// A non-empty `failures` list is surfaced (capped) before the assert so a
/// real engine divergence is root-caused, never masked.
fn report(category: &str, by_fam: &BTreeMap<String, Tally>) {
    let mut total_pass = 0;
    let mut total_fail = 0;
    eprintln!("── [{category}] engine-level byte-exact ──");
    for (fam, t) in by_fam {
        total_pass += t.pass;
        total_fail += t.fail;
        eprintln!("  {fam:22} {}/{} pass", t.pass, t.pass + t.fail);
        for f in &t.failures {
            eprintln!("      FAIL: {f}");
        }
    }
    eprintln!("  [{category}] TOTAL {total_pass}/{} pass", total_pass + total_fail);
    assert!(total_pass > 0, "[{category}] ran zero vectors");
    assert_eq!(total_fail, 0, "[{category}] {total_fail} engine divergence(s) — see FAIL lines above");
}

// Touch `native` so the import is used even if a category test is filtered out.
#[allow(dead_code)]
fn _use_native() {
    let _ = native::session::finalize;
}
