//! I0 — OASIS KMIP 3.0 PQC interop set: engine ground-truth KAT proof.
//!
//! Goal: prove the softhsmrustv3 engine's *deterministic* crypto reproduces
//! the answers embedded in the official OASIS 1452-case PQC interop
//! transcripts **byte-for-byte**, BEFORE any KMIP server replay. This is the
//! foundation of the interop plan (`docs/PQC_INTEROP_TEST_PLAN.md`, I0): the
//! KMIP layer can only match a transcript if the engine underneath it
//! produces the exact bytes the transcript expects.
//!
//! The headline risk this resolves: the interop `siggen` transcripts carry
//! `<Deterministic value="true"/>` + a `<ContextString>` + an expected
//! `<SignatureData>`, i.e. they demand **byte-exact deterministic
//! signatures**. The prior ACVP author (see `acvp_roundtrip.rs`
//! `slh_dsa_sigver_and_siggen`) doubted SLH-DSA deterministic signing would
//! byte-match a published fixture (FIPS 205 §9.2 addrnd wiring). This test
//! settles that empirically against the real OASIS transcripts.
//!
//! Source transcripts (1452 XML files) are not checked in; point the test at
//! them with `INTEROP_KAT_DIR=/path/to/kmip-3-0-pqc-tests`. The test SKIPS
//! (passes, with an eprintln) when the dir is absent, so CI without the
//! corpus is unaffected. The full per-file harness lands in a later phase
//! (I1–I6); this is the de-risking proof on a representative spread.

use std::path::PathBuf;

use softhsmrustv3::constants::*;
use softhsmrustv3::crypto::{sign_ml_dsa, sign_slh_dsa, verify_ml_dsa, verify_slh_dsa};
use softhsmrustv3::native::{decapsulate, register_ml_kem_private_key, session};

// ── transcript location ────────────────────────────────────────────────────

fn interop_dir() -> Option<PathBuf> {
    let p = PathBuf::from(
        std::env::var("INTEROP_KAT_DIR")
            .unwrap_or_else(|_| "/tmp/kmip-pqc/kmip-3-0-pqc-tests".to_string()),
    );
    p.is_dir().then_some(p)
}

// ── minimal OASIS-XML field extraction ─────────────────────────────────────

/// All `value="…"` strings for `<{tag} …>` elements, in document order.
/// Handles empty values (`value=""`). Ignores `#`-prefixed annotation lines.
fn ordered_values(xml: &str, tag: &str) -> Vec<String> {
    let body: String = xml
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    let needle = format!("<{tag} ");
    let mut out = Vec::new();
    let mut rest = body.as_str();
    while let Some(p) = rest.find(&needle) {
        rest = &rest[p + needle.len()..];
        let Some(gt) = rest.find('>') else { break };
        let elem = &rest[..gt];
        if let Some(vp) = elem.find("value=\"") {
            let after = &elem[vp + 7..];
            if let Some(end) = after.find('"') {
                out.push(after[..end].to_string());
            }
        }
        rest = &rest[gt..];
    }
    out
}

fn hexd(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap_or_else(|e| panic!("hex decode ({}…): {e}", &s[..s.len().min(24)]))
}

/// The `<KeyMaterial type="ByteString">` whose decoded length equals
/// `want_len` — i.e. the private (sk) or public (pk) half by size.
fn key_material_of_len(xml: &str, want_len: usize) -> Option<Vec<u8>> {
    ordered_values(xml, "KeyMaterial")
        .into_iter()
        .map(|h| hexd(&h))
        .find(|b| b.len() == want_len)
}

/// Read the lowest-indexed transcript for `{stem}-{op}-{N}-30.xml`. The OASIS
/// set numbers files with a GLOBAL running index (e.g. ML-DSA-65 siggen
/// starts at 121, not 1), so we glob rather than assume `-1-`.
fn read_first(dir: &PathBuf, stem: &str, op: &str) -> Option<(String, String)> {
    let prefix = format!("{stem}-{op}-");
    let mut best: Option<(u64, String)> = None;
    for entry in std::fs::read_dir(dir).ok()? {
        let name = entry.ok()?.file_name().to_string_lossy().into_owned();
        if let Some(rest) = name.strip_prefix(&prefix) {
            // rest = "{N}-30.xml" — parse the leading integer.
            let n: u64 = rest.split('-').next()?.parse().ok()?;
            if best.as_ref().map(|(b, _)| n < *b).unwrap_or(true) {
                best = Some((n, name));
            }
        }
    }
    let (_, name) = best?;
    let body = std::fs::read_to_string(dir.join(&name)).ok()?;
    Some((name, body))
}

// ── parameter-set table (name → ps enum, sk len, pk len, sign mech) ─────────

struct Alg {
    file_stem: &'static str, // "<stem>-1-30.xml"
    ps: u32,
    sk_len: usize,
    pk_len: usize,
    mech: u32,
}

fn ml_dsa_algs() -> Vec<Alg> {
    vec![
        Alg { file_stem: "ML-DSA-44", ps: CKP_ML_DSA_44, sk_len: 2560, pk_len: 1312, mech: CKM_ML_DSA },
        Alg { file_stem: "ML-DSA-65", ps: CKP_ML_DSA_65, sk_len: 4032, pk_len: 1952, mech: CKM_ML_DSA },
        Alg { file_stem: "ML-DSA-87", ps: CKP_ML_DSA_87, sk_len: 4896, pk_len: 2592, mech: CKM_ML_DSA },
    ]
}

fn slh_dsa_algs() -> Vec<Alg> {
    // sk = 4n, pk = 2n  (n = 16/24/32 for 128/192/256). A representative
    // spread across SHA2/SHAKE and the f/s tradeoff.
    vec![
        Alg { file_stem: "SLH-DSA-SHA2-128f", ps: CKP_SLH_DSA_SHA2_128F, sk_len: 64, pk_len: 32, mech: CKM_SLH_DSA },
        Alg { file_stem: "SLH-DSA-SHAKE-128s", ps: CKP_SLH_DSA_SHAKE_128S, sk_len: 64, pk_len: 32, mech: CKM_SLH_DSA },
        Alg { file_stem: "SLH-DSA-SHA2-192f", ps: CKP_SLH_DSA_SHA2_192F, sk_len: 96, pk_len: 48, mech: CKM_SLH_DSA },
    ]
}

// ── the proof: deterministic siggen byte-exact vs the transcript ────────────

/// Pull (sk, ctx, msg, expected_sig) from a `-siggen-1-30.xml` transcript.
fn siggen_vector(xml: &str, sk_len: usize) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> {
    let sk = key_material_of_len(xml, sk_len)?;
    // ContextString may be absent or empty.
    let ctx = ordered_values(xml, "ContextString")
        .into_iter()
        .next()
        .map(|h| hexd(&h))
        .unwrap_or_default();
    // <Data> = the message; <SignatureData> = the expected signature.
    let msg = hexd(&ordered_values(xml, "Data").into_iter().next()?);
    let sig = hexd(&ordered_values(xml, "SignatureData").into_iter().next()?);
    Some((sk, ctx, msg, sig))
}

#[test]
fn ml_dsa_siggen_byte_exact() {
    let Some(dir) = interop_dir() else {
        eprintln!("[I0] INTEROP_KAT_DIR absent — skipping ML-DSA siggen proof");
        return;
    };
    let mut n = 0;
    for a in ml_dsa_algs() {
        let Some((name, xml)) = read_first(&dir, a.file_stem, "siggen") else { continue };
        let Some((sk, ctx, msg, want)) = siggen_vector(&xml, a.sk_len) else {
            panic!("{name}: could not extract siggen vector");
        };
        let det = ordered_values(&xml, "Deterministic")
            .iter()
            .any(|v| v.eq_ignore_ascii_case("true"));
        assert!(det, "{name}: expected Deterministic=true");
        let got = sign_ml_dsa(a.mech, a.ps, &sk, &msg, &ctx, true)
            .unwrap_or_else(|e| panic!("{name}: sign_ml_dsa failed CK_RV=0x{e:x}"));
        assert_eq!(got, want, "{name}: ML-DSA deterministic signature NOT byte-exact");
        eprintln!("[I0] {name}: ML-DSA deterministic siggen byte-exact ({} B sig, {} B ctx)",
            want.len(), ctx.len());
        n += 1;
    }
    assert_eq!(n, 3, "expected all 3 ML-DSA param sets covered in {dir:?}");
}

#[test]
fn slh_dsa_siggen_byte_exact() {
    let Some(dir) = interop_dir() else {
        eprintln!("[I0] INTEROP_KAT_DIR absent — skipping SLH-DSA siggen proof");
        return;
    };
    let mut n = 0;
    for a in slh_dsa_algs() {
        let Some((name, xml)) = read_first(&dir, a.file_stem, "siggen") else { continue };
        let Some((sk, ctx, msg, want)) = siggen_vector(&xml, a.sk_len) else {
            panic!("{name}: could not extract siggen vector");
        };
        let got = sign_slh_dsa(a.mech, a.ps, &sk, &msg, &ctx, true)
            .unwrap_or_else(|e| panic!("{name}: sign_slh_dsa failed CK_RV=0x{e:x}"));
        // This is the assertion the prior author doubted. If it holds, the
        // engine's FIPS 205 §9.2 deterministic path matches the OASIS
        // reference implementation byte-for-byte.
        assert_eq!(got, want, "{name}: SLH-DSA deterministic signature NOT byte-exact");
        eprintln!("[I0] {name}: SLH-DSA deterministic siggen byte-exact ({} B sig)", want.len());
        n += 1;
    }
    assert_eq!(n, 3, "expected all 3 SLH-DSA stems covered in {dir:?}");
}

/// Extract (pk, ctx, msg, sig, expected_valid) from a `-sigver-` transcript.
/// `expected_valid` comes from the first `<ValidityIndicator>` (Valid /
/// Invalid) — ACVP sigver mixes genuine and deliberately-corrupted vectors,
/// so the engine's verify result must MATCH the indicator, not always pass.
fn sigver_vector(
    xml: &str,
    pk_len: usize,
) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, bool)> {
    let pk = key_material_of_len(xml, pk_len)?;
    let ctx = ordered_values(xml, "ContextString")
        .into_iter()
        .next()
        .map(|h| hexd(&h))
        .unwrap_or_default();
    let msg = hexd(&ordered_values(xml, "Data").into_iter().next()?);
    let sig = hexd(&ordered_values(xml, "SignatureData").into_iter().next()?);
    let expected_valid = ordered_values(xml, "ValidityIndicator")
        .into_iter()
        .next()
        .map(|v| v.eq_ignore_ascii_case("valid"))
        .unwrap_or(true);
    Some((pk, ctx, msg, sig, expected_valid))
}

#[test]
fn sigver_matches_validity_indicator() {
    let Some(dir) = interop_dir() else {
        eprintln!("[I0] INTEROP_KAT_DIR absent — skipping sigver proof");
        return;
    };
    let mut n = 0;
    for a in ml_dsa_algs() {
        let Some((name, xml)) = read_first(&dir, a.file_stem, "sigver") else { continue };
        let Some((pk, ctx, msg, sig, want_valid)) = sigver_vector(&xml, a.pk_len) else {
            panic!("{name}: could not extract sigver vector");
        };
        let got_valid = verify_ml_dsa(a.mech, a.ps, &pk, &msg, &sig, &ctx).is_ok();
        assert_eq!(got_valid, want_valid,
            "{name}: ML-DSA verify={got_valid} but ValidityIndicator expects valid={want_valid}");
        eprintln!("[I0] {name}: ML-DSA sigver matches ValidityIndicator (valid={want_valid})");
        n += 1;
    }
    for a in slh_dsa_algs() {
        let Some((name, xml)) = read_first(&dir, a.file_stem, "sigver") else { continue };
        let Some((pk, ctx, msg, sig, want_valid)) = sigver_vector(&xml, a.pk_len) else {
            panic!("{name}: could not extract sigver vector");
        };
        let got_valid = verify_slh_dsa(a.mech, a.ps, &pk, &msg, &sig, &ctx).is_ok();
        assert_eq!(got_valid, want_valid,
            "{name}: SLH-DSA verify={got_valid} but ValidityIndicator expects valid={want_valid}");
        eprintln!("[I0] {name}: SLH-DSA sigver matches ValidityIndicator (valid={want_valid})");
        n += 1;
    }
    assert_eq!(n, 6, "expected all 6 sigver stems covered in {dir:?}");
}

// ── ML-KEM decapsulation: dk + ct → shared secret (deterministic, no coins) ─

struct Kem {
    file_stem: &'static str,
    ps: u32,
    dk_len: usize, // FIPS 203 decapsulation key length
}

fn kem_algs() -> Vec<Kem> {
    vec![
        Kem { file_stem: "ML-KEM-512", ps: CKP_ML_KEM_512, dk_len: 1632 },
        Kem { file_stem: "ML-KEM-768", ps: CKP_ML_KEM_768, dk_len: 2400 },
        Kem { file_stem: "ML-KEM-1024", ps: CKP_ML_KEM_1024, dk_len: 3168 },
    ]
}

#[test]
fn ml_kem_decap_byte_exact() {
    let Some(dir) = interop_dir() else {
        eprintln!("[I0] INTEROP_KAT_DIR absent — skipping ML-KEM decap proof");
        return;
    };
    let _ = session::finalize();
    let sess = session::bootstrap_default_token(0, "so-pin", "user-pin", "interop-mlkem")
        .expect("bootstrap engine session");
    let mut n = 0;
    for k in kem_algs() {
        let Some((name, xml)) = read_first(&dir, k.file_stem, "decapsulation") else { continue };
        // dk = the registered private (decapsulation) key; ct = the first
        // <Data> (Decapsulate input); ss = the 32-byte shared secret the Get
        // response returns (the only 32-byte KeyMaterial in the transcript).
        let dk = key_material_of_len(&xml, k.dk_len)
            .unwrap_or_else(|| panic!("{name}: no dk of len {}", k.dk_len));
        let ct = hexd(&ordered_values(&xml, "Data").into_iter().next()
            .unwrap_or_else(|| panic!("{name}: no Data (ciphertext)")));
        let ss = key_material_of_len(&xml, 32)
            .unwrap_or_else(|| panic!("{name}: no 32-byte shared secret"));
        let handle = register_ml_kem_private_key(sess, k.ps, &dk, name.as_bytes(), "interop")
            .expect("register ml-kem dk");
        let got = decapsulate(sess, handle, CKM_ML_KEM, &ct).expect("decapsulate");
        assert_eq!(got, ss, "{name}: ML-KEM shared secret NOT byte-exact");
        eprintln!("[I0] {name}: ML-KEM decap byte-exact (32 B shared secret)");
        n += 1;
    }
    let _ = session::finalize();
    assert_eq!(n, 3, "expected all 3 ML-KEM param sets covered in {dir:?}");
}
