//! Behaviour ring, end to end through the engine's real entry points: with
//! `PQC_BEHAVIOUR_RING` and `SOFTHSM3_OP_LOG` both set, every `PQCEV` record
//! has a `dur=` field and exactly one 8-byte ring record next to it, and a
//! second process joining the same ring file appends after the first one's
//! records rather than over them.
//!
//! Its own integration-test file for the same reason `oplog_evidence_native.rs`
//! gives: the ring is a per-process `OnceLock`, so a second `#[test]` in a
//! shared binary would inherit an already-resolved ring. `child_writer` below
//! is the exception that proves the rule — it is run in a *fresh* process by
//! `ring_is_shared_across_processes_and_mirrors_the_evidence_log`.

use softhsmrustv3::behaviour::{self, *};
use softhsmrustv3::constants::*;
use softhsmrustv3::{native, state};

const CHILD_ENV: &str = "PQC_BEHAVIOUR_TEST_CHILD";
const CHILD_RECORDS: u64 = 25;

/// Not a test of anything on its own: when spawned with `PQC_BEHAVIOUR_TEST_CHILD`
/// set, it writes `CHILD_RECORDS` records through the global sink and exits.
#[test]
fn child_writer() {
    if std::env::var_os(CHILD_ENV).is_none() {
        return;
    }
    assert!(behaviour::enabled(), "child could not map the ring");
    for i in 0..CHILD_RECORDS {
        behaviour::emit(
            Record::new(p11_src(), OP_PKCS11_C_SIGN, ALG_NONE, RESULT_OK).size_bytes(i),
        );
    }
}

#[test]
fn ring_is_shared_across_processes_and_mirrors_the_evidence_log() {
    if std::env::var_os(CHILD_ENV).is_some() {
        return; // we are the child; only child_writer runs
    }
    let dir = std::env::temp_dir().join(format!("pqc-behaviour-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    let ring_path = dir.join("behaviour.ring");
    let log_path = dir.join("hsm-ops.log");
    // SAFETY: single-threaded, before any engine code has run.
    unsafe {
        std::env::set_var(behaviour::ENV_VAR, &ring_path);
        std::env::set_var(behaviour::SRC_ENV_VAR, "p11-remoting-grpc");
        std::env::set_var(softhsmrustv3::oplog::ENV_VAR, &log_path);
    }
    assert!(
        behaviour::enabled(),
        "ring did not open — the rest of this test would pass vacuously"
    );
    assert!(softhsmrustv3::oplog::enabled());
    assert_eq!(p11_src(), SRC_P11_REMOTING_GRPC);

    // ── The same operations oplog_evidence_native.rs drives ──────────────
    native::init().expect("engine init");
    let slot = 0u32;
    state::ensure_slot(slot);
    native::init_token(slot, "12345678", "behaviour").expect("init_token");
    let so = native::open_session_so(slot, "12345678").expect("SO session");
    native::init_pin(so, "87654321").expect("init_pin");
    native::logout(so).expect("logout SO");
    native::close_session(so).expect("close SO session");
    let sess = native::open_session(slot, "87654321").expect("user session");

    let (mldsa_pub, mldsa_priv) =
        native::generate_ml_dsa_keypair(sess, CKP_ML_DSA_65, b"b", "behaviour-mldsa65")
            .expect("ml-dsa keygen");
    let msg = b"behaviour ring end-to-end";
    let sig = native::sign_pqc(
        sess, mldsa_priv, CKM_ML_DSA, msg, b"", false, false, false, None,
    )
    .expect("sign_pqc");
    native::verify_pqc(sess, mldsa_pub, CKM_ML_DSA, msg, &sig, b"", false, false)
        .expect("verify_pqc");
    let mut bad = sig.clone();
    bad[0] ^= 0xff;
    assert_eq!(
        native::verify_pqc(sess, mldsa_pub, CKM_ML_DSA, msg, &bad, b"", false, false).unwrap_err(),
        CKR_SIGNATURE_INVALID
    );
    let (mlkem_pub, mlkem_priv) =
        native::generate_ml_kem_keypair(sess, CKP_ML_KEM_768, b"b", "behaviour-mlkem768")
            .expect("ml-kem keygen");
    let (ct, ss_enc) = native::encapsulate(sess, mlkem_pub, CKM_ML_KEM).expect("encapsulate");
    let ss_dec = native::decapsulate(sess, mlkem_priv, CKM_ML_KEM, &ct).expect("decapsulate");
    assert_eq!(ss_enc, ss_dec);
    let (ed_pub, ed_priv) =
        native::generate_ed25519_keypair(sess, b"b", "behaviour-ed25519").expect("ed25519 keygen");
    let ed_sig = native::sign(sess, ed_priv, CKM_EDDSA, msg).expect("sign");
    assert!(native::verify(sess, ed_pub, CKM_EDDSA, msg, &ed_sig).expect("verify"));

    // One auth failure, which needs no PQC_AUTH_LOG to reach the ring.
    softhsmrustv3::authlog::emit("remoting-pin", "pin-incorrect", Some("10.0.0.9:4242"));

    // ── Evidence log: every op record carries dur=, real on the op lines ──
    let log = std::fs::read_to_string(&log_path).expect("evidence log readable");
    let records: Vec<&str> = log.lines().filter(|l| l.starts_with("PQCEV ")).collect();
    assert!(!records.is_empty());
    for r in &records {
        assert!(r.contains(" dur="), "no dur= on: {r}");
    }
    let dur_of = |r: &str| -> u64 {
        r.split(" dur=")
            .nth(1)
            .and_then(|t| t.split_whitespace().next())
            .and_then(|v| v.parse().ok())
            .unwrap()
    };
    for r in records
        .iter()
        .filter(|r| r.contains("op=C_GenerateKeyPair") || r.contains("op=C_Sign "))
    {
        assert!(
            dur_of(r) > 0,
            "an operation record must carry a measured duration: {r}"
        );
    }
    for r in records
        .iter()
        .filter(|r| r.contains("op=C_SignInit") || r.contains("op=C_VerifyInit"))
    {
        assert_eq!(
            dur_of(r),
            0,
            "the native path's synthetic init record carries dur=0: {r}"
        );
    }

    // ── Ring: one record per evidence record, plus the auth record ────────
    let snap = behaviour::read_all(&ring_path).expect("ring readable");
    assert_eq!(snap.table_version, TABLE_VERSION);
    assert_eq!(snap.lost, 0);
    assert_eq!(
        snap.records.len(),
        records.len() + 1,
        "one ring record per PQCEV record (+ the auth failure)"
    );
    let p11: Vec<Record> = snap
        .records
        .iter()
        .map(|(_, r)| *r)
        .filter(|r| r.src != SRC_AUTH)
        .collect();
    assert!(
        p11.iter().all(|r| r.src == SRC_P11_REMOTING_GRPC),
        "src comes from PQC_BEHAVIOUR_SRC"
    );
    assert_eq!(p11.len(), records.len());
    // Ring op ids follow the evidence log's op names, record for record.
    for (r, line) in p11.iter().zip(records.iter()) {
        let name = line
            .split(" op=")
            .nth(1)
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap();
        assert_eq!(r.op, op_pkcs11(name), "ring op mismatch for {line}");
    }
    // Algorithms sit on the init / keygen / KEM records, as in the ffi:: shape.
    assert!(
        p11.iter()
            .any(|r| r.op == OP_PKCS11_C_SIGNINIT && r.alg == ALG_ML_DSA_65)
    );
    assert!(
        p11.iter()
            .any(|r| r.op == OP_PKCS11_C_GENERATEKEYPAIR && r.alg == ALG_ML_KEM_768)
    );
    assert!(
        p11.iter()
            .any(|r| r.op == OP_PKCS11_C_GENERATEKEYPAIR && r.alg == ALG_EDDSA)
    );
    assert!(
        p11.iter()
            .any(|r| r.op == OP_PKCS11_C_ENCAPSULATEKEY && r.alg == ALG_ML_KEM_768)
    );
    assert!(p11.iter().any(|r| r.op == OP_PKCS11_C_DECAPSULATEKEY
        && r.alg == ALG_ML_KEM_768
        && r.size == log2_bucket(1088)));
    assert!(
        p11.iter()
            .all(|r| r.op != OP_PKCS11_C_SIGN || r.alg == ALG_NONE),
        "C_Sign records carry no alg"
    );
    // The rejected signature is a caller-error class, everything else ok.
    let verifies: Vec<&Record> = p11.iter().filter(|r| r.op == OP_PKCS11_C_VERIFY).collect();
    assert_eq!(verifies.len(), 3);
    assert_eq!(
        verifies
            .iter()
            .filter(|r| r.result == RESULT_CALLER_ERROR)
            .count(),
        1
    );
    assert_eq!(verifies.iter().filter(|r| r.result == RESULT_OK).count(), 2);
    // Durations: measured on op records, absent on synthetic init records.
    assert!(
        p11.iter()
            .filter(|r| r.op == OP_PKCS11_C_SIGN)
            .all(|r| r.latency > 0)
    );
    assert!(
        p11.iter()
            .filter(|r| r.op == OP_PKCS11_C_SIGNINIT)
            .all(|r| r.latency == 0)
    );
    assert_eq!(p11[0].dt, 255, "first record from this process");
    assert!(p11[1..].iter().all(|r| r.dt < 255));
    // The auth record.
    let auth = snap
        .records
        .iter()
        .map(|(_, r)| *r)
        .find(|r| r.src == SRC_AUTH)
        .expect("auth record");
    assert_eq!(
        (auth.op, auth.result, auth.client),
        (op_auth("remoting-pin"), RESULT_AUTH_FAIL, client_bucket("10.0.0.9")),
        "peer bucketed by address, not by address:port"
    );

    // ── A second process joins the same file and appends ──────────────────
    let before = snap.head;
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "child_writer", "--nocapture"])
        .env(CHILD_ENV, "1")
        .env(behaviour::ENV_VAR, &ring_path)
        .env(behaviour::SRC_ENV_VAR, "p11-remoting-rest")
        .env_remove(softhsmrustv3::oplog::ENV_VAR)
        .status()
        .expect("spawn child");
    assert!(status.success(), "child writer failed");
    let after = behaviour::read_all(&ring_path).expect("ring readable");
    assert_eq!(
        after.head,
        before + CHILD_RECORDS,
        "child appended after the parent's records"
    );
    let child: Vec<&Record> = after
        .records
        .iter()
        .map(|(_, r)| r)
        .filter(|r| r.src == SRC_P11_REMOTING_REST)
        .collect();
    assert_eq!(child.len() as u64, CHILD_RECORDS);
    assert_eq!(
        child[0].dt, 255,
        "the child's first record has its own clock"
    );
    let sizes: Vec<u8> = child.iter().map(|r| r.size).collect();
    assert_eq!(
        sizes,
        (0..CHILD_RECORDS).map(log2_bucket).collect::<Vec<u8>>(),
        "in claim order"
    );
    // And the parent can still write after the child has been and gone.
    behaviour::emit(Record::new(
        p11_src(),
        OP_PKCS11_C_SIGNFINAL,
        ALG_NONE,
        RESULT_OK,
    ));
    assert_eq!(
        behaviour::read_all(&ring_path).unwrap().head,
        before + CHILD_RECORDS + 1
    );
}
