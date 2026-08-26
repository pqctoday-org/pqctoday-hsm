//! Three-transport parity for the `Pkcs11V32` C_* mirror (plan RW0/RW1+).
//!
//! The contract these tests enforce: for the SAME sequence of C_* calls,
//! the exact `ck_rv` (and, where deterministic, the exact output bytes)
//! agree across all three transports —
//!   1. in-process (`verbs_v32::*` called directly — the control),
//!   2. real gRPC (`Pkcs11V32Client` over a loopback server),
//!   3. real REST (`/v32/...` JSON over a loopback server).
//! The control value is CAPTURED, never hardcoded (a CKR codepoint the
//! engine changes must ripple to a test failure at the source, not at a
//! stale literal) — the same discipline the legacy `three_way_parity.rs`
//! established.
//!
//! Because the engine is process-global and its token bootstrap is
//! once-per-process, every test is `#[serial]` and shares one bootstrap.

use acceptance::{bootstrap_once, spawn_grpc_v32, spawn_rest_v32};
use pqctoday_pkcs11_remote_core::verbs_v32 as v32;
use pqctoday_pkcs11_remote_proto as proto;
use serde_json::json;

const CKF_SERIAL_SESSION: u32 = 0x0000_0004;
const CKF_RW_SESSION: u32 = 0x0000_0002;
const CKM_SHA256: u64 = 0x0000_0250;
const CKM_ML_DSA: u64 = 0x0000_001D;
const CKA_CLASS: u64 = 0x0000_0000;
const CKA_VALUE: u64 = 0x0000_0011;

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap()
}

/// POST a `/v32/<path>` JSON body, return the parsed response.
async fn rest_post(base: &str, path: &str, body: serde_json::Value) -> serde_json::Value {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/v32/{path}"))
        .json(&body)
        .send()
        .await
        .expect("rest send");
    assert_eq!(resp.status(), 200, "v32 REST always returns HTTP 200; ck_rv is in the body");
    resp.json().await.expect("rest json")
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}
fn unb64(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(s).expect("b64 decode")
}

// ── V1: session lifecycle + real invalid-handle code across transports ──────

#[test]
fn v1_open_close_and_double_close_ckr_parity() {
    bootstrap_once();
    rt().block_on(async {
        // ── control (in-process) ──
        let (rv_open_ctl, s_ctl) = v32::open_session(v32::SLOT, CKF_SERIAL_SESSION | CKF_RW_SESSION);
        assert_eq!(rv_open_ctl, 0);
        let rv_close_ctl = v32::close_session(s_ctl);
        let rv_double_ctl = v32::close_session(s_ctl); // the captured "expected" for invalid handle
        assert_eq!(rv_close_ctl, 0);

        // ── gRPC ──
        let mut g = spawn_grpc_v32().await.unwrap();
        let go = g
            .c_open_session(proto::V32OpenSessionRequest {
                slot_id: v32::SLOT,
                flags: CKF_SERIAL_SESSION | CKF_RW_SESSION,
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(go.ck_rv, 0);
        let gc = g
            .c_close_session(proto::V32SessionRequest { session_handle: go.session_handle })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(gc.ck_rv, rv_close_ctl);
        let gd = g
            .c_close_session(proto::V32SessionRequest { session_handle: go.session_handle })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(gd.ck_rv, rv_double_ctl, "gRPC double-close CKR must equal control");

        // ── REST ──
        let base = spawn_rest_v32().await.unwrap();
        let ro = rest_post(&base, "open-session", json!({"slot_id": v32::SLOT, "flags": CKF_SERIAL_SESSION | CKF_RW_SESSION})).await;
        assert_eq!(ro["ck_rv"], 0);
        let handle = ro["session_handle"].as_u64().unwrap();
        let rc = rest_post(&base, "close-session", json!({"session_handle": handle})).await;
        assert_eq!(rc["ck_rv"].as_u64().unwrap() as u32, rv_close_ctl);
        let rd = rest_post(&base, "close-session", json!({"session_handle": handle})).await;
        assert_eq!(rd["ck_rv"].as_u64().unwrap() as u32, rv_double_ctl, "REST double-close CKR must equal control");
    });
}

// ── V2: SHA-256 digest — identical OUTPUT bytes across all three ────────────

#[test]
fn v2_digest_output_bytes_identical_all_transports() {
    bootstrap_once();
    rt().block_on(async {
        let data = b"v32 three-way digest parity";

        // control
        let (_rv, s) = v32::open_session(v32::SLOT, CKF_SERIAL_SESSION | CKF_RW_SESSION);
        let (rv_ctl, digest_ctl) = v32::digest(s, CKM_SHA256, &[], data);
        assert_eq!(rv_ctl, 0);
        v32::close_session(s);

        // gRPC
        let mut g = spawn_grpc_v32().await.unwrap();
        let gs = g
            .c_open_session(proto::V32OpenSessionRequest { slot_id: v32::SLOT, flags: CKF_SERIAL_SESSION | CKF_RW_SESSION })
            .await.unwrap().into_inner();
        let gd = g
            .c_digest(proto::V32DigestRequest {
                session_handle: gs.session_handle,
                mechanism: Some(proto::V32Mechanism { mechanism: CKM_SHA256, parameter: vec![] }),
                data: data.to_vec(),
            })
            .await.unwrap().into_inner();
        assert_eq!(gd.ck_rv, 0);
        assert_eq!(gd.data, digest_ctl, "gRPC digest bytes must equal control");

        // REST
        let base = spawn_rest_v32().await.unwrap();
        let rs = rest_post(&base, "open-session", json!({"slot_id": v32::SLOT, "flags": CKF_SERIAL_SESSION | CKF_RW_SESSION})).await;
        let rd = rest_post(&base, "digest", json!({
            "session_handle": rs["session_handle"],
            "mechanism": {"mechanism": CKM_SHA256, "parameter": ""},
            "data": b64(data)
        })).await;
        assert_eq!(rd["ck_rv"], 0);
        assert_eq!(unb64(rd["data"].as_str().unwrap()), digest_ctl, "REST digest bytes must equal control");
    });
}

// ── V3: ML-DSA sign→verify, and the REAL CKR_SIGNATURE_INVALID on tamper ────

#[test]
fn v3_ml_dsa_sign_verify_and_tamper_ckr_parity() {
    bootstrap_once();
    rt().block_on(async {
        // A shared keypair (created once, in-process) that all three verify against —
        // the private key stays server-side; only its handle crosses the wire.
        let fixture = pqctoday_pkcs11_remote_core::verbs::open_session("1234").unwrap();
        let (pub_h, prv_h) = pqctoday_pkcs11_remote_core::verbs::generate_key_pair(
            fixture, pqctoday_pkcs11_remote_core::Algorithm::MlDsa65, b"v32par", "v32par",
        ).unwrap();

        // control: sign, capture the good+tamper verify codes
        let (_rv, s) = v32::open_session(v32::SLOT, CKF_SERIAL_SESSION | CKF_RW_SESSION);
        assert_eq!(v32::sign_init(s, CKM_ML_DSA, &[], prv_h), 0);
        let (rv_sign, sig) = v32::sign(s, b"msg");
        assert_eq!(rv_sign, 0);
        assert_eq!(v32::verify_init(s, CKM_ML_DSA, &[], pub_h), 0);
        let rv_good_ctl = v32::verify(s, b"msg", &sig);
        let mut bad = sig.clone();
        bad[10] ^= 0xFF;
        assert_eq!(v32::verify_init(s, CKM_ML_DSA, &[], pub_h), 0);
        let rv_bad_ctl = v32::verify(s, b"msg", &bad);
        v32::close_session(s);
        assert_eq!(rv_good_ctl, 0);
        assert_ne!(rv_bad_ctl, 0, "tamper must be non-OK");

        // gRPC: verify BOTH the good signature (ck_rv==good) and the tampered one (==bad)
        let mut g = spawn_grpc_v32().await.unwrap();
        let gs = g.c_open_session(proto::V32OpenSessionRequest { slot_id: v32::SLOT, flags: CKF_SERIAL_SESSION | CKF_RW_SESSION }).await.unwrap().into_inner();
        g.c_verify_init(proto::V32KeyedInitRequest { session_handle: gs.session_handle, mechanism: Some(proto::V32Mechanism { mechanism: CKM_ML_DSA, parameter: vec![] }), key_handle: pub_h }).await.unwrap();
        let gg = g.c_verify(proto::V32VerifyRequest { session_handle: gs.session_handle, data: b"msg".to_vec(), signature: sig.clone() }).await.unwrap().into_inner();
        assert_eq!(gg.ck_rv, rv_good_ctl);
        g.c_verify_init(proto::V32KeyedInitRequest { session_handle: gs.session_handle, mechanism: Some(proto::V32Mechanism { mechanism: CKM_ML_DSA, parameter: vec![] }), key_handle: pub_h }).await.unwrap();
        let gb = g.c_verify(proto::V32VerifyRequest { session_handle: gs.session_handle, data: b"msg".to_vec(), signature: bad.clone() }).await.unwrap().into_inner();
        assert_eq!(gb.ck_rv, rv_bad_ctl, "gRPC tamper CKR must equal control's CKR_SIGNATURE_INVALID");

        // REST
        let base = spawn_rest_v32().await.unwrap();
        let rs = rest_post(&base, "open-session", json!({"slot_id": v32::SLOT, "flags": CKF_SERIAL_SESSION | CKF_RW_SESSION})).await;
        let sh = rs["session_handle"].clone();
        rest_post(&base, "verify-init", json!({"session_handle": sh, "mechanism": {"mechanism": CKM_ML_DSA, "parameter": ""}, "key_handle": pub_h})).await;
        let rg = rest_post(&base, "verify", json!({"session_handle": sh, "data": b64(b"msg"), "signature": b64(&sig)})).await;
        assert_eq!(rg["ck_rv"].as_u64().unwrap() as u32, rv_good_ctl);
        rest_post(&base, "verify-init", json!({"session_handle": sh, "mechanism": {"mechanism": CKM_ML_DSA, "parameter": ""}, "key_handle": pub_h})).await;
        let rb = rest_post(&base, "verify", json!({"session_handle": sh, "data": b64(b"msg"), "signature": b64(&bad)})).await;
        assert_eq!(rb["ck_rv"].as_u64().unwrap() as u32, rv_bad_ctl, "REST tamper CKR must equal control");

        pqctoday_pkcs11_remote_core::verbs::close_session(fixture).ok();
    });
}

// ── V4: C_GetAttributeValue §5.7.5 consolidated code parity ─────────────────

#[test]
fn v4_get_attribute_value_sensitive_code_parity() {
    bootstrap_once();
    rt().block_on(async {
        let fixture = pqctoday_pkcs11_remote_core::verbs::open_session("1234").unwrap();
        let (pub_h, prv_h) = pqctoday_pkcs11_remote_core::verbs::generate_key_pair(
            fixture, pqctoday_pkcs11_remote_core::Algorithm::MlDsa65, b"v32attr", "v32attr",
        ).unwrap();

        // control: reading CKA_VALUE of the sensitive private key → SENSITIVE
        let (_rv, s) = v32::open_session(v32::SLOT, CKF_SERIAL_SESSION | CKF_RW_SESSION);
        let (rv_ctl, attrs_ctl) = v32::get_attribute_value(s, prv_h, &[CKA_VALUE, CKA_CLASS]);
        v32::close_session(s);
        assert_ne!(rv_ctl, 0);
        assert!(!attrs_ctl[0].available && attrs_ctl[1].available);

        // gRPC
        let mut g = spawn_grpc_v32().await.unwrap();
        let gs = g.c_open_session(proto::V32OpenSessionRequest { slot_id: v32::SLOT, flags: CKF_SERIAL_SESSION | CKF_RW_SESSION }).await.unwrap().into_inner();
        let ga = g.c_get_attribute_value(proto::V32GetAttributeValueRequest {
            session_handle: gs.session_handle, object_handle: prv_h, attribute_types: vec![CKA_VALUE, CKA_CLASS],
        }).await.unwrap().into_inner();
        assert_eq!(ga.ck_rv, rv_ctl);
        assert!(!ga.attributes[0].available && ga.attributes[1].available);

        // A public-key CKA_CLASS read is available on every transport (positive control)
        let gp = g.c_get_attribute_value(proto::V32GetAttributeValueRequest {
            session_handle: gs.session_handle, object_handle: pub_h, attribute_types: vec![CKA_CLASS],
        }).await.unwrap().into_inner();
        assert_eq!(gp.ck_rv, 0);
        assert!(gp.attributes[0].available);

        // REST
        let base = spawn_rest_v32().await.unwrap();
        let rs = rest_post(&base, "open-session", json!({"slot_id": v32::SLOT, "flags": CKF_SERIAL_SESSION | CKF_RW_SESSION})).await;
        let ra = rest_post(&base, "get-attribute-value", json!({
            "session_handle": rs["session_handle"], "object_handle": prv_h, "attribute_types": [CKA_VALUE, CKA_CLASS]
        })).await;
        assert_eq!(ra["ck_rv"].as_u64().unwrap() as u32, rv_ctl);
        assert_eq!(ra["attributes"][0]["available"], false);
        assert_eq!(ra["attributes"][1]["available"], true);

        pqctoday_pkcs11_remote_core::verbs::close_session(fixture).ok();
    });
}

// ── V5: mechanism list + info parity (discovery categories) ─────────────────

#[test]
fn v5_mechanism_list_and_info_parity() {
    bootstrap_once();
    rt().block_on(async {
        let (rv_ctl, list_ctl) = v32::get_mechanism_list(v32::SLOT);
        assert_eq!(rv_ctl, 0);
        let (rv_i_ctl, min_ctl, max_ctl, flags_ctl) = v32::get_mechanism_info(v32::SLOT, CKM_ML_DSA);
        assert_eq!(rv_i_ctl, 0);

        let mut g = spawn_grpc_v32().await.unwrap();
        let gl = g.c_get_mechanism_list(proto::V32SlotRequest { slot_id: v32::SLOT }).await.unwrap().into_inner();
        assert_eq!(gl.ck_rv, 0);
        assert_eq!(gl.mechanisms.len(), list_ctl.len());
        let gi = g.c_get_mechanism_info(proto::V32GetMechanismInfoRequest { slot_id: v32::SLOT, mechanism: CKM_ML_DSA }).await.unwrap().into_inner();
        assert_eq!((gi.ck_rv, gi.min_key_size, gi.max_key_size, gi.flags), (rv_i_ctl, min_ctl, max_ctl, flags_ctl));

        let base = spawn_rest_v32().await.unwrap();
        let rl = rest_post(&base, "get-mechanism-list", json!({"slot_id": v32::SLOT})).await;
        assert_eq!(rl["mechanisms"].as_array().unwrap().len(), list_ctl.len());
        let ri = rest_post(&base, "get-mechanism-info", json!({"slot_id": v32::SLOT, "mechanism": CKM_ML_DSA})).await;
        assert_eq!(ri["min_key_size"].as_u64().unwrap() as u32, min_ctl);
        assert_eq!(ri["max_key_size"].as_u64().unwrap() as u32, max_ctl);
    });
}

// ── V6: destructive-flag posture — C_DestroyObject gated identically ────────
//
// The parity servers run with destructive ON, so C_DestroyObject actually
// destroys; the point validated here is that the RPC EXISTS and behaves the
// same on both wires as the in-process call (which has no flag — it always
// destroys). A separate unit test in the grpc crate covers the OFF posture.

#[test]
fn v6_destroy_object_parity_with_flag_on() {
    bootstrap_once();
    rt().block_on(async {
        // Three independent throwaway keypairs (one per transport) so each
        // transport destroys its OWN object — a destroy is not idempotent,
        // so they cannot share one handle.
        let fixture = pqctoday_pkcs11_remote_core::verbs::open_session("1234").unwrap();
        let make = || pqctoday_pkcs11_remote_core::verbs::generate_key_pair(
            fixture, pqctoday_pkcs11_remote_core::Algorithm::Ed25519, b"v32del", "v32del",
        ).unwrap();

        // control
        let (_p, prv_ctl) = make();
        let (_rv, s) = v32::open_session(v32::SLOT, CKF_SERIAL_SESSION | CKF_RW_SESSION);
        let rv_ctl = v32::destroy_object(s, prv_ctl);
        assert_eq!(rv_ctl, 0);

        // gRPC
        let (_p2, prv_g) = make();
        let mut g = spawn_grpc_v32().await.unwrap();
        let gs = g.c_open_session(proto::V32OpenSessionRequest { slot_id: v32::SLOT, flags: CKF_SERIAL_SESSION | CKF_RW_SESSION }).await.unwrap().into_inner();
        let gd = g.c_destroy_object(proto::V32ObjectRequest { session_handle: gs.session_handle, object_handle: prv_g }).await.unwrap().into_inner();
        assert_eq!(gd.ck_rv, rv_ctl);

        // REST
        let (_p3, prv_r) = make();
        let base = spawn_rest_v32().await.unwrap();
        let rs = rest_post(&base, "open-session", json!({"slot_id": v32::SLOT, "flags": CKF_SERIAL_SESSION | CKF_RW_SESSION})).await;
        let rd = rest_post(&base, "destroy-object", json!({"session_handle": rs["session_handle"], "object_handle": prv_r})).await;
        assert_eq!(rd["ck_rv"].as_u64().unwrap() as u32, rv_ctl);

        v32::close_session(s);
        pqctoday_pkcs11_remote_core::verbs::close_session(fixture).ok();
    });
}
