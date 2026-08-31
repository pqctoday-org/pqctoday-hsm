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
// RW2 additions.
const CKA_KEY_TYPE: u64 = 0x0000_0100;
const CKA_VALUE_LEN: u64 = 0x0000_0161;
const CKA_PARAMETER_SET: u64 = 0x0000_061d;
const CKA_TOKEN: u64 = 0x0000_0001;
const CKA_SIGN: u64 = 0x0000_0108;
const CKA_VERIFY: u64 = 0x0000_010a;
const CKK_AES: u64 = 0x0000_001f;
const CKK_ML_DSA: u64 = 0x0000_004a;
const CKO_PUBLIC_KEY: u64 = 0x0000_0002;
const CKO_PRIVATE_KEY: u64 = 0x0000_0003;
const CKO_SECRET_KEY: u64 = 0x0000_0004;
const CKM_ML_DSA_KEY_PAIR_GEN: u64 = 0x0000_001C;
const CKM_AES_KEY_GEN: u64 = 0x0000_1080;
const CKP_ML_DSA_65: u64 = 0x2;
// RW3 additions.
const CKA_ENCRYPT: u64 = 0x0000_0104;
const CKA_DECRYPT: u64 = 0x0000_0105;
const CKM_AES_ECB: u64 = 0x0000_1081;
// RW6a additions.
const CKF_DONT_BLOCK: u32 = 0x0000_0001;
const CKR_NO_EVENT: u32 = 0x0000_0008;
const CKR_FUNCTION_NOT_SUPPORTED: u32 = 0x0000_0054;
const CKR_FUNCTION_NOT_PARALLEL: u32 = 0x0000_0051;
const CKR_MECHANISM_INVALID: u32 = 0x0000_0070;
const CKU_USER: u32 = 1;
// RW6b additions.
const CKM_AES_GCM: u64 = 0x0000_1087;
// RW4 additions.
const CKA_DERIVE: u64 = 0x0000_010c;
const CKA_WRAP: u64 = 0x0000_0106;
const CKA_UNWRAP: u64 = 0x0000_0107;
const CKK_GENERIC_SECRET: u64 = 0x0000_0010;
const CKM_AES_KEY_WRAP: u64 = 0x0000_2109;
const CKM_CONCATENATE_BASE_AND_KEY: u64 = 0x0000_0360;
const CKM_HKDF_DERIVE_LOCAL: u64 = 0x0000_402a;
const CKR_KEY_UNEXTRACTABLE: u32 = 0x0000_006A;
// RW5 additions.
const CKK_ML_KEM: u64 = 0x0000_0049;
const CKM_ML_KEM: u64 = 0x0000_0017;
const CKM_ML_KEM_KEY_PAIR_GEN: u64 = 0x0000_000F;
const CKP_ML_KEM_768: u32 = 0x2;
const CKA_ENCAPSULATE: u64 = 0x0000_0633;
const CKA_DECAPSULATE: u64 = 0x0000_0634;
const CKM_SLH_DSA_KEY_PAIR_GEN: u64 = 0x0000_002D;
const CKM_SLH_DSA: u64 = 0x0000_002E;
const CKP_SLH_DSA_SHA2_128F: u32 = 0x03;
const CKP_SLH_DSA_SHAKE_128F: u32 = 0x04;
const CKM_XMSS_KEY_PAIR_GEN: u64 = 0x0000_4034;
const CKM_XMSS: u64 = 0x0000_4036;
const CKM_HSS_KEY_PAIR_GEN: u64 = 0x0000_4032;
const CKM_HSS: u64 = 0x0000_4033;
// G1 gap-remediation additions.
const CKM_RSA_PKCS_KEY_PAIR_GEN: u64 = 0x0000_0000;
const CKM_RSA_PKCS_OAEP: u64 = 0x0000_0009;
const CKA_MODULUS_BITS: u64 = 0x0000_0121;
const CKK_RSA: u32 = 0x0000_0000;
const CKG_MGF1_SHA256: u32 = 0x0000_0002;
// G3 mechanism-cell sweep additions.
const CKM_AES_CTR: u64 = 0x0000_1086;
const CKM_CHACHA20_KEY_GEN: u64 = 0x0000_1225;
const CKM_CHACHA20_POLY1305: u64 = 0x0000_4021;
const CKH_DETERMINISTIC_REQUIRED: u32 = 0x0000_0002;

/// A ulong-valued template entry at native `CK_ULONG` width (8 bytes LE on
/// this LP64 server) — the RW1 finding, applied on the wire's input side.
fn ulong_attr(attribute_type: u64, value: u32) -> serde_json::Value {
    json!({"attribute_type": attribute_type, "value": b64(&(value as usize).to_le_bytes())})
}
fn bool_attr(attribute_type: u64, value: bool) -> serde_json::Value {
    json!({"attribute_type": attribute_type, "value": b64(&[u8::from(value)])})
}
fn ulong_attr_proto(attribute_type: u64, value: u32) -> proto::V32AttributeIn {
    proto::V32AttributeIn { attribute_type, value: (value as usize).to_le_bytes().to_vec() }
}
fn bool_attr_proto(attribute_type: u64, value: bool) -> proto::V32AttributeIn {
    proto::V32AttributeIn { attribute_type, value: vec![u8::from(value)] }
}

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
                mechanism: Some(proto::V32Mechanism { mechanism: CKM_SHA256, parameter: vec![], structured: None }),
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
        g.c_verify_init(proto::V32KeyedInitRequest { session_handle: gs.session_handle, mechanism: Some(proto::V32Mechanism { mechanism: CKM_ML_DSA, parameter: vec![], structured: None }), key_handle: pub_h }).await.unwrap();
        let gg = g.c_verify(proto::V32VerifyRequest { session_handle: gs.session_handle, data: b"msg".to_vec(), signature: sig.clone() }).await.unwrap().into_inner();
        assert_eq!(gg.ck_rv, rv_good_ctl);
        g.c_verify_init(proto::V32KeyedInitRequest { session_handle: gs.session_handle, mechanism: Some(proto::V32Mechanism { mechanism: CKM_ML_DSA, parameter: vec![], structured: None }), key_handle: pub_h }).await.unwrap();
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

// ── V7: template-form C_GenerateKeyPair — positive round trip + the real
// §G3Keygen CKR_TEMPLATE_INCONSISTENT, three ways ──────────────────────────

#[test]
fn v7_generate_key_pair_template_parity() {
    bootstrap_once();
    rt().block_on(async {
        // control: a valid ML-DSA-65 template pair signs/verifies; a
        // mismatched-key-type private template is TEMPLATE_INCONSISTENT.
        let (_rv, s) = v32::open_session(v32::SLOT, CKF_SERIAL_SESSION | CKF_RW_SESSION);
        let good_pub = [
            (CKA_CLASS, (CKO_PUBLIC_KEY as usize).to_le_bytes().to_vec()),
            (CKA_KEY_TYPE, (CKK_ML_DSA as usize).to_le_bytes().to_vec()),
            (CKA_PARAMETER_SET, (CKP_ML_DSA_65 as usize).to_le_bytes().to_vec()),
            (CKA_VERIFY, vec![1u8]),
            (CKA_TOKEN, vec![0u8]),
        ];
        let good_prv = [
            (CKA_CLASS, (CKO_PRIVATE_KEY as usize).to_le_bytes().to_vec()),
            (CKA_KEY_TYPE, (CKK_ML_DSA as usize).to_le_bytes().to_vec()),
            (CKA_PARAMETER_SET, (CKP_ML_DSA_65 as usize).to_le_bytes().to_vec()),
            (CKA_SIGN, vec![1u8]),
            (CKA_TOKEN, vec![0u8]),
        ];
        let (rv_ctl, pub_ctl, prv_ctl) =
            v32::generate_key_pair(s, CKM_ML_DSA_KEY_PAIR_GEN, &[], &good_pub, &good_prv);
        assert_eq!(rv_ctl, 0);
        assert_ne!(pub_ctl, 0);
        assert_ne!(prv_ctl, 0);

        let bad_prv = [
            (CKA_CLASS, (CKO_PRIVATE_KEY as usize).to_le_bytes().to_vec()),
            (CKA_KEY_TYPE, (CKK_AES as usize).to_le_bytes().to_vec()),
            (CKA_PARAMETER_SET, (CKP_ML_DSA_65 as usize).to_le_bytes().to_vec()),
        ];
        let (rv_bad_ctl, _, _) =
            v32::generate_key_pair(s, CKM_ML_DSA_KEY_PAIR_GEN, &[], &good_pub, &bad_prv);
        assert_ne!(rv_bad_ctl, 0);
        v32::close_session(s);

        // gRPC
        let mut g = spawn_grpc_v32().await.unwrap();
        let gs = g.c_open_session(proto::V32OpenSessionRequest { slot_id: v32::SLOT, flags: CKF_SERIAL_SESSION | CKF_RW_SESSION }).await.unwrap().into_inner();
        let good_pub_p = vec![
            ulong_attr_proto(CKA_CLASS, CKO_PUBLIC_KEY as u32),
            ulong_attr_proto(CKA_KEY_TYPE, CKK_ML_DSA as u32),
            ulong_attr_proto(CKA_PARAMETER_SET, CKP_ML_DSA_65 as u32),
            bool_attr_proto(CKA_VERIFY, true),
            bool_attr_proto(CKA_TOKEN, false),
        ];
        let good_prv_p = vec![
            ulong_attr_proto(CKA_CLASS, CKO_PRIVATE_KEY as u32),
            ulong_attr_proto(CKA_KEY_TYPE, CKK_ML_DSA as u32),
            ulong_attr_proto(CKA_PARAMETER_SET, CKP_ML_DSA_65 as u32),
            bool_attr_proto(CKA_SIGN, true),
            bool_attr_proto(CKA_TOKEN, false),
        ];
        let gg = g.c_generate_key_pair(proto::V32GenerateKeyPairRequest {
            session_handle: gs.session_handle,
            mechanism: Some(proto::V32Mechanism { mechanism: CKM_ML_DSA_KEY_PAIR_GEN, parameter: vec![], structured: None }),
            public_key_template: good_pub_p.clone(),
            private_key_template: good_prv_p,
        }).await.unwrap().into_inner();
        assert_eq!(gg.ck_rv, rv_ctl);
        assert_ne!(gg.public_handle, 0);
        assert_ne!(gg.private_handle, 0);

        let bad_prv_p = vec![
            ulong_attr_proto(CKA_CLASS, CKO_PRIVATE_KEY as u32),
            ulong_attr_proto(CKA_KEY_TYPE, CKK_AES as u32),
            ulong_attr_proto(CKA_PARAMETER_SET, CKP_ML_DSA_65 as u32),
        ];
        let gb = g.c_generate_key_pair(proto::V32GenerateKeyPairRequest {
            session_handle: gs.session_handle,
            mechanism: Some(proto::V32Mechanism { mechanism: CKM_ML_DSA_KEY_PAIR_GEN, parameter: vec![], structured: None }),
            public_key_template: good_pub_p,
            private_key_template: bad_prv_p,
        }).await.unwrap().into_inner();
        assert_eq!(gb.ck_rv, rv_bad_ctl, "gRPC TEMPLATE_INCONSISTENT must equal control");

        // REST
        let base = spawn_rest_v32().await.unwrap();
        let rs = rest_post(&base, "open-session", json!({"slot_id": v32::SLOT, "flags": CKF_SERIAL_SESSION | CKF_RW_SESSION})).await;
        let sh = rs["session_handle"].clone();
        let good_pub_j = vec![
            ulong_attr(CKA_CLASS, CKO_PUBLIC_KEY as u32),
            ulong_attr(CKA_KEY_TYPE, CKK_ML_DSA as u32),
            ulong_attr(CKA_PARAMETER_SET, CKP_ML_DSA_65 as u32),
            bool_attr(CKA_VERIFY, true),
            bool_attr(CKA_TOKEN, false),
        ];
        let good_prv_j = vec![
            ulong_attr(CKA_CLASS, CKO_PRIVATE_KEY as u32),
            ulong_attr(CKA_KEY_TYPE, CKK_ML_DSA as u32),
            ulong_attr(CKA_PARAMETER_SET, CKP_ML_DSA_65 as u32),
            bool_attr(CKA_SIGN, true),
            bool_attr(CKA_TOKEN, false),
        ];
        let rg = rest_post(&base, "generate-key-pair", json!({
            "session_handle": sh,
            "mechanism": {"mechanism": CKM_ML_DSA_KEY_PAIR_GEN, "parameter": ""},
            "public_key_template": good_pub_j,
            "private_key_template": good_prv_j,
        })).await;
        assert_eq!(rg["ck_rv"].as_u64().unwrap() as u32, rv_ctl);
        assert_ne!(rg["public_handle"].as_u64().unwrap(), 0);
        assert_ne!(rg["private_handle"].as_u64().unwrap(), 0);

        let bad_prv_j = vec![
            ulong_attr(CKA_CLASS, CKO_PRIVATE_KEY as u32),
            ulong_attr(CKA_KEY_TYPE, CKK_AES as u32),
            ulong_attr(CKA_PARAMETER_SET, CKP_ML_DSA_65 as u32),
        ];
        let rb = rest_post(&base, "generate-key-pair", json!({
            "session_handle": sh,
            "mechanism": {"mechanism": CKM_ML_DSA_KEY_PAIR_GEN, "parameter": ""},
            "public_key_template": good_pub_j,
            "private_key_template": bad_prv_j,
        })).await;
        assert_eq!(rb["ck_rv"].as_u64().unwrap() as u32, rv_bad_ctl, "REST TEMPLATE_INCONSISTENT must equal control");
    });
}

// ── V8: C_CreateObject + the FindObjects FSM (Init/Find/Final) + C_CopyObject
// + C_GetObjectSize — one round trip per transport ──────────────────────────
//
// `max_object_count` below is intentionally large (1000, not the ~10 this
// started with): C_FindObjectsInit(CKA_CLASS=CKO_SECRET_KEY) searches the
// WHOLE TOKEN, not this test's own session, and this file's tests run in
// true parallel sharing one process-wide object store (module doc above).
// As RW3/RW4/RW6b added more secret-key-creating parity tests, a small
// count started intermittently missing this test's own just-created
// object when enough OTHER tests' secret keys existed concurrently — a
// real, load-bearing capacity assumption that broke as the suite grew,
// not a bug in find_objects itself.
#[test]
fn v8_create_find_copy_object_parity() {
    bootstrap_once();
    rt().block_on(async {
        // control
        let (_rv, s) = v32::open_session(v32::SLOT, CKF_SERIAL_SESSION | CKF_RW_SESSION);
        let tmpl_ctl: Vec<(u64, Vec<u8>)> = vec![
            (CKA_CLASS, (CKO_SECRET_KEY as usize).to_le_bytes().to_vec()),
            (CKA_KEY_TYPE, (CKK_AES as usize).to_le_bytes().to_vec()),
            (CKA_TOKEN, vec![0u8]),
            (CKA_VALUE, vec![0x11u8; 16]),
        ];
        let (rv_ctl, h_ctl) = v32::create_object(s, &tmpl_ctl);
        assert_eq!(rv_ctl, 0);
        assert_eq!(v32::find_objects_init(s, &[(CKA_CLASS, (CKO_SECRET_KEY as usize).to_le_bytes().to_vec())]), 0);
        let (rv_find_ctl, handles_ctl) = v32::find_objects(s, 1000);
        assert_eq!(rv_find_ctl, 0);
        assert!(handles_ctl.contains(&h_ctl));
        assert_eq!(v32::find_objects_final(s), 0);
        let (rv_copy_ctl, copy_h_ctl) = v32::copy_object(s, h_ctl, &[]);
        assert_eq!(rv_copy_ctl, 0);
        let (rv_size_ctl, size_ctl) = v32::get_object_size(s, copy_h_ctl);
        assert_eq!(rv_size_ctl, 0);
        assert!(size_ctl > 0);
        v32::close_session(s);

        // gRPC
        let mut g = spawn_grpc_v32().await.unwrap();
        let gs = g.c_open_session(proto::V32OpenSessionRequest { slot_id: v32::SLOT, flags: CKF_SERIAL_SESSION | CKF_RW_SESSION }).await.unwrap().into_inner();
        let gc = g.c_create_object(proto::V32CreateObjectRequest {
            session_handle: gs.session_handle,
            template: vec![
                ulong_attr_proto(CKA_CLASS, CKO_SECRET_KEY as u32),
                ulong_attr_proto(CKA_KEY_TYPE, CKK_AES as u32),
                bool_attr_proto(CKA_TOKEN, false),
                proto::V32AttributeIn { attribute_type: CKA_VALUE, value: vec![0x11u8; 16] },
            ],
        }).await.unwrap().into_inner();
        assert_eq!(gc.ck_rv, rv_ctl);
        g.c_find_objects_init(proto::V32FindObjectsInitRequest {
            session_handle: gs.session_handle,
            template: vec![ulong_attr_proto(CKA_CLASS, CKO_SECRET_KEY as u32)],
        }).await.unwrap();
        let gf = g.c_find_objects(proto::V32FindObjectsRequest { session_handle: gs.session_handle, max_object_count: 1000 }).await.unwrap().into_inner();
        assert_eq!(gf.ck_rv, rv_find_ctl);
        assert!(gf.object_handles.contains(&gc.object_handle));
        let gff = g.c_find_objects_final(proto::V32SessionRequest { session_handle: gs.session_handle }).await.unwrap().into_inner();
        assert_eq!(gff.ck_rv, 0);
        let gcp = g.c_copy_object(proto::V32CopyObjectRequest { session_handle: gs.session_handle, object_handle: gc.object_handle, template: vec![] }).await.unwrap().into_inner();
        assert_eq!(gcp.ck_rv, rv_copy_ctl);
        let gsz = g.c_get_object_size(proto::V32ObjectRequest { session_handle: gs.session_handle, object_handle: gcp.object_handle }).await.unwrap().into_inner();
        assert_eq!(gsz.ck_rv, rv_size_ctl);
        assert_eq!(gsz.size, size_ctl);

        // REST
        let base = spawn_rest_v32().await.unwrap();
        let rs = rest_post(&base, "open-session", json!({"slot_id": v32::SLOT, "flags": CKF_SERIAL_SESSION | CKF_RW_SESSION})).await;
        let sh = rs["session_handle"].clone();
        let rc = rest_post(&base, "create-object", json!({
            "session_handle": sh,
            "template": [
                ulong_attr(CKA_CLASS, CKO_SECRET_KEY as u32),
                ulong_attr(CKA_KEY_TYPE, CKK_AES as u32),
                bool_attr(CKA_TOKEN, false),
                {"attribute_type": CKA_VALUE, "value": b64(&[0x11u8; 16])},
            ],
        })).await;
        assert_eq!(rc["ck_rv"].as_u64().unwrap() as u32, rv_ctl);
        let robj = rc["object_handle"].clone();
        rest_post(&base, "find-objects-init", json!({
            "session_handle": sh,
            "template": [ulong_attr(CKA_CLASS, CKO_SECRET_KEY as u32)],
        })).await;
        let rf = rest_post(&base, "find-objects", json!({"session_handle": sh, "max_object_count": 1000})).await;
        assert_eq!(rf["ck_rv"].as_u64().unwrap() as u32, rv_find_ctl);
        let found: Vec<u64> = rf["object_handles"].as_array().unwrap().iter().map(|v| v.as_u64().unwrap()).collect();
        assert!(found.contains(&robj.as_u64().unwrap()));
        let rff = rest_post(&base, "find-objects-final", json!({"session_handle": sh})).await;
        assert_eq!(rff["ck_rv"].as_u64().unwrap() as u32, 0);
        let rcp = rest_post(&base, "copy-object", json!({"session_handle": sh, "object_handle": robj, "template": []})).await;
        assert_eq!(rcp["ck_rv"].as_u64().unwrap() as u32, rv_copy_ctl);
        let rsz = rest_post(&base, "get-object-size", json!({"session_handle": sh, "object_handle": rcp["object_handle"]})).await;
        assert_eq!(rsz["ck_rv"].as_u64().unwrap() as u32, rv_size_ctl);
        assert_eq!(rsz["size"].as_u64().unwrap() as u32, size_ctl);
    });
}

// ── V9: C_GenerateKey (AES) + C_SetAttributeValue (destructive ON here) ─────

#[test]
fn v9_generate_key_and_set_attribute_value_parity() {
    bootstrap_once();
    rt().block_on(async {
        // control
        let (_rv, s) = v32::open_session(v32::SLOT, CKF_SERIAL_SESSION | CKF_RW_SESSION);
        let tmpl_ctl: Vec<(u64, Vec<u8>)> = vec![
            (CKA_CLASS, (CKO_SECRET_KEY as usize).to_le_bytes().to_vec()),
            (CKA_KEY_TYPE, (CKK_AES as usize).to_le_bytes().to_vec()),
            (CKA_VALUE_LEN, (32usize).to_le_bytes().to_vec()),
            (CKA_TOKEN, vec![0u8]),
        ];
        let (rv_ctl, h_ctl) = v32::generate_key(s, CKM_AES_KEY_GEN, &[], &tmpl_ctl);
        assert_eq!(rv_ctl, 0);
        assert_ne!(h_ctl, 0);
        let rv_set_ctl = v32::set_attribute_value(s, h_ctl, &[]);
        assert_eq!(rv_set_ctl, 0);
        v32::close_session(s);

        // gRPC
        let mut g = spawn_grpc_v32().await.unwrap();
        let gs = g.c_open_session(proto::V32OpenSessionRequest { slot_id: v32::SLOT, flags: CKF_SERIAL_SESSION | CKF_RW_SESSION }).await.unwrap().into_inner();
        let gk = g.c_generate_key(proto::V32GenerateKeyRequest {
            session_handle: gs.session_handle,
            mechanism: Some(proto::V32Mechanism { mechanism: CKM_AES_KEY_GEN, parameter: vec![], structured: None }),
            template: vec![
                ulong_attr_proto(CKA_CLASS, CKO_SECRET_KEY as u32),
                ulong_attr_proto(CKA_KEY_TYPE, CKK_AES as u32),
                ulong_attr_proto(CKA_VALUE_LEN, 32),
                bool_attr_proto(CKA_TOKEN, false),
            ],
        }).await.unwrap().into_inner();
        assert_eq!(gk.ck_rv, rv_ctl);
        assert_ne!(gk.object_handle, 0);
        let gset = g.c_set_attribute_value(proto::V32SetAttributeValueRequest {
            session_handle: gs.session_handle, object_handle: gk.object_handle, template: vec![],
        }).await.unwrap().into_inner();
        assert_eq!(gset.ck_rv, rv_set_ctl, "gRPC set-attribute-value (destructive ON) must equal control");

        // REST
        let base = spawn_rest_v32().await.unwrap();
        let rs = rest_post(&base, "open-session", json!({"slot_id": v32::SLOT, "flags": CKF_SERIAL_SESSION | CKF_RW_SESSION})).await;
        let sh = rs["session_handle"].clone();
        let rk = rest_post(&base, "generate-key", json!({
            "session_handle": sh,
            "mechanism": {"mechanism": CKM_AES_KEY_GEN, "parameter": ""},
            "template": [
                ulong_attr(CKA_CLASS, CKO_SECRET_KEY as u32),
                ulong_attr(CKA_KEY_TYPE, CKK_AES as u32),
                ulong_attr(CKA_VALUE_LEN, 32),
                bool_attr(CKA_TOKEN, false),
            ],
        })).await;
        assert_eq!(rk["ck_rv"].as_u64().unwrap() as u32, rv_ctl);
        assert_ne!(rk["object_handle"].as_u64().unwrap(), 0);
        let rset = rest_post(&base, "set-attribute-value", json!({
            "session_handle": sh, "object_handle": rk["object_handle"], "template": [],
        })).await;
        assert_eq!(rset["ck_rv"].as_u64().unwrap() as u32, rv_set_ctl, "REST set-attribute-value (destructive ON) must equal control");
    });
}

// ── V10: AES-ECB encrypt/decrypt — a SHARED key handle (created once,
// in-process) means ciphertext bytes must be IDENTICAL across all three
// transports, exactly like V2's digest KAT ────────────────────────────────

#[test]
fn v10_aes_ecb_encrypt_decrypt_kat_parity() {
    bootstrap_once();
    rt().block_on(async {
        let plaintext = vec![0x37u8; 32];

        // Shared key, created once in-process — only its handle crosses the
        // wire. §5.8: a session object (CKA_TOKEN=false) is destroyed when
        // its creating session closes, so the fixture session must outlive
        // every transport's use of the key handle (same pattern V3/V4/V6
        // use for their shared keypair fixture).
        let (_rv, fixture) = v32::open_session(v32::SLOT, CKF_SERIAL_SESSION | CKF_RW_SESSION);
        let key_template: Vec<(u64, Vec<u8>)> = vec![
            (CKA_CLASS, (CKO_SECRET_KEY as usize).to_le_bytes().to_vec()),
            (CKA_KEY_TYPE, (CKK_AES as usize).to_le_bytes().to_vec()),
            (CKA_VALUE_LEN, (32usize).to_le_bytes().to_vec()),
            (CKA_ENCRYPT, vec![1u8]),
            (CKA_DECRYPT, vec![1u8]),
            (CKA_TOKEN, vec![0u8]),
        ];
        let (rv_key, key) = v32::generate_key(fixture, CKM_AES_KEY_GEN, &[], &key_template);
        assert_eq!(rv_key, 0);

        // control
        let (_rv, s) = v32::open_session(v32::SLOT, CKF_SERIAL_SESSION | CKF_RW_SESSION);
        assert_eq!(v32::encrypt_init(s, CKM_AES_ECB, &[], key), 0);
        let (rv_enc_ctl, ciphertext_ctl) = v32::encrypt(s, &plaintext);
        assert_eq!(rv_enc_ctl, 0);
        assert_eq!(v32::decrypt_init(s, CKM_AES_ECB, &[], key), 0);
        let (rv_dec_ctl, roundtrip_ctl) = v32::decrypt(s, &ciphertext_ctl);
        assert_eq!(rv_dec_ctl, 0);
        assert_eq!(roundtrip_ctl, plaintext);
        v32::close_session(s);

        // gRPC
        let mut g = spawn_grpc_v32().await.unwrap();
        let gs = g.c_open_session(proto::V32OpenSessionRequest { slot_id: v32::SLOT, flags: CKF_SERIAL_SESSION | CKF_RW_SESSION }).await.unwrap().into_inner();
        g.c_encrypt_init(proto::V32KeyedInitRequest {
            session_handle: gs.session_handle,
            mechanism: Some(proto::V32Mechanism { mechanism: CKM_AES_ECB, parameter: vec![], structured: None }),
            key_handle: key,
        }).await.unwrap();
        let ge = g.c_encrypt(proto::V32DataRequest { session_handle: gs.session_handle, data: plaintext.clone() }).await.unwrap().into_inner();
        assert_eq!(ge.ck_rv, rv_enc_ctl);
        assert_eq!(ge.data, ciphertext_ctl, "gRPC AES-ECB ciphertext bytes must equal control (shared key)");
        g.c_decrypt_init(proto::V32KeyedInitRequest {
            session_handle: gs.session_handle,
            mechanism: Some(proto::V32Mechanism { mechanism: CKM_AES_ECB, parameter: vec![], structured: None }),
            key_handle: key,
        }).await.unwrap();
        let gd = g.c_decrypt(proto::V32DataRequest { session_handle: gs.session_handle, data: ciphertext_ctl.clone() }).await.unwrap().into_inner();
        assert_eq!(gd.ck_rv, rv_dec_ctl);
        assert_eq!(gd.data, plaintext, "gRPC AES-ECB round trip must equal the original plaintext");

        // REST
        let base = spawn_rest_v32().await.unwrap();
        let rs = rest_post(&base, "open-session", json!({"slot_id": v32::SLOT, "flags": CKF_SERIAL_SESSION | CKF_RW_SESSION})).await;
        let sh = rs["session_handle"].clone();
        rest_post(&base, "encrypt-init", json!({
            "session_handle": sh, "mechanism": {"mechanism": CKM_AES_ECB, "parameter": ""}, "key_handle": key,
        })).await;
        let re = rest_post(&base, "encrypt", json!({"session_handle": sh, "data": b64(&plaintext)})).await;
        assert_eq!(re["ck_rv"].as_u64().unwrap() as u32, rv_enc_ctl);
        assert_eq!(unb64(re["data"].as_str().unwrap()), ciphertext_ctl, "REST AES-ECB ciphertext bytes must equal control");
        rest_post(&base, "decrypt-init", json!({
            "session_handle": sh, "mechanism": {"mechanism": CKM_AES_ECB, "parameter": ""}, "key_handle": key,
        })).await;
        let rd = rest_post(&base, "decrypt", json!({"session_handle": sh, "data": re["data"].clone()})).await;
        assert_eq!(rd["ck_rv"].as_u64().unwrap() as u32, rv_dec_ctl);
        assert_eq!(unb64(rd["data"].as_str().unwrap()), plaintext, "REST AES-ECB round trip must equal the original plaintext");

        v32::close_session(fixture);
    });
}

// ── V11: admin/info + session lifecycle (RW6a) ───────────────────────────

#[test]
fn v11_admin_info_and_session_lifecycle_parity() {
    bootstrap_once();
    rt().block_on(async {
        let (rv_info_ctl, info_ctl) = v32::get_info();
        assert_eq!(rv_info_ctl, 0);
        let (rv_slots_ctl, slots_ctl) = v32::get_slot_list(false);
        assert_eq!(rv_slots_ctl, 0);
        let (rv_slotinfo_ctl, slotinfo_ctl) = v32::get_slot_info(v32::SLOT);
        assert_eq!(rv_slotinfo_ctl, 0);
        let rv_event_ctl = v32::wait_for_slot_event(CKF_DONT_BLOCK);
        assert_eq!(rv_event_ctl, CKR_NO_EVENT);

        let (_rv, s) = v32::open_session(v32::SLOT, CKF_SERIAL_SESSION | CKF_RW_SESSION);
        let rv_cancel_ctl = v32::session_cancel(s, 0);
        assert_eq!(rv_cancel_ctl, 0);
        let rv_login_ctl = v32::login_user(s, CKU_USER, b"1234");
        v32::close_session(s);

        let mut g = spawn_grpc_v32().await.unwrap();
        let gi = g.c_get_info(proto::V32Empty {}).await.unwrap().into_inner();
        assert_eq!(gi.ck_rv, rv_info_ctl);
        assert_eq!(gi.data.len(), info_ctl.len());
        let gsl = g.c_get_slot_list(proto::V32GetSlotListRequest { token_present: false }).await.unwrap().into_inner();
        assert_eq!(gsl.ck_rv, 0);
        assert_eq!(gsl.slot_ids.len(), slots_ctl.len());
        let gsi = g.c_get_slot_info(proto::V32SlotRequest { slot_id: v32::SLOT }).await.unwrap().into_inner();
        assert_eq!(gsi.ck_rv, rv_slotinfo_ctl);
        assert_eq!(gsi.data.len(), slotinfo_ctl.len());
        let gev = g.c_wait_for_slot_event(proto::V32SlotEventRequest { flags: CKF_DONT_BLOCK }).await.unwrap().into_inner();
        assert_eq!(gev.ck_rv, rv_event_ctl);
        let gs = g.c_open_session(proto::V32OpenSessionRequest { slot_id: v32::SLOT, flags: CKF_SERIAL_SESSION | CKF_RW_SESSION }).await.unwrap().into_inner();
        let gc = g.c_session_cancel(proto::V32SessionFlagsRequest { session_handle: gs.session_handle, flags: 0 }).await.unwrap().into_inner();
        assert_eq!(gc.ck_rv, rv_cancel_ctl);
        let gl = g.c_login_user(proto::V32LoginRequest { session_handle: gs.session_handle, user_type: CKU_USER, pin: b"1234".to_vec() }).await.unwrap().into_inner();
        assert_eq!(gl.ck_rv, rv_login_ctl, "gRPC login-user CKR must equal control (already-logged-in code included)");
        g.c_close_session(proto::V32SessionRequest { session_handle: gs.session_handle }).await.unwrap();

        let base = spawn_rest_v32().await.unwrap();
        let ri = rest_post(&base, "get-info", json!({})).await;
        assert_eq!(ri["ck_rv"].as_u64().unwrap() as u32, rv_info_ctl);
        assert_eq!(unb64(ri["data"].as_str().unwrap()).len(), info_ctl.len());
        let rsl = rest_post(&base, "get-slot-list", json!({"token_present": false})).await;
        assert_eq!(rsl["slot_ids"].as_array().unwrap().len(), slots_ctl.len());
        let rsi = rest_post(&base, "get-slot-info", json!({"slot_id": v32::SLOT})).await;
        assert_eq!(rsi["ck_rv"].as_u64().unwrap() as u32, rv_slotinfo_ctl);
        let rev = rest_post(&base, "wait-for-slot-event", json!({"flags": CKF_DONT_BLOCK})).await;
        assert_eq!(rev["ck_rv"].as_u64().unwrap() as u32, rv_event_ctl);
        let rs = rest_post(&base, "open-session", json!({"slot_id": v32::SLOT, "flags": CKF_SERIAL_SESSION | CKF_RW_SESSION})).await;
        let sh = rs["session_handle"].clone();
        let rc = rest_post(&base, "session-cancel", json!({"session_handle": sh, "flags": 0})).await;
        assert_eq!(rc["ck_rv"].as_u64().unwrap() as u32, rv_cancel_ctl);
        let rl = rest_post(&base, "login-user", json!({"session_handle": sh, "user_type": CKU_USER, "pin": b64(b"1234")})).await;
        assert_eq!(rl["ck_rv"].as_u64().unwrap() as u32, rv_login_ctl, "REST login-user CKR must equal control");
        rest_post(&base, "close-session", json!({"session_handle": sh})).await;
    });
}

// ── V12: C_CloseAllSessions negative path only ──────────────────────────
//
// The positive path closes EVERY session on a slot — including this
// process's shared bootstrap "keep-alive" session (§5.6.3's login-state
// reset, `reset_login_state_if_no_sessions` / `invalidate_private_handles_
// on_slot` in ffi.rs) — which would corrupt every OTHER test's private-key
// handles if it fired on the shared SLOT while they run. Unlike the core
// crate's #[serial] unit tests, THIS suite runs its tests in true
// parallel by design (see this file's module doc), so there is no safe
// moment to invoke the real destructive path here at all — not even with
// a restore-afterward, since concurrently-running tests would already
// have observed the corrupted state. The positive path is proven safely
// in `verbs_v32::tests::admin_info_and_slot_functions_are_real`
// (core crate, `#[serial]`). This test covers what parity testing here
// CAN safely prove: the real `CKR_SLOT_ID_INVALID` on a bad slot, which
// touches no shared state.
#[test]
fn v12_close_all_sessions_invalid_slot_parity() {
    bootstrap_once();
    rt().block_on(async {
        let rv_ctl = v32::close_all_sessions(0xDEAD_BEEF);
        assert_ne!(rv_ctl, 0);

        let mut g = spawn_grpc_v32().await.unwrap();
        let gcl = g.c_close_all_sessions(proto::V32SlotRequest { slot_id: 0xDEAD_BEEF }).await.unwrap().into_inner();
        assert_eq!(gcl.ck_rv, rv_ctl);

        let base = spawn_rest_v32().await.unwrap();
        let rcl = rest_post(&base, "close-all-sessions", json!({"slot_id": 0xDEAD_BEEFu32})).await;
        assert_eq!(rcl["ck_rv"].as_u64().unwrap() as u32, rv_ctl);
    });
}

// ── V13: honest-code stubs (RW6a) — every one always the same spec code ──

#[test]
fn v13_honest_code_stubs_parity() {
    bootstrap_once();
    rt().block_on(async {
        let (_rv, s) = v32::open_session(v32::SLOT, CKF_SERIAL_SESSION | CKF_RW_SESSION);
        let codes_ctl = (
            v32::digest_key(s, 0),
            v32::get_operation_state(s),
            v32::set_operation_state(s),
            v32::get_function_status(s),
            v32::cancel_function(s),
            v32::async_complete(s),
            v32::async_get_id(s),
            v32::async_join(s, 0, &[]),
        );
        assert_eq!(codes_ctl.0, CKR_FUNCTION_NOT_SUPPORTED);
        assert_eq!(codes_ctl.3, CKR_FUNCTION_NOT_PARALLEL);
        v32::close_session(s);

        let mut g = spawn_grpc_v32().await.unwrap();
        let gs = g.c_open_session(proto::V32OpenSessionRequest { slot_id: v32::SLOT, flags: CKF_SERIAL_SESSION | CKF_RW_SESSION }).await.unwrap().into_inner();
        let sh = gs.session_handle;
        assert_eq!(g.c_digest_key(proto::V32ObjectRequest { session_handle: sh, object_handle: 0 }).await.unwrap().into_inner().ck_rv, codes_ctl.0);
        assert_eq!(g.c_get_operation_state(proto::V32SessionRequest { session_handle: sh }).await.unwrap().into_inner().ck_rv, codes_ctl.1);
        assert_eq!(g.c_set_operation_state(proto::V32SessionRequest { session_handle: sh }).await.unwrap().into_inner().ck_rv, codes_ctl.2);
        assert_eq!(g.c_get_function_status(proto::V32SessionRequest { session_handle: sh }).await.unwrap().into_inner().ck_rv, codes_ctl.3);
        assert_eq!(g.c_cancel_function(proto::V32SessionRequest { session_handle: sh }).await.unwrap().into_inner().ck_rv, codes_ctl.4);
        assert_eq!(g.c_async_complete(proto::V32SessionRequest { session_handle: sh }).await.unwrap().into_inner().ck_rv, codes_ctl.5);
        assert_eq!(g.c_async_get_id(proto::V32SessionRequest { session_handle: sh }).await.unwrap().into_inner().ck_rv, codes_ctl.6);
        assert_eq!(g.c_async_join(proto::V32AsyncJoinRequest { session_handle: sh, id: 0, data: vec![] }).await.unwrap().into_inner().ck_rv, codes_ctl.7);

        let base = spawn_rest_v32().await.unwrap();
        let rs = rest_post(&base, "open-session", json!({"slot_id": v32::SLOT, "flags": CKF_SERIAL_SESSION | CKF_RW_SESSION})).await;
        let sh = rs["session_handle"].clone();
        assert_eq!(rest_post(&base, "digest-key", json!({"session_handle": sh, "object_handle": 0})).await["ck_rv"].as_u64().unwrap() as u32, codes_ctl.0);
        assert_eq!(rest_post(&base, "get-operation-state", json!({"session_handle": sh})).await["ck_rv"].as_u64().unwrap() as u32, codes_ctl.1);
        assert_eq!(rest_post(&base, "set-operation-state", json!({"session_handle": sh})).await["ck_rv"].as_u64().unwrap() as u32, codes_ctl.2);
        assert_eq!(rest_post(&base, "get-function-status", json!({"session_handle": sh})).await["ck_rv"].as_u64().unwrap() as u32, codes_ctl.3);
        assert_eq!(rest_post(&base, "cancel-function", json!({"session_handle": sh})).await["ck_rv"].as_u64().unwrap() as u32, codes_ctl.4);
        assert_eq!(rest_post(&base, "async-complete", json!({"session_handle": sh})).await["ck_rv"].as_u64().unwrap() as u32, codes_ctl.5);
        assert_eq!(rest_post(&base, "async-get-id", json!({"session_handle": sh})).await["ck_rv"].as_u64().unwrap() as u32, codes_ctl.6);
        assert_eq!(rest_post(&base, "async-join", json!({"session_handle": sh, "id": 0, "data": b64(&[])})).await["ck_rv"].as_u64().unwrap() as u32, codes_ctl.7);
    });
}

// ── V14: verify-with-signature matches plain Verify; Sign/VerifyRecover
// reject a non-RSA mechanism with the engine's real code ────────────────

#[test]
fn v14_verify_signature_and_recover_reject_parity() {
    bootstrap_once();
    rt().block_on(async {
        let fixture = pqctoday_pkcs11_remote_core::verbs::open_session("1234").unwrap();
        let (pub_h, prv_h) = pqctoday_pkcs11_remote_core::verbs::generate_key_pair(
            fixture, pqctoday_pkcs11_remote_core::Algorithm::MlDsa65, b"v32rw6a", "v32rw6a",
        ).unwrap();

        let (_rv, s) = v32::open_session(v32::SLOT, CKF_SERIAL_SESSION | CKF_RW_SESSION);
        assert_eq!(v32::sign_init(s, CKM_ML_DSA, &[], prv_h), 0);
        let (rv, sig) = v32::sign(s, b"v14 verify-signature");
        assert_eq!(rv, 0);
        assert_eq!(v32::verify_signature_init(s, CKM_ML_DSA, &[], pub_h, &sig), 0);
        let rv_vs_ctl = v32::verify_signature(s, b"v14 verify-signature");
        assert_eq!(rv_vs_ctl, 0);
        let rv_recover_ctl = v32::sign_recover_init(s, CKM_ML_DSA, &[], prv_h);
        assert_eq!(rv_recover_ctl, CKR_MECHANISM_INVALID);
        v32::close_session(s);

        let mut g = spawn_grpc_v32().await.unwrap();
        let gs = g.c_open_session(proto::V32OpenSessionRequest { slot_id: v32::SLOT, flags: CKF_SERIAL_SESSION | CKF_RW_SESSION }).await.unwrap().into_inner();
        g.c_verify_signature_init(proto::V32VerifySignatureInitRequest {
            session_handle: gs.session_handle,
            mechanism: Some(proto::V32Mechanism { mechanism: CKM_ML_DSA, parameter: vec![], structured: None }),
            key_handle: pub_h,
            signature: sig.clone(),
        }).await.unwrap();
        let gvs = g.c_verify_signature(proto::V32DataRequest { session_handle: gs.session_handle, data: b"v14 verify-signature".to_vec() }).await.unwrap().into_inner();
        assert_eq!(gvs.ck_rv, rv_vs_ctl);
        let gr = g.c_sign_recover_init(proto::V32KeyedInitRequest {
            session_handle: gs.session_handle,
            mechanism: Some(proto::V32Mechanism { mechanism: CKM_ML_DSA, parameter: vec![], structured: None }),
            key_handle: prv_h,
        }).await.unwrap().into_inner();
        assert_eq!(gr.ck_rv, rv_recover_ctl, "gRPC Sign/VerifyRecover on a non-RSA mechanism must equal control");

        let base = spawn_rest_v32().await.unwrap();
        let rs = rest_post(&base, "open-session", json!({"slot_id": v32::SLOT, "flags": CKF_SERIAL_SESSION | CKF_RW_SESSION})).await;
        let sh = rs["session_handle"].clone();
        rest_post(&base, "verify-signature-init", json!({
            "session_handle": sh, "mechanism": {"mechanism": CKM_ML_DSA, "parameter": ""}, "key_handle": pub_h, "signature": b64(&sig),
        })).await;
        let rvs = rest_post(&base, "verify-signature", json!({"session_handle": sh, "data": b64(b"v14 verify-signature")})).await;
        assert_eq!(rvs["ck_rv"].as_u64().unwrap() as u32, rv_vs_ctl);
        let rr = rest_post(&base, "sign-recover-init", json!({
            "session_handle": sh, "mechanism": {"mechanism": CKM_ML_DSA, "parameter": ""}, "key_handle": prv_h,
        })).await;
        assert_eq!(rr["ck_rv"].as_u64().unwrap() as u32, rv_recover_ctl, "REST Sign/VerifyRecover on a non-RSA mechanism must equal control");

        pqctoday_pkcs11_remote_core::verbs::close_session(fixture).ok();
    });
}

// ── V15: dual-function quartet — C_DigestEncryptUpdate's ciphertext must
// equal running Digest and Encrypt as two separate FSMs ──────────────────

#[test]
fn v15_dual_function_digest_encrypt_parity() {
    bootstrap_once();
    rt().block_on(async {
        let (_rv, ks) = v32::open_session(v32::SLOT, CKF_SERIAL_SESSION | CKF_RW_SESSION);
        let key_template: Vec<(u64, Vec<u8>)> = vec![
            (CKA_CLASS, (CKO_SECRET_KEY as usize).to_le_bytes().to_vec()),
            (CKA_KEY_TYPE, (CKK_AES as usize).to_le_bytes().to_vec()),
            (CKA_VALUE_LEN, (32usize).to_le_bytes().to_vec()),
            (CKA_ENCRYPT, vec![1u8]),
            (CKA_TOKEN, vec![0u8]),
        ];
        let (rv_key, key) = v32::generate_key(ks, CKM_AES_KEY_GEN, &[], &key_template);
        assert_eq!(rv_key, 0);

        let part = vec![0x24u8; 16];
        assert_eq!(v32::encrypt_init(ks, CKM_AES_ECB, &[], key), 0);
        let (rv, cipher_expected) = v32::encrypt(ks, &part);
        assert_eq!(rv, 0);

        // control
        assert_eq!(v32::digest_init(ks, CKM_SHA256, &[]), 0);
        assert_eq!(v32::encrypt_init(ks, CKM_AES_ECB, &[], key), 0);
        let (rv_ctl, cipher_ctl) = v32::digest_encrypt_update(ks, &part);
        assert_eq!(rv_ctl, 0);
        assert_eq!(cipher_ctl, cipher_expected);

        // gRPC — same key handle, shared bootstrap session `ks` stays open.
        let mut g = spawn_grpc_v32().await.unwrap();
        let gs = g.c_open_session(proto::V32OpenSessionRequest { slot_id: v32::SLOT, flags: CKF_SERIAL_SESSION | CKF_RW_SESSION }).await.unwrap().into_inner();
        g.c_digest_init(proto::V32MechanismSessionRequest { session_handle: gs.session_handle, mechanism: Some(proto::V32Mechanism { mechanism: CKM_SHA256, parameter: vec![], structured: None }) }).await.unwrap();
        g.c_encrypt_init(proto::V32KeyedInitRequest { session_handle: gs.session_handle, mechanism: Some(proto::V32Mechanism { mechanism: CKM_AES_ECB, parameter: vec![], structured: None }), key_handle: key }).await.unwrap();
        let gd = g.c_digest_encrypt_update(proto::V32DataRequest { session_handle: gs.session_handle, data: part.clone() }).await.unwrap().into_inner();
        assert_eq!(gd.ck_rv, rv_ctl);
        assert_eq!(gd.data, cipher_expected, "gRPC dual-function ciphertext must equal the separate-FSM oracle");

        // REST
        let base = spawn_rest_v32().await.unwrap();
        let rs = rest_post(&base, "open-session", json!({"slot_id": v32::SLOT, "flags": CKF_SERIAL_SESSION | CKF_RW_SESSION})).await;
        let sh = rs["session_handle"].clone();
        rest_post(&base, "digest-init", json!({"session_handle": sh, "mechanism": {"mechanism": CKM_SHA256, "parameter": ""}})).await;
        rest_post(&base, "encrypt-init", json!({"session_handle": sh, "mechanism": {"mechanism": CKM_AES_ECB, "parameter": ""}, "key_handle": key})).await;
        let rd = rest_post(&base, "digest-encrypt-update", json!({"session_handle": sh, "data": b64(&part)})).await;
        assert_eq!(rd["ck_rv"].as_u64().unwrap() as u32, rv_ctl);
        assert_eq!(unb64(rd["data"].as_str().unwrap()), cipher_expected, "REST dual-function ciphertext must equal the separate-FSM oracle");

        v32::close_session(ks);
    });
}

// ── V16: message sign/verify one-shot parity — shared ML-DSA keypair ─────

#[test]
fn v16_message_sign_verify_one_shot_parity() {
    bootstrap_once();
    rt().block_on(async {
        let fixture = pqctoday_pkcs11_remote_core::verbs::open_session("1234").unwrap();
        let (pub_h, prv_h) = pqctoday_pkcs11_remote_core::verbs::generate_key_pair(
            fixture, pqctoday_pkcs11_remote_core::Algorithm::MlDsa65, b"v32msg", "v32msg",
        ).unwrap();

        let (_rv, s) = v32::open_session(v32::SLOT, CKF_SERIAL_SESSION | CKF_RW_SESSION);
        assert_eq!(v32::message_sign_init(s, CKM_ML_DSA, &[], prv_h), 0);
        let (rv, sig) = v32::sign_message(s, b"v16 message");
        assert_eq!(rv, 0);
        assert_eq!(v32::message_sign_final(s), 0);
        assert_eq!(v32::message_verify_init(s, CKM_ML_DSA, &[], pub_h), 0);
        let rv_good_ctl = v32::verify_message(s, b"v16 message", &sig);
        assert_eq!(rv_good_ctl, 0);
        assert_eq!(v32::message_verify_final(s), 0);
        let mut bad = sig.clone();
        bad[3] ^= 0xFF;
        assert_eq!(v32::message_verify_init(s, CKM_ML_DSA, &[], pub_h), 0);
        let rv_bad_ctl = v32::verify_message(s, b"v16 message", &bad);
        assert_ne!(rv_bad_ctl, 0);
        assert_eq!(v32::message_verify_final(s), 0);
        v32::close_session(s);

        let mut g = spawn_grpc_v32().await.unwrap();
        let gs = g.c_open_session(proto::V32OpenSessionRequest { slot_id: v32::SLOT, flags: CKF_SERIAL_SESSION | CKF_RW_SESSION }).await.unwrap().into_inner();
        g.c_message_sign_init(proto::V32KeyedInitRequest { session_handle: gs.session_handle, mechanism: Some(proto::V32Mechanism { mechanism: CKM_ML_DSA, parameter: vec![], structured: None }), key_handle: prv_h }).await.unwrap();
        let gsig = g.c_sign_message(proto::V32DataRequest { session_handle: gs.session_handle, data: b"v16 message".to_vec() }).await.unwrap().into_inner();
        assert_eq!(gsig.ck_rv, 0);
        g.c_message_sign_final(proto::V32SessionRequest { session_handle: gs.session_handle }).await.unwrap();
        g.c_message_verify_init(proto::V32KeyedInitRequest { session_handle: gs.session_handle, mechanism: Some(proto::V32Mechanism { mechanism: CKM_ML_DSA, parameter: vec![], structured: None }), key_handle: pub_h }).await.unwrap();
        let gg = g.c_verify_message(proto::V32VerifyRequest { session_handle: gs.session_handle, data: b"v16 message".to_vec(), signature: gsig.data.clone() }).await.unwrap().into_inner();
        assert_eq!(gg.ck_rv, rv_good_ctl);
        g.c_message_verify_final(proto::V32SessionRequest { session_handle: gs.session_handle }).await.unwrap();
        g.c_message_verify_init(proto::V32KeyedInitRequest { session_handle: gs.session_handle, mechanism: Some(proto::V32Mechanism { mechanism: CKM_ML_DSA, parameter: vec![], structured: None }), key_handle: pub_h }).await.unwrap();
        let gb = g.c_verify_message(proto::V32VerifyRequest { session_handle: gs.session_handle, data: b"v16 message".to_vec(), signature: bad.clone() }).await.unwrap().into_inner();
        assert_eq!(gb.ck_rv, rv_bad_ctl, "gRPC tamper CKR must equal control");

        let base = spawn_rest_v32().await.unwrap();
        let rs = rest_post(&base, "open-session", json!({"slot_id": v32::SLOT, "flags": CKF_SERIAL_SESSION | CKF_RW_SESSION})).await;
        let sh = rs["session_handle"].clone();
        rest_post(&base, "message-sign-init", json!({"session_handle": sh, "mechanism": {"mechanism": CKM_ML_DSA, "parameter": ""}, "key_handle": prv_h})).await;
        let rsig = rest_post(&base, "sign-message", json!({"session_handle": sh, "data": b64(b"v16 message")})).await;
        assert_eq!(rsig["ck_rv"], 0);
        rest_post(&base, "message-sign-final", json!({"session_handle": sh})).await;
        rest_post(&base, "message-verify-init", json!({"session_handle": sh, "mechanism": {"mechanism": CKM_ML_DSA, "parameter": ""}, "key_handle": pub_h})).await;
        let rg = rest_post(&base, "verify-message", json!({"session_handle": sh, "data": b64(b"v16 message"), "signature": rsig["data"]})).await;
        assert_eq!(rg["ck_rv"].as_u64().unwrap() as u32, rv_good_ctl);
        rest_post(&base, "message-verify-final", json!({"session_handle": sh})).await;
        rest_post(&base, "message-verify-init", json!({"session_handle": sh, "mechanism": {"mechanism": CKM_ML_DSA, "parameter": ""}, "key_handle": pub_h})).await;
        let rb = rest_post(&base, "verify-message", json!({"session_handle": sh, "data": b64(b"v16 message"), "signature": b64(&bad)})).await;
        assert_eq!(rb["ck_rv"].as_u64().unwrap() as u32, rv_bad_ctl, "REST tamper CKR must equal control");

        pqctoday_pkcs11_remote_core::verbs::close_session(fixture).ok();
    });
}

// ── V17: message encrypt/decrypt one-shot parity (CK_GCM_MESSAGE_PARAMS,
// RW-P's one variant) — shared AES key, KAT-grade byte equality ─────────

#[test]
fn v17_message_encrypt_decrypt_kat_parity() {
    bootstrap_once();
    rt().block_on(async {
        let (_rv, ks) = v32::open_session(v32::SLOT, CKF_SERIAL_SESSION | CKF_RW_SESSION);
        let key_template: Vec<(u64, Vec<u8>)> = vec![
            (CKA_CLASS, (CKO_SECRET_KEY as usize).to_le_bytes().to_vec()),
            (CKA_KEY_TYPE, (CKK_AES as usize).to_le_bytes().to_vec()),
            (CKA_VALUE_LEN, (32usize).to_le_bytes().to_vec()),
            (CKA_ENCRYPT, vec![1u8]),
            (CKA_DECRYPT, vec![1u8]),
            (CKA_TOKEN, vec![0u8]),
        ];
        let (rv_key, key) = v32::generate_key(ks, CKM_AES_KEY_GEN, &[], &key_template);
        assert_eq!(rv_key, 0);

        let iv = vec![0x09u8; 12];
        let aad = b"v17-aad".to_vec();
        let plaintext = b"v17 message-based AEAD parity".to_vec();

        // control
        assert_eq!(v32::message_encrypt_init(ks, CKM_AES_GCM, &[], key), 0);
        let (rv_ctl, ciphertext_ctl, tag_ctl, iv_used_ctl) = v32::encrypt_message(ks, &iv, 0, &aad, &plaintext, 128);
        assert_eq!(rv_ctl, 0);
        assert_eq!(iv_used_ctl, iv);
        assert_eq!(v32::message_encrypt_final(ks), 0);
        assert_eq!(v32::message_decrypt_init(ks, CKM_AES_GCM, &[], key), 0);
        let (rv_dec_ctl, recovered_ctl) = v32::decrypt_message(ks, &iv, &aad, &ciphertext_ctl, 128, &tag_ctl);
        assert_eq!(rv_dec_ctl, 0);
        assert_eq!(recovered_ctl, plaintext);
        assert_eq!(v32::message_decrypt_final(ks), 0);

        // gRPC — same key handle (shared bootstrap session `ks` stays open)
        let mut g = spawn_grpc_v32().await.unwrap();
        let gs = g.c_open_session(proto::V32OpenSessionRequest { slot_id: v32::SLOT, flags: CKF_SERIAL_SESSION | CKF_RW_SESSION }).await.unwrap().into_inner();
        g.c_message_encrypt_init(proto::V32KeyedInitRequest { session_handle: gs.session_handle, mechanism: Some(proto::V32Mechanism { mechanism: CKM_AES_GCM, parameter: vec![], structured: None }), key_handle: key }).await.unwrap();
        let ge = g.c_encrypt_message(proto::V32EncryptMessageRequest {
            session_handle: gs.session_handle, iv: iv.clone(), iv_generator: 0, aad: aad.clone(), plaintext: plaintext.clone(), tag_bits: 128,
        }).await.unwrap().into_inner();
        assert_eq!(ge.ck_rv, rv_ctl);
        assert_eq!(ge.ciphertext, ciphertext_ctl, "gRPC ciphertext must equal control");
        assert_eq!(ge.tag, tag_ctl, "gRPC tag must equal control");
        g.c_message_encrypt_final(proto::V32SessionRequest { session_handle: gs.session_handle }).await.unwrap();
        g.c_message_decrypt_init(proto::V32KeyedInitRequest { session_handle: gs.session_handle, mechanism: Some(proto::V32Mechanism { mechanism: CKM_AES_GCM, parameter: vec![], structured: None }), key_handle: key }).await.unwrap();
        let gd = g.c_decrypt_message(proto::V32DecryptMessageRequest {
            session_handle: gs.session_handle, iv: iv.clone(), aad: aad.clone(), ciphertext: ciphertext_ctl.clone(), tag_bits: 128, tag: tag_ctl.clone(),
        }).await.unwrap().into_inner();
        assert_eq!(gd.ck_rv, rv_dec_ctl);
        assert_eq!(gd.data, plaintext, "gRPC recovered plaintext must equal the original");
        g.c_message_decrypt_final(proto::V32SessionRequest { session_handle: gs.session_handle }).await.unwrap();

        // REST
        let base = spawn_rest_v32().await.unwrap();
        let rs = rest_post(&base, "open-session", json!({"slot_id": v32::SLOT, "flags": CKF_SERIAL_SESSION | CKF_RW_SESSION})).await;
        let sh = rs["session_handle"].clone();
        rest_post(&base, "message-encrypt-init", json!({"session_handle": sh, "mechanism": {"mechanism": CKM_AES_GCM, "parameter": ""}, "key_handle": key})).await;
        let re = rest_post(&base, "encrypt-message", json!({
            "session_handle": sh, "iv": b64(&iv), "iv_generator": 0, "aad": b64(&aad), "plaintext": b64(&plaintext), "tag_bits": 128,
        })).await;
        assert_eq!(re["ck_rv"].as_u64().unwrap() as u32, rv_ctl);
        assert_eq!(unb64(re["ciphertext"].as_str().unwrap()), ciphertext_ctl, "REST ciphertext must equal control");
        assert_eq!(unb64(re["tag"].as_str().unwrap()), tag_ctl, "REST tag must equal control");
        rest_post(&base, "message-encrypt-final", json!({"session_handle": sh})).await;
        rest_post(&base, "message-decrypt-init", json!({"session_handle": sh, "mechanism": {"mechanism": CKM_AES_GCM, "parameter": ""}, "key_handle": key})).await;
        let rd = rest_post(&base, "decrypt-message", json!({
            "session_handle": sh, "iv": b64(&iv), "aad": b64(&aad), "ciphertext": b64(&ciphertext_ctl), "tag_bits": 128, "tag": b64(&tag_ctl),
        })).await;
        assert_eq!(rd["ck_rv"].as_u64().unwrap() as u32, rv_dec_ctl);
        assert_eq!(unb64(rd["data"].as_str().unwrap()), plaintext, "REST recovered plaintext must equal the original");
        rest_post(&base, "message-decrypt-final", json!({"session_handle": sh})).await;

        v32::close_session(ks);
    });
}

// ── V18: AES-KW wrap/unwrap round trip + the real CKR_KEY_UNEXTRACTABLE
// negative — no RW-P needed, raw mechanism bytes only ────────────────────

#[test]
fn v18_aes_key_wrap_unwrap_parity() {
    bootstrap_once();
    rt().block_on(async {
        let (_rv, ks) = v32::open_session(v32::SLOT, CKF_SERIAL_SESSION | CKF_RW_SESSION);
        let wrapping_tmpl: Vec<(u64, Vec<u8>)> = vec![
            (CKA_CLASS, (CKO_SECRET_KEY as usize).to_le_bytes().to_vec()),
            (CKA_KEY_TYPE, (CKK_AES as usize).to_le_bytes().to_vec()),
            (CKA_VALUE_LEN, (32usize).to_le_bytes().to_vec()),
            (CKA_WRAP, vec![1u8]),
            (CKA_UNWRAP, vec![1u8]),
            (CKA_TOKEN, vec![0u8]),
        ];
        let (rv, wrapping_key) = v32::generate_key(ks, CKM_AES_KEY_GEN, &[], &wrapping_tmpl);
        assert_eq!(rv, 0);
        let target_tmpl: Vec<(u64, Vec<u8>)> = vec![
            (CKA_CLASS, (CKO_SECRET_KEY as usize).to_le_bytes().to_vec()),
            (CKA_KEY_TYPE, (CKK_AES as usize).to_le_bytes().to_vec()),
            (CKA_VALUE_LEN, (16usize).to_le_bytes().to_vec()),
            (0x0162 /* CKA_EXTRACTABLE */, vec![1u8]),
            (CKA_TOKEN, vec![0u8]),
        ];
        let (rv, target_key) = v32::generate_key(ks, CKM_AES_KEY_GEN, &[], &target_tmpl);
        assert_eq!(rv, 0);
        let locked_tmpl: Vec<(u64, Vec<u8>)> = vec![
            (CKA_CLASS, (CKO_SECRET_KEY as usize).to_le_bytes().to_vec()),
            (CKA_KEY_TYPE, (CKK_AES as usize).to_le_bytes().to_vec()),
            (CKA_VALUE_LEN, (16usize).to_le_bytes().to_vec()),
            (0x0162, vec![0u8]),
            (CKA_TOKEN, vec![0u8]),
        ];
        let (rv, locked_key) = v32::generate_key(ks, CKM_AES_KEY_GEN, &[], &locked_tmpl);
        assert_eq!(rv, 0);

        let unwrap_tmpl: Vec<(u64, Vec<u8>)> = vec![
            (CKA_CLASS, (CKO_SECRET_KEY as usize).to_le_bytes().to_vec()),
            (CKA_KEY_TYPE, (CKK_AES as usize).to_le_bytes().to_vec()),
            (0x0162, vec![1u8]),
            (CKA_TOKEN, vec![0u8]),
        ];

        // control
        let (rv_wrap_ctl, wrapped_ctl) = v32::wrap_key(ks, CKM_AES_KEY_WRAP, &[], wrapping_key, target_key);
        assert_eq!(rv_wrap_ctl, 0);
        let (rv_unwrap_ctl, unwrapped_ctl) = v32::unwrap_key(ks, CKM_AES_KEY_WRAP, &[], wrapping_key, &wrapped_ctl, &unwrap_tmpl);
        assert_eq!(rv_unwrap_ctl, 0);
        assert_ne!(unwrapped_ctl, 0);
        let rv_neg_ctl = v32::wrap_key(ks, CKM_AES_KEY_WRAP, &[], wrapping_key, locked_key).0;
        assert_eq!(rv_neg_ctl, CKR_KEY_UNEXTRACTABLE);

        // gRPC
        let mut g = spawn_grpc_v32().await.unwrap();
        let gs = g.c_open_session(proto::V32OpenSessionRequest { slot_id: v32::SLOT, flags: CKF_SERIAL_SESSION | CKF_RW_SESSION }).await.unwrap().into_inner();
        let gw = g.c_wrap_key(proto::V32WrapKeyRequest {
            session_handle: gs.session_handle,
            mechanism: Some(proto::V32Mechanism { mechanism: CKM_AES_KEY_WRAP, parameter: vec![], structured: None }),
            wrapping_key_handle: wrapping_key,
            key_handle: target_key,
        }).await.unwrap().into_inner();
        assert_eq!(gw.ck_rv, rv_wrap_ctl);
        assert_eq!(gw.data, wrapped_ctl, "gRPC wrapped bytes must equal control (same key material, same wrap)");
        let gu = g.c_unwrap_key(proto::V32UnwrapKeyRequest {
            session_handle: gs.session_handle,
            mechanism: Some(proto::V32Mechanism { mechanism: CKM_AES_KEY_WRAP, parameter: vec![], structured: None }),
            unwrapping_key_handle: wrapping_key,
            wrapped_key: wrapped_ctl.clone(),
            template: vec![
                ulong_attr_proto(CKA_CLASS, CKO_SECRET_KEY as u32),
                ulong_attr_proto(CKA_KEY_TYPE, CKK_AES as u32),
                bool_attr_proto(0x0162, true),
                bool_attr_proto(CKA_TOKEN, false),
            ],
        }).await.unwrap().into_inner();
        assert_eq!(gu.ck_rv, rv_unwrap_ctl);
        assert_ne!(gu.object_handle, 0);
        let gn = g.c_wrap_key(proto::V32WrapKeyRequest {
            session_handle: gs.session_handle,
            mechanism: Some(proto::V32Mechanism { mechanism: CKM_AES_KEY_WRAP, parameter: vec![], structured: None }),
            wrapping_key_handle: wrapping_key,
            key_handle: locked_key,
        }).await.unwrap().into_inner();
        assert_eq!(gn.ck_rv, rv_neg_ctl, "gRPC CKR_KEY_UNEXTRACTABLE must equal control");

        // REST
        let base = spawn_rest_v32().await.unwrap();
        let rs = rest_post(&base, "open-session", json!({"slot_id": v32::SLOT, "flags": CKF_SERIAL_SESSION | CKF_RW_SESSION})).await;
        let sh = rs["session_handle"].clone();
        let rw = rest_post(&base, "wrap-key", json!({
            "session_handle": sh,
            "mechanism": {"mechanism": CKM_AES_KEY_WRAP, "parameter": ""},
            "wrapping_key_handle": wrapping_key,
            "key_handle": target_key,
        })).await;
        assert_eq!(rw["ck_rv"].as_u64().unwrap() as u32, rv_wrap_ctl);
        assert_eq!(unb64(rw["data"].as_str().unwrap()), wrapped_ctl, "REST wrapped bytes must equal control");
        let ru = rest_post(&base, "unwrap-key", json!({
            "session_handle": sh,
            "mechanism": {"mechanism": CKM_AES_KEY_WRAP, "parameter": ""},
            "unwrapping_key_handle": wrapping_key,
            "wrapped_key": b64(&wrapped_ctl),
            "template": [
                ulong_attr(CKA_CLASS, CKO_SECRET_KEY as u32),
                ulong_attr(CKA_KEY_TYPE, CKK_AES as u32),
                bool_attr(0x0162, true),
                bool_attr(CKA_TOKEN, false),
            ],
        })).await;
        assert_eq!(ru["ck_rv"].as_u64().unwrap() as u32, rv_unwrap_ctl);
        assert_ne!(ru["object_handle"].as_u64().unwrap(), 0);
        let rn = rest_post(&base, "wrap-key", json!({
            "session_handle": sh,
            "mechanism": {"mechanism": CKM_AES_KEY_WRAP, "parameter": ""},
            "wrapping_key_handle": wrapping_key,
            "key_handle": locked_key,
        })).await;
        assert_eq!(rn["ck_rv"].as_u64().unwrap() as u32, rv_neg_ctl, "REST CKR_KEY_UNEXTRACTABLE must equal control");

        v32::close_session(ks);
    });
}

// ── V19: DeriveKey — raw-param (CONCATENATE_BASE_AND_KEY) and structured
// (HKDF via the oneof) parity, KAT-grade byte equality ───────────────────

#[test]
fn v19_derive_key_raw_and_hkdf_parity() {
    bootstrap_once();
    rt().block_on(async {
        let (_rv, ks) = v32::open_session(v32::SLOT, CKF_SERIAL_SESSION | CKF_RW_SESSION);
        let base_tmpl: Vec<(u64, Vec<u8>)> = vec![
            (CKA_CLASS, (CKO_SECRET_KEY as usize).to_le_bytes().to_vec()),
            (CKA_KEY_TYPE, (CKK_GENERIC_SECRET as usize).to_le_bytes().to_vec()),
            (CKA_VALUE_LEN, (32usize).to_le_bytes().to_vec()),
            (CKA_DERIVE, vec![1u8]),
            (CKA_TOKEN, vec![0u8]),
        ];
        let (rv, base_key) = v32::generate_key(ks, 0x0000_0350 /* CKM_GENERIC_SECRET_KEY_GEN */, &[], &base_tmpl);
        assert_eq!(rv, 0);
        let (rv, second_key) = v32::generate_key(ks, CKM_AES_KEY_GEN, &[], &vec![
            (CKA_CLASS, (CKO_SECRET_KEY as usize).to_le_bytes().to_vec()),
            (CKA_KEY_TYPE, (CKK_AES as usize).to_le_bytes().to_vec()),
            (CKA_VALUE_LEN, (16usize).to_le_bytes().to_vec()),
            (CKA_DERIVE, vec![1u8]),
            (CKA_TOKEN, vec![0u8]),
        ]);
        assert_eq!(rv, 0);

        let out_tmpl: Vec<(u64, Vec<u8>)> = vec![
            (CKA_CLASS, (CKO_SECRET_KEY as usize).to_le_bytes().to_vec()),
            (CKA_KEY_TYPE, (CKK_GENERIC_SECRET as usize).to_le_bytes().to_vec()),
            (CKA_VALUE_LEN, (32usize).to_le_bytes().to_vec()),
            (CKA_TOKEN, vec![0u8]),
        ];

        // control — raw-param concatenate
        let concat_param = (second_key as usize).to_ne_bytes().to_vec();
        let (rv_ctl, derived_ctl) = v32::derive_key(ks, CKM_CONCATENATE_BASE_AND_KEY, &concat_param, base_key, &out_tmpl);
        assert_eq!(rv_ctl, 0);
        let (rv, attrs_ctl) = v32::get_attribute_value(ks, derived_ctl, &[CKA_VALUE]);
        assert_eq!(rv, 0);

        // control — structured HKDF
        let hkdf_params = pqctoday_pkcs11_remote_core::verbs_v32::derive_params::hkdf(
            true, true, 0x0000_0250 /* CKM_SHA256 — prfHashMechanism names the hash, not an HMAC mechanism id */, 0x0000_0002 /* CKF_HKDF_SALT_DATA */, b"v19-salt", 0, b"v19-info",
        );
        let (rv_hkdf_ctl, derived_hkdf_ctl) =
            v32::derive_key(ks, CKM_HKDF_DERIVE_LOCAL, hkdf_params.as_slice(), base_key, &out_tmpl);
        assert_eq!(rv_hkdf_ctl, 0);
        let (rv, attrs_hkdf_ctl) = v32::get_attribute_value(ks, derived_hkdf_ctl, &[CKA_VALUE]);
        assert_eq!(rv, 0);

        // gRPC
        let mut g = spawn_grpc_v32().await.unwrap();
        let gs = g.c_open_session(proto::V32OpenSessionRequest { slot_id: v32::SLOT, flags: CKF_SERIAL_SESSION | CKF_RW_SESSION }).await.unwrap().into_inner();
        let g_out_tmpl = vec![
            ulong_attr_proto(CKA_CLASS, CKO_SECRET_KEY as u32),
            ulong_attr_proto(CKA_KEY_TYPE, CKK_GENERIC_SECRET as u32),
            ulong_attr_proto(CKA_VALUE_LEN, 32),
            bool_attr_proto(CKA_TOKEN, false),
        ];
        let gc = g.c_derive_key(proto::V32DeriveKeyRequest {
            session_handle: gs.session_handle,
            mechanism: CKM_CONCATENATE_BASE_AND_KEY,
            base_key_handle: base_key,
            template: g_out_tmpl.clone(),
            raw_parameter: concat_param.clone(),
            structured: None,
        }).await.unwrap().into_inner();
        assert_eq!(gc.ck_rv, rv_ctl);
        let ga = g.c_get_attribute_value(proto::V32GetAttributeValueRequest { session_handle: gs.session_handle, object_handle: gc.object_handle, attribute_types: vec![CKA_VALUE] }).await.unwrap().into_inner();
        assert_eq!(ga.attributes[0].value, attrs_ctl[0].value, "gRPC concatenated key material must equal control");

        let gh = g.c_derive_key(proto::V32DeriveKeyRequest {
            session_handle: gs.session_handle,
            mechanism: CKM_HKDF_DERIVE_LOCAL,
            base_key_handle: base_key,
            template: g_out_tmpl.clone(),
            raw_parameter: vec![],
            structured: Some(proto::v32_derive_key_request::Structured::Hkdf(proto::V32HkdfParams {
                extract: true, expand: true, prf_hash_mechanism: 0x0000_0250, salt_type: 0x0000_0002,
                salt: b"v19-salt".to_vec(), h_salt_key: 0, info: b"v19-info".to_vec(),
            })),
        }).await.unwrap().into_inner();
        assert_eq!(gh.ck_rv, rv_hkdf_ctl);
        let gha = g.c_get_attribute_value(proto::V32GetAttributeValueRequest { session_handle: gs.session_handle, object_handle: gh.object_handle, attribute_types: vec![CKA_VALUE] }).await.unwrap().into_inner();
        assert_eq!(gha.attributes[0].value, attrs_hkdf_ctl[0].value, "gRPC HKDF-derived key material must equal control");

        // REST
        let base = spawn_rest_v32().await.unwrap();
        let rs = rest_post(&base, "open-session", json!({"slot_id": v32::SLOT, "flags": CKF_SERIAL_SESSION | CKF_RW_SESSION})).await;
        let sh = rs["session_handle"].clone();
        let r_out_tmpl = json!([
            ulong_attr(CKA_CLASS, CKO_SECRET_KEY as u32),
            ulong_attr(CKA_KEY_TYPE, CKK_GENERIC_SECRET as u32),
            ulong_attr(CKA_VALUE_LEN, 32),
            bool_attr(CKA_TOKEN, false),
        ]);
        let rc = rest_post(&base, "derive-key", json!({
            "session_handle": sh, "mechanism": CKM_CONCATENATE_BASE_AND_KEY, "base_key_handle": base_key,
            "template": r_out_tmpl, "raw_parameter": b64(&concat_param),
        })).await;
        assert_eq!(rc["ck_rv"].as_u64().unwrap() as u32, rv_ctl);
        let ra = rest_post(&base, "get-attribute-value", json!({"session_handle": sh, "object_handle": rc["object_handle"], "attribute_types": [CKA_VALUE]})).await;
        assert_eq!(unb64(ra["attributes"][0]["value"].as_str().unwrap()), attrs_ctl[0].value, "REST concatenated key material must equal control");

        let rh = rest_post(&base, "derive-key", json!({
            "session_handle": sh, "mechanism": CKM_HKDF_DERIVE_LOCAL, "base_key_handle": base_key, "template": r_out_tmpl,
            "hkdf": {"extract": true, "expand": true, "prf_hash_mechanism": 0x250, "salt_type": 2, "salt": b64(b"v19-salt"), "h_salt_key": 0, "info": b64(b"v19-info")},
        })).await;
        assert_eq!(rh["ck_rv"].as_u64().unwrap() as u32, rv_hkdf_ctl);
        let rha = rest_post(&base, "get-attribute-value", json!({"session_handle": sh, "object_handle": rh["object_handle"], "attribute_types": [CKA_VALUE]})).await;
        assert_eq!(unb64(rha["attributes"][0]["value"].as_str().unwrap()), attrs_hkdf_ctl[0].value, "REST HKDF-derived key material must equal control");

        v32::close_session(ks);
    });
}

// ── V20: ML-KEM-768 encapsulate on gRPC, decapsulate on REST, against the
// SAME shared keypair — a stronger assertion than a same-transport round
// trip, and the plan's own stated positive-parity design for RW5 ────────

#[test]
fn v20_ml_kem_768_cross_transport_encapsulate_decapsulate() {
    bootstrap_once();
    rt().block_on(async {
        let (_rv, ks) = v32::open_session(v32::SLOT, CKF_SERIAL_SESSION | CKF_RW_SESSION);
        let public_tmpl: Vec<(u64, Vec<u8>)> = vec![
            (CKA_CLASS, (CKO_PUBLIC_KEY as usize).to_le_bytes().to_vec()),
            (CKA_KEY_TYPE, (CKK_ML_KEM as usize).to_le_bytes().to_vec()),
            (CKA_PARAMETER_SET, (CKP_ML_KEM_768 as usize).to_le_bytes().to_vec()),
            (CKA_ENCAPSULATE, vec![1u8]),
            (CKA_TOKEN, vec![0u8]),
        ];
        let private_tmpl: Vec<(u64, Vec<u8>)> = vec![
            (CKA_CLASS, (CKO_PRIVATE_KEY as usize).to_le_bytes().to_vec()),
            (CKA_KEY_TYPE, (CKK_ML_KEM as usize).to_le_bytes().to_vec()),
            (CKA_PARAMETER_SET, (CKP_ML_KEM_768 as usize).to_le_bytes().to_vec()),
            (CKA_DECAPSULATE, vec![1u8]),
            (CKA_TOKEN, vec![0u8]),
        ];
        let (rv, pub_h, prv_h) =
            v32::generate_key_pair(ks, CKM_ML_KEM_KEY_PAIR_GEN, &[], &public_tmpl, &private_tmpl);
        assert_eq!(rv, 0);

        // control: same-transport round trip, as the oracle for "this IS a
        // real, functioning KEM pair" before crossing transports.
        let (rv_ctl, ct_ctl, encap_ctl) = v32::encapsulate_key(ks, CKM_ML_KEM, &[], pub_h, &[]);
        assert_eq!(rv_ctl, 0);
        let (rv_dec_ctl, decap_ctl) = v32::decapsulate_key(ks, CKM_ML_KEM, &[], prv_h, &ct_ctl, &[]);
        assert_eq!(rv_dec_ctl, 0);
        let (rv, ss_encap_ctl) = v32::get_attribute_value(ks, encap_ctl, &[CKA_VALUE]);
        assert_eq!(rv, 0);
        let (rv, ss_decap_ctl) = v32::get_attribute_value(ks, decap_ctl, &[CKA_VALUE]);
        assert_eq!(rv, 0);
        assert_eq!(ss_encap_ctl[0].value, ss_decap_ctl[0].value, "control same-transport KEM must agree on the shared secret");

        // gRPC encapsulates against the peer's public key...
        let mut g = spawn_grpc_v32().await.unwrap();
        let gs = g.c_open_session(proto::V32OpenSessionRequest { slot_id: v32::SLOT, flags: CKF_SERIAL_SESSION | CKF_RW_SESSION }).await.unwrap().into_inner();
        let ge = g.c_encapsulate_key(proto::V32EncapsulateKeyRequest {
            session_handle: gs.session_handle,
            mechanism: Some(proto::V32Mechanism { mechanism: CKM_ML_KEM, parameter: vec![], structured: None }),
            key_handle: pub_h,
            template: vec![],
        }).await.unwrap().into_inner();
        assert_eq!(ge.ck_rv, 0);
        assert_ne!(ge.object_handle, 0);
        let ge_attrs = g.c_get_attribute_value(proto::V32GetAttributeValueRequest {
            session_handle: gs.session_handle, object_handle: ge.object_handle, attribute_types: vec![CKA_VALUE],
        }).await.unwrap().into_inner();

        // ...REST decapsulates the SAME ciphertext against the SAME
        // private key, on a COMPLETELY DIFFERENT session/transport.
        let base = spawn_rest_v32().await.unwrap();
        let rs = rest_post(&base, "open-session", json!({"slot_id": v32::SLOT, "flags": CKF_SERIAL_SESSION | CKF_RW_SESSION})).await;
        let sh = rs["session_handle"].clone();
        let rd = rest_post(&base, "decapsulate-key", json!({
            "session_handle": sh,
            "mechanism": {"mechanism": CKM_ML_KEM, "parameter": ""},
            "private_key_handle": prv_h,
            "ciphertext": b64(&ge.ciphertext),
        })).await;
        assert_eq!(rd["ck_rv"], 0);
        let rd_obj = rd["object_handle"].clone();
        assert_ne!(rd_obj.as_u64().unwrap(), 0);
        let rd_attrs = rest_post(&base, "get-attribute-value", json!({"session_handle": sh, "object_handle": rd_obj, "attribute_types": [CKA_VALUE]})).await;

        // NOTE: encapsulation is randomized (with_rng!), so gRPC's own
        // encapsulate draws independent randomness from the control's —
        // its ciphertext/secret are NOT expected to equal the control's.
        // The real cross-transport correctness property is: whatever
        // gRPC encapsulated, REST's decapsulate of THAT SAME ciphertext
        // must recover THAT SAME shared secret.
        assert_eq!(
            ge_attrs.attributes[0].value,
            unb64(rd_attrs["attributes"][0]["value"].as_str().unwrap()),
            "gRPC's encapsulated shared secret must equal REST's decapsulated shared secret — cross-transport KEM correctness, not just wire plumbing"
        );
        assert_eq!(ge_attrs.attributes[0].value.len(), ss_encap_ctl[0].value.len(), "both must derive a shared secret of the same real length");

        v32::close_session(ks);
    });
}

// ── V21a/V21b (G4, split from the original V21) — algorithm-cell sweep
// over the SAME sign_init/sign/verify_init/verify verbs every other
// signature cell already uses. Split by keygen cost: SLH-DSA-128S keygen
// is fast (routine suite); XMSS/HSS Merkle keygen is not (kept
// `#[ignore]`'d, unchanged from the original V21's own measurement) ──────

struct SignVerifyCell {
    name: &'static str,
    mechanism: u64,
    public_key: u32,
    private_key: u32,
}

/// Shared sign/verify/tamper parity body for one set of algorithm cells —
/// extracted so V21a/V21b don't duplicate the ~40-line loop.
async fn run_sign_verify_cells(ks: u32, cells: &[SignVerifyCell]) {
    let mut g = spawn_grpc_v32().await.unwrap();
    let base = spawn_rest_v32().await.unwrap();

    for cell in cells {
        let msg = format!("v21 {} algorithm cell", cell.name).into_bytes();

        // control
        assert_eq!(v32::sign_init(ks, cell.mechanism, &[], cell.private_key), 0, "{}: sign_init", cell.name);
        let (rv, sig_ctl) = v32::sign(ks, &msg);
        assert_eq!(rv, 0, "{}: sign", cell.name);
        assert_eq!(v32::verify_init(ks, cell.mechanism, &[], cell.public_key), 0, "{}: verify_init", cell.name);
        let rv_good_ctl = v32::verify(ks, &msg, &sig_ctl);
        assert_eq!(rv_good_ctl, 0, "{}: verify must accept its own signature", cell.name);
        let mut bad_sig = sig_ctl.clone();
        bad_sig[0] ^= 0xFF;
        assert_eq!(v32::verify_init(ks, cell.mechanism, &[], cell.public_key), 0);
        let rv_bad_ctl = v32::verify(ks, &msg, &bad_sig);
        assert_ne!(rv_bad_ctl, 0, "{}: a tampered signature must be rejected", cell.name);

        // gRPC — sign fresh (these schemes may be randomized/stateful,
        // so a fresh signature is the correct cross-transport check,
        // not byte-equality with the control's), verify parity both ways.
        let gs = g.c_open_session(proto::V32OpenSessionRequest { slot_id: v32::SLOT, flags: CKF_SERIAL_SESSION | CKF_RW_SESSION }).await.unwrap().into_inner();
        g.c_sign_init(proto::V32KeyedInitRequest { session_handle: gs.session_handle, mechanism: Some(proto::V32Mechanism { mechanism: cell.mechanism, parameter: vec![], structured: None }), key_handle: cell.private_key }).await.unwrap();
        let gsig = g.c_sign(proto::V32DataRequest { session_handle: gs.session_handle, data: msg.clone() }).await.unwrap().into_inner();
        assert_eq!(gsig.ck_rv, 0, "{}: gRPC sign", cell.name);
        g.c_verify_init(proto::V32KeyedInitRequest { session_handle: gs.session_handle, mechanism: Some(proto::V32Mechanism { mechanism: cell.mechanism, parameter: vec![], structured: None }), key_handle: cell.public_key }).await.unwrap();
        let gg = g.c_verify(proto::V32VerifyRequest { session_handle: gs.session_handle, data: msg.clone(), signature: gsig.data }).await.unwrap().into_inner();
        assert_eq!(gg.ck_rv, rv_good_ctl, "{}: gRPC verify-good must match control", cell.name);
        g.c_verify_init(proto::V32KeyedInitRequest { session_handle: gs.session_handle, mechanism: Some(proto::V32Mechanism { mechanism: cell.mechanism, parameter: vec![], structured: None }), key_handle: cell.public_key }).await.unwrap();
        let gb = g.c_verify(proto::V32VerifyRequest { session_handle: gs.session_handle, data: msg.clone(), signature: bad_sig.clone() }).await.unwrap().into_inner();
        assert_eq!(gb.ck_rv, rv_bad_ctl, "{}: gRPC verify-tamper must match control", cell.name);

        // REST — same shape.
        let rs = rest_post(&base, "open-session", json!({"slot_id": v32::SLOT, "flags": CKF_SERIAL_SESSION | CKF_RW_SESSION})).await;
        let sh = rs["session_handle"].clone();
        rest_post(&base, "sign-init", json!({"session_handle": sh, "mechanism": {"mechanism": cell.mechanism, "parameter": ""}, "key_handle": cell.private_key})).await;
        let rsig = rest_post(&base, "sign", json!({"session_handle": sh, "data": b64(&msg)})).await;
        assert_eq!(rsig["ck_rv"], 0, "{}: REST sign", cell.name);
        rest_post(&base, "verify-init", json!({"session_handle": sh, "mechanism": {"mechanism": cell.mechanism, "parameter": ""}, "key_handle": cell.public_key})).await;
        let rg = rest_post(&base, "verify", json!({"session_handle": sh, "data": b64(&msg), "signature": rsig["data"]})).await;
        assert_eq!(rg["ck_rv"].as_u64().unwrap() as u32, rv_good_ctl, "{}: REST verify-good must match control", cell.name);
        rest_post(&base, "verify-init", json!({"session_handle": sh, "mechanism": {"mechanism": cell.mechanism, "parameter": ""}, "key_handle": cell.public_key})).await;
        let rb = rest_post(&base, "verify", json!({"session_handle": sh, "data": b64(&msg), "signature": b64(&bad_sig)})).await;
        assert_eq!(rb["ck_rv"].as_u64().unwrap() as u32, rv_bad_ctl, "{}: REST verify-tamper must match control", cell.name);
    }
}

/// V21a — SLH-DSA (SHA2 + SHAKE), the **"f" (fast)** parameter sets.
///
/// The "s" ("small") sets used by V21b's SLH-DSA-adjacent cousins trade a
/// smaller signature for slow SIGNING specifically (FIPS 205's own
/// small/fast split, not a keygen-cost distinction) — measured live at
/// ~227s for this whole case when it used CKP_SLH_DSA_*_128S, well past
/// the plan's own "keep only if under ~10s" bar. Switched to the "f" sets
/// (CKP_SLH_DSA_*_128F), which are fast: routine suite.
#[test]
fn v21a_slh_dsa_sign_verify_parity() {
    bootstrap_once();
    rt().block_on(async {
        let (_rv, ks) = v32::open_session(v32::SLOT, CKF_SERIAL_SESSION | CKF_RW_SESSION);
        let mut cells = Vec::new();
        for (name, ps) in [("slh-dsa-sha2", CKP_SLH_DSA_SHA2_128F), ("slh-dsa-shake", CKP_SLH_DSA_SHAKE_128F)] {
            let public_tmpl: Vec<(u64, Vec<u8>)> = vec![
                (CKA_CLASS, (CKO_PUBLIC_KEY as usize).to_le_bytes().to_vec()),
                (CKA_PARAMETER_SET, (ps as usize).to_le_bytes().to_vec()),
                (CKA_TOKEN, vec![0u8]),
            ];
            let private_tmpl: Vec<(u64, Vec<u8>)> = vec![(CKA_CLASS, (CKO_PRIVATE_KEY as usize).to_le_bytes().to_vec()), (CKA_TOKEN, vec![0u8])];
            let (rv, pub_h, prv_h) = v32::generate_key_pair(ks, CKM_SLH_DSA_KEY_PAIR_GEN, &[], &public_tmpl, &private_tmpl);
            assert_eq!(rv, 0, "{name} keygen must succeed");
            cells.push(SignVerifyCell { name, mechanism: CKM_SLH_DSA, public_key: pub_h, private_key: prv_h });
        }
        run_sign_verify_cells(ks, &cells).await;
        v32::close_session(ks);
    });
}

/// V21b — XMSS + HSS only.
///
/// #[ignore] — measured ~326s end to end (first live run, unchanged by
/// this split). XMSS keygen builds a full height-10 Merkle tree (1024
/// WOTS+ leaf keys); §6.66.6's smallest single-tree parameter set this
/// engine offers is already height 10, so there is no faster real cell to
/// substitute. Every other test in this suite runs in well under a
/// second; folding this one into the routine run would take the
/// remoting gate step from ~0.5s to 5+ minutes for every contributor.
/// Run explicitly with `cargo test -- --ignored v21b_xmss_hss_sign_verify_parity`
/// (or `--include-ignored` for the whole suite) — not wired into
/// `scripts/local-gate.sh`'s routine step (see that script's own comment
/// for the measured runtime, kept in sync with this one).
#[test]
#[ignore]
fn v21b_xmss_hss_sign_verify_parity() {
    bootstrap_once();
    rt().block_on(async {
        let (_rv, ks) = v32::open_session(v32::SLOT, CKF_SERIAL_SESSION | CKF_RW_SESSION);
        let mut cells = Vec::new();
        {
            let (rv, pub_h, prv_h) = v32::generate_key_pair(ks, CKM_XMSS_KEY_PAIR_GEN, &[], &[], &[]);
            assert_eq!(rv, 0, "xmss keygen (default parameter set) must succeed");
            cells.push(SignVerifyCell { name: "xmss", mechanism: CKM_XMSS, public_key: pub_h, private_key: prv_h });
        }
        {
            let (rv, pub_h, prv_h) = v32::generate_key_pair(ks, CKM_HSS_KEY_PAIR_GEN, &[], &[], &[]);
            assert_eq!(rv, 0, "hss keygen (default single-level LMS) must succeed");
            cells.push(SignVerifyCell { name: "hss", mechanism: CKM_HSS, public_key: pub_h, private_key: prv_h });
        }
        run_sign_verify_cells(ks, &cells).await;
        v32::close_session(ks);
    });
}

// ── V22: RW-T coverage-ledger audit finding — C_VerifySignatureUpdate/
// C_VerifySignatureFinal (multipart verify-with-signature) and
// C_GetSessionValidationFlags, missed by RW6a's original sweep ─────────

#[test]
fn v22_verify_signature_multipart_and_session_validation_flags_parity() {
    bootstrap_once();
    rt().block_on(async {
        let fixture = pqctoday_pkcs11_remote_core::verbs::open_session("1234").unwrap();
        let (pub_h, prv_h) = pqctoday_pkcs11_remote_core::verbs::generate_key_pair(
            fixture, pqctoday_pkcs11_remote_core::Algorithm::MlDsa65, b"v22", "v22",
        ).unwrap();

        let (_rv, s) = v32::open_session(v32::SLOT, CKF_SERIAL_SESSION | CKF_RW_SESSION);
        assert_eq!(v32::sign_init(s, CKM_ML_DSA, &[], prv_h), 0);
        let (rv, sig) = v32::sign(s, b"part-one part-two");
        assert_eq!(rv, 0);
        assert_eq!(v32::verify_signature_init(s, CKM_ML_DSA, &[], pub_h, &sig), 0);
        assert_eq!(v32::verify_signature_update(s, b"part-one "), 0);
        let rv_good_ctl = v32::verify_signature_update(s, b"part-two");
        let rv_final_ctl = v32::verify_signature_final(s);
        assert_eq!(rv_good_ctl, 0);
        assert_eq!(rv_final_ctl, 0);
        const CKS_LAST_VALIDATION_OK: u32 = 1;
        let (rv_flags_ctl, flags_ctl) = v32::get_session_validation_flags(s, CKS_LAST_VALIDATION_OK);
        assert_eq!(rv_flags_ctl, 0);
        assert_eq!(flags_ctl, 0);
        v32::close_session(s);

        let mut g = spawn_grpc_v32().await.unwrap();
        let gs = g.c_open_session(proto::V32OpenSessionRequest { slot_id: v32::SLOT, flags: CKF_SERIAL_SESSION | CKF_RW_SESSION }).await.unwrap().into_inner();
        g.c_verify_signature_init(proto::V32VerifySignatureInitRequest {
            session_handle: gs.session_handle,
            mechanism: Some(proto::V32Mechanism { mechanism: CKM_ML_DSA, parameter: vec![], structured: None }),
            key_handle: pub_h,
            signature: sig.clone(),
        }).await.unwrap();
        g.c_verify_signature_update(proto::V32DataRequest { session_handle: gs.session_handle, data: b"part-one ".to_vec() }).await.unwrap();
        let gu = g.c_verify_signature_update(proto::V32DataRequest { session_handle: gs.session_handle, data: b"part-two".to_vec() }).await.unwrap().into_inner();
        assert_eq!(gu.ck_rv, rv_good_ctl);
        let gf = g.c_verify_signature_final(proto::V32SessionRequest { session_handle: gs.session_handle }).await.unwrap().into_inner();
        assert_eq!(gf.ck_rv, rv_final_ctl);
        let gflags = g.c_get_session_validation_flags(proto::V32GetSessionValidationFlagsRequest { session_handle: gs.session_handle, validation_type: CKS_LAST_VALIDATION_OK }).await.unwrap().into_inner();
        assert_eq!(gflags.ck_rv, rv_flags_ctl);
        assert_eq!(gflags.flags, flags_ctl);

        let base = spawn_rest_v32().await.unwrap();
        let rs = rest_post(&base, "open-session", json!({"slot_id": v32::SLOT, "flags": CKF_SERIAL_SESSION | CKF_RW_SESSION})).await;
        let sh = rs["session_handle"].clone();
        rest_post(&base, "verify-signature-init", json!({
            "session_handle": sh, "mechanism": {"mechanism": CKM_ML_DSA, "parameter": ""}, "key_handle": pub_h, "signature": b64(&sig),
        })).await;
        rest_post(&base, "verify-signature-update", json!({"session_handle": sh, "data": b64(b"part-one ")})).await;
        let ru = rest_post(&base, "verify-signature-update", json!({"session_handle": sh, "data": b64(b"part-two")})).await;
        assert_eq!(ru["ck_rv"].as_u64().unwrap() as u32, rv_good_ctl);
        let rf = rest_post(&base, "verify-signature-final", json!({"session_handle": sh})).await;
        assert_eq!(rf["ck_rv"].as_u64().unwrap() as u32, rv_final_ctl);
        let rflags = rest_post(&base, "get-session-validation-flags", json!({"session_handle": sh, "validation_type": CKS_LAST_VALIDATION_OK})).await;
        assert_eq!(rflags["ck_rv"].as_u64().unwrap() as u32, rv_flags_ctl);
        assert_eq!(rflags["flags"].as_u64().unwrap() as u32, flags_ctl);

        pqctoday_pkcs11_remote_core::verbs::close_session(fixture).ok();
    });
}

// ── V23: AES-GCM one-shot via the structured V32GcmParams oneof (G1
// gap-remediation) — shared key, KAT-grade ciphertext byte equality ────

#[test]
fn v23_aes_gcm_structured_params_kat_parity() {
    bootstrap_once();
    rt().block_on(async {
        let (_rv, ks) = v32::open_session(v32::SLOT, CKF_SERIAL_SESSION | CKF_RW_SESSION);
        let key_template: Vec<(u64, Vec<u8>)> = vec![
            (CKA_CLASS, (CKO_SECRET_KEY as usize).to_le_bytes().to_vec()),
            (CKA_KEY_TYPE, (CKK_AES as usize).to_le_bytes().to_vec()),
            (CKA_VALUE_LEN, (32usize).to_le_bytes().to_vec()),
            (CKA_ENCRYPT, vec![1u8]),
            (CKA_DECRYPT, vec![1u8]),
            (CKA_TOKEN, vec![0u8]),
        ];
        let (rv_key, key) = v32::generate_key(ks, CKM_AES_KEY_GEN, &[], &key_template);
        assert_eq!(rv_key, 0);

        let iv = vec![0x11u8; 12];
        let aad = b"v23-aad".to_vec();
        let plaintext = b"v23 AES-GCM structured-oneof parity".to_vec();
        let gcm_params = pqctoday_pkcs11_remote_core::verbs_v32::cipher_params::gcm(&iv, &aad, 128);

        // control
        assert_eq!(v32::encrypt_init(ks, CKM_AES_GCM, gcm_params.as_slice(), key), 0);
        let (rv_ctl, ciphertext_ctl) = v32::encrypt(ks, &plaintext);
        assert_eq!(rv_ctl, 0);
        let gcm_dparams = pqctoday_pkcs11_remote_core::verbs_v32::cipher_params::gcm(&iv, &aad, 128);
        assert_eq!(v32::decrypt_init(ks, CKM_AES_GCM, gcm_dparams.as_slice(), key), 0);
        let (rv_dec_ctl, recovered_ctl) = v32::decrypt(ks, &ciphertext_ctl);
        assert_eq!(rv_dec_ctl, 0);
        assert_eq!(recovered_ctl, plaintext);

        // gRPC — same key handle, GCM params sent via the structured oneof.
        let mut g = spawn_grpc_v32().await.unwrap();
        let gs = g.c_open_session(proto::V32OpenSessionRequest { slot_id: v32::SLOT, flags: CKF_SERIAL_SESSION | CKF_RW_SESSION }).await.unwrap().into_inner();
        g.c_encrypt_init(proto::V32KeyedInitRequest {
            session_handle: gs.session_handle,
            mechanism: Some(proto::V32Mechanism {
                mechanism: CKM_AES_GCM,
                parameter: vec![],
                structured: Some(proto::v32_mechanism::Structured::Gcm(proto::V32GcmParams { iv: iv.clone(), aad: aad.clone(), tag_bits: 128 })),
            }),
            key_handle: key,
        }).await.unwrap();
        let ge = g.c_encrypt(proto::V32DataRequest { session_handle: gs.session_handle, data: plaintext.clone() }).await.unwrap().into_inner();
        assert_eq!(ge.ck_rv, rv_ctl);
        assert_eq!(ge.data, ciphertext_ctl, "gRPC structured-GCM ciphertext must equal control byte-for-byte");
        g.c_decrypt_init(proto::V32KeyedInitRequest {
            session_handle: gs.session_handle,
            mechanism: Some(proto::V32Mechanism {
                mechanism: CKM_AES_GCM,
                parameter: vec![],
                structured: Some(proto::v32_mechanism::Structured::Gcm(proto::V32GcmParams { iv: iv.clone(), aad: aad.clone(), tag_bits: 128 })),
            }),
            key_handle: key,
        }).await.unwrap();
        let gd = g.c_decrypt(proto::V32DataRequest { session_handle: gs.session_handle, data: ciphertext_ctl.clone() }).await.unwrap().into_inner();
        assert_eq!(gd.ck_rv, rv_dec_ctl);
        assert_eq!(gd.data, plaintext);

        // REST — same key handle, GCM params sent via the mechanism.gcm field.
        let base = spawn_rest_v32().await.unwrap();
        let rs = rest_post(&base, "open-session", json!({"slot_id": v32::SLOT, "flags": CKF_SERIAL_SESSION | CKF_RW_SESSION})).await;
        let sh = rs["session_handle"].clone();
        rest_post(&base, "encrypt-init", json!({
            "session_handle": sh,
            "mechanism": {"mechanism": CKM_AES_GCM, "gcm": {"iv": b64(&iv), "aad": b64(&aad), "tag_bits": 128}},
            "key_handle": key,
        })).await;
        let re = rest_post(&base, "encrypt", json!({"session_handle": sh, "data": b64(&plaintext)})).await;
        assert_eq!(re["ck_rv"].as_u64().unwrap() as u32, rv_ctl);
        assert_eq!(unb64(re["data"].as_str().unwrap()), ciphertext_ctl, "REST structured-GCM ciphertext must equal control");
        rest_post(&base, "decrypt-init", json!({
            "session_handle": sh,
            "mechanism": {"mechanism": CKM_AES_GCM, "gcm": {"iv": b64(&iv), "aad": b64(&aad), "tag_bits": 128}},
            "key_handle": key,
        })).await;
        let rd = rest_post(&base, "decrypt", json!({"session_handle": sh, "data": re["data"].clone()})).await;
        assert_eq!(rd["ck_rv"].as_u64().unwrap() as u32, rv_dec_ctl);
        assert_eq!(unb64(rd["data"].as_str().unwrap()), plaintext);

        v32::close_session(ks);
    });
}

// ── V24: RSA-OAEP encrypt/decrypt via the structured V32OaepParams oneof
// (G1 gap-remediation) — OAEP is randomized, so each transport encrypts
// its own ciphertext; the real property under test is that each one's
// own decrypt recovers the same plaintext ────────────────────────────────

#[test]
fn v24_rsa_oaep_structured_params_parity() {
    bootstrap_once();
    rt().block_on(async {
        let (_rv, ks) = v32::open_session(v32::SLOT, CKF_SERIAL_SESSION | CKF_RW_SESSION);
        let public_tmpl: Vec<(u64, Vec<u8>)> = vec![
            (CKA_CLASS, (CKO_PUBLIC_KEY as usize).to_le_bytes().to_vec()),
            (CKA_KEY_TYPE, (CKK_RSA as usize).to_le_bytes().to_vec()),
            (CKA_MODULUS_BITS, (2048usize).to_le_bytes().to_vec()),
            (CKA_ENCRYPT, vec![1u8]),
            (CKA_TOKEN, vec![0u8]),
        ];
        let private_tmpl: Vec<(u64, Vec<u8>)> = vec![
            (CKA_CLASS, (CKO_PRIVATE_KEY as usize).to_le_bytes().to_vec()),
            (CKA_KEY_TYPE, (CKK_RSA as usize).to_le_bytes().to_vec()),
            (CKA_DECRYPT, vec![1u8]),
            (CKA_TOKEN, vec![0u8]),
        ];
        let (rv, pub_h, prv_h) = v32::generate_key_pair(ks, CKM_RSA_PKCS_KEY_PAIR_GEN, &[], &public_tmpl, &private_tmpl);
        assert_eq!(rv, 0, "RSA-2048 keygen must succeed — a prerequisite for testing OAEP at all");

        let plaintext = b"v24 RSA-OAEP structured-oneof parity".to_vec();

        // control
        let ctl_params = pqctoday_pkcs11_remote_core::verbs_v32::cipher_params::oaep(CKM_SHA256 as u32, CKG_MGF1_SHA256, &[]);
        assert_eq!(v32::encrypt_init(ks, CKM_RSA_PKCS_OAEP, ctl_params.as_slice(), pub_h), 0);
        let (rv_ctl, ciphertext_ctl) = v32::encrypt(ks, &plaintext);
        assert_eq!(rv_ctl, 0);
        let ctl_dparams = pqctoday_pkcs11_remote_core::verbs_v32::cipher_params::oaep(CKM_SHA256 as u32, CKG_MGF1_SHA256, &[]);
        assert_eq!(v32::decrypt_init(ks, CKM_RSA_PKCS_OAEP, ctl_dparams.as_slice(), prv_h), 0);
        let (rv_dec_ctl, recovered_ctl) = v32::decrypt(ks, &ciphertext_ctl);
        assert_eq!(rv_dec_ctl, 0);
        assert_eq!(recovered_ctl, plaintext);

        // gRPC — own OAEP ciphertext (randomized seed), own decrypt.
        let mut g = spawn_grpc_v32().await.unwrap();
        let gs = g.c_open_session(proto::V32OpenSessionRequest { slot_id: v32::SLOT, flags: CKF_SERIAL_SESSION | CKF_RW_SESSION }).await.unwrap().into_inner();
        g.c_encrypt_init(proto::V32KeyedInitRequest {
            session_handle: gs.session_handle,
            mechanism: Some(proto::V32Mechanism {
                mechanism: CKM_RSA_PKCS_OAEP,
                parameter: vec![],
                structured: Some(proto::v32_mechanism::Structured::Oaep(proto::V32OaepParams { hash_alg: CKM_SHA256 as u32, mgf: CKG_MGF1_SHA256, source_data: vec![] })),
            }),
            key_handle: pub_h,
        }).await.unwrap();
        let ge = g.c_encrypt(proto::V32DataRequest { session_handle: gs.session_handle, data: plaintext.clone() }).await.unwrap().into_inner();
        assert_eq!(ge.ck_rv, rv_ctl);
        g.c_decrypt_init(proto::V32KeyedInitRequest {
            session_handle: gs.session_handle,
            mechanism: Some(proto::V32Mechanism {
                mechanism: CKM_RSA_PKCS_OAEP,
                parameter: vec![],
                structured: Some(proto::v32_mechanism::Structured::Oaep(proto::V32OaepParams { hash_alg: CKM_SHA256 as u32, mgf: CKG_MGF1_SHA256, source_data: vec![] })),
            }),
            key_handle: prv_h,
        }).await.unwrap();
        let gd = g.c_decrypt(proto::V32DataRequest { session_handle: gs.session_handle, data: ge.data }).await.unwrap().into_inner();
        assert_eq!(gd.ck_rv, rv_dec_ctl);
        assert_eq!(gd.data, plaintext, "gRPC's own OAEP round trip must recover the original plaintext");

        // REST — same shape.
        let base = spawn_rest_v32().await.unwrap();
        let rs = rest_post(&base, "open-session", json!({"slot_id": v32::SLOT, "flags": CKF_SERIAL_SESSION | CKF_RW_SESSION})).await;
        let sh = rs["session_handle"].clone();
        rest_post(&base, "encrypt-init", json!({
            "session_handle": sh,
            "mechanism": {"mechanism": CKM_RSA_PKCS_OAEP, "oaep": {"hash_alg": CKM_SHA256 as u32, "mgf": CKG_MGF1_SHA256, "source_data": ""}},
            "key_handle": pub_h,
        })).await;
        let re = rest_post(&base, "encrypt", json!({"session_handle": sh, "data": b64(&plaintext)})).await;
        assert_eq!(re["ck_rv"].as_u64().unwrap() as u32, rv_ctl);
        rest_post(&base, "decrypt-init", json!({
            "session_handle": sh,
            "mechanism": {"mechanism": CKM_RSA_PKCS_OAEP, "oaep": {"hash_alg": CKM_SHA256 as u32, "mgf": CKG_MGF1_SHA256, "source_data": ""}},
            "key_handle": prv_h,
        })).await;
        let rd = rest_post(&base, "decrypt", json!({"session_handle": sh, "data": re["data"].clone()})).await;
        assert_eq!(rd["ck_rv"].as_u64().unwrap() as u32, rv_dec_ctl);
        assert_eq!(unb64(rd["data"].as_str().unwrap()), plaintext, "REST's own OAEP round trip must recover the original plaintext");

        v32::close_session(ks);
    });
}

// ── V25: AES-GCM authenticated wrap/unwrap (G1 gap-remediation, the
// AuthWrap positive path RW4 scoped out) — shared wrapping+target keys,
// KAT-grade wrapped-bytes byte equality ──────────────────────────────────

#[test]
fn v25_aes_gcm_authenticated_wrap_unwrap_parity() {
    bootstrap_once();
    rt().block_on(async {
        let (_rv, ks) = v32::open_session(v32::SLOT, CKF_SERIAL_SESSION | CKF_RW_SESSION);
        let wrapping_tmpl: Vec<(u64, Vec<u8>)> = vec![
            (CKA_CLASS, (CKO_SECRET_KEY as usize).to_le_bytes().to_vec()),
            (CKA_KEY_TYPE, (CKK_AES as usize).to_le_bytes().to_vec()),
            (CKA_VALUE_LEN, (32usize).to_le_bytes().to_vec()),
            (CKA_WRAP, vec![1u8]),
            (CKA_UNWRAP, vec![1u8]),
            (CKA_TOKEN, vec![0u8]),
        ];
        let (rv, wrapping_key) = v32::generate_key(ks, CKM_AES_KEY_GEN, &[], &wrapping_tmpl);
        assert_eq!(rv, 0);
        let target_tmpl: Vec<(u64, Vec<u8>)> = vec![
            (CKA_CLASS, (CKO_SECRET_KEY as usize).to_le_bytes().to_vec()),
            (CKA_KEY_TYPE, (CKK_AES as usize).to_le_bytes().to_vec()),
            (CKA_VALUE_LEN, (16usize).to_le_bytes().to_vec()),
            (0x0162 /* CKA_EXTRACTABLE */, vec![1u8]),
            (CKA_TOKEN, vec![0u8]),
        ];
        let (rv, target_key) = v32::generate_key(ks, CKM_AES_KEY_GEN, &[], &target_tmpl);
        assert_eq!(rv, 0);
        let (rv, orig_attrs) = v32::get_attribute_value(ks, target_key, &[CKA_VALUE]);
        assert_eq!(rv, 0);

        let iv = vec![0x22u8; 12];
        let aad = b"v25-authwrap-aad".to_vec();
        let unwrap_tmpl_ctl: Vec<(u64, Vec<u8>)> = vec![
            (CKA_CLASS, (CKO_SECRET_KEY as usize).to_le_bytes().to_vec()),
            (CKA_KEY_TYPE, (CKK_AES as usize).to_le_bytes().to_vec()),
            (0x0162, vec![1u8]),
            (CKA_TOKEN, vec![0u8]),
        ];

        // control
        let ctl_params = pqctoday_pkcs11_remote_core::verbs_v32::cipher_params::gcm(&iv, &aad, 128);
        let (rv_wrap_ctl, wrapped_ctl) = v32::wrap_key_authenticated(ks, CKM_AES_GCM, ctl_params.as_slice(), wrapping_key, target_key, &aad);
        assert_eq!(rv_wrap_ctl, 0);
        let ctl_dparams = pqctoday_pkcs11_remote_core::verbs_v32::cipher_params::gcm(&iv, &aad, 128);
        let (rv_unwrap_ctl, unwrapped_ctl) = v32::unwrap_key_authenticated(ks, CKM_AES_GCM, ctl_dparams.as_slice(), wrapping_key, &wrapped_ctl, &unwrap_tmpl_ctl, &aad);
        assert_eq!(rv_unwrap_ctl, 0);
        assert_ne!(unwrapped_ctl, 0);

        // gRPC
        let mut g = spawn_grpc_v32().await.unwrap();
        let gs = g.c_open_session(proto::V32OpenSessionRequest { slot_id: v32::SLOT, flags: CKF_SERIAL_SESSION | CKF_RW_SESSION }).await.unwrap().into_inner();
        let gw = g.c_wrap_key_authenticated(proto::V32WrapKeyAuthenticatedRequest {
            session_handle: gs.session_handle,
            mechanism: Some(proto::V32Mechanism {
                mechanism: CKM_AES_GCM,
                parameter: vec![],
                structured: Some(proto::v32_mechanism::Structured::Gcm(proto::V32GcmParams { iv: iv.clone(), aad: aad.clone(), tag_bits: 128 })),
            }),
            wrapping_key_handle: wrapping_key,
            key_handle: target_key,
            associated_data: aad.clone(),
        }).await.unwrap().into_inner();
        assert_eq!(gw.ck_rv, rv_wrap_ctl);
        assert_eq!(gw.data, wrapped_ctl, "gRPC authenticated-wrap bytes must equal control (same key/iv/aad)");
        let gu = g.c_unwrap_key_authenticated(proto::V32UnwrapKeyAuthenticatedRequest {
            session_handle: gs.session_handle,
            mechanism: Some(proto::V32Mechanism {
                mechanism: CKM_AES_GCM,
                parameter: vec![],
                structured: Some(proto::v32_mechanism::Structured::Gcm(proto::V32GcmParams { iv: iv.clone(), aad: aad.clone(), tag_bits: 128 })),
            }),
            unwrapping_key_handle: wrapping_key,
            wrapped_key: wrapped_ctl.clone(),
            template: vec![
                ulong_attr_proto(CKA_CLASS, CKO_SECRET_KEY as u32),
                ulong_attr_proto(CKA_KEY_TYPE, CKK_AES as u32),
                bool_attr_proto(0x0162, true),
                bool_attr_proto(CKA_TOKEN, false),
            ],
            associated_data: aad.clone(),
        }).await.unwrap().into_inner();
        assert_eq!(gu.ck_rv, rv_unwrap_ctl);
        assert_ne!(gu.object_handle, 0);
        let ga = g.c_get_attribute_value(proto::V32GetAttributeValueRequest { session_handle: gs.session_handle, object_handle: gu.object_handle, attribute_types: vec![CKA_VALUE] }).await.unwrap().into_inner();
        assert_eq!(ga.attributes[0].value, orig_attrs[0].value, "gRPC unwrapped key material must equal the original");

        // REST
        let base = spawn_rest_v32().await.unwrap();
        let rs = rest_post(&base, "open-session", json!({"slot_id": v32::SLOT, "flags": CKF_SERIAL_SESSION | CKF_RW_SESSION})).await;
        let sh = rs["session_handle"].clone();
        let rw = rest_post(&base, "wrap-key-authenticated", json!({
            "session_handle": sh,
            "mechanism": {"mechanism": CKM_AES_GCM, "gcm": {"iv": b64(&iv), "aad": b64(&aad), "tag_bits": 128}},
            "wrapping_key_handle": wrapping_key,
            "key_handle": target_key,
            "associated_data": b64(&aad),
        })).await;
        assert_eq!(rw["ck_rv"].as_u64().unwrap() as u32, rv_wrap_ctl);
        assert_eq!(unb64(rw["data"].as_str().unwrap()), wrapped_ctl, "REST authenticated-wrap bytes must equal control");
        let ru = rest_post(&base, "unwrap-key-authenticated", json!({
            "session_handle": sh,
            "mechanism": {"mechanism": CKM_AES_GCM, "gcm": {"iv": b64(&iv), "aad": b64(&aad), "tag_bits": 128}},
            "unwrapping_key_handle": wrapping_key,
            "wrapped_key": b64(&wrapped_ctl),
            "template": [
                ulong_attr(CKA_CLASS, CKO_SECRET_KEY as u32),
                ulong_attr(CKA_KEY_TYPE, CKK_AES as u32),
                bool_attr(0x0162, true),
                bool_attr(CKA_TOKEN, false),
            ],
            "associated_data": b64(&aad),
        })).await;
        assert_eq!(ru["ck_rv"].as_u64().unwrap() as u32, rv_unwrap_ctl);
        let ra = rest_post(&base, "get-attribute-value", json!({"session_handle": sh, "object_handle": ru["object_handle"], "attribute_types": [CKA_VALUE]})).await;
        assert_eq!(unb64(ra["attributes"][0]["value"].as_str().unwrap()), orig_attrs[0].value, "REST unwrapped key material must equal the original");

        v32::close_session(ks);
    });
}

// G2 gap-remediation (2026-08-26) — SplitKey/JoinKey, VENDOR EXTENSION (not
// pkcs11f.h; not on the ledger's C_*-scanned RPC count). XOR split uses a
// real RNG for its shares (softhsmrustv3::crypto::split_key::split_xor), so
// unlike the KAT-style V23/V25 cases, this is NOT a byte-identical-across-
// transports check — each transport's own split->join round trip is
// verified independently to recover the original secret, same reasoning as
// V24's OAEP case.
#[test]
fn v26_split_key_xor_round_trip_parity() {
    bootstrap_once();
    rt().block_on(async {
        let (_rv, s) = v32::open_session(v32::SLOT, CKF_SERIAL_SESSION | CKF_RW_SESSION);
        let secret = b"a 32-byte secret key material!!".to_vec();
        let mk_secret_tmpl: Vec<(u64, Vec<u8>)> = vec![
            (CKA_CLASS, (CKO_SECRET_KEY as usize).to_le_bytes().to_vec()),
            (CKA_KEY_TYPE, (CKK_GENERIC_SECRET as usize).to_le_bytes().to_vec()),
            (CKA_TOKEN, vec![0u8]),
            (CKA_VALUE, secret.clone()),
        ];

        // control (in-process)
        let (rv_ctl, secret_h_ctl) = v32::create_object(s, &mk_secret_tmpl);
        assert_eq!(rv_ctl, 0);
        let (rv_split_ctl, shares_ctl) = v32::split_key::split(s, secret_h_ctl, 4, 4, 1, 0, b"\x02", "share");
        assert_eq!(rv_split_ctl, 0);
        assert_eq!(shares_ctl.len(), 4);
        let (rv_join_ctl, joined_ctl) = v32::split_key::join(s, &shares_ctl, 4, 1, 0, secret.len() as u32, b"\x03", "joined");
        assert_eq!(rv_join_ctl, 0);
        let (rv_attrs_ctl, attrs_ctl) = v32::get_attribute_value(s, joined_ctl, &[CKA_VALUE]);
        assert_eq!(rv_attrs_ctl, 0);
        assert_eq!(attrs_ctl[0].value, secret, "control: joined secret must equal the original");

        // gRPC
        let mut g = spawn_grpc_v32().await.unwrap();
        let gs = g.c_open_session(proto::V32OpenSessionRequest { slot_id: v32::SLOT, flags: CKF_SERIAL_SESSION | CKF_RW_SESSION }).await.unwrap().into_inner();
        let (_rv, secret_h_g) = v32::create_object(gs.session_handle, &mk_secret_tmpl);
        assert_eq!(_rv, 0);
        let gsplit = g.split_key(proto::V32SplitKeyRequest {
            session_handle: gs.session_handle,
            secret_handle: secret_h_g,
            parts: 4,
            threshold: 4,
            method: 1,
            polynomial: 0,
            cka_id_prefix: vec![0x02],
            label: "share".to_string(),
        }).await.unwrap().into_inner();
        assert_eq!(gsplit.ck_rv, 0);
        assert_eq!(gsplit.shares.len(), 4);
        let gjoin = g.join_key(proto::V32JoinKeyRequest {
            session_handle: gs.session_handle,
            shares: gsplit.shares,
            threshold: 4,
            method: 1,
            polynomial: 0,
            expected_len: secret.len() as u32,
            cka_id: vec![0x03],
            label: "joined".to_string(),
        }).await.unwrap().into_inner();
        assert_eq!(gjoin.ck_rv, 0);
        assert_ne!(gjoin.object_handle, 0);
        let ga = g.c_get_attribute_value(proto::V32GetAttributeValueRequest { session_handle: gs.session_handle, object_handle: gjoin.object_handle, attribute_types: vec![CKA_VALUE] }).await.unwrap().into_inner();
        assert_eq!(ga.attributes[0].value, secret, "gRPC: joined secret must equal the original");

        // REST
        let base = spawn_rest_v32().await.unwrap();
        let rs = rest_post(&base, "open-session", json!({"slot_id": v32::SLOT, "flags": CKF_SERIAL_SESSION | CKF_RW_SESSION})).await;
        let sh = rs["session_handle"].clone();
        let (_rv, secret_h_r) = v32::create_object(sh.as_u64().unwrap() as u32, &mk_secret_tmpl);
        assert_eq!(_rv, 0);
        let rsplit = rest_post(&base, "split-key", json!({
            "session_handle": sh,
            "secret_handle": secret_h_r,
            "parts": 4,
            "threshold": 4,
            "method": 1,
            "polynomial": 0,
            "cka_id_prefix": b64(&[0x02]),
            "label": "share",
        })).await;
        assert_eq!(rsplit["ck_rv"].as_u64().unwrap() as u32, 0);
        let rshares = rsplit["shares"].clone();
        assert_eq!(rshares.as_array().unwrap().len(), 4);
        let rjoin = rest_post(&base, "join-key", json!({
            "session_handle": sh,
            "shares": rshares,
            "threshold": 4,
            "method": 1,
            "polynomial": 0,
            "expected_len": secret.len() as u32,
            "cka_id": b64(&[0x03]),
            "label": "joined",
        })).await;
        assert_eq!(rjoin["ck_rv"].as_u64().unwrap() as u32, 0);
        let ra = rest_post(&base, "get-attribute-value", json!({"session_handle": sh, "object_handle": rjoin["object_handle"], "attribute_types": [CKA_VALUE]})).await;
        assert_eq!(unb64(ra["attributes"][0]["value"].as_str().unwrap()), secret, "REST: joined secret must equal the original");

        // Below-threshold join must fail with the real engine error code —
        // XOR itself has no per-share threshold check (native::join's XOR
        // arm just XORs whatever it's given; parts==threshold is enforced
        // only at split time, per §13.1), so this uses the GF256 method,
        // which DOES reject an insufficient share count. Proven identically
        // on control and gRPC (REST already proven correct-path above; the
        // negative wire path is the same MechParamBytes-free plain-JSON
        // shape, so it is not re-checked a third time here).
        let (_, gf_shares_ctl) = v32::split_key::split(s, secret_h_ctl, 5, 3, 4, 1, b"\x05", "gfshare");
        let (rv_bad_ctl, _) = v32::split_key::join(s, &gf_shares_ctl[..2], 3, 4, 1, secret.len() as u32, b"\x06", "bad");
        assert_ne!(rv_bad_ctl, 0);

        let gfsplit = g.split_key(proto::V32SplitKeyRequest {
            session_handle: gs.session_handle,
            secret_handle: secret_h_g,
            parts: 5,
            threshold: 3,
            method: 4,
            polynomial: 1,
            cka_id_prefix: vec![0x05],
            label: "gfshare".to_string(),
        }).await.unwrap().into_inner();
        assert_eq!(gfsplit.ck_rv, 0);
        let gbad = g.join_key(proto::V32JoinKeyRequest {
            session_handle: gs.session_handle,
            shares: gfsplit.shares[..2].to_vec(),
            threshold: 3,
            method: 4,
            polynomial: 1,
            expected_len: secret.len() as u32,
            cka_id: vec![0x06],
            label: "bad".to_string(),
        }).await.unwrap().into_inner();
        assert_eq!(gbad.ck_rv, rv_bad_ctl, "gRPC below-threshold rejection must match the engine's own code");

        v32::close_session(s);
    });
}

// ── V27: G3 mechanism-cell sweep — the three genuinely NEW oneof variants
// (AES-CTR, ChaCha20-Poly1305, DSA-CTX's CK_SIGN_ADDITIONAL_CONTEXT). All
// three are deterministic given fixed inputs (no OAEP/XOR-style randomness
// involved), so this is KAT-grade byte-identical parity, same as V23/V25.
// Every OTHER G3 cell (RSA/ECDSA/EdDSA/SHA3/KMAC/KCV/Profile/MultiPart/
// Fork/BIP32) reuses pre-existing raw-bytes-or-no-parameter wire code with
// zero new surface, so it is proven at the core-crate level only — a
// dedicated parity case would just re-exercise the same generic
// V32Mechanism.parameter path G1's own parity cases already cover.
#[test]
fn v27_aes_ctr_chacha20poly1305_and_dsa_ctx_structured_params_kat_parity() {
    bootstrap_once();
    rt().block_on(async {
        let (_rv, ks) = v32::open_session(v32::SLOT, CKF_SERIAL_SESSION | CKF_RW_SESSION);

        // AES-CTR
        let aes_tmpl: Vec<(u64, Vec<u8>)> = vec![
            (CKA_CLASS, (CKO_SECRET_KEY as usize).to_le_bytes().to_vec()),
            (CKA_KEY_TYPE, (CKK_AES as usize).to_le_bytes().to_vec()),
            (CKA_VALUE_LEN, (32usize).to_le_bytes().to_vec()),
            (CKA_ENCRYPT, vec![1u8]),
            (CKA_DECRYPT, vec![1u8]),
            (CKA_TOKEN, vec![0u8]),
        ];
        let (rv, aes_key) = v32::generate_key(ks, CKM_AES_KEY_GEN, &[], &aes_tmpl);
        assert_eq!(rv, 0);
        let cb = vec![0x03u8; 16];
        let ctr_pt = b"v27 AES-CTR structured-oneof KAT parity".to_vec();
        let ctr_params = pqctoday_pkcs11_remote_core::verbs_v32::cipher_params::aes_ctr(128, cb.as_slice().try_into().unwrap());
        assert_eq!(v32::encrypt_init(ks, CKM_AES_CTR, ctr_params.as_slice(), aes_key), 0);
        let (rv_ctl, ctr_ct_ctl) = v32::encrypt(ks, &ctr_pt);
        assert_eq!(rv_ctl, 0);

        let mut g = spawn_grpc_v32().await.unwrap();
        let gs = g.c_open_session(proto::V32OpenSessionRequest { slot_id: v32::SLOT, flags: CKF_SERIAL_SESSION | CKF_RW_SESSION }).await.unwrap().into_inner();
        g.c_encrypt_init(proto::V32KeyedInitRequest {
            session_handle: gs.session_handle,
            mechanism: Some(proto::V32Mechanism {
                mechanism: CKM_AES_CTR, parameter: vec![],
                structured: Some(proto::v32_mechanism::Structured::AesCtr(proto::V32AesCtrParams { counter_bits: 128, cb: cb.clone() })),
            }),
            key_handle: aes_key,
        }).await.unwrap();
        let ge = g.c_encrypt(proto::V32DataRequest { session_handle: gs.session_handle, data: ctr_pt.clone() }).await.unwrap().into_inner();
        assert_eq!(ge.ck_rv, rv_ctl);
        assert_eq!(ge.data, ctr_ct_ctl, "gRPC AES-CTR ciphertext must equal control byte-for-byte");

        let base = spawn_rest_v32().await.unwrap();
        let rs = rest_post(&base, "open-session", json!({"slot_id": v32::SLOT, "flags": CKF_SERIAL_SESSION | CKF_RW_SESSION})).await;
        let sh = rs["session_handle"].clone();
        rest_post(&base, "encrypt-init", json!({
            "session_handle": sh,
            "mechanism": {"mechanism": CKM_AES_CTR, "aes_ctr": {"counter_bits": 128, "cb": b64(&cb)}},
            "key_handle": aes_key,
        })).await;
        let re = rest_post(&base, "encrypt", json!({"session_handle": sh, "data": b64(&ctr_pt)})).await;
        assert_eq!(re["ck_rv"].as_u64().unwrap() as u32, rv_ctl);
        assert_eq!(unb64(re["data"].as_str().unwrap()), ctr_ct_ctl, "REST AES-CTR ciphertext must equal control");

        // ChaCha20-Poly1305
        let (rv, chacha_key) = v32::generate_key(ks, CKM_CHACHA20_KEY_GEN, &[], &[]);
        assert_eq!(rv, 0);
        let nonce = vec![0x04u8; 12];
        let aad = b"v27-chacha-aad".to_vec();
        let chacha_pt = b"v27 ChaCha20-Poly1305 structured-oneof KAT parity".to_vec();
        let chacha_params = pqctoday_pkcs11_remote_core::verbs_v32::cipher_params::chacha20_poly1305(&nonce, &aad);
        assert_eq!(v32::encrypt_init(ks, CKM_CHACHA20_POLY1305, chacha_params.as_slice(), chacha_key), 0);
        let (rv_ctl2, chacha_ct_ctl) = v32::encrypt(ks, &chacha_pt);
        assert_eq!(rv_ctl2, 0);

        g.c_encrypt_init(proto::V32KeyedInitRequest {
            session_handle: gs.session_handle,
            mechanism: Some(proto::V32Mechanism {
                mechanism: CKM_CHACHA20_POLY1305, parameter: vec![],
                structured: Some(proto::v32_mechanism::Structured::Chacha20Poly1305(proto::V32ChaCha20Poly1305Params { nonce: nonce.clone(), aad: aad.clone() })),
            }),
            key_handle: chacha_key,
        }).await.unwrap();
        let ge2 = g.c_encrypt(proto::V32DataRequest { session_handle: gs.session_handle, data: chacha_pt.clone() }).await.unwrap().into_inner();
        assert_eq!(ge2.ck_rv, rv_ctl2);
        assert_eq!(ge2.data, chacha_ct_ctl, "gRPC ChaCha20-Poly1305 ciphertext must equal control byte-for-byte");

        rest_post(&base, "encrypt-init", json!({
            "session_handle": sh,
            "mechanism": {"mechanism": CKM_CHACHA20_POLY1305, "chacha20_poly1305": {"nonce": b64(&nonce), "aad": b64(&aad)}},
            "key_handle": chacha_key,
        })).await;
        let re2 = rest_post(&base, "encrypt", json!({"session_handle": sh, "data": b64(&chacha_pt)})).await;
        assert_eq!(re2["ck_rv"].as_u64().unwrap() as u32, rv_ctl2);
        assert_eq!(unb64(re2["data"].as_str().unwrap()), chacha_ct_ctl, "REST ChaCha20-Poly1305 ciphertext must equal control");

        // DSA-CTX — CK_SIGN_ADDITIONAL_CONTEXT, deterministic hedge.
        let dsa_pub_tmpl: Vec<(u64, Vec<u8>)> = vec![
            (CKA_CLASS, (CKO_PUBLIC_KEY as usize).to_le_bytes().to_vec()),
            (CKA_KEY_TYPE, (CKK_ML_DSA as usize).to_le_bytes().to_vec()),
            (CKA_PARAMETER_SET, (CKP_ML_DSA_65 as usize).to_le_bytes().to_vec()),
            (CKA_VERIFY, vec![1u8]),
            (CKA_TOKEN, vec![0u8]),
        ];
        let dsa_prv_tmpl: Vec<(u64, Vec<u8>)> = vec![
            (CKA_CLASS, (CKO_PRIVATE_KEY as usize).to_le_bytes().to_vec()),
            (CKA_KEY_TYPE, (CKK_ML_DSA as usize).to_le_bytes().to_vec()),
            (CKA_PARAMETER_SET, (CKP_ML_DSA_65 as usize).to_le_bytes().to_vec()),
            (CKA_SIGN, vec![1u8]),
            (CKA_TOKEN, vec![0u8]),
        ];
        let (rv, dsa_pub, dsa_prv) = v32::generate_key_pair(ks, CKM_ML_DSA_KEY_PAIR_GEN, &[], &dsa_pub_tmpl, &dsa_prv_tmpl);
        assert_eq!(rv, 0);
        let ctx = b"v27-dsa-ctx".to_vec();
        let ctx_msg = b"v27 dsa-ctx structured-oneof KAT parity".to_vec();
        let ctx_params = pqctoday_pkcs11_remote_core::verbs_v32::sign_params::additional_context(CKH_DETERMINISTIC_REQUIRED, &ctx);
        assert_eq!(v32::sign_init(ks, CKM_ML_DSA, ctx_params.as_slice(), dsa_prv), 0);
        let (rv_ctl3, sig_ctl) = v32::sign(ks, &ctx_msg);
        assert_eq!(rv_ctl3, 0);

        g.c_sign_init(proto::V32KeyedInitRequest {
            session_handle: gs.session_handle,
            mechanism: Some(proto::V32Mechanism {
                mechanism: CKM_ML_DSA, parameter: vec![],
                structured: Some(proto::v32_mechanism::Structured::SignCtx(proto::V32SignAdditionalContextParams { hedge_variant: CKH_DETERMINISTIC_REQUIRED, context: ctx.clone() })),
            }),
            key_handle: dsa_prv,
        }).await.unwrap();
        let gsig = g.c_sign(proto::V32DataRequest { session_handle: gs.session_handle, data: ctx_msg.clone() }).await.unwrap().into_inner();
        assert_eq!(gsig.ck_rv, rv_ctl3);
        assert_eq!(gsig.data, sig_ctl, "gRPC deterministic DSA-CTX signature must equal control byte-for-byte");
        g.c_verify_init(proto::V32KeyedInitRequest {
            session_handle: gs.session_handle,
            mechanism: Some(proto::V32Mechanism {
                mechanism: CKM_ML_DSA, parameter: vec![],
                structured: Some(proto::v32_mechanism::Structured::SignCtx(proto::V32SignAdditionalContextParams { hedge_variant: CKH_DETERMINISTIC_REQUIRED, context: ctx.clone() })),
            }),
            key_handle: dsa_pub,
        }).await.unwrap();
        let gver = g.c_verify(proto::V32VerifyRequest { session_handle: gs.session_handle, data: ctx_msg.clone(), signature: sig_ctl.clone() }).await.unwrap().into_inner();
        assert_eq!(gver.ck_rv, 0);

        rest_post(&base, "sign-init", json!({
            "session_handle": sh,
            "mechanism": {"mechanism": CKM_ML_DSA, "sign_ctx": {"hedge_variant": CKH_DETERMINISTIC_REQUIRED, "context": b64(&ctx)}},
            "key_handle": dsa_prv,
        })).await;
        let rsig = rest_post(&base, "sign", json!({"session_handle": sh, "data": b64(&ctx_msg)})).await;
        assert_eq!(rsig["ck_rv"].as_u64().unwrap() as u32, rv_ctl3);
        assert_eq!(unb64(rsig["data"].as_str().unwrap()), sig_ctl, "REST deterministic DSA-CTX signature must equal control");
        rest_post(&base, "verify-init", json!({
            "session_handle": sh,
            "mechanism": {"mechanism": CKM_ML_DSA, "sign_ctx": {"hedge_variant": CKH_DETERMINISTIC_REQUIRED, "context": b64(&ctx)}},
            "key_handle": dsa_pub,
        })).await;
        let rver = rest_post(&base, "verify", json!({"session_handle": sh, "data": b64(&ctx_msg), "signature": b64(&sig_ctl)})).await;
        assert_eq!(rver["ck_rv"].as_u64().unwrap() as u32, 0);

        v32::close_session(ks);
    });
}
