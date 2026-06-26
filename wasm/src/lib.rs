//! `pqctoday-kmip-wasm` — the in-browser crypto-agile KMIP 3.0 control plane.
//!
//! WebAssembly counterpart of the native `pqctoday-kmip` server: it links the
//! **transport-free library core** (`pqctoday-kmip` with `--no-default-features`:
//! codec + kmip30/wire + dispatcher + policy + ops + in-memory `MemoryStore`)
//! against the **`softhsmrustv3` PKCS#11 v3.2 engine** — the same Rust engine
//! that compiles to the standalone in-browser HSM — with NO socket, TLS,
//! SQLite, or filesystem. All three planes are live in the browser:
//!
//! * **Plane 1 — crypto agility:** load/activate a YAML policy, and every op is
//!   gated/auto-substituted by the engine ([`KmipPlayground::load_policy`]).
//! * **Plane 2 — KMIP key management:** [`KmipPlayground::run_op`] builds a real
//!   KMIP request, dispatches it, and returns the wire response + a decoded tree.
//! * **Plane 3 — PKCS#11 execution:** the ops drive `softhsmrustv3` for real
//!   ML-DSA / ML-KEM / RSA / EC / AES crypto.
//!
//! Two entry styles:
//! * [`KmipPlayground::submit`] — raw TTLV bytes in → raw TTLV bytes out (the
//!   exact `decode → dispatch → encode` seam the TLS listener runs).
//! * [`KmipPlayground::run_op`] — a small JSON op spec the UI builds from
//!   friendly controls; returns a rich JSON result (status, summary, the real
//!   response wire bytes + decoded tree, and the audit events the op emitted).
//!
//! The native CA issuance (`Certify`/`Re-certify`) and ring-backed `Validate`
//! ops are not in this build (their crypto backends do not cross-compile to
//! wasm32); the dispatcher answers them with `OperationNotSupported`.

use std::sync::Arc;

use serde_json::{json, Value as Json};
use wasm_bindgen::prelude::*;

use pqctoday_kmip::auditlog::{AuditSink, RingSink};
use pqctoday_kmip::codec::{decode_one, TtlvFrame, Value as Ttlv};
use pqctoday_kmip::dispatcher::{dispatch, one_off_request};
use pqctoday_kmip::kmip30::{
    decode_request_message, encode_response_message, ActivateRequest, Attribute,
    BatchErrorContinuationOption, CreateKeyPairRequest, CreateRequest, DecapsulateRequest,
    DecryptRequest, DestroyRequest, EncapsulateRequest, EncryptRequest, GetRequest, KmipAlgorithm,
    LocateRequest, ObjectType, QueryFunction, QueryRequest, RequestBatchItem, RequestHeader,
    RequestMessage, RequestPayload, ResponseBatchItem, ResponseHeader, ResponseMessage,
    ResponsePayload, ResultStatus, RevocationReason, RevokeRequest, SignRequest,
    SignatureVerifyRequest, UsageMask, WireError,
};
use pqctoday_kmip::ops::{Deps, DepsConfig};
use pqctoday_kmip::policy::Engine;
use pqctoday_kmip::store::MemoryStore;

/// Built-in allow-all policy (mirrors `Engine::permissive`'s YAML) so the
/// playground starts usable; the UI swaps stricter policies in via `load_policy`.
const PERMISSIVE_YAML: &str = r#"
schema_version: 1
metadata:
  name: built-in-permissive
  description: built-in allow-all (in-browser sandbox default)
  authority: pqctoday-hsm/wasm
  effective: "always"
rules: []
"#;

/// One in-browser KMIP control plane: a policy engine, an in-memory KMIP object
/// store, an audit ring, and a live `softhsmrustv3` engine session — the exact
/// `Deps` bundle the native server builds, minus the network.
#[wasm_bindgen]
pub struct KmipPlayground {
    deps: Deps,
    /// Concrete handle on the audit ring (the `Deps.sink` is type-erased to
    /// `Arc<dyn AuditSink>`, which has no `snapshot()`); same allocation.
    ring: Arc<RingSink>,
}

#[wasm_bindgen]
impl KmipPlayground {
    /// Boot a fresh control plane: a `softhsmrustv3` token + user session on
    /// slot 0 (real crypto), the built-in permissive policy wired to the audit
    /// ring (so Plane-1 decisions are visible), and a volatile `MemoryStore`.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<KmipPlayground, JsError> {
        console_error_panic_hook::set_once();

        // Plane 3 — bootstrap the engine token + user session (real crypto).
        let session = softhsmrustv3::native::session::bootstrap_default_token(
            0, "so-pin", "1234", "pqctoday-kmip",
        )
        .map_err(|rv| JsError::new(&format!("engine bootstrap failed: CK_RV=0x{rv:08x}")))?;

        // One audit ring fans Plane 1/2/3 events; the engine writes to it too.
        let ring = Arc::new(RingSink::new(1024));
        let sink: Arc<dyn AuditSink> = ring.clone();

        // Plane 1 — start permissive (deny-all engine + activate allow-all).
        let engine = Engine::with_global_sink(sink.clone());
        let loaded = pqctoday_kmip::policy::loader::load_from_str(
            PERMISSIVE_YAML,
            std::path::Path::new("<built-in>"),
        )
        .map_err(|e| JsError::new(&format!("permissive policy parse: {e}")))?;
        engine
            .activate(loaded)
            .map_err(|e| JsError::new(&format!("permissive policy activate: {e}")))?;

        // Plane 2 — volatile object store.
        let store = Arc::new(MemoryStore::new());
        let deps = Deps::new(engine, store, sink, DepsConfig::default())
            .with_engine_session(session);

        Ok(KmipPlayground { deps, ring })
    }

    /// Raw entry: one KMIP 3.0 `Request Message` (TTLV wire bytes) → encoded
    /// `Response Message` (TTLV wire bytes). The identical decode → dispatch →
    /// encode path the TLS listener runs per connection. A wire-decode failure
    /// returns a spec-shaped error `Response Message`, never throws.
    #[wasm_bindgen]
    pub fn submit(&self, ttlv: &[u8]) -> Vec<u8> {
        let response = match decode_request_message(ttlv) {
            Ok(request) => dispatch(&self.deps, request),
            Err(err) => wire_error_response(&err),
        };
        encode_response_message(&response)
    }

    /// High-level driver the UI uses. `spec_json` is a small object the UI
    /// builds from friendly controls, e.g.:
    ///
    /// ```json
    /// {"op":"CreateKeyPair","algorithm":"ML-DSA-65"}
    /// {"op":"Activate","uid":"…"}
    /// {"op":"Sign","uid":"…","text":"hello"}
    /// {"op":"Encapsulate","uid":"…"}
    /// {"op":"Create","algorithm":"AES","length":256}
    /// ```
    ///
    /// Returns a JSON string: `{ ok, operation, status, resultReason, message,
    /// summary, responseWireHex, responseWireLen, responseTree, audit }`.
    /// `audit` is the list of Plane-1/2/3 events this op emitted.
    #[wasm_bindgen]
    pub fn run_op(&self, spec_json: &str) -> String {
        let spec: Json = match serde_json::from_str(spec_json) {
            Ok(v) => v,
            Err(e) => return error_json(&format!("invalid op spec: {e}")),
        };
        let op = spec.get("op").and_then(|v| v.as_str()).unwrap_or("");

        let payload = match build_payload(op, &spec) {
            Ok(p) => p,
            Err(e) => return error_json(&e),
        };

        let before = self.ring.len();
        let response = dispatch(&self.deps, one_off_request(payload));
        let wire = encode_response_message(&response);

        let item: &ResponseBatchItem = &response.batch_items[0];
        let status = match item.result_status {
            ResultStatus::Success => "Success",
            ResultStatus::OperationFailed => "OperationFailed",
            ResultStatus::OperationPending => "OperationPending",
            ResultStatus::OperationUndone => "OperationUndone",
        };
        let summary = item.payload.as_ref().map(summarize).unwrap_or(Json::Null);

        // Audit events this op appended (chronological tail of the ring).
        let snap = self.ring.snapshot();
        let delta: Vec<_> = snap.into_iter().skip(before).collect();

        json!({
            "ok": item.result_status == ResultStatus::Success,
            "operation": item.operation.map(|o| format!("{o:?}")),
            "status": status,
            "resultReason": item.result_reason,
            "message": item.result_message,
            "summary": summary,
            "responseWireHex": to_hex(&wire),
            "responseWireLen": wire.len(),
            "responseTree": frame_json_from_bytes(&wire),
            "audit": delta,
        })
        .to_string()
    }

    /// High-level **batch** driver: build ONE KMIP 3.0 `Request Message` carrying
    /// many operations and dispatch it through the identical decode → dispatch →
    /// encode path `submit`/`run_op` use. This is a *real* on-the-wire batch (one
    /// request, N `Batch Item`s), not N separate requests. `spec_json`:
    ///
    /// ```json
    /// {
    ///   "errorContinuation": "Stop" | "Continue" | "Undo",   // optional, default Stop
    ///   "items": [
    ///     {"op":"CreateKeyPair","intent":"sign"},
    ///     {"op":"Activate","uid":"$IDPlaceholder"},
    ///     {"op":"Sign","uid":"$IDPlaceholder","text":"hello"}
    ///   ]
    /// }
    /// ```
    ///
    /// `$IDPlaceholder` in any `uid` resolves to the UID the previous
    /// UID-producing item created (KMIP §6.4 ID Placeholder) — so Create →
    /// Activate → Sign chains in a single round trip. `errorContinuation`
    /// controls failure handling (§9.5): `Continue` runs every item, `Stop`
    /// halts after the first failure, `Undo` halts AND rolls earlier successes
    /// back (reported as `OperationUndone`).
    ///
    /// Returns `{ ok, errorContinuation, requested, returned, items[], audit,
    /// responseWireHex, responseWireLen, responseTree }` where each `items[]`
    /// entry mirrors a `run_op` result minus the wire (the wire is the one shared
    /// Response Message).
    #[wasm_bindgen]
    pub fn run_batch(&self, spec_json: &str) -> String {
        let spec: Json = match serde_json::from_str(spec_json) {
            Ok(v) => v,
            Err(e) => return error_json(&format!("invalid batch spec: {e}")),
        };
        // §9.5 Batch Error Continuation Option (absent ≡ Stop, applied downstream).
        let cont = match spec.get("errorContinuation").and_then(|v| v.as_str()) {
            Some("Continue") => Some(BatchErrorContinuationOption::Continue),
            Some("Undo") => Some(BatchErrorContinuationOption::Undo),
            Some("Stop") => Some(BatchErrorContinuationOption::Stop),
            _ => None,
        };
        let items_json = match spec.get("items").and_then(|v| v.as_array()) {
            Some(a) if !a.is_empty() => a,
            _ => return error_json("batch spec needs a non-empty \"items\" array"),
        };

        let mut batch_items = Vec::with_capacity(items_json.len());
        for it in items_json {
            let op = it.get("op").and_then(|v| v.as_str()).unwrap_or("");
            match build_payload(op, it) {
                Ok(payload) => batch_items.push(RequestBatchItem {
                    operation: payload.operation(),
                    payload,
                }),
                Err(e) => return error_json(&e),
            }
        }

        let requested = batch_items.len();
        let request = RequestMessage {
            header: RequestHeader {
                batch_error_continuation_option: cont,
                ..RequestHeader::v3()
            },
            batch_items,
        };

        let before = self.ring.len();
        let response = dispatch(&self.deps, request);
        let wire = encode_response_message(&response);

        let items_out: Vec<Json> = response
            .batch_items
            .iter()
            .map(|item| {
                let status = match item.result_status {
                    ResultStatus::Success => "Success",
                    ResultStatus::OperationFailed => "OperationFailed",
                    ResultStatus::OperationPending => "OperationPending",
                    ResultStatus::OperationUndone => "OperationUndone",
                };
                json!({
                    "ok": item.result_status == ResultStatus::Success,
                    "operation": item.operation.map(|o| format!("{o:?}")),
                    "status": status,
                    "resultReason": item.result_reason,
                    "message": item.result_message,
                    "summary": item.payload.as_ref().map(summarize).unwrap_or(Json::Null),
                })
            })
            .collect();

        let snap = self.ring.snapshot();
        let delta: Vec<_> = snap.into_iter().skip(before).collect();
        let all_ok = response
            .batch_items
            .iter()
            .all(|i| i.result_status == ResultStatus::Success);

        json!({
            "ok": all_ok,
            "errorContinuation": cont.map(|c| format!("{c:?}")).unwrap_or_else(|| "Stop".into()),
            "requested": requested,
            "returned": response.batch_items.len(),
            "items": items_out,
            "responseWireHex": to_hex(&wire),
            "responseWireLen": wire.len(),
            "responseTree": frame_json_from_bytes(&wire),
            "audit": delta,
        })
        .to_string()
    }

    /// Activate a crypto-agility policy from YAML (Plane 1). Returns
    /// `{ ok, warnings, error? }`. Subsequent ops are gated/auto-substituted
    /// by this policy until another is loaded.
    #[wasm_bindgen]
    pub fn load_policy(&self, yaml: &str) -> String {
        match pqctoday_kmip::policy::loader::load_from_str(yaml, std::path::Path::new("<wasm>")) {
            Ok(loaded) => {
                let warnings = loaded.warnings.clone();
                match self.deps.engine.activate(loaded) {
                    Ok(_) => json!({ "ok": true, "warnings": warnings }).to_string(),
                    Err(e) => json!({ "ok": false, "error": format!("{e}") }).to_string(),
                }
            }
            Err(e) => json!({ "ok": false, "error": format!("{e}") }).to_string(),
        }
    }

    /// The currently-active policy (Plane 1): `{ active, name, fingerprint,
    /// source, rules }`.
    #[wasm_bindgen]
    pub fn policy_status(&self) -> String {
        match self.deps.engine.active() {
            Some(a) => json!({
                "active": true,
                "name": a.policy.metadata.name,
                "fingerprint": a.source_fingerprint,
                "source": a.source_path,
                "rules": a.policy.rules.len(),
            })
            .to_string(),
            None => json!({ "active": false }).to_string(),
        }
    }

    /// Plane-1 "policy decision tester" (dry-run): evaluate what the active
    /// policy WOULD decide for an operation, without executing it or touching the
    /// store. Unlike the REST facade's dry-run (which uses a minimal request that
    /// can never produce a rekey or min-key-length decision), this passes the
    /// full request fields. spec:
    /// `{"op":"Sign","algorithm":"ML-DSA-65","length":?,"currentAlgorithm":"ECDSA-P256","state":"Active"}`
    /// Returns `{ kind: Allow|Deny|Rekey, algorithm?, from?, to?, rule?, reason? }`.
    #[wasm_bindgen]
    pub fn dry_run(&self, spec_json: &str) -> String {
        use pqctoday_kmip::policy::{Decision, PolicyRequest};
        let spec: Json = match serde_json::from_str(spec_json) {
            Ok(v) => v,
            Err(e) => return error_json(&format!("invalid spec: {e}")),
        };
        let s = |k: &str| spec.get(k).and_then(|v| v.as_str()).map(str::to_string);
        let op = s("op").unwrap_or_else(|| "Sign".into());
        let current = s("currentAlgorithm");
        // For an existing-object op (Sign/Encrypt) the evaluated algorithm IS the
        // stored key's algorithm — mirror how the real op sets both `algorithm`
        // and `current_object_algorithm`, so a substitution surfaces as Rekey.
        let algorithm = s("algorithm").or_else(|| current.clone());
        let state = s("state").unwrap_or_else(|| "Active".into());
        let length = spec.get("length").and_then(|v| v.as_u64()).map(|n| n as u32);
        let attrs = std::collections::HashMap::new();
        let now = time::OffsetDateTime::now_utc();

        let mut pr = PolicyRequest::minimal(&op, algorithm.as_deref(), now, "dry-run", &attrs);
        pr.key_length = length;
        pr.current_object_algorithm = current.as_deref();
        pr.state = Some(&state);
        // A non-None target makes the engine treat this as an existing object, so
        // a substitution against `currentAlgorithm` surfaces as a Rekey decision.
        if current.is_some() {
            pr.target_uid = Some("dry-run-object");
        }

        let out = match self.deps.engine.evaluate(&pr) {
            Decision::Allow { algorithm_override, substituted_by_rule, .. } => json!({
                "kind": "Allow", "algorithm": algorithm_override, "rule": substituted_by_rule,
            }),
            Decision::Deny { human, fired_rule_index, kmip_reason } => json!({
                "kind": "Deny", "reason": human, "rule": fired_rule_index,
                "denyReason": format!("{kmip_reason:?}"),
            }),
            Decision::RekeyAndProceed { from_algorithm, new_algorithm, triggered_by_rule, human, .. } => json!({
                "kind": "Rekey", "from": from_algorithm, "to": new_algorithm,
                "rule": triggered_by_rule, "reason": human,
            }),
        };
        out.to_string()
    }

    /// Every object in the KMIP store (Plane 2 keystore view) as a JSON array.
    #[wasm_bindgen]
    pub fn list_objects(&self) -> String {
        let recs = self.deps.store.find(&|_| true).unwrap_or_default();
        let arr: Vec<Json> = recs
            .iter()
            .map(|r| {
                json!({
                    "uid": r.uid,
                    "objectType": format!("{:?}", r.object_type),
                    "algorithm": r.algorithm.spec_name(),
                    "length": r.cryptographic_length,
                    "state": format!("{:?}", r.state),
                    "name": r.name,
                    "usageMask": r.usage_mask.bits(),
                    "quantumSafe": r.quantum_safe,
                })
            })
            .collect();
        serde_json::to_string(&arr).unwrap_or_else(|_| "[]".into())
    }

    /// The most recent `limit` cross-plane audit events as a JSON array
    /// (each: `{ ts, plane, correlation_id, event }`).
    #[wasm_bindgen]
    pub fn audit_snapshot(&self, limit: usize) -> String {
        let mut snap = self.ring.snapshot();
        if snap.len() > limit {
            snap = snap.split_off(snap.len() - limit);
        }
        serde_json::to_string(&snap).unwrap_or_else(|_| "[]".into())
    }

    /// Clear the audit ring (UI "reset trace" button).
    #[wasm_bindgen]
    pub fn clear_audit(&self) {
        self.ring.clear();
    }
}

/// Decode any KMIP TTLV frame (request or response wire bytes) to a JSON tree
/// the UI renders as the "wire view" and turns into plain English. Free
/// function — does not need an engine instance.
#[wasm_bindgen]
pub fn decode_ttlv(bytes: &[u8]) -> String {
    frame_json_from_bytes(bytes).to_string()
}

// ── request builders ─────────────────────────────────────────────────────────

fn build_payload(op: &str, spec: &Json) -> Result<RequestPayload, String> {
    let uid = || spec.get("uid").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let data = || spec_bytes(spec, "data", "text");

    Ok(match op {
        "Query" => RequestPayload::Query(QueryRequest {
            functions: vec![
                QueryFunction::QueryOperations,
                QueryFunction::QueryObjects,
                QueryFunction::QueryServerInformation,
            ],
        }),
        "Create" => {
            let alg = alg_from_spec(spec).unwrap_or(KmipAlgorithm::Aes);
            let mut attrs = vec![
                Attribute::CryptographicAlgorithm(alg),
                Attribute::CryptographicUsageMask(UsageMask::ENCRYPT | UsageMask::DECRYPT),
            ];
            if let Some(len) = spec.get("length").and_then(|v| v.as_u64()) {
                attrs.push(Attribute::CryptographicLength(len as u32));
            }
            RequestPayload::Create(CreateRequest {
                object_type: ObjectType::SymmetricKey,
                template_attribute: attrs,
            })
        }
        "CreateKeyPair" => {
            // `algorithm` is OPTIONAL. When omitted, we carry only a usage-mask
            // intent and let the active policy's `algorithm_default` rule choose
            // the algorithm — this is the agility path (flip policy → same op
            // resolves to a different algorithm). The dispatcher canonicalises
            // the usage mask into `CreateKeyPair:{Sign,KeyAgreement,Encrypt}`,
            // the op-string the policies key their defaults on.
            let alg = alg_from_spec(spec);
            let intent = spec.get("intent").and_then(|v| v.as_str());
            let usage = match (alg, intent) {
                (Some(a), _) if is_kem(a) => UsageMask::ENCRYPT | UsageMask::DECRYPT,
                (Some(_), _) => UsageMask::SIGN | UsageMask::VERIFY,
                (None, Some("kem")) => UsageMask::KEY_AGREEMENT, // → CreateKeyPair:KeyAgreement
                (None, Some("encrypt")) => UsageMask::ENCRYPT | UsageMask::DECRYPT,
                (None, _) => UsageMask::SIGN | UsageMask::VERIFY, // default intent = sign
            };
            let mut common = vec![Attribute::CryptographicUsageMask(usage)];
            if let Some(a) = alg {
                common.push(Attribute::CryptographicAlgorithm(a));
            }
            if let Some(len) = spec.get("length").and_then(|v| v.as_u64()) {
                common.push(Attribute::CryptographicLength(len as u32));
            }
            RequestPayload::CreateKeyPair(CreateKeyPairRequest {
                common_attributes: common,
                private_key_attributes: vec![],
                public_key_attributes: vec![],
                seed: None,
            })
        }
        "Activate" => RequestPayload::Activate(ActivateRequest { uid: uid() }),
        "Sign" => RequestPayload::Sign(SignRequest {
            uid: uid(),
            data: data(),
            cryptographic_parameters: None,
        }),
        "SignatureVerify" => RequestPayload::SignatureVerify(SignatureVerifyRequest {
            uid: uid(),
            data: data(),
            signature: spec_bytes(spec, "signature", "_"),
            cryptographic_parameters: None,
        }),
        "Encapsulate" => RequestPayload::Encapsulate(EncapsulateRequest {
            uid: uid(),
            input_key_material: None,
            cryptographic_parameters: None,
        }),
        "Decapsulate" => RequestPayload::Decapsulate(DecapsulateRequest {
            uid: uid(),
            data: spec_bytes(spec, "data", "_"),
            cryptographic_parameters: None,
        }),
        "Encrypt" => RequestPayload::Encrypt(EncryptRequest {
            uid: uid(),
            data: data(),
            iv: None,
            cryptographic_parameters: None,
            aad: None,
            init_indicator: None,
            final_indicator: None,
            correlation_value: None,
        }),
        "Decrypt" => RequestPayload::Decrypt(DecryptRequest {
            uid: uid(),
            data: spec_bytes(spec, "data", "_"),
            iv: None,
            cryptographic_parameters: None,
            aad: None,
        }),
        "Locate" => RequestPayload::Locate(LocateRequest {
            attributes: vec![],
            maximum_items: None,
            offset_items: None,
            storage_status_mask: None,
        }),
        "Get" => RequestPayload::Get(GetRequest {
            uid: uid(),
            key_format_type: None,
            key_wrapping_specification: None,
        }),
        "Revoke" => RequestPayload::Revoke(RevokeRequest {
            uid: uid(),
            reason: RevocationReason::Unspecified,
        }),
        "Destroy" => RequestPayload::Destroy(DestroyRequest { uid: uid() }),
        other => return Err(format!("unsupported op '{other}'")),
    })
}

/// Pull bytes from the spec: prefer hex-encoded `hex_key`, else UTF-8 `text_key`.
fn spec_bytes(spec: &Json, hex_key: &str, text_key: &str) -> Vec<u8> {
    if let Some(h) = spec.get(hex_key).and_then(|v| v.as_str()) {
        if let Some(b) = from_hex(h) {
            return b;
        }
    }
    if let Some(t) = spec.get(text_key).and_then(|v| v.as_str()) {
        return t.as_bytes().to_vec();
    }
    Vec::new()
}

fn alg_from_spec(spec: &Json) -> Option<KmipAlgorithm> {
    spec.get("algorithm").and_then(|v| v.as_str()).and_then(alg_from_name)
}

/// Map a KMIP spec-name string (e.g. "ML-DSA-65") to the algorithm enum.
fn alg_from_name(name: &str) -> Option<KmipAlgorithm> {
    use KmipAlgorithm::*;
    const ALL: &[KmipAlgorithm] = &[
        Aes, Rsa, Ecdsa, HmacSha256, HmacSha384, HmacSha512, Ecdh, ChaCha20, ChaCha20Poly1305,
        MlKem512, MlKem768, MlKem1024, MlDsa44, MlDsa65, MlDsa87,
        SlhDsaSha2_128s, SlhDsaSha2_128f, SlhDsaSha2_192s, SlhDsaSha2_192f, SlhDsaSha2_256s,
        SlhDsaSha2_256f, SlhDsaShake128s, SlhDsaShake128f, SlhDsaShake192s, SlhDsaShake192f,
        SlhDsaShake256s, SlhDsaShake256f,
    ];
    ALL.iter().copied().find(|a| a.spec_name().eq_ignore_ascii_case(name))
}

fn is_kem(alg: KmipAlgorithm) -> bool {
    matches!(alg, KmipAlgorithm::MlKem512 | KmipAlgorithm::MlKem768 | KmipAlgorithm::MlKem1024)
}

// ── response summary ───────────────────────────────────────────────────────────

fn summarize(payload: &ResponsePayload) -> Json {
    match payload {
        ResponsePayload::CreateKeyPair(r) => json!({
            "privateKeyUid": r.private_key_uid, "publicKeyUid": r.public_key_uid,
        }),
        ResponsePayload::Create(r) => json!({
            "uid": r.uid, "objectType": format!("{:?}", r.object_type),
        }),
        ResponsePayload::Activate(r) => json!({ "uid": r.uid, "state": format!("{:?}", r.state) }),
        ResponsePayload::Sign(r) => json!({
            "uid": r.uid, "signatureHex": to_hex(&r.signature), "signatureLen": r.signature.len(),
        }),
        ResponsePayload::SignatureVerify(r) => json!({
            "uid": r.uid, "validity": format!("{:?}", r.validity),
        }),
        ResponsePayload::Encapsulate(r) => json!({
            "uid": r.uid, "ciphertextHex": to_hex(&r.data), "ciphertextLen": r.data.len(),
        }),
        ResponsePayload::Decapsulate(r) => json!({ "uid": r.uid }),
        ResponsePayload::Encrypt(r) => json!({
            "uid": r.uid,
            "ciphertextHex": to_hex(&r.ciphertext),
            "tagHex": r.authenticated_encryption_tag.as_ref().map(|t| to_hex(t)),
            "ivHex": r.iv_counter_nonce.as_ref().map(|t| to_hex(t)),
        }),
        ResponsePayload::Decrypt(r) => json!({ "uid": r.uid, "plaintextHex": to_hex(&r.data) }),
        ResponsePayload::Locate(r) => json!({ "uids": r.uids }),
        ResponsePayload::Get(r) => json!({
            "uid": r.uid,
            "objectType": format!("{:?}", r.object_type),
            "algorithm": r.key_block.cryptographic_algorithm.spec_name(),
            "length": r.key_block.cryptographic_length,
            "keyMaterialHex": to_hex(&r.key_block.key_value),
        }),
        ResponsePayload::Query(r) => json!({
            "vendorIdentification": r.vendor_identification,
            "operationCount": r.operations.as_ref().map(|o| o.len()),
        }),
        ResponsePayload::Revoke(r) => json!({ "uid": r.uid, "state": format!("{:?}", r.state) }),
        ResponsePayload::Destroy(r) => json!({ "uid": r.uid, "state": format!("{:?}", r.state) }),
        _ => json!({}),
    }
}

// ── TTLV → JSON tree (the wire view) ────────────────────────────────────────────

fn frame_json_from_bytes(bytes: &[u8]) -> Json {
    match decode_one(bytes) {
        Ok(frame) => frame_json(&frame),
        Err(e) => json!({ "error": format!("{e:?}") }),
    }
}

/// Recursively render a TTLV frame as `{ tag, type, value?, children? }`. The
/// tag is the raw 0x42xxxx hex; the TS layer maps it to a human name + adds the
/// plain-English description (a tag dictionary is easier to maintain in data).
fn frame_json(f: &TtlvFrame) -> Json {
    let tag = format!("0x{:06X}", f.tag.0);
    match &f.value {
        Ttlv::Structure(kids) => json!({
            "tag": tag, "type": "Structure",
            "children": kids.iter().map(frame_json).collect::<Vec<_>>(),
        }),
        Ttlv::Integer(i) => json!({ "tag": tag, "type": "Integer", "value": i }),
        Ttlv::LongInteger(i) => json!({ "tag": tag, "type": "LongInteger", "value": i }),
        Ttlv::BigInteger(b) => json!({ "tag": tag, "type": "BigInteger", "value": to_hex(b) }),
        Ttlv::Enumeration(e) => json!({ "tag": tag, "type": "Enumeration", "value": format!("0x{e:08X}") }),
        Ttlv::Boolean(b) => json!({ "tag": tag, "type": "Boolean", "value": b }),
        Ttlv::TextString(s) => json!({ "tag": tag, "type": "TextString", "value": s }),
        Ttlv::ByteString(b) => json!({ "tag": tag, "type": "ByteString", "value": to_hex(b) }),
        Ttlv::DateTime(d) => json!({ "tag": tag, "type": "DateTime", "value": d }),
        Ttlv::Interval(i) => json!({ "tag": tag, "type": "Interval", "value": i }),
        Ttlv::DateTimeExtended(d) => json!({ "tag": tag, "type": "DateTimeExtended", "value": d }),
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn error_json(msg: &str) -> String {
    json!({ "ok": false, "status": "Error", "message": msg }).to_string()
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Replicates the (native-only, gated-out) `server::listener::wire_error_response`
/// so a malformed inbound frame still gets a spec-shaped KMIP error response.
fn wire_error_response(err: &WireError) -> ResponseMessage {
    use pqctoday_kmip::error::ResultReason;
    let reason = match err {
        WireError::UnsupportedVersion { .. } => ResultReason::UnsupportedProtocolVersion,
        _ => ResultReason::InvalidMessage,
    };
    ResponseMessage {
        header: ResponseHeader::v3_now(),
        batch_items: vec![ResponseBatchItem {
            operation: None,
            result_status: ResultStatus::OperationFailed,
            result_reason: Some(reason as u32),
            result_message: Some(format!("KMIP wire decode failed: {err}")),
            payload: None,
        }],
    }
}
