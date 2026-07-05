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
use pqctoday_kmip::codec::{decode_one, encode_to_vec, Tag, TtlvFrame, Value as Ttlv};
use pqctoday_kmip::dispatcher::{dispatch, one_off_request};
use pqctoday_kmip::kmip30::{
    decode_request_message, encode_request_message, encode_response_message, ActivateRequest,
    Attribute, BatchErrorContinuationOption, CreateKeyPairRequest, CreateRequest,
    DecapsulateRequest, DecryptRequest, DestroyRequest, EncapsulateRequest, EncryptRequest,
    GetRequest, KmipAlgorithm, LocateRequest, ObjectType, QueryFunction, QueryRequest,
    ReKeyKeyPairRequest, ReKeyRequest, RequestBatchItem, RequestHeader, RequestMessage,
    RequestPayload, ResponseBatchItem, ResponseHeader, ResponseMessage, ResponsePayload,
    ResultStatus, RevocationReason, RevokeRequest, SignRequest, SignatureVerifyRequest, UsageMask,
    WireError,
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
    /// `slot` (real crypto; omitted/`undefined` → slot 0, the single-tab
    /// default every existing caller uses), the built-in permissive policy
    /// wired to the audit ring (so Plane-1 decisions are visible), and a
    /// volatile `MemoryStore`.
    ///
    /// The engine's token/slot storage is a `HashMap<u32, TokenState>`
    /// (`rust/src/state.rs`), not a single fixed slot — so a second
    /// `KmipPlayground` in the SAME wasm module instance (e.g. the OASIS
    /// corpus replay booting one engine per test) needs its own slot;
    /// reusing slot 0 while an earlier instance's session on it is still
    /// open fails bootstrap (confirmed empirically: `CK_RV=0x000000b6`).
    /// The engine boots single-slot (only slot 0 pre-registered) —
    /// `state::ensure_slot` is "the multi-slot configuration surface"
    /// (its own doc comment) that brings a new slot online before
    /// `C_InitToken` will accept it; skipping this for a non-zero slot
    /// fails with `CKR_SLOT_ID_INVALID` (confirmed empirically).
    #[wasm_bindgen(constructor)]
    pub fn new(slot: Option<u32>) -> Result<KmipPlayground, JsError> {
        console_error_panic_hook::set_once();
        let slot = slot.unwrap_or(0);
        if slot != 0 {
            softhsmrustv3::state::ensure_slot(slot);
        }

        // Plane 3 — bootstrap the engine token + user session (real crypto).
        let session = softhsmrustv3::native::session::bootstrap_default_token(
            slot, "so-pin", "1234", "pqctoday-kmip",
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
    /// requestWireHex, requestWireLen, responseWireHex, responseWireLen,
    /// responseTree }` where each `items[]` entry mirrors a `run_op` result
    /// minus the wire (the wire is the one shared Request + Response Message —
    /// the actual "N operations, ONE request" proof).
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

        // Encode the REQUEST wire before `dispatch` consumes `request` — this is
        // the "ONE request, many items" proof the Batch tab shows Expert users
        // alongside the shared response (A-grade review C7).
        let request_wire = encode_request_message(&request).unwrap_or_default();

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
            "requestWireHex": to_hex(&request_wire),
            "requestWireLen": request_wire.len(),
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
    /// full request fields (WP4b: date, custom attrs, usage mask, mechanism
    /// params, and key activation date, so temporal / attribute / mechanism
    /// rules evaluate exactly like the production dispatcher path). spec:
    /// `{"op":"Sign","algorithm":"ML-DSA-65","length":?,"currentAlgorithm":"ECDSA-P256",
    ///   "state":"Active","date":"2027-06-01","attrs":{"pqctoday-purpose":"research"},
    ///   "usageMask":["Sign","Verify"],"activationDate":"2026-01-15",
    ///   "mechanism":{"hash":"SHA-256","blockMode":"GCM","padding":"OAEP",
    ///                "deterministic":true,"mech":"CKM_AES_GCM"}}`
    /// Names resolve through the SAME tables the policy loader validates against
    /// (`policy::hash_name_to_code` etc.) — never a second hand-rolled mapping.
    /// Returns `{ kind: Allow|Deny|Rekey, algorithm?, from?, to?, rule?, reason? }`.
    #[wasm_bindgen]
    pub fn dry_run(&self, spec_json: &str) -> String {
        use pqctoday_kmip::policy::{
            block_cipher_mode_name_to_code, ckm_name_to_code, hash_name_to_code,
            padding_method_name_to_code, usage_flag_name_to_bit, Decision, PolicyRequest,
        };
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

        // `date` — the simulated request clock. Absent/invalid → now (back-compat).
        let parse_day = |v: &str| -> Option<time::OffsetDateTime> {
            let p: Vec<&str> = v.split('T').next().unwrap_or(v).split('-').collect();
            if p.len() < 3 {
                return None;
            }
            let y: i32 = p[0].parse().ok()?;
            let m: u8 = p[1].parse().ok()?;
            let d: u8 = p[2].parse().ok()?;
            let date = time::Date::from_calendar_date(y, time::Month::try_from(m).ok()?, d).ok()?;
            Some(date.midnight().assume_utc())
        };
        let now = s("date")
            .as_deref()
            .and_then(parse_day)
            .unwrap_or_else(time::OffsetDateTime::now_utc);

        // `attrs` — custom x-attributes ({name: value}, x- prefix optional; the
        // engine stores bare names, loader-style).
        let attrs: std::collections::HashMap<String, String> = spec
            .get("attrs")
            .and_then(|v| v.as_object())
            .map(|o| {
                o.iter()
                    .map(|(k, v)| {
                        let name = k.strip_prefix("x-").unwrap_or(k).to_string();
                        (name, v.as_str().unwrap_or_default().to_string())
                    })
                    .collect()
            })
            .unwrap_or_default();

        let name = s("name");
        let mut pr = PolicyRequest::minimal(&op, algorithm.as_deref(), now, "dry-run", &attrs);
        pr.key_length = length;
        pr.current_object_algorithm = current.as_deref();
        pr.state = Some(&state);
        // `name` — the key label, so name_pattern rules preview correctly.
        pr.name = name.as_deref();
        // A non-None target makes the engine treat this as an existing object, so
        // a substitution against `currentAlgorithm` surfaces as a Rekey decision.
        if current.is_some() {
            pr.target_uid = Some("dry-run-object");
        }

        // `usageMask` — flag names resolved by the engine's own table. Absent →
        // None (require_usage_mask then fails closed, exactly like a Create that
        // declared no mask).
        pr.usage_mask = spec.get("usageMask").and_then(|v| v.as_array()).map(|flags| {
            flags
                .iter()
                .filter_map(|f| f.as_str())
                .filter_map(usage_flag_name_to_bit)
                .fold(UsageMask::empty(), |acc, b| acc | b)
        });

        // `activationDate` — drives max_key_age_days (age = date − activation).
        pr.object_activation_date = s("activationDate").as_deref().and_then(parse_day);

        // `mechanism` — the hash/mode/padding/deterministic/CKM dimension,
        // mapped through the same name tables the loader validates against.
        if let Some(m) = spec.get("mechanism").and_then(|v| v.as_object()) {
            let ms = |k: &str| m.get(k).and_then(|v| v.as_str());
            pr.mechanism.hashing_algorithm = ms("hash").and_then(hash_name_to_code);
            pr.mechanism.block_cipher_mode =
                ms("blockMode").and_then(block_cipher_mode_name_to_code);
            pr.mechanism.padding_method = ms("padding").and_then(padding_method_name_to_code);
            pr.mechanism.deterministic = m.get("deterministic").and_then(|v| v.as_bool());
            pr.mechanism.canonical_mech = ms("mech").and_then(ckm_name_to_code);
        }

        let (decision, trace) = self.deps.engine.evaluate_traced(&pr);
        let mut out = match decision {
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
        // Per-rule engine trace (1-based `index`) so the Hub visual simulator
        // highlights exactly what the engine did — not a re-derived guess.
        let trace_json: Vec<Json> = trace
            .iter()
            .map(|t| json!({ "index": t.index, "effect": t.effect, "note": t.note }))
            .collect();
        if let Some(obj) = out.as_object_mut() {
            obj.insert("trace".into(), Json::Array(trace_json));
        }
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
                    // Curve/size-qualified ("AES-128", "X25519", "ECDSA-P256")
                    // so the keystore UI and the policies name the same thing.
                    "algorithm": pqctoday_kmip::ops::helpers::qualified_name(
                        r.algorithm,
                        r.cryptographic_length,
                    ),
                    "length": r.cryptographic_length,
                    "state": format!("{:?}", r.state),
                    "name": r.name,
                    "usageMask": r.usage_mask.bits(),
                    // Explicit KMIP §11 attribute when the client set one;
                    // otherwise the engine's length-aware classification
                    // (AES-128 at-risk, classical asym false, PQC/hybrid true).
                    "quantumSafe": r.quantum_safe.unwrap_or_else(||
                        r.algorithm.quantum_safe_with_length(r.cryptographic_length)),
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

/// Encode a JSON tree (`{tag, type, value?, children?}` — the exact shape
/// `decode_ttlv` emits) to KMIP TTLV wire bytes. The inverse of `decode_ttlv`;
/// lets a caller build an arbitrary request by hand (any of the 66 KMIP 3.0
/// operations, not just the ones `run_op`'s friendly `build_payload` below
/// covers) and hand the resulting bytes to `submit`, which dispatches them
/// through the exact same path a real request takes. Malformed input here is
/// a caller bug (a hand-built tree or a corpus-port bug), not a KMIP-protocol
/// outcome, so it throws rather than returning the `{ok:false,...}` JSON
/// convention `dry_run`/`load_policy` use.
#[wasm_bindgen]
pub fn encode_ttlv(tree_json: &str) -> Result<Vec<u8>, JsError> {
    let node: Json =
        serde_json::from_str(tree_json).map_err(|e| JsError::new(&format!("invalid tree JSON: {e}")))?;
    let frame = frame_from_json(&node).map_err(|e| JsError::new(&e))?;
    Ok(encode_to_vec(&frame))
}

// ── generic JSON tree ⇄ TTLV frame (encode_ttlv's helpers) ───────────────────

/// Parse one `{tag, type, value?, children?}` node back into a `TtlvFrame` —
/// the inverse of `frame_json` below. Recurses into `children` for
/// `Structure` nodes.
fn frame_from_json(node: &Json) -> Result<TtlvFrame, String> {
    let tag_str = node
        .get("tag")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "node missing string \"tag\"".to_string())?;
    let item_type = node
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("tag {tag_str} missing string \"type\""))?;
    let tag = tag_from_hex(tag_str).ok_or_else(|| format!("invalid tag hex '{tag_str}'"))?;
    let value = value_from_json(item_type, node).map_err(|e| format!("tag {tag_str} ({item_type}): {e}"))?;
    Ok(TtlvFrame { tag, value })
}

/// Parse a `"0x420028"` (or bare `"420028"`) hex string into a [`Tag`].
fn tag_from_hex(s: &str) -> Option<Tag> {
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    u32::from_str_radix(s, 16).ok().and_then(Tag::new)
}

/// Parse a node's `value` (or, for `Structure`, its `children`) per the
/// declared `type` name — the 1:1 inverse of `frame_json`'s match arms below.
fn value_from_json(item_type: &str, node: &Json) -> Result<Ttlv, String> {
    if item_type == "Structure" {
        let children = node
            .get("children")
            .and_then(|v| v.as_array())
            .ok_or_else(|| "Structure node missing array \"children\"".to_string())?;
        let frames = children.iter().map(frame_from_json).collect::<Result<Vec<_>, _>>()?;
        return Ok(Ttlv::Structure(frames));
    }
    let value = node.get("value").ok_or_else(|| format!("{item_type} node missing \"value\""))?;
    match item_type {
        "Integer" => Ok(Ttlv::Integer(json_i64(value)? as i32)),
        "LongInteger" => Ok(Ttlv::LongInteger(json_i64(value)?)),
        "BigInteger" => Ok(Ttlv::BigInteger(json_hex_bytes(value)?)),
        "Enumeration" => Ok(Ttlv::Enumeration(json_enum_u32(value)?)),
        "Boolean" => value
            .as_bool()
            .map(Ttlv::Boolean)
            .ok_or_else(|| format!("Boolean value not a bool: {value}")),
        "TextString" => value
            .as_str()
            .map(|s| Ttlv::TextString(s.to_string()))
            .ok_or_else(|| format!("TextString value not a string: {value}")),
        "ByteString" => Ok(Ttlv::ByteString(json_hex_bytes(value)?)),
        "DateTime" => Ok(Ttlv::DateTime(json_i64(value)?)),
        "Interval" => Ok(Ttlv::Interval(json_i64(value)? as u32)),
        "DateTimeExtended" => Ok(Ttlv::DateTimeExtended(json_i64(value)?)),
        other => Err(format!("unknown TTLV item type '{other}'")),
    }
}

/// Numeric value, accepting either sign JSON encodes it with (`serde_json`
/// picks `u64` for non-negative numbers, `i64` otherwise).
fn json_i64(v: &Json) -> Result<i64, String> {
    v.as_i64()
        .or_else(|| v.as_u64().map(|u| u as i64))
        .ok_or_else(|| format!("expected an integer, got {v}"))
}

/// Hex-string value (ByteString/BigInteger — same convention `to_hex` below
/// produces: lowercase, no `0x` prefix).
fn json_hex_bytes(v: &Json) -> Result<Vec<u8>, String> {
    let s = v.as_str().ok_or_else(|| format!("expected a hex string, got {v}"))?;
    from_hex(s).ok_or_else(|| format!("invalid hex string '{s}'"))
}

/// Enumeration value — accepts either the `"0xNNNNNNNN"` hex string
/// `frame_json` emits (round-tripping a decoded tree) or a bare JSON number
/// (the natural form for a hand-built request template).
fn json_enum_u32(v: &Json) -> Result<u32, String> {
    if let Some(n) = v.as_u64() {
        return Ok(n as u32);
    }
    if let Some(s) = v.as_str() {
        let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
        return u32::from_str_radix(s, 16).map_err(|_| format!("invalid enumeration hex '{s}'"));
    }
    Err(format!("expected an enumeration (number or hex string), got {v}"))
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
            // H1 — a present-but-unknown algorithm name is an error, not a
            // silent fallback to AES. Absent → NO algorithm attribute, so the
            // active policy's `algorithm_default` chooses (the label-only
            // agility path — the old `unwrap_or(Aes)` fallback pinned every
            // label-only Create to bare AES and Pass 0 never fired).
            let alg = alg_from_spec_checked(spec)?;
            let mut attrs = vec![Attribute::CryptographicUsageMask(
                UsageMask::ENCRYPT | UsageMask::DECRYPT,
            )];
            if let Some(a) = alg {
                attrs.push(Attribute::CryptographicAlgorithm(a));
            }
            if let Some(len) = spec.get("length").and_then(|v| v.as_u64()) {
                attrs.push(Attribute::CryptographicLength(len as u32));
            }
            if let Some(name) = spec.get("name").and_then(|v| v.as_str()) {
                attrs.push(Attribute::Name(name.to_string()));
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
            // H1 — a present-but-unknown algorithm name is an error, not a
            // silent fall-through to the default signing keypair.
            let alg = alg_from_spec_checked(spec)?;
            let intent = spec.get("intent").and_then(|v| v.as_str());
            let usage = match (alg, intent) {
                (Some(a), _) if is_kem(a) => UsageMask::ENCRYPT | UsageMask::DECRYPT,
                // ECDH (incl. X25519/X448) is key agreement — the dispatcher
                // canonicalises this to `CreateKeyPair:KeyAgreement`.
                (Some(KmipAlgorithm::Ecdh), _) => UsageMask::KEY_AGREEMENT,
                (Some(_), _) => UsageMask::SIGN | UsageMask::VERIFY,
                (None, Some("kem")) => UsageMask::KEY_AGREEMENT, // → CreateKeyPair:KeyAgreement
                (None, Some("encrypt")) => UsageMask::ENCRYPT | UsageMask::DECRYPT,
                (None, _) => UsageMask::SIGN | UsageMask::VERIFY, // default intent = sign
            };
            let mut common = vec![Attribute::CryptographicUsageMask(usage)];
            if let Some(a) = alg {
                common.push(Attribute::CryptographicAlgorithm(a));
            }
            let explicit_len = spec.get("length").and_then(|v| v.as_u64()).map(|l| l as u32);
            let implied_len = spec
                .get("algorithm")
                .and_then(|v| v.as_str())
                .and_then(implied_length_for_name);
            if let Some(len) = explicit_len.or(implied_len) {
                common.push(Attribute::CryptographicLength(len));
            }
            if let Some(name) = spec.get("name").and_then(|v| v.as_str()) {
                common.push(Attribute::Name(name.to_string()));
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
        // `ivHex` threads the IV between the two calls of a symmetric round trip
        // (the UI carries it from Encrypt's `ivHex` response field back into
        // Decrypt's `ivHex` request field — this engine doesn't auto-generate one
        // unless the key's stored CryptographicParameters set `RandomIV=true`,
        // which the generic `Create` op above doesn't set).
        "Encrypt" => RequestPayload::Encrypt(EncryptRequest {
            uid: uid(),
            data: data(),
            iv: spec_hex_opt(spec, "ivHex"),
            cryptographic_parameters: None,
            aad: None,
            init_indicator: None,
            final_indicator: None,
            correlation_value: None,
        }),
        "Decrypt" => RequestPayload::Decrypt(DecryptRequest {
            uid: uid(),
            data: spec_bytes(spec, "data", "_"),
            iv: spec_hex_opt(spec, "ivHex"),
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
        // Substitution-aware rekey (Migration tab "Migrate all remaining"
        // sweep): the app names only the UID; the active policy decides the
        // replacement algorithm (like-for-like when it has no substitution).
        "ReKey" => RequestPayload::ReKey(ReKeyRequest {
            uid: uid(),
            offset: None,
            template_attribute: vec![],
        }),
        "ReKeyKeyPair" => RequestPayload::ReKeyKeyPair(ReKeyKeyPairRequest {
            uid: uid(),
            offset: None,
            common_attributes: vec![],
            private_key_attributes: vec![],
            public_key_attributes: vec![],
        }),
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

/// Optional hex-encoded bytes (e.g. the IV a symmetric Encrypt/Decrypt round
/// trip carries between calls — `None` when the spec omits the key, distinct
/// from `spec_bytes`' "absent → empty Vec" for required fields).
fn spec_hex_opt(spec: &Json, hex_key: &str) -> Option<Vec<u8>> {
    spec.get(hex_key).and_then(|v| v.as_str()).and_then(from_hex)
}

/// Resolve the spec's `algorithm` field, distinguishing "absent" (Ok(None) —
/// the policy-default path) from "present but not implemented" (Err) (H1).
///
/// The old silent-drop behaviour meant a spec naming an algorithm the engine
/// doesn't implement (e.g. `FrodoKEM-1344`) fell through to a default: Create
/// became an AES key and CreateKeyPair a signing keypair — so "Run for real"
/// exercised a *different* request than the UI displayed, and the policy verdict
/// shown was for the wrong request. Surfacing an error keeps Preview (which
/// dry-runs the raw string) and Run-for-real honest about each other.
fn alg_from_spec_checked(spec: &Json) -> Result<Option<KmipAlgorithm>, String> {
    match spec.get("algorithm").and_then(|v| v.as_str()) {
        None => Ok(None),
        Some(name) => alg_from_name(name).map(Some).ok_or_else(|| {
            format!("unknown algorithm '{name}' — not a KMIP spec name this engine implements")
        }),
    }
}

/// Map a KMIP spec-name string (e.g. "ML-DSA-65") to the algorithm enum.
fn alg_from_name(name: &str) -> Option<KmipAlgorithm> {
    use KmipAlgorithm::*;
    // Montgomery curves collapse to ECDH at the enum layer; the implied
    // CryptographicLength (255/448) rides separately — see
    // `implied_length_for_name`, which `build_payload` consults.
    if name.eq_ignore_ascii_case("X25519") || name.eq_ignore_ascii_case("X448") {
        return Some(Ecdh);
    }
    const ALL: &[KmipAlgorithm] = &[
        Aes, Rsa, Ecdsa, HmacSha256, HmacSha384, HmacSha512, Ecdh, Ed25519, Ed448,
        ChaCha20, ChaCha20Poly1305,
        MlKem512, MlKem768, MlKem1024, MlDsa44, MlDsa65, MlDsa87,
        SlhDsaSha2_128s, SlhDsaSha2_128f, SlhDsaSha2_192s, SlhDsaSha2_192f, SlhDsaSha2_256s,
        SlhDsaSha2_256f, SlhDsaShake128s, SlhDsaShake128f, SlhDsaShake192s, SlhDsaShake192f,
        SlhDsaShake256s, SlhDsaShake256f,
        // K6 hybrid KEMs.
        X25519MlKem768, SecP256r1MlKem768,
    ];
    ALL.iter().copied().find(|a| a.spec_name().eq_ignore_ascii_case(name))
}

/// CryptographicLength a bare algorithm NAME implies when the spec carries no
/// explicit `length` — how "X25519"/"X448" reach the dispatcher's Montgomery
/// path (and Ed25519 its §6.7 mech-info bit count) behind the coarse enum.
fn implied_length_for_name(name: &str) -> Option<u32> {
    if name.eq_ignore_ascii_case("X25519") || name.eq_ignore_ascii_case("Ed25519") {
        Some(255)
    } else if name.eq_ignore_ascii_case("X448") {
        Some(448)
    } else {
        None
    }
}

fn is_kem(alg: KmipAlgorithm) -> bool {
    matches!(alg, KmipAlgorithm::MlKem512 | KmipAlgorithm::MlKem768 | KmipAlgorithm::MlKem1024)
        || alg.is_hybrid_kem()
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
            "rekeyed": r.rekeyed.as_ref().map(|k| json!({
                "oldUid": k.old_uid,
                "newPrivateKeyUid": k.new_private_key_uid,
                "newPublicKeyUid": k.new_public_key_uid,
            })),
        }),
        ResponsePayload::SignatureVerify(r) => json!({
            "uid": r.uid, "validity": format!("{:?}", r.validity),
        }),
        ResponsePayload::Encapsulate(r) => json!({
            "uid": r.uid, "ciphertextHex": to_hex(&r.data), "ciphertextLen": r.data.len(),
            "rekeyed": r.rekeyed.as_ref().map(|k| json!({
                "oldUid": k.old_uid,
                "newPrivateKeyUid": k.new_uid,
                "newPublicKeyUid": k.new_public_key_uid,
            })),
        }),
        ResponsePayload::Decapsulate(r) => json!({ "uid": r.uid }),
        ResponsePayload::Encrypt(r) => json!({
            "uid": r.uid,
            "ciphertextHex": to_hex(&r.ciphertext),
            "tagHex": r.authenticated_encryption_tag.as_ref().map(|t| to_hex(t)),
            "ivHex": r.iv_counter_nonce.as_ref().map(|t| to_hex(t)),
            "rekeyed": r.rekeyed.as_ref().map(|k| json!({
                "oldUid": k.old_uid,
                "newUid": k.new_uid,
            })),
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
        // Sweep-driven rekey: the replacement UID(s). The new algorithm is read
        // from the keystore (list_objects) after the op — the response carries
        // only the KMIP §6.1.51/52 UIDs.
        ResponsePayload::ReKey(r) => json!({ "uid": r.uid }),
        ResponsePayload::ReKeyKeyPair(r) => json!({
            "privateKeyUid": r.private_key_uid, "publicKeyUid": r.public_key_uid,
        }),
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

#[cfg(test)]
mod encode_ttlv_tests {
    use super::*;
    use std::path::Path;

    /// Round-trip every OASIS "pristine" (placeholder-free) corpus fixture
    /// through `decode_ttlv` → `encode_ttlv` → byte-exact match. These are
    /// real, checked-in KMIP 3.0 request bytes (the same fixtures the native
    /// `oasis_request_roundtrip` encoder-fidelity test uses) — free, strong
    /// regression coverage for the new generic encoder. Runs under plain
    /// `cargo test` (this crate builds as `rlib` for exactly this reason —
    /// see the `[lib]` comment in `Cargo.toml`), no wasm host needed.
    #[test]
    fn round_trips_every_pristine_corpus_fixture() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../kmip/conformance/oasis_corpus_bytes/pristine");
        let mut checked = 0;
        for entry in std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display())) {
            let path = entry.expect("dir entry").path();
            if path.extension().and_then(|e| e.to_str()) != Some("bin") {
                continue;
            }
            let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            let tree_json = decode_ttlv(&bytes);
            let re_encoded = encode_ttlv(&tree_json)
                .unwrap_or_else(|e| panic!("encode_ttlv({}) failed: {e:?}", path.display()));
            assert_eq!(
                re_encoded,
                bytes,
                "round-trip mismatch for {}",
                path.file_name().unwrap().to_string_lossy()
            );
            checked += 1;
        }
        assert!(checked > 0, "no .bin fixtures found under {}", dir.display());
    }

    /// Same round-trip, against the much larger "stubbed" tier — every
    /// individual Request/ResponseMessage from the full 102-file OASIS
    /// corpus (1234 messages), with `$`-placeholders replaced by neutral
    /// stub values (not just the 124 already-placeholder-free "pristine"
    /// ones) — broader structural coverage of the wire format than the
    /// pristine-only check above.
    #[test]
    fn round_trips_every_stubbed_corpus_fixture() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../kmip/conformance/oasis_corpus_bytes/stubbed");
        let mut checked = 0;
        let mut failures: Vec<String> = Vec::new();
        for entry in std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display())) {
            let path = entry.expect("dir entry").path();
            if path.extension().and_then(|e| e.to_str()) != Some("bin") {
                continue;
            }
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            let tree_json = decode_ttlv(&bytes);
            match encode_ttlv(&tree_json) {
                Ok(re_encoded) if re_encoded == bytes => {}
                Ok(_) => failures.push(format!("{name}: byte mismatch")),
                Err(e) => failures.push(format!("{name}: encode_ttlv failed: {e:?}")),
            }
            checked += 1;
        }
        assert!(checked > 0, "no .bin fixtures found under {}", dir.display());
        assert!(
            failures.is_empty(),
            "{}/{checked} stubbed fixtures failed round-trip:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
}
