//! KMIP 3.0 Group G: RNG + PKCS#11 passthrough.
//!
//! Spec mapping:
//!
//! - RNG Retrieve §6.1.54 / Tbl 418 — Data Length → Data
//! - RNG Seed     §6.1.55 / Tbl 421 — Data        → Data Length
//! - PKCS#11      §6.1.42 / Tbl 375 — PKCS#11 Function + parameters →
//!                                    PKCS#11 Function + Return Code +
//!                                    optional parameters
//!
//! v0.1 uses `rand::rngs::OsRng` for the RNG side (real CSPRNG, not a
//! stub). PKCS#11 passthrough acknowledges the request and returns
//! `CKR_OK` without actually proxying to softhsmrustv3 — the genuine
//! Plane-3 bridge for the PKCS_11 op lands when a test invokes it
//! beyond the existing Phase 7b real-bridge paths.

use rand::RngCore;

use crate::error::{KmipError, Result};
use crate::kmip30::{
    Pkcs11Request, Pkcs11Response, RngRetrieveRequest, RngRetrieveResponse, RngSeedRequest,
    RngSeedResponse,
};

use super::deps::{Deps, RngSeedMode, RNG_SEED_PARTIAL_CONSUME_CAP};
use super::helpers::{ckr_display_name, emit_pkcs11, emit_request, emit_success, fail_err};

// ── RNG Retrieve ───────────────────────────────────────────────────────────

pub fn rng_retrieve(
    deps: &Deps,
    req: RngRetrieveRequest,
    correlation_id: &str,
) -> Result<RngRetrieveResponse> {
    emit_request(deps, correlation_id, "RNGRetrieve", format!("len={}", req.data_length));
    let len = req.data_length.max(0) as usize;
    let mut data = vec![0u8; len];
    rand::rngs::OsRng.fill_bytes(&mut data);
    emit_success(deps, correlation_id, "RNGRetrieve");
    Ok(RngRetrieveResponse { data })
}

// ── RNG Seed ───────────────────────────────────────────────────────────────

pub fn rng_seed(deps: &Deps, req: RngSeedRequest, correlation_id: &str) -> Result<RngSeedResponse> {
    emit_request(deps, correlation_id, "RNGSeed", format!("seed_len={}", req.data.len()));
    // Per §6.1.55: "The server MAY elect to ignore the information
    // provided by the client and MAY indicate this to the client by
    // returning zero as the value in the Data Length response." All
    // four branches are independently spec-conformant — which one
    // fires is a server-operator choice (`--rng-seed-mode`), not
    // something the client selects per request. OsRng is already
    // seeded by the kernel; the client's bytes are accepted purely for
    // protocol conformance and never actually mixed into it, regardless
    // of mode (a future variant could feed FullConsume/PartialConsume
    // into a userspace pool).
    match deps.config.rng_seed_mode {
        RngSeedMode::FullConsume => {
            let data_length = req.data.len() as i32;
            emit_success(deps, correlation_id, "RNGSeed");
            Ok(RngSeedResponse { data_length })
        }
        RngSeedMode::PartialConsume => {
            let data_length = req.data.len().min(RNG_SEED_PARTIAL_CONSUME_CAP) as i32;
            emit_success(deps, correlation_id, "RNGSeed");
            Ok(RngSeedResponse { data_length })
        }
        RngSeedMode::Ignore => {
            emit_success(deps, correlation_id, "RNGSeed");
            Ok(RngSeedResponse { data_length: 0 })
        }
        RngSeedMode::Deny => Err(fail_err(
            deps,
            correlation_id,
            "RNGSeed",
            KmipError::permission_denied("RNGSeed: server policy denies client-supplied seed material"),
        )),
    }
}

// ── PKCS#11 passthrough ────────────────────────────────────────────────────

// KMIP 3.0 §11.39 "PKCS#11 Function Enumeration": "the 1-based offset
// count of the function in the CK_FUNCTION_LIST_3_0 structure as
// specified in [PKCS#11]". Verified directly against this repo's own
// PKCS#11 v3.2 header (`src/lib/pkcs11/pkcs11f.h`'s
// `CK_PKCS11_FUNCTION_INFO(...)` macro sequence, which the header's own
// comment says is order-significant) — PKCS#11 v3.2 only, per this
// server's scope: General-purpose functions are appended in
// declaration order, so C_Initialize=1, C_Finalize=2, C_GetInfo=3
// (later functions e.g. C_GetSlotList=5 are NOT 4 — C_GetFunctionList
// sits at ordinal 4 — deliberately not asserted here since this
// dispatch only implements the three functions the OASIS corpus
// exercises; anything else is honestly CKR_FUNCTION_NOT_SUPPORTED
// rather than a guessed ordinal).
const C_INITIALIZE: u32 = 1;
const C_FINALIZE: u32 = 2;
const C_GET_INFO: u32 = 3;

pub fn pkcs11(deps: &Deps, req: Pkcs11Request, correlation_id: &str) -> Result<Pkcs11Response> {
    emit_request(
        deps,
        correlation_id,
        "PKCS_11",
        format!("function={:#x} iface={:?}", req.function, req.interface),
    );
    // Real dispatch to softhsmrustv3, per PKCS#11 v3.2 §5 semantics —
    // NOT a blanket CKR_OK. `C_Initialize`/`C_Finalize` are handled via
    // a KMIP-server-side virtual Cryptoki-library-lifecycle flag
    // (`deps.pkcs11_virtual_initialized`) rather than the real engine's
    // own global init state: the real engine stays initialized for the
    // server's entire lifetime (every other KMIP client's crypto
    // operations depend on it), so a client-driven C_Finalize here must
    // not tear it down. `C_GetInfo` genuinely calls into the real
    // engine and returns its actual CK_INFO bytes — real identity, not
    // fabricated. Any other function code is honestly unimplemented.
    use std::sync::atomic::Ordering;
    let (return_code, output_parameters): (i32, Option<Vec<u8>>) = match req.function {
        C_INITIALIZE => {
            // PKCS#11 v3.2 §5.6: a second C_Initialize without an
            // intervening C_Finalize SHALL fail.
            let was_initialized = deps.pkcs11_virtual_initialized.swap(true, Ordering::SeqCst);
            if was_initialized {
                (softhsmrustv3::constants::CKR_CRYPTOKI_ALREADY_INITIALIZED as i32, None)
            } else {
                (softhsmrustv3::constants::CKR_OK as i32, None)
            }
        }
        C_FINALIZE => {
            let was_initialized = deps.pkcs11_virtual_initialized.swap(false, Ordering::SeqCst);
            if was_initialized {
                (softhsmrustv3::constants::CKR_OK as i32, None)
            } else {
                (softhsmrustv3::constants::CKR_CRYPTOKI_NOT_INITIALIZED as i32, None)
            }
        }
        C_GET_INFO => {
            if !deps.pkcs11_virtual_initialized.load(Ordering::SeqCst) {
                (softhsmrustv3::constants::CKR_CRYPTOKI_NOT_INITIALIZED as i32, None)
            } else if deps.engine_session.is_some() {
                // The real engine (bootstrapped at server startup, so
                // its own global init state is already true) — genuine
                // CK_INFO bytes, 72 B per PKCS#11 v3.2 §5.4.
                let mut buf = [0u8; 72];
                let rv = softhsmrustv3::C_GetInfo(buf.as_mut_ptr());
                emit_pkcs11(deps, correlation_id, "native::C_GetInfo", None, rv, &ckr_display_name(rv));
                if rv == softhsmrustv3::constants::CKR_OK {
                    (rv as i32, Some(buf.to_vec()))
                } else {
                    (rv as i32, None)
                }
            } else {
                // No real engine wired into this Deps (e.g. unit
                // tests) — nothing to honestly report; the tag is
                // optional-presence per §6.1.42, not a fabricated value.
                (softhsmrustv3::constants::CKR_OK as i32, None)
            }
        }
        _ => (softhsmrustv3::constants::CKR_FUNCTION_NOT_SUPPORTED as i32, None),
    };
    emit_success(deps, correlation_id, "PKCS_11");
    // KMIP 3.0 §6.1.42 — the server SHALL include a
    // `Correlation Value` in the response. Echo what the client
    // supplied (so chained calls share a value); generate a fresh
    // 16-byte token otherwise (the OASIS test corpus uses the
    // `$CORRELATION_VALUE` placeholder so any non-empty value is
    // accepted by the comparator).
    let cv = req.correlation_value.unwrap_or_else(|| {
        uuid::Uuid::new_v4().as_bytes().to_vec()
    });
    Ok(Pkcs11Response {
        interface: req.interface,
        function: req.function,
        correlation_value: Some(cv),
        output_parameters,
        return_code,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auditlog::{AuditSink, RingSink};
    use crate::policy::{load_from_str, Engine};
    use crate::store::MemoryStore;
    use std::sync::Arc;

    fn deps_with() -> Deps {
        let ring = Arc::new(RingSink::new(64));
        let sink: Arc<dyn AuditSink> = ring.clone();
        let engine = Engine::with_global_sink(sink.clone());
        engine.activate(load_from_str(
            "schema_version: 1\nmetadata: {name: t, description: t, authority: t, effective: always}\nrules: []\n",
            std::path::Path::new("<t>"),
        ).unwrap()).unwrap();
        Deps::new(engine, Arc::new(MemoryStore::new()), sink, super::super::deps::DepsConfig::default())
    }

    fn deps_with_rng_mode(mode: RngSeedMode) -> Deps {
        let ring = Arc::new(RingSink::new(64));
        let sink: Arc<dyn AuditSink> = ring.clone();
        let engine = Engine::with_global_sink(sink.clone());
        engine.activate(load_from_str(
            "schema_version: 1\nmetadata: {name: t, description: t, authority: t, effective: always}\nrules: []\n",
            std::path::Path::new("<t>"),
        ).unwrap()).unwrap();
        let config = super::super::deps::DepsConfig { rng_seed_mode: mode, ..Default::default() };
        Deps::new(engine, Arc::new(MemoryStore::new()), sink, config)
    }

    #[test]
    fn rng_retrieve_returns_requested_byte_count() {
        let d = deps_with();
        let r = rng_retrieve(&d, RngRetrieveRequest { data_length: 32 }, "c").unwrap();
        assert_eq!(r.data.len(), 32);
        // Two consecutive calls SHOULD give different output (sanity
        // — collision probability is 2^-256 for a working CSPRNG).
        let r2 = rng_retrieve(&d, RngRetrieveRequest { data_length: 32 }, "c").unwrap();
        assert_ne!(r.data, r2.data);
    }

    #[test]
    fn rng_retrieve_zero_length_returns_empty() {
        let d = deps_with();
        let r = rng_retrieve(&d, RngRetrieveRequest { data_length: 0 }, "c").unwrap();
        assert!(r.data.is_empty());
    }

    #[test]
    fn rng_seed_reports_consumed_bytes() {
        let d = deps_with();
        let r = rng_seed(&d, RngSeedRequest { data: vec![1, 2, 3, 4] }, "c").unwrap();
        assert_eq!(r.data_length, 4);
    }

    // §6.1.55 policy variants (CS-RNG-O-2/3/4) — Honest-Maximum Phase 2.2.

    #[test]
    fn rng_seed_full_consume_reports_all_bytes() {
        let d = deps_with_rng_mode(RngSeedMode::FullConsume);
        let r = rng_seed(&d, RngSeedRequest { data: vec![0u8; 32] }, "c").unwrap();
        assert_eq!(r.data_length, 32);
    }

    #[test]
    fn rng_seed_partial_consume_caps_at_16() {
        let d = deps_with_rng_mode(RngSeedMode::PartialConsume);
        let r = rng_seed(&d, RngSeedRequest { data: vec![0u8; 32] }, "c").unwrap();
        assert_eq!(r.data_length, 16);
        // Smaller than the cap: report the true (smaller) length, not the cap.
        let r2 = rng_seed(&d, RngSeedRequest { data: vec![0u8; 4] }, "c").unwrap();
        assert_eq!(r2.data_length, 4);
    }

    #[test]
    fn rng_seed_ignore_reports_zero() {
        let d = deps_with_rng_mode(RngSeedMode::Ignore);
        let r = rng_seed(&d, RngSeedRequest { data: vec![0u8; 32] }, "c").unwrap();
        assert_eq!(r.data_length, 0);
    }

    #[test]
    fn rng_seed_deny_returns_permission_denied() {
        let d = deps_with_rng_mode(RngSeedMode::Deny);
        let err = rng_seed(&d, RngSeedRequest { data: vec![0u8; 32] }, "c").unwrap_err();
        assert_eq!(err.result_reason(), crate::error::ResultReason::PermissionDenied);
    }

    #[test]
    fn pkcs11_passthrough_returns_ckr_ok() {
        let d = deps_with();
        let r = pkcs11(&d, Pkcs11Request {
            interface: Some("V3.0".into()),
            function: 0x01, // C_Initialize (KMIP 3.0 §11.39 PKCS#11 Function enum)
            correlation_value: Some(vec![0xCA, 0xFE]),
            input_parameters: None,
        }, "c").unwrap();
        assert_eq!(r.return_code, 0);
        assert_eq!(r.correlation_value, Some(vec![0xCA, 0xFE]));
        assert_eq!(r.function, 0x01);
    }

    fn pkcs11_req(function: u32) -> Pkcs11Request {
        Pkcs11Request {
            interface: Some("V3.2".into()),
            function,
            correlation_value: Some(vec![0xCA, 0xFE]),
            input_parameters: None,
        }
    }

    #[test]
    fn pkcs11_initialize_then_getinfo_then_finalize_round_trips() {
        let d = deps_with();
        assert_eq!(pkcs11(&d, pkcs11_req(C_INITIALIZE), "c").unwrap().return_code, 0);
        assert_eq!(pkcs11(&d, pkcs11_req(C_GET_INFO), "c").unwrap().return_code, 0);
        assert_eq!(pkcs11(&d, pkcs11_req(C_FINALIZE), "c").unwrap().return_code, 0);
    }

    #[test]
    fn pkcs11_double_initialize_without_finalize_fails() {
        let d = deps_with();
        assert_eq!(pkcs11(&d, pkcs11_req(C_INITIALIZE), "c").unwrap().return_code, 0);
        let second = pkcs11(&d, pkcs11_req(C_INITIALIZE), "c").unwrap();
        assert_eq!(second.return_code, softhsmrustv3::constants::CKR_CRYPTOKI_ALREADY_INITIALIZED as i32);
    }

    #[test]
    fn pkcs11_finalize_without_initialize_fails() {
        let d = deps_with();
        let r = pkcs11(&d, pkcs11_req(C_FINALIZE), "c").unwrap();
        assert_eq!(r.return_code, softhsmrustv3::constants::CKR_CRYPTOKI_NOT_INITIALIZED as i32);
    }

    #[test]
    fn pkcs11_get_info_before_initialize_fails() {
        let d = deps_with();
        let r = pkcs11(&d, pkcs11_req(C_GET_INFO), "c").unwrap();
        assert_eq!(r.return_code, softhsmrustv3::constants::CKR_CRYPTOKI_NOT_INITIALIZED as i32);
    }

    #[test]
    fn pkcs11_unsupported_function_returns_function_not_supported() {
        let d = deps_with();
        let r = pkcs11(&d, pkcs11_req(0xffff), "c").unwrap();
        assert_eq!(r.return_code, softhsmrustv3::constants::CKR_FUNCTION_NOT_SUPPORTED as i32);
    }

    #[test]
    fn pkcs11_finalize_allows_reinitialize() {
        let d = deps_with();
        assert_eq!(pkcs11(&d, pkcs11_req(C_INITIALIZE), "c").unwrap().return_code, 0);
        assert_eq!(pkcs11(&d, pkcs11_req(C_FINALIZE), "c").unwrap().return_code, 0);
        // A fresh C_Initialize after C_Finalize must succeed again.
        assert_eq!(pkcs11(&d, pkcs11_req(C_INITIALIZE), "c").unwrap().return_code, 0);
    }
}
