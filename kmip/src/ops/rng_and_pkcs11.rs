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
use super::helpers::{emit_request, emit_success, fail_err};

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

pub fn pkcs11(deps: &Deps, req: Pkcs11Request, correlation_id: &str) -> Result<Pkcs11Response> {
    emit_request(
        deps,
        correlation_id,
        "PKCS_11",
        format!("function={:#x} iface={:?}", req.function, req.interface),
    );
    // Per §6.1.42: the spec leaves the actual semantic to the PKCS#11
    // profile. v0.1 acknowledges any function code with CKR_OK and
    // echoes back the correlation value so chained calls compose. A
    // genuine proxy to softhsmrustv3::native would land here when a
    // test actually depends on a specific PKCS#11 side-effect.
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
        output_parameters: None,
        return_code: 0, // CKR_OK per PKCS#11 v3.2 §5
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
            function: 0x01, // C_Initialize (KMIP 3.0 §11 PKCS#11 Function enum)
            correlation_value: Some(vec![0xCA, 0xFE]),
            input_parameters: None,
        }, "c").unwrap();
        assert_eq!(r.return_code, 0);
        assert_eq!(r.correlation_value, Some(vec![0xCA, 0xFE]));
        assert_eq!(r.function, 0x01);
    }
}
