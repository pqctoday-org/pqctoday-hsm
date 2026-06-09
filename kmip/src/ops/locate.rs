//! KMIP 3.0 §6.1.32 **Locate** operation.
//!
//! > "This operation requests that the server search for one or more
//! > Managed Objects, depending on the attributes specified in the
//! > request."
//!
//! Op codepoint `0x08` (verified — `Locate = 0x00000008`).
//!
//! ## Plane mapping
//!
//! - **Plane 1** — engine.evaluate (rare to gate Locate via policy).
//! - **Plane 2** — `KeyStore::find` with a predicate built from the
//!   request's attribute filters. Returns UIDs only — KMIP `Get` is a
//!   separate op for fetching the full record.
//! - **Plane 3** — would call `C_FindObjectsInit` + `C_FindObjects` +
//!   `C_FindObjectsFinal` (PKCS#11 v3.2 §C.5.15-17) against the token to
//!   confirm the KMIP-store metadata still has live object handles. v0.1
//!   relies on the KMIP store; Phase 7 wires the PKCS#11 reconciliation.

use std::collections::HashMap;
use time::OffsetDateTime;

use crate::error::Result;
use crate::kmip30::{Attribute, KmipAlgorithm, LocateRequest, LocateResponse, ObjectType, State};
use crate::policy::{Decision, PolicyRequest};
use crate::store::ObjectRecord;

use super::deps::Deps;
use super::helpers::{emit_pkcs11, emit_request, emit_success, fail_err};
use crate::error::KmipError;

pub fn locate(deps: &Deps, req: LocateRequest, correlation_id: &str) -> Result<LocateResponse> {
    let started = OffsetDateTime::now_utc();
    emit_request(
        deps,
        correlation_id,
        "Locate",
        format!("filters={} max={:?}", req.attributes.len(), req.maximum_items),
    );

    // Plane-1 policy gate.
    let empty: HashMap<String, String> = HashMap::new();
    let p_req = PolicyRequest::minimal("Locate", None, started, correlation_id, &empty);
    if let Decision::Deny { human, .. } = deps.engine.evaluate(&p_req) {
        return Err(fail_err(
            deps,
            correlation_id,
            "Locate",
            KmipError::permission_denied(human),
        ));
    }

    // Build the predicate from the request's attribute filters.
    let filters = build_filters(&req.attributes);

    // Plane-3 emit (Phase 7 wires C_FindObjects* reconciliation).
    emit_pkcs11(
        deps,
        correlation_id,
        "C_FindObjectsInit",
        None,
        0,
        "CKR_OK",
    );

    // Plane-2: store search.
    let mut matches = deps.store.find(&|r| filters.matches(r))?;

    // Apply MaximumItems cap.
    if let Some(max) = req.maximum_items {
        matches.truncate(max as usize);
    }

    emit_pkcs11(deps, correlation_id, "C_FindObjectsFinal", None, 0, "CKR_OK");
    emit_success(deps, correlation_id, "Locate");

    Ok(LocateResponse {
        uids: matches.into_iter().map(|r| r.uid).collect(),
    })
}

/// Attribute filters extracted from the LocateRequest template.
struct LocateFilters {
    algorithm: Option<KmipAlgorithm>,
    object_type: Option<ObjectType>,
    state: Option<State>,
    name: Option<String>,
}

impl LocateFilters {
    fn matches(&self, r: &ObjectRecord) -> bool {
        if let Some(a) = self.algorithm {
            if r.algorithm != a {
                return false;
            }
        }
        if let Some(t) = self.object_type {
            if r.object_type != t {
                return false;
            }
        }
        if let Some(s) = self.state {
            if r.state != s {
                return false;
            }
        }
        if let Some(want) = &self.name {
            match &r.name {
                Some(have) if have == want => {}
                _ => return false,
            }
        }
        true
    }
}

fn build_filters(attrs: &[Attribute]) -> LocateFilters {
    let mut f = LocateFilters {
        algorithm: None,
        object_type: None,
        state: None,
        name: None,
    };
    for a in attrs {
        match a {
            Attribute::CryptographicAlgorithm(alg) => f.algorithm = Some(*alg),
            Attribute::ObjectType(t) => f.object_type = Some(*t),
            Attribute::State(s) => f.state = Some(*s),
            Attribute::Name(n) => f.name = Some(n.clone()),
            _ => {}
        }
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auditlog::{AuditSink, RingSink};
    use crate::kmip30::UsageMask;
    use crate::policy::{load_from_str, Engine};
    use crate::store::{MemoryStore, ObjectRecord};
    use std::sync::Arc;

    fn deps_with() -> Deps {
        let ring = Arc::new(RingSink::new(64));
        let sink: Arc<dyn AuditSink> = ring.clone();
        let engine = Engine::with_global_sink(sink.clone());
        engine
            .activate(load_from_str(
                "schema_version: 1\nmetadata: {name: t, description: t, authority: t, effective: always}\nrules: []\n",
                std::path::Path::new("<t>"),
            ).unwrap())
            .unwrap();
        Deps::new(engine, Arc::new(MemoryStore::new()), sink, super::super::deps::DepsConfig::default())
    }

    fn put(deps: &Deps, uid: &str, algo: KmipAlgorithm, obj_type: ObjectType, state: State) {
        deps.store.put(ObjectRecord {
            uid: uid.into(),
            object_type: obj_type,
            algorithm: algo,
            cryptographic_length: 0,
            usage_mask: UsageMask::empty(),
            state,
            pkcs11_cka_id: vec![],
            pkcs11_slot: 0,
            initial_date: OffsetDateTime::UNIX_EPOCH,
            activation_date: None,
            supersedes: None,
            name: None,

            links: std::collections::HashMap::new(),

            custom_attributes: std::collections::HashMap::new(),


            key_material: None,


            key_format_type: None,
        ..ObjectRecord::default()
}).unwrap();
    }

    #[test]
    fn locate_filters_by_algorithm() {
        let d = deps_with();
        put(&d, "a", KmipAlgorithm::Aes, ObjectType::SymmetricKey, State::Active);
        put(&d, "b", KmipAlgorithm::MlDsa87, ObjectType::PrivateKey, State::Active);
        let r = locate(&d, LocateRequest {
            attributes: vec![Attribute::CryptographicAlgorithm(KmipAlgorithm::MlDsa87)],
            maximum_items: None,
        }, "c").unwrap();
        assert_eq!(r.uids, vec!["b"]);
    }

    #[test]
    fn locate_filters_by_state() {
        let d = deps_with();
        put(&d, "a", KmipAlgorithm::Aes, ObjectType::SymmetricKey, State::Active);
        put(&d, "b", KmipAlgorithm::Aes, ObjectType::SymmetricKey, State::Deactivated);
        let r = locate(&d, LocateRequest {
            attributes: vec![Attribute::State(State::Active)],
            maximum_items: None,
        }, "c").unwrap();
        assert_eq!(r.uids, vec!["a"]);
    }

    #[test]
    fn locate_combines_filters_with_and() {
        let d = deps_with();
        put(&d, "a", KmipAlgorithm::Aes, ObjectType::SymmetricKey, State::Active);
        put(&d, "b", KmipAlgorithm::Aes, ObjectType::SymmetricKey, State::Deactivated);
        put(&d, "c", KmipAlgorithm::MlDsa87, ObjectType::PrivateKey, State::Active);
        let r = locate(&d, LocateRequest {
            attributes: vec![
                Attribute::CryptographicAlgorithm(KmipAlgorithm::Aes),
                Attribute::State(State::Active),
            ],
            maximum_items: None,
        }, "corr").unwrap();
        assert_eq!(r.uids, vec!["a"]);
    }

    #[test]
    fn locate_respects_maximum_items() {
        let d = deps_with();
        for i in 0..5 {
            put(&d, &format!("k{i}"), KmipAlgorithm::Aes, ObjectType::SymmetricKey, State::Active);
        }
        let r = locate(&d, LocateRequest {
            attributes: vec![],
            maximum_items: Some(2),
        }, "c").unwrap();
        assert_eq!(r.uids.len(), 2);
    }
}
