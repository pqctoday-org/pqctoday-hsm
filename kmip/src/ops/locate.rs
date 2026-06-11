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
use super::helpers::{emit_request, emit_success, fail_err};
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

    // K15 — Locate searches the Plane-2 store only; no PKCS#11 call is
    // made, so no `Pkcs11Call` audit record is fabricated for it.

    // KMIP 3.0 §6.1.32 `Storage Status Mask` (§12.3 Table 608: On-line
    // 0x01, Archival 0x02, Destroyed 0x04). Every object on this server
    // is On-line storage: Archive (§6.1.4) is acknowledged but never
    // moves bytes, so nothing is ever in Archival storage. A mask that
    // EXCLUDES the On-line bit therefore matches nothing → empty
    // response. A mask including On-line — or an absent mask, which the
    // spec defaults to On-line-only — searches normally.
    const STORAGE_STATUS_ONLINE: u32 = 0x0000_0001;
    if let Some(mask) = req.storage_status_mask {
        if mask & STORAGE_STATUS_ONLINE == 0 {
            emit_success(deps, correlation_id, "Locate");
            return Ok(LocateResponse { uids: Vec::new() });
        }
    }

    // Plane-2: store search.
    let mut matches = deps.store.find(&|r| filters.matches(r))?;

    // Paging needs a stable total order — `MemoryStore::find` iterates a
    // HashMap, so without a sort `Offset Items` would skip a *random* N.
    // Sort on (Initial Date, UID): creation order with a deterministic
    // tie-break.
    matches.sort_by(|a, b| (a.initial_date, &a.uid).cmp(&(b.initial_date, &b.uid)));

    // KMIP 3.0 §6.1.32 `Offset Items` — skip the first N matches, THEN
    // cap with `Maximum Items` (offset selects the page start, max the
    // page size).
    if let Some(off) = req.offset_items {
        let off = (off as usize).min(matches.len());
        matches = matches.split_off(off);
    }

    // Apply MaximumItems cap.
    if let Some(max) = req.maximum_items {
        matches.truncate(max as usize);
    }

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
    /// KMIP 3.0 §11 `Application Specific Information` filter —
    /// `(namespace, data)` pair. TL-M-3 step #0 finds a previously
    /// Created SymmetricKey by it.
    application_specific_information: Option<(String, String)>,
    /// KMIP 3.0 §11 `Group Link` filter — UID reference. SASED-M-3
    /// step #0 finds a previously Registered SecretData by it.
    group_link: Option<String>,
}

impl LocateFilters {
    fn matches(&self, r: &ObjectRecord) -> bool {
        // KMIP 3.0 §6.1.32 — by default Locate filters out objects in
        // the `Destroyed` / `DestroyedCompromised` states (the
        // `StorageStatusMask` default value is `Online` only). A client
        // who wants tombstones must request them explicitly via the
        // mask — not yet wired through the codec; until it is, the
        // strict default applies.
        if matches!(r.state, State::Destroyed | State::DestroyedCompromised) {
            // Override the default only when the client explicitly
            // filtered by one of those states.
            if !matches!(self.state, Some(State::Destroyed) | Some(State::DestroyedCompromised)) {
                return false;
            }
        }

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
        if let Some((ns, data)) = &self.application_specific_information {
            match &r.application_specific_information {
                Some((have_ns, have_data)) if have_ns == ns && have_data == data => {}
                _ => return false,
            }
        }
        if let Some(want_gl) = &self.group_link {
            match r.links.get("GroupLink") {
                Some(have) if have == want_gl => {}
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
        application_specific_information: None,
        group_link: None,
    };
    for a in attrs {
        match a {
            Attribute::CryptographicAlgorithm(alg) => f.algorithm = Some(*alg),
            Attribute::ObjectType(t) => f.object_type = Some(*t),
            Attribute::State(s) => f.state = Some(*s),
            Attribute::Name(n) => f.name = Some(n.clone()),
            Attribute::ApplicationSpecificInformation { namespace, data } => {
                f.application_specific_information = Some((namespace.clone(), data.clone()));
            }
            Attribute::GroupLink(uid) => {
                f.group_link = Some(uid.clone());
            }
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
        }, "c").unwrap();
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
            ..Default::default()
        }, "c").unwrap();
        assert_eq!(r.uids.len(), 2);
    }

    /// K12 — §6.1.32 `Offset Items` skips N matches before the
    /// `Maximum Items` cap: 3 objects, offset 1, max 1 → exactly the
    /// second object in the stable (InitialDate, UID) order.
    #[test]
    fn locate_offset_items_skips_then_caps() {
        let d = deps_with();
        put(&d, "a", KmipAlgorithm::Aes, ObjectType::SymmetricKey, State::Active);
        put(&d, "b", KmipAlgorithm::Aes, ObjectType::SymmetricKey, State::Active);
        put(&d, "c", KmipAlgorithm::Aes, ObjectType::SymmetricKey, State::Active);
        let r = locate(&d, LocateRequest {
            offset_items: Some(1),
            maximum_items: Some(1),
            ..Default::default()
        }, "c").unwrap();
        assert_eq!(r.uids, vec!["b"]);
        // Offset past the end → empty, not a panic.
        let r = locate(&d, LocateRequest {
            offset_items: Some(9),
            ..Default::default()
        }, "c").unwrap();
        assert!(r.uids.is_empty());
    }

    /// K12 — §6.1.32 `Storage Status Mask`: all objects are On-line
    /// (Archive is a no-op), so a mask without the On-line bit (0x01)
    /// matches nothing; a mask including it — or no mask — searches
    /// normally.
    #[test]
    fn locate_storage_status_mask_filters_storage_classes() {
        let d = deps_with();
        put(&d, "a", KmipAlgorithm::Aes, ObjectType::SymmetricKey, State::Active);
        // Archival-only (0x02) → empty.
        let r = locate(&d, LocateRequest {
            storage_status_mask: Some(0x02),
            ..Default::default()
        }, "c").unwrap();
        assert!(r.uids.is_empty());
        // On-line (0x01) → results.
        let r = locate(&d, LocateRequest {
            storage_status_mask: Some(0x01),
            ..Default::default()
        }, "c").unwrap();
        assert_eq!(r.uids, vec!["a"]);
        // Absent → spec default is On-line-only → results.
        let r = locate(&d, LocateRequest::default(), "c").unwrap();
        assert_eq!(r.uids, vec!["a"]);
    }
}
