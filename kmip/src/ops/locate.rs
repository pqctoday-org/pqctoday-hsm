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
    if let Decision::Deny { kmip_reason, human, .. } = deps.engine.evaluate(&p_req) {
        return Err(fail_err(
            deps,
            correlation_id,
            "Locate",
            KmipError::failed(kmip_reason.to_result_reason(), human),
        ));
    }

    // Build the predicate from the request's attribute filters.
    let filters = build_filters(&req.attributes);

    // K15 — Locate searches the Plane-2 store only; no PKCS#11 call is
    // made, so no `Pkcs11Call` audit record is fabricated for it.

    // KMIP 3.0 §6.1.32 `Storage Status Mask` (§12.3 Table 608: On-line
    // 0x01, Archival 0x02, Destroyed 0x04). K22 — Archive (§6.1.4) is
    // real now, so the mask filters actual storage status: "The server
    // SHALL NOT return unique identifiers for objects that are archived
    // unless the Storage Status Mask field includes the Archived
    // Storage indicator", and "If omitted, then only on-line objects
    // SHALL be returned". (Destroyed-state tombstones keep the existing
    // state-filter behaviour in `LocateFilters::matches` — this server
    // never moves them to a separate Destroyed storage class.)
    const STORAGE_STATUS_ONLINE: u32 = 0x0000_0001;
    const STORAGE_STATUS_ARCHIVAL: u32 = 0x0000_0002;
    const STORAGE_STATUS_DESTROYED: u32 = 0x0000_0004;
    let storage_mask = req.storage_status_mask.unwrap_or(STORAGE_STATUS_ONLINE);

    // Plane-2: store search.
    let mut matches = deps.store.find(&|r| {
        // §6.1.32 storage-status gate. Destroyed / DestroyedCompromised are
        // tombstones: returned only when the client asks for them — via the
        // Destroyed storage-status bit (0x04, F-4) OR an explicit Destroyed
        // state filter (backward-compatible path). Archived objects need the
        // Archival bit; everything else is On-line.
        let storage_ok = if matches!(r.state, State::Destroyed | State::DestroyedCompromised) {
            storage_mask & STORAGE_STATUS_DESTROYED != 0
                || matches!(
                    filters.state,
                    Some(State::Destroyed) | Some(State::DestroyedCompromised)
                )
        } else if r.archived {
            storage_mask & STORAGE_STATUS_ARCHIVAL != 0
        } else {
            storage_mask & STORAGE_STATUS_ONLINE != 0
        };
        storage_ok && filters.matches(r)
    })?;

    // Plane-3 reconciliation: when a real engine is wired, drop records
    // whose PKCS#11 handle is no longer present. Guards against the
    // persistent-SQLite + volatile-engine restart case where store
    // metadata outlives the token. Runs before paging so `Offset Items`
    // and `Maximum Items` operate on live records only.
    //
    // The probe applies ONLY to records whose key bytes live exclusively
    // inside the engine (`key_material == None` — Create / CreateKeyPair,
    // see `ObjectRecord::key_material` doc). For those a vanished handle
    // is a genuine orphan: the object can no longer be served at all
    // (`Get` falls through to the engine — get.rs §"engine-held"), so
    // returning its UID from Locate would be a dangling reference.
    //
    // Records that carry their own `key_material` (Register / Import of
    // Raw symmetric keys, certificates, secret data, …) are store-backed:
    // `Get` serves them straight from the store without touching the
    // engine, so they remain valid and locatable even when no engine
    // handle exists. Many were never engine-imported in the first place
    // (e.g. AES Register has no import branch in register_import_export),
    // so probing them would spuriously drop legitimately store-only
    // objects — the Phase 7b.1 regression (OASIS BL-M-1/4/14: a freshly
    // Registered AES key vanished from its own Locate). Gating on
    // `key_material.is_none()` keeps the orphan guard sound for the
    // engine-resident case it was written for while leaving store-backed
    // objects locatable.
    if let Some(session) = deps.engine_session {
        matches.retain(|r| {
            // WP-2 remediation — a Certificate's authoritative DER lives in
            // `certificate_value` regardless of creation path (Certify
            // sets both `key_material`/`certificate_value`; Register only
            // `certificate_value`), and `Get` now reads it directly rather
            // than depending on the engine mirror (see get.rs). A
            // Certificate is therefore store-backed exactly like a
            // Register'd raw key, and probing it here was actively wrong:
            // a best-effort projection failure (der_x509 couldn't extract
            // a Subject, or the engine session was absent) would make an
            // otherwise-perfectly-servable certificate permanently
            // unlocatable.
            if r.key_material.is_some() || r.certificate_value.is_some() {
                // Store-backed: locatable regardless of engine state.
                return true;
            }
            matches!(
                super::helpers::find_handle_for_object(session, &r.pkcs11_cka_id, r.object_type),
                Ok(Some(_))
            )
        });
    }

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
    /// KMIP `Object Group` (0x420056) filter — group-membership label.
    /// An object matches when ANY of its `object_groups` memberships
    /// equals this value (Object Group is multi-instance). This is the
    /// capability behind SASED-M-3 step #0's group-membership Locate.
    object_group: Option<String>,
    /// WP-2 remediation — `Certificate Subject CN` filter (§4.6). Only
    /// meaningful against Certificate records.
    certificate_subject_cn: Option<String>,
    /// WP-2 remediation — X.509 `Certificate Issuer` filter (§4.6). Only
    /// meaningful against Certificate records.
    x509_certificate_issuer: Option<String>,
}

impl LocateFilters {
    fn matches(&self, r: &ObjectRecord) -> bool {
        // KMIP 3.0 §6.1.32 storage-status visibility (Destroyed tombstones /
        // archived objects) is decided by the `StorageStatusMask` gate in
        // `locate()` before this runs (F-4). `matches` is now purely the
        // attribute filter set.
        if let Some(a) = self.algorithm {
            // Certificate records carry a `CryptographicAlgorithm`
            // sentinel (always Rsa — see certify.rs / register_import_
            // export.rs, "never inspected" by design) since the field has
            // no real meaning for an X.509 object. Matching it as if it
            // were genuine data would make `Locate(CryptographicAlgorithm
            // =Rsa)` incorrectly return every certificate in the store;
            // skip this filter dimension for certificates entirely rather
            // than treat the sentinel as real (WP-2 remediation).
            if r.object_type != ObjectType::Certificate && r.algorithm != a {
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
        // KMIP `Object Group` membership — multi-instance, so the
        // record matches when ANY of its group labels equals the
        // requested one (AND-combined with the other filters above).
        if let Some(want_group) = &self.object_group {
            if !r.object_groups.iter().any(|g| g == want_group) {
                return false;
            }
        }
        // WP-2 remediation — Certificate-specific search dimensions, since
        // Certify/Register-created certs otherwise had no way to be found
        // by anything but UID.
        if let Some(want_cn) = &self.certificate_subject_cn {
            match &r.certificate_subject_cn {
                Some(have) if have == want_cn => {}
                _ => return false,
            }
        }
        if let Some(want_issuer) = &self.x509_certificate_issuer {
            match &r.x509_certificate_issuer {
                Some(have) if have == want_issuer => {}
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
        object_group: None,
        certificate_subject_cn: None,
        x509_certificate_issuer: None,
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
            Attribute::ObjectGroup(g) => {
                f.object_group = Some(g.clone());
            }
            Attribute::CertificateSubjectCN(cn) => {
                f.certificate_subject_cn = Some(cn.clone());
            }
            Attribute::X509CertificateIssuer(issuer) => {
                f.x509_certificate_issuer = Some(issuer.clone());
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

    /// Like `put`, but stamps the object into the given Object Group
    /// memberships (multi-instance Object Group attribute).
    fn put_groups(deps: &Deps, uid: &str, groups: &[&str]) {
        deps.store.put(ObjectRecord {
            uid: uid.into(),
            object_type: ObjectType::SecretData,
            algorithm: KmipAlgorithm::Aes,
            state: State::Active,
            initial_date: OffsetDateTime::UNIX_EPOCH,
            object_groups: groups.iter().map(|s| s.to_string()).collect(),
            ..ObjectRecord::default()
        }).unwrap();
    }

    /// P2.1 — Object Group group-membership Locate. Two objects in
    /// "G1", one in "G2": Locate by G1 returns exactly the two, by G2
    /// the one, by an unknown group nothing. This is the underlying
    /// capability behind SASED-M-3 / TL-M-3 (which stay SKIP under the
    /// hermetic replay harness's cross-transcript state wipe).
    #[test]
    fn locate_filters_by_object_group() {
        let d = deps_with();
        put_groups(&d, "a", &["G1"]);
        put_groups(&d, "b", &["G1"]);
        put_groups(&d, "c", &["G2"]);

        let mut g1 = locate(&d, LocateRequest {
            attributes: vec![Attribute::ObjectGroup("G1".into())],
            ..Default::default()
        }, "cid").unwrap().uids;
        g1.sort();
        assert_eq!(g1, vec!["a", "b"]);

        let g2 = locate(&d, LocateRequest {
            attributes: vec![Attribute::ObjectGroup("G2".into())],
            ..Default::default()
        }, "cid").unwrap().uids;
        assert_eq!(g2, vec!["c"]);

        let none = locate(&d, LocateRequest {
            attributes: vec![Attribute::ObjectGroup("nope".into())],
            ..Default::default()
        }, "cid").unwrap().uids;
        assert!(none.is_empty());
    }

    /// Multi-instance: an object in BOTH "G1" and "G2" is located by
    /// either of its memberships.
    #[test]
    fn locate_multi_group_object_found_by_either() {
        let d = deps_with();
        put_groups(&d, "multi", &["G1", "G2"]);
        for g in ["G1", "G2"] {
            let r = locate(&d, LocateRequest {
                attributes: vec![Attribute::ObjectGroup(g.into())],
                ..Default::default()
            }, "cid").unwrap();
            assert_eq!(r.uids, vec!["multi"], "should be found by group {g}");
        }
    }

    /// Object Group AND-combines with other filters: a G1 Locate that
    /// also pins ObjectType=SymmetricKey must skip a SecretData member.
    #[test]
    fn locate_object_group_and_object_type() {
        let d = deps_with();
        // "a" is SecretData in G1 (via put_groups); "b" is a SymmetricKey
        // in G1 we build by hand.
        put_groups(&d, "a", &["G1"]);
        d.store.put(ObjectRecord {
            uid: "b".into(),
            object_type: ObjectType::SymmetricKey,
            algorithm: KmipAlgorithm::Aes,
            state: State::Active,
            initial_date: OffsetDateTime::UNIX_EPOCH,
            object_groups: vec!["G1".into()],
            ..ObjectRecord::default()
        }).unwrap();
        let r = locate(&d, LocateRequest {
            attributes: vec![
                Attribute::ObjectGroup("G1".into()),
                Attribute::ObjectType(ObjectType::SymmetricKey),
            ],
            ..Default::default()
        }, "cid").unwrap();
        assert_eq!(r.uids, vec!["b"]);
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

    /// K12/K22 — §6.1.32 `Storage Status Mask`: with no archived
    /// objects, a mask without the On-line bit (0x01) matches
    /// nothing; a mask including it — or no mask — searches normally.
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

    /// Regression guard (Phase 7b.1 orphan-filter): a store-backed
    /// object — one that carries its own `key_material` (e.g. a Register
    /// of a Raw AES SymmetricKey, as in OASIS BL-M-1/4/14) — must remain
    /// locatable even when an engine session is present and the engine
    /// holds no handle for it. The orphan filter (added by 9176662)
    /// dropped EVERY record whose PKCS#11 handle was absent, wrongly
    /// removing legitimately store-only objects and regressing
    /// conformance 92→89. The `key_material.is_some()` short-circuit
    /// keeps such records present without ever probing the (here-bogus)
    /// engine session.
    #[test]
    fn locate_keeps_store_backed_object_with_engine_session_present() {
        let mut d = deps_with();
        // Simulate a real engine being wired (the conformance/default
        // server path). The session id is never dereferenced because the
        // record below carries `key_material`, so the filter short-circuits.
        d.engine_session = Some(1);

        // A Registered Raw AES key: store-backed, no engine import.
        d.store
            .put(ObjectRecord {
                uid: "store-only".into(),
                object_type: ObjectType::SymmetricKey,
                algorithm: KmipAlgorithm::Aes,
                state: State::Active,
                pkcs11_cka_id: vec![9, 9, 9],
                key_material: Some(vec![0u8; 32]),
                initial_date: OffsetDateTime::UNIX_EPOCH,
                ..ObjectRecord::default()
            })
            .unwrap();

        let r = locate(
            &d,
            LocateRequest {
                attributes: vec![Attribute::CryptographicAlgorithm(KmipAlgorithm::Aes)],
                ..Default::default()
            },
            "c",
        )
        .unwrap();
        assert_eq!(
            r.uids,
            vec!["store-only"],
            "a store-backed object must survive Locate even with an engine session present"
        );
    }

    /// K22 — §6.1.32: "The server SHALL NOT return unique identifiers
    /// for objects that are archived unless the Storage Status Mask
    /// field includes the Archived Storage indicator" + "If omitted,
    /// then only on-line objects SHALL be returned."
    #[test]
    fn locate_storage_status_mask_filters_archived_objects() {
        let d = deps_with();
        put(&d, "online", KmipAlgorithm::Aes, ObjectType::SymmetricKey, State::Active);
        put(&d, "arch", KmipAlgorithm::Aes, ObjectType::SymmetricKey, State::Active);
        let mut rec = d.store.get("arch").unwrap().unwrap();
        rec.archived = true;
        d.store.update(rec).unwrap();

        // Absent mask → On-line only: archived object excluded.
        let r = locate(&d, LocateRequest::default(), "c").unwrap();
        assert_eq!(r.uids, vec!["online"]);
        // On-line only (0x01) → archived excluded.
        let r = locate(&d, LocateRequest {
            storage_status_mask: Some(0x01),
            ..Default::default()
        }, "c").unwrap();
        assert_eq!(r.uids, vec!["online"]);
        // Archival only (0x02) → ONLY the archived object.
        let r = locate(&d, LocateRequest {
            storage_status_mask: Some(0x02),
            ..Default::default()
        }, "c").unwrap();
        assert_eq!(r.uids, vec!["arch"]);
        // Both (0x03) → both, in stable (InitialDate, UID) order.
        let r = locate(&d, LocateRequest {
            storage_status_mask: Some(0x03),
            ..Default::default()
        }, "c").unwrap();
        assert_eq!(r.uids, vec!["arch", "online"]);
    }

    /// F-4 — §6.1.32 Destroyed storage-status bit (0x04): tombstones are
    /// returned only when the mask includes the Destroyed indicator; the
    /// default On-line mask hides them.
    #[test]
    fn locate_storage_status_mask_destroyed_bit() {
        let d = deps_with();
        put(&d, "live", KmipAlgorithm::Aes, ObjectType::SymmetricKey, State::Active);
        put(&d, "dead", KmipAlgorithm::Aes, ObjectType::SymmetricKey, State::Destroyed);

        // Default (On-line) → tombstone hidden.
        let r = locate(&d, LocateRequest::default(), "c").unwrap();
        assert_eq!(r.uids, vec!["live"]);
        // Destroyed bit (0x04) alone → only the tombstone.
        let r = locate(&d, LocateRequest {
            storage_status_mask: Some(0x04),
            ..Default::default()
        }, "c").unwrap();
        assert_eq!(r.uids, vec!["dead"]);
        // On-line + Destroyed (0x05) → both, in stable (InitialDate, UID) order.
        let r = locate(&d, LocateRequest {
            storage_status_mask: Some(0x05),
            ..Default::default()
        }, "c").unwrap();
        assert_eq!(r.uids, vec!["dead", "live"]);
    }
}
