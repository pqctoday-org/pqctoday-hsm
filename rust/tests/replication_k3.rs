//! K3 acceptance — key attestation (plan R2.3; spec §5.1; reviews K0B-R-01..03).
#![cfg(feature = "educational-replication")]

mod replication_common;
use replication_common::*;

use der::{Decode, Encode};
use softhsmrustv3::constants::*;
use softhsmrustv3::replication::{
    self as repl,
    asn1::{Evidence, Operation},
    evidence::{verify_evidence_core, EvidenceRole},
    host_verify,
    oids::Purpose,
    pki::TrustInputs,
    Profile,
};

const CHAL: [u8; 32] = [0xc4; 32];

/// The host verifier's trust inputs, built from PUBLIC bytes only: the
/// manufacturing root plus the CRLs a host would hold.
fn host_trust(w: &World, of: usize) -> TrustInputs {
    let t = trust_of(w, of);
    TrustInputs { roots: vec![w.ca.root_der().to_vec()], crls: t.crls }
}

/// Engine-side and host-side verdicts on the same bytes must agree.
fn both(w: &World, slot: usize, ev: &[u8], role: EvidenceRole, nonce: &[u8; 32]) -> bool {
    let engine = verify_evidence_core(ev, &trust_of(w, slot), repl::now_unix(), Profile::Educational, role, nonce, None).is_ok();
    let host = verify_evidence_core(ev, &host_trust(w, slot), repl::now_unix(), Profile::Educational, role, nonce, None).is_ok();
    assert_eq!(engine, host, "engine and host verifiers disagree");
    engine
}

#[test]
fn k3_generated_and_restored_keys_report_true_history() {
    let _g = lock();
    let w = world(2);
    let (ps, pd) = policies(&w);
    for kp in ALL {
        let (src, _) = gen_key(w.tokens[0].user, kp, &ps);
        let ev = repl::attest_key(w.tokens[0].user, src, &CHAL).unwrap();
        assert!(both(&w, 0, &ev, EvidenceRole::KeyAttestation, &CHAL));
        let c = host_verify::verify_key_evidence(&ev, &host_trust(&w, 0), &CHAL, w.now, Profile::Educational).unwrap();
        assert!(c.key.local && c.key.never_extractable && c.key.sensitive && !c.key.extractable, "{kp:?}");
        assert_eq!(c.key.policy, Some(ps));
        assert!(c.key.provenance.is_none());
        assert_eq!(c.device_id, w.device_ids()[0]);
        // Restored copy on token 1: imported history plus provenance.
        let req = request(&w, 0, 1, Operation::LiveClone, &pd);
        let pkg = repl::create_replication_package(w.tokens[0].user, src, &req).unwrap();
        let (rep, _) = repl::import_replication_package(w.tokens[1].user, &pkg, &[]).unwrap();
        let ev2 = repl::attest_key(w.tokens[1].user, rep, &CHAL).unwrap();
        assert!(both(&w, 1, &ev2, EvidenceRole::KeyAttestation, &CHAL));
        let c2 = host_verify::verify_key_evidence(&ev2, &host_trust(&w, 1), &CHAL, w.now, Profile::Educational).unwrap();
        assert!(!c2.key.local && !c2.key.never_extractable && c2.key.sensitive && !c2.key.extractable, "{kp:?} restored");
        assert_eq!(c2.key.lineage, c.key.lineage);
        assert_eq!(c2.key.policy, Some(pd));
        let prov = repl::asn1::ReplicationProvenance::from_der(c2.key.provenance.as_deref().unwrap()).unwrap();
        assert_eq!(prov.source_device_id.as_bytes(), w.device_ids()[0], "provenance names the true source");
        assert_eq!(prov.source_unique_id, c.key.unique_id);
    }
}

#[test]
fn k3_refusals() {
    let _g = lock();
    let w = world(2);
    let (ps, pd) = policies(&w);
    let (k, _) = gen_key(w.tokens[0].user, Kp::MlDsa, &ps);
    let ev = repl::attest_key(w.tokens[0].user, k, &CHAL).unwrap();
    // Wrong / repeated-for-another-verifier nonce.
    assert!(!both(&w, 0, &ev, EvidenceRole::KeyAttestation, &[0xc5; 32]));
    // Wrong role (domain separation, K0B-R-01): key evidence as source/destination.
    assert!(!both(&w, 0, &ev, EvidenceRole::Source, &CHAL));
    assert!(!both(&w, 0, &ev, EvidenceRole::Destination, &CHAL));
    // Stale and future evidence.
    repl::set_clock_override(Some(w.now + 301));
    assert!(!both(&w, 0, &ev, EvidenceRole::KeyAttestation, &CHAL), "stale");
    repl::set_clock_override(Some(w.now - 120));
    assert!(verify_evidence_core(&ev, &trust_of(&w, 0), w.now - 120, Profile::Educational, EvidenceRole::KeyAttestation, &CHAL, None).is_err(), "future");
    repl::set_clock_override(Some(w.now));
    // All-zero challenge is refused at generation.
    assert_eq!(repl::attest_key(w.tokens[0].user, k, &[0; 32]), Err(CKR_ARGUMENTS_BAD));
    // Production profile rejects the documentation arc.
    assert!(verify_evidence_core(&ev, &trust_of(&w, 0), w.now, Profile::Production, EvidenceRole::KeyAttestation, &CHAL, None).is_err());
    // Untrusted chain: a verifier with a different root.
    let other = repl::test_ca::TestManufacturingCa::new(w.now).unwrap();
    let t = TrustInputs { roots: vec![other.root_der().to_vec()], crls: trust_of(&w, 0).crls };
    assert!(verify_evidence_core(&ev, &t, w.now, Profile::Educational, EvidenceRole::KeyAttestation, &CHAL, None).is_err());
    // Device substitution (K0B-R-03): swap the intermediate for token 1's device.
    let mut parsed = Evidence::from_der(&ev).unwrap();
    let dev1 = repl::pki::parse_cert(&repl::device_certificate(w.tokens[1].user).unwrap()).unwrap();
    parsed.intermediate_certificates = Some(vec![dev1]);
    assert!(!both(&w, 0, &parsed.to_der().unwrap(), EvidenceRole::KeyAttestation, &CHAL));
    // Claim tampering (e.g. a restored key claiming local generation) breaks the signature.
    let mut forged = Evidence::from_der(&ev).unwrap();
    let last = forged.tbs.reported_elements[2].claims.len() - 1;
    forged.tbs.reported_elements[2].claims.swap(0, last);
    assert!(!both(&w, 0, &forged.to_der().unwrap(), EvidenceRole::KeyAttestation, &CHAL), "non-canonical claim order");
    // Downgrade: a classical/other signature algorithm identifier.
    let mut down = Evidence::from_der(&ev).unwrap();
    down.signatures[0].signature_algorithm.oid = der::oid::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
    assert!(!both(&w, 0, &down.to_der().unwrap(), EvidenceRole::KeyAttestation, &CHAL), "ecdsa-with-SHA256 downgrade");
    // Non-canonical DER (BER long-form outer length) and oversized input.
    let mut ber = vec![0x30, 0x84];
    ber.extend_from_slice(&((ev.len() - 4) as u32).to_be_bytes());
    ber.extend_from_slice(&ev[4..]);
    assert!(!both(&w, 0, &ber, EvidenceRole::KeyAttestation, &CHAL), "BER");
    assert!(!both(&w, 0, &vec![0x30; 40 * 1024], EvidenceRole::KeyAttestation, &CHAL), "oversized");
    // Revoked attestation certificate.
    let crl = w.as_so(0, |so| repl::issue_device_crl(so, &[Purpose::KeyAttestation], 86_400).unwrap());
    let dev0 = repl::device_certificate(w.tokens[0].user).unwrap();
    w.as_so(1, |so| repl::enroll_crl(so, &crl, Some(&dev0)).unwrap());
    assert!(verify_evidence_core(&ev, &trust_of(&w, 1), w.now, Profile::Educational, EvidenceRole::KeyAttestation, &CHAL, None).is_err(), "revoked attestation key");
    let _ = pd;
}

#[test]
fn k3_destination_evidence_binds_transaction_domain_policy_and_recipient() {
    let _g = lock();
    let w = world(2);
    let (_, pd) = policies(&w);
    let chal = repl::issue_source_challenge(w.tokens[0].user).unwrap();
    let req = repl::begin_receive(w.tokens[1].user, Operation::LiveClone, &chal, &DOMAIN, &pd).unwrap();
    let r = repl::asn1::ReplicationRequest::from_der(&req).unwrap();
    let ev = r.recipient_evidence.to_der().unwrap();
    let v = verify_evidence_core(&ev, &trust_of(&w, 0), w.now, Profile::Educational, EvidenceRole::Destination, &chal, None).unwrap();
    assert_eq!(v.claims.transaction_id.unwrap(), r.transaction_id.as_bytes());
    assert_eq!(v.claims.domain_id, Some(DOMAIN));
    assert_eq!(v.claims.policy, Some(pd));
    let recovery = repl::pki::parse_cert(&repl::function_certificate(w.tokens[1].user, Purpose::RecoveryRecipient).unwrap()).unwrap();
    assert_eq!(v.claims.key.public_hash, Some(repl::pki::spki_hash(&recovery)));
    assert_eq!(v.claims.device_id, w.device_ids()[1]);
}
