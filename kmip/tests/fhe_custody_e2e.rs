//! FHE key custody over KMIP Operation PKCS_11, interface `PQCTODAY_FHE_1_0` (plan D02387 WP-B): the real PKCS_11
//! handler in front of a real engine token, one KMIP function per PKCS#11 call. The security officer enrols a CKKS
//! decryption policy with a signed admin request; a user generates a seed (`C_GenerateKey`), exports public material
//! (`C_DeriveKey`, `C_GetAttributeValue`, `C_DestroyObject`: byte-identical to the engine's own derive) and has a
//! ciphertext decrypted in the PKCS#11 multi-step model (`C_DecryptInit`, `C_Decrypt` size query, `C_Decrypt`); the
//! security officer then destroys the seed with a signed `destroyFheSeed`. INSECURE CKKS test ring 0x8002 only.
#![cfg(feature = "fhe-custody")]

use std::sync::Arc;

use der::Encode;
use pqctoday_kmip::auditlog::{AuditSink, RingSink};
use pqctoday_kmip::kmip30::Pkcs11Request;
use pqctoday_kmip::ops::fhe_bridge::{self, AttributeV1, DecryptInitV1, DecryptV1, DeriveKeyV1, GenerateKeyV1, GetAttributeValueV1, IFACE, ROLE_ADMIN_CN};
use pqctoday_kmip::ops::rng_and_pkcs11::pkcs11;
use pqctoday_kmip::ops::{engine_bridge, Deps, DepsConfig};
use pqctoday_kmip::policy::{load_from_str, Engine};
use pqctoday_kmip::server::auth::{AuthContext, Identity};
use pqctoday_kmip::store::MemoryStore;
use softhsmrustv3::constants::*;
use softhsmrustv3::native;
use softhsmrustv3::replication::admin::{self, AdminOperation};
use softhsmrustv3::replication::fhe_ckks::{mech, params, spec::Generator};
use softhsmrustv3::replication::test_ca::{AdminAuthorityKey, TestManufacturingCa};
use softhsmrustv3::replication::{self as repl, admin_host, fhe, host_verify, records, Profile};

const SO: &str = "so-pin-fhe-kmip";
const USER: &str = "user-pin-fhe-kmip";
const DOMAIN: [u8; 32] = [0x5a; 32];
const PS: u32 = 0x8002;
const NOW: u64 = 1_790_000_000;
const KAT_SEED: [u8; 32] = [7u8; 32];

const PERMISSIVE_POLICY: &str = r#"
schema_version: 1
metadata: { name: t, description: t, authority: t, effective: always }
rules: []
"#;

struct Lab {
    deps: Deps,
    user: u32,
    admin_key: AdminAuthorityKey,
    device_id: [u8; 32],
    replication_policy: [u8; 48],
}

/// One token on slot 0: enrolled device, function certificates, an admin authority and an FHE-profile replication
/// policy (provisioning, done directly on the engine); then a user session behind a KMIP `Deps`.
fn lab() -> Lab {
    softhsmrustv3::ffi::reset_all_engine_state_for_test();
    let _ = native::finalize();
    repl::set_clock_override(Some(NOW));
    repl::select_educational_profile();
    native::init().expect("init");
    let mut ca = TestManufacturingCa::new(NOW).expect("test root");
    native::init_token(0, SO, "fhe-kmip").expect("init token");
    let so = native::open_session_so(0, SO).expect("so session");
    native::init_pin(so, USER).expect("init pin");
    let csr = repl::begin_device_enrollment(so).expect("begin enrollment");
    let dev = ca.issue_device(&csr, NOW).expect("device cert");
    let crl = ca.crl(NOW - 10, NOW + 7 * 86_400).expect("root crl");
    repl::complete_device_enrollment(so, ca.root_der(), &dev, &crl).expect("complete enrollment");
    repl::issue_function_certificates(so).expect("function certificates");
    let admin_key = AdminAuthorityKey::new(&ca, NOW).expect("admin authority");
    admin::enroll_admin_authority(so, &admin_key.cert_der).expect("enroll admin authority");
    let device_id = repl::device_id(so).unwrap();
    let rp = records::build_policy_with_constraint(
        DOMAIN, [true, true, true], vec![device_id], NOW - 60, NOW + 30 * 86_400, 4,
        vec![CKM_PQCTODAY_FHE_DERIVE_PUBLIC, CKM_PQCTODAY_FHE_DECRYPT], false, fhe::ckks_profile_constraint_hash(),
    )
    .unwrap();
    let replication_policy = repl::enroll_policy(so, &rp).expect("enroll replication policy");
    native::logout(so).unwrap();
    native::close_session(so).unwrap();
    let user = native::open_session(0, USER).expect("user session");

    let pin_file = std::env::temp_dir().join(format!("fhe-kmip-so-pin-{}", std::process::id()));
    std::fs::write(&pin_file, SO).unwrap();
    engine_bridge::configure_admin(pin_file, 0);
    fhe_bridge::enable();

    let sink: Arc<dyn AuditSink> = Arc::new(RingSink::new(64));
    let policy_engine = Engine::with_global_sink(sink.clone());
    policy_engine.replace_all(load_from_str(PERMISSIVE_POLICY, std::path::Path::new("<e2e>")).unwrap()).unwrap();
    let deps = Deps::new(policy_engine, Arc::new(MemoryStore::new()), sink, DepsConfig::default()).with_engine_session(user);
    Lab { deps, user, admin_key, device_id, replication_policy }
}

fn auth(cn: Option<&str>) -> AuthContext {
    AuthContext { identity: cn.map(|c| Identity { username: c.to_string() }) }
}

/// One KMIP PKCS_11 request on the FHE interface; returns (return code, output).
fn call(lab: &Lab, cn: Option<&str>, function: u32, input: &[u8]) -> (u32, Vec<u8>) {
    let req = Pkcs11Request { interface: Some(IFACE.into()), function, correlation_value: None, input_parameters: Some(input.to_vec()) };
    let resp = pkcs11(&lab.deps, req, &auth(cn), "fhe-e2e").expect("PKCS_11 response");
    assert_eq!(resp.interface.as_deref(), Some(IFACE));
    (resp.return_code as u32, resp.output_parameters.unwrap_or_default())
}

fn ckks_policy() -> Vec<u8> {
    let ps = params::find(PS).unwrap();
    fhe::FheDecryptPolicy {
        version: 2,
        allowed_output_types: vec![mech::release_type(ps)],
        never_release: vec![],
        predicates: vec![],
        recipients: vec![],
        recipient_only: false,
        max_decrypts: 2,
        ckks: Some(fhe::CkksReleasePolicy { max_values: (ps.n() / 2) as u32, precision_bits: 20, value_bound_log2: 10, scale_log2: ps.log_default_scale as u8, flood_recipients: true, flood_owner: false, stat_security_bits: 30 }),
    }
    .to_der()
    .unwrap()
}

/// SO over KMIP: nonce (function 7), then the signed request (function 8). Returns (request, result).
fn admin_over_kmip(lab: &Lab, seq: u64, op: &AdminOperation) -> (Vec<u8>, (u32, Vec<u8>)) {
    let (rv, nonce) = call(lab, Some(ROLE_ADMIN_CN), 7, b"");
    assert_eq!(rv, CKR_OK, "AdminIssueNonce");
    let nonce: [u8; 32] = nonce.try_into().expect("32-byte nonce");
    let tbs = admin_host::tbs_request(&lab.device_id, &lab.admin_key.key_id(), &nonce, seq, NOW, op).unwrap();
    let sig = lab.admin_key.sign(&admin_host::request_signed_bytes(&tbs)).unwrap();
    let req = admin_host::signed_request(&tbs, &sig).unwrap();
    let r = call(lab, Some(ROLE_ADMIN_CN), 8, &req);
    (req, r)
}

fn utf8(uid: &[u8]) -> der::asn1::Utf8StringRef<'_> {
    der::asn1::Utf8StringRef::new(std::str::from_utf8(uid).unwrap()).unwrap()
}

fn octets(b: &[u8]) -> der::asn1::OctetString {
    der::asn1::OctetString::new(b.to_vec()).unwrap()
}

/// `C_GetAttributeValue` over KMIP: (return code, the template as returned).
fn get_attrs(lab: &Lab, uid: &[u8], types: &[u32]) -> (u32, Vec<AttributeV1>) {
    let q = GetAttributeValueV1 { object: utf8(uid), types: types.to_vec() }.to_der().unwrap();
    let (rv, out) = call(lab, None, 3, &q);
    let attrs = if out.is_empty() { Vec::new() } else { repl::asn1::decode_strict(&out, 16 << 20).unwrap() };
    (rv, attrs)
}

/// The export sequence over KMIP: `C_DeriveKey` → `C_GetAttributeValue(CKA_VALUE)` → `C_DestroyObject`.
fn export_over_kmip(lab: &Lab, base: &[u8], kind: u32, from: u64, to: u64) -> Vec<u8> {
    let d = DeriveKeyV1 { base_key: utf8(base), version: 2, kind, key: 0, digit: 0, from_limb: from, to_limb: to }.to_der().unwrap();
    let (rv, obj) = call(lab, None, 2, &d);
    assert_eq!(rv, CKR_OK, "C_DeriveKey kind {kind}");
    assert_eq!(obj.len(), 36);
    let (rv, attrs) = get_attrs(lab, &obj, &[CKA_VALUE]);
    assert_eq!(rv, CKR_OK, "C_GetAttributeValue");
    let value = attrs[0].value.as_ref().expect("CKA_VALUE").as_bytes().to_vec();
    assert_eq!(call(lab, None, 4, &obj).0, CKR_OK, "C_DestroyObject");
    assert_eq!(get_attrs(lab, &obj, &[CKA_VALUE]).0, 0x60, "the public object is gone");
    value
}

/// The engine's own derive, as the custodian CLI does it: derive, read CKA_VALUE, destroy.
fn derive_direct(s: u32, seed: u32, kind: u32, from: usize, to: usize) -> Vec<u8> {
    let h = mech::derive_public_v2(s, seed, kind, 0, 0, from, to).expect("derive");
    let v = native::get_attribute(s, h, CKA_VALUE).unwrap();
    assert_eq!(softhsmrustv3::ffi::C_DestroyObject(s, h), CKR_OK);
    v
}

/// Header ‖ c0 limbs ‖ c1 limbs (the oracle's ciphertext layout).
fn ct_bytes(ps_id: u32, level: u32, scale: u32, c0: &[u64], c1: &[u64]) -> Vec<u8> {
    let mut b = mech::CT_MAGIC.to_vec();
    for v in [ps_id, level, scale, 0] {
        b.extend_from_slice(&v.to_le_bytes());
    }
    for v in c0.iter().chain(c1) {
        b.extend_from_slice(&v.to_le_bytes());
    }
    b
}

/// Deterministic plaintext coefficients below 2^bound_log2 (the engine's CKKS tests use the same generator).
fn plaintext(n: usize, bound_log2: u32) -> Vec<i128> {
    let mut x = 0x9e37_79b9_7f4a_7c15u64;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let v = (x as i64) as i128;
            if bound_log2 >= 63 { v << (bound_log2 - 63) } else { v >> (63 - bound_log2) }
        })
        .collect()
}

/// Precision (−log2 of the largest real or imaginary error) of an owner release against `want`.
fn release_precision(out: &[u8], want: &[(f64, f64)]) -> f64 {
    assert_eq!(out[0], mech::OUT_TYPE);
    let unit = (out[1] as f64).exp2();
    let cnt = u16::from_be_bytes([out[2], out[3]]) as usize;
    assert_eq!((cnt, out.len()), (want.len(), 4 + 16 * cnt));
    let mut m = 0f64;
    for (i, &(re, im)) in want.iter().enumerate() {
        let r = i64::from_le_bytes(out[4 + 16 * i..12 + 16 * i].try_into().unwrap()) as f64 / unit;
        let j = i64::from_le_bytes(out[12 + 16 * i..20 + 16 * i].try_into().unwrap()) as f64 / unit;
        m = m.max((r - re).abs()).max((j - im).abs());
    }
    -m.log2()
}

fn decrypt_init_der(uid: &[u8]) -> Vec<u8> {
    DecryptInitV1 { key: utf8(uid), recipient: octets(&[0u8; 48]) }.to_der().unwrap()
}

fn decrypt_der(ct: &[u8], output_len: u64) -> Vec<u8> {
    DecryptV1 { ciphertext: octets(ct), output_len }.to_der().unwrap()
}

#[test]
fn fhe_custody_over_kmip_end_to_end() {
    let lab = lab();
    let pol = ckks_policy();

    // ── SO: signed enrolment of the decryption policy, over KMIP ──
    let (req, (rv, receipt)) = admin_over_kmip(&lab, 1, &AdminOperation::EnrollFheDecryptPolicy { policy: pol.clone() });
    assert_eq!(rv, CKR_OK, "enrollFheDecryptPolicy over KMIP");
    let view = host_verify::verify_admin_receipt(&receipt, &req, &repl::trust_inputs(0), NOW, Profile::Educational).expect("receipt verifies");
    let dpid: [u8; 48] = view.output.clone().expect("policy ID in the receipt").try_into().unwrap();
    // Other admin operations are not served by the FHE interface, and a user identity cannot reach the SO functions.
    let other = AdminOperation::EnrollPolicy { policy: vec![0x30, 0x00] };
    assert_eq!(admin_over_kmip(&lab, 2, &other).1 .0, CKR_FUNCTION_NOT_SUPPORTED);
    assert_eq!(call(&lab, Some("tenant-a"), 7, b"").0, CKR_USER_TYPE_INVALID);
    assert_eq!(call(&lab, None, 8, &req).0, CKR_USER_TYPE_INVALID);

    // ── User: C_GenerateKey over KMIP, then C_GetAttributeValue on the seed ──
    let gen_der = GenerateKeyV1 {
        param_set: PS,
        replication_policy_id: octets(&lab.replication_policy),
        decrypt_policy_id: octets(&dpid),
        label: octets(b"kmip seed"),
        id: octets(b"kmip-seed"),
    }
    .to_der()
    .unwrap();
    let (rv, uid) = call(&lab, None, 1, &gen_der);
    assert_eq!(rv, CKR_OK, "C_GenerateKey");
    assert_eq!(uid.len(), 36);
    let (rv, attrs) = get_attrs(&lab, &uid, &[CKA_PQCTODAY_FHE_PARAM_SET, CKA_PQCTODAY_FHE_DECRYPT_POLICY, CKA_PQCTODAY_FHE_LINEAGE_ID, CKA_VALUE]);
    assert_eq!(rv, CKR_ATTRIBUTE_SENSITIVE, "the seed value is sensitive; the rest of the template is still returned");
    let v = |i: usize| attrs[i].value.as_ref().map(|o| o.as_bytes().to_vec());
    assert_eq!(v(0).map(|b| u32::from_le_bytes(b[..4].try_into().unwrap())), Some(PS));
    assert_eq!(v(1).as_deref(), Some(&dpid[..]));
    let lineage: [u8; 32] = v(2).expect("lineage").try_into().unwrap();
    assert_eq!(v(3), None, "CK_UNAVAILABLE_INFORMATION for CKA_VALUE");
    // The SO identity cannot use the user functions. The seed is not destroyable (CKA_DESTROYABLE = FALSE), so the
    // token refuses the normal user's C_DestroyObject.
    assert_eq!(call(&lab, Some(ROLE_ADMIN_CN), 4, &uid).0, CKR_USER_TYPE_INVALID);
    let (rv, d) = get_attrs(&lab, &uid, &[CKA_DESTROYABLE]);
    assert_eq!((rv, d[0].value.as_ref().map(|o| o.as_bytes().to_vec())), (CKR_OK, Some(vec![0u8])));
    assert_eq!(call(&lab, None, 4, &uid).0, CKR_ACTION_PROHIBITED, "only the security officer destroys an FHE seed");

    // ── Public export over KMIP is byte-identical to the engine's own derive ──
    let h = fhe::generate_fhe_seed_with_value_for_test(lab.user, PS, &lab.replication_policy, &dpid, &KAT_SEED, b"kat-seed").expect("KAT seed");
    let kat_uid = native::get_attribute(lab.user, h, CKA_UNIQUE_ID).unwrap();
    for (kind, from, to) in [(mech::PUBLIC_KIND_CKKS_DESCRIPTOR, 0usize, 0usize), (mech::PUBLIC_KIND_CKKS_PUBLIC_KEY, 0, 1)] {
        let over_kmip = export_over_kmip(&lab, &kat_uid, kind, from as u64, to as u64);
        assert_eq!(over_kmip, derive_direct(lab.user, h, kind, from, to), "kind {kind} differs from the engine's derive");
        assert!(!over_kmip.is_empty());
    }

    // ── Decrypt over KMIP, PKCS#11 multi-step: C_DecryptInit, C_Decrypt size query, C_Decrypt ──
    let ps = params::find(PS).unwrap();
    let m = plaintext(ps.n(), 30);
    let g = Generator::new(ps, &KAT_SEED);
    let (c0, c1) = g.encrypt_for_test(0, &m, &[5u8; 32]).unwrap();
    drop(g);
    let ct = ct_bytes(PS, 0, 40, &c0, &c1);
    let want = mech::decode_slots_wide(&m, 40);
    for i in 0..2 {
        assert_eq!(call(&lab, Some("tenant-a"), 5, &decrypt_init_der(&kat_uid)).0, CKR_OK, "C_DecryptInit {i}");
        // Another client can neither start a second operation nor continue this one.
        assert_eq!(call(&lab, Some("tenant-b"), 5, &decrypt_init_der(&kat_uid)).0, CKR_OPERATION_ACTIVE);
        assert_eq!(call(&lab, Some("tenant-b"), 6, &decrypt_der(&ct, 0)).0, CKR_OPERATION_NOT_INITIALIZED);
        let (rv, len) = call(&lab, Some("tenant-a"), 6, &decrypt_der(&ct, 0));
        assert_eq!(rv, CKR_OK, "C_Decrypt size query {i}");
        let len: u64 = repl::asn1::decode_strict(&len, 16).unwrap();
        let (rv, need) = call(&lab, Some("tenant-a"), 6, &decrypt_der(&ct, 1));
        assert_eq!(rv, CKR_BUFFER_TOO_SMALL, "the operation stays active");
        assert_eq!(repl::asn1::decode_strict::<u64>(&need, 16).unwrap(), len, "the needed length comes back");
        let (rv, out) = call(&lab, Some("tenant-a"), 6, &decrypt_der(&ct, len));
        assert_eq!(rv, CKR_OK, "C_Decrypt {i}");
        assert!(release_precision(&out, &want) >= 19.0, "owner release at the policy's 2^-20 rounding");
        assert_eq!(call(&lab, Some("tenant-a"), 6, &decrypt_der(&ct, len)).0, CKR_OPERATION_NOT_INITIALIZED, "the operation ended");
    }
    assert_eq!(call(&lab, Some("tenant-a"), 5, &decrypt_init_der(&kat_uid)).0, CKR_OK);
    let (rv, len) = call(&lab, Some("tenant-a"), 6, &decrypt_der(&ct, 0));
    let refused = if rv == CKR_OK {
        let len: u64 = repl::asn1::decode_strict(&len, 16).unwrap();
        call(&lab, Some("tenant-a"), 6, &decrypt_der(&ct, len)).0
    } else {
        rv
    };
    assert_eq!(refused, CKR_ACTION_PROHIBITED, "max_decrypts reached: refused by the engine");

    // ── SO: destroyFheSeed over KMIP; the seed is gone, its receipt names the lineage ──
    let (req, (rv, receipt)) = admin_over_kmip(&lab, 2, &AdminOperation::DestroyFheSeed { lineage });
    assert_eq!(rv, CKR_OK, "destroyFheSeed over KMIP");
    let view = host_verify::verify_admin_receipt(&receipt, &req, &repl::trust_inputs(0), NOW, Profile::Educational).expect("receipt verifies");
    assert_eq!(view.output.as_deref(), Some(&lineage[..]));
    assert_eq!(get_attrs(&lab, &uid, &[CKA_PQCTODAY_FHE_PARAM_SET]).0, 0x60, "destroyed");
    // An exact retry returns the stored receipt; the same operation with a fresh nonce finds no seed and is refused
    // with the admin path's uniform refusal code (stage failures are collapsed, so a refusal reveals nothing).
    assert_eq!(call(&lab, Some(ROLE_ADMIN_CN), 8, &req).1, receipt);
    assert_eq!(admin_over_kmip(&lab, 3, &AdminOperation::DestroyFheSeed { lineage }).1 .0, CKR_ACTION_PROHIBITED);

    // ── Refusals ──
    assert_eq!(get_attrs(&lab, &[b'z'; 36], &[CKA_VALUE]).0, 0x60, "unknown unique ID: CKR_KEY_HANDLE_INVALID");
    assert_eq!(call(&lab, None, 2, b"junk").0, 0x20, "not DER: CKR_DATA_INVALID");
}
