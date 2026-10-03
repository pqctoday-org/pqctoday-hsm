//! Shared fixture for the K2–K4 replication suites: two (or three) tokens on
//! separate slots enrolled under one fresh host-side test manufacturing root,
//! with each other's device CRLs and a common replication policy enrolled.
#![allow(dead_code)]

use std::sync::{Mutex, MutexGuard, OnceLock};

use softhsmrustv3::constants::*;
use softhsmrustv3::native;
use softhsmrustv3::replication::{self as repl, oids::Purpose, records, test_ca::TestManufacturingCa};

pub const SO: &str = "so-pin-edu";
pub const USER: &str = "user-pin-edu";
pub const DOMAIN: [u8; 32] = [0x5a; 32];
pub const CKA_LABEL: u32 = 0x0000_0003;

pub fn lock() -> MutexGuard<'static, ()> {
    static L: OnceLock<Mutex<()>> = OnceLock::new();
    L.get_or_init(|| Mutex::new(())).lock().unwrap_or_else(|e| e.into_inner())
}

pub fn ul(v: u32) -> Vec<u8> {
    (v as usize).to_le_bytes().to_vec()
}

pub fn bb(v: bool) -> Vec<u8> {
    vec![v as u8]
}

pub fn raw_template(attrs: &[(u32, Vec<u8>)]) -> Vec<usize> {
    attrs.iter().flat_map(|(t, v)| [*t as usize, v.as_ptr() as usize, v.len()]).collect()
}

pub struct Token {
    pub slot: u32,
    pub so: u32,
    pub user: u32,
}

pub struct World {
    pub ca: TestManufacturingCa,
    pub tokens: Vec<Token>,
    pub now: u64,
}

/// Reset the engine and bring up `n` tokens. Enrollment runs as SO; the
/// SO then logs out and a user session is opened per slot.
pub fn world(n: u32) -> World {
    unsafe { std::env::set_var("SOFTHSMRUST_SLOTS", "4") };
    softhsmrustv3::ffi::reset_all_engine_state_for_test();
    let _ = native::finalize();
    repl::inject_crash(None);
    let now = 1_790_000_000; // 2026-09-21, fixed host clock for determinism
    repl::set_clock_override(Some(now));
    repl::select_educational_profile();
    native::init().expect("init");
    let mut ca = TestManufacturingCa::new(now).expect("test root");
    let mut so_sessions = Vec::new();
    for slot in 0..n {
        native::init_token(slot, SO, &format!("edu-{slot}")).expect("init token");
        let so = native::open_session_so(slot, SO).expect("so session");
        native::init_pin(so, USER).expect("init pin");
        let csr = repl::begin_device_enrollment(so).expect("begin enrollment");
        let dev = ca.issue_device(&csr, now).expect("device cert");
        let crl = ca.crl(now - 10, now + 7 * 86_400).expect("root crl");
        repl::complete_device_enrollment(so, ca.root_der(), &dev, &crl).expect("complete enrollment");
        repl::issue_function_certificates(so).expect("functions");
        so_sessions.push(so);
    }
    // Cross-enroll each peer's device-issuer CRL.
    for a in 0..n as usize {
        for b in 0..n as usize {
            if a != b {
                let crl = repl::own_device_crl(so_sessions[b]).unwrap();
                let dev = repl::device_certificate(so_sessions[b]).unwrap();
                repl::enroll_crl(so_sessions[a], &crl, Some(&dev)).expect("peer crl");
            }
        }
    }
    let mut tokens = Vec::new();
    for (slot, so) in so_sessions.into_iter().enumerate() {
        native::logout(so).unwrap();
        native::close_session(so).unwrap();
        let user = native::open_session(slot as u32, USER).expect("user session");
        tokens.push(Token { slot: slot as u32, so: 0, user });
    }
    World { ca, tokens, now }
}

impl World {
    pub fn device_ids(&self) -> Vec<[u8; 32]> {
        self.tokens.iter().map(|t| repl::device_id(t.user).unwrap()).collect()
    }

    /// Run `f` as SO on `slot` (user logged out for the duration).
    pub fn as_so<R>(&self, slot: usize, f: impl FnOnce(u32) -> R) -> R {
        let t = &self.tokens[slot];
        native::logout(t.user).unwrap();
        let so = native::open_session_so(t.slot, SO).unwrap();
        let r = f(so);
        native::logout(so).unwrap();
        native::close_session(so).unwrap();
        let mut pin = USER.as_bytes().to_vec();
        assert_eq!(softhsmrustv3::ffi::C_Login(t.user, CKU_USER, pin.as_mut_ptr(), pin.len() as u32), CKR_OK);
        r
    }

    /// Enroll the same policy on every token; returns its id.
    pub fn enroll_policy_everywhere(&self, der: &[u8]) -> [u8; 48] {
        let mut id = [0u8; 48];
        for i in 0..self.tokens.len() {
            id = self.as_so(i, |so| repl::enroll_policy(so, der).expect("enroll policy"));
        }
        id
    }

    pub fn policy(&self, ops: [bool; 3], max_replicas: u32, mechs: Vec<u32>) -> Vec<u8> {
        records::build_policy(DOMAIN, ops, self.device_ids(), self.now - 60, self.now + 30 * 86_400, max_replicas, mechs, false)
            .unwrap()
    }
}

pub fn gen_aes(session: u32, len: u32, policy: Option<&[u8; 48]>) -> Result<u32, u32> {
    let mut attrs = vec![
        (CKA_CLASS, ul(CKO_SECRET_KEY)),
        (CKA_KEY_TYPE, ul(CKK_AES)),
        (CKA_VALUE_LEN, ul(len)),
        (CKA_TOKEN, bb(true)),
        (CKA_SENSITIVE, bb(true)),
        (CKA_EXTRACTABLE, bb(false)),
        (CKA_COPYABLE, bb(false)),
        (CKA_MODIFIABLE, bb(false)),
        (CKA_ENCRYPT, bb(true)),
        (CKA_DECRYPT, bb(true)),
    ];
    if let Some(p) = policy {
        attrs.push((CKA_PQCTODAY_REPLICATION_POLICY_ID, p.to_vec()));
    }
    let t = raw_template(&attrs);
    let mut mech = [CKM_AES_KEY_GEN as usize, 0, 0];
    let mut h = 0u32;
    match softhsmrustv3::ffi::C_GenerateKey(session, mech.as_mut_ptr() as *mut u8, t.as_ptr() as *mut u8, attrs.len() as u32, &mut h) {
        CKR_OK => Ok(h),
        rv => Err(rv),
    }
}

/// ML-KEM-768 or ML-DSA-65 pair; returns `(public, private)`.
pub fn gen_pqc(session: u32, mech: u32, policy: Option<&[u8; 48]>) -> Result<(u32, u32), u32> {
    let (ps, pub_use, prv_use) = if mech == CKM_ML_KEM_KEY_PAIR_GEN {
        (CKP_ML_KEM_768, CKA_ENCAPSULATE, CKA_DECAPSULATE)
    } else {
        (CKP_ML_DSA_65, CKA_VERIFY, CKA_SIGN)
    };
    let pubt_attrs = vec![(CKA_TOKEN, bb(true)), (CKA_PARAMETER_SET, ul(ps)), (pub_use, bb(true))];
    let mut prvt_attrs = vec![
        (CKA_TOKEN, bb(true)),
        (CKA_SENSITIVE, bb(true)),
        (CKA_EXTRACTABLE, bb(false)),
        (CKA_COPYABLE, bb(false)),
        (CKA_MODIFIABLE, bb(false)),
        (prv_use, bb(true)),
    ];
    if let Some(p) = policy {
        prvt_attrs.push((CKA_PQCTODAY_REPLICATION_POLICY_ID, p.to_vec()));
    }
    let pubt = raw_template(&pubt_attrs);
    let prvt = raw_template(&prvt_attrs);
    let mut m = [mech as usize, 0, 0];
    let (mut hp, mut hk) = (0u32, 0u32);
    match softhsmrustv3::ffi::C_GenerateKeyPair(
        session,
        m.as_mut_ptr() as *mut u8,
        pubt.as_ptr() as *mut u8,
        pubt_attrs.len() as u32,
        prvt.as_ptr() as *mut u8,
        prvt_attrs.len() as u32,
        &mut hp,
        &mut hk,
    ) {
        CKR_OK => Ok((hp, hk)),
        rv => Err(rv),
    }
}

/// Full live-clone ceremony from token `s` to token `d`; returns the request
/// and package and the import result.
pub struct Run {
    pub request: Vec<u8>,
    pub package: Vec<u8>,
}

pub fn request(w: &World, s: usize, d: usize, op: repl::asn1::Operation, policy: &[u8; 48]) -> Vec<u8> {
    let chal = repl::issue_source_challenge(w.tokens[s].user).expect("source challenge");
    repl::begin_receive(w.tokens[d].user, op, &chal, &DOMAIN, policy).expect("begin receive")
}

pub fn trust_of(w: &World, slot: usize) -> repl::pki::TrustInputs {
    repl::trust_inputs(w.tokens[slot].slot)
}

pub fn purpose_cert(w: &World, slot: usize, p: Purpose) -> Vec<u8> {
    repl::function_certificate(w.tokens[slot].user, p).unwrap()
}

// ── Key profiles and helpers shared by K3/K4 ───────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kp {
    Aes(u32),
    MlKem,
    MlDsa,
}

pub const ALL: [Kp; 5] = [Kp::Aes(16), Kp::Aes(24), Kp::Aes(32), Kp::MlKem, Kp::MlDsa];

/// Mechanisms every test policy allows (sorted).
pub fn test_mechs() -> Vec<u32> {
    let mut m = vec![CKM_AES_GCM, CKM_ML_KEM, CKM_ML_DSA];
    m.sort_unstable();
    m
}

/// `(source key, source public key)` bound to `policy`.
pub fn gen_key(session: u32, kp: Kp, policy: &[u8; 48]) -> (u32, Option<u32>) {
    match kp {
        Kp::Aes(n) => (gen_aes(session, n, Some(policy)).expect("bound AES"), None),
        Kp::MlKem => {
            let (p, k) = gen_pqc(session, CKM_ML_KEM_KEY_PAIR_GEN, Some(policy)).expect("bound ML-KEM");
            (k, Some(p))
        }
        Kp::MlDsa => {
            let (p, k) = gen_pqc(session, CKM_ML_DSA_KEY_PAIR_GEN, Some(policy)).expect("bound ML-DSA");
            (k, Some(p))
        }
    }
}

/// Prove the replica is the same key: AES decrypts, ML-KEM decapsulates,
/// ML-DSA signs verifiably under the source public key.
pub fn prove_same_key(kp: Kp, src_s: u32, src: u32, src_pub: Option<u32>, dst_s: u32, replica: u32) {
    match kp {
        Kp::Aes(_) => {
            let iv = [9u8; 12];
            let ct = native::encrypt(src_s, src, CKM_AES_GCM, b"pqctoday-edu", Some(&iv), None, b"aad", Some(16)).unwrap();
            let pt = native::decrypt(dst_s, replica, CKM_AES_GCM, &ct, Some(&iv), None, b"aad", Some(16)).unwrap();
            assert_eq!(pt, b"pqctoday-edu");
        }
        Kp::MlKem => {
            let (ct, ss) = native::encapsulate(src_s, src_pub.unwrap(), CKM_ML_KEM).unwrap();
            let ss2 = native::decapsulate(dst_s, replica, CKM_ML_KEM, &ct).unwrap();
            assert_eq!(ss, ss2);
        }
        Kp::MlDsa => {
            let sig = native::sign(dst_s, replica, CKM_ML_DSA, b"signed by the replica").unwrap();
            assert!(native::verify(src_s, src_pub.unwrap(), CKM_ML_DSA, b"signed by the replica", &sig).unwrap());
        }
    }
}

pub fn uid(session: u32, h: u32) -> Vec<u8> {
    native::get_attribute(session, h, CKA_UNIQUE_ID).expect("unique id")
}

/// Current handle of the object with `unique_id` (handles change on logout).
pub fn by_uid(unique_id: &[u8]) -> Option<u32> {
    softhsmrustv3::state::OBJECTS.with(|o| {
        o.borrow().iter().find(|(_, a)| a.get(&CKA_UNIQUE_ID).map(|v| v.as_slice()) == Some(unique_id)).map(|(h, _)| *h)
    })
}

/// Number of non-record key objects on `slot` with `lineage`.
pub fn replicas_with_lineage(slot: u32, lineage: &[u8]) -> usize {
    softhsmrustv3::state::OBJECTS.with(|o| {
        o.borrow()
            .values()
            .filter(|a| {
                softhsmrustv3::state::object_slot_of(a) == slot
                    && a.get(&CKA_PQCTODAY_REPLICATION_LINEAGE_ID).map(|v| v.as_slice()) == Some(lineage)
                    && matches!(softhsmrustv3::state::get_object_attr_u32_from(a, CKA_CLASS), Some(CKO_SECRET_KEY) | Some(CKO_PRIVATE_KEY))
            })
            .count()
    })
}

/// Source policy (generous) and destination policy (strict, max 1 replica),
/// both enrolled everywhere. Returns `(source_id, destination_id)`.
pub fn policies(w: &World) -> ([u8; 48], [u8; 48]) {
    let src = w.policy([true, true, true], 16, test_mechs());
    let dst = w.policy([true, true, true], 1, test_mechs());
    (w.enroll_policy_everywhere(&src), w.enroll_policy_everywhere(&dst))
}
