//! Streamed CKKS custodian CLI (EDUCATIONAL). Same custody model as
//! `fhe_custodian` (TFHE): the token holds a non-extractable FHE seed; public
//! material leaves through `CKM_PQCTODAY_FHE_DERIVE_PUBLIC`, decryption runs
//! under the seed's typed policy. For CKKS the GB-sized bootstrapping key set
//! is streamed: every piece is one bounded `C_DeriveKey` (parameter version 2),
//! read once with `C_GetAttributeValue`, written to disk and destroyed. The
//! token never holds the set (plan pqctoday-fhe
//! docs/ckks/ckks-streamed-evaluation-keys-plan-2026-10-10.md §3).
//!
//!   ckks_custodian init <dir> <param-set> [--test-seed]   token, policies, seed (0x8002 = INSECURE test ring)
//!   ckks_custodian export <dir> [limbs-per-chunk]          descriptor, public key, every key chunk, token-signed
//!                                                          manifest (manifest-token.der) and host-signed manifest
//!   ckks_custodian decrypt <dir> <ct_level0.bin> <out> [--new]
//!                                                          policy-gated decryption → owner output
//!                                                          (--new: with the rotation's new seed)
//!   ckks_custodian rotate <dir> [limbs-per-chunk] [--test-seed]
//!                                                          E10: the user generates a new seed in the token; the SO
//!                                                          streams the rotation key old → new (DERIVE_PUBLIC v3)
//!                                                          and its token-signed manifest to out/rotation/
//!   ckks_custodian retire-old <dir>                        E10: the SO retires the old seed (after the FHE server
//!                                                          confirms re-encryption), named by the rotation descriptor
//!
//! `--test-seed` (test-support builds only) installs the seed 00..1f (init)
//! or 20..3f (rotate) so the export can be byte-compared with the
//! pqctoday-fhe oracle and rotation check.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;

use sha2::Digest;
use softhsmrustv3::constants::*;
use softhsmrustv3::native;
use softhsmrustv3::replication::fhe_ckks::{mech, params};
use softhsmrustv3::replication::{self as repl, fhe, fhe_custody as tf, records, test_ca::TestManufacturingCa};

const SO: &str = "edu-ckks-so";
const USER: &str = "edu-ckks-user";
const SEED_ID: &[u8] = b"ckks-custodian-seed";
const NEW_SEED_ID: &[u8] = b"ckks-custodian-seed-rotated";
const SIGNER_ID: &[u8] = b"ckks-custodian-manifest-signer";
const DOMAIN: [u8; 32] = *b"pqctoday-ckks-custodian-domainv1";

fn die(what: &str, rv: u32) -> ! {
    eprintln!("error: {what}: CKR 0x{rv:x}");
    std::process::exit(1)
}

fn ok<T>(what: &str, r: Result<T, u32>) -> T {
    r.unwrap_or_else(|rv| die(what, rv))
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

fn open(dir: &Path) {
    repl::select_educational_profile();
    std::fs::create_dir_all(dir.join("store")).unwrap();
    softhsmrustv3::store::configure_persistent_store(dir.join("store")).expect("configure store");
    ok("C_Initialize", native::init());
}

fn ul(v: u32) -> Vec<u8> {
    (v as usize).to_le_bytes().to_vec()
}

fn template(attrs: &[(u32, Vec<u8>)]) -> Vec<usize> {
    attrs.iter().flat_map(|(t, v)| [*t as usize, v.as_ptr() as usize, v.len()]).collect()
}

fn gen_signer(s: u32) {
    let pubt_a = vec![(CKA_TOKEN, vec![1]), (CKA_PARAMETER_SET, ul(CKP_ML_DSA_65)), (CKA_VERIFY, vec![1]), (native::CKA_ID, SIGNER_ID.to_vec())];
    let prvt_a = vec![(CKA_TOKEN, vec![1]), (CKA_SENSITIVE, vec![1]), (CKA_EXTRACTABLE, vec![0]), (CKA_SIGN, vec![1]), (native::CKA_ID, SIGNER_ID.to_vec())];
    let (pt, kt) = (template(&pubt_a), template(&prvt_a));
    let mut m = [CKM_ML_DSA_KEY_PAIR_GEN as usize, 0, 0];
    let (mut hp, mut hk) = (0u32, 0u32);
    let rv = softhsmrustv3::ffi::C_GenerateKeyPair(s, m.as_mut_ptr() as *mut u8, pt.as_ptr() as *mut u8, pubt_a.len() as u32, kt.as_ptr() as *mut u8, prvt_a.len() as u32, &mut hp, &mut hk);
    if rv != CKR_OK {
        die("generate manifest signer", rv);
    }
}

fn find(s: u32, id: &[u8], class: u32) -> u32 {
    ok("find", native::find_all_by_cka_id(s, id))
        .into_iter()
        .find(|h| native::get_attribute_u32(s, *h, CKA_CLASS) == Some(class))
        .unwrap_or_else(|| die("object not found (run init first)", CKR_OBJECT_HANDLE_INVALID))
}

/// Peak resident set of this process (Linux VmHWM), in KiB.
fn peak_rss_kib() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/self/status").ok()?;
    s.lines().find(|l| l.starts_with("VmHWM:"))?.split_whitespace().nth(1)?.parse().ok()
}

fn cmd_init(dir: &Path, param_set: u32, test_seed: bool) {
    if dir.join("store").exists() {
        eprintln!("error: {} already initialised", dir.display());
        std::process::exit(1);
    }
    let ps = params::find(param_set).unwrap_or_else(|| die("unknown CKKS parameter set", CKR_MECHANISM_PARAM_INVALID));
    open(dir);
    let t = now();
    let out = dir.join("out");
    std::fs::create_dir_all(&out).unwrap();
    ok("C_InitToken", native::init_token(0, SO, "ckks-custodian"));
    let so = ok("SO login", native::open_session_so(0, SO));
    ok("C_InitPIN", native::init_pin(so, USER));
    let mut ca = ok("test root", TestManufacturingCa::new(t));
    let csr = ok("begin enrollment", repl::begin_device_enrollment(so));
    let dev = ok("device cert", ca.issue_device(&csr, t));
    let root_crl = ok("root CRL", ca.crl(t - 10, t + 30 * 86_400));
    ok("complete enrollment", repl::complete_device_enrollment(so, ca.root_der(), &dev, &root_crl));
    ok("function certificates", repl::issue_function_certificates(so));
    let device_id = ok("device id", repl::device_id(so));
    let repl_pol = ok(
        "replication policy",
        records::build_policy_with_constraint(DOMAIN, [true, true, true], vec![device_id], t - 60, t + 365 * 86_400, 4, vec![CKM_PQCTODAY_FHE_DERIVE_PUBLIC, CKM_PQCTODAY_FHE_DECRYPT], false, fhe::ckks_profile_constraint_hash()),
    );
    let rp = ok("enroll replication policy", repl::enroll_policy(so, &repl_pol));
    let dpol = {
        use der::Encode;
        fhe::FheDecryptPolicy {
            version: 2,
            allowed_output_types: vec![fhe::FheType { type_name: mech::CKKS_TYPE_NAME.into(), width_bits: 64, param_set: ps.id, serialization_version: mech::CT_VERSION, compressed_allowed: false }],
            never_release: vec![],
            predicates: vec![],
            recipients: vec![],
            recipient_only: false,
            max_decrypts: 10_000,
            // Owner release: every slot, rounded to 2^-20, |value| < 2^10, at the default scale.
            ckks: Some(fhe::CkksReleasePolicy {
                max_values: (ps.n() / 2) as u32,
                precision_bits: 20,
                value_bound_log2: 10,
                scale_log2: ps.log_default_scale as u8,
                flood_recipients: true,
                flood_owner: std::env::var("CKKS_FLOOD_OWNER").is_ok(),
                stat_security_bits: 30,
            }),
        }
        .to_der()
        .unwrap()
    };
    let dp = ok("enroll decrypt policy", fhe::enroll_fhe_decrypt_policy(so, &dpol));
    std::fs::write(out.join("decrypt_policy.der"), &dpol).unwrap();
    ok("SO logout", native::logout(so));
    ok("close", native::close_session(so));
    let s = ok("user login", native::open_session(0, USER));
    let seed = if test_seed {
        #[cfg(feature = "test-support")]
        {
            ok("KEY_GEN (test seed)", fhe::generate_fhe_seed_with_value_for_test(s, ps.id, &rp, &dp, &core::array::from_fn(|i| i as u8), SEED_ID))
        }
        #[cfg(not(feature = "test-support"))]
        die("--test-seed needs a test-support build", CKR_FUNCTION_NOT_SUPPORTED)
    } else {
        ok("KEY_GEN", fhe::generate_fhe_seed(s, ps.id, &rp, &dp, Some(b"CKKS custodian seed"), Some(SEED_ID)))
    };
    gen_signer(s);
    println!("initialised {} (PQCTODAY EDUCATIONAL TEST ONLY): {} seed handle {seed}", dir.display(), ps.name);
}

/// One bounded `C_DeriveKey(CKM_PQCTODAY_FHE_DERIVE_PUBLIC, version 2)` →
/// `C_GetAttributeValue(CKA_VALUE)` → `C_DestroyObject`, through the C ABI.
fn derive(s: u32, seed: u32, kind: u32, k: u32, d: u32, from: usize, to: usize) -> Vec<u8> {
    let p: [usize; 6] = [2, kind as usize, k as usize, d as usize, from, to];
    let mut m = [CKM_PQCTODAY_FHE_DERIVE_PUBLIC as usize, p.as_ptr() as usize, std::mem::size_of_val(&p)];
    let mut h = 0u32;
    let rv = softhsmrustv3::ffi::C_DeriveKey(s, m.as_mut_ptr() as *mut u8, seed, std::ptr::null_mut(), 0, &mut h);
    if rv != CKR_OK {
        die(&format!("C_DeriveKey(kind {kind}, key {k}, digit {d}, limbs {from}..{to})"), rv);
    }
    let v = native::get_attribute(s, h, CKA_VALUE).unwrap_or_else(|| die("C_GetAttributeValue", CKR_DEVICE_ERROR));
    let rv = softhsmrustv3::ffi::C_DestroyObject(s, h);
    if rv != CKR_OK {
        die("C_DestroyObject", rv);
    }
    v
}

/// `stream`: write every output file as a frame to stdout instead of to disk
/// (`PQCKF1` ‖ u16 BE path length ‖ path ‖ u64 BE length ‖ bytes), so a board
/// never stores the key set; the report goes to stderr. Receiver:
/// pqctoday-fhe `reference-runs/ckks-stream-e2e/receive.py`.
fn cmd_export(dir: &Path, per_chunk: usize, stream: bool) {
    open(dir);
    let s = ok("user login", native::open_session(0, USER));
    let seed = find(s, SEED_ID, CKO_SECRET_KEY);
    let signer = find(s, SIGNER_ID, CKO_PRIVATE_KEY);
    let ps = params::find(native::get_attribute_u32(s, seed, CKA_PQCTODAY_FHE_PARAM_SET).unwrap()).unwrap();
    let out = dir.join("out");
    if !stream {
        let _ = std::fs::remove_dir_all(out.join("pk"));
        let _ = std::fs::remove_dir_all(out.join("evk"));
        std::fs::create_dir_all(out.join("pk")).unwrap();
    }
    let stdout = std::cell::RefCell::new(std::io::BufWriter::with_capacity(1 << 20, std::io::stdout().lock()));
    let emit = |rel: &str, bytes: &[u8]| {
        if stream {
            let mut w = stdout.borrow_mut();
            w.write_all(b"PQCKF1").unwrap();
            w.write_all(&(rel.len() as u16).to_be_bytes()).unwrap();
            w.write_all(rel.as_bytes()).unwrap();
            w.write_all(&(bytes.len() as u64).to_be_bytes()).unwrap();
            w.write_all(bytes).unwrap();
        } else {
            std::fs::write(out.join(rel), bytes).unwrap();
        }
    };
    let mut manifest = String::new();
    let mut put = |rel: String, bytes: &[u8]| {
        emit(&rel, bytes);
        manifest.push_str(&format!("{rel} {}\n", sha2::Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect::<String>()));
        bytes.len() as u64
    };
    let t0 = Instant::now();
    let mut total = put("descriptor.der".into(), &derive(s, seed, mech::PUBLIC_KIND_CKKS_DESCRIPTOR, 0, 0, 0, 0));
    for from in (0..ps.pk_limbs()).step_by(per_chunk) {
        let to = (from + per_chunk).min(ps.pk_limbs());
        total += put(format!("pk/{from}_{to}.bin"), &derive(s, seed, mech::PUBLIC_KIND_CKKS_PUBLIC_KEY, 0, 0, from, to));
    }
    let (mut calls, mut slowest) = (0u64, 0f64);
    for (k, key) in ps.keys.iter().enumerate() {
        if !stream {
            std::fs::create_dir_all(out.join(format!("evk/k{k:03}"))).unwrap();
        }
        for d in 0..key.dnum() {
            for from in (0..key.limbs()).step_by(per_chunk) {
                let to = (from + per_chunk).min(key.limbs());
                let tc = Instant::now();
                let b = derive(s, seed, mech::PUBLIC_KIND_CKKS_EVK_CHUNK, k as u32, d as u32, from, to);
                slowest = slowest.max(tc.elapsed().as_secs_f64());
                total += put(format!("evk/k{k:03}/d{d:02}_{from}_{to}.bin"), &b);
                calls += 1;
            }
        }
        if !stream {
            eprint!("\rkey {}/{}", k + 1, ps.keys.len());
        }
    }
    if !stream {
        eprintln!();
    }
    let secs = t0.elapsed().as_secs_f64();
    // Token-signed manifest (kind 6, E3): the token's own ledger of every chunk
    // it served this session, signed with its receipt-signing key. Refused
    // unless the export above covered the set exactly once.
    emit("manifest-token.der", &derive(s, seed, mech::PUBLIC_KIND_CKKS_MANIFEST, 0, 0, 0, 0));
    // Host-signed manifest (kept for compatibility): one SHA-256 per file in export order, signed (TFHE model, spec
    // §5.2): the application signs with the token-resident ML-DSA-65 key.
    emit("manifest.txt", manifest.as_bytes());
    let lineage = native::get_attribute(s, seed, CKA_PQCTODAY_FHE_LINEAGE_ID).unwrap();
    let ph = native::get_attribute(s, seed, CKA_PQCTODAY_FHE_PARAM_HASH).unwrap();
    let mder = ok("manifest", tf::public_manifest(&lineage, &ph, mech::PUBLIC_KIND_CKKS_EVK_CHUNK, manifest.as_bytes()));
    emit("manifest.der", &mder);
    emit("manifest.sig", &ok("C_Sign(CKM_ML_DSA)", native::sign(s, signer, CKM_ML_DSA, &mder)));
    let signer_pub = find(s, SIGNER_ID, CKO_PUBLIC_KEY);
    emit("signer_spki.der", &native::get_attribute(s, signer_pub, CKA_PUBLIC_KEY_INFO).unwrap());
    let report = format!(
        "{{\n \"paramSet\": {},\n \"name\": \"{}\",\n \"keys\": {},\n \"limbsPerCall\": {per_chunk},\n \"evkCalls\": {calls},\n \"bytes\": {total},\n \"seconds\": {secs:.3},\n \"mbPerSecond\": {:.1},\n \"slowestCallSeconds\": {slowest:.4},\n \"peakRssKiB\": {}\n}}\n",
        ps.id,
        ps.name,
        ps.keys.len(),
        total as f64 / 1e6 / secs,
        peak_rss_kib().map(|v| v.to_string()).unwrap_or_else(|| "null".into())
    );
    if stream {
        stdout.borrow_mut().flush().unwrap();
        eprint!("{report}");
    } else {
        std::fs::write(out.join("export.json"), &report).unwrap();
        std::io::stdout().write_all(report.as_bytes()).unwrap();
    }
}

fn cmd_decrypt(dir: &Path, ct: &Path, dst: &Path, new_seed: bool) {
    open(dir);
    let s = ok("user login", native::open_session(0, USER));
    let seed = find(s, if new_seed { NEW_SEED_ID } else { SEED_ID }, CKO_SECRET_KEY);
    let input = std::fs::read(ct).expect("read ciphertext");
    let p = [1usize; 1];
    let mut prm = vec![0u8; (std::mem::size_of::<usize>() + 48).next_multiple_of(std::mem::size_of::<usize>())];
    prm[..std::mem::size_of::<usize>()].copy_from_slice(&p[0].to_le_bytes());
    let mut m = [CKM_PQCTODAY_FHE_DECRYPT as usize, prm.as_ptr() as usize, prm.len()];
    let rv = softhsmrustv3::ffi::C_DecryptInit(s, m.as_mut_ptr() as *mut u8, seed);
    if rv != CKR_OK {
        die("C_DecryptInit", rv);
    }
    let mut n = 0u32;
    let rv = softhsmrustv3::ffi::C_Decrypt(s, input.as_ptr() as *mut u8, input.len() as u32, std::ptr::null_mut(), &mut n);
    if rv != CKR_OK {
        die("C_Decrypt (size)", rv);
    }
    let mut outb = vec![0u8; n as usize];
    let t = Instant::now();
    let rv = softhsmrustv3::ffi::C_Decrypt(s, input.as_ptr() as *mut u8, input.len() as u32, outb.as_mut_ptr(), &mut n);
    if rv != CKR_OK {
        eprintln!("refused by policy or input check (reason in the token audit log only)");
        die("C_Decrypt(CKM_PQCTODAY_FHE_DECRYPT)", rv);
    }
    outb.truncate(n as usize);
    std::fs::write(dst, &outb).unwrap();
    println!("released {} B in {:.3} s", outb.len(), t.elapsed().as_secs_f64());
}

/// One bounded `C_DeriveKey(CKM_PQCTODAY_FHE_DERIVE_PUBLIC, version 3)` in the
/// SO session: hBaseKey = CK_INVALID_HANDLE, both seeds named by lineage.
#[allow(clippy::too_many_arguments)]
fn derive_rotation(so: u32, old: &[u8], new: &[u8], kind: u32, d: u32, from: usize, to: usize) -> Vec<u8> {
    let mut p: Vec<u8> = [3usize, kind as usize, 0, d as usize, from, to].iter().flat_map(|w| w.to_le_bytes()).collect();
    p.extend_from_slice(old);
    p.extend_from_slice(new);
    let mut m = [CKM_PQCTODAY_FHE_DERIVE_PUBLIC as usize, p.as_ptr() as usize, p.len()];
    let mut h = 0u32;
    let rv = softhsmrustv3::ffi::C_DeriveKey(so, m.as_mut_ptr() as *mut u8, 0, std::ptr::null_mut(), 0, &mut h);
    if rv != CKR_OK {
        die(&format!("C_DeriveKey(v3 kind {kind}, digit {d}, limbs {from}..{to})"), rv);
    }
    let v = native::get_attribute(so, h, CKA_VALUE).unwrap_or_else(|| die("C_GetAttributeValue", CKR_DEVICE_ERROR));
    let rv = softhsmrustv3::ffi::C_DestroyObject(so, h);
    if rv != CKR_OK {
        die("C_DestroyObject", rv);
    }
    v
}

/// E10: the user generates the new seed (token KEY_GEN, same policies as the
/// old seed) and hands both lineages to the SO, who streams the rotation key.
fn cmd_rotate(dir: &Path, per_chunk: usize, test_seed: bool) {
    open(dir);
    let s = ok("user login", native::open_session(0, USER));
    let old = find(s, SEED_ID, CKO_SECRET_KEY);
    let ps = params::find(native::get_attribute_u32(s, old, CKA_PQCTODAY_FHE_PARAM_SET).unwrap()).unwrap();
    let attr48 = |t: u32| -> [u8; 48] { native::get_attribute(s, old, t).and_then(|v| v.try_into().ok()).unwrap_or_else(|| die("seed policy attribute", CKR_DEVICE_ERROR)) };
    let (rp, dp) = (attr48(CKA_PQCTODAY_REPLICATION_POLICY_ID), attr48(CKA_PQCTODAY_FHE_DECRYPT_POLICY));
    if !ok("find", native::find_all_by_cka_id(s, NEW_SEED_ID)).is_empty() {
        die("a rotated seed already exists in this token", CKR_ACTION_PROHIBITED);
    }
    let new = if test_seed {
        #[cfg(feature = "test-support")]
        {
            ok("KEY_GEN (test seed 20..3f)", fhe::generate_fhe_seed_with_value_for_test(s, ps.id, &rp, &dp, &core::array::from_fn(|i| 0x20 + i as u8), NEW_SEED_ID))
        }
        #[cfg(not(feature = "test-support"))]
        die("--test-seed needs a test-support build", CKR_FUNCTION_NOT_SUPPORTED)
    } else {
        ok("KEY_GEN", fhe::generate_fhe_seed(s, ps.id, &rp, &dp, Some(b"CKKS custodian seed (rotated)"), Some(NEW_SEED_ID)))
    };
    let lin = |h: u32| native::get_attribute(s, h, CKA_PQCTODAY_FHE_LINEAGE_ID).unwrap();
    let (lo, ln) = (lin(old), lin(new));
    ok("user logout", native::logout(s));
    ok("close", native::close_session(s));

    let so = ok("SO login", native::open_session_so(0, SO));
    let out = dir.join("out").join("rotation");
    let _ = std::fs::remove_dir_all(&out);
    std::fs::create_dir_all(&out).unwrap();
    let t0 = Instant::now();
    let desc = derive_rotation(so, &lo, &ln, mech::PUBLIC_KIND_CKKS_DESCRIPTOR, 0, 0, 0);
    std::fs::write(out.join("descriptor.der"), &desc).unwrap();
    let k = ps.rotation_desc();
    let (mut bytes, mut calls, mut slowest) = (0usize, 0u64, 0f64);
    for d in 0..k.dnum() {
        for from in (0..k.limbs()).step_by(per_chunk) {
            let to = (from + per_chunk).min(k.limbs());
            let tc = Instant::now();
            let b = derive_rotation(so, &lo, &ln, mech::PUBLIC_KIND_CKKS_EVK_CHUNK, d as u32, from, to);
            slowest = slowest.max(tc.elapsed().as_secs_f64());
            bytes += b.len();
            calls += 1;
            std::fs::write(out.join(format!("d{d:02}_{from}_{to}.bin")), &b).unwrap();
        }
    }
    let secs = t0.elapsed().as_secs_f64();
    let manifest = derive_rotation(so, &lo, &ln, mech::PUBLIC_KIND_CKKS_MANIFEST, 0, 0, 0);
    std::fs::write(out.join("manifest-token.der"), &manifest).unwrap();
    ok("SO logout", native::logout(so));
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let report = format!(
        "{{\n \"paramSet\": {},\n \"digits\": {},\n \"limbs\": {},\n \"limbsPerCall\": {per_chunk},\n \"chunkCalls\": {calls},\n \"bBytes\": {bytes},\n \"seconds\": {secs:.4},\n \"slowestCallSeconds\": {slowest:.4},\n \"oldLineage\": \"{}\",\n \"newLineage\": \"{}\",\n \"manifestBytes\": {},\n \"peakRssKiB\": {}\n}}\n",
        ps.id,
        k.dnum(),
        k.limbs(),
        hex(&lo),
        hex(&ln),
        manifest.len(),
        peak_rss_kib().map(|v| v.to_string()).unwrap_or_else(|| "null".into())
    );
    std::fs::write(out.join("rotate.json"), &report).unwrap();
    print!("{report}");
}

/// E10: the SO retires the old seed once the FHE server has confirmed
/// re-encryption. The SO names it by the old lineage in the public rotation
/// descriptor; the token refuses unless the rotation manifest was signed.
fn cmd_retire_old(dir: &Path) {
    let desc = std::fs::read(dir.join("out").join("rotation").join("descriptor.der")).unwrap_or_else(|_| die("no rotation descriptor (run rotate first)", CKR_OPERATION_NOT_INITIALIZED));
    let d: softhsmrustv3::replication::fhe_ckks::rotation::CkksRotationDescriptorV1 = der::Decode::from_der(&desc).unwrap_or_else(|_| die("rotation descriptor", CKR_DATA_INVALID));
    let lo: [u8; 32] = d.old_lineage.as_bytes().try_into().unwrap_or_else(|_| die("old lineage", CKR_DATA_INVALID));
    open(dir);
    let so = ok("SO login", native::open_session_so(0, SO));
    ok("retire old seed", softhsmrustv3::replication::fhe_ckks::rotation::retire_old_seed(so, &lo));
    ok("SO logout", native::logout(so));
    println!("old seed retired (lineage {})", lo.iter().map(|x| format!("{x:02x}")).collect::<String>());
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("init") if a.len() >= 4 => {
            let ps = u32::from_str_radix(a[3].trim_start_matches("0x"), if a[3].starts_with("0x") { 16 } else { 10 }).expect("param set");
            cmd_init(&PathBuf::from(&a[2]), ps, a.get(4).map(String::as_str) == Some("--test-seed"))
        }
        Some(c @ ("export" | "export-stream")) if a.len() >= 3 => cmd_export(&PathBuf::from(&a[2]), a.get(3).map(|v| v.parse().unwrap()).unwrap_or(8), c == "export-stream"),
        Some("decrypt") if a.len() == 5 || (a.len() == 6 && a[5] == "--new") => cmd_decrypt(&PathBuf::from(&a[2]), &PathBuf::from(&a[3]), &PathBuf::from(&a[4]), a.len() == 6),
        Some("rotate") if a.len() >= 3 => {
            let per = a.get(3).filter(|v| !v.starts_with("--")).map(|v| v.parse().unwrap()).unwrap_or(8);
            cmd_rotate(&PathBuf::from(&a[2]), per, a.iter().any(|v| v == "--test-seed"))
        }
        Some("retire-old") if a.len() == 3 => cmd_retire_old(&PathBuf::from(&a[2])),
        _ => {
            eprintln!("usage: ckks_custodian init <dir> <param-set> [--test-seed] | export|export-stream <dir> [limbs-per-chunk] | decrypt <dir> <ct.bin> <out> [--new] | rotate <dir> [limbs-per-chunk] [--test-seed] | retire-old <dir>");
            std::process::exit(2);
        }
    }
}
