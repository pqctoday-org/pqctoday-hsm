//! FHE custodian CLI — programme stage F in software (EDUCATIONAL).
//!
//! The token (softhsmrustv3, `educational-fhe`) holds the FHE seed. The
//! untrusted compute server (KV260) receives only public material and a
//! signed manifest, and returns a result ciphertext that the token decrypts
//! under its typed decryption policy.
//!
//!   fhe_custodian init <dir>             persistent token + test root + seed + manifest key
//!   fhe_custodian export <dir>           public material, manifests, signatures, trust inputs
//!   fhe_custodian decrypt <dir> <ct.bin> policy-gated decryption → owner output
//!   fhe_custodian verify-signer [--now <unix>] <dir>…
//!                                        owner-side K3 check of each export's
//!                                        manifest signer (public bytes only)
//!
//! State lives in <dir>/store (SQLite, encrypted private objects). PINs are
//! fixed educational values; nothing here is production custody.

use std::path::{Path, PathBuf};

use softhsmrustv3::constants::*;
use softhsmrustv3::native;
use softhsmrustv3::replication::{
    self as repl, fhe, fhe_tfhe as tf, records, test_ca::TestManufacturingCa,
};

const SO: &str = "edu-custodian-so";
const USER: &str = "edu-custodian-user";
const SEED_ID: &[u8] = b"fhe-custodian-seed";
const SIGNER_ID: &[u8] = b"fhe-custodian-manifest-signer";
const DOMAIN: [u8; 32] = *b"pqctoday-fhe-custodian-domain-v1";

fn die(what: &str, rv: u32) -> ! {
    eprintln!("error: {what}: CKR 0x{rv:x}");
    std::process::exit(1)
}

fn ok<T>(what: &str, r: Result<T, u32>) -> T {
    r.unwrap_or_else(|rv| die(what, rv))
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
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
    attrs
        .iter()
        .flat_map(|(t, v)| [*t as usize, v.as_ptr() as usize, v.len()])
        .collect()
}

/// Token-resident, non-extractable ML-DSA-65 manifest-signing key.
fn gen_signer(s: u32) -> (u32, u32) {
    let pubt_a = vec![
        (CKA_TOKEN, vec![1]),
        (CKA_PARAMETER_SET, ul(CKP_ML_DSA_65)),
        (CKA_VERIFY, vec![1]),
        (native::CKA_ID, SIGNER_ID.to_vec()),
    ];
    let prvt_a = vec![
        (CKA_TOKEN, vec![1]),
        (CKA_SENSITIVE, vec![1]),
        (CKA_EXTRACTABLE, vec![0]),
        (CKA_SIGN, vec![1]),
        (native::CKA_ID, SIGNER_ID.to_vec()),
    ];
    let (pt, kt) = (template(&pubt_a), template(&prvt_a));
    let mut m = [CKM_ML_DSA_KEY_PAIR_GEN as usize, 0, 0];
    let (mut hp, mut hk) = (0u32, 0u32);
    let rv = softhsmrustv3::ffi::C_GenerateKeyPair(
        s,
        m.as_mut_ptr() as *mut u8,
        pt.as_ptr() as *mut u8,
        pubt_a.len() as u32,
        kt.as_ptr() as *mut u8,
        prvt_a.len() as u32,
        &mut hp,
        &mut hk,
    );
    if rv != CKR_OK {
        die("generate manifest signer", rv);
    }
    (hp, hk)
}

fn find(s: u32, id: &[u8], class: u32) -> u32 {
    ok("find", native::find_all_by_cka_id(s, id))
        .into_iter()
        .find(|h| native::get_attribute_u32(s, *h, CKA_CLASS) == Some(class))
        .unwrap_or_else(|| {
            die(
                "object not found (run init first)",
                CKR_OBJECT_HANDLE_INVALID,
            )
        })
}

fn cmd_init(dir: &Path) {
    if dir.join("store").exists() {
        eprintln!("error: {} already initialised", dir.display());
        std::process::exit(1);
    }
    open(dir);
    let t = now();
    let out = dir.join("out");
    std::fs::create_dir_all(out.join("crls")).unwrap();
    // Token + SO enrollment under a fresh host-side TEST manufacturing root.
    ok("C_InitToken", native::init_token(0, SO, "fhe-custodian"));
    let so = ok("SO login", native::open_session_so(0, SO));
    ok("C_InitPIN", native::init_pin(so, USER));
    let mut ca = ok("test root", TestManufacturingCa::new(t));
    let csr = ok("begin enrollment", repl::begin_device_enrollment(so));
    let dev = ok("device cert", ca.issue_device(&csr, t));
    let root_crl = ok("root CRL", ca.crl(t - 10, t + 30 * 86_400));
    ok(
        "complete enrollment",
        repl::complete_device_enrollment(so, ca.root_der(), &dev, &root_crl),
    );
    ok(
        "function certificates",
        repl::issue_function_certificates(so),
    );
    let device_id = ok("device id", repl::device_id(so));
    let repl_pol = ok(
        "replication policy",
        records::build_policy_with_constraint(
            DOMAIN,
            [true, true, true],
            vec![device_id],
            t - 60,
            t + 365 * 86_400,
            4,
            vec![CKM_PQCTODAY_FHE_DERIVE_PUBLIC, CKM_PQCTODAY_FHE_DECRYPT],
            false,
            fhe::profile_constraint_hash(),
        ),
    );
    let rp = ok(
        "enroll replication policy",
        repl::enroll_policy(so, &repl_pol),
    );
    let ty = |n: &str, w: u16| fhe::FheType {
        type_name: n.into(),
        width_bits: w,
        param_set: 1,
        serialization_version: 1,
        compressed_allowed: false,
    };
    let dpol = {
        use der::Encode;
        fhe::FheDecryptPolicy {
            version: 1,
            allowed_output_types: vec![
                ty("FheBool", 1),
                ty("FheUint16", 16),
                ty("FheUint32", 32),
                ty("FheUint8", 8),
            ],
            never_release: vec![ty("FheUint64", 64)],
            predicates: vec![],
            recipients: vec![],
            recipient_only: false,
            max_decrypts: 10_000,
            ckks: None,
        }
        .to_der()
        .unwrap()
    };
    let dp = ok(
        "enroll decrypt policy",
        fhe::enroll_fhe_decrypt_policy(so, &dpol),
    );
    std::fs::write(out.join("root.der"), ca.root_der()).unwrap();
    std::fs::write(out.join("crls/root.crl.der"), &root_crl).unwrap();
    std::fs::write(out.join("decrypt_policy.der"), &dpol).unwrap();
    ok("SO logout", native::logout(so));
    ok("close", native::close_session(so));
    // User: the seed and the manifest-signing key.
    let s = ok("user login", native::open_session(0, USER));
    let seed = ok(
        "KEY_GEN",
        fhe::generate_fhe_seed(s, 1, &rp, &dp, Some(b"FHE custodian seed"), Some(SEED_ID)),
    );
    let (_, _) = gen_signer(s);
    std::fs::write(
        out.join("crls/device.crl.der"),
        ok("device CRL", repl::own_device_crl(s)),
    )
    .unwrap();
    println!(
        "initialised {} (PQCTODAY EDUCATIONAL TEST ONLY): seed handle {seed}, device id {}",
        dir.display(),
        device_id
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
}

fn cmd_export(dir: &Path) {
    open(dir);
    let s = ok("user login", native::open_session(0, USER));
    let seed = find(s, SEED_ID, CKO_SECRET_KEY);
    let signer = find(s, SIGNER_ID, CKO_PRIVATE_KEY);
    let signer_pub = find(s, SIGNER_ID, CKO_PUBLIC_KEY);
    let out = dir.join("out");
    let lineage = native::get_attribute(s, seed, CKA_PQCTODAY_FHE_LINEAGE_ID).unwrap();
    let ph = native::get_attribute(s, seed, CKA_PQCTODAY_FHE_PARAM_HASH).unwrap();
    for (kind, name) in [
        (
            tf::PUBLIC_KIND_COMPRESSED_SERVER_KEY,
            "compressed_server_key",
        ),
        (tf::PUBLIC_KIND_COMPACT_PUBLIC_KEY, "compact_public_key"),
    ] {
        let h = ok("DERIVE_PUBLIC", tf::derive_public(s, seed, kind));
        let blob = native::get_attribute(s, h, CKA_VALUE).unwrap();
        let manifest = ok("manifest", tf::public_manifest(&lineage, &ph, kind, &blob));
        let sig = ok(
            "C_Sign(CKM_ML_DSA)",
            native::sign(s, signer, CKM_ML_DSA, &manifest),
        );
        std::fs::write(out.join(format!("{name}.bin")), &blob).unwrap();
        std::fs::write(out.join(format!("{name}.manifest.der")), &manifest).unwrap();
        std::fs::write(out.join(format!("{name}.manifest.sig")), &sig).unwrap();
        println!(
            "{name}: {} B, manifest {} B, signature {} B",
            blob.len(),
            manifest.len(),
            sig.len()
        );
    }
    std::fs::write(
        out.join("signer_spki.der"),
        native::get_attribute(s, signer_pub, CKA_PUBLIC_KEY_INFO).unwrap(),
    )
    .unwrap();
    // K3 evidence that the manifest key is token-resident and non-extractable;
    // nonce = first 32 bytes of SHA-384(server-key manifest DER).
    use sha2::Digest;
    let m = std::fs::read(out.join("compressed_server_key.manifest.der")).unwrap();
    let nonce: [u8; 32] = sha2::Sha384::digest(&m)[..32].try_into().unwrap();
    std::fs::write(
        out.join("signer_evidence.der"),
        ok("attest_key", repl::attest_key(s, signer, &nonce)),
    )
    .unwrap();
    std::fs::write(
        out.join("crls/device.crl.der"),
        ok("device CRL", repl::own_device_crl(s)),
    )
    .unwrap();
    println!("exported to {}", out.display());
}

fn cmd_decrypt(dir: &Path, ct: &Path) {
    open(dir);
    let s = ok("user login", native::open_session(0, USER));
    let seed = find(s, SEED_ID, CKO_SECRET_KEY);
    let input = std::fs::read(ct).expect("read ciphertext");
    match tf::decrypt(s, seed, &[0u8; 48], &input, false) {
        Ok((_, Some(tf::DecryptOutput::Owner(b)))) => {
            let width = u16::from_be_bytes([b[1], b[2]]);
            let mut v = [0u8; 8];
            v[..(b.len() - 3).min(8)].copy_from_slice(&b[3..3 + (b.len() - 3).min(8)]);
            let kind = if b[0] == 0 {
                "FheBool".to_string()
            } else {
                format!("FheUint{width}")
            };
            println!("released {kind} = {}", u64::from_le_bytes(v));
        }
        Ok(_) => die("unexpected output", CKR_DEVICE_ERROR),
        Err(rv) => {
            eprintln!("refused by policy or input check (reason in the token audit log only)");
            die("C_Decrypt(CKM_PQCTODAY_FHE_DECRYPT)", rv)
        }
    }
}

// ── verify-signer: the data owner's K3 check, before pinning a signer ──────

#[derive(Default)]
struct SignerReport {
    signer_spki_sha256: String,
    device_id: String,
    unique_id: String,
    evidence_issued_at: u64,
    chain: Vec<String>,
    crl_next_update: Vec<(String, u64)>,
    root_sha256: String,
    lineage: String,
    param_hash: String,
}

fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn read(p: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(p).map_err(|e| format!("read {}: {e}", p.display()))
}

/// Verify one export directory (`<dir>/out` or `<dir>` itself). Public bytes
/// only: the token is never opened.
fn verify_signer_dir(dir: &Path, now: u64) -> Result<SignerReport, String> {
    use der::Decode;
    use sha2::Digest;
    let out = if dir.join("out").is_dir() { dir.join("out") } else { dir.to_path_buf() };
    let evidence = read(&out.join("signer_evidence.der"))?;
    let spki = read(&out.join("signer_spki.der"))?;
    let root = read(&out.join("root.der"))?;
    let manifest = read(&out.join("compressed_server_key.manifest.der"))?;
    let mut crls = Vec::new();
    let mut entries: Vec<_> = std::fs::read_dir(out.join("crls")).map_err(|e| format!("crls: {e}"))?.flatten().map(|e| e.path()).collect();
    entries.sort();
    for p in entries.iter().filter(|p| p.extension().is_some_and(|x| x == "der")) {
        crls.push(read(p)?);
    }
    // The evidence nonce binds it to this export (custodian `export`).
    let nonce: [u8; 32] = sha2::Sha384::digest(&manifest)[..32].try_into().unwrap();
    let trust = repl::pki::TrustInputs { roots: vec![root.clone()], crls: crls.clone() };
    // Freshness window (0, now]: the nonce already binds the evidence to THIS
    // export, so its age is bounded by the export, not by the host clock (the
    // owner verifies a stored export later). Chain and CRLs are checked at `now`.
    let claims = repl::evidence::verify_evidence_core(
        &evidence,
        &trust,
        now,
        repl::Profile::Educational,
        repl::evidence::EvidenceRole::KeyAttestation,
        &nonce,
        Some((0, now)),
    )
    .map_err(|r| format!("evidence: {}", r.0))?
    .claims;
    // Claims the owner must check on top of the verified signature and chain.
    let k = &claims.key;
    let spki_hash: [u8; 48] = sha2::Sha384::digest(&spki).into();
    if k.public_hash != Some(spki_hash) {
        return Err("attested key is not signer_spki.der".into());
    }
    if k.key_type != CKK_ML_DSA || k.parameter_set != CKP_ML_DSA_65 {
        return Err("attested key is not ML-DSA-65".into());
    }
    if !k.sensitive || k.extractable || !k.never_extractable || !k.local {
        return Err("attested key is not a token-resident, never-extractable key".into());
    }
    let ev = repl::asn1::Evidence::from_der(&evidence).map_err(|_| "evidence DER".to_string())?;
    let mut chain = Vec::new();
    if let Some(leaf) = ev.signatures.first().and_then(|s| s.sid.certificate.as_ref()) {
        chain.push(leaf.tbs_certificate.subject.to_string());
    }
    let device = ev.intermediate_certificates.as_ref().and_then(|v| v.first()).ok_or("no device certificate")?;
    chain.push(device.tbs_certificate.subject.to_string());
    let root_cert = repl::pki::parse_cert(&root).map_err(|_| "root DER".to_string())?;
    chain.push(root_cert.tbs_certificate.subject.to_string());
    // device_id = SHA-256 of the device certificate's SPKI (spec E-03).
    use der::Encode;
    let dev_spki = device.tbs_certificate.subject_public_key_info.to_der().map_err(|_| "device SPKI".to_string())?;
    let dev_id: [u8; 32] = sha2::Sha256::digest(&dev_spki).into();
    if dev_id != claims.device_id {
        return Err("device_id claim does not match the device certificate".into());
    }
    let mut crl_next_update = Vec::new();
    for (p, der) in entries.iter().filter(|p| p.extension().is_some_and(|x| x == "der")).zip(&crls) {
        let c = x509_cert::crl::CertificateList::from_der(der).map_err(|_| format!("CRL DER {}", p.display()))?;
        let next = c.tbs_cert_list.next_update.as_ref().map(repl::pki::time_secs).unwrap_or(0);
        crl_next_update.push((p.file_stem().unwrap().to_string_lossy().trim_end_matches(".crl").to_string(), next));
    }
    let m = tf::FhePublicManifestV1::from_der(&manifest).map_err(|_| "manifest DER".to_string())?;
    Ok(SignerReport {
        signer_spki_sha256: hexs(&sha2::Sha256::digest(&spki)),
        device_id: hexs(&claims.device_id),
        unique_id: k.unique_id.clone(),
        evidence_issued_at: claims.issued_at,
        chain,
        crl_next_update,
        root_sha256: hexs(&sha2::Sha256::digest(&root)),
        lineage: hexs(m.lineage.as_bytes()),
        param_hash: hexs(m.param_hash.as_bytes()),
    })
}

/// One JSON line per directory; exit 0 only if every directory passes and,
/// with several, all share one root, one lineage and one parameter hash.
fn cmd_verify_signer(args: &[String]) -> ! {
    let mut now = now();
    let mut dirs = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--now" {
            now = it.next().and_then(|v| v.parse().ok()).unwrap_or_else(|| {
                eprintln!("usage: --now <unix seconds>");
                std::process::exit(2)
            });
        } else {
            dirs.push(PathBuf::from(a));
        }
    }
    if dirs.is_empty() {
        eprintln!("usage: fhe_custodian verify-signer [--now <unix>] <dir>…");
        std::process::exit(2);
    }
    let mut ok = true;
    let mut seen: Option<(String, String, String)> = None;
    for d in &dirs {
        let mut line = serde_json::json!({ "dir": d.display().to_string(), "now": now });
        match verify_signer_dir(d, now) {
            Ok(r) => {
                let key = (r.root_sha256.clone(), r.lineage.clone(), r.param_hash.clone());
                let consistent = seen.get_or_insert_with(|| key.clone()) == &key;
                line["result"] = if consistent { "pass".into() } else { "fail".into() };
                if !consistent {
                    line["reason"] = "root, lineage or paramHash differs from the first directory".into();
                    ok = false;
                }
                line["signer_spki_sha256"] = r.signer_spki_sha256.into();
                line["device_id"] = r.device_id.into();
                line["unique_id"] = r.unique_id.into();
                line["evidence_issued_at"] = r.evidence_issued_at.into();
                line["chain"] = r.chain.into();
                line["crl_next_update"] = serde_json::Value::Object(r.crl_next_update.into_iter().map(|(k, v)| (k, v.into())).collect());
                line["root_sha256"] = r.root_sha256.into();
                line["lineage"] = r.lineage.into();
                line["param_hash"] = r.param_hash.into();
            }
            Err(reason) => {
                line["result"] = "fail".into();
                line["reason"] = reason.into();
                ok = false;
            }
        }
        println!("{line}");
    }
    std::process::exit(if ok { 0 } else { 1 })
}

/// TEST ONLY (`test-support`): encrypt under the owner's client key, so the
/// decrypt path can be exercised without the compute server.
#[cfg(feature = "test-support")]
fn cmd_encrypt_owner(dir: &Path, ty: &str, value: u64, out: &Path) {
    open(dir);
    let s = ok("user login", native::open_session(0, USER));
    let seed = find(s, SEED_ID, CKO_SECRET_KEY);
    std::fs::write(
        out,
        ok("encrypt_for_test", tf::encrypt_for_test(s, seed, ty, value)),
    )
    .unwrap();
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.get(1).map(String::as_str) == Some("verify-signer") {
        cmd_verify_signer(&a[2..]);
    }
    match (a.get(1).map(String::as_str), a.get(2), a.get(3)) {
        (Some("init"), Some(d), None) => cmd_init(&PathBuf::from(d)),
        (Some("export"), Some(d), None) => cmd_export(&PathBuf::from(d)),
        (Some("decrypt"), Some(d), Some(c)) => cmd_decrypt(&PathBuf::from(d), &PathBuf::from(c)),
        #[cfg(feature = "test-support")]
        (Some("encrypt-owner"), Some(d), Some(t)) => cmd_encrypt_owner(
            &PathBuf::from(d),
            t,
            a[4].parse().unwrap(),
            &PathBuf::from(&a[5]),
        ),
        _ => {
            eprintln!("usage: fhe_custodian init|export <dir> | decrypt <dir> <ciphertext.bin> | verify-signer [--now <unix>] <dir>…");
            std::process::exit(2);
        }
    }
}
