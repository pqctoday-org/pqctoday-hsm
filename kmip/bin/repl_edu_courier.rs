//! `repl_edu_courier` — operator-side tool for the EDUCATIONAL two-board replication test.
//!
//! PQCTODAY EDUCATIONAL TEST ONLY. Built only with
//! `--features educational-replication`. Two subcommands:
//!
//! - `bootstrap`: a fresh test manufacturing root (held in memory for this run only), then
//!   the board-local enrollment of both boards by running `repl_edu_board` on each over SSH
//!   (owner decision O4: root, device and admin enrollment are board-local; this is control-plane
//!   bootstrap, files in and out). Writes the public trust material to `--out`.
//! - `ceremony`: the replication itself over **KMIP on the crypto network only** (owner O1/O2):
//!   challenge → begin_receive → create package → import → receipt, then an independent host
//!   verification of the receipt. The package never travels over SSH.
//!
//! The courier is an untrusted carrier by design: it only moves engine-produced DER.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use pqctoday_kmip::codec;
use pqctoday_kmip::kmip30::ops::Pkcs11Request;
use pqctoday_kmip::kmip30::{wire::encode_request_message, RequestBatchItem, RequestHeader, RequestMessage, RequestPayload};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use softhsmrustv3::constants::{CKM_AES_GCM, CKM_ML_DSA, CKM_ML_KEM};
use softhsmrustv3::replication::{self as repl, host_verify, pki::TrustInputs, test_ca::TestManufacturingCa};

const V1: &str = "PQCTODAY_KEY_REPLICATION_1_0";
const CEREMONY: &str = "PQCTODAY_KEY_REPLICATION_CEREMONY_1_0";
const IFACE_ADMIN: &str = "PQCTODAY_KEY_REPLICATION_ADMIN_1_0";
/// Fixed educational replication domain for this lab.
const DOMAIN: [u8; 32] = *b"PQCTODAY-EDU-LAB-MX95-MX95PRO-01";

const USAGE: &str = "\
repl_edu_courier bootstrap --src HOST --dst HOST --ssh-key KEY --out DIR [--remote-dir /tmp/repl-test] [--fhe]
repl_edu_courier ceremony  --src-kmip IP:PORT --dst-kmip IP:PORT --src-name SNI --dst-name SNI
                           --tls-ca PEM --client-cert PEM --client-key PEM
                           --trust DIR --uid UID --out DIR [--op live|backup|restore] [--negative]
                           [--dst-policy FILE] [--expect-refusal]
repl_edu_courier make-policy --trust DIR --out FILE [--fhe]
repl_edu_courier bootstrap ... --m12 --hook-up CMD --src-kmip IP:PORT --dst-kmip IP:PORT --src-name SNI --dst-name SNI
                 --tls-ca PEM --client-cert PEM --client-key PEM --admin-cert PEM --admin-key PEM
  (M12: board-local admin-authority enrollment, source AES key, then servers up and signed admin
   operations over KMIP on both boards with host-verified receipts and admin negatives)
  (bootstrap test flag: --fhe-skip-dst-decrypt-policy enrolls the FHE decrypt policy on the source only)";

fn main() {
    if let Err(e) = run() {
        eprintln!("repl_edu_courier: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    eprintln!("PQCTODAY EDUCATIONAL TEST ONLY");
    let mut a: Vec<String> = std::env::args().skip(1).collect();
    let cmd = if a.is_empty() { String::new() } else { a.remove(0) };
    match cmd.as_str() {
        "bootstrap" => bootstrap(&mut a),
        "make-policy" => make_policy(&mut a),
        "ceremony" => ceremony(&mut a),
        _ => Err(USAGE.into()),
    }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

// ── bootstrap (control plane, board-local enrollment) ─────────────────────

struct Board {
    host: String,
    key: String,
    dir: String,
}

impl Board {
    fn ssh(&self, remote: &str, stdin: Option<&[u8]>) -> Result<Vec<u8>, String> {
        // `--src local --dst local` = host rehearsal: run the same commands in a local shell
        // against per-board remote dirs, instead of over SSH.
        let mut c = if self.host == "local" {
            let mut c = Command::new("sh");
            c.args(["-c", remote]);
            c
        } else {
            let mut c = Command::new("ssh");
            c.args(["-i", &self.key, "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "-o", "StrictHostKeyChecking=no"])
                .args(["-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR", &format!("admin@{}", self.host), remote]);
            c
        };
        c.stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = c.spawn().map_err(|e| format!("ssh {}: {e}", self.host))?;
        if let Some(data) = stdin {
            child.stdin.take().unwrap().write_all(data).map_err(|e| format!("ssh stdin: {e}"))?;
        }
        let out = child.wait_with_output().map_err(|e| format!("ssh {}: {e}", self.host))?;
        if !out.status.success() {
            return Err(format!("{}: `{remote}` failed: {}", self.host, String::from_utf8_lossy(&out.stderr).trim()));
        }
        Ok(out.stdout)
    }
    /// Run the board tool. PINs come from a 0600 file on the board, never from this command line.
    fn tool(&self, args: &str) -> Result<String, String> {
        let d = &self.dir;
        let out = self.ssh(
            &format!("set -a; . {d}/pins.env; set +a; {d}/repl_edu_board --store {d}/engine {args}"),
            None,
        )?;
        let s = String::from_utf8_lossy(&out).to_string();
        eprintln!("  [{}] repl_edu_board {args}\n{}", self.host, s.trim_end().lines().map(|l| format!("    {l}")).collect::<Vec<_>>().join("\n"));
        Ok(s)
    }
    fn put(&self, name: &str, data: &[u8]) -> Result<(), String> {
        self.ssh(&format!("cat > {}/x/{name}", self.dir), Some(data)).map(|_| ())
    }
    fn get(&self, name: &str) -> Result<Vec<u8>, String> {
        self.ssh(&format!("cat {}/x/{name}", self.dir), None)
    }
}

fn bootstrap(a: &mut Vec<String>) -> Result<(), String> {
    let key = need(a, "--ssh-key")?;
    let dir = opt(a, "--remote-dir").unwrap_or_else(|| "/tmp/repl-test".into());
    // Rehearsal only: distinct local dirs for the two simulated boards.
    let src_dir = opt(a, "--src-dir").unwrap_or_else(|| dir.clone());
    let dst_dir = opt(a, "--dst-dir").unwrap_or_else(|| dir.clone());
    let out = PathBuf::from(need(a, "--out")?);
    let fhe_profile = take_flag(a, "--fhe");
    // TEST ONLY (negative case): leave the destination WITHOUT the FHE decrypt policy, so an FHE
    // seed import there must be refused and install nothing (engine: descriptor's decrypt policy
    // must be enrolled at the destination).
    let skip_dst_dp = take_flag(a, "--fhe-skip-dst-decrypt-policy");
    let boards = [
        Board { host: need(a, "--src")?, key: key.clone(), dir: src_dir },
        Board { host: need(a, "--dst")?, key, dir: dst_dir },
    ];
    std::fs::create_dir_all(&out).map_err(|e| format!("{}: {e}", out.display()))?;
    let t = now();
    let mut ca = TestManufacturingCa::new(t).map_err(rv("test root"))?;
    let root_crl = ca.crl(t - 60, t + 7 * 86_400).map_err(rv("root CRL"))?;
    save(&out, "root.der", ca.root_der())?;
    save(&out, "root-crl.der", &root_crl)?;

    let mut devs = Vec::new();
    for (i, b) in boards.iter().enumerate() {
        let tag = if i == 0 { "src" } else { "dst" };
        b.ssh(&format!("mkdir -p {}/x", b.dir), None)?;
        b.tool("init")?;
        b.tool(&format!("csr {}/x/csr.der", b.dir))?;
        let dev = ca.issue_device(&b.get("csr.der")?, t).map_err(rv("issue device cert"))?;
        b.put("root.der", ca.root_der())?;
        b.put("device-issued.der", &dev)?;
        b.put("root-crl.der", &root_crl)?;
        let d = &b.dir;
        b.tool(&format!("complete {d}/x/root.der {d}/x/device-issued.der {d}/x/root-crl.der {d}/x"))?;
        let (cert, crl, id) = (b.get("device.der")?, b.get("device-crl.der")?, b.get("device-id.bin")?);
        save(&out, &format!("{tag}-device.der"), &cert)?;
        save(&out, &format!("{tag}-device-crl.der"), &crl)?;
        save(&out, &format!("{tag}-device-id.bin"), &id)?;
        devs.push((cert, crl, <[u8; 32]>::try_from(id.as_slice()).map_err(|_| "device id size")?));
    }
    // Each board enrolls the other's device certificate and device CRL.
    for (i, b) in boards.iter().enumerate() {
        let (cert, crl, _) = &devs[1 - i];
        b.put("peer-device.der", cert)?;
        b.put("peer-crl.der", crl)?;
        b.tool(&format!("peer {0}/x/peer-device.der {0}/x/peer-crl.der", b.dir))?;
    }
    // One policy naming both devices, enrolled on both. With --fhe it is constrained to the FHE
    // seed profile (FHE plan stage F) and each board also enrolls the typed decrypt policy.
    let policy = if fhe_profile {
        fhe_policy(&devs, t)?
    } else {
        let mut mechs = vec![CKM_AES_GCM, CKM_ML_KEM, CKM_ML_DSA];
        mechs.sort_unstable();
        repl::records::build_policy(DOMAIN, [true, true, true], vec![devs[0].2, devs[1].2], t - 60, t + 7 * 86_400, 4, mechs, false)
            .map_err(rv("build policy"))?
    };
    if fhe_profile {
        let enrolled: &[Board] = if skip_dst_dp { &boards[..1] } else { &boards[..] };
        for b in enrolled {
            b.tool(&format!("fhe-policy {0}/x/fhe-dp-id.bin", b.dir))?;
        }
        let dp = boards[0].get("fhe-dp-id.bin")?;
        if !skip_dst_dp && boards[1].get("fhe-dp-id.bin")? != dp {
            return Err("the two boards computed different FHE decrypt-policy ids".into());
        }
        save(&out, "fhe-dp-id.bin", &dp)?;
    }
    save(&out, "policy.der", &policy)?;
    for b in &boards {
        b.put("policy.der", &policy)?;
        b.tool(&format!("policy {0}/x/policy.der {0}/x/policy-id.bin", b.dir))?;
    }
    let pid = boards[0].get("policy-id.bin")?;
    if boards[1].get("policy-id.bin")? != pid {
        return Err("the two boards computed different policy ids".into());
    }
    save(&out, "policy-id.bin", &pid)?;
    println!("bootstrap OK: both boards enrolled under one test root; policy id {}", hex(&pid[..8]));
    if take_flag(a, "--m12") {
        m12(a, &mut ca, &boards, &devs, &out, t)?;
    }
    Ok(())
}

// ── M12: signed administration over KMIP (admin addendum 3.2; engine M9 + C1) ─────────

fn m12(a: &mut Vec<String>, ca: &mut TestManufacturingCa, boards: &[Board; 2], devs: &[(Vec<u8>, Vec<u8>, [u8; 32])], out: &Path, t: u64) -> Result<(), String> {
    use softhsmrustv3::replication::admin::AdminOperation;
    use softhsmrustv3::replication::{admin_host, test_ca::AdminAuthorityKey};
    let hook_up = need(a, "--hook-up")?;
    let ca_pem = need(a, "--tls-ca")?;
    let user_tls = tls_config(&ca_pem, &need(a, "--client-cert")?, &need(a, "--client-key")?)?;
    let admin_tls = tls_config(&ca_pem, &need(a, "--admin-cert")?, &need(a, "--admin-key")?)?;
    let parse = |addr: String| -> Result<(String, u16), String> {
        let (h, p) = addr.rsplit_once(':').ok_or("address must be IP:PORT")?;
        Ok((h.to_string(), p.parse().map_err(|_| "bad port")?))
    };
    let addrs = [(parse(need(a, "--src-kmip")?)?, need(a, "--src-name")?), (parse(need(a, "--dst-kmip")?)?, need(a, "--dst-name")?)];

    // 1. Board-local: admin-authority certificate (host-held key) on both boards.
    let ak = AdminAuthorityKey::new(ca, t).map_err(rv("admin authority key"))?;
    save(out, "admin-authority.der", &ak.cert_der)?;
    for b in boards {
        b.put("admin-authority.der", &ak.cert_der)?;
        b.tool(&format!("admin-enroll {}/x/admin-authority.der", b.dir))?;
    }
    // 2. Board-local: the source key for the post-admin live clone (servers still down).
    let d0 = &boards[0].dir;
    boards[0].ssh(&format!("mkdir -p {d0}/x/m12-aes"), None)?;
    boards[0].tool(&format!("genkey aes256 {d0}/x/policy-id.bin {d0}/x/m12-aes"))?;
    save(out, "m12-src-uid.txt", &boards[0].get("m12-aes/uid.txt")?)?;
    // 3. Servers up (the runner's hook: stop appliance kmip, start the test servers).
    println!("== M12 hook-up: {hook_up}");
    let st = Command::new("sh").args(["-c", &hook_up]).status().map_err(|e| format!("hook-up: {e}"))?;
    if !st.success() {
        return Err("hook-up failed".into());
    }
    let ep = |i: usize, tls: &Arc<rustls::ClientConfig>| Kmip { host: addrs[i].0 .0.clone(), port: addrs[i].0 .1, sni: addrs[i].1.clone(), tls: tls.clone() };
    let mut trust = TrustInputs { roots: vec![ca.root_der().to_vec()], crls: vec![load(out, "root-crl.der")?, load(out, "src-device-crl.der")?, load(out, "dst-device-crl.der")?] };
    let key_id = ak.key_id();
    let mut log = String::new();
    let mut line = |l: String| {
        println!("{l}");
        log.push_str(&l);
        log.push('\n');
    };
    let rc_name = |rc: i32| format!("0x{:08x}", rc as u32);

    // One signed admin call: fresh nonce, sign, execute, verify the receipt on the host.
    let run = |admin: &Kmip, dev: &[u8; 32], seq: u64, op: &AdminOperation, trust: &TrustInputs| -> Result<(i32, Vec<u8>, Vec<u8>), String> {
        let (rc, nonce, _, _) = admin.call(IFACE_ADMIN, 1, &[])?;
        if rc != 0 {
            return Ok((rc, Vec::new(), Vec::new()));
        }
        let nonce: [u8; 32] = nonce.try_into().map_err(|_| "nonce size")?;
        let tbs = admin_host::tbs_request(dev, &key_id, &nonce, seq, now(), op).map_err(rv("tbs_request"))?;
        let sig = ak.sign(&admin_host::request_signed_bytes(&tbs)).map_err(rv("admin sign"))?;
        let req = admin_host::signed_request(&tbs, &sig).map_err(rv("signed_request"))?;
        let (rc, receipt, _, _) = admin.call(IFACE_ADMIN, 2, &req)?;
        if rc == 0 {
            host_verify::verify_admin_receipt(&receipt, &req, trust, now(), repl::Profile::Educational).map_err(|e| format!("admin receipt verify: {e:?}"))?;
        }
        Ok((rc, req, receipt))
    };

    for (i, b) in boards.iter().enumerate() {
        let admin = ep(i, &admin_tls);
        let user = ep(i, &user_tls);
        let dev = devs[i].2;
        let other = devs[1 - i].2;
        let name = if i == 0 { "src" } else { "dst" };
        // seq 1: enroll a policy (a v2 of the bootstrap policy, longer validity).
        let mut mechs = vec![CKM_AES_GCM, CKM_ML_KEM, CKM_ML_DSA];
        mechs.sort_unstable();
        let p2 = repl::records::build_policy(DOMAIN, [true, true, true], vec![devs[0].2, devs[1].2], t - 60, t + 14 * 86_400, 4, mechs, false).map_err(rv("policy v2"))?;
        let (rc, req1, rcpt1) = run(&admin, &dev, 1, &AdminOperation::EnrollPolicy { policy: p2 }, &trust)?;
        line(format!("[{name}] seq1 enrollPolicy            CK_RV={} receipt={} B{}", rc_name(rc), rcpt1.len(), if rc == 0 { "  receipt host-verified" } else { "" }));
        if rc != 0 {
            return Err(format!("{name}: enrollPolicy refused"));
        }
        // Negatives.
        let (rc, retry, _, _) = admin.call(IFACE_ADMIN, 2, &req1)?;
        let same = rc == 0 && retry == rcpt1;
        line(format!("[{name}] NEG exact retry → same receipt            {}", if same { "PASS" } else { "FAIL" }));
        if !same {
            return Err("exact admin retry did not return the stored receipt".into());
        }
        let mut neg = |what: &str, r: (i32, Vec<u8>, Vec<u8>)| -> Result<(), String> {
            line(format!("[{name}] NEG {what:<36} CK_RV={}", rc_name(r.0)));
            if r.0 == 0 { Err(format!("FAIL {name}: {what} accepted")) } else { Ok(()) }
        };
        neg("sequence gap (3 instead of 2)", run(&admin, &dev, 3, &AdminOperation::RotateRecoveryKey, &trust)?)?;
        neg("wrong device id (peer's)", run(&admin, &other, 2, &AdminOperation::RotateRecoveryKey, &trust)?)?;
        {
            let (rc, nonce, _, _) = admin.call(IFACE_ADMIN, 1, &[])?;
            let nonce: [u8; 32] = nonce.try_into().map_err(|_| format!("nonce rc {}", rc_name(rc)))?;
            let tbs = admin_host::tbs_request(&dev, &key_id, &nonce, 2, now(), &AdminOperation::RotateRecoveryKey).map_err(rv("tbs"))?;
            let mut sig = ak.sign(&admin_host::request_signed_bytes(&tbs)).map_err(rv("sign"))?;
            sig[100] ^= 1;
            let req = admin_host::signed_request(&tbs, &sig).map_err(rv("signed_request"))?;
            let (rc, _, _, _) = admin.call(IFACE_ADMIN, 2, &req)?;
            neg("tampered signature", (rc, Vec::new(), Vec::new()))?;
            // the consumed-or-replaced nonce is now stale: reuse it with a correct signature
            let sig2 = ak.sign(&admin_host::request_signed_bytes(&tbs)).map_err(rv("sign"))?;
            let _ = admin.call(IFACE_ADMIN, 1, &[])?; // replace-on-issue makes `nonce` stale
            let req2 = admin_host::signed_request(&tbs, &sig2).map_err(rv("signed_request"))?;
            let (rc, _, _, _) = admin.call(IFACE_ADMIN, 2, &req2)?;
            neg("stale (replaced) nonce", (rc, Vec::new(), Vec::new()))?;
        }
        let (rc, _, _, _) = user.call(IFACE_ADMIN, 1, &[])?;
        line(format!("[{name}] NEG user-role connection → admin     CK_RV={} {}", rc_name(rc), if rc == 0x103 { "PASS" } else { "FAIL" }));
        if rc != 0x103 {
            return Err("user role reached the admin interface".into());
        }
        let (rc, _, _, _) = admin.call(CEREMONY, 1, &[])?;
        line(format!("[{name}] NEG admin-role connection → ceremony CK_RV={} {}", rc_name(rc), if rc == 0x103 { "PASS" } else { "FAIL" }));
        if rc != 0x103 {
            return Err("admin role reached a user interface".into());
        }
        // seq 2..4: rotation, a newer root CRL, function re-issuance.
        let (rc, _, r2) = run(&admin, &dev, 2, &AdminOperation::RotateRecoveryKey, &trust)?;
        line(format!("[{name}] seq2 rotateRecoveryKey       CK_RV={} receipt={} B", rc_name(rc), r2.len()));
        if rc != 0 { return Err("rotateRecoveryKey refused".into()); }
        let crl2 = ca.crl(now() - 60, now() + 7 * 86_400).map_err(rv("root CRL 2"))?;
        let (rc, _, r3) = run(&admin, &dev, 3, &AdminOperation::EnrollCrl { crl: crl2.clone(), issuer_device_cert: None }, &trust)?;
        line(format!("[{name}] seq3 enrollCrl (newer root)   CK_RV={} receipt={} B", rc_name(rc), r3.len()));
        if rc != 0 { return Err("enrollCrl refused".into()); }
        trust.crls[0] = crl2.clone();
        // keep the second board on the same root CRL number sequence
        if i == 0 {
            let _ = b;
        }
        let (rc, _, r4) = run(&admin, &dev, 4, &AdminOperation::IssueFunctionCerts, &trust)?;
        line(format!("[{name}] seq4 issueFunctionCerts       CK_RV={} receipt={} B", rc_name(rc), r4.len()));
        if rc != 0 { return Err("issueFunctionCerts refused".into()); }
    }
    save(out, "root-crl.der", &trust.crls[0])?;
    save(out, "m12-admin.log", log.as_bytes())?;
    println!("M12 admin phase PASS on both boards (servers left up for the post-admin ceremony)");
    Ok(())
}

#[cfg(feature = "educational-fhe")]
fn fhe_policy(devs: &[(Vec<u8>, Vec<u8>, [u8; 32])], t: u64) -> Result<Vec<u8>, String> {
    use softhsmrustv3::constants::{CKM_PQCTODAY_FHE_DECRYPT, CKM_PQCTODAY_FHE_DERIVE_PUBLIC};
    let mut mechs = vec![CKM_PQCTODAY_FHE_DERIVE_PUBLIC, CKM_PQCTODAY_FHE_DECRYPT];
    mechs.sort_unstable();
    repl::records::build_policy_with_constraint(
        DOMAIN,
        [true, true, true],
        vec![devs[0].2, devs[1].2],
        t - 60,
        t + 7 * 86_400,
        4,
        mechs,
        false,
        repl::fhe::profile_constraint_hash(),
    )
    .map_err(rv("build FHE policy"))
}

#[cfg(not(feature = "educational-fhe"))]
fn fhe_policy(_: &[(Vec<u8>, Vec<u8>, [u8; 32])], _: u64) -> Result<Vec<u8>, String> {
    Err("--fhe needs a courier built with --features educational-fhe".into())
}

/// Build a replication policy over the two devices in a bootstrap trust dir (negative cases).
fn make_policy(a: &mut Vec<String>) -> Result<(), String> {
    let trust = PathBuf::from(need(a, "--trust")?);
    let out = PathBuf::from(need(a, "--out")?);
    let fhe = take_flag(a, "--fhe");
    let id = |n: &str| -> Result<[u8; 32], String> { load(&trust, n)?.try_into().map_err(|_| format!("{n}: not 32 bytes")) };
    let devs = [(Vec::new(), Vec::new(), id("src-device-id.bin")?), (Vec::new(), Vec::new(), id("dst-device-id.bin")?)];
    let t = now();
    let policy = if fhe {
        fhe_policy(&devs, t)?
    } else {
        let mut mechs = vec![CKM_AES_GCM, CKM_ML_KEM, CKM_ML_DSA];
        mechs.sort_unstable();
        repl::records::build_policy(DOMAIN, [true, true, true], vec![devs[0].2, devs[1].2], t - 60, t + 7 * 86_400, 4, mechs, false)
            .map_err(rv("build policy"))?
    };
    std::fs::write(&out, &policy).map_err(|e| format!("{}: {e}", out.display()))?;
    println!("wrote {} ({} B, fhe={fhe})", out.display(), policy.len());
    Ok(())
}

// ── ceremony (crypto plane, KMIP only) ────────────────────────────────────

struct Kmip {
    host: String,
    port: u16,
    sni: String,
    tls: Arc<rustls::ClientConfig>,
}

impl Kmip {
    /// One PKCS#11 operation (0x33) in one Request Message. `function` is the KMIP 1-based value.
    fn call(&self, iface: &str, function: u32, input: &[u8]) -> Result<(i32, Vec<u8>, f64, Option<String>), String> {
        let req = RequestMessage {
            header: RequestHeader::v3(),
            batch_items: vec![RequestBatchItem {
                operation: pqctoday_kmip::kmip30::Operation::Pkcs11,
                payload: RequestPayload::Pkcs11(Pkcs11Request {
                    interface: Some(iface.to_string()),
                    function,
                    correlation_value: None,
                    input_parameters: if input.is_empty() { None } else { Some(input.to_vec()) },
                }),
            }],
        };
        let bytes = encode_request_message(&req).ok_or("request encoding failed")?;
        let started = Instant::now();
        let name = rustls::pki_types::ServerName::try_from(self.sni.clone()).map_err(|e| format!("SNI {}: {e}", self.sni))?;
        let conn = rustls::ClientConnection::new(self.tls.clone(), name).map_err(|e| format!("TLS: {e}"))?;
        let sock = TcpStream::connect((self.host.as_str(), self.port)).map_err(|e| format!("connect {}:{}: {e}", self.host, self.port))?;
        let mut tls = rustls::StreamOwned::new(conn, sock);
        tls.write_all(&bytes).map_err(|e| format!("write: {e}"))?;
        let _ = tls.flush();
        let mut resp = Vec::new();
        match tls.read_to_end(&mut resp) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {}
            Err(e) => return Err(format!("read: {e}")),
        }
        let ms = started.elapsed().as_secs_f64() * 1e3;
        let kx = tls.conn.negotiated_key_exchange_group().map(|g| format!("{:?}", g.name()));
        let (frame, _) = codec::decode(&resp).map_err(|e| format!("response TTLV: {e:?}"))?;
        let (mut rc, mut out, mut status, mut msg) = (None, Vec::new(), None, None);
        walk(&frame, &mut |tag, v| match (tag, v) {
            (0x42_015d, codec::Value::Integer(i)) => rc = Some(*i),
            (0x42_015c, codec::Value::ByteString(b)) => out = b.clone(),
            (0x42_007f, codec::Value::Enumeration(e)) => status = Some(*e),
            (0x42_007d, codec::Value::TextString(s)) => msg = Some(s.clone()),
            _ => {}
        });
        match (status, rc) {
            (Some(0), Some(rc)) => Ok((rc, out, ms, kx)),
            _ => Err(format!("KMIP failure: status {status:?}, message {msg:?}")),
        }
    }
}

fn walk(f: &codec::TtlvFrame, visit: &mut dyn FnMut(u32, &codec::Value)) {
    visit(f.tag.0, &f.value);
    if let codec::Value::Structure(children) = &f.value {
        for c in children {
            walk(c, visit);
        }
    }
}

fn ceremony(a: &mut Vec<String>) -> Result<(), String> {
    let tls = tls_config(&need(a, "--tls-ca")?, &need(a, "--client-cert")?, &need(a, "--client-key")?)?;
    let ep = |addr: String, sni: String| -> Result<Kmip, String> {
        let (h, p) = addr.rsplit_once(':').ok_or("address must be IP:PORT")?;
        Ok(Kmip { host: h.into(), port: p.parse().map_err(|_| "bad port")?, sni, tls: tls.clone() })
    };
    let src = ep(need(a, "--src-kmip")?, need(a, "--src-name")?)?;
    let dst = ep(need(a, "--dst-kmip")?, need(a, "--dst-name")?)?;
    let trust_dir = PathBuf::from(need(a, "--trust")?);
    let uid = need(a, "--uid")?;
    let out = PathBuf::from(need(a, "--out")?);
    let op: u8 = match opt(a, "--op").as_deref() {
        None | Some("live") => 0,
        Some("backup") => 1,
        Some("restore") => 2,
        Some(o) => return Err(format!("unknown --op {o}")),
    };
    let negative = take_flag(a, "--negative");
    // Negative-case mode: some step MUST be refused; success of the whole ceremony is a failure.
    let expect_refusal = take_flag(a, "--expect-refusal");
    std::fs::create_dir_all(&out).map_err(|e| format!("{}: {e}", out.display()))?;
    // The destination requests its own enrolled policy; default = the shared bootstrap policy.
    let pid = match opt(a, "--dst-policy") {
        Some(p) => std::fs::read(&p).map_err(|e| format!("{p}: {e}"))?,
        None => load(&trust_dir, "policy-id.bin")?,
    };
    if pid.len() != 48 || uid.len() != 36 {
        return Err("policy id must be 48 bytes and --uid 36 characters".into());
    }
    let mut log = String::new();
    let mut step = |name: &str, r: &(i32, Vec<u8>, f64, Option<String>)| {
        let line = format!("{name:<28} CK_RV=0x{:08x} out={:>6} B  {:>7.1} ms  kx={}", r.0 as u32, r.1.len(), r.2, r.3.as_deref().unwrap_or("?"));
        println!("{line}");
        log.push_str(&line);
        log.push('\n');
    };
    // In --expect-refusal mode a refused step ends the ceremony successfully ("REFUSED as expected").
    let ok = |r: &(i32, Vec<u8>, f64, Option<String>), what: &str| -> Result<(), String> {
        if r.0 == 0 {
            Ok(())
        } else if expect_refusal {
            Err(format!("EXPECTED-REFUSAL {what}: CK_RV 0x{:08x}", r.0 as u32))
        } else {
            Err(format!("{what}: CK_RV 0x{:08x}", r.0 as u32))
        }
    };
    let steps = (|| -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {

    // 1. source issues its challenge (ceremony fn 1 = IssueSourceChallenge).
    let r = src.call(CEREMONY, 1, &[])?;
    step("src IssueSourceChallenge", &r);
    ok(&r, "IssueSourceChallenge")?;
    let chal = r.1;
    // 2. destination begins receiving (ceremony fn 2): the BeginReceive DER (addendum §6.9).
    let br = repl::asn1::to_der(&repl::admin::BeginReceive {
        version: 1,
        operation: match op {
            0 => repl::asn1::Operation::LiveClone,
            1 => repl::asn1::Operation::OfflineBackup,
            _ => repl::asn1::Operation::Restore,
        },
        source_challenge: repl::asn1::octets(&chal),
        domain_id: repl::asn1::octets(&DOMAIN),
        requested_policy: repl::asn1::octets(&pid),
    })
    .map_err(|e| format!("BeginReceive DER: CK_RV 0x{e:08x}"))?;
    let r = dst.call(CEREMONY, 2, &br)?;
    step("dst BeginReceive", &r);
    ok(&r, "BeginReceive")?;
    let request = r.1;
    // 3. source creates the package (v1 fn 1), key by CKA_UNIQUE_ID.
    let r = src.call(V1, 1, &key_call(uid.as_bytes(), &request))?;
    step("src CreateReplicationPackage", &r);
    ok(&r, "CreateReplicationPackage")?;
    let package = r.1;
    // 4. destination imports (v1 fn 2) and returns the receipt.
    let r = dst.call(V1, 2, &package)?;
    step("dst ImportReplicationPackage", &r);
    ok(&r, "ImportReplicationPackage")?;
    Ok((request, package, r.1))
    })();
    let (request, package, receipt) = match steps {
        Ok(v) if expect_refusal => {
            save(&out, "ceremony.log", log.as_bytes())?;
            let _ = v;
            return Err("FAIL: --expect-refusal but every step was accepted".into());
        }
        Ok(v) => v,
        Err(e) if expect_refusal && e.starts_with("EXPECTED-REFUSAL") => {
            println!("PASS refused as expected — {}", e.trim_start_matches("EXPECTED-REFUSAL "));
            log.push_str(&format!("PASS {e}\n"));
            save(&out, "ceremony.log", log.as_bytes())?;
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    save(&out, "request.der", &request)?;
    save(&out, "package.der", &package)?;
    save(&out, "receipt.der", &receipt)?;

    // 5. independent host verification of the receipt (third party: neither board).
    let trust = TrustInputs {
        roots: vec![load(&trust_dir, "root.der")?],
        crls: vec![load(&trust_dir, "root-crl.der")?, load(&trust_dir, "src-device-crl.der")?, load(&trust_dir, "dst-device-crl.der")?],
    };
    match host_verify::verify_receipt(&receipt, &package, &request, &trust, now(), repl::Profile::Educational) {
        Ok(_) => {
            println!("PASS receipt verified on the operator host against the test root and both device CRLs");
            log.push_str("PASS host_verify::verify_receipt\n");
        }
        Err(e) => return Err(format!("FAIL host receipt verification: {e:?}")),
    }

    if negative {
        let expect_refused = |name: &str, r: (i32, Vec<u8>, f64, Option<String>), log: &mut String| -> Result<(), String> {
            let line = format!("NEG {name:<36} CK_RV=0x{:08x}", r.0 as u32);
            println!("{line}");
            log.push_str(&line);
            log.push('\n');
            if r.0 == 0 { Err(format!("FAIL {name}: accepted")) } else { Ok(()) }
        };
        // Exact retry of a committed import must return the byte-identical receipt (recovery path).
        let r = dst.call(V1, 2, &package)?;
        let same = r.0 == 0 && r.1 == receipt;
        let line = format!("NEG exact retry → same receipt              {}", if same { "PASS" } else { "FAIL" });
        println!("{line}");
        log.push_str(&line);
        log.push('\n');
        if !same {
            return Err("FAIL exact retry did not return the stored receipt".into());
        }
        // One flipped byte in the signed region.
        let mut t = package.clone();
        let i = t.len() / 2;
        t[i] ^= 0x01;
        expect_refused("tampered package", dst.call(V1, 2, &t)?, &mut log)?;
        // Package delivered to the wrong recipient (the source).
        expect_refused("wrong recipient (package to source)", src.call(V1, 2, &package)?, &mut log)?;
        // Ordinal 0 is invalid on the 1-based KMIP wire; CloneKey is not offered over KMIP.
        expect_refused("function value 0", src.call(V1, 0, &[])?, &mut log)?;
        expect_refused("CloneKey over KMIP", src.call(V1, 3, &[])?, &mut log)?;
        // Unknown key reference.
        expect_refused("unknown CKA_UNIQUE_ID", src.call(V1, 1, &key_call(&[b'0'; 36], &request))?, &mut log)?;
    }
    save(&out, "ceremony.log", log.as_bytes())?;
    Ok(())
}

/// DER `SEQUENCE { keyUniqueID UTF8String (SIZE(36)), payload OCTET STRING }`.
fn key_call(uid: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut body = tlv(0x0c, uid);
    body.extend(tlv(0x04, payload));
    tlv(0x30, &body)
}

fn tlv(tag: u8, v: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match v.len() {
        n if n < 0x80 => out.push(n as u8),
        n if n < 0x100 => out.extend([0x81, n as u8]),
        n if n < 0x10000 => out.extend([0x82, (n >> 8) as u8, n as u8]),
        n => out.extend([0x83, (n >> 16) as u8, (n >> 8) as u8, n as u8]),
    }
    out.extend_from_slice(v);
    out
}

/// TLS 1.3, hybrid ML-KEM groups only, mutual TLS — the KMIP 3.0 quantum-safe profile.
fn tls_config(ca: &str, cert: &str, key: &str) -> Result<Arc<rustls::ClientConfig>, String> {
    let read = |p: &str| std::fs::read(p).map_err(|e| format!("{p}: {e}"));
    let mut roots = rustls::RootCertStore::empty();
    for c in CertificateDer::pem_slice_iter(&read(ca)?) {
        roots.add(c.map_err(|e| format!("CA PEM: {e}"))?).map_err(|e| format!("CA: {e}"))?;
    }
    let certs = CertificateDer::pem_slice_iter(&read(cert)?).collect::<Result<Vec<_>, _>>().map_err(|e| format!("client cert: {e}"))?;
    let key = PrivateKeyDer::from_pem_slice(&read(key)?).map_err(|e| format!("client key: {e}"))?;
    let provider = rustls::crypto::CryptoProvider {
        cipher_suites: vec![
            rustls::crypto::aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
            rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384,
        ],
        kx_groups: vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768, rustls::crypto::aws_lc_rs::kx_group::SECP256R1MLKEM768],
        ..rustls::crypto::aws_lc_rs::default_provider()
    };
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| format!("TLS: {e}"))?
        .with_root_certificates(roots)
        .with_client_auth_cert(certs, key)
        .map_err(|e| format!("client auth: {e}"))?;
    Ok(Arc::new(cfg))
}

// ── plumbing ──────────────────────────────────────────────────────────────

fn opt(a: &mut Vec<String>, name: &str) -> Option<String> {
    let i = a.iter().position(|x| x == name)?;
    let v = a.get(i + 1).cloned();
    a.drain(i..(i + 2).min(a.len()));
    v
}
fn need(a: &mut Vec<String>, name: &str) -> Result<String, String> {
    opt(a, name).ok_or_else(|| format!("{name} required\n{USAGE}"))
}
fn take_flag(a: &mut Vec<String>, name: &str) -> bool {
    match a.iter().position(|x| x == name) {
        Some(i) => {
            a.remove(i);
            true
        }
        None => false,
    }
}
fn rv(what: &'static str) -> impl Fn(u32) -> String {
    move |r| format!("{what}: CK_RV 0x{r:08x}")
}
fn save(dir: &Path, name: &str, data: &[u8]) -> Result<(), String> {
    std::fs::write(dir.join(name), data).map_err(|e| format!("{name}: {e}"))
}
fn load(dir: &Path, name: &str) -> Result<Vec<u8>, String> {
    std::fs::read(dir.join(name)).map_err(|e| format!("{}/{name}: {e}", dir.display()))
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
