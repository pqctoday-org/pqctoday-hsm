//! `repl_edu_board` — board-local tool for the EDUCATIONAL two-board replication test.
//!
//! PQCTODAY EDUCATIONAL TEST ONLY. Built only with `--features educational-replication`.
//! Runs ON a board, against the engine's durable SQLite store (`--store`), and never
//! while a KMIP server holds the same store: engine state is process-global, so the
//! store is shared SEQUENTIALLY with the test KMIP server, never concurrently.
//!
//! SO subcommands are the board-local bootstrap (owner decision O4): device enrollment,
//! function certificates, peer/root CRLs and policy. User subcommands generate a
//! replication-eligible key (eligibility binds only at C_GenerateKey/C_GenerateKeyPair)
//! and run the functional checks that prove a replica is the same key. Nothing here
//! talks to the network; files in, files out.
//!
//! PINs come from the environment (`REPL_SO_PIN`, `REPL_USER_PIN`) so they never appear
//! in a process listing.

use std::path::{Path, PathBuf};

use softhsmrustv3::constants::*;
use softhsmrustv3::native;
use softhsmrustv3::replication as repl;

const USAGE: &str = "\
repl_edu_board --store DIR [--slot N] <command> [args]
  init                                   initialise the token (SO + user PIN) if needed
  csr OUT                                SO: begin device enrollment, write the CSR
  complete ROOT DEV ROOTCRL OUTDIR       SO: finish enrollment, issue function certs;
                                         writes OUTDIR/{device.der,device-crl.der,device-id.bin}
  peer DEV CRL                           SO: enroll a peer device certificate + its CRL
  root-crl CRL                           SO: enroll a newer root CRL
  policy POLICY OUT                      SO: enroll a policy, write its 48-byte id
  genkey KIND POLICYID OUTDIR            user: policy-bound key; KIND = aes256|mlkem768|mldsa65;
                                         writes OUTDIR/{uid.txt,lineage.bin[,pub-uid.txt]}
  check-src KIND UID PUBUID OUTDIR       user, source: AES encrypt / ML-KEM encapsulate a vector
  check-dst KIND LINEAGE INDIR OUTDIR    user, destination: decrypt / decapsulate / sign with the replica
  check-verify PUBUID INDIR              user, source: verify the replica's ML-DSA signature
  count-lineage LINEAGE                  user: print how many secret/private keys carry this lineage
  uid-of-lineage LINEAGE                 user: print the CKA_UNIQUE_ID of the one key with this lineage
  destroy-lineage LINEAGE                user: C_DestroyObject on the one key with this lineage
                                         (restore proof: the source key is gone before restore)
FHE (built with --features educational-fhe; FHE plan stage F, PR #318 engine):
  fhe-policy OUT                         SO: enroll the fixed typed decrypt policy, write its 48-byte id
  fhe-genkey RPID DPID OUTDIR            user: FHE seed bound to replication policy RPID + decrypt policy
                                         DPID, plus a token ML-DSA-65 manifest signer;
                                         writes OUTDIR/{uid.txt,lineage.bin}
  fhe-export LINEAGE OUTDIR              user: compressed server key + compact public key with signed
                                         manifests, signer SPKI, signer evidence, device CRL
                                         (the layout of rust/examples/fhe_custodian.rs `export`)
  fhe-decrypt LINEAGE CT                 user: typed policy-gated decrypt of one result ciphertext;
                                         prints 'released <Type> = <v>' (exit 0) or 'refused ...' (exit 1)
env: REPL_SO_PIN, REPL_USER_PIN (required)";

const IV: [u8; 12] = [0x51; 12];
const AAD: &[u8] = b"pqctoday-edu-two-board";
const VECTOR: &[u8] = b"PQCTODAY EDUCATIONAL TEST ONLY: two-board replication vector";

fn main() {
    if let Err(e) = run() {
        eprintln!("repl_edu_board: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let store = take_opt(&mut args, "--store").ok_or_else(|| format!("--store required\n{USAGE}"))?;
    let slot: u32 = take_opt(&mut args, "--slot").map(|s| s.parse().map_err(|_| "bad --slot".to_string())).transpose()?.unwrap_or(0);
    let cmd = args.first().cloned().ok_or_else(|| USAGE.to_string())?;
    let a = &args[1..];

    eprintln!("PQCTODAY EDUCATIONAL TEST ONLY — repl_edu_board {cmd}");
    softhsmrustv3::store::configure_persistent_store(&store).map_err(|e| format!("store {store}: {e}"))?;
    repl::select_educational_profile();
    native::init().map_err(ck("init"))?;

    let so_pin = env("REPL_SO_PIN")?;
    let user_pin = env("REPL_USER_PIN")?;

    match (cmd.as_str(), a.len()) {
        ("init", 0) => {
            if softhsmrustv3::state::is_token_initialized(slot) {
                println!("token already initialised on slot {slot}");
            } else {
                native::init_token(slot, &so_pin, "pqctoday-edu-repl").map_err(ck("init_token"))?;
                let so = native::open_session_so(slot, &so_pin).map_err(ck("SO session"))?;
                native::init_pin(so, &user_pin).map_err(ck("init_pin"))?;
                end(so);
                println!("token initialised on slot {slot}");
            }
        }
        ("csr", 1) => as_so(slot, &so_pin, |so| {
            let csr = repl::begin_device_enrollment(so).map_err(ck("begin_device_enrollment"))?;
            write(&a[0], &csr)
        })?,
        ("complete", 4) => as_so(slot, &so_pin, |so| {
            let (root, dev, crl) = (read(&a[0])?, read(&a[1])?, read(&a[2])?);
            repl::complete_device_enrollment(so, &root, &dev, &crl).map_err(ck("complete_device_enrollment"))?;
            repl::issue_function_certificates(so).map_err(ck("issue_function_certificates"))?;
            let out = PathBuf::from(&a[3]);
            write(out.join("device.der"), &repl::device_certificate(so).map_err(ck("device_certificate"))?)?;
            write(out.join("device-crl.der"), &repl::own_device_crl(so).map_err(ck("own_device_crl"))?)?;
            write(out.join("device-id.bin"), &repl::device_id(so).map_err(ck("device_id"))?)
        })?,
        ("peer", 2) => as_so(slot, &so_pin, |so| {
            let (dev, crl) = (read(&a[0])?, read(&a[1])?);
            repl::enroll_crl(so, &crl, Some(&dev)).map_err(ck("enroll_crl(peer)"))
        })?,
        ("root-crl", 1) => as_so(slot, &so_pin, |so| repl::enroll_crl(so, &read(&a[0])?, None).map_err(ck("enroll_crl(root)")))?,
        ("policy", 2) => as_so(slot, &so_pin, |so| {
            let id = repl::enroll_policy(so, &read(&a[0])?).map_err(ck("enroll_policy"))?;
            write(&a[1], &id)
        })?,
        ("genkey", 3) => as_user(slot, &user_pin, |s| {
            let pid: [u8; 48] = read(&a[1])?.try_into().map_err(|_| "policy id must be 48 bytes".to_string())?;
            let out = PathBuf::from(&a[2]);
            let (key, public) = genkey(s, &a[0], &pid)?;
            write(out.join("uid.txt"), &attr(s, key, CKA_UNIQUE_ID)?)?;
            write(out.join("lineage.bin"), &attr(s, key, CKA_PQCTODAY_REPLICATION_LINEAGE_ID)?)?;
            if let Some(p) = public {
                write(out.join("pub-uid.txt"), &attr(s, p, CKA_UNIQUE_ID)?)?;
            }
            Ok(())
        })?,
        ("check-src", 4) => as_user(slot, &user_pin, |s| {
            let out = PathBuf::from(&a[3]);
            match a[0].as_str() {
                "aes256" => {
                    let k = by_uid(s, a[1].as_bytes())?;
                    let ct = native::encrypt(s, k, CKM_AES_GCM, VECTOR, Some(&IV), None, AAD, Some(16)).map_err(ck("encrypt"))?;
                    write(out.join("ct.bin"), &ct)
                }
                "mlkem768" => {
                    let p = by_uid(s, a[2].as_bytes())?;
                    let (ct, ss) = native::encapsulate(s, p, CKM_ML_KEM).map_err(ck("encapsulate"))?;
                    write(out.join("ct.bin"), &ct)?;
                    write(out.join("ss.bin"), &ss)
                }
                "mldsa65" => Ok(()), // the destination signs; the source verifies (check-verify)
                k => Err(format!("unknown KIND {k}")),
            }
        })?,
        ("check-dst", 4) => as_user(slot, &user_pin, |s| {
            let lineage = read(&a[1])?;
            let (inp, out) = (PathBuf::from(&a[2]), PathBuf::from(&a[3]));
            let replica = replica_by_lineage(s, &lineage)?;
            match a[0].as_str() {
                "aes256" => {
                    let pt = native::decrypt(s, replica, CKM_AES_GCM, &read(inp.join("ct.bin"))?, Some(&IV), None, AAD, Some(16))
                        .map_err(ck("decrypt with replica"))?;
                    same(&pt, VECTOR, "AES-256-GCM plaintext")
                }
                "mlkem768" => {
                    let ss = native::decapsulate(s, replica, CKM_ML_KEM, &read(inp.join("ct.bin"))?).map_err(ck("decapsulate with replica"))?;
                    same(&ss, &read(inp.join("ss.bin"))?, "ML-KEM-768 shared secret")
                }
                "mldsa65" => {
                    let sig = native::sign(s, replica, CKM_ML_DSA, VECTOR).map_err(ck("sign with replica"))?;
                    write(out.join("sig.bin"), &sig)
                }
                k => Err(format!("unknown KIND {k}")),
            }
        })?,
        ("count-lineage", 1) => as_user(slot, &user_pin, |s| {
            let lineage = read(&a[0])?;
            let mut excluded = Vec::new();
            for class in [CKO_SECRET_KEY, CKO_PRIVATE_KEY] {
                for h in find(s, &[(CKA_CLASS, ul(class)), (CKA_PQCTODAY_REPLICATION_LINEAGE_ID, lineage.clone())])? {
                    if let Some(role) = repl::records::object_attrs(h).and_then(|at| repl::records::role_of(&at)) {
                        excluded.push(role);
                    }
                    let txt = |t: u32| native::get_attribute(s, h, t).map(|v| String::from_utf8_lossy(&v).to_string()).unwrap_or_else(|| "-".into());
                    println!(
                        "  handle {h}: class 0x{class:x} keytype {:?} uid {} label {} id {} fhe-lineage {} object_attrs {}",
                        native::get_attribute_u32(s, h, CKA_KEY_TYPE),
                        txt(CKA_UNIQUE_ID),
                        txt(native::CKA_LABEL),
                        txt(native::CKA_ID),
                        native::get_attribute(s, h, CKA_PQCTODAY_FHE_LINEAGE_ID).is_some(),
                        repl::records::object_attrs(h).is_some(),
                    );
                }
            }
            println!("lineage-count {} (records excluded, by role: {excluded:?})", keys_by_lineage(s, &lineage)?.len());
            Ok(())
        })?,
        ("uid-of-lineage", 1) => as_user(slot, &user_pin, |s| {
            let h = replica_by_lineage(s, &read(&a[0])?)?;
            println!("{}", String::from_utf8_lossy(&attr(s, h, CKA_UNIQUE_ID)?));
            Ok(())
        })?,
        ("destroy-lineage", 1) => as_user(slot, &user_pin, |s| {
            let h = replica_by_lineage(s, &read(&a[0])?)?;
            rv(softhsmrustv3::ffi::C_DestroyObject(s, h), "C_DestroyObject")?;
            println!("destroyed the key with this lineage on slot {slot}");
            Ok(())
        })?,
        ("check-verify", 2) => as_user(slot, &user_pin, |s| {
            let p = by_uid(s, a[0].as_bytes())?;
            let sig = read(PathBuf::from(&a[1]).join("sig.bin"))?;
            match native::verify(s, p, CKM_ML_DSA, VECTOR, &sig).map_err(ck("verify"))? {
                true => {
                    println!("PASS ML-DSA-65 signature from the replica verifies under the source public key");
                    Ok(())
                }
                false => Err("FAIL replica signature does not verify".into()),
            }
        })?,
        #[cfg(feature = "educational-fhe")]
        ("fhe-policy", 1) => as_so(slot, &so_pin, |so| fhe_cmd::policy(so, &a[0]))?,
        #[cfg(feature = "educational-fhe")]
        ("fhe-genkey", 3) => as_user(slot, &user_pin, |s| fhe_cmd::genkey(s, &a[0], &a[1], &a[2]))?,
        #[cfg(feature = "educational-fhe")]
        ("fhe-export", 2) => as_user(slot, &user_pin, |s| fhe_cmd::export(s, &a[0], &a[1]))?,
        #[cfg(feature = "educational-fhe")]
        ("fhe-decrypt", 2) => {
            let s = native::open_session(slot, &user_pin).map_err(ck("user session"))?;
            let released = fhe_cmd::decrypt(s, &a[0], &a[1]);
            end(s);
            if !released? {
                std::process::exit(1);
            }
        }
        // TEST ONLY: encrypt under the seed's client key so decrypt can be rehearsed without the
        // compute server (as `fhe_custodian encrypt-owner`). Never in a non-test-support build.
        #[cfg(all(feature = "educational-fhe", feature = "test-support"))]
        ("fhe-encrypt-test", 4) => as_user(slot, &user_pin, |s| {
            let seed = replica_by_lineage(s, &read(&a[0])?)?;
            let v: u64 = a[2].parse().map_err(|_| "value must be an integer".to_string())?;
            let ct = softhsmrustv3::replication::fhe_tfhe::encrypt_for_test(s, seed, &a[1], v).map_err(ck("encrypt_for_test"))?;
            write(&a[3], &ct)
        })?,
        _ => return Err(USAGE.into()),
    }
    Ok(())
}

/// FHE stage F on the board (custodian or backup). Mirrors `rust/examples/fhe_custodian.rs`
/// but runs against the replication-enrolled store, so the same seed can be backed up to the
/// peer board with the replication ceremony and decrypted there after a restore.
#[cfg(feature = "educational-fhe")]
mod fhe_cmd {
    use super::*;
    use softhsmrustv3::replication::{fhe, fhe_tfhe as tf};

    const SIGNER_ID: &[u8] = b"fhe-custodian-manifest-signer";
    const SEED_ID: &[u8] = b"fhe-custodian-seed";
    /// CKA_LABEL tells an audit where a manifest signer came from (7f condition 3). Either way its
    /// K3 evidence (attest_key) is exported with every fhe-export (signer_evidence.der).
    const LABEL_AT_INIT: &[u8] = b"fhe-manifest-signer generated-at-init";
    const LABEL_ON_RESTORE: &[u8] = b"fhe-manifest-signer generated-on-restore";

    /// The fixed educational decrypt policy (same as `fhe_custodian init`): FheBool/U8/U16/U32
    /// may be released to the owner, FheUint64 never.
    pub fn policy(so: u32, out: &str) -> Result<(), String> {
        use der::Encode;
        let ty = |n: &str, w: u16| fhe::FheType {
            type_name: n.into(),
            width_bits: w,
            param_set: 1,
            serialization_version: 1,
            compressed_allowed: false,
        };
        let der = fhe::FheDecryptPolicy {
            version: 1,
            allowed_output_types: vec![ty("FheBool", 1), ty("FheUint16", 16), ty("FheUint32", 32), ty("FheUint8", 8)],
            never_release: vec![ty("FheUint64", 64)],
            predicates: vec![],
            recipients: vec![],
            recipient_only: false,
            max_decrypts: 10_000,
        }
        .to_der()
        .map_err(|e| format!("decrypt policy DER: {e}"))?;
        let id = fhe::enroll_fhe_decrypt_policy(so, &der).map_err(ck("enroll_fhe_decrypt_policy"))?;
        write(out, &id)
    }

    pub fn genkey(s: u32, rpid: &str, dpid: &str, outdir: &str) -> Result<(), String> {
        let rp: [u8; 48] = read(rpid)?.try_into().map_err(|_| "replication policy id must be 48 bytes".to_string())?;
        let dp: [u8; 48] = read(dpid)?.try_into().map_err(|_| "decrypt policy id must be 48 bytes".to_string())?;
        let seed = fhe::generate_fhe_seed(s, 1, &rp, &dp, Some(b"FHE custodian seed"), Some(SEED_ID)).map_err(ck("generate_fhe_seed"))?;
        if signer(s, CKO_PRIVATE_KEY).is_err() {
            gen_signer(s, LABEL_AT_INIT)?;
        }
        let out = PathBuf::from(outdir);
        write(out.join("uid.txt"), &attr(s, seed, CKA_UNIQUE_ID)?)?;
        write(out.join("lineage.bin"), &attr(s, seed, CKA_PQCTODAY_REPLICATION_LINEAGE_ID)?)
    }

    pub fn export(s: u32, lineage: &str, outdir: &str) -> Result<(), String> {
        let seed = replica_by_lineage(s, &read(lineage)?)?;
        // A restored backup has the seed but no manifest signer yet: make one. Its SPKI differs
        // from the custodian's, so a compute server pinning the signer must be told on failover.
        if signer(s, CKO_PRIVATE_KEY).is_err() {
            eprintln!("note: no manifest signer on this token; generating a new one (new signer SPKI, label {})", String::from_utf8_lossy(LABEL_ON_RESTORE));
            gen_signer(s, LABEL_ON_RESTORE)?;
        }
        let (signer_priv, signer_pub) = (signer(s, CKO_PRIVATE_KEY)?, signer(s, CKO_PUBLIC_KEY)?);
        let out = PathBuf::from(outdir);
        std::fs::create_dir_all(out.join("crls")).map_err(|e| format!("{}: {e}", out.display()))?;
        let fl = attr(s, seed, CKA_PQCTODAY_FHE_LINEAGE_ID)?;
        let ph = attr(s, seed, CKA_PQCTODAY_FHE_PARAM_HASH)?;
        for (kind, name) in [(tf::PUBLIC_KIND_COMPRESSED_SERVER_KEY, "compressed_server_key"), (tf::PUBLIC_KIND_COMPACT_PUBLIC_KEY, "compact_public_key")] {
            let h = tf::derive_public(s, seed, kind).map_err(ck("DERIVE_PUBLIC"))?;
            let blob = attr(s, h, CKA_VALUE)?;
            let manifest = tf::public_manifest(&fl, &ph, kind, &blob).map_err(ck("public_manifest"))?;
            let sig = native::sign(s, signer_priv, CKM_ML_DSA, &manifest).map_err(ck("sign manifest"))?;
            write(out.join(format!("{name}.bin")), &blob)?;
            write(out.join(format!("{name}.manifest.der")), &manifest)?;
            write(out.join(format!("{name}.manifest.sig")), &sig)?;
        }
        write(out.join("signer_spki.der"), &attr(s, signer_pub, CKA_PUBLIC_KEY_INFO)?)?;
        // K3 evidence that the manifest key is token-resident and non-extractable;
        // nonce = first 32 bytes of SHA-384(server-key manifest DER), as fhe_custodian.
        use sha2::Digest;
        let m = read(out.join("compressed_server_key.manifest.der"))?;
        let nonce: [u8; 32] = sha2::Sha384::digest(&m)[..32].try_into().unwrap();
        write(out.join("signer_evidence.der"), &repl::attest_key(s, signer_priv, &nonce).map_err(ck("attest_key"))?)?;
        write(out.join("crls/device.crl.der"), &repl::own_device_crl(s).map_err(ck("own_device_crl"))?)
    }

    /// `Ok(true)` = released (printed), `Ok(false)` = refused by policy or input check.
    pub fn decrypt(s: u32, lineage: &str, ct: &str) -> Result<bool, String> {
        let seed = replica_by_lineage(s, &read(lineage)?)?;
        let input = read(ct)?;
        match tf::decrypt(s, seed, &[0u8; 48], &input, false) {
            Ok((_, Some(tf::DecryptOutput::Owner(b)))) if b.len() >= 3 => {
                let width = u16::from_be_bytes([b[1], b[2]]);
                let n = (b.len() - 3).min(8);
                let mut v = [0u8; 8];
                v[..n].copy_from_slice(&b[3..3 + n]);
                let kind = if b[0] == 0 { "FheBool".to_string() } else { format!("FheUint{width}") };
                println!("released {kind} = {}", u64::from_le_bytes(v));
                Ok(true)
            }
            Ok(_) => Err("unexpected decrypt output".into()),
            Err(rv) => {
                println!("refused by policy or input check (CK_RV 0x{rv:08x}; reason in the token audit log only)");
                Ok(false)
            }
        }
    }

    fn signer(s: u32, class: u32) -> Result<u32, String> {
        native::find_all_by_cka_id(s, SIGNER_ID)
            .map_err(ck("find signer"))?
            .into_iter()
            .find(|h| native::get_attribute_u32(s, *h, CKA_CLASS) == Some(class))
            .ok_or_else(|| "manifest signer not found (run fhe-genkey first)".to_string())
    }

    fn gen_signer(s: u32, label: &[u8]) -> Result<(), String> {
        let pubt = vec![(CKA_TOKEN, bb(true)), (CKA_PARAMETER_SET, ul(CKP_ML_DSA_65)), (CKA_VERIFY, bb(true)), (native::CKA_ID, SIGNER_ID.to_vec()), (native::CKA_LABEL, label.to_vec())];
        let prvt = vec![(CKA_TOKEN, bb(true)), (CKA_SENSITIVE, bb(true)), (CKA_EXTRACTABLE, bb(false)), (CKA_SIGN, bb(true)), (native::CKA_ID, SIGNER_ID.to_vec()), (native::CKA_LABEL, label.to_vec())];
        let (tp, tk) = (raw(&pubt), raw(&prvt));
        let mut m = [CKM_ML_DSA_KEY_PAIR_GEN as usize, 0, 0];
        let (mut hp, mut hk) = (0u32, 0u32);
        rv(
            softhsmrustv3::ffi::C_GenerateKeyPair(s, m.as_mut_ptr() as *mut u8, tp.as_ptr() as *mut u8, pubt.len() as u32, tk.as_ptr() as *mut u8, prvt.len() as u32, &mut hp, &mut hk),
            "generate manifest signer",
        )
    }
}

// ── sessions ──────────────────────────────────────────────────────────────

fn as_so(slot: u32, pin: &str, f: impl FnOnce(u32) -> Result<(), String>) -> Result<(), String> {
    let so = native::open_session_so(slot, pin).map_err(ck("SO session"))?;
    let r = f(so);
    end(so);
    r
}

fn as_user(slot: u32, pin: &str, f: impl FnOnce(u32) -> Result<(), String>) -> Result<(), String> {
    let s = native::open_session(slot, pin).map_err(ck("user session"))?;
    let r = f(s);
    end(s);
    r
}

fn end(session: u32) {
    let _ = native::logout(session);
    let _ = native::close_session(session);
}

// ── keys ──────────────────────────────────────────────────────────────────

fn ul(v: u32) -> Vec<u8> {
    (v as usize).to_le_bytes().to_vec()
}
fn bb(v: bool) -> Vec<u8> {
    vec![v as u8]
}
fn raw(attrs: &[(u32, Vec<u8>)]) -> Vec<usize> {
    attrs.iter().flat_map(|(t, v)| [*t as usize, v.as_ptr() as usize, v.len()]).collect()
}

/// Policy-bound, locally generated, non-extractable key, exactly as the K4 suite makes it.
fn genkey(s: u32, kind: &str, pid: &[u8; 48]) -> Result<(u32, Option<u32>), String> {
    let protected = |extra: Vec<(u32, Vec<u8>)>| {
        let mut v = vec![
            (CKA_TOKEN, bb(true)),
            (CKA_SENSITIVE, bb(true)),
            (CKA_EXTRACTABLE, bb(false)),
            (CKA_COPYABLE, bb(false)),
            (CKA_MODIFIABLE, bb(false)),
            (CKA_PQCTODAY_REPLICATION_POLICY_ID, pid.to_vec()),
        ];
        v.extend(extra);
        v
    };
    match kind {
        "aes256" => {
            let attrs = protected(vec![
                (CKA_CLASS, ul(CKO_SECRET_KEY)),
                (CKA_KEY_TYPE, ul(CKK_AES)),
                (CKA_VALUE_LEN, ul(32)),
                (CKA_ENCRYPT, bb(true)),
                (CKA_DECRYPT, bb(true)),
                (CKA_DERIVE, bb(false)),
            ]);
            let t = raw(&attrs);
            let mut m = [CKM_AES_KEY_GEN as usize, 0, 0];
            let mut h = 0u32;
            rv(softhsmrustv3::ffi::C_GenerateKey(s, m.as_mut_ptr() as *mut u8, t.as_ptr() as *mut u8, attrs.len() as u32, &mut h), "C_GenerateKey")?;
            Ok((h, None))
        }
        "mlkem768" | "mldsa65" => {
            let (mech, ps, pu, pr) = if kind == "mlkem768" {
                (CKM_ML_KEM_KEY_PAIR_GEN, CKP_ML_KEM_768, CKA_ENCAPSULATE, CKA_DECAPSULATE)
            } else {
                (CKM_ML_DSA_KEY_PAIR_GEN, CKP_ML_DSA_65, CKA_VERIFY, CKA_SIGN)
            };
            let pubt = vec![(CKA_TOKEN, bb(true)), (CKA_PARAMETER_SET, ul(ps)), (pu, bb(true))];
            let prvt = protected(vec![(pr, bb(true))]);
            let (tp, tk) = (raw(&pubt), raw(&prvt));
            let mut m = [mech as usize, 0, 0];
            let (mut hp, mut hk) = (0u32, 0u32);
            rv(
                softhsmrustv3::ffi::C_GenerateKeyPair(
                    s,
                    m.as_mut_ptr() as *mut u8,
                    tp.as_ptr() as *mut u8,
                    pubt.len() as u32,
                    tk.as_ptr() as *mut u8,
                    prvt.len() as u32,
                    &mut hp,
                    &mut hk,
                ),
                "C_GenerateKeyPair",
            )?;
            Ok((hk, Some(hp)))
        }
        k => Err(format!("unknown KIND {k}")),
    }
}

/// Exactly one visible object with this CKA_UNIQUE_ID, else refuse (7f: no label lookups).
fn by_uid(s: u32, uid: &[u8]) -> Result<u32, String> {
    let found = find(s, &[(CKA_UNIQUE_ID, uid.to_vec())])?;
    match found.as_slice() {
        [h] => Ok(*h),
        [] => Err(format!("no object with CKA_UNIQUE_ID {}", String::from_utf8_lossy(uid))),
        _ => Err("more than one object with that CKA_UNIQUE_ID".into()),
    }
}

/// Usable keys carrying `lineage` on this token. Replication RECORDS (ledger entries, cached
/// packages, … tagged with the engine-private record role) can carry the lineage too and are
/// excluded, so a source that has created a package still counts as holding one key.
fn keys_by_lineage(s: u32, lineage: &[u8]) -> Result<Vec<u32>, String> {
    let mut hits = Vec::new();
    for class in [CKO_SECRET_KEY, CKO_PRIVATE_KEY] {
        hits.extend(find(s, &[(CKA_CLASS, ul(class)), (CKA_PQCTODAY_REPLICATION_LINEAGE_ID, lineage.to_vec())])?);
    }
    Ok(hits
        .into_iter()
        .filter(|h| repl::records::object_attrs(*h).map(|a| repl::records::role_of(&a).is_none()).unwrap_or(true))
        .collect())
}

/// The installed replica: the one usable secret/private key carrying `lineage` on this token.
fn replica_by_lineage(s: u32, lineage: &[u8]) -> Result<u32, String> {
    let hits = keys_by_lineage(s, lineage)?;
    match hits.as_slice() {
        [h] => Ok(*h),
        [] => Err("no replica with that lineage on this token".into()),
        _ => Err(format!("{} keys share that lineage on this token (expected exactly one replica)", hits.len())),
    }
}

fn find(s: u32, attrs: &[(u32, Vec<u8>)]) -> Result<Vec<u32>, String> {
    let t = raw(attrs);
    rv(softhsmrustv3::ffi::C_FindObjectsInit(s, t.as_ptr() as *mut u8, attrs.len() as u32), "C_FindObjectsInit")?;
    let mut out = Vec::new();
    loop {
        let mut buf = [0u32; 16];
        let mut n = 0u32;
        let r = softhsmrustv3::ffi::C_FindObjects(s, buf.as_mut_ptr(), buf.len() as u32, &mut n);
        if r != CKR_OK {
            let _ = softhsmrustv3::ffi::C_FindObjectsFinal(s);
            return Err(format!("C_FindObjects: CK_RV 0x{r:08x}"));
        }
        out.extend_from_slice(&buf[..n as usize]);
        if n == 0 {
            break;
        }
    }
    rv(softhsmrustv3::ffi::C_FindObjectsFinal(s), "C_FindObjectsFinal")?;
    Ok(out)
}

fn attr(s: u32, h: u32, t: u32) -> Result<Vec<u8>, String> {
    native::get_attribute(s, h, t).ok_or_else(|| format!("attribute 0x{t:08x} unavailable on handle {h}"))
}

// ── plumbing ──────────────────────────────────────────────────────────────

fn take_opt(args: &mut Vec<String>, name: &str) -> Option<String> {
    let i = args.iter().position(|a| a == name)?;
    let v = args.get(i + 1).cloned();
    args.drain(i..(i + 2).min(args.len()));
    v
}

fn env(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("{name} is not set"))
}

fn ck(what: &'static str) -> impl Fn(u32) -> String {
    move |rv| format!("{what}: CK_RV 0x{rv:08x}{}", repl::last_refusal().map(|r| format!(" ({r})")).unwrap_or_default())
}

fn rv(r: u32, what: &str) -> Result<(), String> {
    if r == CKR_OK { Ok(()) } else { Err(format!("{what}: CK_RV 0x{r:08x}")) }
}

fn read(p: impl AsRef<Path>) -> Result<Vec<u8>, String> {
    std::fs::read(p.as_ref()).map_err(|e| format!("read {}: {e}", p.as_ref().display()))
}

fn write(p: impl AsRef<Path>, data: &[u8]) -> Result<(), String> {
    std::fs::write(p.as_ref(), data).map_err(|e| format!("write {}: {e}", p.as_ref().display()))?;
    println!("wrote {} ({} B)", p.as_ref().display(), data.len());
    Ok(())
}

fn same(got: &[u8], want: &[u8], what: &str) -> Result<(), String> {
    if got == want {
        println!("PASS {what} matches");
        Ok(())
    } else {
        Err(format!("FAIL {what} differs"))
    }
}
