// SPDX-License-Identifier: AGPL-3.0-only
//
//! LAMPS composites through the KMIP op handlers — PKCS#11 v3.3 working
//! draft composites (`CKK_COMP_SIG` / `CKK_COMP_KEM`, one engine object per
//! key), as KMIP vendor-extension algorithms (KMIP 3.0 defines none).
//!
//! - Known answers: the LAMPS vectors committed under
//!   `rust/kat/pkcs11-v33/` (provenance in that directory's PROVENANCE.md)
//!   go in through `Register` and out through `Decapsulate` (the draft
//!   authors' `k`) and `SignatureVerify` (their `s` / `sWithContext`); their
//!   `x5c` certificates pass `Validate`. The four raw vectors in
//!   `kat/composite-sigs/external-composite-vectors.json`, including the
//!   high-S ECDSA case of `.49`, verify the same way.
//! - Every supported set: `CreateKeyPair` → `Sign` / `SignatureVerify`, or
//!   `Encapsulate` / `Decapsulate`, with no second engine handle.
//! - B0: the TLS hybrid combiner and the composite-KEM combiner give
//!   different secrets from the same key and ciphertext.
//!
//! The brainpool sets are skipped while the engine table marks them
//! unsupported, and are then covered with no edit here.

use std::sync::Arc;

use pqctoday_kmip::auditlog::{AuditSink, RingSink};
use pqctoday_kmip::kmip30::{
    ActivateRequest, Attribute, CreateKeyPairRequest, CryptographicParameters, DecapsulateRequest,
    EncapsulateRequest, GetRequest, KeyBlock, KeyFormatType, KmipAlgorithm, ObjectType, RegisterRequest,
    SignRequest, SignatureValidity, SignatureVerifyRequest, UsageMask, ValidateRequest,
};
use pqctoday_kmip::ops::{Deps, DepsConfig};
use pqctoday_kmip::policy::Engine;
use pqctoday_kmip::server::auth::AuthContext;
use pqctoday_kmip::store::MemoryStore;
use softhsmrustv3::native::composite::CompositeParams;
use time::OffsetDateTime;

fn engine_test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(())).lock().unwrap_or_else(|e| e.into_inner())
}

fn deps() -> Deps {
    use softhsmrustv3::native::session;
    let _ = session::finalize();
    session::init().expect("engine init");
    let s = session::bootstrap_default_token(0, "so-pin", "user-pin", "composite-v33").expect("session");
    let sink: Arc<dyn AuditSink> = Arc::new(RingSink::new(64));
    Deps::new(Engine::permissive(), Arc::new(MemoryStore::new()), sink, DepsConfig::default()).with_engine_session(s)
}

fn auth() -> AuthContext {
    AuthContext::open()
}

/// Standard base64 with padding (RFC 4648 §4), as the vector files use.
fn b64(s: &str) -> Vec<u8> {
    let val = |c: u8| -> u32 {
        match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a' + 26) as u32,
            b'0'..=b'9' => (c - b'0' + 52) as u32,
            b'+' => 62,
            b'/' => 63,
            _ => panic!("not base64: {c:#x}"),
        }
    };
    let s = s.as_bytes();
    assert_eq!(s.len() % 4, 0);
    let mut out = Vec::new();
    for chunk in s.chunks(4) {
        let pad = chunk.iter().filter(|&&c| c == b'=').count();
        let n = chunk.iter().fold(0u32, |n, &c| (n << 6) | if c == b'=' { 0 } else { val(c) });
        out.extend_from_slice(&[(n >> 16) as u8, (n >> 8) as u8, n as u8][..3 - pad]);
    }
    out
}

fn vectors(file: &str) -> serde_json::Value {
    let path = format!("{}/../rust/kat/pkcs11-v33/{file}/testvectors.json", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"))).unwrap()
}

/// The composite variant whose engine row is the draft name `tc_id`.
fn algo_for_tc(tc_id: &str) -> Option<(KmipAlgorithm, CompositeParams)> {
    KmipAlgorithm::ALL.iter().copied().find_map(|a| {
        let p = a.composite_params()?;
        let name = match p {
            CompositeParams::Sig(r) => r.name,
            CompositeParams::Kem(r) => r.name,
        };
        (name == tc_id).then_some((a, p))
    })
}

/// Register one composite key (Raw = the drafts' §4 serialisation), born
/// Active (ActivationDate in the past, the OASIS corpus pattern).
fn register(d: &Deps, object_type: ObjectType, alg: KmipAlgorithm, format: KeyFormatType, key: Vec<u8>, usage: UsageMask) -> String {
    pqctoday_kmip::ops::register_import_export::register(
        d,
        RegisterRequest {
            secret_data_type: None,
            object_type,
            attributes: vec![
                Attribute::CryptographicAlgorithm(alg),
                Attribute::CryptographicUsageMask(usage),
                Attribute::ActivationDate(OffsetDateTime::now_utc().unix_timestamp() - 3600),
            ],
            managed_object: Some(KeyBlock {
                key_format_type: format,
                cryptographic_algorithm: alg,
                cryptographic_length: 0,
                key_value: key,
                key_wrapping_data: None,
            }),
            protection_storage_masks: None,
            certificate_payload: None,
        },
        &auth(),
        "register",
    )
    .unwrap_or_else(|e| panic!("Register {}: {e:?}", alg.spec_name()))
    .uid
}

fn material(d: &Deps, uid: &str) -> Vec<u8> {
    pqctoday_kmip::ops::get::get(
        d,
        GetRequest { uid: uid.into(), key_format_type: None, key_wrapping_specification: None },
        &auth(),
        "get",
    )
    .expect("Get")
    .key_block
    .key_value
}

fn decapsulate(d: &Deps, uid: &str, ct: &[u8]) -> Vec<u8> {
    let r = pqctoday_kmip::ops::decapsulate::decapsulate(
        d,
        DecapsulateRequest { uid: uid.into(), data: ct.to_vec(), cryptographic_parameters: None, attributes: vec![] },
        &auth(),
        "decap",
    )
    .unwrap_or_else(|e| panic!("Decapsulate: {e:?}"));
    material(d, &r.uid)
}

fn encapsulate(d: &Deps, uid: &str) -> (Vec<u8>, Vec<u8>) {
    let r = pqctoday_kmip::ops::encapsulate::encapsulate(
        d,
        EncapsulateRequest { uid: uid.into(), input_key_material: None, cryptographic_parameters: None, attributes: vec![] },
        &auth(),
        "encap",
    )
    .unwrap_or_else(|e| panic!("Encapsulate: {e:?}"));
    (r.data.clone(), material(d, &r.uid))
}

fn ctx_params(ctx: &[u8]) -> Option<CryptographicParameters> {
    (!ctx.is_empty()).then(|| CryptographicParameters { context_string: Some(ctx.to_vec()), ..Default::default() })
}

fn sign(d: &Deps, uid: &str, m: &[u8], cp: Option<CryptographicParameters>) -> pqctoday_kmip::error::Result<Vec<u8>> {
    pqctoday_kmip::ops::sign::sign(
        d,
        SignRequest {
            uid: uid.into(),
            data: m.to_vec(),
            cryptographic_parameters: cp,
            init_indicator: None,
            final_indicator: None,
            correlation_value: None,
        },
        &auth(),
        "sign",
    )
    .map(|r| r.signature)
}

fn verify(d: &Deps, uid: &str, m: &[u8], s: &[u8], ctx: &[u8]) -> SignatureValidity {
    pqctoday_kmip::ops::signature_verify::signature_verify(
        d,
        SignatureVerifyRequest {
            uid: uid.into(),
            data: m.to_vec(),
            signature: s.to_vec(),
            cryptographic_parameters: ctx_params(ctx),
            init_indicator: None,
            final_indicator: None,
            correlation_value: None,
        },
        &auth(),
        "verify",
    )
    .unwrap_or_else(|e| panic!("SignatureVerify: {e:?}"))
    .validity
}

fn validate(d: &Deps, chain: Vec<Vec<u8>>) -> SignatureValidity {
    pqctoday_kmip::ops::validate::validate(
        d,
        ValidateRequest { certificates: chain, uids: vec![], validity_date: None },
        &auth(),
        "validate",
    )
    .expect("Validate")
    .validity
}

/// The subjectPublicKeyInfo of a DER certificate: (algorithm OID, key bytes).
fn cert_spki(der: &[u8]) -> (String, Vec<u8>) {
    use der::Decode;
    let c = x509_cert::Certificate::from_der(der).expect("x5c parses");
    let spki = c.tbs_certificate.subject_public_key_info;
    (spki.algorithm.oid.to_string(), spki.subject_public_key.raw_bytes().to_vec())
}

fn create_pair(d: &Deps, alg: KmipAlgorithm, usage: UsageMask, intent: &str) -> pqctoday_kmip::error::Result<(String, String)> {
    let kp = pqctoday_kmip::ops::create_key_pair::create_key_pair(
        d,
        CreateKeyPairRequest {
            common_attributes: vec![Attribute::CryptographicAlgorithm(alg), Attribute::CryptographicUsageMask(usage)],
            private_key_attributes: vec![],
            public_key_attributes: vec![],
            seed: None,
        },
        intent,
        &auth(),
        "ckp",
    )?;
    for uid in [&kp.private_key_uid, &kp.public_key_uid] {
        pqctoday_kmip::ops::activate::activate(d, ActivateRequest { uid: uid.clone() }, "act").expect("activate");
    }
    Ok((kp.private_key_uid, kp.public_key_uid))
}

/// B8 — decapsulation known answers: each supported composite-KEM vector's
/// private key `dk` (`mlkemSeed ‖ tradSK`) is Registered, the vector's
/// ciphertext `c` is Decapsulated through KMIP, and the secret Get returns is
/// the draft authors' `k`. The public key `ek` Registers too, and a fresh
/// Encapsulate to it decapsulates with the registered private key. The
/// vector's `x5c` (issued by the file's `cacert`) carries the set's OID over
/// `ek` and validates through KMIP Validate. Sabotage: one flipped
/// ciphertext bit decapsulates (ML-KEM implicit rejection, draft §3.5) to
/// another secret.
#[test]
fn composite_kem_vectors_decapsulate_through_kmip() {
    let _g = engine_test_lock();
    let d = deps();
    let doc = vectors("composite-kem");
    let cacert = b64(doc["cacert"].as_str().unwrap());
    let mut checked = 0;
    for v in doc["tests"].as_array().unwrap() {
        let tc = v["tcId"].as_str().unwrap();
        let Some((alg, p)) = algo_for_tc(tc) else { continue };
        let x5c = b64(v["x5c"].as_str().unwrap());
        let (oid, cert_key) = cert_spki(&x5c);
        let ek = b64(v["ek"].as_str().unwrap());
        assert_eq!(oid, p.oid(), "{tc}: x5c OID");
        assert_eq!(cert_key, ek, "{tc}: x5c key is ek");
        if !p.supported() {
            eprintln!("SKIP {tc}: the engine does not support this set yet");
            continue;
        }
        assert_eq!(validate(&d, vec![x5c, cacert.clone()]), SignatureValidity::Valid, "{tc}: x5c chain");

        let dk = b64(v["dk"].as_str().unwrap());
        let (c, k) = (b64(v["c"].as_str().unwrap()), b64(v["k"].as_str().unwrap()));
        let priv_uid = register(&d, ObjectType::PrivateKey, alg, KeyFormatType::Raw, dk, UsageMask::DECRYPT);
        assert_eq!(decapsulate(&d, &priv_uid, &c), k, "{tc}: k");
        let mut bad = c.clone();
        bad[0] ^= 0x01;
        assert_ne!(decapsulate(&d, &priv_uid, &bad), k, "{tc}: a tampered ciphertext gives another secret");

        let pub_uid = register(&d, ObjectType::PublicKey, alg, KeyFormatType::Raw, ek, UsageMask::ENCRYPT);
        let (ct, ss) = encapsulate(&d, &pub_uid);
        assert_eq!(ss.len(), 32, "{tc}: §3.4 SHA3-256 output");
        assert_eq!(decapsulate(&d, &priv_uid, &ct), ss, "{tc}: round trip");
        checked += 1;
    }
    assert_eq!(checked, softhsmrustv3::native::composite::COMPOSITE_KEM_SETS.iter().filter(|p| p.supported).count(), "every supported composite KEM set");
    assert!(checked >= 10);
    let _ = softhsmrustv3::native::session::finalize();
}

/// B8 — verification known answers: each supported composite-signature
/// vector's public key `pk` is Registered (Raw, and the x5c's SPKI as X_509)
/// and the authors' `s` over `m` (empty context) and `sWithContext` (the
/// file's `ctx`) verify through KMIP SignatureVerify; each under the wrong
/// context, and a flipped bit, do not. The private key `sk` Registers and
/// KMIP Sign output verifies under the registered public key. The vector's
/// self-signed `x5c` validates.
#[test]
fn composite_sig_vectors_verify_through_kmip() {
    let _g = engine_test_lock();
    let d = deps();
    let doc = vectors("composite-sig");
    let (m, ctx) = (b64(doc["m"].as_str().unwrap()), b64(doc["ctx"].as_str().unwrap()));
    let mut checked = 0;
    for v in doc["tests"].as_array().unwrap() {
        let tc = v["tcId"].as_str().unwrap();
        let Some((alg, p)) = algo_for_tc(tc) else { continue };
        let x5c = b64(v["x5c"].as_str().unwrap());
        let pk = b64(v["pk"].as_str().unwrap());
        assert_eq!(cert_spki(&x5c), (p.oid().to_string(), pk.clone()), "{tc}: x5c SPKI");
        if !p.supported() {
            eprintln!("SKIP {tc}: the engine does not support this set yet");
            continue;
        }
        assert_eq!(validate(&d, vec![x5c.clone()]), SignatureValidity::Valid, "{tc}: x5c");

        let (s, s_ctx) = (b64(v["s"].as_str().unwrap()), b64(v["sWithContext"].as_str().unwrap()));
        let pub_uid = register(&d, ObjectType::PublicKey, alg, KeyFormatType::Raw, pk.clone(), UsageMask::VERIFY);
        assert_eq!(verify(&d, &pub_uid, &m, &s, &[]), SignatureValidity::Valid, "{tc}: s");
        assert_eq!(verify(&d, &pub_uid, &m, &s_ctx, &ctx), SignatureValidity::Valid, "{tc}: sWithContext");
        assert_eq!(verify(&d, &pub_uid, &m, &s, &ctx), SignatureValidity::Invalid, "{tc}: s under ctx");
        assert_eq!(verify(&d, &pub_uid, &m, &s_ctx, &[]), SignatureValidity::Invalid, "{tc}: sWithContext without ctx");
        let mut bad = s.clone();
        bad[10] ^= 0x01;
        assert_eq!(verify(&d, &pub_uid, &m, &bad, &[]), SignatureValidity::Invalid, "{tc}: flipped ML-DSA bit");

        // The same key from the certificate, as X_509.
        let spki_der = {
            use der::{Decode, Encode};
            x509_cert::Certificate::from_der(&x5c).unwrap().tbs_certificate.subject_public_key_info.to_der().unwrap()
        };
        let pub_x509 = register(&d, ObjectType::PublicKey, alg, KeyFormatType::X509, spki_der, UsageMask::VERIFY);
        assert_eq!(verify(&d, &pub_x509, &m, &s, &[]), SignatureValidity::Valid, "{tc}: X_509 import");

        let sk = b64(v["sk"].as_str().unwrap());
        let priv_uid = register(&d, ObjectType::PrivateKey, alg, KeyFormatType::Raw, sk, UsageMask::SIGN);
        let ours = sign(&d, &priv_uid, &m, ctx_params(&ctx)).unwrap_or_else(|e| panic!("{tc}: Sign {e:?}"));
        assert_eq!(verify(&d, &pub_uid, &m, &ours, &ctx), SignatureValidity::Valid, "{tc}: our signature");
        checked += 1;
    }
    assert_eq!(checked, softhsmrustv3::native::composite::COMPOSITE_SIG_SETS.iter().filter(|p| p.supported).count(), "every supported composite signature set");
    assert!(checked >= 16);
    let _ = softhsmrustv3::native::session::finalize();
}

/// B8 — the four raw vectors of `kat/composite-sigs/external-composite-
/// vectors.json` (.40, .45, .46 and the high-S ECDSA case of .49) verify
/// through KMIP SignatureVerify on a Registered composite public key, i.e.
/// through the engine's `CKM_COMP_SIG`.
#[test]
fn external_raw_composite_vectors_verify_through_kmip() {
    let _g = engine_test_lock();
    let d = deps();
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/kat/composite-sigs/external-composite-vectors.json");
    let doc: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let raw = &doc["raw_signature_vectors"];
    let msg = raw["message_utf8"].as_str().unwrap().as_bytes();
    let mut checked = Vec::new();
    for v in raw["vectors"].as_array().unwrap() {
        let tc = v["tcId"].as_str().unwrap();
        let alg = KmipAlgorithm::composite_from_oid(v["oid"].as_str().unwrap()).unwrap_or_else(|| panic!("{tc}"));
        assert_eq!(v["expect"], "verifies");
        let pk = hex::decode(v["pk_hex"].as_str().unwrap()).unwrap();
        let sig = hex::decode(v["sig_hex"].as_str().unwrap()).unwrap();
        let uid = register(&d, ObjectType::PublicKey, alg, KeyFormatType::Raw, pk, UsageMask::VERIFY);
        assert_eq!(verify(&d, &uid, msg, &sig, &[]), SignatureValidity::Valid, "{tc}");
        let mut bad = sig.clone();
        *bad.last_mut().unwrap() ^= 0x01;
        assert_ne!(
            pqctoday_kmip::ops::signature_verify::signature_verify(
                &d,
                SignatureVerifyRequest {
                    uid: uid.clone(),
                    data: msg.to_vec(),
                    signature: bad,
                    cryptographic_parameters: None,
                    init_indicator: None,
                    final_indicator: None,
                    correlation_value: None,
                },
                &auth(),
                "verify-bad",
            )
            .map(|r| r.validity)
            .ok(),
            Some(SignatureValidity::Valid),
            "{tc}: tampered traditional half"
        );
        checked.push(v["oid"].as_str().unwrap().to_string());
    }
    checked.sort();
    assert_eq!(checked, ["1.3.6.1.5.5.7.6.40", "1.3.6.1.5.5.7.6.45", "1.3.6.1.5.5.7.6.46", "1.3.6.1.5.5.7.6.49"]);
    let _ = softhsmrustv3::native::session::finalize();
}

/// B2/B3 — every supported composite-signature set: CreateKeyPair (one
/// engine object, no second handle), KMIP Sign with and without a context,
/// SignatureVerify accepts and rejects. Where the set can sign
/// deterministically (`composite_sig::deterministic_available`), two
/// Deterministic signatures are identical; otherwise Deterministic is
/// refused. The ML-DSA Internal / External-Mu interfaces do not exist for
/// composites and are refused. The brainpool sets are refused at
/// CreateKeyPair while the engine does not support them.
#[test]
fn composite_sig_create_sign_verify_every_set() {
    let _g = engine_test_lock();
    let d = deps();
    let mut done = 0;
    for &alg in KmipAlgorithm::ALL.iter().filter(|a| a.is_composite_sig()) {
        let Some(CompositeParams::Sig(p)) = alg.composite_params() else { unreachable!() };
        let pair = create_pair(&d, alg, UsageMask::SIGN | UsageMask::VERIFY, "CreateKeyPair:Sign");
        if !p.supported {
            assert!(pair.is_err(), "{}: unsupported set must be refused", alg.spec_name());
            continue;
        }
        let (prv, publ) = pair.unwrap_or_else(|e| panic!("{}: {e:?}", alg.spec_name()));
        let rec = d.store.get(&prv).unwrap().unwrap();
        assert_eq!(rec.pkcs11_cka_id_secondary, None, "{}", alg.spec_name());
        let m = b"composite sign through KMIP";
        for ctx in [&b""[..], b"application context"] {
            let s = sign(&d, &prv, m, ctx_params(ctx)).unwrap_or_else(|e| panic!("{}: {e:?}", alg.spec_name()));
            assert!(p.signature_size().admits(s.len()), "{}", alg.spec_name());
            assert_eq!(verify(&d, &publ, m, &s, ctx), SignatureValidity::Valid, "{}", alg.spec_name());
            assert_eq!(verify(&d, &publ, b"another message", &s, ctx), SignatureValidity::Invalid, "{}", alg.spec_name());
        }
        let det = Some(CryptographicParameters { deterministic: Some(true), ..Default::default() });
        if softhsmrustv3::native::composite_sig::deterministic_available(p) {
            let a = sign(&d, &prv, m, det.clone()).unwrap();
            let b = sign(&d, &prv, m, det.clone()).unwrap();
            assert_eq!(a, b, "{}: deterministic", alg.spec_name());
        } else {
            assert!(sign(&d, &prv, m, det).is_err(), "{}: no deterministic form", alg.spec_name());
        }
        let internal = Some(CryptographicParameters { internal: Some(true), ..Default::default() });
        assert!(sign(&d, &prv, m, internal).is_err(), "{}: Internal refused", alg.spec_name());
        done += 1;
    }
    assert_eq!(done, softhsmrustv3::native::composite::COMPOSITE_SIG_SETS.iter().filter(|p| p.supported).count());
    assert!(done >= 16);
    let _ = softhsmrustv3::native::session::finalize();
}

/// B4 — every supported composite-KEM set: CreateKeyPair, Encapsulate to the
/// public key, Decapsulate with the private key, same 32-byte secret; the
/// deterministic-coins interface (ML-KEM only) is refused; Get of the
/// public key is the composite SPKI under the set's OID.
#[test]
fn composite_kem_create_encapsulate_decapsulate_every_set() {
    let _g = engine_test_lock();
    let d = deps();
    let mut done = 0;
    for &alg in KmipAlgorithm::ALL.iter().filter(|a| a.is_composite_kem()) {
        let p = alg.composite_params().unwrap();
        let pair = create_pair(&d, alg, UsageMask::ENCRYPT | UsageMask::DECRYPT, "CreateKeyPair:KeyAgreement");
        if !p.supported() {
            assert!(pair.is_err(), "{}: unsupported set must be refused", alg.spec_name());
            continue;
        }
        let (prv, publ) = pair.unwrap_or_else(|e| panic!("{}: {e:?}", alg.spec_name()));
        let (ct, ss) = encapsulate(&d, &publ);
        assert_eq!(ss.len(), 32, "{}", alg.spec_name());
        assert_eq!(decapsulate(&d, &prv, &ct), ss, "{}", alg.spec_name());
        let coins = pqctoday_kmip::ops::encapsulate::encapsulate(
            &d,
            EncapsulateRequest {
                uid: publ.clone(),
                input_key_material: Some(vec![0u8; 32]),
                cryptographic_parameters: None,
                attributes: vec![],
            },
            &auth(),
            "encap-coins",
        );
        assert!(coins.is_err(), "{}: deterministic coins refused", alg.spec_name());
        let spki = material(&d, &publ);
        use der::Decode;
        let parsed = spki::SubjectPublicKeyInfoOwned::from_der(&spki).unwrap();
        assert_eq!(parsed.algorithm.oid.to_string(), p.oid(), "{}", alg.spec_name());
        done += 1;
    }
    assert_eq!(done, softhsmrustv3::native::composite::COMPOSITE_KEM_SETS.iter().filter(|p| p.supported).count());
    assert!(done >= 10);
    let _ = softhsmrustv3::native::session::finalize();
}

/// B0 — the two combiners give different secrets from the same inputs.
///
/// One X25519 + ML-KEM-768 key (the LAMPS `id-MLKEM768-X25519-SHA3-256`
/// vector's `dk`) and one ciphertext (its `c`): `mlkemCT ‖ x25519CT` is
/// byte-for-byte the TLS X25519MLKEM768 ciphertext layout as well. Through
/// KMIP as the composite KEM it decapsulates to the vector's `k`
/// (`SHA3-256(mlkemSS ‖ tradSS ‖ tradCT ‖ tradPK ‖ Label)`,
/// draft-ietf-lamps-pq-composite-kem-23 §3.4); through the engine's TLS
/// hybrid decapsulation, with the same two component keys, it gives
/// `mlkemSS ‖ x25519SS` (draft-ietf-tls-ecdhe-mlkem). The two differ, and the
/// composite secret is the §3.4 hash of exactly that TLS secret and the
/// public values — so a certificate naming the composite OID over a TLS
/// hybrid key would make every relying party derive the wrong key.
#[test]
fn tls_hybrid_and_composite_kem_combiners_differ_on_the_same_inputs() {
    use sha3::Digest;
    use softhsmrustv3::constants as c;
    let _g = engine_test_lock();
    let d = deps();
    let session = d.engine_session.unwrap();
    let doc = vectors("composite-kem");
    let v = doc["tests"].as_array().unwrap().iter().find(|v| v["tcId"] == "id-MLKEM768-X25519-SHA3-256").unwrap();
    let (dk, ek) = (b64(v["dk"].as_str().unwrap()), b64(v["ek"].as_str().unwrap()));
    let (ct, k) = (b64(v["c"].as_str().unwrap()), b64(v["k"].as_str().unwrap()));

    // Composite, through KMIP.
    let alg = KmipAlgorithm::CompositeMlKem768X25519;
    let priv_uid = register(&d, ObjectType::PrivateKey, alg, KeyFormatType::Raw, dk.clone(), UsageMask::DECRYPT);
    let composite_ss = decapsulate(&d, &priv_uid, &ct);
    assert_eq!(composite_ss, k);

    // TLS hybrid, same component keys: the ML-KEM-768 key from the seed
    // dk[..64] (d ‖ z), the X25519 key from dk[64..] (composite-kem-23 §4.2).
    let (_, mlkem_priv) =
        softhsmrustv3::native::generate_ml_kem_keypair_from_seed(session, c::CKP_ML_KEM_768, &dk[..64], b"tls-mlkem", "tls")
            .expect("ML-KEM-768 from the vector's seed");
    let x_priv = {
        let word = std::mem::size_of::<usize>();
        let class = (c::CKO_PRIVATE_KEY as usize).to_ne_bytes();
        let key_type = (c::CKK_EC_MONTGOMERY as usize).to_ne_bytes();
        let ec_params = [0x06u8, 0x03, 0x2b, 0x65, 0x6e]; // OID 1.3.101.110 (id-X25519, RFC 8410 §3)
        let value = dk[64..].to_vec();
        assert_eq!(value.len(), 32);
        let attrs: [(u32, &[u8]); 4] = [
            (c::CKA_CLASS, &class),
            (c::CKA_KEY_TYPE, &key_type),
            (c::CKA_EC_PARAMS, &ec_params),
            (c::CKA_VALUE, &value),
        ];
        assert_eq!(class.len(), word);
        let tmpl: Vec<usize> = attrs.iter().flat_map(|(t, v)| [*t as usize, v.as_ptr() as usize, v.len()]).collect();
        let mut h = 0u32;
        let rv = softhsmrustv3::ffi::C_CreateObject(session, tmpl.as_ptr() as *mut u8, attrs.len() as u32, &mut h);
        assert_eq!(rv, c::CKR_OK, "X25519 private key object");
        h
    };
    let tls_ss = softhsmrustv3::native::hybrid::decapsulate(
        session,
        softhsmrustv3::native::hybrid::Hybrid::X25519MlKem768,
        mlkem_priv,
        x_priv,
        &ct,
    )
    .expect("TLS hybrid decapsulation of the same ciphertext");

    assert_eq!(tls_ss.len(), 64, "mlkemSS ‖ x25519SS");
    assert_ne!(tls_ss, composite_ss, "the two combiners must not agree");
    assert_ne!(&tls_ss[..32], composite_ss.as_slice());
    // §3.4 over the TLS secret: SHA3-256(mlkemSS ‖ tradSS ‖ tradCT ‖ tradPK ‖ Label),
    // Label 5c2e2f2f5e5c (§6).
    let mut h = sha3::Sha3_256::new();
    h.update(&tls_ss);
    h.update(&ct[1088..]);
    h.update(&ek[1184..]);
    h.update([0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c]);
    assert_eq!(h.finalize().to_vec(), composite_ss, "composite = §3.4 hash of the TLS concatenation and the public values");
    let _ = softhsmrustv3::native::session::finalize();
}
