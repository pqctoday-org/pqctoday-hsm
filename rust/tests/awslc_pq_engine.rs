//! ML-DSA / ML-KEM through the engine's own entry points (the `native` API the
//! KMIP server and the remoting services call), checked against fips204 and
//! ml-kem called directly.
//!
//! Every assertion holds whichever backend the engine picks, so the same
//! binary is run twice by the gate: as is (AWS-LC CPU path, `crypto::awslc_pq`)
//! and with `PQC_AWSLC_PQ_DISABLE=1` (fips204 / ml-kem only). The first test
//! states which of the two this process is running.
#![cfg(not(target_arch = "wasm32"))]

use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
use softhsmrustv3::constants::*;
use softhsmrustv3::native;
use std::sync::{Mutex, MutexGuard, OnceLock};

fn serialize() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// One user session on slot 0, set up once per process.
fn session() -> u32 {
    static S: OnceLock<u32> = OnceLock::new();
    *S.get_or_init(|| {
        native::init().expect("init");
        softhsmrustv3::state::ensure_slot(0);
        native::init_token(0, "12345678", "awslc-pq").expect("init_token");
        let so = native::open_session_so(0, "12345678").expect("SO session");
        native::init_pin(so, "87654321").expect("init_pin");
        native::logout(so).expect("logout");
        native::close_session(so).expect("close SO");
        native::open_session(0, "87654321").expect("user session")
    })
}

macro_rules! per_set {
    ($ps:expr, $m:ident => $body:expr) => {
        match $ps {
            CKP_ML_DSA_44 => {
                use fips204::ml_dsa_44 as $m;
                $body
            }
            CKP_ML_DSA_65 => {
                use fips204::ml_dsa_65 as $m;
                $body
            }
            CKP_ML_DSA_87 => {
                use fips204::ml_dsa_87 as $m;
                $body
            }
            other => panic!("{other}"),
        }
    };
}

fn fips_pk(ps: u32, xi: &[u8; 32]) -> Vec<u8> {
    per_set!(ps, m => m::KG::keygen_from_seed(xi).0.into_bytes().to_vec())
}

fn fips_verify(ps: u32, xi: &[u8; 32], msg: &[u8], sig: &[u8], ctx: &[u8]) -> bool {
    per_set!(ps, m => {
        let (pk, _) = m::KG::keygen_from_seed(xi);
        pk.verify(msg, &sig.try_into().unwrap(), ctx)
    })
}

fn fips_sign(ps: u32, xi: &[u8; 32], msg: &[u8], ctx: &[u8], rnd: [u8; 32]) -> Vec<u8> {
    struct Fixed([u8; 32], usize);
    impl fips204::RngCore for Fixed {
        fn next_u32(&mut self) -> u32 {
            unimplemented!()
        }
        fn next_u64(&mut self) -> u64 {
            unimplemented!()
        }
        fn fill_bytes(&mut self, out: &mut [u8]) {
            for o in out {
                *o = self.0[self.1];
                self.1 += 1;
            }
        }
        fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), fips204::RngError> {
            self.fill_bytes(out);
            Ok(())
        }
    }
    impl fips204::CryptoRng for Fixed {}
    per_set!(ps, m => {
        let (_, sk) = m::KG::keygen_from_seed(xi);
        sk.try_sign_with_rng(&mut Fixed(rnd, 0), msg, ctx).unwrap().to_vec()
    })
}

#[test]
fn reports_which_backend_this_process_runs() {
    let disabled = std::env::var("PQC_AWSLC_PQ_DISABLE").is_ok_and(|v| v.trim() == "1");
    assert_eq!(softhsmrustv3::crypto::awslc_pq::enabled(), !disabled);
    eprintln!(
        "awslc_pq_engine: backend = {}",
        if disabled { "fips204/ml-kem" } else { "AWS-LC" }
    );
}

/// ML-DSA through `native::sign_pqc` / `verify_pqc`, every set, with and
/// without a context: seeded key generation is byte-identical to fips204;
/// normal hedged signatures verify under fips204; deterministic and
/// explicit-rnd signatures are byte-identical to fips204; external µ and a
/// fips204 HashML-DSA signature verify through the engine; a wrong context
/// is rejected.
#[test]
fn mldsa_through_the_engine() {
    let _g = serialize();
    let s = session();
    for ps in [CKP_ML_DSA_44, CKP_ML_DSA_65, CKP_ML_DSA_87] {
        let xi = [ps as u8 * 11; 32];
        let (pub_h, prv_h) =
            native::generate_ml_dsa_keypair_from_seed(s, ps, &xi, b"id", "k").unwrap();
        let pk = native::get_attribute(s, pub_h, CKA_VALUE).expect("public key value");
        assert_eq!(pk, fips_pk(ps, &xi), "keygen byte-identity");
        for ctx in [&b""[..], b"engine context"] {
            let msg = b"engine message";
            let hedged =
                native::sign_pqc(s, prv_h, CKM_ML_DSA, msg, ctx, false, false, false, None)
                    .unwrap();
            assert!(
                fips_verify(ps, &xi, msg, &hedged, ctx),
                "engine hedged -> fips204"
            );
            assert_eq!(
                native::verify_pqc(s, pub_h, CKM_ML_DSA, msg, &hedged, ctx, false, false),
                Ok(())
            );
            assert_eq!(
                native::verify_pqc(s, pub_h, CKM_ML_DSA, msg, &hedged, b"wrong", false, false),
                Err(CKR_SIGNATURE_INVALID)
            );
            let det =
                native::sign_pqc(s, prv_h, CKM_ML_DSA, msg, ctx, true, false, false, None).unwrap();
            assert_eq!(
                det,
                fips_sign(ps, &xi, msg, ctx, [0; 32]),
                "deterministic byte-identity"
            );
            let rnd = [0x3c; 32];
            let explicit = native::sign_pqc(
                s,
                prv_h,
                CKM_ML_DSA,
                msg,
                ctx,
                false,
                false,
                false,
                Some(&rnd),
            )
            .unwrap();
            assert_eq!(
                explicit,
                fips_sign(ps, &xi, msg, ctx, rnd),
                "explicit rnd byte-identity"
            );
            let foreign = fips_sign(ps, &xi, msg, ctx, [9; 32]);
            assert_eq!(
                native::verify_pqc(s, pub_h, CKM_ML_DSA, msg, &foreign, ctx, false, false),
                Ok(())
            );
        }
        // External µ, hedged (engine) and verified both by the engine and as
        // a pure signature by fips204.
        let mu = {
            use sha3::digest::{ExtendableOutput, Update, XofReader};
            let mut tr = [0u8; 64];
            let mut h = sha3::Shake256::default();
            h.update(&pk);
            h.finalize_xof().read(&mut tr);
            let mut h = sha3::Shake256::default();
            h.update(&tr);
            h.update(&[0, 0]);
            h.update(b"mu message");
            let mut mu = [0u8; 64];
            h.finalize_xof().read(&mut mu);
            mu
        };
        let mu_sig =
            native::sign_pqc(s, prv_h, CKM_ML_DSA, &mu, b"", false, false, true, None).unwrap();
        assert_eq!(
            native::verify_pqc(s, pub_h, CKM_ML_DSA, &mu, &mu_sig, b"", false, true),
            Ok(())
        );
        assert!(fips_verify(ps, &xi, b"mu message", &mu_sig, b""));
        // HashML-DSA stays fips204; the engine verifies a fips204 one.
        let hashed = per_set!(ps, m => {
            let (_, sk) = m::KG::keygen_from_seed(&xi);
            sk.try_hash_sign(b"prehashed", b"c", &fips204::Ph::SHA512).unwrap().to_vec()
        });
        assert_eq!(
            native::verify_pqc(
                s,
                pub_h,
                CKM_HASH_ML_DSA_SHA512,
                b"prehashed",
                &hashed,
                b"c",
                false,
                false
            ),
            Ok(())
        );
        assert_eq!(
            native::verify_pqc(
                s,
                pub_h,
                CKM_ML_DSA,
                b"prehashed",
                &hashed,
                b"c",
                false,
                false
            ),
            Err(CKR_SIGNATURE_INVALID)
        );
    }
}

/// ML-KEM through `native::encapsulate` / `encapsulate_deterministic` /
/// `decapsulate`, every set: seeded key generation and deterministic
/// encapsulation are byte-identical to ml-kem, randomized encapsulation
/// round-trips, and a tampered ciphertext yields ml-kem's implicit-rejection
/// secret.
#[test]
fn mlkem_through_the_engine() {
    use ml_kem::kem::Decapsulate;
    use ml_kem::{EncapsulateDeterministic, EncodedSizeUser, KemCore};
    let _g = serialize();
    let s = session();
    for ps in [CKP_ML_KEM_512, CKP_ML_KEM_768, CKP_ML_KEM_1024] {
        let dz = [ps as u8 * 7; 64];
        let (pub_h, prv_h) =
            native::generate_ml_kem_keypair_from_seed(s, ps, &dz, b"id", "k").unwrap();
        let ek = native::get_attribute(s, pub_h, CKA_VALUE).expect("ek");
        let d = ml_kem::B32::try_from(&dz[..32]).unwrap();
        let z = ml_kem::B32::try_from(&dz[32..]).unwrap();
        macro_rules! check {
            ($k:ty) => {{
                let (dk_r, ek_r) = <$k>::generate_deterministic(&d, &z);
                assert_eq!(ek, ek_r.as_bytes().to_vec(), "keygen byte-identity");
                let m = [0x6b; 32];
                let (ct, ss) = native::encapsulate_deterministic(s, pub_h, CKM_ML_KEM, &m).unwrap();
                let (ct_r, ss_r) = ek_r
                    .encapsulate_deterministic(&ml_kem::B32::from(m))
                    .unwrap();
                assert_eq!(
                    (ct.clone(), ss.clone()),
                    (ct_r.to_vec(), ss_r.to_vec()),
                    "encaps byte-identity"
                );
                assert_eq!(native::decapsulate(s, prv_h, CKM_ML_KEM, &ct).unwrap(), ss);
                let (ct2, ss2) = native::encapsulate(s, pub_h, CKM_ML_KEM).unwrap();
                assert_eq!(
                    native::decapsulate(s, prv_h, CKM_ML_KEM, &ct2).unwrap(),
                    ss2
                );
                let mut bad = ct.clone();
                bad[5] ^= 0x40;
                let k_bar = dk_r
                    .decapsulate(&bad.as_slice().try_into().unwrap())
                    .unwrap()
                    .to_vec();
                assert_eq!(
                    native::decapsulate(s, prv_h, CKM_ML_KEM, &bad).unwrap(),
                    k_bar,
                    "implicit rejection"
                );
                assert_ne!(k_bar, ss);
            }};
        }
        match ps {
            CKP_ML_KEM_512 => check!(ml_kem::MlKem512),
            CKP_ML_KEM_768 => check!(ml_kem::MlKem768),
            _ => check!(ml_kem::MlKem1024),
        }
    }
}
