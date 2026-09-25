//! fips204 / ml-kem versus AWS-LC (`crypto::awslc_pq`) for ML-DSA and ML-KEM.
//!
//! ```text
//! cargo run --profile release-native --example awslc_pq_bench -- [rounds] [ops per round]
//! OPENSSL_armcap=0x3d cargo run ...   # AWS-LC without the SHA3 instructions (A53/A55 set)
//! OPENSSL_armcap=0    cargo run ...   # AWS-LC with NEON masked: C reference code
//! ```
//!
//! Rounds are interleaved (fips204, then AWS-LC, then the next round) so a
//! frequency or load change on a shared host hits both sides; each cell
//! reports the minimum and the median per-operation time over the rounds.
//! Timing is process CPU time of this single thread's work.
//!
//! The "fips204 (engine)" rows do what `crypto::handlers` did before AWS-LC
//! routing: decode the private / public key bytes on every call. The
//! "fips204 (decoded)" sign row keeps the decoded key, which bounds what a
//! fips204-side key cache could reach.

use std::time::Duration;

use softhsmrustv3::constants::*;
use softhsmrustv3::crypto::awslc_pq as aws;

fn cpu_now() -> Duration {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) };
    Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
}

struct Cell {
    name: &'static str,
    samples: Vec<Duration>,
}

impl Cell {
    fn new(name: &'static str) -> Self {
        Cell {
            name,
            samples: Vec::new(),
        }
    }
    fn run(&mut self, ops: usize, mut f: impl FnMut()) {
        let t0 = cpu_now();
        for _ in 0..ops {
            f();
        }
        self.samples.push((cpu_now() - t0) / ops as u32);
    }
    fn min(&self) -> Duration {
        *self.samples.iter().min().unwrap()
    }
    fn median(&self) -> Duration {
        let mut v = self.samples.clone();
        v.sort();
        v[v.len() / 2]
    }
}

fn us(d: Duration) -> f64 {
    d.as_secs_f64() * 1e6
}

fn report(title: &str, base: &Cell, cells: &[&Cell]) {
    println!("{title}");
    for c in std::iter::once(base).chain(cells.iter().copied()) {
        println!(
            "  {:<24} min {:>9.1} us   median {:>9.1} us   x{:.2} vs {}",
            c.name,
            us(c.min()),
            us(c.median()),
            us(base.min()) / us(c.min()),
            base.name
        );
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let rounds: usize = args.get(1).and_then(|a| a.parse().ok()).unwrap_or(15);
    let ops: usize = args.get(2).and_then(|a| a.parse().ok()).unwrap_or(40);
    println!(
        "awslc_pq_bench: rounds={rounds} ops/round={ops} OPENSSL_armcap={:?} arch={}",
        std::env::var("OPENSSL_armcap").ok(),
        std::env::consts::ARCH
    );
    assert!(aws::enabled(), "unset {} to compare", aws::DISABLE_ENV);

    mldsa65(rounds, ops);
    mlkem768(rounds, ops);
}

fn mldsa65(rounds: usize, ops: usize) {
    use fips204::ml_dsa_65;
    use fips204::traits::{KeyGen, SerDes, Signer, Verifier};

    let xi = [7u8; 32];
    let (pk_f, sk_f) = ml_dsa_65::KG::keygen_from_seed(&xi);
    let pk = pk_f.clone().into_bytes().to_vec();
    let sk = sk_f.clone().into_bytes().to_vec();
    let (pk_a, sk_a) = aws::mldsa_keygen_from_seed(CKP_ML_DSA_65, &xi).expect("aws keygen");
    assert_eq!(
        (pk_a.as_slice(), sk_a.as_slice()),
        (pk.as_slice(), sk.as_slice()),
        "keygen byte-identity"
    );
    let msg = [0x5au8; 64];
    let ctx: &[u8] = b"";
    let sig = sk_f.try_sign(&msg, ctx).unwrap();
    // Warm AWS-LC's parsed-key cache (the engine path parses once per key).
    let _ = aws::mldsa_sign(CKP_ML_DSA_65, &sk, &msg, ctx).expect("aws sign");

    let mut kg_f = Cell::new("fips204 keygen");
    let mut kg_a = Cell::new("AWS-LC keygen");
    let mut sg_f = Cell::new("fips204 sign (engine)");
    let mut sg_fd = Cell::new("fips204 sign (decoded)");
    let mut sg_a = Cell::new("AWS-LC sign");
    let mut vf_f = Cell::new("fips204 verify (engine)");
    let mut vf_a = Cell::new("AWS-LC verify");
    for _ in 0..rounds {
        kg_f.run(ops, || {
            std::hint::black_box(ml_dsa_65::KG::keygen_from_seed(&xi));
        });
        kg_a.run(ops, || {
            std::hint::black_box(aws::mldsa_keygen_from_seed(CKP_ML_DSA_65, &xi));
        });
        sg_f.run(ops, || {
            let arr: [u8; 4032] = sk.as_slice().try_into().unwrap();
            let k = ml_dsa_65::PrivateKey::try_from_bytes(arr).unwrap();
            std::hint::black_box(k.try_sign(&msg, ctx).unwrap());
        });
        sg_fd.run(ops, || {
            std::hint::black_box(sk_f.try_sign(&msg, ctx).unwrap());
        });
        sg_a.run(ops, || {
            std::hint::black_box(aws::mldsa_sign(CKP_ML_DSA_65, &sk, &msg, ctx).unwrap());
        });
        vf_f.run(ops, || {
            let arr: [u8; 1952] = pk.as_slice().try_into().unwrap();
            let k = ml_dsa_65::PublicKey::try_from_bytes(arr).unwrap();
            assert!(k.verify(&msg, &sig, ctx));
        });
        vf_a.run(ops, || {
            assert_eq!(
                aws::mldsa_verify(CKP_ML_DSA_65, &pk, &msg, &sig, ctx),
                Some(true)
            );
        });
    }
    report("ML-DSA-65 keygen (from xi)", &kg_f, &[&kg_a]);
    report(
        "ML-DSA-65 sign (hedged, 64-byte message, empty ctx)",
        &sg_f,
        &[&sg_fd, &sg_a],
    );
    report("ML-DSA-65 verify", &vf_f, &[&vf_a]);
}

fn mlkem768(rounds: usize, ops: usize) {
    use ml_kem::kem::Decapsulate;
    use ml_kem::{B32, EncapsulateDeterministic, EncodedSizeUser, KemCore, MlKem768};

    let d = B32::try_from(&[1u8; 32][..]).unwrap();
    let z = B32::try_from(&[2u8; 32][..]).unwrap();
    let mut seed = [0u8; 64];
    seed[..32].copy_from_slice(&d);
    seed[32..].copy_from_slice(&z);
    let (dk_r, ek_r) = MlKem768::generate_deterministic(&d, &z);
    let ek = ek_r.as_bytes().to_vec();
    let dk = dk_r.as_bytes().to_vec();
    let (ek_a, dk_a) = aws::mlkem_keygen_from_seed(CKP_ML_KEM_768, &seed).expect("aws keygen");
    assert_eq!(
        (ek_a.as_slice(), dk_a.as_slice()),
        (ek.as_slice(), dk.as_slice()),
        "keygen byte-identity"
    );
    let m = [9u8; 32];
    let mb = B32::try_from(&m[..]).unwrap();
    let (ct, ss) = ek_r.encapsulate_deterministic(&mb).unwrap();
    let (ct_a, ss_a) = aws::mlkem_encaps(CKP_ML_KEM_768, &ek, &m).expect("aws encaps");
    assert_eq!(
        (ct_a.as_slice(), ss_a.as_slice()),
        (ct.as_slice(), ss.as_slice()),
        "encaps byte-identity"
    );

    let mut kg_f = Cell::new("ml-kem keygen");
    let mut kg_a = Cell::new("AWS-LC keygen");
    let mut en_f = Cell::new("ml-kem encaps (engine)");
    let mut en_a = Cell::new("AWS-LC encaps");
    let mut de_f = Cell::new("ml-kem decaps (engine)");
    let mut de_a = Cell::new("AWS-LC decaps");
    type Ek = <MlKem768 as KemCore>::EncapsulationKey;
    type Dk = <MlKem768 as KemCore>::DecapsulationKey;
    for _ in 0..rounds {
        kg_f.run(ops, || {
            std::hint::black_box(MlKem768::generate_deterministic(&d, &z));
        });
        kg_a.run(ops, || {
            std::hint::black_box(aws::mlkem_keygen_from_seed(CKP_ML_KEM_768, &seed));
        });
        en_f.run(ops, || {
            let arr = ml_kem::array::Array::try_from(ek.as_slice()).unwrap();
            let k = Ek::from_bytes(&arr);
            std::hint::black_box(k.encapsulate_deterministic(&mb).unwrap());
        });
        en_a.run(ops, || {
            std::hint::black_box(aws::mlkem_encaps(CKP_ML_KEM_768, &ek, &m).unwrap());
        });
        de_f.run(ops, || {
            let arr = ml_kem::array::Array::try_from(dk.as_slice()).unwrap();
            let k = Dk::from_bytes(&arr);
            let c = ml_kem::array::Array::try_from(ct.as_slice()).unwrap();
            std::hint::black_box(k.decapsulate(&c).unwrap());
        });
        de_a.run(ops, || {
            std::hint::black_box(aws::mlkem_decaps(CKP_ML_KEM_768, &dk, &ct).unwrap());
        });
    }
    report("ML-KEM-768 keygen (from d||z)", &kg_f, &[&kg_a]);
    report("ML-KEM-768 encaps (fixed m)", &en_f, &[&en_a]);
    report("ML-KEM-768 decaps", &de_f, &[&de_a]);
}
