//! Wall-clock timing for the engine's hash-based signature paths.
//!
//! Measurement tool for the KV260 hash-signature plan, Phase 1 ("CPU fixes").
//! It calls the same functions `C_Sign` reaches, so the SLH-DSA sign numbers
//! include the private-key decode the handler does on every call.
//!
//! ```text
//! cargo run --release --example hashsig_timing -- slh  [iters] [name filter]
//! cargo run --release --example hashsig_timing -- lms  [signs]
//! cargo run --release --example hashsig_timing -- xmss [signs]
//! cargo run --release --example hashsig_timing -- slhcc <callers> <per caller> [shake]
//! ```
//!
//! Every SLH-DSA key is derived from fixed seeds and signed deterministically,
//! and the tool prints a SHA-256 of each signature, so two builds can be
//! checked for byte-identical output as well as compared for speed.

use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use softhsmrustv3::constants::*;
use softhsmrustv3::crypto::handlers::sign_slh_dsa;
use softhsmrustv3::crypto::{lms, xmss_bridge};

fn median(mut v: Vec<Duration>) -> Duration {
    v.sort();
    v[v.len() / 2]
}

fn min(v: &[Duration]) -> Duration {
    *v.iter().min().expect("at least one sample")
}

/// Process CPU time (all threads). Wall-clock time on a shared host is noisy;
/// CPU time is not affected by other processes waiting for the same cores.
fn cpu_now() -> Duration {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid, writable timespec for the duration of the call.
    unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut ts) };
    Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1e3
}

fn short_hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn slh(iters: usize, filter: &str) {
    macro_rules! one {
        ($name:literal, $m:ident, $ckp:expr) => {{
            if $name.contains(filter) {
            use fips205::traits::{KeyGen, SerDes};
            const N: usize = fips205::$m::N;
            let seeds = ([0x11u8; N], [0x22u8; N], [0x33u8; N]);
            let mut kg = Vec::new();
            let mut sk_bytes = Vec::new();
            for _ in 0..iters.max(1) {
                let t = Instant::now();
                let (_, sk) = fips205::$m::KG::keygen_with_seeds::<N>(&seeds.0, &seeds.1, &seeds.2);
                kg.push(t.elapsed());
                sk_bytes = sk.into_bytes().to_vec();
            }
            let msg = b"hashsig timing message";
            let mut sg = Vec::new();
            let mut sg_cpu = Vec::new();
            let mut sig = Vec::new();
            for _ in 0..iters {
                let (t, c) = (Instant::now(), cpu_now());
                sig = sign_slh_dsa(CKM_SLH_DSA, $ckp, &sk_bytes, msg, b"", true).expect("sign");
                sg.push(t.elapsed());
                sg_cpu.push(cpu_now() - c);
            }
            println!(
                "{:<20} keygen min {:>8.2} med {:>8.2} ms | sign min {:>8.2} med {:>8.2} cpu {:>8.2} ms (n={}) sig {}",
                $name,
                ms(min(&kg)),
                ms(median(kg)),
                ms(min(&sg)),
                ms(median(sg)),
                ms(min(&sg_cpu)),
                iters,
                short_hash(&sig)
            );
            }
        }};
    }
    one!(
        "SLH-DSA-SHA2-128s",
        slh_dsa_sha2_128s,
        CKP_SLH_DSA_SHA2_128S
    );
    one!(
        "SLH-DSA-SHAKE-128s",
        slh_dsa_shake_128s,
        CKP_SLH_DSA_SHAKE_128S
    );
    one!(
        "SLH-DSA-SHA2-128f",
        slh_dsa_sha2_128f,
        CKP_SLH_DSA_SHA2_128F
    );
    one!(
        "SLH-DSA-SHAKE-128f",
        slh_dsa_shake_128f,
        CKP_SLH_DSA_SHAKE_128F
    );
    one!(
        "SLH-DSA-SHA2-192s",
        slh_dsa_sha2_192s,
        CKP_SLH_DSA_SHA2_192S
    );
    one!(
        "SLH-DSA-SHAKE-192s",
        slh_dsa_shake_192s,
        CKP_SLH_DSA_SHAKE_192S
    );
    one!(
        "SLH-DSA-SHA2-256s",
        slh_dsa_sha2_256s,
        CKP_SLH_DSA_SHA2_256S
    );
    one!(
        "SLH-DSA-SHAKE-256s",
        slh_dsa_shake_256s,
        CKP_SLH_DSA_SHAKE_256S
    );
}

fn lms_run(signs: usize) {
    for (name, lms_param) in [
        ("LMS SHA256 H5/W4", CKP_LMS_SHA256_M32_H5),
        ("LMS SHA256 H10/W4", CKP_LMS_SHA256_M32_H10),
        ("LMS SHA256 H15/W4", CKP_LMS_SHA256_M32_H15),
    ] {
        let t = Instant::now();
        let (_pk, mut sk) = lms::lms_keygen(lms_param, CKP_LMOTS_SHA256_N32_W4).expect("keygen");
        let kg = t.elapsed();
        let mut times = Vec::new();
        for _ in 0..signs {
            let mut next = Vec::new();
            let t = Instant::now();
            let _sig = lms::hss_sign(lms_param, &sk, b"m", &mut |s: &[u8]| {
                next = s.to_vec();
                Ok(())
            })
            .expect("sign");
            times.push(t.elapsed());
            sk = next;
        }
        let each: Vec<String> = times.iter().map(|d| format!("{:.1}", ms(*d))).collect();
        println!(
            "{name:<22} keygen {:>9.2} ms   sign median {:>9.2} ms   each [{}]",
            ms(kg),
            ms(median(times.clone())),
            each.join(", ")
        );
    }
}

fn xmss_run(signs: usize) {
    for (name, p) in [
        ("XMSS-SHA2_10_256", CKP_XMSS_SHA2_10_256),
        ("XMSS-SHA2_16_256", CKP_XMSS_SHA2_16_256),
    ] {
        let t = Instant::now();
        let (_pk, mut sk) = xmss_bridge::xmss_keygen(p).expect("keygen");
        let kg = t.elapsed();
        let mut times = Vec::new();
        for _ in 0..signs {
            let t = Instant::now();
            let (_sig, next) = xmss_bridge::xmss_sign(p, &sk, b"m").expect("sign");
            times.push(t.elapsed());
            sk = next;
        }
        let each: Vec<String> = times.iter().map(|d| format!("{:.1}", ms(*d))).collect();
        println!(
            "{name:<22} keygen {:>9.2} ms   sign median {:>9.2} ms   each [{}]",
            ms(kg),
            ms(median(times.clone())),
            each.join(", ")
        );
    }
}

/// `callers` threads sign concurrently with one SLH-DSA-SHA2-128s key (or
/// SHAKE-128s with `shake`), `per` signatures each. Reports the wall time of
/// the whole batch, the mean latency per signature and the throughput. This
/// is the "1 caller vs N concurrent callers" measurement for the process-wide
/// core budget in fips205's `parallel` feature.
fn slh_concurrent(callers: usize, per: usize, shake: bool) {
    use fips205::traits::{KeyGen, SerDes};
    let (name, ckp, sk_bytes) = if shake {
        let (_, sk) =
            fips205::slh_dsa_shake_128s::KG::keygen_with_seeds::<16>(&[1; 16], &[2; 16], &[3; 16]);
        (
            "SLH-DSA-SHAKE-128s",
            CKP_SLH_DSA_SHAKE_128S,
            sk.into_bytes().to_vec(),
        )
    } else {
        let (_, sk) =
            fips205::slh_dsa_sha2_128s::KG::keygen_with_seeds::<16>(&[1; 16], &[2; 16], &[3; 16]);
        (
            "SLH-DSA-SHA2-128s",
            CKP_SLH_DSA_SHA2_128S,
            sk.into_bytes().to_vec(),
        )
    };
    fips205::budget_stats::reset();
    let start = Instant::now();
    let lat: Vec<Duration> = std::thread::scope(|s| {
        let hs: Vec<_> = (0..callers)
            .map(|_| {
                s.spawn(|| {
                    (0..per)
                        .map(|_| {
                            let t = Instant::now();
                            sign_slh_dsa(CKM_SLH_DSA, ckp, &sk_bytes, b"m", b"", true)
                                .expect("sign");
                            t.elapsed()
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        hs.into_iter()
            .flat_map(|h| h.join().expect("signer"))
            .collect()
    });
    let wall = start.elapsed();
    let mean = lat.iter().sum::<Duration>() / lat.len() as u32;
    println!(
        "{name:<20} callers {callers:>2} x {per} | batch {:>8.1} ms | mean latency {:>8.1} ms | {:>6.2} sig/s | peak extra threads {} (cores {})",
        ms(wall),
        ms(mean),
        lat.len() as f64 / wall.as_secs_f64(),
        fips205::budget_stats::peak_extra_threads(),
        std::thread::available_parallelism().map_or(1, |n| n.get())
    );
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let what = args.get(1).map(String::as_str).unwrap_or("slh");
    let n: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(5);
    match what {
        "slh" => slh(n, args.get(3).map(String::as_str).unwrap_or("")),
        "lms" => lms_run(n),
        "xmss" => xmss_run(n),
        // slhcc <callers> <per-caller> [shake]
        "slhcc" => slh_concurrent(
            n,
            args.get(3).and_then(|s| s.parse().ok()).unwrap_or(3),
            args.get(4).map(String::as_str) == Some("shake"),
        ),
        other => eprintln!("unknown mode {other}; use slh | slhcc | lms | xmss"),
    }
}
