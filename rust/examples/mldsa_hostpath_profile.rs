//! Host-path profile of PKCS#11 ML-DSA-65 signing with the whole-signature
//! accelerator SIMULATED (`pqc_hw::mldsa_sign_sim`).
//!
//! The engine runs its real path — `C_SignInit` + `C_Sign` (length query) +
//! `C_Sign` (fill), exactly the operation `pqc-fpga-bench` times — and the
//! sign hook drives the real ABI v2 lane driver against simulated lanes. The
//! simulator returns after a MODELLED latency and does no cryptography on the
//! caller's thread, so everything measured here is host-side cost. This is a
//! model of the board, not a board measurement.
//!
//! ```text
//! cargo run --release --features hw-accel --example mldsa_hostpath_profile -- stages [signs]
//! cargo run --release --features hw-accel --example mldsa_hostpath_profile -- arm [signs]
//! cargo run --release --features hw-accel --example mldsa_hostpath_profile -- attempts [signs]
//! cargo run --release --features hw-accel --example mldsa_hostpath_profile -- \
//!     throughput <workers> <seconds> <ratio> [spin|sleep|irq] [cores]
//! ```
//!
//! * `stages`: one thread, simulated lanes with zero modelled latency and
//!   zero sync cost; prints per-signature wall and thread-CPU time and the
//!   `pqc_hw::stage` table (host stages only).
//! * `arm`: the same operation with the hook off (CPU-only signing).
//! * `attempts`: rejection-loop attempts per ML-DSA-65 signature, from
//!   fips204's software loop through the reference simulator backend.
//! * `throughput`: time-compressed emulation of the board. `ratio` is the
//!   measured A53/container CPU-time ratio; modelled board latencies (env
//!   below) are divided by it so the container runs the board's timeline
//!   `ratio` times faster, and the result is divided by `ratio` again.
//!   Workers are pinned to `cores` (default 4) cores.
//!
//! Model inputs (board time, microseconds; defaults from the 250 MHz
//! co-simulation fit, see docs/proposals/kv260-mldsa-hostpath-0924.md):
//! `SIM_SIGN_BASE_US` (777), `SIM_SIGN_PER_ATTEMPT_US` (371),
//! `SIM_MEAN_ATTEMPTS` (5.05), `SIM_DMA_PHASE_US` (25), `SIM_SYNC_CALL_US`
//! (0), `SIM_SYNC_PER_LINE_NS` (0).
#[cfg(all(feature = "hw-accel", target_os = "linux", target_arch = "aarch64"))]
mod profile {
    use pqc_hw::mldsa_sign::WaitMode;
    use pqc_hw::mldsa_sign_sim::{ModelBackend, SimLane, SimTiming};
    use pqc_hw::stage;
    use softhsmrustv3::{ffi, hw_accel, native};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    const CKM_ML_DSA: u32 = 0x1d;
    const CKP_ML_DSA_65: u32 = 0x2;
    const CKR_OK: u32 = 0;

    fn env_f64(name: &str, default: f64) -> f64 {
        std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
    }

    fn thread_cpu() -> Duration {
        let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        // SAFETY: `ts` is a valid, writable timespec for the call.
        unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) };
        Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
    }

    fn pin_to(core: usize) {
        // SAFETY: a zeroed cpu_set_t is a valid empty set; CPU_SET writes in bounds.
        unsafe {
            let mut set: libc::cpu_set_t = std::mem::zeroed();
            libc::CPU_SET(core, &mut set);
            libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
        }
    }

    struct Bench {
        session: u32,
        key: u32,
    }

    fn setup() -> Bench {
        native::init().expect("engine init");
        native::init_token(0, "12345678", "profile").expect("init_token");
        let so = native::open_session_so(0, "12345678").expect("SO session");
        native::init_pin(so, "87654321").expect("init_pin");
        native::logout(so).expect("logout");
        native::close_session(so).expect("close");
        let session = native::open_session(0, "87654321").expect("user session");
        let (_public, private) =
            native::generate_ml_dsa_keypair(session, CKP_ML_DSA_65, b"profile", "profile")
                .expect("keygen");
        Bench { session, key: private }
    }

    fn open_worker_session() -> u32 {
        native::open_session(0, "87654321").expect("worker session")
    }

    /// The operation `pqc-fpga-bench` times: C_SignInit, C_Sign(size), C_Sign.
    fn sign_once(session: u32, key: u32, message: &mut [u8], signature: &mut [u8]) {
        let mut mechanism: [usize; 3] = [CKM_ML_DSA as usize, 0, 0];
        let rv = ffi::C_SignInit(session, mechanism.as_mut_ptr().cast(), key);
        assert_eq!(rv, CKR_OK, "C_SignInit 0x{rv:x}");
        let mut length: u32 = 0;
        let rv = ffi::C_Sign(
            session,
            message.as_mut_ptr(),
            message.len() as u32,
            std::ptr::null_mut(),
            &mut length,
        );
        assert_eq!(rv, CKR_OK, "C_Sign(size) 0x{rv:x}");
        length = signature.len() as u32;
        let rv = ffi::C_Sign(
            session,
            message.as_mut_ptr(),
            message.len() as u32,
            signature.as_mut_ptr(),
            &mut length,
        );
        assert_eq!(rv, CKR_OK, "C_Sign 0x{rv:x}");
    }

    fn board_timing(ratio: f64) -> (SimTiming, f64) {
        let us = |name: &str, default: f64| Duration::from_secs_f64(env_f64(name, default) / ratio / 1e6);
        (
            SimTiming {
                sign_base: us("SIM_SIGN_BASE_US", 777.0),
                sign_per_attempt: us("SIM_SIGN_PER_ATTEMPT_US", 371.0),
                load: us("SIM_LOAD_US", 60.0),
                dma_phase: us("SIM_DMA_PHASE_US", 25.0),
                sync_call: us("SIM_SYNC_CALL_US", 0.0),
                sync_per_line: Duration::from_secs_f64(env_f64("SIM_SYNC_PER_LINE_NS", 0.0) / ratio / 1e9),
            },
            env_f64("SIM_MEAN_ATTEMPTS", 5.05),
        )
    }

    fn install(timing: SimTiming, mean_attempts: f64, mode: WaitMode) -> Vec<SimLane> {
        let lanes: Vec<SimLane> = (0..2)
            .map(|index| {
                SimLane::new(
                    1 << 20,
                    0x7000_0000 + ((index as u64) << 20),
                    Box::new(ModelBackend::new(mean_attempts, 0x9e37_79b9_7f4a_7c15 + index as u64)),
                    timing,
                )
            })
            .collect();
        assert!(hw_accel::install_mldsa65_sim(lanes.clone(), mode));
        lanes
    }

    fn percentile(sorted: &[f64], p: f64) -> f64 {
        sorted[((sorted.len() as f64 * p) as usize).min(sorted.len() - 1)]
    }

    fn run_single(signs: usize, accelerated: bool) {
        let bench = setup();
        let lanes = install(SimTiming::default(), 5.05, WaitMode::Spin);
        hw_accel::set_mldsa65_sign_enabled(accelerated);
        hw_accel::install_stage_profile();
        pin_to(0);
        let mut message = b"hsm-perf-bench measured sign ML-DSA-65 - tenant 0".to_vec();
        let mut signature = vec![0u8; 3309];
        for _ in 0..50 {
            sign_once(bench.session, bench.key, &mut message, &mut signature);
        }
        let _ = stage::take();
        let mut wall = Vec::with_capacity(signs);
        let mut cpu = Vec::with_capacity(signs);
        for _ in 0..signs {
            let (w0, c0) = (Instant::now(), thread_cpu());
            sign_once(bench.session, bench.key, &mut message, &mut signature);
            cpu.push((thread_cpu() - c0).as_secs_f64() * 1e6);
            wall.push(w0.elapsed().as_secs_f64() * 1e6);
        }
        let table = stage::take();
        wall.sort_by(f64::total_cmp);
        cpu.sort_by(f64::total_cmp);
        let mean = |v: &[f64]| v.iter().sum::<f64>() / v.len() as f64;
        println!(
            "mode={} signs={signs} wall_us mean={:.1} p50={:.1} p90={:.1} cpu_us mean={:.1} p50={:.1}",
            if accelerated { "accelerated(sim, zero latency)" } else { "arm" },
            mean(&wall),
            percentile(&wall, 0.5),
            percentile(&wall, 0.9),
            mean(&cpu),
            percentile(&cpu, 0.5),
        );
        let per_sign = |ns: u64| ns as f64 / 1e3 / signs as f64;
        let mut attributed = 0.0;
        for stage_id in stage::Stage::all() {
            let count = table.count(stage_id);
            if count == 0 {
                continue;
            }
            let us = per_sign(table.ns(stage_id));
            println!("  stage {:<16} per_sign_us={us:>8.2} calls_per_sign={:.2}", stage_id.name(), count as f64 / signs as f64);
            if matches!(
                stage_id,
                stage::Stage::KeyDecode
                    | stage::Stage::ExpandA
                    | stage::Stage::MessageHash
                    | stage::Stage::Flatten
                    | stage::Stage::Accelerator
                    | stage::Stage::SoftwareLoop
                    | stage::Stage::ContextLookup
            ) {
                attributed += us;
            }
        }
        println!("  stage {:<16} per_sign_us={:>8.2} (wall mean minus attributed stages)", "pkcs11_other", mean(&wall) - attributed);
        let counters: Vec<_> = lanes.iter().map(SimLane::counters).collect();
        let total_signs: u64 = counters.iter().map(|c| c.signs).sum();
        if total_signs > 0 {
            let dev: u64 = counters.iter().map(|c| c.sync_bytes_for_device).sum();
            let cpu_b: u64 = counters.iter().map(|c| c.sync_bytes_for_cpu).sum();
            let calls: u64 = counters.iter().map(|c| c.syncs_for_device + c.syncs_for_cpu).sum();
            let loads: u64 = counters.iter().map(|c| c.loads).sum();
            println!(
                "  device: signs={total_signs} context_loads={loads} sync_calls_per_sign={:.2} sync_for_device_bytes_per_sign={:.0} sync_for_cpu_bytes_per_sign={:.0}",
                calls as f64 / total_signs as f64,
                dev as f64 / total_signs as f64,
                cpu_b as f64 / total_signs as f64
            );
        }
    }

    fn attempts(signs: usize) {
        let lanes: Vec<SimLane> = (0..1)
            .map(|_| SimLane::new(1 << 20, 0x7000_0000, hw_accel::mldsa65_reference_backend(), SimTiming::default()))
            .collect();
        assert!(hw_accel::install_mldsa65_sim(lanes.clone(), WaitMode::Spin));
        use fips204::traits::{KeyGen, SerDes};
        let mut histogram = [0u64; 32];
        let mut last = 0;
        for index in 0..signs {
            let (_pk, sk) = fips204::ml_dsa_65::KG::keygen_from_seed(&[(index % 16) as u8; 32]);
            let sk = sk.into_bytes();
            let message = (index as u64).to_le_bytes();
            let _ = softhsmrustv3::crypto::handlers::sign_ml_dsa(CKM_ML_DSA, CKP_ML_DSA_65, &sk, &message, &[], false)
                .expect("sign");
            let total = lanes[0].counters().attempts;
            histogram[((total - last) as usize).min(31)] += 1;
            last = total;
        }
        let mean = last as f64 / signs as f64;
        println!("ml-dsa-65 attempts: signs={signs} mean={mean:.3}");
        for (attempts, count) in histogram.iter().enumerate().filter(|(_, c)| **c > 0) {
            println!("  attempts={attempts:>2} signs={count}");
        }
    }

    fn throughput(workers: usize, seconds: f64, ratio: f64, mode: WaitMode, cores: usize) {
        let bench = setup();
        let (timing, mean_attempts) = board_timing(ratio);
        let lanes = install(timing, mean_attempts, mode);
        let stop = Arc::new(AtomicBool::new(false));
        let total = Arc::new(AtomicU64::new(0));
        let key = bench.key;
        let started = Instant::now();
        let warmup = Duration::from_millis(300);
        let threads: Vec<_> = (0..workers)
            .map(|worker| {
                let stop = Arc::clone(&stop);
                let total = Arc::clone(&total);
                let session = open_worker_session();
                std::thread::spawn(move || {
                    pin_to(worker % cores);
                    let mut message = format!("hsm-perf-bench measured sign ML-DSA-65 - worker {worker}").into_bytes();
                    let mut signature = vec![0u8; 3309];
                    let mut cpu = Duration::ZERO;
                    let mut counted = 0u64;
                    while !stop.load(Ordering::Relaxed) {
                        let c0 = thread_cpu();
                        sign_once(session, key, &mut message, &mut signature);
                        if started.elapsed() > warmup {
                            cpu += thread_cpu() - c0;
                            counted += 1;
                            total.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    (counted, cpu)
                })
            })
            .collect();
        std::thread::sleep(warmup);
        let device_before: u64 = lanes.iter().map(|l| l.counters().signs).sum();
        let measured = Instant::now();
        let total_before = total.load(Ordering::Relaxed);
        std::thread::sleep(Duration::from_secs_f64(seconds));
        let signs = total.load(Ordering::Relaxed) - total_before;
        let device_signs: u64 = lanes.iter().map(|l| l.counters().signs).sum::<u64>() - device_before;
        let elapsed = measured.elapsed().as_secs_f64();
        stop.store(true, Ordering::Relaxed);
        let mut cpu = Duration::ZERO;
        let mut counted = 0;
        for thread in threads {
            let (n, c) = thread.join().unwrap();
            counted += n;
            cpu += c;
        }
        let rate = signs as f64 / elapsed;
        println!(
            "throughput workers={workers} cores={cores} wait={mode:?} ratio={ratio:.2} container_sig_s={rate:.1} board_equivalent_sig_s={:.1} fpga_share={:.3} host_cpu_us_per_sign_board={:.0}",
            rate / ratio,
            device_signs as f64 / signs.max(1) as f64,
            cpu.as_secs_f64() * 1e6 / counted.max(1) as f64 * ratio,
        );
    }

    pub fn main() {
        let args: Vec<String> = std::env::args().skip(1).collect();
        let arg = |i: usize, default: &str| args.get(i).cloned().unwrap_or_else(|| default.to_string());
        match arg(0, "stages").as_str() {
            "stages" => run_single(arg(1, "2000").parse().unwrap(), true),
            "arm" => run_single(arg(1, "2000").parse().unwrap(), false),
            "attempts" => attempts(arg(1, "2000").parse().unwrap()),
            "throughput" => {
                let mode = match arg(4, "spin").as_str() {
                    "sleep" => WaitMode::Sleep,
                    "irq" => WaitMode::Interrupt,
                    _ => WaitMode::Spin,
                };
                throughput(
                    arg(1, "4").parse().unwrap(),
                    arg(2, "5").parse().unwrap(),
                    arg(3, "1").parse().unwrap(),
                    mode,
                    arg(5, "4").parse().unwrap(),
                )
            }
            other => panic!("unknown mode {other}"),
        }
    }
}

fn main() {
    #[cfg(all(feature = "hw-accel", target_os = "linux", target_arch = "aarch64"))]
    profile::main();
    #[cfg(not(all(feature = "hw-accel", target_os = "linux", target_arch = "aarch64")))]
    eprintln!("mldsa_hostpath_profile needs --features hw-accel on linux/aarch64");
}
