//! Fixed-duration, multi-threaded measurement primitive (plan §A7): "count
//! ops in T seconds, not fixed-op-count." Each worker closure is already
//! bound to its own PKCS#11 session and pre-generated key material — the
//! measured loop calls nothing but that one real engine operation,
//! repeatedly, through the same dlopen'd C ABI the mechanism proofs used.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;

/// One JSONL result row — field set and order match the harness's output
/// contract from the plan (§A4.1 component 1): `{access_path, topology,
/// instances, instance_id, tenants, tenant_index, slot, threads, category,
/// algorithm, security_level, op, ops_per_sec, p50_ms, p99_ms, duration_s,
/// total_ops, engine_version}`.
///
/// `instances` is the COUNT of independent-topology instances in this run
/// (e.g. `3`); `instance_id` is WHICH one produced this specific row
/// (`0..instances`, always `0` under shared-1-instance topology, where
/// there's only ever one). Conflating the two was a real gap
/// (hsm-perf-bench-instance-slot-telemetry-plan-07192026.md §1, row 1) —
/// every row in a 3-instance run used to carry `instances: 3` with
/// nothing distinguishing which instance it came from.
///
/// Likewise `tenants` is the COUNT of tenants provisioned (fixed at 2
/// today); `tenant_index`/`slot` identify WHICH tenant's own worker
/// threads produced this row — the measurement loop used to pool every
/// worker thread across every tenant into one aggregate row per
/// (algorithm, op), which silently averaged away exactly the per-tenant
/// fairness/contention question a shared-vs-independent-topology
/// benchmark exists to answer (telemetry plan §2.2). `tenant_index` is
/// this harness's own 0-based ordinal (0=alice, 1=bob); `slot` is the
/// real PKCS#11 slot number that tenant's token landed on (via the
/// standard `C_GetSlotList` auto-replenish — see `pkcs11.rs`) — the two
/// happen to coincide today (alice always lands on slot 0, bob on slot
/// 1) but are conceptually distinct, so both are reported rather than
/// assuming a caller can derive one from the other.
#[derive(serde::Serialize)]
pub struct ResultRow {
    pub access_path: &'static str,
    pub topology: &'static str,
    pub instances: u32,
    pub instance_id: u32,
    pub tenants: u32,
    pub tenant_index: u32,
    pub slot: u64,
    pub threads: u32,
    pub category: &'static str,
    pub algorithm: &'static str,
    pub security_level: &'static str,
    pub op: &'static str,
    pub ops_per_sec: f64,
    pub p50_ms: f64,
    pub p99_ms: f64,
    pub duration_s: f64,
    pub total_ops: u64,
    pub engine_version: String,
}

/// Run `worker_fns.len()` OS threads concurrently, each calling its own
/// closure in a tight loop: `warmup_secs` unmeasured (lazy_static init,
/// allocator warm-up — §A7), then `duration_secs` measured with a
/// per-op monotonic timestamp recorded into a per-thread `Vec<f64>`
/// (millisecond latencies) — merged into one reservoir on return
/// ("bounded" per §A7 in spirit: bounded by however many ops a single
/// thread completes in a few seconds, not literally capacity-limited,
/// since this harness measures single points rather than a long-running
/// service). Each worker checks a shared `AtomicBool` deadline flag
/// between ops rather than each thread reading its own clock every
/// iteration, so the measured window closes at (very nearly) the same
/// wall-clock instant across all threads.
///
/// A worker closure returning `Err` aborts that thread's loop early and
/// the error is propagated after `join` — a real engine failure mid-run
/// must surface as a hard error, not a silently-short count.
pub fn run_point<F>(duration_secs: f64, warmup_secs: f64, worker_fns: Vec<F>) -> Result<(u64, Vec<f64>, f64)>
where
    F: FnMut() -> Result<()> + Send + 'static,
{
    let warmup_deadline = Instant::now() + Duration::from_secs_f64(warmup_secs);
    let stop = Arc::new(AtomicBool::new(false));

    let handles: Vec<std::thread::JoinHandle<Result<(u64, Vec<f64>)>>> = worker_fns
        .into_iter()
        .map(|mut op| {
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                // Warm-up: run the real op, discard timings.
                while Instant::now() < warmup_deadline {
                    op()?;
                }
                let mut count: u64 = 0;
                let mut latencies_ms = Vec::new();
                while !stop.load(Ordering::Relaxed) {
                    let start = Instant::now();
                    op()?;
                    latencies_ms.push(start.elapsed().as_secs_f64() * 1000.0);
                    count += 1;
                }
                Ok((count, latencies_ms))
            })
        })
        .collect();

    // The measured window starts once every thread has cleared warm-up
    // (they share one `warmup_deadline`, so this sleep is that deadline
    // plus the measured duration) and ends when `stop` flips.
    std::thread::sleep(warmup_deadline.saturating_duration_since(Instant::now()));
    let measured_start = Instant::now();
    std::thread::sleep(Duration::from_secs_f64(duration_secs));
    stop.store(true, Ordering::Relaxed);
    let actual_duration_s = measured_start.elapsed().as_secs_f64();

    let mut total_ops: u64 = 0;
    let mut all_latencies_ms = Vec::new();
    for h in handles {
        let (count, mut latencies) = h.join().expect("worker thread panicked")?;
        total_ops += count;
        all_latencies_ms.append(&mut latencies);
    }
    Ok((total_ops, all_latencies_ms, actual_duration_s))
}

/// p50/p99 from a latency sample. Nearest-rank on the sorted vector —
/// sufficient for a benchmark chart, not a claim of statistical rigor.
pub fn percentiles_ms(mut latencies_ms: Vec<f64>) -> (f64, f64) {
    if latencies_ms.is_empty() {
        return (0.0, 0.0);
    }
    latencies_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let rank = |p: f64| -> f64 {
        let idx = ((p * latencies_ms.len() as f64).ceil() as usize).saturating_sub(1);
        latencies_ms[idx.min(latencies_ms.len() - 1)]
    };
    (rank(0.50), rank(0.99))
}
