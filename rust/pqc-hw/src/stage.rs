//! Per-stage host-path timing for accelerator operations.
//!
//! Off by default. When enabled (`enable(true)`, or `PQC_HW_STAGE_PROFILE=1`
//! read by [`enable_from_env`]), every instrumented stage adds its wall time
//! and one count to a thread-local table; [`take_thread`] returns and resets
//! the calling thread's table and [`snapshot_global`] returns the sum over
//! every thread that has called [`flush_thread`] (or [`report`]).
//!
//! Records contain stage labels, counts and nanoseconds only: no key
//! material, message, signature or intermediate value is ever retained.
//! Disabled, each stage costs one relaxed atomic load and no clock read.

use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Instant;

/// Instrumented stages of one ML-DSA signing operation, in path order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub enum Stage {
    /// Private-key decode (`skDecode` + NTT of s1, s2, t0).
    KeyDecode = 0,
    /// Per-key context lookup (digest + cache map), when a cache is used.
    ContextLookup,
    /// `ExpandA(rho)` on the CPU.
    ExpandA,
    /// `mu` and `rho'` hashing.
    MessageHash,
    /// Flattening polynomials into temporary vectors for the accelerator.
    Flatten,
    /// Choosing and locking a signer lane.
    LaneAcquire,
    /// Deciding whether the lane already holds the public matrix.
    ContextCheck,
    /// Uploading the public matrix (encode + sync + DMA + LOAD + publish).
    ContextLoad,
    /// Writing the request record and secret input into the DMA buffer.
    Encode,
    /// Cache clean of the DMA input before the device reads it.
    SyncForDevice,
    /// DMA controller DISPATCH phase (start to done).
    Dispatch,
    /// Signer SIGN command (start to done).
    SignerWait,
    /// DMA controller PUBLISH phase (start to done).
    Publish,
    /// Cache invalidate of the DMA output before the CPU reads it.
    SyncForCpu,
    /// Completion validation and signature copy-out.
    Readback,
    /// The rejection loop on the CPU (no accelerator, or fallback).
    SoftwareLoop,
    /// The whole accelerator hook call, as seen by the signer.
    Accelerator,
}

pub const STAGES: usize = 17;

const NAMES: [&str; STAGES] = [
    "key_decode",
    "context_lookup",
    "expand_a",
    "message_hash",
    "flatten",
    "lane_acquire",
    "context_check",
    "context_load",
    "encode",
    "sync_for_device",
    "dispatch",
    "signer_wait",
    "publish",
    "sync_for_cpu",
    "readback",
    "software_loop",
    "accelerator",
];

impl Stage {
    pub fn name(self) -> &'static str {
        NAMES[self as usize]
    }

    pub fn all() -> [Stage; STAGES] {
        use Stage::*;
        [
            KeyDecode,
            ContextLookup,
            ExpandA,
            MessageHash,
            Flatten,
            LaneAcquire,
            ContextCheck,
            ContextLoad,
            Encode,
            SyncForDevice,
            Dispatch,
            SignerWait,
            Publish,
            SyncForCpu,
            Readback,
            SoftwareLoop,
            Accelerator,
        ]
    }
}

/// Accumulated time and count per stage.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Table {
    pub ns: [u64; STAGES],
    pub count: [u64; STAGES],
}

impl Table {
    pub fn add(&mut self, other: &Table) {
        for index in 0..STAGES {
            self.ns[index] += other.ns[index];
            self.count[index] += other.count[index];
        }
    }

    pub fn ns(&self, stage: Stage) -> u64 {
        self.ns[stage as usize]
    }

    pub fn count(&self, stage: Stage) -> u64 {
        self.count[stage as usize]
    }

    /// One line per non-empty stage: `name count total_us mean_us`.
    pub fn render(&self) -> String {
        let mut out = String::new();
        for stage in Stage::all() {
            let count = self.count(stage);
            if count == 0 {
                continue;
            }
            let total_us = self.ns(stage) as f64 / 1e3;
            out.push_str(&format!(
                "{}\t{}\t{:.1}\t{:.2}\n",
                stage.name(),
                count,
                total_us,
                total_us / count as f64
            ));
        }
        out
    }
}

static ENABLED: AtomicBool = AtomicBool::new(false);
static GLOBAL: Mutex<Table> = Mutex::new(Table {
    ns: [0; STAGES],
    count: [0; STAGES],
});

thread_local! {
    static LOCAL: RefCell<Table> = const {
        RefCell::new(Table {
            ns: [0; STAGES],
            count: [0; STAGES],
        })
    };
}

pub fn enable(on: bool) {
    ENABLED.store(on, Ordering::Relaxed);
}

/// Enables profiling when `PQC_HW_STAGE_PROFILE=1`.
pub fn enable_from_env() {
    if std::env::var_os("PQC_HW_STAGE_PROFILE").is_some_and(|value| value == "1") {
        enable(true);
    }
}

#[inline]
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// Start time of a stage, only when profiling is on.
#[inline]
pub fn start() -> Option<Instant> {
    enabled().then(Instant::now)
}

/// Ends a stage started with [`start`].
#[inline]
pub fn end(stage: Stage, started: Option<Instant>) {
    if let Some(started) = started {
        record(stage, started.elapsed().as_nanos() as u64);
    }
}

/// Adds one measured occurrence of `stage` to the calling thread's table.
#[inline]
pub fn record(stage: Stage, ns: u64) {
    if !enabled() {
        return;
    }
    LOCAL.with(|table| {
        let mut table = table.borrow_mut();
        table.ns[stage as usize] += ns;
        table.count[stage as usize] += 1;
    });
}

/// Returns and resets the calling thread's table.
pub fn take_thread() -> Table {
    LOCAL.with(|table| std::mem::take(&mut *table.borrow_mut()))
}

/// Moves the calling thread's table into the process-wide sum.
pub fn flush_thread() {
    let local = take_thread();
    GLOBAL.lock().unwrap_or_else(|e| e.into_inner()).add(&local);
}

/// The process-wide sum of flushed tables.
pub fn snapshot_global() -> Table {
    *GLOBAL.lock().unwrap_or_else(|e| e.into_inner())
}

/// Returns and resets the process-wide sum.
pub fn take_global() -> Table {
    std::mem::take(&mut *GLOBAL.lock().unwrap_or_else(|e| e.into_inner()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_records_nothing_and_enabled_accumulates() {
        // Thread-local tables make this immune to other tests' threads; the
        // flag is process-wide, so this is the only test that toggles it.
        let handle = std::thread::spawn(|| {
            enable(false);
            record(Stage::Encode, 10);
            assert_eq!(take_thread(), Table::default());
            enable(true);
            record(Stage::Encode, 10);
            record(Stage::Encode, 5);
            let started = start();
            end(Stage::Readback, started);
            enable(false);
            take_thread()
        });
        let table = handle.join().unwrap();
        assert_eq!(table.ns(Stage::Encode), 15);
        assert_eq!(table.count(Stage::Encode), 2);
        assert_eq!(table.count(Stage::Readback), 1);
        assert!(table.render().contains("encode\t2\t"));
    }
}
