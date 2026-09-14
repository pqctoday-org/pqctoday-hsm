//! Diagnostic-only, thread-local phase timing for PQC software baselines.
//!
//! An operation emits one JSONL record only when `PQC_PHASE_PROFILE_OUTPUT`
//! names an output file. Records contain labels, counts and durations only;
//! cryptographic inputs, outputs and intermediate values are never retained.

use std::cell::RefCell;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub enum Phase {
    Hashing = 0,
    Sampling = 1,
    MatrixExpansion = 2,
    Ntt = 3,
    Multiplication = 4,
    Encoding = 5,
    Tree = 6,
    Comparison = 7,
    Orchestration = 8,
}

const PHASES: [(&str, Phase); 9] = [
    ("hashing", Phase::Hashing),
    ("sampling", Phase::Sampling),
    ("matrix_expansion", Phase::MatrixExpansion),
    ("ntt", Phase::Ntt),
    ("multiplication", Phase::Multiplication),
    ("encoding", Phase::Encoding),
    ("tree", Phase::Tree),
    ("comparison", Phase::Comparison),
    ("orchestration", Phase::Orchestration),
];

#[derive(Clone, Copy, Default)]
struct Metric {
    ns: u128,
    calls: u64,
}

struct Active {
    phase: Phase,
    resumed: Instant,
}

struct Trace {
    algorithm: &'static str,
    operation: &'static str,
    started: Instant,
    metrics: [Metric; 9],
    stack: Vec<Active>,
}

thread_local! { static TRACE: RefCell<Option<Trace>> = const { RefCell::new(None) }; }
static OUTPUT: OnceLock<Option<Mutex<File>>> = OnceLock::new();

fn output() -> Option<&'static Mutex<File>> {
    OUTPUT
        .get_or_init(|| {
            let path = std::env::var_os("PQC_PHASE_PROFILE_OUTPUT")?;
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .ok()
                .map(Mutex::new)
        })
        .as_ref()
}

#[must_use]
pub struct OperationGuard {
    enabled: bool,
}

pub fn operation(algorithm: &'static str, operation: &'static str) -> OperationGuard {
    if output().is_none() {
        return OperationGuard { enabled: false };
    }
    let now = Instant::now();
    let enabled = TRACE.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_some() {
            return false;
        }
        *slot = Some(Trace {
            algorithm,
            operation,
            started: now,
            metrics: [Metric::default(); 9],
            stack: vec![Active {
                phase: Phase::Orchestration,
                resumed: now,
            }],
        });
        true
    });
    OperationGuard { enabled }
}

#[must_use]
pub struct SpanGuard {
    enabled: bool,
}

pub fn span(phase: Phase) -> SpanGuard {
    let now = Instant::now();
    let enabled = TRACE.with(|slot| {
        let mut slot = slot.borrow_mut();
        let Some(trace) = slot.as_mut() else {
            return false;
        };
        if let Some(parent) = trace.stack.last() {
            trace.metrics[parent.phase as usize].ns +=
                now.duration_since(parent.resumed).as_nanos();
        }
        trace.metrics[phase as usize].calls += 1;
        trace.stack.push(Active {
            phase,
            resumed: now,
        });
        true
    });
    SpanGuard { enabled }
}

impl Drop for SpanGuard {
    fn drop(&mut self) {
        if !self.enabled {
            return;
        }
        let now = Instant::now();
        TRACE.with(|slot| {
            let mut slot = slot.borrow_mut();
            let Some(trace) = slot.as_mut() else {
                return;
            };
            if let Some(active) = trace.stack.pop() {
                trace.metrics[active.phase as usize].ns +=
                    now.duration_since(active.resumed).as_nanos();
            }
            if let Some(parent) = trace.stack.last_mut() {
                parent.resumed = now;
            }
        });
    }
}

impl Drop for OperationGuard {
    fn drop(&mut self) {
        if !self.enabled {
            return;
        }
        let now = Instant::now();
        let trace = TRACE.with(|slot| {
            let mut slot = slot.borrow_mut();
            if let Some(trace) = slot.as_mut() {
                if let Some(active) = trace.stack.last() {
                    trace.metrics[active.phase as usize].ns +=
                        now.duration_since(active.resumed).as_nanos();
                }
            }
            slot.take()
        });
        if let Some(trace) = trace {
            emit(trace, now);
        }
    }
}

fn emit(trace: Trace, finished: Instant) {
    let Some(file) = output() else {
        return;
    };
    let mut line = format!(
        "{{\"schema\":\"pqctoday.pqc-phase-profile.v1\",\"algorithm\":\"{}\",\"operation\":\"{}\",\"duration_ns\":{},\"phases\":{{",
        trace.algorithm, trace.operation, finished.duration_since(trace.started).as_nanos()
    );
    for (index, (name, phase)) in PHASES.iter().enumerate() {
        if index != 0 {
            line.push(',');
        }
        let metric = trace.metrics[*phase as usize];
        line.push_str(&format!(
            "\"{name}\":{{\"ns\":{},\"calls\":{}}}",
            metric.ns, metric.calls
        ));
    }
    line.push_str("}}\n");
    let mut file = file.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let _ = file.write_all(line.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nested_spans_emit_structured_exclusive_totals() {
        let path = std::env::temp_dir().join(format!("pqc-profile-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        std::env::set_var("PQC_PHASE_PROFILE_OUTPUT", &path);
        {
            let _op = operation("ML-KEM-768", "encaps");
            {
                let _span = span(Phase::Hashing);
                std::hint::black_box(1);
            }
        }
        let line = std::fs::read_to_string(&path).unwrap();
        let value: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(value["schema"], "pqctoday.pqc-phase-profile.v1");
        assert_eq!(value["algorithm"], "ML-KEM-768");
        assert_eq!(value["phases"]["hashing"]["calls"], 1);
        let _ = std::fs::remove_file(path);
    }
}
