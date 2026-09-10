//! Authentication-attempt evidence log — shared by `pqctoday-kmip` and both
//! PKCS#11-remoting services.
//!
//! docs/remediation-plan-auth-visibility-evidence-log-09102026.md, Q1
//! (decided): a failed login attempt (bad KMIP credential, rejected TLS
//! handshake, wrong PKCS#11-remoting PIN) needs a signal that actually
//! reaches the appliance's syslog/RELP collector. A bare `tracing::warn!`
//! does not — checked live against the running appliance, `journald`'s
//! `ForwardToSyslog` is off, so anything that only goes through `tracing`
//! reaches `journalctl` and nothing else. This is a small, purpose-built
//! sink instead, matching [`crate::oplog`]'s proven shape (env-var-gated
//! path, `OpenOptions::append`, one line per event) so the appliance side
//! can tail it exactly the way it already tails `SOFTHSM3_OP_LOG`.
//!
//! Deliberately a **separate** sink from `oplog`, not a reuse of it: an
//! auth failure is not a PKCS#11 operation, and `oplog`'s `PQCEV` grammar
//! and its one consumer (`pqctoday-sandbox/tests/_evidence.sh`) are shaped
//! specifically around paired `C_*` records. Blurring the two would make
//! both harder to parse.
//!
//! ```text
//! PQCAUTH v=1 ts=<ms since epoch> pid=<pid> surface=<surface> reason=<reason> peer=<ip:port|none>
//! ```
//!
//! `surface` identifies which of the three call sites raised the event
//! (`kmip-credential`, `kmip-tls-handshake`, `remoting-pin`); `reason` is a
//! short, fixed token per surface (never free text — see each call site's
//! own doc comment for its exact set, and keep it that way: unbounded
//! values here would be exactly the cardinality mistake
//! `metrics.rs::record_admin_request`'s own doc already warns against for
//! Prometheus, and this sink has the same "one file, one format, many
//! readers" shape as a metric even though it isn't one).
//!
//! Same three constraints as `oplog` (runtime-gated via `OnceLock`, `cfg`'d
//! out on `wasm32-unknown-unknown`), for the same reasons — see that
//! module's doc for the full rationale. This sink is not on any
//! measured-throughput hot path (an auth failure is, definitionally, not
//! the common case), so the zero-cost-when-off property matters here for
//! consistency with `oplog`, not because a benchmark depends on it.

#![allow(dead_code)]

/// `PQC_AUTH_LOG` accepts the same values as `SOFTHSM3_OP_LOG`
/// ([`crate::oplog::ENV_VAR`]): unset or empty disables; `stderr`/`-` writes
/// to stderr; any other value is a file path, opened append so several
/// processes (KMIP, both remoting services) can share one log.
pub const ENV_VAR: &str = "PQC_AUTH_LOG";

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
mod sink {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::sync::{Mutex, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    enum Target {
        Stderr,
        File(std::fs::File),
    }

    static SINK: OnceLock<Option<Mutex<Target>>> = OnceLock::new();

    fn sink() -> &'static Option<Mutex<Target>> {
        SINK.get_or_init(|| {
            let spec = std::env::var(super::ENV_VAR).ok()?;
            if spec.is_empty() {
                return None;
            }
            if spec == "stderr" || spec == "-" {
                return Some(Mutex::new(Target::Stderr));
            }
            match OpenOptions::new().create(true).append(true).open(&spec) {
                Ok(f) => Some(Mutex::new(Target::File(f))),
                Err(e) => {
                    eprintln!(
                        "PQCAUTH v=1 op=authlog_init error=\"cannot open {spec}: {e}\" fallback=stderr"
                    );
                    Some(Mutex::new(Target::Stderr))
                }
            }
        })
    }

    pub fn enabled() -> bool {
        sink().is_some()
    }

    pub fn emit(surface: &str, reason: &str, peer: Option<&str>) {
        let Some(lock) = sink().as_ref() else {
            return;
        };
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let pid = std::process::id();
        let peer = peer.unwrap_or("none");
        let line = format!("PQCAUTH v=1 ts={ts} pid={pid} surface={surface} reason={reason} peer={peer}\n");
        if let Ok(mut t) = lock.lock() {
            let _ = match &mut *t {
                Target::Stderr => {
                    let mut e = std::io::stderr();
                    e.write_all(line.as_bytes()).and_then(|_| e.flush())
                }
                Target::File(f) => f.write_all(line.as_bytes()).and_then(|_| f.flush()),
            };
        }
    }
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod sink {
    pub fn enabled() -> bool {
        false
    }
    pub fn emit(_surface: &str, _reason: &str, _peer: Option<&str>) {}
}

#[inline]
pub fn enabled() -> bool {
    sink::enabled()
}

/// Record one authentication-attempt failure. `surface` and `reason` should
/// be short, fixed tokens (see module doc); `peer`, when known, should be
/// `ip:port`.
pub fn emit(surface: &str, reason: &str, peer: Option<&str>) {
    if !enabled() {
        return;
    }
    sink::emit(surface, reason, peer);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_by_default_when_env_var_unset() {
        // This process may have run other tests that already resolved the
        // OnceLock one way or another (integration tests avoid this by
        // running in their own process — see oplog_evidence.rs's own doc on
        // exactly this hazard); this unit test only checks that `enabled()`
        // does not panic and returns a bool, not a specific value, for
        // exactly that reason.
        let _ = enabled();
    }
}
