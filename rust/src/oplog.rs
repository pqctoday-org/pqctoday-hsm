//! PKCS#11 operation-evidence log — the Rust engine's half.
//!
//! This is the counterpart of the C++ engine's `src/lib/common/OpLog.{h,cpp}`,
//! and it deliberately emits the **same** record grammar. One parser
//! (`pqctoday-sandbox/tests/_evidence.sh`) therefore serves both engines, and a
//! scenario does not need to know which one it is talking to:
//!
//! ```text
//! PQCEV v=1 ts=<ms since epoch> pid=<pid> op=<C_ function> <key=value>...
//! ```
//!
//! Why this exists: before it, the shipped Rust library emitted **nothing at
//! all** — the only `println!`/`eprintln!` in the tree live in a KAT generator.
//! So the two scenarios this engine backs (`hsm-perf-bench`, `pqctoday-kmip`)
//! could assert that ML-DSA ran inside the token but never show it.
//!
//! # Three constraints, all load-bearing
//!
//! **1. Runtime gating, never a compile-time feature.** The crate already has
//! an opt-in `acvp` feature with a deliberate note that every shipped artifact
//! builds *without* it. That pattern is exactly wrong here: a compile-time
//! logging feature means the artifact you collect evidence from is not the
//! artifact you ship. `SOFTHSM3_OP_LOG` is read once at first use; unset means
//! `enabled()` is a single relaxed load returning false.
//!
//! *Deviation from the plan, stated on purpose:* the programme document called
//! for the `log` facade crate. A facade routes through whatever logger the host
//! installs, which would format records however that logger sees fit — and the
//! whole value here is that the bytes match the C++ engine's exactly. A
//! self-contained sink is both closer to the requirement and one dependency
//! lighter; the requirement the facade was chosen for (zero cost when off) is
//! met by the `OnceLock` check.
//!
//! **2. The WASM targets must keep building.** `wasm32-unknown-unknown` has no
//! usable filesystem and no process id, so the whole sink is `cfg`-gated out
//! there and every entry point becomes a no-op. `wasm32-unknown-emscripten`
//! keeps it: that target is linked into `openssl.wasm` as a staticlib and does
//! have emscripten's POSIX shims. The gate is on the *sink*, not on the call
//! sites, so instrumented code compiles identically everywhere.
//!
//! **3. Logging must be off when the benchmark measures.** `hsm-perf-bench`
//! reaches ~62,000 signs/sec; logging every operation at that rate measures the
//! logger. Its evidence run (small N, logging on) and its measurement run
//! (logging off) are separate, and any published ops/sec figure must come from
//! the latter and say so.

#![allow(dead_code)]
// Not a warning here, a hard error. Every arm of the two lookup tables below is
// a `const` pattern, and Rust silently reinterprets an arm whose name is NOT a
// const as an irrefutable BINDING that swallows every arm after it. That is not
// hypothetical: `CKR_DEVICE_ERROR` is absent from `constants.rs`, so the first
// draft of `rv_name` returned "CKR_DEVICE_ERROR" for every input, and the only
// signal was an `unreachable pattern` warning lost among the crate's other 57.
// Denying it turns the next such typo into a build failure.
#![deny(unreachable_patterns)]

/// `CKR_DEVICE_ERROR` — defined here because `constants.rs` does not carry it.
/// Value from the normative header (`src/lib/pkcs11/pkcs11t.h:1384`), not from
/// memory: the PKCS#11 v3.2 spec and that header are the only reference for
/// `CK*` values.
const CKR_DEVICE_ERROR: u32 = 0x0000_0030;

/// `SOFTHSM3_OP_LOG` accepts the same values as the C++ engine: unset or empty
/// disables; `stderr` or `-` writes to stderr — the only retrieval path for the
/// distroless `pqc-kmip` container, where `docker logs` is all there is; any
/// other value is a file path, opened append so several processes can share one
/// evidence file.
pub const ENV_VAR: &str = "SOFTHSM3_OP_LOG";

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
                    // Fall back to stderr rather than silently disabling: a run
                    // that was asked for evidence and produced none must be
                    // visibly wrong, not quietly empty.
                    eprintln!(
                        "PQCEV v=1 op=oplog_init error=\"cannot open {spec}: {e}\" fallback=stderr"
                    );
                    Some(Mutex::new(Target::Stderr))
                }
            }
        })
    }

    pub fn enabled() -> bool {
        sink().is_some()
    }

    pub fn emit(op: &str, tail: &str) {
        let Some(lock) = sink().as_ref() else {
            return;
        };
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let pid = std::process::id();
        // One formatted line, one write: records from concurrent sessions
        // interleave but never split.
        let line = format!("PQCEV v=1 ts={ts} pid={pid} op={op} {tail}\n");
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
    // No filesystem, no process id, no wall clock worth the name. The call
    // sites still compile; they just do nothing.
    pub fn enabled() -> bool {
        false
    }
    pub fn emit(_op: &str, _tail: &str) {}
}

#[inline]
pub fn enabled() -> bool {
    sink::enabled()
}

#[inline]
pub fn emit(op: &str, tail: &str) {
    sink::emit(op, tail)
}

/// Spelled-out PKCS#11 mechanism name, or `CKM_UNKNOWN`. The numeric id is
/// always logged alongside, so an unknown name costs readability, never data.
///
/// The pre-hash ML-DSA and SLH-DSA variants are named as well as the pure ones:
/// they are still post-quantum signatures, and leaving them unnamed would let a
/// consumer conclude no PQC signing happened when it did. Classical mechanisms
/// are named too, so "no classical fallback where PQC is claimed" is assertable
/// rather than merely hoped for.
pub fn mech_name(mech: u32) -> &'static str {
    use crate::constants::*;
    match mech {
        CKM_ML_DSA => "CKM_ML_DSA",
        CKM_ML_DSA_KEY_PAIR_GEN => "CKM_ML_DSA_KEY_PAIR_GEN",
        CKM_SLH_DSA => "CKM_SLH_DSA",
        CKM_SLH_DSA_KEY_PAIR_GEN => "CKM_SLH_DSA_KEY_PAIR_GEN",
        CKM_ML_KEM => "CKM_ML_KEM",
        CKM_ML_KEM_KEY_PAIR_GEN => "CKM_ML_KEM_KEY_PAIR_GEN",
        CKM_HSS => "CKM_HSS",
        CKM_XMSS => "CKM_XMSS",
        CKM_XMSSMT => "CKM_XMSSMT",
        CKM_RSA_PKCS => "CKM_RSA_PKCS",
        CKM_RSA_PKCS_PSS => "CKM_RSA_PKCS_PSS",
        CKM_RSA_PKCS_KEY_PAIR_GEN => "CKM_RSA_PKCS_KEY_PAIR_GEN",
        CKM_ECDSA => "CKM_ECDSA",
        CKM_EC_KEY_PAIR_GEN => "CKM_EC_KEY_PAIR_GEN",
        CKM_ECDH1_DERIVE => "CKM_ECDH1_DERIVE",
        CKM_EDDSA => "CKM_EDDSA",
        CKM_AES_KEY_GEN => "CKM_AES_KEY_GEN",
        _ => "CKM_UNKNOWN",
    }
}

/// `CKR_OK` and the error codes a scenario is likely to see. Anything else is
/// `CKR_UNKNOWN` with the numeric value alongside.
pub fn rv_name(rv: u32) -> &'static str {
    use crate::constants::*;
    match rv {
        CKR_OK => "CKR_OK",
        CKR_ARGUMENTS_BAD => "CKR_ARGUMENTS_BAD",
        CKR_BUFFER_TOO_SMALL => "CKR_BUFFER_TOO_SMALL",
        CKR_CRYPTOKI_NOT_INITIALIZED => "CKR_CRYPTOKI_NOT_INITIALIZED",
        CKR_DEVICE_ERROR => "CKR_DEVICE_ERROR",
        CKR_FUNCTION_FAILED => "CKR_FUNCTION_FAILED",
        CKR_GENERAL_ERROR => "CKR_GENERAL_ERROR",
        CKR_KEY_FUNCTION_NOT_PERMITTED => "CKR_KEY_FUNCTION_NOT_PERMITTED",
        CKR_KEY_HANDLE_INVALID => "CKR_KEY_HANDLE_INVALID",
        CKR_KEY_TYPE_INCONSISTENT => "CKR_KEY_TYPE_INCONSISTENT",
        CKR_MECHANISM_INVALID => "CKR_MECHANISM_INVALID",
        CKR_MECHANISM_PARAM_INVALID => "CKR_MECHANISM_PARAM_INVALID",
        CKR_OBJECT_HANDLE_INVALID => "CKR_OBJECT_HANDLE_INVALID",
        CKR_OPERATION_ACTIVE => "CKR_OPERATION_ACTIVE",
        CKR_OPERATION_NOT_INITIALIZED => "CKR_OPERATION_NOT_INITIALIZED",
        CKR_SESSION_HANDLE_INVALID => "CKR_SESSION_HANDLE_INVALID",
        CKR_TEMPLATE_INCOMPLETE => "CKR_TEMPLATE_INCOMPLETE",
        CKR_TEMPLATE_INCONSISTENT => "CKR_TEMPLATE_INCONSISTENT",
        CKR_USER_NOT_LOGGED_IN => "CKR_USER_NOT_LOGGED_IN",
        _ => "CKR_UNKNOWN",
    }
}

/// `CKA_PARAMETER_SET` is mechanism-relative — `2` means ML-DSA-65 under
/// `CKM_ML_DSA` and ML-KEM-768 under `CKM_ML_KEM` — so resolving it needs both.
pub fn param_set_name(mech: u32, ps: u32) -> &'static str {
    use crate::constants::*;
    match mech {
        CKM_ML_DSA | CKM_ML_DSA_KEY_PAIR_GEN => match ps {
            1 => "ML-DSA-44",
            2 => "ML-DSA-65",
            3 => "ML-DSA-87",
            _ => "unknown",
        },
        CKM_ML_KEM | CKM_ML_KEM_KEY_PAIR_GEN => match ps {
            1 => "ML-KEM-512",
            2 => "ML-KEM-768",
            3 => "ML-KEM-1024",
            _ => "unknown",
        },
        CKM_SLH_DSA | CKM_SLH_DSA_KEY_PAIR_GEN => match ps {
            1 => "SLH-DSA-SHA2-128s",
            2 => "SLH-DSA-SHAKE-128s",
            3 => "SLH-DSA-SHA2-128f",
            4 => "SLH-DSA-SHAKE-128f",
            5 => "SLH-DSA-SHA2-192s",
            6 => "SLH-DSA-SHAKE-192s",
            7 => "SLH-DSA-SHA2-192f",
            8 => "SLH-DSA-SHAKE-192f",
            9 => "SLH-DSA-SHA2-256s",
            10 => "SLH-DSA-SHAKE-256s",
            11 => "SLH-DSA-SHA2-256f",
            12 => "SLH-DSA-SHAKE-256f",
            _ => "unknown",
        },
        _ => "n/a",
    }
}

/// Render a byte string (a `CKA_LABEL`, typically) as a safe log value: bare
/// when it matches `[A-Za-z0-9._:/+-]+`, otherwise double-quoted with `\"`,
/// `\\` and `\xNN` escapes. Truncated to 128 source bytes. Empty renders as the
/// bare token `-`.
///
/// The escaping matters to the consumer, not just to readability: the parser
/// splits records on whitespace, so an unquoted label containing a space would
/// corrupt every field after it. A quoted label is reported as unattributable
/// instead — wrong-but-visible beats wrong-and-silent.
pub fn value(data: &[u8]) -> String {
    if data.is_empty() {
        return "-".to_string();
    }
    let data = &data[..data.len().min(128)];
    let bare = data.iter().all(|&c| {
        c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b':' | b'/' | b'+' | b'-')
    });
    if bare {
        return String::from_utf8_lossy(data).into_owned();
    }
    let mut out = String::with_capacity(data.len() + 8);
    out.push('"');
    for &c in data {
        match c {
            b'"' | b'\\' => {
                out.push('\\');
                out.push(c as char);
            }
            0x20..=0x7e => out.push(c as char),
            _ => out.push_str(&format!("\\x{c:02x}")),
        }
    }
    out.push('"');
    out
}

/// The `key=` / `keytype=` / `paramset=` fragment of a record, read off the
/// object store. Reports `-` for anything absent rather than a default, so a
/// consumer can tell "the token said false/zero" from "the token never said".
///
/// Only ever called behind [`enabled()`], so it costs nothing in a normal run.
pub fn key_fields(h_key: u32, mech: u32) -> String {
    let label = crate::state::get_object_attr_bytes(h_key, crate::native::keygen::CKA_LABEL)
        .unwrap_or_default();
    let key_type = crate::state::get_object_attr_u32(h_key, crate::constants::CKA_KEY_TYPE);
    let ps = crate::state::get_object_param_set(h_key);

    let key_type_str = match key_type {
        Some(k) => format!("0x{k:02x}"),
        None => "-".to_string(),
    };
    let ps_str = if ps == 0 {
        "-".to_string()
    } else {
        param_set_name(mech, ps).to_string()
    };
    format!(
        "key={} keytype={} paramset={}",
        value(&label),
        key_type_str,
        ps_str
    )
}

/// The custody half of a keygen record: the attributes that decide whether
/// "generated in the HSM and never leaves it" is actually true. Several
/// scenarios assert non-extractability today with nothing behind the assertion;
/// logging these at generation is what turns it into evidence.
pub fn key_custody_fields(h_key: u32) -> String {
    use crate::constants::*;
    const FIELDS: [(&str, u32); 5] = [
        ("extractable", CKA_EXTRACTABLE),
        ("sensitive", CKA_SENSITIVE),
        ("never_extractable", CKA_NEVER_EXTRACTABLE),
        ("always_sensitive", CKA_ALWAYS_SENSITIVE),
        ("local", CKA_LOCAL),
    ];
    FIELDS
        .iter()
        .map(|(name, attr)| {
            let v = match crate::state::get_object_attr_bytes(h_key, *attr) {
                Some(b) if !b.is_empty() => {
                    if b[0] != 0 {
                        "true"
                    } else {
                        "false"
                    }
                }
                _ => "-",
            };
            format!("{name}={v}")
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_renders_bare_when_safe() {
        assert_eq!(value(b"ssh-host-mldsa-65"), "ssh-host-mldsa-65");
        assert_eq!(value(b""), "-");
    }

    #[test]
    fn value_quotes_anything_that_would_break_field_splitting() {
        // A space is the dangerous case: unquoted, it would shift every
        // subsequent key=value pair by one field in the consumer's parser.
        assert_eq!(value(b"my key"), "\"my key\"");
        assert_eq!(value(b"a\"b"), "\"a\\\"b\"");
        assert_eq!(value(&[0x01]), "\"\\x01\"");
    }

    #[test]
    fn value_truncates_long_labels() {
        let long = vec![b'a'; 300];
        assert_eq!(value(&long).len(), 128);
    }

    #[test]
    fn param_set_is_resolved_relative_to_the_mechanism() {
        use crate::constants::*;
        // The same numeric 2 means different things per mechanism -- the whole
        // reason param_set_name takes the mechanism.
        assert_eq!(param_set_name(CKM_ML_DSA, 2), "ML-DSA-65");
        assert_eq!(param_set_name(CKM_ML_KEM, 2), "ML-KEM-768");
    }

    #[test]
    fn unknown_codes_are_named_not_guessed() {
        assert_eq!(mech_name(0xdead_beef), "CKM_UNKNOWN");
        assert_eq!(rv_name(0xdead_beef), "CKR_UNKNOWN");
    }
}
