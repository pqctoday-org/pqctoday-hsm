//! WP7-c (cert-ops plan revision, 07-09) — permanent, automated
//! enforcement of invariant 0a ("no crypto in the `kmip` crate — only
//! encoding") for the pure-Rust cert-ops surface this session's
//! Certify/Re-certify/Validate port owns: every cryptographic
//! PRIMITIVE (sign, verify, hash) executes in `softhsmrustv3` via a
//! `native::*`/`C_*` call; this crate builds/parses DER and reformats
//! already-computed signatures, never computes one.
//!
//! Previously this invariant was "verified by hand, once, by reading
//! `spki_verify.rs`/`certify.rs`/`validate.rs`" (plan §7 WP7 item c) —
//! nothing stopped a future change from silently reintroducing crypto.
//! This is that permanent gate.
//!
//! **Scope is deliberately the three cert-ops files, not the whole
//! crate.** The plan's original wording ("the kmip crate's non-test
//! source has zero direct calls...") reads as crate-wide; it isn't
//! achievable as a literal crate-wide gate today. `mac_and_hash.rs`'s
//! `Hash`/`MAC` operations, `register_import_export.rs` /
//! `get_attributes.rs`'s §11 Digest-at-creation logic, `derive_key.rs`,
//! `policy/policy.rs`, and `server/auth.rs`'s password hashing all call
//! `sha2` directly in production code too — all pre-existing, all
//! outside what this session's port ever touched or hand-verified.
//! Widening this gate to cover them is real, separate follow-up work,
//! not something to silently paper over by weakening what this gate
//! checks. See the plan doc's cert-ops-scope note for the full list.
//!
//! (i) below is what this file checks; (ii) — no C-backed crypto crate
//! (`ring`, `aws-lc-rs`) in the wasm dependency graph — is checked by
//! [`wasm_dependency_graph_has_no_c_backed_crypto`].

use std::fs;
use std::path::Path;
use std::process::Command;

/// Crate-path prefixes for crypto-primitive APIs that must never be
/// called directly from the cert-ops surface — every one of these has
/// a `native::*` equivalent in `softhsmrustv3` that runs the same
/// primitive inside the engine instead.
const BANNED_TOKENS: &[&str] = &[
    "sha2::",
    "sha3::",
    "p256::",
    "p384::",
    "p521::",
    "ed25519_dalek::",
    "rsa::",
];

/// The cert-ops surface this gate covers — see the module doc for why
/// this isn't crate-wide.
const SCOPED_FILES: &[&str] = &[
    "src/ops/certify.rs",
    "src/ops/validate.rs",
    "src/ops/spki_verify.rs",
];

/// Remove `//` line comments and `/* */` block comments (no nesting —
/// none of the scoped files nest block comments). Run before
/// [`strip_test_code`] so a stray brace inside a doc comment can never
/// desynchronize that pass's brace counting.
fn strip_comments(src: &str) -> String {
    // Byte-based throughout — `src` is full of multi-byte UTF-8 (em
    // dashes, section signs) in comments, so slicing it as `&str` at an
    // arbitrary scan offset would panic on a non-char-boundary index.
    // `[u8]::starts_with` has no such restriction.
    let bytes = src.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i..].starts_with(b"//") {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if bytes[i..].starts_with(b"/*") {
            i += 2;
            while i < bytes.len() && !bytes[i..].starts_with(b"*/") {
                i += 1;
            }
            i = (i + 2).min(bytes.len());
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Remove every `#[cfg(test)]`-attributed item/block and every
/// `mod tests { ... }` body (balanced-brace counting — not a real Rust
/// parser, good enough for a source-grep gate). What's left is the
/// text that actually ships in a release build.
fn strip_test_code(src: &str) -> String {
    let bytes = src.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i..].starts_with(b"#[cfg(test)]") || bytes[i..].starts_with(b"mod tests") {
            if let Some(open_rel) = bytes[i..].iter().position(|&b| b == b'{') {
                let open = i + open_rel;
                let mut depth = 0i32;
                let mut j = open;
                while j < bytes.len() {
                    match bytes[j] {
                        b'{' => depth += 1,
                        b'}' => {
                            depth -= 1;
                            if depth == 0 {
                                j += 1;
                                break;
                            }
                        }
                        _ => {}
                    }
                    j += 1;
                }
                i = j;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[test]
fn certops_production_source_calls_no_crypto_primitive_directly() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let mut violations = Vec::new();

    for rel_path in SCOPED_FILES {
        let path = Path::new(manifest_dir).join(rel_path);
        let raw = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("WP7-c gate: failed to read {rel_path}: {e}"));
        let production_only = strip_test_code(&strip_comments(&raw));

        for (line_no, line) in production_only.lines().enumerate() {
            for token in BANNED_TOKENS {
                if line.contains(token) {
                    violations.push(format!(
                        "{rel_path}:~{line_no}: direct `{token}` call outside \
                         #[cfg(test)] — route this through a softhsmrustv3::native::* \
                         call instead. Offending line (post comment/test strip):\n    {line}"
                    ));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "invariant 0a violated (\"no crypto in the kmip crate — only \
         encoding\") in the cert-ops surface:\n\n{}",
        violations.join("\n\n")
    );
}

/// (ii) — `cargo tree` for the wasm-targeted dependency graph
/// (`--no-default-features`, the feature set the in-browser bundle
/// actually builds with per `Cargo.toml`'s `native` feature doc)
/// contains no `ring` / `aws-lc-rs`. Confirms WP3/WP4's "the wasm graph
/// is already 100% clean" claim stays true, permanently — a future
/// dependency bump that pulls one back in transitively fails this test
/// instead of silently shipping a C-backed crypto crate into the
/// browser bundle.
///
/// Native-only: needs `cargo` on `PATH` and network-independent
/// metadata resolution (offline-safe once `Cargo.lock` is present, same
/// as any other `cargo tree` invocation in CI).
#[test]
fn wasm_dependency_graph_has_no_c_backed_crypto() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let output = Command::new(env!("CARGO"))
        .args([
            "tree",
            "--no-default-features",
            "--target",
            "wasm32-unknown-unknown",
            "-e",
            "normal",
        ])
        .current_dir(manifest_dir)
        .output()
        .expect("WP7-c gate: failed to run `cargo tree` — is cargo on PATH?");

    // `cargo tree` for a target with no matching lockfile entries for some
    // platform-gated deps can still exit 0 with a partial tree; treat a
    // hard failure (missing target support etc.) as a skip, not a false
    // "clean" pass — but a genuine dependency-resolution error should
    // still fail loudly rather than be silently swallowed.
    assert!(
        output.status.success(),
        "WP7-c gate: `cargo tree --no-default-features --target \
         wasm32-unknown-unknown` failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let tree = String::from_utf8_lossy(&output.stdout);
    for banned_crate in ["ring", "aws-lc-rs", "aws_lc_rs"] {
        assert!(
            !tree.contains(banned_crate),
            "invariant 0b violated (\"pure Rust... ring, aws-lc-rs... \
             gone from production code\"): `{banned_crate}` appears in the \
             wasm32 (--no-default-features) dependency graph:\n{tree}"
        );
    }
}

/// A gate that always passes proves nothing — these check the stripping
/// logic itself against adversarial synthetic fixtures, so a future
/// edit to `strip_comments`/`strip_test_code` that accidentally starts
/// swallowing production code (making the gate above silently
/// toothless) fails loudly here instead.
#[cfg(test)]
mod self_test {
    use super::*;

    #[test]
    fn production_call_survives_stripping_and_would_be_flagged() {
        let src = "fn f() {\n    let d = sha2::Sha256::digest(x);\n}\n";
        let stripped = strip_test_code(&strip_comments(src));
        assert!(
            stripped.contains("sha2::"),
            "a genuine production-path call must NOT be stripped: {stripped:?}"
        );
    }

    #[test]
    fn cfg_test_inline_block_is_stripped() {
        let src = "fn f() {\n    #[cfg(test)]\n    {\n        use sha2::Sha256;\n        let _ = sha2::Sha256::digest(x);\n    }\n    real_code();\n}\n";
        let stripped = strip_test_code(&strip_comments(src));
        assert!(
            !stripped.contains("sha2::"),
            "a #[cfg(test)] block must be stripped: {stripped:?}"
        );
        assert!(
            stripped.contains("real_code();"),
            "code after the stripped block must survive: {stripped:?}"
        );
    }

    #[test]
    fn mod_tests_block_is_stripped() {
        let src = "fn prod() {}\n#[cfg(test)]\nmod tests {\n    use sha2::Sha256;\n    fn t() { let _ = sha2::Sha256::digest(x); }\n}\n";
        let stripped = strip_test_code(&strip_comments(src));
        assert!(!stripped.contains("sha2::"), "mod tests must be stripped: {stripped:?}");
        assert!(stripped.contains("fn prod()"), "code before mod tests must survive: {stripped:?}");
    }

    #[test]
    fn line_comment_mentioning_a_banned_token_is_stripped() {
        let src = "fn f() {\n    // was a direct sha2::Sha256::digest call, fixed in WP7-d\n    real_code();\n}\n";
        let stripped = strip_test_code(&strip_comments(src));
        assert!(
            !stripped.contains("sha2::"),
            "a historical mention inside a comment must not false-positive: {stripped:?}"
        );
    }

    #[test]
    fn block_comment_and_non_ascii_em_dash_do_not_panic_or_leak() {
        // Real comments in this crate are full of em dashes (—) and
        // section signs (§) — exactly the multi-byte UTF-8 that broke
        // the first cut of this gate (str-slicing at a non-char-boundary
        // byte offset panics). This fixture is the regression pin.
        let src = "/* — uses sha2::Sha256 internally, historically — */\nfn f() { real_code(); }\n";
        let stripped = strip_test_code(&strip_comments(src));
        assert!(!stripped.contains("sha2::"), "block comment must be stripped: {stripped:?}");
        assert!(stripped.contains("real_code();"));
    }
}
