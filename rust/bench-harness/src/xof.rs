//! SHAKE128 / SHAKE256 throughput, measured OUTSIDE the PKCS#11 API.
//!
//! PKCS#11 v3.2 defines no SHAKE digest mechanism (SHAKE appears only
//! inside SLH-DSA and ML-DSA), so the engine cannot be asked for one through
//! C_Digest. This probe calls the same RustCrypto `sha3` crate the engine
//! links, directly, so the numbers show what the primitive costs on a
//! target. Every row carries `access_path = "rust-sha3-direct"` and an
//! empty `engine_version` so nothing downstream can mistake it for an HSM
//! measurement. It is a subcommand, not a matrix cell, for the same reason:
//! the PKCS#11 matrix (`--list-algorithms`) stays exactly as it was.

use anyhow::Result;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Shake128, Shake256};

use crate::measure;

#[derive(clap::Args, Debug)]
pub struct XofArgs {
    /// Worker threads, all on one "tenant" (there is no HSM state to split).
    #[arg(long, default_value_t = 4)]
    pub threads: u32,
    #[arg(long, default_value_t = 2.0)]
    pub duration_secs: f64,
    #[arg(long, default_value_t = 0.5)]
    pub warmup_secs: f64,
    #[arg(long, default_value_t = 0)]
    pub min_ops: u64,
    #[arg(long, default_value_t = 60.0)]
    pub max_secs: f64,
    /// Bytes squeezed per operation (32 = the SHAKE128 security level's
    /// natural output; 64 for SHAKE256's).
    #[arg(long)]
    pub output_len: Option<usize>,
}

/// (name, security level, input bytes, SHAKE256?, default output bytes)
const POINTS: [(&str, &str, usize, bool, usize); 6] = [
    ("SHAKE128-64B", "L1", 64, false, 32),
    ("SHAKE128-1KB", "L1", 1024, false, 32),
    ("SHAKE128-16KB", "L1", 16384, false, 32),
    ("SHAKE256-64B", "L5", 64, true, 64),
    ("SHAKE256-1KB", "L5", 1024, true, 64),
    ("SHAKE256-16KB", "L5", 16384, true, 64),
];

/// One SHAKE operation: absorb `data`, squeeze `out.len()` bytes.
pub fn shake(shake256: bool, data: &[u8], out: &mut [u8]) {
    if shake256 {
        let mut h = Shake256::default();
        h.update(data);
        h.finalize_xof().read(out);
    } else {
        let mut h = Shake128::default();
        h.update(data);
        h.finalize_xof().read(out);
    }
}

pub fn run(args: &XofArgs) -> Result<()> {
    let stdout = std::io::stdout();
    for (name, level, data_len, shake256, default_out) in POINTS {
        let out_len = args.output_len.unwrap_or(default_out);
        let workers: Vec<_> = (0..args.threads)
            .map(|_| {
                let data: Vec<u8> = (0..data_len).map(|i| (i % 251) as u8).collect();
                let mut out = vec![0u8; out_len];
                move || -> Result<()> {
                    shake(shake256, &data, &mut out);
                    std::hint::black_box(&out);
                    Ok(())
                }
            })
            .collect();
        let (total_ops, latencies_ms, duration_s) = measure::run_point(
            args.duration_secs,
            args.warmup_secs,
            args.min_ops,
            args.max_secs,
            workers,
        )?;
        let (p50_ms, p99_ms) = measure::percentiles_ms(latencies_ms);
        let row = measure::ResultRow {
            access_path: "rust-sha3-direct",
            topology: "none",
            instances: 1,
            instance_id: 0,
            tenants: 1,
            tenant_index: 0,
            slot: 0,
            threads: args.threads,
            category: "xof",
            algorithm: name,
            security_level: level,
            op: "digest",
            ops_per_sec: total_ops as f64 / duration_s,
            p50_ms,
            p99_ms,
            duration_s,
            total_ops,
            engine_version: String::new(),
        };
        eprintln!(
            "[ok] measured {name} OUTSIDE PKCS#11 ({out_len}-byte output): {:.0} ops/sec over {:.2}s ({} ops)",
            row.ops_per_sec, row.duration_s, row.total_ops
        );
        serde_json::to_writer(&stdout, &row)?;
        println!();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::shake;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    /// FIPS 202 known answers for the empty message (NIST example values),
    /// so the probe provably computes SHAKE and not something cheaper.
    #[test]
    fn shake_matches_fips202_empty_message_vectors() {
        let mut out = [0u8; 32];
        shake(false, b"", &mut out);
        assert_eq!(out.to_vec(), hex("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"));
        let mut out = [0u8; 64];
        shake(true, b"", &mut out);
        assert_eq!(
            out.to_vec(),
            hex("46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be")
        );
    }
}
