# Vendored aws-lc-sys 0.44.0 (Cortex-A5x Montgomery dispatch)

- **Origin:** crates.io `aws-lc-sys` 0.44.0, `.crate` sha256
  `f09fae7be8bb3174e05c6afdb34199e6dc0c7c04ba9fa237b1967adfbde27483` (the checksum
  every lockfile in this repo recorded for it before vendoring).
- **Local change:** exactly `aws-lc-sys-0.44.0-cortex-a5x.patch`, applied with
  `patch -p1` inside `aws-lc-sys-0.44.0/aws-lc/`. It touches four files:
  `crypto/fipsmodule/bn/montgomery.c`, `crypto/fipsmodule/cpucap/cpu_aarch64_linux.c`,
  `crypto/fipsmodule/cpucap/internal.h`, `include/openssl/arm_arch.h`.
- **What it does:** AWS-LC sends every ARM core that is not "wide multiplier"
  capable to s2n-bignum's Karatsuba+NEON Montgomery kernels, which are scheduled for
  Graviton2 and lose on 2-wide in-order cores. The patch detects Cortex-A53/A55 by
  MIDR and keeps them on the scalar `armv8-mont` path. Every other core is unchanged
  (the new bit is only set for those two part numbers).
- **Measured (2026-09-27, same-board A-B-A-B, stock vs patched, both engine builds
  from one commit):** RSA-OAEP decrypt 2048/3072/4096 on a Cortex-A55 (FRDM-IMX95)
  1.27× / 1.60× / 1.21–1.26×, on a Cortex-A53 (KV260) 1.28–1.39× / 1.64–1.69× /
  1.22–1.25×; controls flat. RSA ACVP and engine RSA tests (50) pass on both cores
  with the patched build, where the new path is actually taken.
- **Consumers:** `rust/Cargo.toml`, `kmip/Cargo.toml` and `remoting/Cargo.toml`
  `[patch.crates-io]` (so the KMIP server and the remoting services get it too).
  `wasm/` builds for wasm32 and is untouched.
- **Verify:** `scripts/verify-vendored-aws-lc-sys.sh` re-derives this tree from the
  crates.io package plus the patch and diffs it.
- **Exit plan:** upstream the patch to aws/aws-lc (draft in the pqctoday-cacp docs);
  when a release carries it, delete this directory and the three patch entries.
