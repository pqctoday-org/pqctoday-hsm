// Feature switches that depend on the target (Cargo cannot make a default feature target-specific).
//
//   pqc_replication   K2-K4 key hierarchy, attestation and replication: the `educational-replication` feature, or
//                     the default `fhe-custody` feature on a native target.
//   pqc_ckks_custody  streamed CKKS custody: the `educational-ckks` feature, or `fhe-custody` on a native target.
//
// `fhe-custody` is a default feature (plan D02387, owner decisions F1/F7/F10), so native builds - the boards' engine,
// the KMIP server, native tools - get CKKS custody by default, while the wasm32 bundles (the Hub playground) stay as
// they were. TFHE custody (`educational-fhe`, TFHE-rs) is NOT part of it: it stays opt-in and non-commercial (F10).
fn main() {
    println!("cargo::rustc-check-cfg=cfg(pqc_replication)");
    println!("cargo::rustc-check-cfg=cfg(pqc_ckks_custody)");
    let feature = |f: &str| std::env::var(format!("CARGO_FEATURE_{}", f.to_uppercase().replace('-', "_"))).is_ok();
    let wasm = std::env::var("CARGO_CFG_TARGET_ARCH").map(|a| a == "wasm32").unwrap_or(false);
    let custody = feature("fhe-custody") && !wasm;
    if feature("educational-replication") || custody {
        println!("cargo::rustc-cfg=pqc_replication");
    }
    if feature("educational-ckks") || custody {
        println!("cargo::rustc-cfg=pqc_ckks_custody");
    }
    println!("cargo::rerun-if-changed=build.rs");
}
