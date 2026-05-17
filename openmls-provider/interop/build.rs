fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Use the vendored protoc binary so the build doesn't depend on a
    // system-installed protobuf compiler.
    std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?);
    tonic_build::configure()
        .build_server(true)
        .build_client(true) // also needed by `tests/grpc_smoke.rs`
        .compile_protos(&["proto/mls_client.proto"], &["proto"])?;
    Ok(())
}
