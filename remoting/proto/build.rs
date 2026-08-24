fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Vendored protoc — no system protobuf compiler dependency. Same
    // pattern as ../../openmls-provider/interop/build.rs.
    // SAFETY: build script, single-threaded, before any other code reads env.
    unsafe {
        std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?);
    }
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["proto/pkcs11_remote.proto"], &["proto"])?;
    Ok(())
}
