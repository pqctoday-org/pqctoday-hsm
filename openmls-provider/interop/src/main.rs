//! Runnable gRPC server entrypoint — see [`pqctoday_mls_interop`] for the
//! actual service implementation.

use clap::Parser;
use pqctoday_mls_interop::mls_client::mls_client_server::MlsClientServer;
use pqctoday_mls_interop::PqcTodayInteropClient;
use tonic::transport::Server;
use tonic_health::server::health_reporter;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(version, about = "MLS interop gRPC client backed by openmls_pqctoday_crypto")]
struct Args {
    /// Bind port (0.0.0.0:<port>). The IETF test-runner defaults to 50051+.
    #[arg(short, long, default_value_t = 50053)]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let args = Args::parse();
    let addr = format!("0.0.0.0:{}", args.port).parse()?;
    let service = PqcTodayInteropClient::new()?;

    let (mut health_reporter, health_service) = health_reporter();
    health_reporter
        .set_serving::<MlsClientServer<PqcTodayInteropClient>>()
        .await;

    tracing::info!(
        "pqctoday-mls gRPC interop client listening on {} \
         (21 RPCs implemented — full parity with openmls/interop_client; 13 RPCs stubbed \
         to match openmls's own `todo!()`/`Status::unimplemented`)",
        addr
    );

    Server::builder()
        .add_service(health_service)
        .add_service(MlsClientServer::new(service))
        .serve(addr)
        .await?;
    Ok(())
}
