#![forbid(unsafe_code)]
use clap::Parser;
use std::{net::SocketAddr, path::PathBuf};
use wholepact_engine::Engine;
use wholepact_service::{application, security::SecurityConfig};

#[derive(Parser)]
#[command(
    version,
    about = "Authenticated loopback Wholepact development service. No signing or settlement capabilities are enabled."
)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:4318")]
    bind: SocketAddr,
    #[arg(long, default_value = "wholepact-local.sqlite")]
    database: PathBuf,
    /// User-supplied local client grants. Does not create persistent credentials.
    #[arg(long, conflicts_with = "development_fixture")]
    security_config: Option<PathBuf>,
    /// Explicitly use a public, synthetic test credential. Only non-private test data.
    #[arg(long)]
    development_fixture: bool,
}
#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("wholepact-service: {error}");
        std::process::exit(1);
    }
}
async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    if !args.bind.ip().is_loopback() || args.bind.port() == 0 {
        return Err("Only a fixed loopback bind is supported".into());
    }
    let config = if args.development_fixture {
        eprintln!("DEVELOPMENT FIXTURE: public authentication credential; use synthetic non-private records only. No funds or signing.");
        SecurityConfig::development_fixture()
    } else {
        let path = args.security_config.ok_or("Provide --security-config for previously approved local grants, or --development-fixture for isolated synthetic testing")?;
        if std::fs::metadata(&path)?.len() > 65_536 {
            return Err("Security configuration exceeds 64 KiB".into());
        }
        serde_json::from_slice(&std::fs::read(path)?)?
    };
    let engine = Engine::open(&args.database)?;
    let app = application(engine, config, args.bind.port(), args.development_fixture)?;
    let listener = tokio::net::TcpListener::bind(args.bind).await?;
    eprintln!("Wholepact local service listening on http://{}; metadata only; chain observation inactive.", args.bind);
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
