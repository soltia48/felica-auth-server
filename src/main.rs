//! `felica-auth-server` binary entry point.

use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use felica_auth_server::http::{router, AppState};
use felica_auth_server::keystore::KeyStore;
use felica_auth_server::session::SessionManager;

/// Remote FeliCa authentication server: holds the long-term keys and performs
/// FeliCa Standard mutual authentication, handing the resulting session material
/// to a client that owns the reader and runs the encrypted commands itself.
#[derive(Debug, Parser)]
#[command(name = "felica-auth-server", version, about)]
struct Args {
    /// Bind address.
    #[arg(long, env = "FELICA_HOST", default_value = "127.0.0.1")]
    host: String,

    /// TCP port to listen on.
    #[arg(long, env = "FELICA_PORT", default_value_t = 8000)]
    port: u16,

    /// Logging verbosity (error, warn, info, debug, trace). Overridden by RUST_LOG.
    #[arg(long, env = "FELICA_LOG_LEVEL", default_value = "info")]
    log_level: String,

    /// Path to the keys JSONL file.
    #[arg(long, env = "FELICA_KEYS", default_value = "keys.jsonl")]
    keys: String,

    /// Only authenticate read-only services (with or without key), so the card
    /// rejects any Write in the resulting session.
    #[arg(long, env = "FELICA_READ_ONLY_NODES")]
    read_only_nodes: bool,

    /// Idle seconds after which an unfinished authentication is reaped.
    #[arg(long, env = "FELICA_SESSION_TTL", default_value_t = 300)]
    session_ttl: u64,

    /// Maximum number of concurrent live sessions.
    #[arg(long, env = "FELICA_MAX_SESSIONS", default_value_t = 1024)]
    max_sessions: usize,
}

async fn run(args: Args) -> Result<(), String> {
    let keystore = KeyStore::from_jsonl(&args.keys).map_err(|e| e.message)?;
    tracing::info!(
        systems = keystore.system_codes().len(),
        path = %args.keys,
        "loaded DES system keys",
    );

    if args.read_only_nodes {
        tracing::info!("restricted to authenticating read-only services");
    }

    let manager = SessionManager::new(
        Arc::new(keystore),
        args.read_only_nodes,
        Duration::from_secs(args.session_ttl),
        args.max_sessions,
    );
    Arc::clone(&manager).spawn_reaper();

    let state = AppState { manager };
    let app = router(state);

    let addr = format!("{}:{}", args.host, args.port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|e| format!("failed to bind {addr}: {e}"))?;
    tracing::info!(%addr, "felica-auth-server listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|e| format!("server error: {e}"))
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutdown signal received");
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();

    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| args.log_level.to_lowercase());
    let env_filter = EnvFilter::try_new(&filter).unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .init();

    match run(args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            tracing::error!("{message}");
            ExitCode::FAILURE
        }
    }
}
