//! `felica-auth-server` binary entry point.

use std::collections::HashSet;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use felica_auth_server::http::{router, AppState};
use felica_auth_server::keystore::KeyStore;
use felica_auth_server::session::SessionManager;

/// Remote FeliCa crypto oracle: holds the keys and drives FeliCa Standard mutual
/// authentication / secure messaging while a separate client owns the reader.
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

    /// Restrict encrypted-exchange command codes (decimal or 0x-hex). Repeatable,
    /// or comma-separated via the environment variable.
    #[arg(
        long = "allowed-cmd-code",
        env = "FELICA_ALLOWED_CMD_CODES",
        value_delimiter = ',',
        value_name = "CODE"
    )]
    allowed_cmd_codes: Vec<String>,

    /// Idle seconds after which a session is reaped.
    #[arg(long, env = "FELICA_SESSION_TTL", default_value_t = 300)]
    session_ttl: u64,

    /// Maximum number of concurrent live sessions.
    #[arg(long, env = "FELICA_MAX_SESSIONS", default_value_t = 1024)]
    max_sessions: usize,
}

fn parse_cmd_code(raw: &str) -> Result<u8, String> {
    let trimmed = raw.trim();
    let (radix, digits) = match trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        Some(hex) => (16, hex),
        None => (10, trimmed),
    };
    u8::from_str_radix(digits, radix)
        .map_err(|_| format!("invalid --allowed-cmd-code value '{raw}'"))
}

async fn run(args: Args) -> Result<(), String> {
    let allowed_cmd_codes: Option<HashSet<u8>> = if args.allowed_cmd_codes.is_empty() {
        None
    } else {
        Some(
            args.allowed_cmd_codes
                .iter()
                .map(|code| parse_cmd_code(code))
                .collect::<Result<HashSet<_>, _>>()?,
        )
    };

    let keystore = KeyStore::from_jsonl(&args.keys).map_err(|e| e.message)?;
    tracing::info!(
        systems = keystore.system_codes().len(),
        path = %args.keys,
        "loaded DES system keys",
    );

    let manager = SessionManager::new(
        Arc::new(keystore),
        allowed_cmd_codes.clone(),
        Duration::from_secs(args.session_ttl),
        args.max_sessions,
    );
    Arc::clone(&manager).spawn_reaper();

    if let Some(codes) = &allowed_cmd_codes {
        let mut sorted: Vec<u8> = codes.iter().copied().collect();
        sorted.sort_unstable();
        let formatted: Vec<String> = sorted.iter().map(|c| format!("0x{c:02X}")).collect();
        tracing::info!(
            codes = formatted.join(", "),
            "restricted encrypted-exchange command codes"
        );
    }

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
