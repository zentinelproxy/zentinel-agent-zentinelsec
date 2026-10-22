//! Zentinel ZentinelSec Agent CLI
//!
//! Command-line interface for the pure Rust ModSecurity-compatible WAF agent.
//! Uses gRPC transport with Agent Protocol v2 for communication with Zentinel proxy.

use anyhow::Result;
use clap::Parser;
use tracing::info;

use zentinel_agent_protocol::v2::GrpcAgentServerV2;
use zentinel_agent_zentinelsec::{ZentinelSecAgent, ZentinelSecConfig};

/// Command line arguments
#[derive(Parser, Debug)]
#[command(name = "zentinel-zentinelsec-agent")]
#[command(
    about = "Pure Rust ModSecurity-compatible WAF agent for Zentinel - loads the stock OWASP CRS without C dependencies"
)]
#[command(version = env!("CARGO_PKG_VERSION"))]
struct Args {
    /// gRPC server address (default: "0.0.0.0:50051")
    #[arg(long, default_value = "0.0.0.0:50051", env = "AGENT_GRPC_ADDRESS")]
    grpc_address: String,

    /// Paths to ModSecurity rule files (can be specified multiple times, supports glob patterns)
    #[arg(long = "rules", env = "ZENTINELSEC_RULES", value_delimiter = ',')]
    rules_paths: Vec<String>,

    /// Block mode (true) or detect-only mode (false)
    #[arg(long, default_value = "true", env = "ZENTINELSEC_BLOCK_MODE")]
    block_mode: bool,

    /// Paths to exclude from inspection (comma-separated)
    #[arg(long, env = "ZENTINELSEC_EXCLUDE_PATHS")]
    exclude_paths: Option<String>,

    /// Enable request body inspection
    #[arg(long, default_value = "true", env = "ZENTINELSEC_BODY_INSPECTION")]
    body_inspection: bool,

    /// Maximum body size to inspect in bytes (default 1MB)
    #[arg(long, default_value = "1048576", env = "ZENTINELSEC_MAX_BODY_SIZE")]
    max_body_size: usize,

    /// Enable response body inspection
    #[arg(long, default_value = "false", env = "ZENTINELSEC_RESPONSE_INSPECTION")]
    response_inspection: bool,

    /// Enable verbose logging
    #[arg(short, long, env = "ZENTINELSEC_VERBOSE")]
    verbose: bool,
}

impl Args {
    fn to_config(&self) -> ZentinelSecConfig {
        let exclude_paths = self
            .exclude_paths
            .as_ref()
            .map(|p| p.split(',').map(|s| s.trim().to_string()).collect())
            .unwrap_or_default();

        ZentinelSecConfig {
            rules_paths: self.rules_paths.clone(),
            block_mode: self.block_mode,
            exclude_paths,
            body_inspection_enabled: self.body_inspection,
            max_body_size: self.max_body_size,
            response_inspection_enabled: self.response_inspection,
        }
    }
}

/// Default tracing directives.
///
/// The agent logs from three places, each under its own target: this binary,
/// the library crate that holds the handler, and the rule engine
/// (`zentinel_modsec`: warnings about rules it cannot honour, body processor
/// failures at debug). A filter that misses one drops its output silently.
/// The engine is logged at `warn` unless `--verbose`.
fn default_log_filter(verbose: bool) -> String {
    let level = if verbose { "debug" } else { "info" };
    let engine = if verbose { "debug" } else { "warn" };
    format!(
        "{}={level},zentinel_agent_zentinelsec={level},zentinel_modsec={engine},zentinel_agent_protocol=info",
        env!("CARGO_CRATE_NAME"),
    )
}

/// The filter to install, and a message if `RUST_LOG` could not be used.
///
/// An unset or blank `RUST_LOG` (`Environment=RUST_LOG=` in a unit file) means
/// the defaults; so does an invalid one, after saying so.
fn build_env_filter(
    rust_log: Option<&str>,
    verbose: bool,
) -> (tracing_subscriber::EnvFilter, Option<String>) {
    use tracing_subscriber::EnvFilter;
    let defaults = || EnvFilter::new(default_log_filter(verbose));
    match rust_log.map(str::trim).filter(|v| !v.is_empty()) {
        None => (defaults(), None),
        Some(value) => match EnvFilter::try_new(value) {
            Ok(filter) => (filter, None),
            Err(e) => (
                defaults(),
                Some(format!(
                    "ignoring invalid RUST_LOG ({e}); using the default log filter"
                )),
            ),
        },
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let args = Args::parse();

    // Initialize tracing. RUST_LOG, when set, replaces the default directives.
    let (env_filter, problem) =
        build_env_filter(std::env::var("RUST_LOG").ok().as_deref(), args.verbose);
    if let Some(problem) = problem {
        // Logging is not set up yet, so this goes straight to stderr.
        eprintln!("{problem}");
    }
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .json()
        .init();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        protocol = "v2",
        "Starting Zentinel ZentinelSec Agent (pure Rust ModSecurity)"
    );

    // Build configuration
    let config = args.to_config();

    info!(
        rules_count = config.rules_paths.len(),
        block_mode = config.block_mode,
        body_inspection = config.body_inspection_enabled,
        response_inspection = config.response_inspection_enabled,
        max_body_size = config.max_body_size,
        "Configuration loaded"
    );

    if config.rules_paths.is_empty() {
        tracing::warn!("No rules paths configured - ZentinelSec will not block any requests");
        tracing::warn!(
            "Use --rules to specify rule files, e.g.: --rules /etc/modsecurity/crs/rules/*.conf"
        );
    }

    // Create agent
    let agent = ZentinelSecAgent::new(config)?;

    // Start agent server using gRPC transport (v2 protocol)
    let addr: std::net::SocketAddr = args
        .grpc_address
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid gRPC address '{}': {}", args.grpc_address, e))?;

    info!(
        address = %addr,
        transport = "grpc",
        protocol = "v2",
        "Starting gRPC agent server"
    );

    let server = GrpcAgentServerV2::new("zentinel-zentinelsec", Box::new(agent));
    server
        .run(addr)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::EnvFilter;

    #[test]
    fn default_filter_names_the_library_and_the_engine() {
        let filter = default_log_filter(false);
        assert!(
            filter.contains(&format!("{}=info", env!("CARGO_CRATE_NAME"))),
            "{filter}"
        );
        assert!(
            filter.contains("zentinel_agent_zentinelsec=info"),
            "{filter}"
        );
        assert!(filter.contains("zentinel_modsec=warn"), "{filter}");
        assert!(EnvFilter::try_new(&filter).is_ok());
    }

    #[test]
    fn blank_rust_log_means_the_defaults() {
        for value in [None, Some(""), Some("  ")] {
            let (filter, problem) = build_env_filter(value, false);
            assert!(problem.is_none());
            assert_eq!(
                filter.to_string(),
                EnvFilter::new(default_log_filter(false)).to_string()
            );
        }
    }

    #[test]
    fn rust_log_replaces_the_defaults() {
        let (filter, problem) = build_env_filter(Some("zentinel_modsec=error"), true);
        assert!(problem.is_none());
        assert_eq!(filter.to_string(), "zentinel_modsec=error");
    }

    #[test]
    fn invalid_rust_log_falls_back_and_says_so() {
        let (filter, problem) = build_env_filter(Some("info,foo=bogus"), false);
        assert!(problem.unwrap().contains("invalid RUST_LOG"));
        assert_eq!(
            filter.to_string(),
            EnvFilter::new(default_log_filter(false)).to_string()
        );
    }

    #[test]
    fn verbose_raises_the_library_and_the_engine_to_debug() {
        let filter = default_log_filter(true);
        assert!(
            filter.contains("zentinel_agent_zentinelsec=debug"),
            "{filter}"
        );
        assert!(filter.contains("zentinel_modsec=debug"), "{filter}");
        assert!(EnvFilter::try_new(&filter).is_ok());
    }
}
