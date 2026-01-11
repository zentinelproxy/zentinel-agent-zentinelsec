//! Sentinel SentinelSec Agent CLI
//!
//! Command-line interface for the pure Rust ModSecurity-compatible WAF agent.

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use tracing::info;

use sentinel_agent_sentinelsec::{SentinelSecAgent, SentinelSecConfig};
use sentinel_agent_protocol::AgentServer;

/// Command line arguments
#[derive(Parser, Debug)]
#[command(name = "sentinel-sentinelsec-agent")]
#[command(about = "Pure Rust ModSecurity-compatible WAF agent for Sentinel - full OWASP CRS support without C dependencies")]
struct Args {
    /// Path to Unix socket
    #[arg(
        long,
        default_value = "/tmp/sentinel-sentinelsec.sock",
        env = "AGENT_SOCKET"
    )]
    socket: PathBuf,

    /// Paths to ModSecurity rule files (can be specified multiple times, supports glob patterns)
    #[arg(long = "rules", env = "SENTINELSEC_RULES", value_delimiter = ',')]
    rules_paths: Vec<String>,

    /// Block mode (true) or detect-only mode (false)
    #[arg(long, default_value = "true", env = "SENTINELSEC_BLOCK_MODE")]
    block_mode: bool,

    /// Paths to exclude from inspection (comma-separated)
    #[arg(long, env = "SENTINELSEC_EXCLUDE_PATHS")]
    exclude_paths: Option<String>,

    /// Enable request body inspection
    #[arg(long, default_value = "true", env = "SENTINELSEC_BODY_INSPECTION")]
    body_inspection: bool,

    /// Maximum body size to inspect in bytes (default 1MB)
    #[arg(long, default_value = "1048576", env = "SENTINELSEC_MAX_BODY_SIZE")]
    max_body_size: usize,

    /// Enable response body inspection
    #[arg(long, default_value = "false", env = "SENTINELSEC_RESPONSE_INSPECTION")]
    response_inspection: bool,

    /// Enable verbose logging
    #[arg(short, long, env = "SENTINELSEC_VERBOSE")]
    verbose: bool,
}

impl Args {
    fn to_config(&self) -> SentinelSecConfig {
        let exclude_paths = self
            .exclude_paths
            .as_ref()
            .map(|p| p.split(',').map(|s| s.trim().to_string()).collect())
            .unwrap_or_default();

        SentinelSecConfig {
            rules_paths: self.rules_paths.clone(),
            block_mode: self.block_mode,
            exclude_paths,
            body_inspection_enabled: self.body_inspection,
            max_body_size: self.max_body_size,
            response_inspection_enabled: self.response_inspection,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let args = Args::parse();

    // Initialize tracing
    let log_level = if args.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(format!(
            "{}={},sentinel_agent_protocol=info",
            env!("CARGO_CRATE_NAME"),
            log_level
        ))
        .json()
        .init();

    info!("Starting Sentinel SentinelSec Agent (pure Rust ModSecurity)");

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
        tracing::warn!("No rules paths configured - SentinelSec will not block any requests");
        tracing::warn!(
            "Use --rules to specify rule files, e.g.: --rules /etc/modsecurity/crs/rules/*.conf"
        );
    }

    // Create agent
    let agent = SentinelSecAgent::new(config)?;

    // Start agent server
    info!(socket = ?args.socket, "Starting agent server");
    let server = AgentServer::new("sentinel-sentinelsec-agent", args.socket, Box::new(agent));
    server.run().await.map_err(|e| anyhow::anyhow!("{}", e))?;

    Ok(())
}
