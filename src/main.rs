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
    about = "Pure Rust ModSecurity-compatible WAF agent for Zentinel - full OWASP CRS support without C dependencies"
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

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let args = Args::parse();

    // Initialize tracing
    let log_level = if args.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(format!(
            "{}={},zentinel_agent_protocol=info",
            env!("CARGO_CRATE_NAME"),
            log_level
        ))
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
