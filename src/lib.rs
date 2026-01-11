//! Sentinel SentinelSec Agent Library
//!
//! A pure Rust ModSecurity-compatible WAF agent for Sentinel proxy.
//! Provides full OWASP Core Rule Set (CRS) support without any C dependencies.
//!
//! # Example
//!
//! ```ignore
//! use sentinel_agent_sentinelsec::{SentinelSecAgent, SentinelSecConfig};
//! use sentinel_agent_protocol::AgentServer;
//!
//! let config = SentinelSecConfig {
//!     rules_paths: vec!["/etc/modsecurity/crs/rules/*.conf".to_string()],
//!     ..Default::default()
//! };
//! let agent = SentinelSecAgent::new(config)?;
//! let server = AgentServer::new("sentinelsec", "/tmp/sentinelsec.sock", Box::new(agent));
//! server.run().await?;
//! ```

use anyhow::Result;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use sentinel_agent_protocol::{
    AgentHandler, AgentResponse, AuditMetadata, ConfigureEvent, HeaderOp, RequestBodyChunkEvent,
    RequestHeadersEvent, ResponseBodyChunkEvent, ResponseHeadersEvent,
};

use sentinel_modsec::ModSecurity;

/// SentinelSec configuration
#[derive(Debug, Clone)]
pub struct SentinelSecConfig {
    /// Paths to ModSecurity rule files (glob patterns supported)
    pub rules_paths: Vec<String>,
    /// Block mode (true) or detect-only mode (false)
    pub block_mode: bool,
    /// Paths to exclude from inspection
    pub exclude_paths: Vec<String>,
    /// Enable request body inspection
    pub body_inspection_enabled: bool,
    /// Maximum body size to inspect in bytes
    pub max_body_size: usize,
    /// Enable response body inspection
    pub response_inspection_enabled: bool,
}

impl Default for SentinelSecConfig {
    fn default() -> Self {
        Self {
            rules_paths: vec![],
            block_mode: true,
            exclude_paths: vec![],
            body_inspection_enabled: true,
            max_body_size: 1048576, // 1MB
            response_inspection_enabled: false,
        }
    }
}

/// JSON-serializable configuration for SentinelSec agent
///
/// Used for parsing configuration from the proxy's agent config.
/// Field names use kebab-case to match YAML/JSON config conventions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SentinelSecConfigJson {
    /// Paths to ModSecurity rule files (glob patterns supported)
    #[serde(default)]
    pub rules_paths: Vec<String>,
    /// Block mode (true) or detect-only mode (false)
    #[serde(default = "default_block_mode")]
    pub block_mode: bool,
    /// Paths to exclude from inspection
    #[serde(default)]
    pub exclude_paths: Vec<String>,
    /// Enable request body inspection
    #[serde(default = "default_body_inspection")]
    pub body_inspection_enabled: bool,
    /// Maximum body size to inspect in bytes
    #[serde(default = "default_max_body_size")]
    pub max_body_size: usize,
    /// Enable response body inspection
    #[serde(default)]
    pub response_inspection_enabled: bool,
}

fn default_block_mode() -> bool {
    true
}

fn default_body_inspection() -> bool {
    true
}

fn default_max_body_size() -> usize {
    1048576 // 1MB
}

impl From<SentinelSecConfigJson> for SentinelSecConfig {
    fn from(json: SentinelSecConfigJson) -> Self {
        Self {
            rules_paths: json.rules_paths,
            block_mode: json.block_mode,
            exclude_paths: json.exclude_paths,
            body_inspection_enabled: json.body_inspection_enabled,
            max_body_size: json.max_body_size,
            response_inspection_enabled: json.response_inspection_enabled,
        }
    }
}

/// Detection result from SentinelSec
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    /// Rule ID that triggered the detection
    pub rule_id: String,
    /// Detection message
    pub message: String,
    /// Severity level
    pub severity: Option<String>,
}

/// SentinelSec engine wrapper
pub struct SentinelSecEngine {
    modsec: ModSecurity,
    /// Agent configuration
    pub config: SentinelSecConfig,
}

impl SentinelSecEngine {
    /// Create a new SentinelSec engine with the given configuration
    pub fn new(config: SentinelSecConfig) -> Result<Self> {
        // Build rules string from all rule files
        let mut rules_content = String::new();

        // Always enable the rule engine
        rules_content.push_str("SecRuleEngine On\n");

        // Load rules from configured paths
        let mut loaded_count = 0;
        for path_pattern in &config.rules_paths {
            // Handle glob patterns
            let paths = glob::glob(path_pattern)
                .map_err(|e| anyhow::anyhow!("Invalid glob pattern '{}': {}", path_pattern, e))?;

            for entry in paths {
                match entry {
                    Ok(path) => {
                        if path.is_file() {
                            let content = fs::read_to_string(&path).map_err(|e| {
                                anyhow::anyhow!("Failed to read rule file {:?}: {}", path, e)
                            })?;
                            rules_content.push_str(&content);
                            rules_content.push('\n');
                            loaded_count += 1;
                            debug!(path = ?path, "Loaded rule file");
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "Error reading glob entry");
                    }
                }
            }
        }

        // Create the ModSecurity engine
        let modsec = if rules_content.trim().is_empty() || loaded_count == 0 {
            // No rules loaded, create with just SecRuleEngine On
            ModSecurity::from_string("SecRuleEngine On")
                .map_err(|e| anyhow::anyhow!("Failed to initialize SentinelSec engine: {}", e))?
        } else {
            ModSecurity::from_string(&rules_content)
                .map_err(|e| anyhow::anyhow!("Failed to parse rules: {}", e))?
        };

        info!(rules_files = loaded_count, rule_count = modsec.rule_count(), "SentinelSec engine initialized");

        Ok(Self { modsec, config })
    }

    /// Check if path should be excluded
    pub fn is_excluded(&self, path: &str) -> bool {
        self.config
            .exclude_paths
            .iter()
            .any(|p| path.starts_with(p))
    }
}

/// Body accumulator for tracking in-progress bodies
#[derive(Debug, Default)]
struct BodyAccumulator {
    data: Vec<u8>,
}

/// Pending transaction for body accumulation
struct PendingTransaction {
    body: BodyAccumulator,
    method: String,
    uri: String,
    headers: HashMap<String, Vec<String>>,
    #[allow(dead_code)]
    client_ip: String,
}

/// SentinelSec agent
pub struct SentinelSecAgent {
    engine: Arc<RwLock<SentinelSecEngine>>,
    pending_requests: Arc<RwLock<HashMap<String, PendingTransaction>>>,
}

impl SentinelSecAgent {
    /// Create a new SentinelSec agent with the given configuration
    pub fn new(config: SentinelSecConfig) -> Result<Self> {
        let engine = SentinelSecEngine::new(config)?;
        Ok(Self {
            engine: Arc::new(RwLock::new(engine)),
            pending_requests: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Reconfigure the agent with new settings
    ///
    /// This rebuilds the SentinelSec engine with the new configuration.
    /// In-flight requests using the old engine will complete normally.
    pub async fn reconfigure(&self, config: SentinelSecConfig) -> Result<()> {
        info!("Reconfiguring SentinelSec engine");
        let new_engine = SentinelSecEngine::new(config)?;
        let mut engine = self.engine.write().await;
        *engine = new_engine;
        // Clear pending requests since rules may have changed
        let mut pending = self.pending_requests.write().await;
        pending.clear();
        info!("SentinelSec engine reconfigured successfully");
        Ok(())
    }

    /// Process a complete request through SentinelSec
    async fn process_request(
        &self,
        correlation_id: &str,
        method: &str,
        uri: &str,
        headers: &HashMap<String, Vec<String>>,
        body: Option<&[u8]>,
    ) -> Result<Option<(u16, String, Vec<String>)>> {
        let engine = self.engine.read().await;

        // Create a new transaction
        let mut tx = engine.modsec.new_transaction();

        // Process URI
        tx.process_uri(uri, method, "HTTP/1.1")
            .map_err(|e| anyhow::anyhow!("process_uri failed: {}", e))?;

        // Add headers
        for (name, values) in headers {
            for value in values {
                tx.add_request_header(name, value)
                    .map_err(|e| anyhow::anyhow!("add_request_header failed: {}", e))?;
            }
        }

        // Process request headers (phase 1)
        tx.process_request_headers()
            .map_err(|e| anyhow::anyhow!("process_request_headers failed: {}", e))?;

        // Check for intervention after headers
        if let Some(intervention) = tx.intervention() {
            let status = intervention.status;
            if status != 0 && status != 200 {
                debug!(
                    correlation_id = correlation_id,
                    status = status,
                    "SentinelSec intervention (headers)"
                );
                let rule_ids = tx.matched_rules().iter().map(|s| s.to_string()).collect();
                return Ok(Some((status, "Blocked by SentinelSec".to_string(), rule_ids)));
            }
        }

        // Process body if provided (phase 2)
        if let Some(body_data) = body {
            if !body_data.is_empty() {
                tx.append_request_body(body_data)
                    .map_err(|e| anyhow::anyhow!("append_request_body failed: {}", e))?;
                tx.process_request_body()
                    .map_err(|e| anyhow::anyhow!("process_request_body failed: {}", e))?;

                // Check for intervention after body
                if let Some(intervention) = tx.intervention() {
                    let status = intervention.status;
                    if status != 0 && status != 200 {
                        debug!(
                            correlation_id = correlation_id,
                            status = status,
                            "SentinelSec intervention (body)"
                        );
                        let rule_ids = tx.matched_rules().iter().map(|s| s.to_string()).collect();
                        return Ok(Some((status, "Blocked by SentinelSec".to_string(), rule_ids)));
                    }
                }
            }
        }

        Ok(None)
    }
}

#[async_trait::async_trait]
impl AgentHandler for SentinelSecAgent {
    async fn on_configure(&self, event: ConfigureEvent) -> AgentResponse {
        debug!(agent_id = %event.agent_id, "Received configure event");

        // Parse the JSON config into SentinelSecConfigJson
        let config_json: SentinelSecConfigJson = match serde_json::from_value(event.config) {
            Ok(config) => config,
            Err(e) => {
                warn!(error = %e, "Failed to parse SentinelSec configuration");
                // Return allow but log the error - agent can still work with existing config
                return AgentResponse::default_allow();
            }
        };

        // Convert to internal config and reconfigure the engine
        let config: SentinelSecConfig = config_json.into();
        if let Err(e) = self.reconfigure(config).await {
            warn!(error = %e, "Failed to reconfigure SentinelSec engine");
            // Return allow but log the error
            return AgentResponse::default_allow();
        }

        info!(agent_id = %event.agent_id, "SentinelSec agent configured successfully");
        AgentResponse::default_allow()
    }

    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        let path = &event.uri;
        let correlation_id = &event.metadata.correlation_id;

        // Check exclusions
        {
            let engine = self.engine.read().await;
            if engine.is_excluded(path) {
                debug!(path = path, "Path excluded from SentinelSec");
                return AgentResponse::default_allow();
            }
        }

        // Always process headers immediately (phase 1)
        // This detects attacks in URI, query string, and headers
        match self
            .process_request(
                correlation_id,
                &event.method,
                &event.uri,
                &event.headers,
                None,
            )
            .await
        {
            Ok(Some((status, message, rule_ids))) => {
                let engine = self.engine.read().await;
                if engine.config.block_mode {
                    info!(
                        correlation_id = correlation_id,
                        status = status,
                        rules = ?rule_ids,
                        "Request blocked by SentinelSec"
                    );
                    let rule_id = rule_ids.first().cloned().unwrap_or_default();
                    AgentResponse::block(status, Some("Forbidden".to_string()))
                        .add_response_header(HeaderOp::Set {
                            name: "X-WAF-Blocked".to_string(),
                            value: "true".to_string(),
                        })
                        .add_response_header(HeaderOp::Set {
                            name: "X-WAF-Rule".to_string(),
                            value: rule_id,
                        })
                        .add_response_header(HeaderOp::Set {
                            name: "X-WAF-Message".to_string(),
                            value: message.clone(),
                        })
                        .with_audit(AuditMetadata {
                            tags: vec!["sentinelsec".to_string(), "blocked".to_string()],
                            rule_ids,
                            reason_codes: vec![message],
                            ..Default::default()
                        })
                } else {
                    info!(
                        correlation_id = correlation_id,
                        rules = ?rule_ids,
                        "SentinelSec detection (detect-only mode)"
                    );
                    AgentResponse::default_allow()
                        .add_request_header(HeaderOp::Set {
                            name: "X-WAF-Detected".to_string(),
                            value: message.clone(),
                        })
                        .with_audit(AuditMetadata {
                            tags: vec!["sentinelsec".to_string(), "detected".to_string()],
                            rule_ids,
                            reason_codes: vec![message],
                            ..Default::default()
                        })
                }
            }
            Ok(None) => {
                // Headers passed - if body inspection enabled, store for body processing
                let engine = self.engine.read().await;
                if engine.config.body_inspection_enabled {
                    let mut pending = self.pending_requests.write().await;
                    pending.insert(
                        correlation_id.clone(),
                        PendingTransaction {
                            body: BodyAccumulator::default(),
                            method: event.method.clone(),
                            uri: event.uri.clone(),
                            headers: event.headers.clone(),
                            client_ip: event.metadata.client_ip.clone(),
                        },
                    );
                }
                AgentResponse::default_allow()
            }
            Err(e) => {
                warn!(error = %e, "SentinelSec processing error");
                AgentResponse::default_allow()
            }
        }
    }

    async fn on_response_headers(&self, _event: ResponseHeadersEvent) -> AgentResponse {
        AgentResponse::default_allow()
    }

    async fn on_request_body_chunk(&self, event: RequestBodyChunkEvent) -> AgentResponse {
        let correlation_id = &event.correlation_id;

        // Check if we have a pending request
        let pending_exists = {
            let pending = self.pending_requests.read().await;
            pending.contains_key(correlation_id)
        };

        if !pending_exists {
            // No pending request - body inspection might be disabled
            return AgentResponse::default_allow();
        }

        // Decode base64 chunk
        let chunk = match base64::engine::general_purpose::STANDARD.decode(&event.data) {
            Ok(data) => data,
            Err(e) => {
                warn!(error = %e, "Failed to decode body chunk");
                return AgentResponse::default_allow();
            }
        };

        // Accumulate chunk
        let should_process = {
            let mut pending = self.pending_requests.write().await;
            if let Some(tx) = pending.get_mut(correlation_id) {
                let engine = self.engine.read().await;

                // Check size limit
                if tx.body.data.len() + chunk.len() > engine.config.max_body_size {
                    debug!(
                        correlation_id = correlation_id,
                        "Body exceeds max size, skipping inspection"
                    );
                    pending.remove(correlation_id);
                    return AgentResponse::default_allow();
                }

                tx.body.data.extend(chunk);
                event.is_last
            } else {
                false
            }
        };

        // If this is the last chunk, process the complete request
        if should_process {
            let pending_tx = {
                let mut pending = self.pending_requests.write().await;
                pending.remove(correlation_id)
            };

            if let Some(tx) = pending_tx {
                match self
                    .process_request(
                        correlation_id,
                        &tx.method,
                        &tx.uri,
                        &tx.headers,
                        Some(&tx.body.data),
                    )
                    .await
                {
                    Ok(Some((status, message, rule_ids))) => {
                        let engine = self.engine.read().await;
                        if engine.config.block_mode {
                            info!(
                                correlation_id = correlation_id,
                                status = status,
                                rules = ?rule_ids,
                                "Request blocked by SentinelSec (body inspection)"
                            );
                            let rule_id = rule_ids.first().cloned().unwrap_or_default();
                            return AgentResponse::block(status, Some("Forbidden".to_string()))
                                .add_response_header(HeaderOp::Set {
                                    name: "X-WAF-Blocked".to_string(),
                                    value: "true".to_string(),
                                })
                                .add_response_header(HeaderOp::Set {
                                    name: "X-WAF-Rule".to_string(),
                                    value: rule_id,
                                })
                                .add_response_header(HeaderOp::Set {
                                    name: "X-WAF-Message".to_string(),
                                    value: message.clone(),
                                })
                                .with_audit(AuditMetadata {
                                    tags: vec![
                                        "sentinelsec".to_string(),
                                        "blocked".to_string(),
                                        "body".to_string(),
                                    ],
                                    rule_ids,
                                    reason_codes: vec![message],
                                    ..Default::default()
                                });
                        } else {
                            info!(
                                correlation_id = correlation_id,
                                rules = ?rule_ids,
                                "SentinelSec detection in body (detect-only mode)"
                            );
                            return AgentResponse::default_allow()
                                .add_request_header(HeaderOp::Set {
                                    name: "X-WAF-Detected".to_string(),
                                    value: message.clone(),
                                })
                                .with_audit(AuditMetadata {
                                    tags: vec![
                                        "sentinelsec".to_string(),
                                        "detected".to_string(),
                                        "body".to_string(),
                                    ],
                                    rule_ids,
                                    reason_codes: vec![message],
                                    ..Default::default()
                                });
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        warn!(error = %e, "SentinelSec body processing error");
                    }
                }
            }
        }

        AgentResponse::default_allow()
    }

    async fn on_response_body_chunk(&self, event: ResponseBodyChunkEvent) -> AgentResponse {
        // Response body inspection not yet implemented
        let _ = event;
        AgentResponse::default_allow()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SentinelSecConfig::default();
        assert!(config.rules_paths.is_empty());
        assert!(config.block_mode);
        assert!(config.body_inspection_enabled);
        assert!(!config.response_inspection_enabled);
        assert_eq!(config.max_body_size, 1048576);
    }

    #[test]
    fn test_engine_initialization() {
        let config = SentinelSecConfig::default();
        let engine = SentinelSecEngine::new(config);
        assert!(engine.is_ok());
    }

    #[test]
    fn test_engine_with_inline_rule() {
        // Test with a simple inline rule
        let config = SentinelSecConfig::default();
        let engine = SentinelSecEngine::new(config).unwrap();

        // Verify engine is working
        let mut tx = engine.modsec.new_transaction();
        tx.process_uri("/test", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();

        // Should not block clean requests
        assert!(tx.intervention().is_none());
    }

    #[test]
    fn test_path_exclusion() {
        let config = SentinelSecConfig {
            exclude_paths: vec!["/health".to_string(), "/metrics".to_string()],
            ..Default::default()
        };
        let engine = SentinelSecEngine::new(config).unwrap();

        assert!(engine.is_excluded("/health"));
        assert!(engine.is_excluded("/health/live"));
        assert!(engine.is_excluded("/metrics"));
        assert!(!engine.is_excluded("/api/users"));
    }
}
