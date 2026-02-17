//! Zentinel ZentinelSec Agent Library
//!
//! A pure Rust ModSecurity-compatible WAF agent for Zentinel proxy.
//! Provides full OWASP Core Rule Set (CRS) support without any C dependencies.
//!
//! # Example
//!
//! ```ignore
//! use zentinel_agent_zentinelsec::{ZentinelSecAgent, ZentinelSecConfig};
//! use zentinel_agent_protocol::v2::GrpcAgentServerV2;
//!
//! let config = ZentinelSecConfig {
//!     rules_paths: vec!["/etc/modsecurity/crs/rules/*.conf".to_string()],
//!     ..Default::default()
//! };
//! let agent = ZentinelSecAgent::new(config)?;
//! let server = GrpcAgentServerV2::new("zentinelsec", Box::new(agent));
//! server.run("0.0.0.0:50051".parse().unwrap()).await?;
//! ```

use anyhow::Result;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use zentinel_agent_protocol::{
    AgentResponse, AuditMetadata, EventType, HeaderOp, RequestBodyChunkEvent,
    RequestHeadersEvent, ResponseBodyChunkEvent, ResponseHeadersEvent,
};
use zentinel_agent_protocol::v2::{
    AgentCapabilities, AgentFeatures, AgentHandlerV2, AgentLimits, DrainReason,
    HealthStatus, MetricsReport, ShutdownReason,
};

use zentinel_modsec::ModSecurity;

/// ZentinelSec configuration
#[derive(Debug, Clone)]
pub struct ZentinelSecConfig {
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

impl Default for ZentinelSecConfig {
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

/// JSON-serializable configuration for ZentinelSec agent
///
/// Used for parsing configuration from the proxy's agent config.
/// Field names use kebab-case to match YAML/JSON config conventions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ZentinelSecConfigJson {
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

impl From<ZentinelSecConfigJson> for ZentinelSecConfig {
    fn from(json: ZentinelSecConfigJson) -> Self {
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

/// Detection result from ZentinelSec
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    /// Rule ID that triggered the detection
    pub rule_id: String,
    /// Detection message
    pub message: String,
    /// Severity level
    pub severity: Option<String>,
}

/// ZentinelSec engine wrapper
pub struct ZentinelSecEngine {
    modsec: ModSecurity,
    /// Agent configuration
    pub config: ZentinelSecConfig,
}

impl ZentinelSecEngine {
    /// Create a new ZentinelSec engine with the given configuration
    pub fn new(config: ZentinelSecConfig) -> Result<Self> {
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
                .map_err(|e| anyhow::anyhow!("Failed to initialize ZentinelSec engine: {}", e))?
        } else {
            ModSecurity::from_string(&rules_content)
                .map_err(|e| anyhow::anyhow!("Failed to parse rules: {}", e))?
        };

        info!(rules_files = loaded_count, rule_count = modsec.rule_count(), "ZentinelSec engine initialized");

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

/// ZentinelSec agent
pub struct ZentinelSecAgent {
    engine: Arc<RwLock<ZentinelSecEngine>>,
    pending_requests: Arc<RwLock<HashMap<String, PendingTransaction>>>,
    /// Metrics tracking
    requests_total: AtomicU64,
    requests_blocked: AtomicU64,
    requests_allowed: AtomicU64,
    /// Draining state
    draining: AtomicU64, // 0 = not draining, >0 = drain end timestamp ms
}

impl ZentinelSecAgent {
    /// Create a new ZentinelSec agent with the given configuration
    pub fn new(config: ZentinelSecConfig) -> Result<Self> {
        let engine = ZentinelSecEngine::new(config)?;
        Ok(Self {
            engine: Arc::new(RwLock::new(engine)),
            pending_requests: Arc::new(RwLock::new(HashMap::new())),
            requests_total: AtomicU64::new(0),
            requests_blocked: AtomicU64::new(0),
            requests_allowed: AtomicU64::new(0),
            draining: AtomicU64::new(0),
        })
    }

    /// Check if the agent is currently draining
    fn is_draining(&self) -> bool {
        let drain_end = self.draining.load(Ordering::Relaxed);
        if drain_end == 0 {
            return false;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        now < drain_end
    }

    /// Reconfigure the agent with new settings
    ///
    /// This rebuilds the ZentinelSec engine with the new configuration.
    /// In-flight requests using the old engine will complete normally.
    pub async fn reconfigure(&self, config: ZentinelSecConfig) -> Result<()> {
        info!("Reconfiguring ZentinelSec engine");
        let new_engine = ZentinelSecEngine::new(config)?;
        let mut engine = self.engine.write().await;
        *engine = new_engine;
        // Clear pending requests since rules may have changed
        let mut pending = self.pending_requests.write().await;
        pending.clear();
        info!("ZentinelSec engine reconfigured successfully");
        Ok(())
    }

    /// Process a complete request through ZentinelSec
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
                    "ZentinelSec intervention (headers)"
                );
                let rule_ids = tx.matched_rules().iter().map(|s| s.to_string()).collect();
                return Ok(Some((status, "Blocked by ZentinelSec".to_string(), rule_ids)));
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
                            "ZentinelSec intervention (body)"
                        );
                        let rule_ids = tx.matched_rules().iter().map(|s| s.to_string()).collect();
                        return Ok(Some((status, "Blocked by ZentinelSec".to_string(), rule_ids)));
                    }
                }
            }
        }

        Ok(None)
    }
}

#[async_trait::async_trait]
impl AgentHandlerV2 for ZentinelSecAgent {
    /// Return agent capabilities for v2 protocol negotiation
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities::new(
            "zentinel-zentinelsec",
            "ZentinelSec WAF Agent",
            env!("CARGO_PKG_VERSION"),
        )
        .with_event(EventType::RequestHeaders)
        .with_event(EventType::RequestBodyChunk)
        .with_event(EventType::ResponseHeaders)
        .with_event(EventType::ResponseBodyChunk)
        .with_features(AgentFeatures {
            streaming_body: true,
            websocket: false,
            guardrails: false,
            config_push: true,
            metrics_export: true,
            concurrent_requests: 100,
            cancellation: true,
            flow_control: false,
            health_reporting: true,
        })
        .with_limits(AgentLimits {
            max_body_size: 10 * 1024 * 1024, // 10MB
            max_concurrency: 100,
            preferred_chunk_size: 64 * 1024, // 64KB
            max_memory: None,
            max_processing_time_ms: Some(5000),
        })
    }

    /// Handle configuration updates from the proxy
    async fn on_configure(&self, config: serde_json::Value, version: Option<String>) -> bool {
        debug!(config_version = ?version, "Received configure event");

        // Parse the JSON config into ZentinelSecConfigJson
        let config_json: ZentinelSecConfigJson = match serde_json::from_value(config) {
            Ok(config) => config,
            Err(e) => {
                warn!(error = %e, "Failed to parse ZentinelSec configuration");
                return false;
            }
        };

        // Convert to internal config and reconfigure the engine
        let config: ZentinelSecConfig = config_json.into();
        if let Err(e) = self.reconfigure(config).await {
            warn!(error = %e, "Failed to reconfigure ZentinelSec engine");
            return false;
        }

        info!(config_version = ?version, "ZentinelSec agent configured successfully");
        true
    }

    /// Return current health status
    fn health_status(&self) -> HealthStatus {
        if self.is_draining() {
            let drain_end = self.draining.load(Ordering::Relaxed);
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            let eta_ms = if drain_end > now { Some(drain_end - now) } else { None };
            HealthStatus {
                agent_id: "zentinel-zentinelsec".to_string(),
                state: zentinel_agent_protocol::v2::HealthState::Draining { eta_ms },
                message: Some("Agent is draining".to_string()),
                load: None,
                resources: None,
                valid_until_ms: None,
                timestamp_ms: now,
            }
        } else {
            HealthStatus::healthy("zentinel-zentinelsec")
        }
    }

    /// Return metrics report for v2 protocol
    fn metrics_report(&self) -> Option<MetricsReport> {
        use zentinel_agent_protocol::v2::{CounterMetric, GaugeMetric};

        let mut report = MetricsReport::new("zentinel-zentinelsec", 10_000);

        report.counters.push(CounterMetric::new(
            "zentinelsec_requests_total",
            self.requests_total.load(Ordering::Relaxed),
        ));
        report.counters.push(CounterMetric::new(
            "zentinelsec_requests_blocked",
            self.requests_blocked.load(Ordering::Relaxed),
        ));
        report.counters.push(CounterMetric::new(
            "zentinelsec_requests_allowed",
            self.requests_allowed.load(Ordering::Relaxed),
        ));

        // Add gauge for pending requests
        let pending_count = {
            // Use try_read to avoid blocking if lock is held
            self.pending_requests
                .try_read()
                .map(|p| p.len() as f64)
                .unwrap_or(0.0)
        };
        report.gauges.push(GaugeMetric::new(
            "zentinelsec_pending_requests",
            pending_count,
        ));

        Some(report)
    }

    /// Handle shutdown request
    async fn on_shutdown(&self, reason: ShutdownReason, grace_period_ms: u64) {
        info!(
            reason = ?reason,
            grace_period_ms = grace_period_ms,
            "Received shutdown request"
        );
        // Clear pending requests on shutdown
        let mut pending = self.pending_requests.write().await;
        pending.clear();
    }

    /// Handle drain request
    async fn on_drain(&self, duration_ms: u64, reason: DrainReason) {
        info!(
            duration_ms = duration_ms,
            reason = ?reason,
            "Received drain request"
        );
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        self.draining.store(now + duration_ms, Ordering::Relaxed);
    }

    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
        let path = &event.uri;
        let correlation_id = &event.metadata.correlation_id;

        // Check exclusions
        {
            let engine = self.engine.read().await;
            if engine.is_excluded(path) {
                debug!(path = path, "Path excluded from ZentinelSec");
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
                    self.requests_blocked.fetch_add(1, Ordering::Relaxed);
                    info!(
                        correlation_id = correlation_id,
                        status = status,
                        rules = ?rule_ids,
                        "Request blocked by ZentinelSec"
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
                            tags: vec!["zentinelsec".to_string(), "blocked".to_string()],
                            rule_ids,
                            reason_codes: vec![message],
                            ..Default::default()
                        })
                } else {
                    self.requests_allowed.fetch_add(1, Ordering::Relaxed);
                    info!(
                        correlation_id = correlation_id,
                        rules = ?rule_ids,
                        "ZentinelSec detection (detect-only mode)"
                    );
                    AgentResponse::default_allow()
                        .add_request_header(HeaderOp::Set {
                            name: "X-WAF-Detected".to_string(),
                            value: message.clone(),
                        })
                        .with_audit(AuditMetadata {
                            tags: vec!["zentinelsec".to_string(), "detected".to_string()],
                            rule_ids,
                            reason_codes: vec![message],
                            ..Default::default()
                        })
                }
            }
            Ok(None) => {
                self.requests_allowed.fetch_add(1, Ordering::Relaxed);
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
                self.requests_allowed.fetch_add(1, Ordering::Relaxed);
                warn!(error = %e, "ZentinelSec processing error");
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
                            self.requests_blocked.fetch_add(1, Ordering::Relaxed);
                            // Decrement allowed since we counted it in headers phase
                            self.requests_allowed.fetch_sub(1, Ordering::Relaxed);
                            info!(
                                correlation_id = correlation_id,
                                status = status,
                                rules = ?rule_ids,
                                "Request blocked by ZentinelSec (body inspection)"
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
                                        "zentinelsec".to_string(),
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
                                "ZentinelSec detection in body (detect-only mode)"
                            );
                            return AgentResponse::default_allow()
                                .add_request_header(HeaderOp::Set {
                                    name: "X-WAF-Detected".to_string(),
                                    value: message.clone(),
                                })
                                .with_audit(AuditMetadata {
                                    tags: vec![
                                        "zentinelsec".to_string(),
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
                        warn!(error = %e, "ZentinelSec body processing error");
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
        let config = ZentinelSecConfig::default();
        assert!(config.rules_paths.is_empty());
        assert!(config.block_mode);
        assert!(config.body_inspection_enabled);
        assert!(!config.response_inspection_enabled);
        assert_eq!(config.max_body_size, 1048576);
    }

    #[test]
    fn test_engine_initialization() {
        let config = ZentinelSecConfig::default();
        let engine = ZentinelSecEngine::new(config);
        assert!(engine.is_ok());
    }

    #[test]
    fn test_engine_with_inline_rule() {
        // Test with a simple inline rule
        let config = ZentinelSecConfig::default();
        let engine = ZentinelSecEngine::new(config).unwrap();

        // Verify engine is working
        let mut tx = engine.modsec.new_transaction();
        tx.process_uri("/test", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();

        // Should not block clean requests
        assert!(tx.intervention().is_none());
    }

    #[test]
    fn test_path_exclusion() {
        let config = ZentinelSecConfig {
            exclude_paths: vec!["/health".to_string(), "/metrics".to_string()],
            ..Default::default()
        };
        let engine = ZentinelSecEngine::new(config).unwrap();

        assert!(engine.is_excluded("/health"));
        assert!(engine.is_excluded("/health/live"));
        assert!(engine.is_excluded("/metrics"));
        assert!(!engine.is_excluded("/api/users"));
    }

    #[test]
    fn test_sql_injection_blocked() {
        // Create a ModSecurity engine with a SQL injection detection rule
        let rules = r#"
            SecRuleEngine On
            SecRule ARGS "@detectSQLi" "id:942100,phase:2,deny,status:403,msg:'SQL Injection Attack Detected'"
            SecRule QUERY_STRING "@detectSQLi" "id:942101,phase:1,deny,status:403,msg:'SQL Injection in Query String'"
            SecRule REQUEST_URI "@contains union select" "id:942102,phase:1,deny,status:403,msg:'UNION SELECT detected'"
        "#;

        let modsec = zentinel_modsec::ModSecurity::from_string(rules).unwrap();

        // Test 1: Classic SQL injection in query string
        let mut tx = modsec.new_transaction();
        tx.process_uri("/api/users?id=1' OR '1'='1", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();

        let intervention = tx.intervention();
        assert!(
            intervention.is_some(),
            "Expected SQL injection to be blocked: 1' OR '1'='1"
        );
        if let Some(i) = intervention {
            assert_eq!(i.status, 403);
            println!("Blocked with status {}: {:?}", i.status, i.rule_ids);
        }

        // Test 2: UNION-based SQL injection
        let mut tx2 = modsec.new_transaction();
        tx2.process_uri("/api/users?id=1 union select * from users--", "GET", "HTTP/1.1").unwrap();
        tx2.process_request_headers().unwrap();

        let intervention2 = tx2.intervention();
        assert!(
            intervention2.is_some(),
            "Expected UNION SELECT injection to be blocked"
        );

        // Test 3: Clean request should pass
        let mut tx3 = modsec.new_transaction();
        tx3.process_uri("/api/users?id=123", "GET", "HTTP/1.1").unwrap();
        tx3.process_request_headers().unwrap();

        assert!(
            tx3.intervention().is_none(),
            "Clean request should not be blocked"
        );
    }

    #[test]
    fn test_xss_blocked() {
        // Create a ModSecurity engine with XSS detection rule
        let rules = r#"
            SecRuleEngine On
            SecRule ARGS "@detectXSS" "id:941100,phase:2,deny,status:403,msg:'XSS Attack Detected'"
            SecRule QUERY_STRING "@detectXSS" "id:941101,phase:1,deny,status:403,msg:'XSS in Query String'"
            SecRule REQUEST_URI "@contains <script" "id:941102,phase:1,deny,status:403,msg:'Script tag detected'"
        "#;

        let modsec = zentinel_modsec::ModSecurity::from_string(rules).unwrap();

        // Test 1: Script tag injection
        let mut tx = modsec.new_transaction();
        tx.process_uri("/search?q=<script>alert(1)</script>", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();

        let intervention = tx.intervention();
        assert!(
            intervention.is_some(),
            "Expected XSS to be blocked: <script>alert(1)</script>"
        );
        if let Some(i) = intervention {
            assert_eq!(i.status, 403);
            println!("XSS blocked with status {}: {:?}", i.status, i.rule_ids);
        }

        // Test 2: Event handler injection
        let mut tx2 = modsec.new_transaction();
        tx2.process_uri("/search?q=<img src=x onerror=alert(1)>", "GET", "HTTP/1.1").unwrap();
        tx2.process_request_headers().unwrap();

        let intervention2 = tx2.intervention();
        assert!(
            intervention2.is_some(),
            "Expected event handler XSS to be blocked"
        );

        // Test 3: Clean request should pass
        let mut tx3 = modsec.new_transaction();
        tx3.process_uri("/search?q=hello+world", "GET", "HTTP/1.1").unwrap();
        tx3.process_request_headers().unwrap();

        assert!(
            tx3.intervention().is_none(),
            "Clean request should not be blocked"
        );
    }

    #[test]
    fn test_request_body_sql_injection() {
        // Test SQL injection in POST body
        let rules = r#"
            SecRuleEngine On
            SecRequestBodyAccess On
            SecRule ARGS "@detectSQLi" "id:942200,phase:2,deny,status:403,msg:'SQL Injection in Body'"
        "#;

        let modsec = zentinel_modsec::ModSecurity::from_string(rules).unwrap();

        let mut tx = modsec.new_transaction();
        tx.process_uri("/api/login", "POST", "HTTP/1.1").unwrap();
        tx.add_request_header("Content-Type", "application/x-www-form-urlencoded").unwrap();
        tx.process_request_headers().unwrap();

        // Add malicious body
        let body = b"username=admin&password=' OR '1'='1";
        tx.append_request_body(body).unwrap();
        tx.process_request_body().unwrap();

        let intervention = tx.intervention();
        assert!(
            intervention.is_some(),
            "Expected SQL injection in POST body to be blocked"
        );
        if let Some(i) = intervention {
            assert_eq!(i.status, 403);
            println!("Body SQLi blocked: {:?}", i.rule_ids);
        }
    }
}
