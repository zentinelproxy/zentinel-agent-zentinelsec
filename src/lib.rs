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

use zentinel_agent_protocol::v2::{
    AgentCapabilities, AgentFeatures, AgentHandlerV2, AgentLimits, DrainReason, HealthStatus,
    MetricsReport, ShutdownReason,
};
use zentinel_agent_protocol::{
    AgentResponse, AuditMetadata, EventType, HeaderOp, RequestBodyChunkEvent, RequestCompleteEvent,
    RequestHeadersEvent, ResponseBodyChunkEvent, ResponseHeadersEvent,
};

/// Maximum concurrent requests buffered for body inspection.
#[cfg(test)]
const PENDING_REQUESTS_MAX: usize = 10;
#[cfg(not(test))]
const PENDING_REQUESTS_MAX: usize = 100_000;

/// Drop pending body buffers when the proxy never finishes the request.
const PENDING_REQUEST_MAX_AGE_MS: u64 = 120_000;

use zentinel_modsec::ModSecurity;

/// ZentinelSec configuration
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZentinelSecConfig {
    /// Paths to ModSecurity rule files
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

impl ZentinelSecConfig {
    /// Names (as written in a `config { }` block) of the settings that differ
    /// between `self` and `other`. Used to log what a configure changed
    /// without logging the values.
    pub fn changed_keys(&self, other: &ZentinelSecConfig) -> Vec<&'static str> {
        let mut keys = Vec::new();
        if self.rules_paths != other.rules_paths {
            keys.push("rules-paths");
        }
        if self.block_mode != other.block_mode {
            keys.push("block-mode");
        }
        if self.exclude_paths != other.exclude_paths {
            keys.push("exclude-paths");
        }
        if self.body_inspection_enabled != other.body_inspection_enabled {
            keys.push("body-inspection-enabled");
        }
        if self.max_body_size != other.max_body_size {
            keys.push("max-body-size");
        }
        if self.response_inspection_enabled != other.response_inspection_enabled {
            keys.push("response-inspection-enabled");
        }
        keys
    }

    /// Whether going from `self` to `other` needs the rule set rebuilt.
    /// Only the rule files shape the compiled rules; the other settings are
    /// read per request and can change in place.
    fn needs_rebuild(&self, other: &ZentinelSecConfig) -> bool {
        self.rules_paths != other.rules_paths
    }
}

/// The agent's `config { }` block, as the proxy sends it in Configure.
///
/// Every field is optional: a field that is absent keeps the value from the
/// command line / environment (see [`ZentinelSecConfigJson::apply_to`]). Unknown
/// keys are rejected, so a misspelled key fails the configure instead of being
/// ignored. Keys are kebab-case; `rules`, `body-inspection` and
/// `response-inspection` are accepted as aliases matching the CLI flags. A
/// list may be given as a single string (the proxy turns a one-argument KDL
/// node into a scalar).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ZentinelSecConfigJson {
    /// Paths to ModSecurity rule files (glob patterns supported)
    #[serde(
        default,
        alias = "rules",
        deserialize_with = "one_or_many",
        skip_serializing_if = "Option::is_none"
    )]
    pub rules_paths: Option<Vec<String>>,
    /// Block mode (true) or detect-only mode (false)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_mode: Option<bool>,
    /// Paths to exclude from inspection
    #[serde(
        default,
        deserialize_with = "one_or_many",
        skip_serializing_if = "Option::is_none"
    )]
    pub exclude_paths: Option<Vec<String>>,
    /// Enable request body inspection
    #[serde(
        default,
        alias = "body-inspection",
        skip_serializing_if = "Option::is_none"
    )]
    pub body_inspection_enabled: Option<bool>,
    /// Maximum body size to inspect in bytes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_body_size: Option<usize>,
    /// Enable response body inspection
    #[serde(
        default,
        alias = "response-inspection",
        skip_serializing_if = "Option::is_none"
    )]
    pub response_inspection_enabled: Option<bool>,
}

/// Accept a list as a JSON array or as a single string.
fn one_or_many<'de, D>(deserializer: D) -> std::result::Result<Option<Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }
    Ok(Some(match OneOrMany::deserialize(deserializer)? {
        OneOrMany::One(s) => vec![s],
        OneOrMany::Many(v) => v,
    }))
}

/// Trim the entries of a list from the config block and drop empty ones.
/// A list that was given but has nothing left is an error: it is almost
/// always a mistake (`rules-paths ""`), and taking it literally would turn
/// inspection off.
fn clean_list(key: &str, list: &[String]) -> std::result::Result<Vec<String>, String> {
    let cleaned: Vec<String> = list
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if cleaned.is_empty() {
        return Err(format!(
            "`{key}` is empty; omit it to keep the value from the command line"
        ));
    }
    Ok(cleaned)
}

impl ZentinelSecConfigJson {
    /// Parse a configure payload. Rejects anything but an object, unknown
    /// keys and wrongly typed values.
    pub fn from_value(value: serde_json::Value) -> std::result::Result<Self, String> {
        if !value.is_object() {
            return Err(format!("expected an object, got {}", json_kind(&value)));
        }
        serde_json::from_value(value).map_err(|e| e.to_string())
    }

    /// Overlay these settings on `base`: a field that is present replaces the
    /// base value, an absent one keeps it.
    pub fn apply_to(
        &self,
        base: &ZentinelSecConfig,
    ) -> std::result::Result<ZentinelSecConfig, String> {
        let mut config = base.clone();
        if let Some(rules) = &self.rules_paths {
            config.rules_paths = clean_list("rules-paths", rules)?;
        }
        if let Some(block_mode) = self.block_mode {
            config.block_mode = block_mode;
        }
        if let Some(exclude) = &self.exclude_paths {
            config.exclude_paths = if exclude.is_empty() {
                Vec::new()
            } else {
                clean_list("exclude-paths", exclude)?
            };
        }
        if let Some(body) = self.body_inspection_enabled {
            config.body_inspection_enabled = body;
        }
        if let Some(max) = self.max_body_size {
            if max == 0 {
                return Err("`max-body-size` must be greater than 0".to_string());
            }
            config.max_body_size = max;
        }
        if let Some(response) = self.response_inspection_enabled {
            config.response_inspection_enabled = response;
        }
        Ok(config)
    }
}

fn json_kind(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "a boolean",
        serde_json::Value::Number(_) => "a number",
        serde_json::Value::String(_) => "a string",
        serde_json::Value::Array(_) => "an array",
        serde_json::Value::Object(_) => "an object",
    }
}

/// A stable hash of a JSON value, independent of object key order: FNV-1a
/// over the value serialized with every object's keys sorted.
pub fn config_hash(value: &serde_json::Value) -> u64 {
    fn canonical(value: &serde_json::Value, out: &mut String) {
        match value {
            serde_json::Value::Object(map) => {
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                out.push('{');
                for (i, key) in keys.into_iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push_str(&serde_json::Value::String(key.clone()).to_string());
                    out.push(':');
                    canonical(&map[key], out);
                }
                out.push('}');
            }
            serde_json::Value::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    canonical(item, out);
                }
                out.push(']');
            }
            other => out.push_str(&other.to_string()),
        }
    }
    let mut text = String::new();
    canonical(value, &mut text);
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in text.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
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
    /// Number of rule files loaded from `config.rules_paths`
    pub rule_files: usize,
}

impl ZentinelSecEngine {
    /// Create a new ZentinelSec engine with the given configuration
    pub fn new(config: ZentinelSecConfig) -> Result<Self> {
        Self::build(config, false)
    }

    /// Like [`ZentinelSecEngine::new`], but every rules pattern must match at
    /// least one file and the result must contain at least one rule. Used
    /// when the rules came from a `config { }` block, so a misspelled path
    /// fails the configure instead of silently loading fewer (or zero) rules.
    pub fn new_strict(config: ZentinelSecConfig) -> Result<Self> {
        Self::build(config, true)
    }

    fn build(config: ZentinelSecConfig, strict: bool) -> Result<Self> {
        // Hand the engine `Include` directives rather than the text of each
        // rule file.
        //
        // Splicing file contents together loses the one thing the engine needs
        // to resolve `@pmFromFile`/`@ipMatchFromFile` data paths and nested
        // `Include`s: which file a directive came from. Those paths are
        // relative to their own rule file, so a concatenated string sent them
        // to the process's working directory instead. Stock CRS references
        // `scanners-user-agents.data` and many others, which meant the
        // documented deployment only started if it happened to be run from
        // /etc/modsecurity/crs/rules.
        let mut rules_content = String::new();

        // Always enable the rule engine
        rules_content.push_str("SecRuleEngine On\n");

        // Resolve the configured patterns ourselves so a path that cannot be
        // read is reported against the pattern that produced it, and so the
        // file count is available for logging.
        let mut loaded_count = 0;
        for path_pattern in &config.rules_paths {
            let before = loaded_count;
            // Handle glob patterns
            let paths = glob::glob(path_pattern)
                .map_err(|e| anyhow::anyhow!("Invalid glob pattern '{}': {}", path_pattern, e))?;

            for entry in paths {
                match entry {
                    Ok(path) => {
                        if path.is_file() {
                            // An absolute path keeps the include independent of
                            // the working directory; quoting keeps a path with
                            // spaces in one argument.
                            let absolute = fs::canonicalize(&path).map_err(|e| {
                                anyhow::anyhow!("Failed to resolve rule file {:?}: {}", path, e)
                            })?;
                            rules_content
                                .push_str(&format!("Include \"{}\"\n", absolute.display()));
                            loaded_count += 1;
                            debug!(path = ?absolute, "Including rule file");
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "Error reading glob entry");
                    }
                }
            }
            if strict && loaded_count == before {
                anyhow::bail!("rules pattern '{}' matched no rule file", path_pattern);
            }
        }

        // Create the ModSecurity engine
        let modsec = if loaded_count == 0 {
            // No rules loaded, create with just SecRuleEngine On
            ModSecurity::from_string("SecRuleEngine On")
                .map_err(|e| anyhow::anyhow!("Failed to initialize ZentinelSec engine: {}", e))?
        } else {
            ModSecurity::from_string(&rules_content)
                .map_err(|e| anyhow::anyhow!("Failed to parse rules: {}", e))?
        };

        info!(
            rules_files = loaded_count,
            rule_count = modsec.rule_count(),
            "ZentinelSec engine initialized"
        );

        if strict && modsec.rule_count() == 0 {
            anyhow::bail!("the configured rule files contain no rules");
        }

        Ok(Self {
            modsec,
            config,
            rule_files: loaded_count,
        })
    }

    /// Number of rules the engine loaded.
    pub fn rule_count(&self) -> usize {
        self.modsec.rule_count()
    }

    /// The underlying ModSecurity engine.
    ///
    /// Exposed so tests can drive transactions through the rules this agent
    /// actually loaded, rather than through a separately built engine that
    /// might load them differently.
    pub fn modsec(&self) -> &ModSecurity {
        &self.modsec
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
    created_at_ms: u64,
    /// The body grew past `max_body_size`: finish the request without inspection
    /// instead of dropping the entry (a later chunk would look like an unknown
    /// correlation and fail closed mid-request).
    inspection_skipped: bool,
}

/// Current Unix time in milliseconds.
fn current_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// True when the request is known to carry no body.
///
/// Only a `Content-Length` of zero in every occurrence proves it: the method and
/// the absence of `Content-Length` prove nothing (the proxy reports
/// `protocol: "HTTP/1.1"` for every request, and HTTP/2 carries bodies of
/// undeclared length). A request that is parked anyway is released when its
/// response starts, so memory follows the number of requests in flight rather
/// than every request ever seen.
fn request_has_empty_body(headers: &HashMap<String, Vec<String>>) -> bool {
    let mut cl_values = Vec::new();
    for (name, header_values) in headers {
        if name.eq_ignore_ascii_case("content-length") {
            cl_values.extend(header_values.iter().map(String::as_str));
        }
    }
    !cl_values.is_empty()
        && cl_values
            .iter()
            .all(|v| v.trim().parse::<u64>().map(|n| n == 0).unwrap_or(false))
}

/// Remove pending body buffers older than [`PENDING_REQUEST_MAX_AGE_MS`].
fn sweep_stale_pending(pending: &mut HashMap<String, PendingTransaction>, now_ms: u64) {
    pending.retain(|_, tx| now_ms.saturating_sub(tx.created_at_ms) <= PENDING_REQUEST_MAX_AGE_MS);
}

/// Block with 403 when inspection state is missing or invalid (fail-closed).
fn fail_closed_block_response(correlation_id: &str, reason: &str) -> AgentResponse {
    warn!(
        correlation_id = correlation_id,
        reason = reason,
        "Blocking request (fail-closed)"
    );
    AgentResponse::block(403, Some("Forbidden".to_string()))
        .add_response_header(HeaderOp::Set {
            name: "X-WAF-Blocked".to_string(),
            value: "true".to_string(),
        })
        .add_response_header(HeaderOp::Set {
            name: "X-WAF-Message".to_string(),
            value: reason.to_string(),
        })
        .with_audit(AuditMetadata {
            tags: vec![
                "zentinelsec".to_string(),
                "blocked".to_string(),
                "fail-closed".to_string(),
            ],
            rule_ids: vec![],
            reason_codes: vec![reason.to_string()],
            ..Default::default()
        })
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
    /// The configuration from the command line / environment. A `config { }`
    /// block is overlaid on this, never on a previous block.
    base_config: ZentinelSecConfig,
    /// Hash of the last accepted configure payload. Also serializes
    /// configures: the proxy sends one per pooled connection, concurrently.
    last_configure: tokio::sync::Mutex<Option<u64>>,
}

impl ZentinelSecAgent {
    /// Create a new ZentinelSec agent with the given configuration
    pub fn new(config: ZentinelSecConfig) -> Result<Self> {
        let engine = ZentinelSecEngine::new(config.clone())?;
        Ok(Self {
            base_config: config,
            last_configure: tokio::sync::Mutex::new(None),
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

    /// The configuration currently in effect.
    pub async fn active_config(&self) -> ZentinelSecConfig {
        self.engine.read().await.config.clone()
    }

    /// Number of requests whose body is being buffered for inspection.
    pub async fn pending_count(&self) -> usize {
        self.pending_requests.read().await.len()
    }

    /// Number of rules the active engine loaded.
    pub async fn rule_count(&self) -> usize {
        self.engine.read().await.rule_count()
    }

    /// Reconfigure the agent with new settings
    ///
    /// The rule set is rebuilt only when the rule files changed; other
    /// settings are updated in place. Requests whose body is still being
    /// buffered are kept and inspected with the new settings.
    pub async fn reconfigure(&self, config: ZentinelSecConfig) -> Result<()> {
        self.apply(config, false).await.map(|_| ())
    }

    /// Make `config` the active configuration. Returns the names of the
    /// settings that changed (empty: nothing to do).
    async fn apply(&self, config: ZentinelSecConfig, strict: bool) -> Result<Vec<&'static str>> {
        let current = self.active_config().await;
        let changed = current.changed_keys(&config);
        if changed.is_empty() {
            return Ok(changed);
        }
        if current.needs_rebuild(&config) {
            let new_engine = if strict {
                ZentinelSecEngine::new_strict(config)?
            } else {
                ZentinelSecEngine::new(config)?
            };
            *self.engine.write().await = new_engine;
        } else {
            self.engine.write().await.config = config;
        }
        Ok(changed)
    }

    /// Handle a configure payload (the agent's `config { }` block): see the
    /// README's Configuration section for the rules.
    pub async fn configure(&self, config: serde_json::Value) -> std::result::Result<(), String> {
        let hash = config_hash(&config);
        let mut last = self.last_configure.lock().await;
        if *last == Some(hash) {
            debug!(
                config_hash = format!("{hash:016x}"),
                "Configuration unchanged"
            );
            return Ok(());
        }

        let overlay = ZentinelSecConfigJson::from_value(config)
            .map_err(|e| format!("invalid ZentinelSec configuration: {e}"))?;
        let effective = overlay
            .apply_to(&self.base_config)
            .map_err(|e| format!("invalid ZentinelSec configuration: {e}"))?;
        let rules_from_block = overlay.rules_paths.is_some();

        let changed = self
            .apply(effective, rules_from_block)
            .await
            .map_err(|e| format!("failed to load rules: {e:#}"))?;
        if rules_from_block && self.engine.read().await.rule_count() == 0 {
            // Cannot happen with strict loading, but never report success
            // for a configure that asked for rules and loaded none.
            return Err("the configured rules loaded no rule".to_string());
        }

        *last = Some(hash);
        info!(
            config_hash = format!("{hash:016x}"),
            changed = ?changed,
            "ZentinelSec agent configured"
        );
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
                // The rules that caused the intervention, not every rule that
                // matched: `matched_rules()` also lists CRS setup actions and
                // chain starters whose chain never completed, so its first
                // entry under stock CRS is a setup rule such as 900990 rather
                // than the rule that blocked.
                let rule_ids = intervention.rule_ids.clone();
                let message = intervention
                    .log
                    .clone()
                    .unwrap_or_else(|| "Blocked by ZentinelSec".to_string());
                return Ok(Some((status, message, rule_ids)));
            }
        }

        // Phase 2. `None` means a body is still coming and will be processed
        // by a later call; `Some` (possibly empty) runs phase 2 now. Phase 2
        // must run even without a body: CRS evaluates ARGS (the query
        // string) for SQLi/XSS, and makes its anomaly-score blocking
        // decision (949110), in phase 2. Skipping it for bodyless requests
        // meant no GET was ever blocked under stock CRS.
        if let Some(body_data) = body {
            if !body_data.is_empty() {
                tx.append_request_body(body_data)
                    .map_err(|e| anyhow::anyhow!("append_request_body failed: {}", e))?;
            }
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
                    let rule_ids = intervention.rule_ids.clone();
                    let message = intervention
                        .log
                        .clone()
                        .unwrap_or_else(|| "Blocked by ZentinelSec".to_string());
                    return Ok(Some((status, message, rule_ids)));
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
        match self.configure(config).await {
            Ok(()) => true,
            Err(e) => {
                warn!(config_version = ?version, error = %e, "Rejected configuration");
                false
            }
        }
    }

    /// Return current health status
    fn health_status(&self) -> HealthStatus {
        if self.is_draining() {
            let drain_end = self.draining.load(Ordering::Relaxed);
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            let eta_ms = if drain_end > now {
                Some(drain_end - now)
            } else {
                None
            };
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

        // Run phases 1 and 2 now, with an empty body, so attacks in the URI,
        // query string and headers are decided here. When a body is still
        // expected, phase 2 runs again with the accumulated body on the last
        // chunk. Known-empty bodies (`Content-Length: 0` only) finish here and
        // are not parked.
        let empty: &[u8] = &[];
        match self
            .process_request(
                correlation_id,
                &event.method,
                &event.uri,
                &event.headers,
                Some(empty),
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
                let engine = self.engine.read().await;
                if engine.config.body_inspection_enabled && !request_has_empty_body(&event.headers)
                {
                    let now = current_time_ms();
                    let mut pending = self.pending_requests.write().await;
                    sweep_stale_pending(&mut pending, now);
                    if pending.len() >= PENDING_REQUESTS_MAX {
                        self.requests_allowed.fetch_sub(1, Ordering::Relaxed);
                        self.requests_blocked.fetch_add(1, Ordering::Relaxed);
                        return fail_closed_block_response(
                            correlation_id,
                            "pending request capacity exceeded",
                        );
                    }
                    pending.insert(
                        correlation_id.clone(),
                        PendingTransaction {
                            body: BodyAccumulator::default(),
                            method: event.method.clone(),
                            uri: event.uri.clone(),
                            headers: event.headers.clone(),
                            client_ip: event.metadata.client_ip.clone(),
                            created_at_ms: now,
                            inspection_skipped: false,
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

    async fn on_request_complete(&self, event: RequestCompleteEvent) -> AgentResponse {
        // A request that never sent a body leaves its pending entry behind;
        // drop it when the proxy reports the request finished.
        self.pending_requests
            .write()
            .await
            .remove(&event.correlation_id);
        AgentResponse::default_allow()
    }

    async fn on_response_headers(&self, event: ResponseHeadersEvent) -> AgentResponse {
        // Upstream responses start before the proxy always sends RequestComplete;
        // drop any body buffer so bodyless requests cannot pin memory.
        self.pending_requests
            .write()
            .await
            .remove(&event.correlation_id);
        AgentResponse::default_allow()
    }

    async fn on_request_body_chunk(&self, event: RequestBodyChunkEvent) -> AgentResponse {
        let correlation_id = &event.correlation_id;

        let chunk = match base64::engine::general_purpose::STANDARD.decode(&event.data) {
            Ok(data) => data,
            Err(e) => {
                warn!(error = %e, "Failed to decode body chunk");
                return fail_closed_block_response(correlation_id, "invalid body chunk encoding");
            }
        };

        let mut pending = self.pending_requests.write().await;
        let engine = self.engine.read().await;

        if !pending.contains_key(correlation_id) {
            // With inspection turned off nothing is parked, and the proxy may
            // still stream the body to us: there is nothing to decide.
            if !engine.config.body_inspection_enabled {
                return AgentResponse::default_allow();
            }
            return fail_closed_block_response(correlation_id, "no pending request for body chunk");
        }

        if pending
            .get(correlation_id)
            .is_some_and(|tx| tx.inspection_skipped)
        {
            if event.is_last {
                pending.remove(correlation_id);
            }
            return AgentResponse::default_allow();
        }

        let over_limit = pending
            .get(correlation_id)
            .is_some_and(|tx| tx.body.data.len() + chunk.len() > engine.config.max_body_size);
        if over_limit {
            debug!(
                correlation_id = correlation_id,
                "Body exceeds max size, skipping inspection"
            );
            if let Some(tx) = pending.get_mut(correlation_id) {
                tx.inspection_skipped = true;
                // Release the part that was buffered; it will not be inspected.
                tx.body.data = Vec::new();
            }
            if event.is_last {
                pending.remove(correlation_id);
            }
            return AgentResponse::default_allow();
        }

        let should_process = match pending.get_mut(correlation_id) {
            Some(tx) => {
                tx.body.data.extend(chunk);
                event.is_last
            }
            None => false,
        };
        drop(engine);
        drop(pending);

        if should_process {
            let pending_tx = {
                let mut pending = self.pending_requests.write().await;
                match pending.remove(correlation_id) {
                    Some(tx) => tx,
                    None => {
                        return fail_closed_block_response(
                            correlation_id,
                            "no pending request for body chunk",
                        );
                    }
                }
            };

            match self
                .process_request(
                    correlation_id,
                    &pending_tx.method,
                    &pending_tx.uri,
                    &pending_tx.headers,
                    Some(&pending_tx.body.data),
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
    use zentinel_agent_protocol::{Decision, RequestMetadata};

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
        tx.process_uri("/api/users?id=1' OR '1'='1", "GET", "HTTP/1.1")
            .unwrap();
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
        tx2.process_uri(
            "/api/users?id=1 union select * from users--",
            "GET",
            "HTTP/1.1",
        )
        .unwrap();
        tx2.process_request_headers().unwrap();

        let intervention2 = tx2.intervention();
        assert!(
            intervention2.is_some(),
            "Expected UNION SELECT injection to be blocked"
        );

        // Test 3: Clean request should pass
        let mut tx3 = modsec.new_transaction();
        tx3.process_uri("/api/users?id=123", "GET", "HTTP/1.1")
            .unwrap();
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
        tx.process_uri("/search?q=<script>alert(1)</script>", "GET", "HTTP/1.1")
            .unwrap();
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
        tx2.process_uri("/search?q=<img src=x onerror=alert(1)>", "GET", "HTTP/1.1")
            .unwrap();
        tx2.process_request_headers().unwrap();

        let intervention2 = tx2.intervention();
        assert!(
            intervention2.is_some(),
            "Expected event handler XSS to be blocked"
        );

        // Test 3: Clean request should pass
        let mut tx3 = modsec.new_transaction();
        tx3.process_uri("/search?q=hello+world", "GET", "HTTP/1.1")
            .unwrap();
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
        tx.add_request_header("Content-Type", "application/x-www-form-urlencoded")
            .unwrap();
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

    /// Phase 2 runs for a request without a body: CRS inspects ARGS (the
    /// query string) and makes its blocking decision in phase 2, so a GET
    /// must be able to be blocked by a phase-2 rule.
    #[tokio::test]
    async fn test_phase2_rule_blocks_bodyless_get() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("rules.conf"),
            r#"SecRule ARGS "@detectSQLi" "id:10,phase:2,deny,status:403""#,
        )
        .unwrap();
        let config = ZentinelSecConfig {
            rules_paths: vec![dir.path().join("*.conf").display().to_string()],
            ..Default::default()
        };
        let agent = ZentinelSecAgent::new(config).unwrap();
        let headers = HashMap::new();
        let empty: &[u8] = &[];

        let blocked = agent
            .process_request(
                "c1",
                "GET",
                "/s?id=1%27%20OR%20%271%27%3D%271",
                &headers,
                Some(empty),
            )
            .await
            .unwrap();
        assert_eq!(blocked.map(|(status, _, _)| status), Some(403));

        let clean = agent
            .process_request("c2", "GET", "/s?q=hello", &headers, Some(empty))
            .await
            .unwrap();
        assert!(clean.is_none());
    }

    fn test_headers_event(
        id: &str,
        method: &str,
        uri: &str,
        headers: HashMap<String, Vec<String>>,
    ) -> RequestHeadersEvent {
        RequestHeadersEvent {
            metadata: RequestMetadata {
                correlation_id: id.to_string(),
                request_id: id.to_string(),
                client_ip: "127.0.0.1".to_string(),
                client_port: 12345,
                server_name: None,
                protocol: "HTTP/1.1".to_string(),
                tls_version: None,
                tls_cipher: None,
                route_id: None,
                upstream_id: None,
                timestamp: "2026-01-01T00:00:00Z".to_string(),
                traceparent: None,
            },
            method: method.to_string(),
            uri: uri.to_string(),
            headers,
        }
    }

    fn test_body_chunk_event(id: &str, data: &[u8], is_last: bool) -> RequestBodyChunkEvent {
        RequestBodyChunkEvent {
            correlation_id: id.to_string(),
            data: base64::engine::general_purpose::STANDARD.encode(data),
            is_last,
            total_size: Some(data.len()),
            chunk_index: 0,
            bytes_received: data.len(),
        }
    }

    async fn test_agent_minimal() -> ZentinelSecAgent {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("rules.conf"),
            "SecRuleEngine DetectionOnly\n",
        )
        .unwrap();
        let config = ZentinelSecConfig {
            rules_paths: vec![dir.path().join("rules.conf").display().to_string()],
            ..Default::default()
        };
        ZentinelSecAgent::new(config).unwrap()
    }

    /// Regression: bodyless GETs must not accumulate `pending_requests` (OOM).
    #[tokio::test]
    async fn test_bodyless_gets_do_not_accumulate_pending() {
        use zentinel_agent_protocol::v2::AgentHandlerV2;

        let agent = test_agent_minimal().await;
        for i in 0..10_000 {
            let id = format!("bodyless-{i}");
            let response = agent
                .on_request_headers(test_headers_event(
                    &id,
                    "GET",
                    "/api/health",
                    HashMap::new(),
                ))
                .await;
            assert!(
                matches!(response.decision, Decision::Allow),
                "GET {id} should allow"
            );

            // A GET carries no body, so nothing arrives to release the entry:
            // the response starting is what must release it. Without this the
            // map grows by one entry per request for the life of the process.
            agent
                .on_response_headers(ResponseHeadersEvent {
                    correlation_id: id.clone(),
                    status: 200,
                    headers: HashMap::new(),
                })
                .await;
        }
        assert_eq!(
            agent.pending_count().await,
            0,
            "a body-less request must not outlive its response"
        );
    }

    #[tokio::test]
    async fn test_body_chunk_without_pending_is_denied() {
        use zentinel_agent_protocol::v2::AgentHandlerV2;

        let agent = test_agent_minimal().await;
        let response = agent
            .on_request_body_chunk(test_body_chunk_event("orphan", b"payload", true))
            .await;
        assert!(
            matches!(response.decision, Decision::Block { status: 403, .. }),
            "orphan body chunk must fail closed"
        );
    }

    #[tokio::test]
    async fn test_post_content_length_zero_runs_phase2_without_parking() {
        use zentinel_agent_protocol::v2::AgentHandlerV2;

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("rules.conf"),
            r#"SecRule ARGS "@detectSQLi" "id:10,phase:2,deny,status:403""#,
        )
        .unwrap();
        let config = ZentinelSecConfig {
            rules_paths: vec![dir.path().join("rules.conf").display().to_string()],
            ..Default::default()
        };
        let agent = ZentinelSecAgent::new(config).unwrap();
        let mut headers = HashMap::new();
        headers.insert("content-length".to_string(), vec!["0".to_string()]);

        let blocked = agent
            .on_request_headers(test_headers_event(
                "cl0-block",
                "POST",
                "/s?id=1%27%20OR%20%271%27%3D%271",
                headers.clone(),
            ))
            .await;
        assert!(
            matches!(blocked.decision, Decision::Block { status: 403, .. }),
            "POST with Content-Length: 0 should run phase 2 at headers"
        );
        assert_eq!(agent.pending_count().await, 0);

        let clean = agent
            .on_request_headers(test_headers_event(
                "cl0-allow",
                "POST",
                "/s?q=hello",
                headers,
            ))
            .await;
        assert!(matches!(clean.decision, Decision::Allow));
        assert_eq!(agent.pending_count().await, 0);
    }

    #[tokio::test]
    async fn test_bodied_post_still_buffers_for_inspection() {
        use zentinel_agent_protocol::v2::AgentHandlerV2;

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("rules.conf"),
            r#"
            SecRequestBodyAccess On
            SecRule REQUEST_BODY "@contains UNION SELECT" "id:6002,phase:2,deny,status:403"
            "#,
        )
        .unwrap();
        let config = ZentinelSecConfig {
            rules_paths: vec![dir.path().join("rules.conf").display().to_string()],
            ..Default::default()
        };
        let agent = ZentinelSecAgent::new(config).unwrap();

        let allowed = agent
            .on_request_headers(test_headers_event(
                "bodied",
                "POST",
                "/submit",
                HashMap::new(),
            ))
            .await;
        assert!(matches!(allowed.decision, Decision::Allow));
        assert_eq!(agent.pending_count().await, 1);

        let blocked = agent
            .on_request_body_chunk(test_body_chunk_event(
                "bodied",
                b"id=1 UNION SELECT password",
                true,
            ))
            .await;
        assert!(matches!(blocked.decision, Decision::Block { .. }));
        assert_eq!(agent.pending_count().await, 0);
    }

    #[tokio::test]
    async fn test_pending_cap_rejects_new_parks_fail_closed() {
        use zentinel_agent_protocol::v2::AgentHandlerV2;

        let agent = test_agent_minimal().await;
        for i in 0..PENDING_REQUESTS_MAX {
            agent
                .on_request_headers(test_headers_event(
                    &format!("park-{i}"),
                    "POST",
                    "/submit",
                    HashMap::new(),
                ))
                .await;
        }
        assert_eq!(agent.pending_count().await, PENDING_REQUESTS_MAX);

        let capped = agent
            .on_request_headers(test_headers_event(
                "over-cap",
                "POST",
                "/submit",
                HashMap::new(),
            ))
            .await;
        assert!(
            matches!(capped.decision, Decision::Block { status: 403, .. }),
            "must not park when at capacity"
        );
        assert_eq!(agent.pending_count().await, PENDING_REQUESTS_MAX);

        let orphan_body = agent
            .on_request_body_chunk(test_body_chunk_event("over-cap", b"x", true))
            .await;
        assert!(
            matches!(orphan_body.decision, Decision::Block { status: 403, .. }),
            "body for uncapped correlation id must fail closed"
        );
    }

    #[tokio::test]
    async fn test_response_headers_drop_pending_before_body() {
        use zentinel_agent_protocol::v2::AgentHandlerV2;

        let agent = test_agent_minimal().await;
        agent
            .on_request_headers(test_headers_event(
                "resp-drop",
                "POST",
                "/x",
                HashMap::new(),
            ))
            .await;
        assert_eq!(agent.pending_count().await, 1);

        agent
            .on_response_headers(ResponseHeadersEvent {
                correlation_id: "resp-drop".to_string(),
                status: 200,
                headers: HashMap::new(),
            })
            .await;
        assert_eq!(agent.pending_count().await, 0);

        let denied = agent
            .on_request_body_chunk(test_body_chunk_event("resp-drop", b"late", true))
            .await;
        assert!(matches!(
            denied.decision,
            Decision::Block { status: 403, .. }
        ));
    }
}
