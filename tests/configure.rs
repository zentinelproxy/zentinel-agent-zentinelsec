//! Configure handling: the proxy sends the agent's `config { }` block on every
//! connection (each pooled connection and every reconnect), so configure must
//! be idempotent, overlay the command-line settings, and reject what it cannot
//! apply instead of silently running with fewer rules.

use base64::Engine;
use serde_json::json;
use std::collections::HashMap;
use zentinel_agent_protocol::{
    v2::AgentHandlerV2, Decision, RequestBodyChunkEvent, RequestHeadersEvent, RequestMetadata,
};
use zentinel_agent_zentinelsec::{config_hash, ZentinelSecAgent, ZentinelSecConfig};

const RULES: &str = r#"
SecRequestBodyAccess On
SecRule QUERY_STRING "@contains attack" "id:1001,phase:1,deny,status:403"
SecRule REQUEST_BODY "@contains UNION SELECT" "id:6002,phase:2,deny,status:403"
"#;

const OTHER_RULES: &str = r#"
SecRequestBodyAccess On
SecRule QUERY_STRING "@contains other" "id:1101,phase:1,deny,status:403"
SecRule REQUEST_BODY "@contains UNION SELECT" "id:6102,phase:2,deny,status:403"
"#;

struct Fixture {
    dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("rules.conf"), RULES).unwrap();
        std::fs::create_dir(dir.path().join("other")).unwrap();
        std::fs::write(dir.path().join("other/rules.conf"), OTHER_RULES).unwrap();
        Self { dir }
    }

    fn rules(&self) -> String {
        self.dir.path().join("rules.conf").display().to_string()
    }

    fn other_rules(&self) -> String {
        self.dir.path().join("other/*.conf").display().to_string()
    }

    /// The agent as started with `--rules <rules.conf> --max-body-size 4096`.
    fn agent(&self) -> ZentinelSecAgent {
        ZentinelSecAgent::new(ZentinelSecConfig {
            rules_paths: vec![self.rules()],
            max_body_size: 4096,
            ..Default::default()
        })
        .unwrap()
    }
}

fn headers_event(id: &str, method: &str, uri: &str) -> RequestHeadersEvent {
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
        headers: HashMap::new(),
    }
}

fn body_event(id: &str, data: &str) -> RequestBodyChunkEvent {
    RequestBodyChunkEvent {
        correlation_id: id.to_string(),
        data: base64::engine::general_purpose::STANDARD.encode(data),
        is_last: true,
        total_size: Some(data.len()),
        chunk_index: 0,
        bytes_received: data.len(),
    }
}

async fn blocks_query(agent: &ZentinelSecAgent, uri: &str) -> bool {
    let response = agent
        .on_request_headers(headers_event(&uuid::Uuid::new_v4().to_string(), "GET", uri))
        .await;
    matches!(response.decision, Decision::Block { .. })
}

/// The scenario the proxy creates: a request's body is still being buffered
/// when another pooled connection (or a reconnect) delivers the same
/// configuration. The body must still be inspected.
#[tokio::test]
async fn identical_configure_keeps_pending_body_and_rules() {
    let fx = Fixture::new();
    let agent = fx.agent();
    let block = json!({ "rules-paths": [fx.rules()], "block-mode": true });

    assert!(agent.on_configure(block.clone(), None).await);

    let allowed = agent
        .on_request_headers(headers_event("in-flight", "POST", "/submit"))
        .await;
    assert!(matches!(allowed.decision, Decision::Allow));
    assert_eq!(agent.pending_count().await, 1);

    // Three more connections deliver the identical block.
    for _ in 0..3 {
        assert!(agent.on_configure(block.clone(), None).await);
    }
    assert_eq!(
        agent.pending_count().await,
        1,
        "an identical configure dropped the buffered body"
    );

    let response = agent
        .on_request_body_chunk(body_event("in-flight", "id=1 UNION SELECT password"))
        .await;
    assert!(
        matches!(response.decision, Decision::Block { .. }),
        "the in-flight body was not inspected after configure"
    );
    assert!(blocks_query(&agent, "/x?q=attack").await);
}

/// A configure that does change the rules rebuilds them, but requests whose
/// body is in flight are kept and inspected with the new rules.
#[tokio::test]
async fn changed_configure_keeps_pending_body() {
    let fx = Fixture::new();
    let agent = fx.agent();

    agent
        .on_request_headers(headers_event("in-flight", "POST", "/submit"))
        .await;
    assert!(
        agent
            .on_configure(
                json!({ "rules-paths": fx.other_rules(), "block-mode": false }),
                None
            )
            .await
    );
    assert_eq!(agent.pending_count().await, 1);
    assert!(
        agent
            .on_configure(json!({ "rules-paths": fx.other_rules() }), None)
            .await
    );
    assert_eq!(agent.pending_count().await, 1);

    let response = agent
        .on_request_body_chunk(body_event("in-flight", "id=1 UNION SELECT password"))
        .await;
    assert!(matches!(response.decision, Decision::Block { .. }));
    // The new rule set is the one in effect.
    assert!(blocks_query(&agent, "/x?q=other").await);
    assert!(!blocks_query(&agent, "/x?q=attack").await);
}

/// Fields missing from the block keep the command-line values; before, they
/// fell back to the defaults, and a block without `rules-paths` loaded zero
/// rules while reporting success.
#[tokio::test]
async fn partial_configure_keeps_cli_values() {
    let fx = Fixture::new();
    let agent = fx.agent();

    assert!(
        agent
            .on_configure(json!({ "exclude-paths": "/health" }), None)
            .await
    );
    let active = agent.active_config().await;
    assert_eq!(active.rules_paths, vec![fx.rules()]);
    assert_eq!(active.max_body_size, 4096);
    assert!(active.block_mode);
    assert_eq!(active.exclude_paths, vec!["/health".to_string()]);
    assert!(blocks_query(&agent, "/x?q=attack").await);
    assert!(!blocks_query(&agent, "/health?q=attack").await);

    // An empty block changes nothing.
    assert!(agent.on_configure(json!({}), None).await);
    assert_eq!(agent.active_config().await.rules_paths, vec![fx.rules()]);
}

#[tokio::test]
async fn misspelled_key_is_rejected() {
    let fx = Fixture::new();
    let agent = fx.agent();
    let before = agent.active_config().await;

    assert!(
        !agent
            .on_configure(
                json!({ "rule-paths": [fx.other_rules()], "block-mode": false }),
                None
            )
            .await
    );
    assert_eq!(agent.active_config().await, before);
    assert!(blocks_query(&agent, "/x?q=attack").await);
}

#[tokio::test]
async fn rules_that_load_nothing_are_rejected() {
    let fx = Fixture::new();
    let agent = fx.agent();
    let before = agent.active_config().await;
    let missing = fx.dir.path().join("nope/*.conf").display().to_string();

    // A pattern that matches no file, alone or next to a valid one.
    assert!(
        !agent
            .on_configure(json!({ "rules-paths": missing.clone() }), None)
            .await
    );
    assert!(
        !agent
            .on_configure(json!({ "rules-paths": [fx.rules(), missing] }), None)
            .await
    );
    // A list with nothing left after parsing.
    assert!(!agent.on_configure(json!({ "rules-paths": "" }), None).await);
    assert!(
        !agent
            .on_configure(json!({ "rules-paths": [" ", ""] }), None)
            .await
    );
    // Not an object, or a wrongly typed value.
    assert!(!agent.on_configure(json!(["rules.conf"]), None).await);
    assert!(
        !agent
            .on_configure(json!({ "block-mode": "false" }), None)
            .await
    );
    assert!(
        !agent
            .on_configure(json!({ "max-body-size": 0 }), None)
            .await
    );

    assert_eq!(agent.active_config().await, before);
    assert!(blocks_query(&agent, "/x?q=attack").await);
}

/// The CLI flag names are accepted as aliases, and a rejected configure does
/// not stop the same block from being accepted once it is valid.
#[tokio::test]
async fn cli_aliases_are_accepted() {
    let fx = Fixture::new();
    let agent = ZentinelSecAgent::new(ZentinelSecConfig::default()).unwrap();
    assert!(!blocks_query(&agent, "/x?q=attack").await);

    assert!(
        agent
            .on_configure(
                json!({ "rules": fx.rules(), "body-inspection": false }),
                None
            )
            .await
    );
    let active = agent.active_config().await;
    assert_eq!(active.rules_paths, vec![fx.rules()]);
    assert!(!active.body_inspection_enabled);
    assert!(blocks_query(&agent, "/x?q=attack").await);
}

#[test]
fn config_hash_ignores_key_order() {
    let a = json!({ "block-mode": true, "rules-paths": ["a", "b"] });
    let b = json!({ "rules-paths": ["a", "b"], "block-mode": true });
    let c = json!({ "rules-paths": ["b", "a"], "block-mode": true });
    assert_eq!(config_hash(&a), config_hash(&b));
    assert_ne!(config_hash(&a), config_hash(&c));
}

/// A rule file that exists but holds no rule (only comments, or only engine
/// directives) would leave the agent with zero rules: reject it.
#[tokio::test]
async fn rule_file_without_rules_is_rejected() {
    let fx = Fixture::new();
    let agent = fx.agent();
    let before = agent.rule_count().await;
    assert!(before > 0);
    let empty = fx.dir.path().join("empty.conf");
    std::fs::write(&empty, "# nothing here\nSecRequestBodyAccess On\n").unwrap();

    let err = agent
        .configure(json!({ "rules-paths": empty.display().to_string() }))
        .await
        .unwrap_err();
    assert!(err.contains("contain no rules"), "{err}");
    assert_eq!(agent.rule_count().await, before);
    assert!(blocks_query(&agent, "/x?q=attack").await);
}
