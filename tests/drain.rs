//! Drain handling (#19): requests in flight during a drain finish and their
//! bodies are still inspected. The drain is signalled through health
//! (`Draining`) only; requests that still arrive are inspected as usual, never
//! refused with a block (the proxy would turn that into a WAF 503 instead of
//! the route's failure mode).

use base64::Engine;
use std::collections::HashMap;
use std::time::Duration;
use zentinel_agent_protocol::{
    v2::{AgentHandlerV2, DrainReason, HealthState},
    Decision, RequestBodyChunkEvent, RequestHeadersEvent, RequestMetadata,
};
use zentinel_agent_zentinelsec::{ZentinelSecAgent, ZentinelSecConfig};

const RULES: &str = r#"
SecRule REQUEST_BODY "@contains UNION SELECT" "id:6002,phase:2,deny,status:403"
"#;

fn agent(dir: &tempfile::TempDir, block_mode: bool) -> ZentinelSecAgent {
    let rules = dir.path().join("rules.conf");
    std::fs::write(&rules, RULES).unwrap();
    ZentinelSecAgent::new(ZentinelSecConfig {
        rules_paths: vec![rules.display().to_string()],
        block_mode,
        ..Default::default()
    })
    .unwrap()
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

fn body_event(id: &str, data: &str, chunk_index: u32, is_last: bool) -> RequestBodyChunkEvent {
    RequestBodyChunkEvent {
        correlation_id: id.to_string(),
        data: base64::engine::general_purpose::STANDARD.encode(data),
        is_last,
        total_size: None,
        chunk_index,
        bytes_received: data.len(),
    }
}

/// The scenario from #8: the headers and the first part of a body arrive, the
/// proxy drains the agent, and the rest of the body arrives. The attack in
/// the body must still be found.
#[tokio::test]
async fn a_body_that_straddles_a_drain_is_still_inspected() {
    let dir = tempfile::tempdir().unwrap();
    let agent = agent(&dir, true);

    let headers = agent
        .on_request_headers(headers_event("straddle", "POST", "/submit"))
        .await;
    assert!(matches!(headers.decision, Decision::Allow));
    let first = agent
        .on_request_body_chunk(body_event("straddle", "id=1 UNION ", 0, false))
        .await;
    assert!(matches!(first.decision, Decision::Allow));
    assert_eq!(agent.pending_count().await, 1);

    agent.on_drain(30_000, DrainReason::ConfigReload).await;
    assert_eq!(
        agent.pending_count().await,
        1,
        "a drain must not drop a body that is still being buffered"
    );

    let last = agent
        .on_request_body_chunk(body_event("straddle", "SELECT password", 1, true))
        .await;
    assert!(
        matches!(last.decision, Decision::Block { status: 403, .. }),
        "the body of a request in flight during a drain must still be inspected, got {:?}",
        last.decision
    );
    assert_eq!(agent.pending_count().await, 0);
}

/// A drain changes health only: a new clean request is still allowed and a
/// new attack is still blocked by the rules, not refused with a 503.
#[tokio::test]
async fn new_requests_are_still_inspected_while_draining() {
    let dir = tempfile::tempdir().unwrap();
    let agent = agent(&dir, true);
    assert!(matches!(agent.health_status().state, HealthState::Healthy));

    agent.on_drain(30_000, DrainReason::Maintenance).await;
    assert!(matches!(
        agent.health_status().state,
        HealthState::Draining { eta_ms: Some(_) }
    ));

    let clean = agent
        .on_request_headers(headers_event("clean", "GET", "/"))
        .await;
    assert!(
        matches!(clean.decision, Decision::Allow),
        "a clean request during a drain must be allowed, got {:?}",
        clean.decision
    );

    let headers = agent
        .on_request_headers(headers_event("attack", "POST", "/submit"))
        .await;
    assert!(matches!(headers.decision, Decision::Allow));
    let body = agent
        .on_request_body_chunk(body_event("attack", "id=1 UNION SELECT password", 0, true))
        .await;
    assert!(
        matches!(body.decision, Decision::Block { status: 403, .. }),
        "an attack during a drain must be blocked by the rules, got {:?}",
        body.decision
    );
}

/// The drain is bounded by its duration: afterwards health is `Healthy`
/// again (the protocol has no "resume" message).
#[tokio::test]
async fn health_is_healthy_again_after_the_drain_window() {
    let dir = tempfile::tempdir().unwrap();
    let agent = agent(&dir, true);

    agent.on_drain(20, DrainReason::ConfigReload).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let response = agent
        .on_request_headers(headers_event("after", "GET", "/"))
        .await;
    assert!(matches!(response.decision, Decision::Allow));
    assert!(matches!(agent.health_status().state, HealthState::Healthy));
}
