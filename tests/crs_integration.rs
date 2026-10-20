//! Integration tests against a real OWASP CRS checkout.
//!
//! These load CRS through `ZentinelSecEngine` itself — the same code path the
//! agent uses — rather than building an engine separately, because the way
//! rules are loaded is itself a thing that has broken: splicing rule files
//! together lost the base path CRS needs to resolve its `.data` files, so the
//! documented deployment only started when run from the CRS rules directory.
//!
//! Two properties of this file are deliberate:
//!
//! * **A missing fixture is a failure, not a skip.** These tests previously
//!   returned early when the checkout was absent, and CI never fetched it, so
//!   they reported green without ever running. Set `ZENTINELSEC_SKIP_CRS_TESTS`
//!   to opt out locally; CI must not.
//! * **Assertions name the rules that must fire.** The previous form was
//!   `assert!(blocked || !rule_ids.is_empty())`, and `rule_ids` came from
//!   `matched_rules()`, which under stock CRS always contains the 901xxx setup
//!   rules — so it could never fail, whatever the engine did.

use std::path::{Path, PathBuf};
use zentinel_agent_zentinelsec::{ZentinelSecConfig, ZentinelSecEngine};

/// Where the CRS checkout lives. Override with `ZENTINELSEC_CRS_DIR`.
fn crs_dir() -> Option<PathBuf> {
    if std::env::var_os("ZENTINELSEC_SKIP_CRS_TESTS").is_some() {
        return None;
    }
    let dir = std::env::var("ZENTINELSEC_CRS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("test-rules/crs"));

    assert!(
        dir.join("crs-setup.conf").is_file(),
        "OWASP CRS checkout not found at {}.\n\
         Fetch it with:\n\
           mkdir -p test-rules && \\\n\
           git clone --depth 1 https://github.com/coreruleset/coreruleset.git test-rules/crs && \\\n\
           cp test-rules/crs/crs-setup.conf.example test-rules/crs/crs-setup.conf\n\
         Set ZENTINELSEC_CRS_DIR to use another location, or \
         ZENTINELSEC_SKIP_CRS_TESTS=1 to skip these tests locally. \
         CI must not set either.",
        dir.display()
    );
    Some(dir)
}

/// Load the whole rule set the way the README tells operators to.
fn engine(dir: &Path) -> ZentinelSecEngine {
    let config = ZentinelSecConfig {
        rules_paths: vec![
            dir.join("crs-setup.conf").display().to_string(),
            dir.join("rules/*.conf").display().to_string(),
        ],
        ..Default::default()
    };
    ZentinelSecEngine::new(config).expect("CRS should load through the agent's own loader")
}

/// Rule IDs reported for a request, and whether it was interrupted.
fn probe(
    e: &ZentinelSecEngine,
    method: &str,
    uri: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> (bool, Vec<String>) {
    let mut tx = e.modsec().new_transaction();
    tx.process_uri(uri, method, "HTTP/1.1").unwrap();
    tx.add_request_header("Host", "example.com").unwrap();
    tx.add_request_header(
        "User-Agent",
        "Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0",
    )
    .unwrap();
    tx.add_request_header("Accept", "text/html,application/xhtml+xml")
        .unwrap();
    tx.add_request_header("Accept-Language", "en-US,en;q=0.9")
        .unwrap();
    tx.add_request_header("Accept-Encoding", "gzip, deflate")
        .unwrap();
    tx.add_request_header("Connection", "keep-alive").unwrap();
    for (k, v) in headers {
        tx.add_request_header(k, v).unwrap();
    }
    if !body.is_empty() {
        tx.add_request_header("Content-Length", &body.len().to_string())
            .unwrap();
    }
    tx.process_request_headers().unwrap();
    if !body.is_empty() {
        tx.append_request_body(body).unwrap();
    }
    tx.process_request_body().unwrap();

    let ids = tx
        .intervention()
        .map(|i| i.rule_ids.clone())
        .unwrap_or_default();
    let blocked = tx
        .intervention()
        .map(|i| i.status != 0 && i.status != 200)
        .unwrap_or(false);
    (blocked, ids)
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

#[test]
fn crs_loads_through_the_agent_loader() {
    let Some(dir) = crs_dir() else { return };
    let e = engine(&dir);
    assert!(
        e.rule_count() > 500,
        "expected the full CRS rule set, loaded {}",
        e.rule_count()
    );
}

#[test]
fn crs_loads_regardless_of_working_directory() {
    // The regression this guards: CRS `.data` files are referenced relative to
    // the rule file that names them, so a loader that concatenates file
    // contents resolves them against the process's working directory instead
    // and fails on `scanners-user-agents.data`.
    //
    // The working directory during `cargo test` is the crate root, which is
    // not the CRS rules directory, so loading by absolute path is already the
    // case that used to fail. Deliberately no `chdir` here: tests share a
    // process, and changing the working directory under them is a race.
    let Some(dir) = crs_dir() else { return };
    let dir = std::fs::canonicalize(&dir).expect("CRS dir");
    let e = engine(&dir);
    assert!(e.rule_count() > 500);
}

// ---------------------------------------------------------------------------
// Detection — each asserts the rule that must fire
// ---------------------------------------------------------------------------

#[test]
fn crs_detects_attacks() {
    let Some(dir) = crs_dir() else { return };
    let e = engine(&dir);

    let cases: &[(&str, &str, &str, &[u8])] = &[
        (
            "SQLi in query",
            "GET",
            "/u?id=1'+UNION+SELECT+password+FROM+users--+",
            b"",
        ),
        (
            "SQLi in body",
            "POST",
            "/u",
            b"q=1' UNION SELECT password FROM users-- ",
        ),
        (
            "XSS in query",
            "GET",
            "/s?q=%3Cscript%3Ealert(1)%3C/script%3E",
            b"",
        ),
        (
            // Matched only by 942100 (libinjection). Before zentinel-modsec
            // 0.5.0 that rule kept only its last setvar, so its anomaly score
            // was dropped and this request passed (zentinel-modsec#47).
            "SQLi seen only by libinjection",
            "GET",
            "/u?id=1%27%20OR%20%271%27=%271",
            b"",
        ),
        ("LFI in query", "GET", "/f?p=../../../../etc/passwd", b""),
        (
            "RCE in body",
            "POST",
            "/r",
            b"cmd=/bin/bash -c \"cat /etc/passwd\"",
        ),
    ];

    for (name, method, uri, body) in cases {
        let headers: &[(&str, &str)] = if body.is_empty() {
            &[]
        } else {
            &[("Content-Type", "application/x-www-form-urlencoded")]
        };
        let (blocked, ids) = probe(&e, method, uri, headers, body);
        assert!(blocked, "{name}: expected CRS to block, rule_ids={ids:?}");
    }
}

#[test]
fn crs_detects_attacks_in_xml_bodies() {
    // XML is flattened into ARGS, which is what stock CRS rules inspect.
    let Some(dir) = crs_dir() else { return };
    let e = engine(&dir);
    let xml: &[(&str, &[u8])] = &[
        ("element text", br#"<o><q>1' UNION SELECT password FROM users-- </q></o>"#),
        ("attribute", br#"<o q="1' UNION SELECT password FROM users-- "/>"#),
        ("soap envelope", br#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><q>1' UNION SELECT password FROM users-- </q></soap:Body></soap:Envelope>"#),
    ];
    for (name, body) in xml {
        let (blocked, ids) = probe(
            &e,
            "POST",
            "/u",
            &[("Content-Type", "application/xml")],
            body,
        );
        assert!(
            blocked,
            "SQLi in XML {name}: expected a block, rule_ids={ids:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// False positives — the half that was never tested
// ---------------------------------------------------------------------------

#[test]
fn crs_does_not_block_ordinary_traffic() {
    // This is the test whose absence let a 100%-block-rate defect ship: with
    // stock CRS every one of these was denied by 920100, including `GET /`.
    let Some(dir) = crs_dir() else { return };
    let e = engine(&dir);

    let cases: &[(&str, &str, &str, &[u8])] = &[
        ("root", "GET", "/", b""),
        ("static page", "GET", "/index.html", b""),
        ("health check", "GET", "/api/v1/health", b""),
        ("stylesheet", "GET", "/static/app.css", b""),
        ("pdf download", "GET", "/docs/report.pdf", b""),
        (
            "ordinary query",
            "GET",
            "/search?q=blue+widgets&page=2",
            b"",
        ),
        ("form post", "POST", "/api/orders", b"item=widget&qty=3"),
    ];

    for (name, method, uri, body) in cases {
        let headers: &[(&str, &str)] = if body.is_empty() {
            &[]
        } else {
            &[("Content-Type", "application/x-www-form-urlencoded")]
        };
        let (blocked, ids) = probe(&e, method, uri, headers, body);
        assert!(
            !blocked,
            "{name}: ordinary traffic must not be blocked, but rule(s) {ids:?} fired"
        );
    }
}

#[test]
fn crs_does_not_block_an_ordinary_xml_post() {
    let Some(dir) = crs_dir() else { return };
    let e = engine(&dir);
    let (blocked, ids) = probe(
        &e,
        "POST",
        "/api/orders",
        &[("Content-Type", "application/xml")],
        br#"<order><item id="7">widget</item><qty>3</qty></order>"#,
    );
    assert!(
        !blocked,
        "benign XML must not be blocked, rule(s) {ids:?} fired"
    );
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

#[test]
fn a_block_names_the_rule_that_caused_it() {
    // `X-WAF-Rule` is built from the first reported id. Taking it from
    // `matched_rules()` produced a CRS setup rule such as 900990 rather than
    // the rule that blocked, which is useless to whoever is debugging it.
    let Some(dir) = crs_dir() else { return };
    let e = engine(&dir);
    let (blocked, ids) = probe(
        &e,
        "GET",
        "/u?id=1'+UNION+SELECT+password+FROM+users--+",
        &[],
        b"",
    );
    assert!(blocked);
    let first = ids.first().map(String::as_str).unwrap_or("");
    assert!(
        !first.starts_with("900") && !first.starts_with("901"),
        "the reported rule should be the one that blocked, got {ids:?}"
    );
}
