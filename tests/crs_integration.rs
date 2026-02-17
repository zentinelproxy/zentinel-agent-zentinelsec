//! Integration tests with real OWASP CRS rules.
//!
//! These tests require the CRS rules to be downloaded:
//! ```
//! mkdir -p test-rules && cd test-rules
//! git clone --depth 1 https://github.com/coreruleset/coreruleset.git crs
//! cp crs/crs-setup.conf.example crs/crs-setup.conf
//! ```

use std::path::Path;

fn crs_available() -> bool {
    Path::new("test-rules/crs/crs-setup.conf").exists()
}

fn load_crs() -> zentinel_modsec::ModSecurity {
    // Load CRS setup first, then specific rule files
    let mut rules_content = String::new();

    // Enable SecRuleEngine
    rules_content.push_str("SecRuleEngine On\n");
    rules_content.push_str("SecRequestBodyAccess On\n");

    // Load crs-setup.conf
    let setup = std::fs::read_to_string("test-rules/crs/crs-setup.conf")
        .expect("Failed to read crs-setup.conf");
    rules_content.push_str(&setup);
    rules_content.push('\n');

    // Load specific rule files for testing (not all, to keep tests fast)
    let rule_files = [
        "test-rules/crs/rules/REQUEST-901-INITIALIZATION.conf",
        "test-rules/crs/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf",
        "test-rules/crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
        "test-rules/crs/rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf",
        "test-rules/crs/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf",
    ];

    for path in &rule_files {
        if Path::new(path).exists() {
            let content = std::fs::read_to_string(path)
                .unwrap_or_else(|_| panic!("Failed to read {}", path));
            rules_content.push_str(&content);
            rules_content.push('\n');
        }
    }

    zentinel_modsec::ModSecurity::from_string(&rules_content)
        .expect("Failed to parse CRS rules")
}

#[test]
fn test_crs_loads_successfully() {
    if !crs_available() {
        eprintln!("Skipping CRS test - rules not downloaded. Run:");
        eprintln!("  cd test-rules && git clone --depth 1 https://github.com/coreruleset/coreruleset.git crs");
        return;
    }

    let modsec = load_crs();
    let rule_count = modsec.rule_count();
    println!("Loaded {} CRS rules", rule_count);
    assert!(rule_count > 0, "Expected at least some rules to load");
}

#[test]
fn test_crs_sql_injection_942100() {
    if !crs_available() {
        eprintln!("Skipping CRS test - rules not downloaded");
        return;
    }

    let modsec = load_crs();

    // Test classic SQL injection patterns
    let sqli_payloads = [
        "/api/users?id=1' OR '1'='1",
        "/api/users?id=1; DROP TABLE users--",
        "/api/users?id=1 UNION SELECT * FROM passwords--",
        "/search?q=' OR 1=1--",
        "/login?user=admin'--",
    ];

    println!("\n=== CRS SQL Injection Detection ===");
    for payload in &sqli_payloads {
        let mut tx = modsec.new_transaction();
        tx.process_uri(payload, "GET", "HTTP/1.1").unwrap();
        tx.add_request_header("Host", "example.com").unwrap();
        tx.process_request_headers().unwrap();

        let blocked = tx.intervention().map(|i| i.status != 0 && i.status != 200).unwrap_or(false);
        let rule_ids: Vec<_> = tx.matched_rules().to_vec();

        println!("  {} => {} {:?}",
            payload,
            if blocked { "BLOCKED" } else { "allowed" },
            rule_ids
        );

        assert!(blocked || !rule_ids.is_empty(),
            "Expected SQLi to be detected: {}", payload);
    }
}

#[test]
fn test_crs_xss_941100() {
    if !crs_available() {
        eprintln!("Skipping CRS test - rules not downloaded");
        return;
    }

    let modsec = load_crs();

    // Test XSS patterns
    let xss_payloads = [
        "/search?q=<script>alert(1)</script>",
        "/search?q=<img src=x onerror=alert(1)>",
        "/search?q=javascript:alert(document.cookie)",
        "/page?content=<svg onload=alert(1)>",
        "/comment?text=<body onload=alert('XSS')>",
    ];

    println!("\n=== CRS XSS Detection ===");
    for payload in &xss_payloads {
        let mut tx = modsec.new_transaction();
        tx.process_uri(payload, "GET", "HTTP/1.1").unwrap();
        tx.add_request_header("Host", "example.com").unwrap();
        tx.process_request_headers().unwrap();

        let blocked = tx.intervention().map(|i| i.status != 0 && i.status != 200).unwrap_or(false);
        let rule_ids: Vec<_> = tx.matched_rules().to_vec();

        println!("  {} => {} {:?}",
            payload,
            if blocked { "BLOCKED" } else { "allowed" },
            rule_ids
        );

        assert!(blocked || !rule_ids.is_empty(),
            "Expected XSS to be detected: {}", payload);
    }
}

#[test]
fn test_crs_path_traversal_930100() {
    if !crs_available() {
        eprintln!("Skipping CRS test - rules not downloaded");
        return;
    }

    let modsec = load_crs();

    // Test path traversal patterns
    let lfi_payloads = [
        "/download?file=../../../etc/passwd",
        "/read?path=....//....//etc/shadow",
        "/view?doc=/etc/passwd",
        "/include?page=..\\..\\..\\windows\\system32\\config\\sam",
    ];

    println!("\n=== CRS Path Traversal Detection ===");
    for payload in &lfi_payloads {
        let mut tx = modsec.new_transaction();
        tx.process_uri(payload, "GET", "HTTP/1.1").unwrap();
        tx.add_request_header("Host", "example.com").unwrap();
        tx.process_request_headers().unwrap();

        let blocked = tx.intervention().map(|i| i.status != 0 && i.status != 200).unwrap_or(false);
        let rule_ids: Vec<_> = tx.matched_rules().to_vec();

        println!("  {} => {} {:?}",
            payload,
            if blocked { "BLOCKED" } else { "allowed" },
            rule_ids
        );

        assert!(blocked || !rule_ids.is_empty(),
            "Expected LFI to be detected: {}", payload);
    }
}

#[test]
fn test_crs_command_injection_932100() {
    if !crs_available() {
        eprintln!("Skipping CRS test - rules not downloaded");
        return;
    }

    let modsec = load_crs();

    // Test command injection patterns
    let rce_payloads = [
        "/ping?host=127.0.0.1;cat /etc/passwd",
        "/exec?cmd=|ls -la",
        "/run?command=`id`",
        "/process?input=$(whoami)",
    ];

    println!("\n=== CRS Command Injection Detection ===");
    for payload in &rce_payloads {
        let mut tx = modsec.new_transaction();
        tx.process_uri(payload, "GET", "HTTP/1.1").unwrap();
        tx.add_request_header("Host", "example.com").unwrap();
        tx.process_request_headers().unwrap();

        let blocked = tx.intervention().map(|i| i.status != 0 && i.status != 200).unwrap_or(false);
        let rule_ids: Vec<_> = tx.matched_rules().to_vec();

        println!("  {} => {} {:?}",
            payload,
            if blocked { "BLOCKED" } else { "allowed" },
            rule_ids
        );

        assert!(blocked || !rule_ids.is_empty(),
            "Expected RCE to be detected: {}", payload);
    }
}

#[test]
fn test_crs_clean_requests_pass() {
    if !crs_available() {
        eprintln!("Skipping CRS test - rules not downloaded");
        return;
    }

    let modsec = load_crs();

    // Test legitimate requests
    let clean_requests = [
        ("/", "GET"),
        ("/api/users", "GET"),
        ("/api/users/123", "GET"),
        ("/search?q=hello+world", "GET"),
        ("/products?category=electronics&page=1", "GET"),
        ("/login", "POST"),
    ];

    println!("\n=== CRS Clean Requests ===");
    for (path, method) in &clean_requests {
        let mut tx = modsec.new_transaction();
        tx.process_uri(path, method, "HTTP/1.1").unwrap();
        tx.add_request_header("Host", "example.com").unwrap();
        tx.add_request_header("User-Agent", "Mozilla/5.0").unwrap();
        tx.process_request_headers().unwrap();

        let blocked = tx.intervention().map(|i| i.status != 0 && i.status != 200).unwrap_or(false);
        let rule_ids: Vec<_> = tx.matched_rules().to_vec();

        println!("  {} {} => {} {:?}",
            method, path,
            if blocked { "BLOCKED" } else { "allowed" },
            rule_ids
        );

        // Clean requests should not be blocked
        assert!(!blocked,
            "Clean request should not be blocked: {} {}", method, path);
    }
}

#[test]
fn test_crs_post_body_sqli() {
    if !crs_available() {
        eprintln!("Skipping CRS test - rules not downloaded");
        return;
    }

    let modsec = load_crs();

    println!("\n=== CRS POST Body SQL Injection ===");

    let mut tx = modsec.new_transaction();
    tx.process_uri("/api/login", "POST", "HTTP/1.1").unwrap();
    tx.add_request_header("Host", "example.com").unwrap();
    tx.add_request_header("Content-Type", "application/x-www-form-urlencoded").unwrap();
    tx.process_request_headers().unwrap();

    // Add SQL injection in POST body
    let body = b"username=admin&password=' OR '1'='1' --";
    tx.append_request_body(body).unwrap();
    tx.process_request_body().unwrap();

    let blocked = tx.intervention().map(|i| i.status != 0 && i.status != 200).unwrap_or(false);
    let rule_ids: Vec<_> = tx.matched_rules().to_vec();

    println!("  POST body SQLi => {} {:?}",
        if blocked { "BLOCKED" } else { "allowed" },
        rule_ids
    );

    assert!(blocked || !rule_ids.is_empty(),
        "Expected POST body SQLi to be detected");
}
