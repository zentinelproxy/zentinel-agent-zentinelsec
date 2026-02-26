# zentinel-agent-zentinelsec

A pure Rust ModSecurity-compatible WAF agent for [Zentinel](https://github.com/zentinelproxy/zentinel) reverse proxy. Provides full OWASP Core Rule Set (CRS) support with **zero C dependencies** - no libmodsecurity required.

> **Note:** CRS compatibility depends on the [zentinel-modsec](https://github.com/zentinelproxy/zentinel-modsec) engine, a pure Rust reimplementation of libmodsecurity. If you encounter unsupported SecLang features, please [file an issue](https://github.com/zentinelproxy/zentinel-agent-zentinelsec/issues).

## Features

- **Full OWASP CRS Compatibility**: Parse and execute 800+ CRS rules
- **Pure Rust Implementation**: No libmodsecurity or C dependencies
- **Built-in SQLi/XSS Detection**: Native `@detectSQLi` and `@detectXSS` operators
- **SecLang Support**: Load standard ModSecurity rule files
- **Request Body Inspection**: JSON, form data, XML, and all content types
- **Response Body Inspection**: Detect data leakage (opt-in)
- **Block or Detect-Only Mode**: Monitor before blocking
- **Path Exclusions**: Skip inspection for trusted paths
- **Zero Installation Hassle**: Just `cargo install`, no system dependencies

## Comparison with Other WAF Agents

| Feature | ZentinelSec | ModSec | WAF |
|---------|-------------|--------|-----|
| Detection Rules | 800+ CRS rules | 800+ CRS rules | 285 rules |
| SecLang Support | Yes | Yes | No |
| Custom Rules | Yes | Yes | No |
| @detectSQLi/@detectXSS | Yes (pure Rust) | Yes (C lib) | No |
| Dependencies | **Pure Rust** | libmodsecurity (C) | Pure Rust |
| Binary Size | ~10MB | ~50MB | ~5MB |
| Installation | `cargo install` | Requires libmodsecurity | `cargo install` |

**ZentinelSec combines the best of both worlds**: Full CRS compatibility like ModSec, with zero-dependency installation like WAF.

## Installation

### Using Bundle (Recommended)

```bash
# Install just this agent
zentinel bundle install zentinelsec

# Or install all bundled agents
zentinel bundle install
```

The bundle command downloads the correct binary for your platform and places it in the standard location. See the [bundle documentation](https://zentinelproxy.io/docs/deployment/bundle/) for details.

### Using Cargo

```bash
cargo install zentinel-agent-zentinelsec
```

### From Source

```bash
git clone https://github.com/zentinelproxy/zentinel-agent-zentinelsec
cd zentinel-agent-zentinelsec
cargo build --release
```

## Usage

```bash
zentinel-zentinelsec-agent \
  --socket /var/run/zentinel/zentinelsec.sock \
  --rules /etc/modsecurity/crs/crs-setup.conf \
  --rules "/etc/modsecurity/crs/rules/*.conf"
```

### Command Line Options

| Option | Environment Variable | Description | Default |
|--------|---------------------|-------------|---------|
| `--socket` | `AGENT_SOCKET` | Unix socket path | `/tmp/zentinel-zentinelsec.sock` |
| `--rules` | `ZENTINELSEC_RULES` | Rule file paths (glob patterns supported) | - |
| `--block-mode` | `ZENTINELSEC_BLOCK_MODE` | Block (true) or detect-only (false) | `true` |
| `--exclude-paths` | `ZENTINELSEC_EXCLUDE_PATHS` | Paths to exclude (comma-separated) | - |
| `--body-inspection` | `ZENTINELSEC_BODY_INSPECTION` | Enable request body inspection | `true` |
| `--max-body-size` | `ZENTINELSEC_MAX_BODY_SIZE` | Maximum body size to inspect (bytes) | `1048576` (1MB) |
| `--response-inspection` | `ZENTINELSEC_RESPONSE_INSPECTION` | Enable response body inspection | `false` |
| `--verbose`, `-v` | `ZENTINELSEC_VERBOSE` | Enable debug logging | `false` |

## OWASP CRS Setup

### Download CRS

```bash
# Clone the CRS repository
sudo mkdir -p /etc/modsecurity
sudo git clone https://github.com/coreruleset/coreruleset /etc/modsecurity/crs

# Copy example configuration
sudo cp /etc/modsecurity/crs/crs-setup.conf.example /etc/modsecurity/crs/crs-setup.conf
```

### Run with CRS

```bash
zentinel-zentinelsec-agent \
  --socket /var/run/zentinel/zentinelsec.sock \
  --rules /etc/modsecurity/crs/crs-setup.conf \
  --rules "/etc/modsecurity/crs/rules/*.conf"
```

## Zentinel Configuration

```kdl
agents {
    agent "zentinelsec" {
        type "custom"
        transport "unix_socket" {
            path "/var/run/zentinel/zentinelsec.sock"
        }
        events "request_headers" "request_body_chunk" "response_body_chunk"
        timeout-ms 100
        failure-mode "open"
    }
}

routes {
    route "all" {
        matches { path-prefix "/" }
        upstream "backend"
        agents "zentinelsec"
    }
}
```

## Paranoia Levels

Configure in `/etc/modsecurity/crs/crs-setup.conf`:

```apache
SecAction "id:900000,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=1"
```

| Level | Description | Use Case |
|-------|-------------|----------|
| 1 | Standard protection, minimal false positives | Production - most applications |
| 2 | Elevated protection, some false positives | Security-sensitive apps |
| 3 | High protection, moderate false positives | Staging/testing, or with tuning |
| 4 | Maximum protection, high false positives | Security research |

## Response Headers

| Header | Description |
|--------|-------------|
| `X-WAF-Blocked` | `true` if request was blocked |
| `X-WAF-Rule` | Rule ID that triggered the block |
| `X-WAF-Message` | Detection message |
| `X-WAF-Detected` | Detection message (detect-only mode) |

## CRS Rule Categories

| File Pattern | Protection |
|--------------|------------|
| REQUEST-913-* | Scanner detection |
| REQUEST-920-* | Protocol enforcement |
| REQUEST-930-* | Local file inclusion (LFI) |
| REQUEST-931-* | Remote file inclusion (RFI) |
| REQUEST-932-* | Remote code execution (RCE) |
| REQUEST-941-* | Cross-site scripting (XSS) |
| REQUEST-942-* | SQL injection |
| REQUEST-943-* | Session fixation |
| REQUEST-944-* | Java attacks |
| RESPONSE-950-* | Data leakage |

## Docker/Kubernetes

```yaml
# Environment variables
env:
  - name: AGENT_SOCKET
    value: "/var/run/zentinel/zentinelsec.sock"
  - name: ZENTINELSEC_RULES
    value: "/etc/modsecurity/crs/crs-setup.conf,/etc/modsecurity/crs/rules/*.conf"
  - name: ZENTINELSEC_BLOCK_MODE
    value: "true"
  - name: ZENTINELSEC_EXCLUDE_PATHS
    value: "/health,/metrics"
```

## Writing Custom Rules

Create custom rules using SecLang syntax:

```apache
# /etc/modsecurity/custom-rules.conf

# Block requests with specific user-agent
SecRule REQUEST_HEADERS:User-Agent "@contains badbot" \
    "id:100001,phase:1,deny,status:403,msg:'Bad bot detected'"

# Detect sensitive data in responses
SecRule RESPONSE_BODY "@rx \b\d{3}-\d{2}-\d{4}\b" \
    "id:100002,phase:4,deny,status:500,msg:'SSN detected in response'"
```

Load custom rules:

```bash
zentinel-zentinelsec-agent \
  --rules /etc/modsecurity/crs/crs-setup.conf \
  --rules "/etc/modsecurity/crs/rules/*.conf" \
  --rules /etc/modsecurity/custom-rules.conf
```

## Development

```bash
# Run with debug logging
RUST_LOG=debug cargo run -- --socket /tmp/test.sock --rules ./test-rules.conf

# Run tests
cargo test

# Build release binary
cargo build --release
```

## Architecture

ZentinelSec uses [zentinel-modsec](https://github.com/zentinelproxy/zentinel-modsec), a pure Rust reimplementation of libmodsecurity:

- **Parser**: Full SecLang parser for SecRule, SecAction, SecMarker directives
- **Variables**: REQUEST_URI, ARGS, REQUEST_HEADERS, TX collections, and more
- **Operators**: 37+ operators including @rx, @pm, @detectSQLi, @detectXSS
- **Transformations**: 35+ transformations (urlDecode, base64Decode, lowercase, etc.)
- **Engine**: 5-phase transaction processing with rule chaining and anomaly scoring

## Related Agents

| Agent | Use Case |
|-------|----------|
| **[ModSec](/agents/modsec/)** | C-based libmodsecurity (if you need maximum compatibility) |
| **[WAF](/agents/waf/)** | Lightweight, ~20 rules (if you need minimal overhead) |
| **[AI Gateway](/agents/ai-gateway/)** | AI/LLM-specific security controls |

## License

Apache-2.0
