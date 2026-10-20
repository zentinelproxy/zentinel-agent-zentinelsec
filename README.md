# zentinel-agent-zentinelsec

A pure Rust ModSecurity-compatible WAF agent for [Zentinel](https://github.com/zentinelproxy/zentinel) reverse proxy. Loads the OWASP Core Rule Set with **zero C dependencies** - no libmodsecurity required.

> **CRS compatibility is measured, not assumed.** Detection comes from the
> [zentinel-modsec](https://github.com/zentinelproxy/zentinel-modsec) engine, a
> pure Rust reimplementation of libmodsecurity, which is run against the OWASP
> CRS regression suite on every push. See
> [CRS conformance](#crs-conformance) for the current number and the known gaps
> before deploying this in blocking mode.

## Features

- **Loads the stock OWASP CRS**: all 703 rules of CRS 4.30 parse and execute; see [CRS conformance](#crs-conformance)
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
| Detection Rules | stock CRS, [conformance measured](#crs-conformance) | stock CRS (reference implementation) | 285 rules |
| SecLang Support | Yes | Yes | No |
| Custom Rules | Yes | Yes | No |
| @detectSQLi/@detectXSS | Yes (pure Rust) | Yes (C lib) | No |
| Dependencies | **Pure Rust** | libmodsecurity (C) | Pure Rust |
| Binary Size | ~10MB | ~50MB | ~5MB |
| Installation | `cargo install` | Requires libmodsecurity | `cargo install` |

**ZentinelSec aims to combine the two**: the stock CRS rule set like ModSec, with
zero-dependency installation like WAF. Unlike ModSec it is not the reference
implementation of SecLang, so its CRS behaviour is
[measured against the upstream regression suite](#crs-conformance) rather than
taken as given.

## CRS conformance

Detection is provided by [zentinel-modsec](https://github.com/zentinelproxy/zentinel-modsec),
which runs the OWASP CRS regression suite — roughly 5,000 request/expectation
pairs naming the rule IDs that must or must not fire — on every push.

| | |
|---|---|
| Corpus | CRS `main` (4.31.0-dev), 5,184 runnable cases |
| Passing | **4,806 (92.7%)** |

That corpus runs in `DetectionOnly` at paranoia level 4, which is how CRS
documents it. It measures whether individual rules **match**; it does not
measure whether the WAF **decides** correctly, because in that mode nothing
blocks and the anomaly score never reaches rule 949110. Both properties are
tested, separately, in that repository.

### Before deploying in blocking mode

`--block-mode` defaults to `true`. Stock CRS is tested in exactly that
configuration — `crs_does_not_block_ordinary_traffic` and `crs_detects_attacks`
in `tests/crs_integration.rs` assert that ordinary requests pass and attacks are
blocked, against a real CRS checkout.

> **Upgrade from builds on `zentinel-modsec` 0.4.x.** 0.4.0 ran only the last
> `setvar` of each rule, so CRS anomaly scores were dropped: an SQLi that only
> libinjection (942100) catches was detected and let through
> ([zentinel-modsec#47](https://github.com/zentinelproxy/zentinel-modsec/issues/47)).
> It also loaded nothing past the first line of a rule file with CRLF line
> endings ([#44](https://github.com/zentinelproxy/zentinel-modsec/pull/44)).
>
> Versions of `zentinel-modsec` before 0.4.0 deny **every** request under stock
> CRS, `GET /` included, because CRS 920100 tests an unimplemented
> `REQUEST_LINE` with a negated regex
> ([zentinel-modsec#29](https://github.com/zentinelproxy/zentinel-modsec/issues/29)).
> They also miss payloads that encode spaces as `+`, or that percent-encode the
> `=` in a form body ([#34](https://github.com/zentinelproxy/zentinel-modsec/issues/34),
> [#38](https://github.com/zentinelproxy/zentinel-modsec/issues/38)) — both
> straightforward bypasses.

## Installation

### Using Bundle (Recommended)

```bash
# Install just this agent
zentinel bundle install zentinelsec

# Or install all bundled agents
zentinel bundle install
```

The bundle command downloads the correct binary for your platform and places it in the standard location. See the [bundle documentation](https://docs.zentinelproxy.io/deployment/bundle/) for details.

### Using Cargo

`zentinel-agent-zentinelsec` is not published on crates.io, so `cargo install zentinel-agent-zentinelsec` does not
work. Install straight from the repository instead:

```bash
cargo install --git https://github.com/zentinelproxy/zentinel-agent-zentinelsec
```

This builds and installs the `zentinel-zentinelsec-agent` binary.

### Prebuilt Binaries

Each [release](https://github.com/zentinelproxy/zentinel-agent-zentinelsec/releases) ships binaries
for `linux-x86_64`, `linux-aarch64`, and `darwin-aarch64`:

```bash
VERSION=0.3.0
PLATFORM=linux-x86_64   # or linux-aarch64, darwin-aarch64
curl -fsSL -o zentinel-zentinelsec-agent.tar.gz \
  "https://github.com/zentinelproxy/zentinel-agent-zentinelsec/releases/download/v${VERSION}/zentinel-zentinelsec-agent-${VERSION}-${PLATFORM}.tar.gz"
tar -xzf zentinel-zentinelsec-agent.tar.gz
sudo install -m 0755 zentinel-zentinelsec-agent /usr/local/bin/
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
