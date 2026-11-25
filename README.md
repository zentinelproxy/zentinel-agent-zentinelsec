<p align="center">
  <a href="https://zentinelproxy.io">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/banner/zentinel-agent-zentinelsec-banner-on-dark.svg">
      <img alt="Zentinel ZentinelSec agent" src="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/banner/zentinel-agent-zentinelsec-banner-on-light.svg" height="64">
    </picture>
  </a>
</p>

<h3 align="center">ZentinelSec agent</h3>

<p align="center">Runs ModSecurity rules, including the stock OWASP Core Rule Set, on request headers and bodies with a pure-Rust engine and no C dependencies.</p>

<p align="center">
  <a href="https://github.com/zentinelproxy/zentinel-agent-zentinelsec/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/zentinelproxy/zentinel-agent-zentinelsec/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-9b4d8a?style=flat&labelColor=1f161e">
  <img alt="Rust: 1.94.1+" src="https://img.shields.io/badge/rust-1.94.1%2B-f68d31?style=flat&labelColor=1f161e&logo=rust&logoColor=white">
  <img alt="Agent protocol: v2" src="https://img.shields.io/badge/agent%20protocol-v2-f68d31?style=flat&labelColor=1f161e">
</p>

<p align="center">
  <a href="https://registry.zentinelproxy.io/zentinelsec/">Registry</a> &middot;
  <a href="https://docs.zentinelproxy.io">Docs</a> &middot;
  <a href="https://github.com/zentinelproxy">All repositories</a>
</p>

This agent evaluates SecLang rules with
[zentinel-modsec](https://github.com/zentinelproxy/zentinel-modsec), a pure-Rust
reimplementation of libmodsecurity, and blocks with the status the rules ask
for. It loads the stock OWASP CRS unchanged and ships as a single binary with
nothing to install beside it.

**Which ModSecurity agent?** This one uses the Rust engine. Its sibling
[zentinel-agent-modsec](https://github.com/zentinelproxy/zentinel-agent-modsec)
wraps the C libmodsecurity, the reference implementation, and needs that
library installed wherever it runs. Because this engine is a reimplementation,
its CRS behavior is measured rather than assumed (see
[CRS conformance](#crs-conformance)); choose modsec when you need the reference
behavior.

> **Known limitations** (checked against stock CRS on 2026-10-21):
>
> - Up to 0.3.0, phase 2 rules ran only when a request had a body. Most CRS
>   detection, and the blocking evaluation in rule 949110, is phase 2, so an
>   attack in the query string of a `GET` passed. Fixed in 0.4.0.
> - A body larger than `--max-body-size` is passed on uninspected.
> - `--response-inspection` is accepted but response bodies are not inspected.
> - The agent listens on gRPC only; there is no Unix-socket mode.
> - Up to 0.5.0, with the CRS at blocking paranoia level 3, attacks were not
>   blocked: a `skipAfter` off-by-one in the engine ended phase 2 before the
>   blocking evaluation. Fixed in 0.5.1, built on zentinel-modsec 0.8.1
>   ([zentinel-modsec#97](https://github.com/zentinelproxy/zentinel-modsec/pull/97)).
>   Levels 1, 2 and 4 were not affected.
> - Up to 0.4.1 (built on zentinel-modsec 0.5.0), `@detectSQLi` was an
>   approximation of libinjection that flagged ordinary crawler User-Agents, so
>   stock CRS blocked Googlebot, bingbot, AhrefsBot and others (rule 942100,
>   then 949110). Fixed in 0.5.0, built on zentinel-modsec 0.8.0
>   ([zentinel-modsec#84](https://github.com/zentinelproxy/zentinel-modsec/issues/84)).
> - Release 0.3.0 is built on zentinel-modsec 0.1 and does not run stock CRS:
>   it exits at startup on current CRS with
>   `unknown variable: MULTIPART_PART_HEADERS`. The bundle installs 0.4.1 from
>   Zentinel 26.10_9 on; earlier releases install 0.3.0.

## Quick start

```bash
# 1. The OWASP CRS
sudo git clone https://github.com/coreruleset/coreruleset /etc/modsecurity/crs
sudo cp /etc/modsecurity/crs/crs-setup.conf.example /etc/modsecurity/crs/crs-setup.conf

# 2. The agent, built from main (see Known limitations)
cargo install --git https://github.com/zentinelproxy/zentinel-agent-zentinelsec

# 3. Run it (crs-setup.conf first)
zentinel-zentinelsec-agent \
  --grpc-address 127.0.0.1:50051 \
  --rules /etc/modsecurity/crs/crs-setup.conf \
  --rules "/etc/modsecurity/crs/rules/*.conf"
```

Then point Zentinel at it. Request bodies reach agents only when the top-level
`waf` block enables body inspection:

```kdl
system {
    worker-threads 0
}

listeners {
    listener "http" {
        address "127.0.0.1:8080"
        protocol "http"
    }
}

// Request bodies reach agents only when this block enables them.
waf {
    mode "off"
    body-inspection {
        inspect-request-body #true
        max-inspection-bytes 1048576
    }
}

agents {
    agent "zentinelsec" type="waf" {
        grpc "http://127.0.0.1:50051"
        events "request_headers" "request_body"
        timeout-ms 200
        failure-mode "closed"
    }
}

filters {
    filter "zentinelsec" {
        type "agent"
        agent "zentinelsec"
        failure-mode "closed"
    }
}

routes {
    route "default" {
        matches {
            path-prefix "/"
        }
        upstream "backend"
        filters "zentinelsec"
    }
}

upstreams {
    upstream "backend" {
        target "127.0.0.1:3000"
    }
}
```

`failure-mode "closed"` on the filter rejects requests while the agent is
unreachable; use `"open"` to forward them uninspected instead.

```bash
curl -i -d "id=1' OR '1'='1" http://127.0.0.1:8080/   # 403 with CRS loaded
```

## Install

### Cargo (recommended for now)

The crate is not on crates.io; install from the repository:

```bash
cargo install --git https://github.com/zentinelproxy/zentinel-agent-zentinelsec
```

This installs the `zentinel-zentinelsec-agent` binary built from `main`, on
zentinel-modsec 0.13.1.

### Bundle

```bash
zentinel bundle install zentinelsec
```

Installs the release pinned in the proxy's bundle lock (0.3.0 before Zentinel
26.10_9, which does not run stock CRS, see Known limitations). 0.6.0 is the
release to run.
See the [bundle documentation](https://docs.zentinelproxy.io/deployment/bundle/).

### Release binaries

Each [release](https://github.com/zentinelproxy/zentinel-agent-zentinelsec/releases)
ships `linux-x86_64`, `linux-aarch64` and `darwin-aarch64`, each with a
`.sha256`. From 0.4.0, every asset has passed `scripts/smoke-test.sh` (stock
CRS behind a real Zentinel) before it was published.

```bash
VERSION=0.6.0
PLATFORM=linux-x86_64   # or linux-aarch64, darwin-aarch64
curl -fsSL -o zentinel-zentinelsec-agent.tar.gz \
  "https://github.com/zentinelproxy/zentinel-agent-zentinelsec/releases/download/v${VERSION}/zentinel-zentinelsec-agent-${VERSION}-${PLATFORM}.tar.gz"
tar -xzf zentinel-zentinelsec-agent.tar.gz
sudo install -m 0755 zentinel-zentinelsec-agent /usr/local/bin/
```

0.3.0 has the limitation above.

### From source

```bash
git clone https://github.com/zentinelproxy/zentinel-agent-zentinelsec
cd zentinel-agent-zentinelsec
cargo build --release
```

## Configuration

The agent is configured with command-line flags or environment variables,
and with a `config { }` block on the proxy's `agent` definition (see
[below](#the-config--block)). The block needs Zentinel 26.10_8 or later and
this agent 0.4.1 or later (built on `zentinel-agent-protocol` 0.6.51; the
0.6.50 gRPC server dropped Configure events, so older builds ignore it).

| Option | Environment | Default | Meaning |
|---|---|---|---|
| `--grpc-address` | `AGENT_GRPC_ADDRESS` | `0.0.0.0:50051` | gRPC listen address. The default listens on all interfaces; bind `127.0.0.1` when the proxy is local |
| `--rules` | `ZENTINELSEC_RULES` | none | Rule file or glob; repeat the flag or comma-separate. Loaded in order, so put `crs-setup.conf` first. With no rules nothing is blocked |
| `--block-mode` | `ZENTINELSEC_BLOCK_MODE` | `true` | Block on an intervention; `false` is detect-only |
| `--exclude-paths` | `ZENTINELSEC_EXCLUDE_PATHS` | none | Comma-separated path prefixes that skip inspection |
| `--body-inspection` | `ZENTINELSEC_BODY_INSPECTION` | `true` | Inspect request bodies |
| `--max-body-size` | `ZENTINELSEC_MAX_BODY_SIZE` | `1048576` | Largest body inspected, in bytes; larger bodies pass uninspected |
| `--response-inspection` | `ZENTINELSEC_RESPONSE_INSPECTION` | `false` | Accepted, not implemented |
| `-v`, `--verbose` | `ZENTINELSEC_VERBOSE` | `false` | Debug logging |

Logs are JSON on stdout. By default the agent, its handler
(`zentinel_agent_zentinelsec`) and the rule engine (`zentinel_modsec`, at
`warn`) are logged; `--verbose` raises all three to `debug`. `RUST_LOG`, when
set, replaces these defaults, so it must name every target you want to see,
e.g. `RUST_LOG=zentinel_zentinelsec_agent=info,zentinel_agent_zentinelsec=info,zentinel_modsec=warn`.
With `RUST_LOG` set, `--verbose` does not change the filter, and the default
directives also include `zentinel_agent_protocol=info`, so a bare
`RUST_LOG=debug` turns on debug output for every dependency too. An empty
`RUST_LOG` means the defaults; an invalid one is reported on stderr and the
defaults are used.

The boolean options are switches: `--block-mode` cannot take a value, so
`--block-mode=false` is rejected. To turn one off, set the environment
variable, e.g. `ZENTINELSEC_BLOCK_MODE=false`.

### The `config { }` block

```kdl
agents {
    agent "zentinelsec" type="waf" {
        grpc address="http://127.0.0.1:50051"
        events "request_headers" "request_body"
        config {
            rules-paths "/etc/modsecurity/crs/crs-setup.conf" "/etc/modsecurity/crs/rules/*.conf"
            block-mode #true
            exclude-paths "/health" "/metrics"
            max-body-size 1048576
        }
    }
}
```

Keys: `rules-paths` (alias `rules`), `block-mode`, `exclude-paths`,
`body-inspection-enabled` (alias `body-inspection`), `max-body-size`,
`response-inspection-enabled` (alias `response-inspection`). A list may be a
single value.

The proxy sends this block on every connection it opens to the agent: once per
pooled connection at startup and again on every reconnect. The agent applies
it by these rules:

1. **Idempotent.** A block identical to the one already in effect (compared
   by a hash of its canonical JSON) changes nothing. When the block does
   change, the rule set is rebuilt only if `rules-paths` changed; the other
   settings change in place. Requests whose body is being buffered are never
   dropped by a configure: they are inspected when their last chunk arrives.
2. **Merge, don't replace.** The block is overlaid on the flags and
   environment: a key that is absent keeps the value from the command line,
   so `config { block-mode #false }` keeps your `--rules`.
3. **Reject what cannot be applied.** The configure fails (the agent ends the
   stream, the proxy does not use the connection, and the active
   configuration stays as it was) for an unknown or misspelled key, a value of
   the wrong type, a list that is empty after parsing (`rules-paths ""`),
   `max-body-size 0`, a `rules-paths` pattern that matches no file, rule files
   that contain no rule, or a rule file that does not parse. A block that
   names rules can therefore never leave the agent running with zero rules.
4. **No secrets in logs.** A configure is logged with the hash of the block
   and the names of the settings it changed, never the values.

Rule files are passed to the engine as `Include`s with absolute paths, so data
files that CRS references relatively resolve next to their rule file whatever
the working directory. Paranoia level, anomaly thresholds and exclusions are
set in the rules themselves (`crs-setup.conf` or your own file), as with any
ModSecurity deployment. Proxy-side agent options are in the
[agents reference](https://docs.zentinelproxy.io/configuration/agents/).

## CRS conformance

zentinel-modsec runs the OWASP CRS regression suite on every push. Its current
result, from that repository: 4,806 of 5,184 runnable cases pass (92.7%,
CRS `main` 4.31.0-dev). The corpus runs in `DetectionOnly` at paranoia level 4,
as CRS documents it, so it measures whether rules **match**, not whether
requests are **blocked**. Blocking with stock CRS is tested separately here:
`crs_detects_attacks`, `crs_does_not_block_ordinary_traffic` and
`crs_does_not_block_ordinary_crawlers` in
`tests/crs_integration.rs` run against a real CRS checkout (they drive the
engine directly, so they do not cover the `GET` limitation above).

Builds on zentinel-modsec before 0.8.0 block ordinary crawlers under stock CRS
([zentinel-modsec#84](https://github.com/zentinelproxy/zentinel-modsec/issues/84)),
and builds before 0.5.0 are unsafe in blocking mode: 0.4.x kept
only the last `setvar` of a rule, dropping CRS anomaly scores
([zentinel-modsec#47](https://github.com/zentinelproxy/zentinel-modsec/issues/47)),
and versions before 0.4.0 deny every request under stock CRS
([zentinel-modsec#29](https://github.com/zentinelproxy/zentinel-modsec/issues/29)).
`main` requires 0.8.1.

## How it works

On `request_headers` the agent runs phases 1 and 2 on the URI, query string
and headers, with an empty body (CRS inspects `ARGS` and makes its blocking
decision in phase 2). If that passes and body inspection is on, it buffers the
body and, when the last chunk arrives, runs the rules again with the body.

A request is held only while its body may still arrive. Requests whose every
`Content-Length` is `0` are not held. Others are released by their last body
chunk, by the start of their response, or after 120 s without a body chunk;
at most 100 000 are held at once. A request on an excluded path, one detected
at the headers in detect-only mode, or one that hit an engine error keeps only
a marker, so its body is allowed without inspection.

The agent fails closed (in block mode) when it cannot inspect a body it
should: a body chunk with no pending request (released, or refused at the
limit) or one that does not decode gets a `403`, as does a new request while
the limit is reached. Detect-only mode never blocks for these; it logs a
warning and allows.

| Outcome | What the agent returns |
|---|---|
| Intervention, block mode | The rule's status, body `Forbidden`, response headers `X-WAF-Blocked: true`, `X-WAF-Rule` (the first matching rule ID) and `X-WAF-Message` |
| Intervention, detect-only | Allow, with `X-WAF-Detected` added to the request sent upstream |
| Engine error | Allow, logged as a warning |
| Body chunk the agent cannot inspect, or the pending-request limit reached, block mode | `403`, logged as `Blocking request (fail-closed)`; detect-only allows and logs a warning |

## Development

```bash
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings

# The CRS tests need a checkout (or set ZENTINELSEC_SKIP_CRS_TESTS=1)
mkdir -p test-rules
git clone --depth 1 https://github.com/coreruleset/coreruleset.git test-rules/crs
cp test-rules/crs/crs-setup.conf.example test-rules/crs/crs-setup.conf
cargo test
```

Building needs Rust 1.94.1+.

## Related

- [Registry page](https://registry.zentinelproxy.io/zentinelsec/)
- [zentinel-modsec](https://github.com/zentinelproxy/zentinel-modsec): the engine
- [zentinel-agent-modsec](https://github.com/zentinelproxy/zentinel-agent-modsec): the same rules on the C libmodsecurity
- [zentinel-agent-waf](https://github.com/zentinelproxy/zentinel-agent-waf): Zentinel's own rule set, no SecLang
- [Agent protocol v2](https://docs.zentinelproxy.io/agents/v2/)
- [Zentinel](https://github.com/zentinelproxy/zentinel)

## License

Apache-2.0, see [`LICENSE`](LICENSE).

---

<p align="center">
  <sub>Part of <a href="https://zentinelproxy.io">Zentinel</a>, the security-first reverse proxy. The shisa guards the gate.</sub>
</p>
