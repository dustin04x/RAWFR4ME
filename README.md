# RAWFRAME

**Terminal-native HTTP interception and security testing workbench.**

RAWFRAME is an open-source Rust workspace for authorized HTTP/1.1 testing from the terminal. It provides a local forward proxy, opaque HTTPS tunnelling, opt-in TLS interception, an in-memory traffic history, and a live request workbench inside a keyboard-driven TUI. It is built for testers who want a compact terminal workflow with explicit scope and visible request lifecycle state.

The current release is **0.2.0**. Milestones 1–4 are complete: core application, HTTP proxy, HTTP interception, and HTTPS TLS interception. Opaque `CONNECT` tunnelling is the default. Persistence, functional Repeater transmission, Intruder, Decoder, HTTP/2, and WebSocket support are not implemented.

RAWFRAME is intended **only** for systems you own or are explicitly authorized to test.

![RAWFRAME Proxy workspace while listening](docs/screenshots/140x40_02_listening.png)

## Screenshots

Captured from real PTY sessions of the current TUI at 140×40. These are terminal captures, not mockups.

| Live interception paused for review | Modified and unchanged requests forwarded |
| --- | --- |
| ![Paused request in the interception workbench](docs/screenshots/140x40_04_live_paused.png) | ![Modified and forwarded requests](docs/screenshots/140x40_08_modified.png) |

| Decrypted HTTPS request | TLS settings and local CA fingerprint |
| --- | --- |
| ![Decrypted HTTPS traffic in the Proxy workspace](docs/screenshots/tls/140x40_07_decrypted_https.png) | ![HTTPS TLS interception settings and CA fingerprint](docs/screenshots/tls/140x40_06_ca_path_and_fingerprint.png) |

| Scope-blocked request with explanation |
| --- |
| ![Request blocked by scope policy](docs/screenshots/140x40_13_scope_blocked_inspector.png) |

## Features

### Implemented

**Proxy and destination policy**

- HTTP/1.1 forward proxying with streamed request and response bodies.
- Opaque HTTPS `CONNECT` tunnelling with bidirectional relay and half-close.
- IPv4, IPv6, and hostname destinations with absolute-form and `Host` validation.
- End-to-end header preservation, including duplicates and `Set-Cookie`, with hop-by-hop filtering.
- Default-deny scope by exact host, leading wildcard, scheme, and port.
- Resolve-once DNS with address validation for loopback, private, link-local, metadata, and reserved ranges.
- Body caps, connection limits, connect/response/idle timeouts, and bounded event and command queues.

**HTTPS TLS interception**

- Opt-in HTTP/1.1 TLS interception; opaque `CONNECT` remains the default.
- Local certificate authority with explicit creation, fingerprint display, and public-certificate export.
- Per-host leaf certificates with a bounded cache.
- Separate upstream TLS session with mandatory certificate-chain and hostname verification.
- Decrypted requests enter the same interception queue, history, and lifecycle as HTTP traffic.
- Enabling or disabling interception applies to new `CONNECT` sessions; established sessions keep their configuration until close.
- No certificate-pinning bypass.

**Request interception**

- Pause matching requests before upstream contact.
- Inspect the raw request and forward it unchanged or modified after validation.
- Drop paused requests without fabricating an upstream response.
- Bounded pending queue, interception timeout, cancellation on disable/stop, and lifecycle tracking.

**Terminal interface**

- Proxy, HTTP History, Repeater, and Settings workspaces.
- Request/response inspector with raw, headers, and body views.
- Keyboard navigation, mouse support, command palette, and resizable panes.
- Live engine state, TLS state, queue state, and source provenance.
- Sensitive-header redaction and terminal-safe rendering of captured text.
- Repeater is currently an offline request editor with parse validation and multiple tabs; Send reports that transmission is unavailable.

### Planned, not implemented

- Functional Repeater transmission and response capture/comparison.
- SQLite persistence, projects, sessions, durable history, and export.
- Decoder, Intruder, and advanced traffic analysis.
- HTTP/2, HTTP/3, and WebSocket interception.
- HTTP proxy authentication and per-client rate limits.

## Architecture

RAWFRAME is a five-crate Cargo workspace. Dependency flow is one-way; the TUI never opens sockets and the proxy never depends on the TUI.

| Crate | Responsibility |
| --- | --- |
| `rawframe-core` | Domain models, configuration, scope rules, lifecycle, filters, bounded event/command contracts, terminal-safety primitives, and labelled fixtures. No network or terminal I/O. |
| `rawframe-http` | Authored HTTP/1.x document parser used by Repeater and tests. This is not the live proxy wire implementation. |
| `rawframe-proxy` | Tokio/Hyper listener, HTTP forwarding, opaque `CONNECT` relay, TLS interception, destination policy, body guards, limits, and graceful shutdown. |
| `rawframe-tui` | Ratatui/Crossterm application, workspaces, inspector, editor, layouts, input handling, and terminal lifecycle. |
| `rawframe-cli` | Composition root: CLI validation, logging, Tokio runtime, proxy worker, and TUI loop. |

```mermaid
flowchart LR
    client[HTTP client / browser] -->|HTTP or CONNECT| proxy[rawframe-proxy]
    cli[rawframe-cli] --> tui[rawframe-tui]
    cli --> proxy
    tui --> http[rawframe-http]
    tui --> core[rawframe-core]
    proxy --> core
    http --> core
```

### Request lifecycle

1. The client connects to the local proxy listener.
2. The proxy parses the destination and validates it against scope and address policy.
3. HTTP requests are forwarded upstream or paused by the interception queue.
4. HTTPS `CONNECT` is relayed as an opaque tunnel unless TLS interception is explicitly enabled.
5. Intercepted HTTPS traffic is terminated locally, decrypted, and handled through the existing HTTP interception lifecycle.
6. Upstream TLS certificate-chain and hostname verification remains mandatory for intercepted sessions.

`rawframe-cli` owns the Tokio runtime and spawns `rawframe_proxy::run_service`. The TUI exchanges commands and events through bounded channels, polls without blocking, and renders captured traffic and lifecycle state.

See [docs/architecture.md](docs/architecture.md) for the full data flow, module map, and design decisions.

## Security model

TLS interception is security-sensitive. RAWFRAME keeps it explicit and bounded.

- **Opt-in interception.** Opaque `CONNECT` is the default. TLS interception is off unless enabled with `--tls-intercept` or the Settings toggle.
- **Explicit CA trust.** RAWFRAME never installs its CA automatically. The operator must export the public certificate and trust it in the client or dedicated test profile.
- **Protected private key.** CA material is stored locally under `$XDG_DATA_HOME/rawframe/ca` or `~/.local/share/rawframe/ca`. On Unix, the key is `0600` and the directory is `0700`. The private key is never exported, logged, or published in events or history.
- **No verification bypass.** Upstream certificate-chain and hostname verification cannot be disabled. `--tls-upstream-ca` replaces the trust roots for a lab; it does not weaken verification.
- **Scope before connection.** Scope is checked before DNS resolution or any upstream socket is opened. A denial is recorded as blocked and never forwarded.
- **Resolve-once address policy.** Every resolved address is validated before connection. Loopback and private upstreams require `--allow-private-upstreams`; link-local, metadata, multicast, documentation, and reserved ranges remain blocked.
- **Loopback by default.** Remote binding requires both a non-loopback `--bind` and `--allow-remote-bind`. There is no proxy authentication; protect any remote listener with host firewalls or a trusted network.
- **Bounded failure.** Bodies, connections, queues, and timeouts are bounded. Disabling interception or stopping the proxy cancels pending work instead of leaving it unresolved.
- **Local data only.** No telemetry, external reporting, shell execution from captured content, or automatic trust-store modification. Diagnostics are written to a local log without captured headers or bodies.
- **Presentation safety.** Sensitive headers are redacted by default, and captured text is sanitized before terminal rendering.

### Limitations

- HTTP/1.1 only. HTTP/2, HTTP/3, and WebSocket forwarding/interception are not supported.
- TLS interception does not bypass certificate pinning. Pinned clients fail the intercepted handshake by design.
- Modified HTTPS requests cannot change the original `CONNECT` authority; changing host or port requires a new connection.
- Opaque tunnels expose only destination, duration, byte counts, and outcome; payload and inner headers are not captured.
- History and settings are session-only. No database, project files, export, or persistent storage exists.
- Repeater does not transmit requests yet.
- Scope is configured from the CLI; there is no scope-rule editor.
- There is no proxy authentication, per-client rate limit, or HTTP `503` response for connection-limit overflow.

See [docs/security.md](docs/security.md) for the threat model and the complete controls and gaps.

## Installation and usage

### Prerequisites

- Rust **1.88+** with edition 2024 support.
- A terminal of at least 64×18. The inspector requires 108 columns; 140×40 is recommended.
- A truecolor terminal and a monospace font with box-drawing coverage for the intended appearance.
- Python 3 with `cryptography` only for the real-binary PTY regression, not for normal operation.

### Build and run

```bash
git clone https://github.com/dustin04x/RAWFR4ME.git
cd RAWFR4ME
cargo build --workspace
cargo run -p rawframe-cli --bin rawframe
```

The proxy starts idle with default-deny scope. Press `P` on the Proxy workspace to start it.

### Quick local HTTP check

```bash
# Terminal 1: local upstream
python3 -m http.server 8000 --bind 127.0.0.1

# Terminal 2: RAWFRAME, authorizing only this local upstream
cargo run -p rawframe-cli --bin rawframe -- \
  --port 8080 \
  --scope http://127.0.0.1:8000 \
  --allow-private-upstreams
# Press P on the Proxy workspace.

# Terminal 3: send a request through the proxy
curl --noproxy '' -x http://127.0.0.1:8080 http://127.0.0.1:8000/
```

For a release build, use `cargo build --release -p rawframe-cli` and run `target/release/rawframe`.

### Enable HTTPS interception

The CA is created when HTTPS TLS interception is first enabled, or explicitly with `--tls-ca-regenerate`. For a new test setup:

```bash
# Create a new local CA. This invalidates trust in any previous RAWFRAME CA.
target/debug/rawframe --tls-ca-regenerate

# Inspect the public certificate path, status, and SHA-256 fingerprint.
target/debug/rawframe --tls-ca-show
target/debug/rawframe --tls-ca-fingerprint

# Export only the public certificate.
target/debug/rawframe --tls-ca-export ./rawframe-ca.crt.pem

# Start with interception and an explicit HTTPS scope.
target/debug/rawframe \
  --tls-intercept \
  --port 8080 \
  --scope https://lab.example.test:443
```

For a local HTTPS origin, add `--allow-private-upstreams` and use the exact host and port in `--scope`.

Then:

1. Use a disposable browser profile or dedicated test VM.
2. Import `rawframe-ca.crt.pem` as a trusted certificate authority in that profile only. Do not add it to the system trust store.
3. Configure the client to use `127.0.0.1:8080` as its HTTP/HTTPS proxy.
4. Confirm that the target certificate is issued by the RAWFRAME CA before sending sensitive traffic.
5. Disable TLS interception or restart without `--tls-intercept`, remove the CA from the profile, and delete the profile when finished.

Only scoped `CONNECT` targets are eligible for interception. Removing trust does not affect opaque tunnelling. `--tls-ca-regenerate` permanently invalidates the old CA; every client that trusted it must be updated.

### CLI reference

```text
rawframe [OPTIONS]
```

| Option | Purpose |
| --- | --- |
| `--bind <ADDR>` | Listener address. Defaults to `127.0.0.1`. |
| `--port <PORT>` | Listener port. Defaults to `8080`. |
| `--allow-remote-bind` | Required for a non-loopback bind address. |
| `--scope <RULE>` | Allow an upstream host; repeatable. Supplying no rules denies everything. |
| `--allow-private-upstreams` | Permit loopback/private targets for local labs. |
| `--no-mouse` | Disable mouse capture and interaction. |
| `--no-redact` | Show sensitive header values. Dangerous in shared environments. |
| `--log-file <FILE>` | Override the default local diagnostic log path. |
| `--tls-intercept` | Enable HTTPS TLS interception for scoped `CONNECT` targets. |
| `--tls-ca-dir <DIR>` | Override the local CA directory. |
| `--tls-upstream-ca <FILE>` | Use an explicit PEM trust bundle for upstream TLS; verification stays on. |
| `--tls-ca-show` | Print CA path/status and exit. |
| `--tls-ca-export <FILE>` | Export the public CA certificate and exit. |
| `--tls-ca-fingerprint` | Print the CA SHA-256 fingerprint and exit. |
| `--tls-ca-regenerate` | Replace the CA and exit. Invalidates prior trust. |

`--scope` accepts `host`, `host:port`, `http://host[:port]`, `https://host[:port]`, and leading wildcards such as `*.example.test`. HTTPS scope rules are required for intercepted `CONNECT` targets.

## Keyboard shortcuts

Single-letter shortcuts are suppressed while typing in an editor, search field, or Settings field. `Ctrl+C` always exits.

### Global

| Shortcut | Action |
| --- | --- |
| `Ctrl+K` | Open the command palette. |
| `Ctrl+1` … `Ctrl+4` | Go to Proxy, HTTP History, Repeater, and Settings. |
| `Ctrl+5`, `Ctrl+6` | Open the planned Intruder and Decoder placeholders. |
| `Ctrl+F` | Search HTTP History. |
| `Ctrl+N` | Create a Repeater tab. |
| `Ctrl+W` | Close the current Repeater tab. |
| `Ctrl+U` | Clear HTTP History filters. |
| `Tab` / `Shift+Tab` | Move focus between navigation, content, and inspector. |
| `?` | Show keyboard help. |
| `Q` | Quit; confirmation is required with unsaved edits or paused requests. |
| `Ctrl+C` | Immediate emergency exit. |

### Proxy

| Shortcut | Action |
| --- | --- |
| `↑` / `↓`, `J` / `K` | Move through traffic or the pending queue. |
| `PageUp` / `PageDown` | Move by eight rows. |
| `Home` / `End` | Jump to the first or last row. |
| `Enter` | Inspect the selected request. |
| `P` | Start or stop the proxy. |
| `I` | Toggle interception. |
| `F` | Forward a paused request unchanged. |
| `E` | Edit a paused request in the workbench. |
| `S` | Send the modified request after validation. |
| `Ctrl+Enter` | Send the modified request while the editor is active. |
| `D` | Drop the paused request. |
| `R` | Open the selected request in Repeater. |

### HTTP History and inspector

| Shortcut | Action |
| --- | --- |
| `/` or `Ctrl+F` | Search History. |
| `M`, `S`, `H` | Cycle method, status, and host filters. |
| `Enter` | Open the selected request in the inspector. |
| `[` / `]`, `←` / `→` | Switch the inspector between request and response. |
| `1`, `2`, `3` | Show raw, headers, or body view. |
| `X` | Toggle sensitive-header redaction in the inspector. |
| `R` / `E` | Open the selected request in Repeater, view or edit mode. |

### Repeater and Settings

| Context | Shortcut | Action |
| --- | --- | --- |
| Repeater | `Enter` / `E` | Start editing the active document. |
| Repeater | `S` or `Ctrl+Enter` | Attempt to send. Transmission is not implemented and nothing is sent. |
| Repeater | `←` / `→` | Switch tabs. |
| Settings | `↑` / `↓`, `J` / `K` | Select a setting. |
| Settings | `Enter` / `Space` | Toggle or edit the selected setting. |
| Settings | `Esc` | Cancel an inline edit. |

Mouse support includes click-to-select, double-click inspection, right-click context menus, wheel scrolling, and draggable pane dividers. Disable it with `--no-mouse`.

Settings and traffic history are session-only. Network limit changes apply after the proxy is restarted.

## Defaults

| Setting | Default |
| --- | --- |
| Listener | `127.0.0.1:8080` |
| Scope | Empty allowlist; deny all |
| Request/response body cap | 2 MiB each |
| Concurrent client connections | 128 |
| Connect / response-header / idle timeout | 10 s / 30 s / 60 s |
| Interception timeout and queue | 120 s; 32 entries |
| HTTPS TLS interception | Off |
| Upstream TLS verification | On; cannot be disabled |
| Sensitive-header redaction | On |

Diagnostics default to `$XDG_DATA_HOME/rawframe/logs/rawframe.log` or `~/.local/share/rawframe/logs/rawframe.log`. Logs contain lifecycle data, not captured headers or bodies. The file is owner-only on Unix.

## Roadmap

Milestone numbers follow [docs/roadmap.md](docs/roadmap.md).

| Milestone | Status |
| --- | --- |
| M1 — Core architecture and TUI | Complete |
| M2 — HTTP proxy engine | Complete |
| M3 — HTTP interception | Complete |
| M4 — HTTPS TLS interception | Complete |
| M5 — Persistence, sessions, and protocol coverage | Planned |
| M6 — Functional Repeater | Planned |
| Later — Intruder, Decoder, traffic analysis, protocol expansion, release hardening | Planned |

Planned work is not available in this build. See [docs/roadmap.md](docs/roadmap.md) for scope, acceptance criteria, and known limitations.

## Testing

Run the repository quality gates from the workspace root:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Or run `./scripts/check.sh`.

The latest verified M4 release run reported:

- **239 passing tests, 0 failed** across the workspace.
- **89/89 PTY checks** passing at 140×40, 100×30, and 80×24.
- A passing real-binary PTY regression that enables and disables TLS interception through the TUI.

The PTY test requires Python 3 with `cryptography`; without it, that test skips while the remaining proxy-level HTTP/HTTPS tests still run. Test suites use local servers and self-contained test CAs; no test contacts an external website. These are milestone results, not a guarantee for every future commit.

## Project status and contribution

RAWFRAME is under active pre-1.0 development. The M1–M4 foundations are implemented and tested; planned modules are visible in the navigation but clearly marked as placeholders. Interfaces and terminal behavior may change.

Contributions should preserve the security defaults: loopback binding, default-deny scope, explicit private-upstream opt-in, mandatory upstream TLS verification, redaction, and terminal sanitization. Add tests for behavioral changes and run the quality gates before submitting. See [CONTRIBUTING.md](CONTRIBUTING.md) and [docs/development.md](docs/development.md).

**License:** MIT. See [LICENSE](LICENSE).

## Documentation

- [Architecture](docs/architecture.md)
- [Security model](docs/security.md)
- [Development guide](docs/development.md)
- [Roadmap](docs/roadmap.md)
- [Dependency graph](docs/dependency-graph.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
