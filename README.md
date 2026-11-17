# RAWFRAME

**Terminal-native HTTP interception and security testing workbench.**

RAWFRAME is an open-source Rust workspace for authorized HTTP/1.1 testing from the terminal. It provides a local forward proxy, opaque HTTPS tunnelling, opt-in TLS interception, durable SQLite history with sessions and redacted export, and a live request workbench inside a keyboard-driven TUI. It is built for testers who want a compact terminal workflow with explicit scope and visible request lifecycle state.

The current release is **0.2.0**. Milestones 1–6 are complete: core application, HTTP proxy, HTTP interception, HTTPS TLS interception, durable history/sessions/export, and a functional Repeater with real HTTP/HTTPS execution, response inspection, comparison, and persisted provenance. Opaque `CONNECT` tunnelling is the default. Intruder, Decoder, HTTP/2, and WebSocket support are not implemented.

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

| Scope-blocked request with explanation | Repeater workspace with independent tabs |
| --- | --- |
| ![Request blocked by scope policy](docs/screenshots/140x40_13_scope_blocked_inspector.png) | ![Repeater editor and response panel](docs/screenshots/repeater/140x40_01_workspace.png) |

The Repeater workspace is also captured from a real PTY at
[100×30](docs/screenshots/repeater/100x30_01_workspace.png) and
[80×24](docs/screenshots/repeater/80x24_01_workspace.png).

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

**Durable history and sessions**

- SQLite persistence in a dedicated storage crate; the proxy and TUI never link SQLite.
- Versioned schema migrations, crash recovery, and `incomplete` markers for interrupted transactions.
- Captured traffic is written on a separate thread, so the proxy request path never waits on disk.
- Sensitive header values are redacted before writing; bodies are stored only when explicitly opted in.
- Browse stored sessions, restore them read-only into History, and export redacted JSON Lines.
- Restored traffic is labelled `RESTORED`, is never live, and is never forwarded.
- Live target-scope editing in Settings, applied to new requests without restarting the listener.

**Request interception**

- Pause matching requests before upstream contact.
- Inspect the raw request and forward it unchanged or modified after validation.
- Drop paused requests without fabricating an upstream response.
- Bounded pending queue, interception timeout, cancellation on disable/stop, and lifecycle tracking.

**Repeater**

- Real HTTP/1.1 execution to scoped destinations over direct client connections; no simulated responses or placeholder success states.
- `http` and `https` schemes, arbitrary valid methods, custom ports, query strings, ordered duplicate headers, and binary request bodies.
- Multiple independent tabs with per-tab editor, draft state, execution history, follow-redirect toggle, and response comparison.
- Separate editor and response panels (vertical split below 84 columns), Raw, Headers, Body, Pretty JSON, Hex, and Compare views.
- Explicit lifecycle phases: Draft, Validating, Connecting, Sending, Receiving, Completed, Failed, Cancelled, TimedOut, and Blocked by scope.
- Independent upstream connection per execution and per redirect hop; no CONNECT tunnel, local MITM CA, or interception queue is used.
- Mandatory upstream TLS certificate-chain and hostname verification; scope and private-address policy are enforced before every connection and redirect hop.
- Safe redirects are opt-in: at most five hops, every destination is scope-checked, and credentials are stripped on cross-origin hops.
- Response limits, timeouts, cancellation, and a bounded concurrency limit are enforced in the execution path.
- Completed transactions are attributed to Repeater provenance with the original capture reference, redacted through the same policy as proxy history, and distinguished from proxy traffic. Storage failures are reported without crashing execution.

**Terminal interface**

- Proxy, HTTP History, Repeater, and Settings workspaces.
- Request/response inspector with raw, headers, and body views.
- Keyboard navigation, mouse support, command palette, and resizable panes.
- Live engine state, TLS state, queue state, and source provenance.
- Sensitive-header redaction and terminal-safe rendering of captured text.

### Planned, not implemented

- Decoder, Intruder, and advanced traffic analysis.
- HTTP/2, HTTP/3, and WebSocket interception.
- HTTP proxy authentication and per-client rate limits.

## Architecture

RAWFRAME is a seven-crate Cargo workspace. Dependency flow is one-way; the TUI never opens sockets or SQLite, and the proxy never depends on the TUI.

| Crate | Responsibility |
| --- | --- |
| `rawframe-core` | Domain models, configuration, scope rules, lifecycle, filters, bounded event/command contracts, terminal-safety primitives, and labelled fixtures. No network or terminal I/O. |
| `rawframe-http` | Authored HTTP/1.x document parser used by Repeater and tests. This is not the live proxy wire implementation. |
| `rawframe-proxy` | Tokio/Hyper listener, HTTP forwarding, opaque `CONNECT` relay, TLS interception, destination policy, body guards, limits, and graceful shutdown. |
| `rawframe-repeater` | Repeater execution engine: request validation handoff, independent HTTP/1.1 connections, verified HTTPS, redirects, bounded response capture, timeouts, cancellation, and the command service. Reuses proxy destination/TLS policy but not its listener, CA, or interception queue. |
| `rawframe-store` | SQLite schema/migrations, a single writer thread, redaction-on-write, session queries, restore, and redacted export. No proxy or TUI dependency. |
| `rawframe-tui` | Ratatui/Crossterm application, workspaces, inspector, editor, layouts, input handling, and terminal lifecycle. |
| `rawframe-cli` | Composition root: CLI validation, logging, Tokio runtime, proxy worker, storage worker/capture pump, and TUI loop. |

```mermaid
flowchart LR
    client[HTTP client / browser] -->|HTTP or CONNECT| proxy[rawframe-proxy]
    cli[rawframe-cli] --> tui[rawframe-tui]
    cli --> proxy
    cli --> store[rawframe-store]
    cli --> repeater[rawframe-repeater]
    repeater --> proxy
    tui --> http[rawframe-http]
    tui --> core[rawframe-core]
    proxy --> core
    store --> core
    repeater --> core
    http --> core
    proxy -. events .-> store
    repeater -. events .-> store
```

### Request lifecycle

1. The client connects to the local proxy listener.
2. The proxy parses the destination and validates it against scope and address policy.
3. HTTP requests are forwarded upstream or paused by the interception queue.
4. HTTPS `CONNECT` is relayed as an opaque tunnel unless TLS interception is explicitly enabled.
5. Intercepted HTTPS traffic is terminated locally, decrypted, and handled through the existing HTTP interception lifecycle.
6. Upstream TLS certificate-chain and hostname verification remains mandatory for intercepted sessions.

`rawframe-cli` owns the Tokio runtime and spawns `rawframe_proxy::run_service`, plus the storage worker and a capture pump subscribed to the same event bus. The TUI exchanges commands and events through bounded channels, polls without blocking, and renders captured traffic and lifecycle state. Storage failures are reported in the UI; the proxy keeps running.

See [docs/architecture.md](docs/architecture.md) for the full data flow, module map, and design decisions.

## Security model

TLS interception is security-sensitive. RAWFRAME keeps it explicit and bounded.

- **Opt-in interception.** Opaque `CONNECT` is the default. TLS interception is off unless enabled with `--tls-intercept` or the Settings toggle.
- **Explicit CA trust.** RAWFRAME never installs its CA automatically. The operator must export the public certificate and trust it in the client or dedicated test profile.
- **Protected private key.** CA material is stored locally under `$XDG_DATA_HOME/rawframe/ca` or `~/.local/share/rawframe/ca`. On Unix, the key is `0600` and the directory is `0700`. The private key is never exported, logged, or published in events or history.
- **No verification bypass.** Upstream certificate-chain and hostname verification cannot be disabled. `--tls-upstream-ca` replaces the trust roots for a lab; it does not weaken verification.
- **Scope before connection.** Scope is checked before DNS resolution or any upstream socket is opened. A denial is recorded as blocked and never forwarded.
- **Repeater is not a bypass.** Repeater opens its own scoped connections, uses the same resolve-once address policy, always verifies upstream TLS, and never enters the interception queue or trusts the local CA. Scope is re-checked before every redirect hop.
- **Safe redirects.** Following redirects is off by default. When enabled, RAWFRAME caps the chain at five hops, validates each destination against scope, and removes `Authorization`, `Proxy-Authorization`, `Cookie`, `X-Api-Key`, `X-Auth-Token`, and `X-Csrf-Token` on cross-origin hops.
- **Resolve-once address policy.** Every resolved address is validated before connection. Loopback and private upstreams require `--allow-private-upstreams`; link-local, metadata, multicast, documentation, and reserved ranges remain blocked.
- **Loopback by default.** Remote binding requires both a non-loopback `--bind` and `--allow-remote-bind`. There is no proxy authentication; protect any remote listener with host firewalls or a trusted network.
- **Bounded failure.** Bodies, connections, queues, and timeouts are bounded. Disabling interception or stopping the proxy cancels pending work instead of leaving it unresolved.
- **Local data only.** No telemetry, external reporting, shell execution from captured content, or automatic trust-store modification. Diagnostics are written to a local log without captured headers or bodies.
- **Redaction before storage.** Sensitive header values are replaced with `<redacted>` and bodies are stored as SQL `NULL` unless the operator explicitly opts in with `--persist-sensitive-headers` / `--persist-bodies`. Changing the policy never rewrites existing rows.
- **Protected database.** On Unix the database and exports are `0600` in a `0700` directory; WAL + `synchronous=FULL` limit crash loss, and a 512 MiB ceiling stops runaway growth with an explicit error instead of filling the disk.
- **Honest save state.** The footer shows `DB ON`, `DB OFF`, or `DB ERROR`; dropped captures are counted and surfaced. Corrupt or unavailable databases disable persistence without deleting the file.
- **Presentation safety.** Sensitive headers are redacted by default, and captured text is sanitized before terminal rendering.

### Limitations

- HTTP/1.1 only. HTTP/2, HTTP/3, and WebSocket forwarding/interception are not supported.
- TLS interception does not bypass certificate pinning. Pinned clients fail the intercepted handshake by design.
- Modified HTTPS requests cannot change the original `CONNECT` authority; changing host or port requires a new connection.
- Opaque tunnels expose only destination, duration, byte counts, and outcome; payload and inner headers are not captured.
- Captured history and sessions persist in SQLite. Settings, storage policy, and scope rules are runtime state: set them with CLI flags or in the UI for the current run. There is no configuration file.
- Bodies and sensitive header values are absent from stored history unless explicitly enabled, and cannot be recovered later.
- Repeater transmits HTTP/1.1 only. It has no HTTP/2, WebSocket, client-certificate, or proxy-auth support.
- Repeater requests are direct; they do not traverse the local proxy listener or reuse a captured connection. A different client certificate, source address, or proxy path can produce a different result.
- Scope is edited in Settings or via `--scope`; wildcard and port rules apply to new proxy and Repeater requests immediately.
- There is no proxy authentication, per-client rate limit, or HTTP `503` response for connection-limit overflow.

See [docs/security.md](docs/security.md) for the threat model and the complete controls and gaps.

## Installation and usage

### Prerequisites

- Rust **1.89+** with edition 2024 support.
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

### Persisted history

Captured traffic is written to a local SQLite database by default at `$XDG_DATA_HOME/rawframe/rawframe.db` or `~/.local/share/rawframe/rawframe.db`. The directory is `0700` and the database is `0600` on Unix.

- Sensitive header values are stored as `<redacted>`; bodies are stored as SQL `NULL`. Both are opt-in: `--persist-sensitive-headers` and `--persist-bodies` (also toggles in Settings).
- `--db FILE` chooses another database; `--no-persist` keeps everything in memory only.
- Changing the policy affects new captures only. It never rewrites existing rows.
- Press `B` to browse stored sessions, `Enter` to restore one read-only into History, and `E` to export it as redacted JSON Lines.
- The footer shows `DB ON (n stored)`, `DB OFF`, or `DB ERROR`. Corrupt or unavailable databases disable persistence with an explicit message; the proxy keeps running.

Export without starting the UI (newest session, or a specific one):

```bash
rawframe --db ~/.local/share/rawframe/rawframe.db \
  --export-history ./engagement-history.jsonl

rawframe --db ~/.local/share/rawframe/rawframe.db \
  --export-session sess-abc123 \
  --export-history ./engagement-history.jsonl
```

Exports contain the stored, already-redacted rows, not live in-memory values. Withheld bodies are marked `"omitted": true`; binary bodies are hex-encoded.

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

### Repeater quick start

Repeater is independent of the proxy listener and does not require pressing `P`.

1. Start with an explicit scope and, for a local lab origin, private-upstream permission:

   ```bash
   target/debug/rawframe --scope http://127.0.0.1:8000 --allow-private-upstreams
   ```

2. Press `Ctrl+3` for Repeater, then `Enter`/`E` to edit the seeded request line and headers. The request line uses an absolute URL, for example `POST http://127.0.0.1:8000/api HTTP/1.1`.
3. Press `Ctrl+Enter` or `S` to send; `C` cancels an execution. Responses render on the right (or below in an 80-column terminal).
4. Use `1`–`6` for Raw, Headers, Body, Pretty JSON, Hex, and Compare. `F` toggles safe redirect following; `X` clears the current response.
5. Close a tab with `Ctrl+W`; `Ctrl+N` creates a new blank tab. Each tab keeps its own document, in-flight execution, response, and execution history.

Completed Repeater executions appear in HTTP History with `REPEATER` provenance and the original capture reference when the document came from History or the proxy. They are persisted under the same redaction/body policy as proxy traffic. No proxy capture is fabricated.

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
| `--db <FILE>` | SQLite database for captured history. |
| `--no-persist` | Do not create or write a database; history is memory-only. |
| `--persist-bodies` | Store captured request/response bodies (off by default). |
| `--persist-sensitive-headers` | Store sensitive header values instead of `<redacted>` (off by default). |
| `--session-name <NAME>` | Name this capture session. |
| `--project <NAME>` | Name the project that owns this session. |
| `--export-history <FILE>` | Export stored history as JSON Lines and exit. |
| `--export-session <ID>` | Session to export; defaults to the newest session. |
| `--tls-intercept` | Enable HTTPS TLS interception for scoped `CONNECT` targets. |
| `--tls-ca-dir <DIR>` | Override the local CA directory. |
| `--tls-upstream-ca <FILE>` | Use an explicit PEM trust bundle for upstream TLS; verification stays on. |
| `--tls-ca-show` | Print CA path/status and exit. |
| `--tls-ca-export <FILE>` | Export the public CA certificate and exit. |
| `--tls-ca-fingerprint` | Print the CA SHA-256 fingerprint and exit. |
| `--tls-ca-regenerate` | Replace the CA and exit. Invalidates prior trust. |

`--scope` accepts `host`, `host:port`, `http://host[:port]`, `https://host[:port]`, and leading wildcards such as `*.example.test`. HTTPS scope rules are required for intercepted `CONNECT` targets and for Repeater HTTPS requests.

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
| `B` | Browse stored sessions (restore read-only, export). |
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
| Repeater | `S` or `Ctrl+Enter` | Validate and execute the active document. |
| Repeater | `C` | Cancel the in-flight execution for the active tab. |
| Repeater | `←` / `→` | Switch tabs. |
| Repeater | `F` | Toggle safe redirect following for the active tab. |
| Repeater | `1`–`6` | Raw, Headers, Body, Pretty JSON, Hex, Compare. |
| Repeater | `X` | Clear the current response (history is retained). |
| Settings | `↑` / `↓`, `J` / `K` | Select a setting. |
| Settings | `Enter` / `Space` | Toggle or edit the selected setting; **Target scope** opens the live rule editor. |
| Settings | `Esc` | Cancel an inline edit. |
| Scope editor | `Enter` / `Del` / `Ctrl+B` | Add typed rule / remove selected / toggle default-deny. |
| Stored sessions | `↑` / `↓`, `Enter`, `E`, `R` | Select, restore read-only, export, refresh. |

Mouse support includes click-to-select, double-click inspection, right-click context menus, wheel scrolling, and draggable pane dividers. Disable it with `--no-mouse`.

Captured history and sessions persist in SQLite. Settings, body limits, storage policy, and scope rules are not saved to a configuration file: choose them with CLI flags or in the UI for this run. Network limit changes apply after the proxy is restarted; scope edits apply to new requests immediately.

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
| Persistence | On; local SQLite database |
| Stored bodies / sensitive headers | Off; SQL `NULL` and `<redacted>` |
| Database ceiling | 512 MiB |

Diagnostics default to `$XDG_DATA_HOME/rawframe/logs/rawframe.log` or `~/.local/share/rawframe/logs/rawframe.log`. Logs contain lifecycle data, not captured headers or bodies. The file is owner-only on Unix.

## Roadmap

Milestone numbers follow [docs/roadmap.md](docs/roadmap.md).

| Milestone | Status |
| --- | --- |
| M1 — Core architecture and TUI | Complete |
| M2 — HTTP proxy engine | Complete |
| M3 — HTTP interception | Complete |
| M4 — HTTPS TLS interception | Complete |
| M5 — Persistence, sessions, and protocol coverage | Complete |
| M6 — Functional Repeater | Complete |
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

The latest verified M6 run reported:

- **322 passing tests, 0 failed** across the workspace (M5 baseline: 280), including real local HTTP/HTTPS Repeater executions, binary bodies, duplicate headers, redirect loops and credential stripping, scope refusal, timeouts, cancellation, response limits, Repeater persistence/redaction, and an end-to-end M5 schema-v1 upgrade fixture.
- The existing PTY screenshot and TLS enable/disable regressions still pass.
- Repeater tests use local HTTP/HTTPS servers and self-signed test certificates; storage tests use isolated temporary databases; proxy tests use local servers only.

The PTY test requires Python 3 with `cryptography`; without it, that test skips while the remaining proxy-level HTTP/HTTPS tests still run. Test suites use local servers and self-contained test CAs; no test contacts an external website. These are milestone results, not a guarantee for every future commit.

## Project status and contribution

RAWFRAME is under active pre-1.0 development. The M1–M6 foundations are implemented and tested; planned modules are visible in the navigation but clearly marked as placeholders. Interfaces and terminal behavior may change.

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
