# ▌ RAWFRAME

**Terminal-native HTTP interception and security testing workbench.**

RAWFRAME is an open-source, terminal-first alternative to the workflow shape of
Burp Suite: forward traffic, inspect HTTP messages, browse history, and keep a
testing session organized — without leaving the terminal.

> **Status: Milestone 3 (in progress, not complete).**
> RAWFRAME forwards real HTTP/1.1 proxy traffic, relays opaque HTTPS `CONNECT`
> tunnels, and includes an interception engine/workbench for pausing matching
> HTTP requests before upstream and resolving them (forward unchanged, forward
> modified, drop) with real proxy events. TLS is **not** intercepted: CONNECT
> remains opaque (metadata/byte counts only), there is no local CA/certificate
> management, and decrypted HTTPS inspection is unavailable. SQLite persistence,
> Repeater transmission, Intruder, and Decoder remain unimplemented.

RAWFRAME is intended only for systems for which you have explicit authorization.
Only test what you own or are engaged to test.

## What works today

| Area | Status |
|---|---|
| Cargo workspace, shared models, bounded event bus, command boundary | Implemented |
| HTTP/1.1 forward proxy with streaming request/response bodies | Implemented |
| IPv4, IPv6, and hostname destinations; absolute-form and `Host` validation | Implemented |
| End-to-end header preservation, including duplicates and `Set-Cookie` | Implemented |
| Hop-by-hop header filtering and upstream normalization | Implemented |
| Opaque HTTPS `CONNECT` tunneling with bidirectional half-close | Implemented |
| Default-deny scope by host, wildcard host, scheme, and port | Implemented |
| DNS resolve-once address policy (rebinding resistant) | Implemented |
| Request/response size, connection, connect, response, and idle limits | Implemented |
| Live HTTP capture, CONNECT metadata, failures, counts in the TUI | Implemented |
| Start/stop from the TUI with real lifecycle state | Implemented |
| Simulated fixtures, clearly separated from live captures | Retained and labelled |
| Terminal lifecycle, keyboard/mouse navigation, inspector, palette | Implemented |
| Sensitive-header redaction and terminal-escape/bidi sanitization | Implemented |
| HTTP interception pause/forward modified/drop (engine + TUI workbench integration) | **Implemented/in progress** |
| TLS interception, local CA, certificate management | **Not implemented** |
| SQLite persistence, sessions, export | **Not implemented (Milestone 4)** |
| Repeater transmission | **Not implemented (Milestone 5)** |
| Intruder and Decoder | **Explicitly planned placeholders** |

Simulated fixtures use the reserved `.test` domain and never leave the machine.
Live captures use IDs starting at 1000 and carry `LIVE` source badges. The Proxy
banner, header badge, footer, and row labels distinguish the two modes.

## Requirements

- Rust **1.88 or newer** (edition 2024).
- A terminal of at least **64 × 18** cells. **108+ columns** are recommended so
  the inspector fits. RAWFRAME shows a resize message below the minimum.
- A truecolor terminal is recommended.
- A monospace font with good box-drawing and geometric glyph coverage.
  **JetBrains Mono** is the recommended terminal font for HTTP content.

Linux, macOS, and Windows terminals supported by Crossterm should work. Mouse
capture, bracketed paste, and truecolor support depend on the terminal.

## Build, run, and forward traffic

```bash
cargo run -p rawframe-cli --bin rawframe
```

The proxy starts **offline** and default-deny. Use the Proxy screen and press
`P` (or click **Start**) to bind the listener. For a self-contained local test:

```bash
# Terminal 1: local upstream
python3 -m http.server 8000 --bind 127.0.0.1

# Terminal 2: RAWFRAME, authorizing only this local upstream
cargo run -p rawframe-cli --bin rawframe -- \
  --port 8080 \
  --scope http://127.0.0.1:8000 \
  --allow-private-upstreams
# Press P on the Proxy screen.

# Terminal 3: send a real proxied request
curl --noproxy '' -x http://127.0.0.1:8080 http://127.0.0.1:8000/
```

The request appears under **LIVE REQUESTS** with its method, host, path, state,
size, and age. It is also inserted into HTTP History alongside the labelled
simulated fixtures, where existing search and method/status/host filters work.

An opaque HTTPS tunnel looks like this:

```bash
curl --noproxy '' -x http://127.0.0.1:8080 https://example.test/
```

The `CONNECT` row records destination, outcome, duration, and bytes in each
direction. No certificate is generated, no TLS is terminated, and no payload or
header inside the tunnel is visible to RAWFRAME.

Useful options:

```bash
rawframe --help
rawframe --port 8081
rawframe --scope example.test
rawframe --scope '*.example.test:443'
rawframe --scope https://api.example.test:443
rawframe --allow-private-upstreams
rawframe --bind 0.0.0.0 --allow-remote-bind
rawframe --no-mouse
rawframe --no-redact          # DANGEROUS: reveal sensitive header values
```

`--scope` may be repeated. Without any scope rule, every HTTP request and
CONNECT is denied. `--allow-private-upstreams` is required for loopback and
private lab targets such as `127.0.0.1`, `10.0.0.0/8`, or `::1`. Remote listener
binding requires `--allow-remote-bind`; the TUI Settings screen permits loopback
only.

The default log is written to `$XDG_DATA_HOME/rawframe/logs/rawframe.log`, or
`~/.local/share/rawframe/logs/rawframe.log` when `XDG_DATA_HOME` is unset. Logs
are local-only, contain no captured headers or bodies, and are created with
owner-only permissions on Unix. Use `--log-file` to choose another path.

## Defaults and limits

| Setting | Default | Enforcement |
|---|---|---|
| Listener | `127.0.0.1:8080` | loopback only unless explicitly authorized |
| Scope | empty allowlist, default deny | checked before DNS/connect |
| Max request body | 2 MiB | declared length rejected before streaming; streamed bytes bounded |
| Max response body | 2 MiB | declared length rejected before streaming; streamed bytes bounded |
| Max concurrent connections | 128 | excess client connections are closed |
| DNS/connect/handshake timeout | 10 s each | bounded upstream establishment |
| Response-header timeout | 30 s | `504` on timeout |
| Body and tunnel idle timeout | 60 s | stalled streams/tunnels are terminated |
| Upstream TLS verification | on, locked | no TLS termination path exists yet |
| Redaction | on | `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, API keys |

Settings are session-only and are not persisted. Network limits changed in the
TUI apply when the proxy is restarted; other values may still show the
configured value until then.

## Interception workflow (M3, current)

1. **Start RAWFRAME**: `cargo run -p rawframe-cli --bin rawframe -- --port 8080 --scope http://127.0.0.1:8000 --allow-private-upstreams` (adjust port/scope for your local authorized target).
2. **Start the proxy**: in the Proxy screen press `P` (or use the Start control) and wait for `LISTENING`.
3. **Configure scope**: use `--scope` rules (exact host / wildcard / optional scheme:port). With no allowlist rules, upstream requests are denied by default. `--allow-private-upstreams` is required for loopback/private lab targets.
4. **Enable interception**: press `I` in the Proxy screen to arm interception for matching HTTP requests (scope/interception rules as configured). HTTPS `CONNECT` tunnels remain opaque and are not decrypted/intercepted.
5. **Send traffic with curl** (example): `curl --noproxy '' -x http://127.0.0.1:8080 http://127.0.0.1:8000/`
6. **Edit / forward / drop**: when a matching HTTP request is paused it appears in the interception queue. Select it, press `E` to edit the raw HTTP request, `F` to forward unchanged, `Ctrl+Enter` to forward the validated modified request, or `D` to drop it. Validation failures keep the request pending.
7. **Use History**: resolved live transactions appear in HTTP History/inspector with interception-aware outcome metadata where available (e.g. forwarded unchanged/modified, dropped, timed out/cancelled, failed). Dropped/cancelled/timed-out requests do not fabricate upstream responses.

**Current limitations:** TLS interception/local CA is not implemented; HTTPS inside `CONNECT` is not inspectable. Real end-to-end TUI interception workflow automation/PTY coverage is limited in this environment (proxy-engine integration tests cover core interception behavior). UI behavior, shortcuts, and history/original-vs-final inspection are still being finalized.

## Build and quality gates

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

or `./scripts/check.sh`.

## Keyboard

`Ctrl+K` opens the command palette, `Ctrl+1`…`Ctrl+6` jump between modules,
`Tab`/`Shift+Tab` cycle focus, and `?` opens the full help overlay.

| Context | Keys |
|---|---|
| Navigation | `↑ ↓` / `j k`, `Enter`, `Tab` |
| Proxy | `P` start/stop, `Enter` inspect, `F` forward*, `D` drop*, `R` replay*, `E` edit* |
| History | `Enter` inspect, `/` or `Ctrl+F` search, `M` method, `S` status, `H` host, `Ctrl+U` clear |
| Inspector | `↑ ↓` scroll, `[` `]` request/response, `1` `2` `3` raw/headers/body |
| Repeater | `Enter` edit, `Ctrl+N` new tab, `Ctrl+W` close, `Ctrl+Enter` send (offline) |
| Application | `Q` quit, `Ctrl+C` immediate quit, `I` toggle inspector |

\* Forward/drop apply only to paused **simulated** fixtures. Live traffic is
forwarded automatically in Milestone 2; interception pause/edit is Milestone 4.
Repeater transmission remains unavailable and is labelled as such.

Single-letter shortcuts never fire while editing a document or search field.
`Ctrl+C` is always an immediate exit.

## Mouse

Click navigation, tabs, filter chips, and buttons. Click a traffic row to select
it and double-click to open the inspector. Right-click rows, tabs, and documents
for context actions. Scroll the panel under the pointer. Drag the vertical
dividers to resize the navigation and inspector panels.

## Architecture

```
rawframe-cli ──> rawframe-tui ──> rawframe-http ──> rawframe-core
      │                │                                 ▲
      ├──> rawframe-proxy ────────────────────────────────┤
      └───────────────────────────────────────────────────┘
```

- **rawframe-core** — request/response/traffic/tunnel models, configuration,
  scope rules, lifecycle validation, history filters, bounded event bus,
  application commands, terminal-safety primitives, and labelled fixtures. No
  I/O.
- **rawframe-http** — HTTP/1.x document parsing for the Repeater and tests. It
  is not the wire-framing implementation used by the proxy.
- **rawframe-proxy** — Tokio + Hyper HTTP/1.1 listener, streaming forwarder,
  opaque CONNECT relay, scope/address enforcement, limits, capture events, and
  graceful shutdown. It does not depend on the TUI.
- **rawframe-tui** — Ratatui/Crossterm application shell, screens, state machine,
  rendering, input handling, and terminal lifecycle. It never opens sockets; it
  polls `AppEvent`s and emits `AppCommand`s.
- **rawframe-cli** — composition root: owns the Tokio runtime, starts the proxy
  worker, attaches its bounded command channel to the UI, and runs the terminal
  loop.

Read [architecture](docs/architecture.md),
[dependency graph](docs/dependency-graph.md),
[security model](docs/security.md), [development](docs/development.md), and
[roadmap](docs/roadmap.md) for details. See [CONTRIBUTING.md](CONTRIBUTING.md)
and [SECURITY.md](SECURITY.md) for contribution and vulnerability reporting.
[development guide](docs/development.md), and
[roadmap](docs/roadmap.md).

## Security posture in this build

- Listener defaults to loopback; remote bind requires an explicit CLI flag.
- Target scope is default-deny. Every HTTP request and CONNECT is checked before
  upstream resolution or connection.
- Hostnames are resolved once; **every** resolved address is validated against a
  public-address policy, and the connection uses those exact addresses. Private
  and loopback answers require `--allow-private-upstreams`; link-local, metadata,
  multicast, unspecified, documentation, and reserved ranges are rejected.
- Absolute-form scheme/host/port must match the `Host` header. Duplicate `Host`
  headers and invalid authorities are rejected.
- Hop-by-hop headers are removed in both directions; end-to-end duplicates are
  preserved. `Content-Length` on responses is regenerated by Hyper's framing.
- Request/response bodies are streamed with hard byte caps. Malformed requests,
  upstream failures, header timeouts, and stalled bodies become recorded failures
  rather than fabricated successes.
- Event/command channels are bounded. Excess connections are refused, and
  tunnels/body streams have activity-based idle limits.
- `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, and common
  API-key headers are redacted by default in the inspector.
- Captured text is escaped for terminal display, including C0/C1 controls and
  Unicode bidi overrides.
- Upstream TLS verification is locked on, but **no TLS interception exists yet**,
  so tunneled certificates are not validated by RAWFRAME — the client validates
  them end to end. There is no insecure verification toggle.
- Bodies and sensitive headers are not persisted; no database exists in this
  build. Local logs contain lifecycle events, not captured traffic.
- No telemetry, no shell execution from captured content, and no certificate
  authority/private key generation.

See [docs/security.md](docs/security.md) for the threat model, controls, and
known gaps.

## Known limitations

- HTTPS `CONNECT` is opaque: no URL, headers, body, certificate, or response
  inside the tunnel is captured. Only destination and byte/duration metadata.
- Only HTTP/1.1 is handled; HTTP/2, WebSocket upgrade forwarding, and HTTP/3 are
  not supported. Hop-by-hop `Upgrade` is stripped.
- Interception pause/edit/forward/drop is not wired to live traffic yet. The
  existing forward/drop controls affect only simulated paused fixtures.
- Repeater still cannot transmit. Settings and history are in-memory only.
- Connection-limit overflow closes the socket without an HTTP `503`.
- A configured connect/DNS/handshake timeout is applied to each phase, so one
  request can spend up to roughly three times that limit while establishing an
  upstream; the overall request is not given a single unified deadline.
- DNS policy is deliberately conservative and may reject some special-purpose
  address ranges.
- No authentication on the proxy listener. Keep it on loopback or protect remote
  binding at the host firewall; `--allow-remote-bind` is an explicit risk.
- No rate limiting or per-client quotas beyond the global connection limit.

## Licensing

MIT. See [LICENSE](LICENSE).

## Current limitations

- HTTPS `CONNECT` is opaque: no TLS interception, no local CA/certificate management, and no decrypted HTTPS inspection.
- SQLite persistence, sessions, and export are not implemented.
- Intruder and Decoder are planned placeholders; Repeater transmission is not available.
- Scope is default-deny; private upstreams and non-loopback listener binding require explicit opt-in.
