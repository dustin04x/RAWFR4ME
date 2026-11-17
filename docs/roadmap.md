# Roadmap

RAWFRAME is built in testable milestones. A later milestone does not begin until
the previous milestone’s foundation and tests pass. Nothing in this roadmap is
claimed as implemented until it appears under “completed” with tests.

## Milestone 1 — Application foundation ✅

Delivered in 0.1.0:

- Cargo workspace with one-way crate dependencies and documented graph.
- Shared request/response/traffic/session/config/certificate models.
- Validated interception lifecycle and default-deny scope model.
- Asynchronous application event bus and outbound command contract.
- Terminal lifecycle with raw mode, alternate screen, mouse capture, bracketed
  paste, panic-safe restoration, and responsive resize handling.
- Persistent shell: header, navigation, workspace, context inspector, footer.
- Theme system with three restrained accent presets and semantic colors.
- Keyboard-first navigation with focus management and context-sensitive keys.
- Mouse navigation, row selection, double-click inspection, context menus,
  wheel scrolling, and draggable panel dividers.
- Command palette with fuzzy ranking.
- Proxy, HTTP History, Repeater, and Settings screens.
- Request/response inspector with raw, headers, and body views.
- Search and cumulative method/status/host filters.
- Multiple Repeater tabs with an editable, parse-validated document buffer.
- Sensitive-header redaction and terminal-safe rendering of hostile content.
- 17 clearly labelled simulated transactions.
- Unit tests across every crate plus keyboard/mouse integration tests.
- Architecture, dependency, security, development, and roadmap documentation.

## Milestone 2 — HTTP proxy engine ✅

Delivered in 0.2.0:

- Dedicated `rawframe-proxy` crate using Tokio and Hyper; no dependency on the
  TUI.
- Tokio listener with bounded concurrency, header read limits/timeouts, and
  graceful shutdown.
- Real HTTP/1.1 absolute-form forwarding for IPv4, IPv6, and hostname
  destinations.
- Streaming request and response bodies through bounded guarded bodies; no
  full-body buffering for forwarding.
- Duplicate end-to-end header preservation, hop-by-hop filtering, and normalized
  upstream requests.
- Opaque HTTPS `CONNECT` tunneling with bidirectional relay, half-close,
  activity idle timeout, byte counts, duration, and metadata events.
- Default-deny scope for exact/wildcard hosts, scheme, and port.
- Resolve-once DNS with validation of every resolved address, including
  loopback/private opt-in and always-blocked link-local/metadata/reserved ranges.
- Request/response body caps, connection limits, DNS/connect/handshake timeout,
  response-header timeout, and idle timeout.
- Bounded event/command channels with async backpressure.
- Real proxy lifecycle commands, actual bound address/state events, live HTTP
  captures, CONNECT metadata, failures, and live counts in the TUI.
- Live captures inserted into the existing history/filter/inspector flow with
  `LIVE` provenance; simulated fixtures remain visibly separate.
- Tunnel inspector that states payload is not captured and displays no fabricated
  HTTP body.
- Local-only integration suite covering forwarding, streaming, duplicate
  headers, malformed requests, invalid destinations, scope, exact/wildcard,
  scheme/port, IPv4/IPv6, CONNECT, bidirectional traffic, half-close, upstream
  failure, timeouts, concurrency, connection limits, DNS policy, and shutdown.
- TUI-to-engine boundary test that starts the real worker with `P`, receives a
  real capture, renders `LIVE ENGINE`/`LIVE REQUESTS`, stops the worker, and
  verifies clean exit.
- README, architecture, dependency, security, development, and roadmap updates.

Explicitly absent: TLS interception, CA/certificate generation, live pause/edit,
SQLite persistence, export, Repeater transmission, Intruder, Decoder.

## Milestone 3 — Interception workbench (implemented)

### M3 status (this workspace)

- Real HTTP interception engine implemented in proxy/core with bounded queue, pause-before-upstream for matching requests, forward unchanged/modified/drop, timeout/cancel handling, and real-engine integration tests.
- TUI interception workbench integrated (queue/editor/actions/event sync, history/inspector outcome display) with PTY verification completed.

Goal: operator-controlled pause/modify/forward/drop without blocking unrelated connections.

Scope:

- Pause matching live HTTP requests before upstream contact.
- Per-request forward, drop, edit-and-forward, and cancellation.
- Interception timeouts and bounded queues.
- Scope-aware matching and validated modified destinations.
- Clear “no fabricated response” behavior for dropped, cancelled, and timed-out requests.

Exit criteria / tests:

- Pause/forward/drop integration tests with a local server.
- Timeout and cancellation tests; no deadlock when the TUI is busy.
- Rule matching and scope enforcement tests.
- End-to-end intercept-edit-forward assertion against the local upstream.

## Milestone 4 — HTTPS TLS interception (implemented)

### M4 status (this workspace)

- Opt-in HTTPS TLS interception implemented for HTTP/1.1: local CA management, per-host leaf certificates, separate verified upstream TLS, decrypted requests through the existing interception queue, and local TLS integration tests.
- Enabling/disabling TLS applies to new CONNECT sessions; established sessions keep their configuration snapshot until close.
- Opaque `CONNECT` remains the default and works unchanged when interception is disabled.
- CA lifecycle CLI commands, certificate/X.509 tests, HTTPS lifecycle tests, and a real-binary PTY regression are in place.

Goal: functional HTTPS interception with a securely managed local CA and
separate verified upstream TLS.

Scope:

- Generate the local CA only on explicit operator command.
- Owner-only key permissions (`0600`), restricted directory (`0700`).
- Client-facing Rustls termination with per-host leaf certificates.
- Separate upstream Rustls connection with verification enabled.
- Bounded certificate cache; scope-limited issuance.
- Clear trust instructions and CA fingerprint display.
- Explicit interception mode while preserving the opaque CONNECT path.
- Never silently disable upstream verification.

Exit criteria / tests:

- Certificate generation and metadata tests.
- Hostname leaf issuance, cache reuse, expiry, and SAN coverage.
- End-to-end HTTPS interception against a self-contained local TLS server.
- Upstream verification failure is reported, not bypassed.
- HTTPS pause/drop/modify flows and SNI/CONNECT mismatch fail-closed tests.
- Client trust failure produces an actionable error.
- Client/upstream disconnect and proxy shutdown cancel pending work cleanly.
- No key material is logged or serialized into traffic/session state.
- Opaque CONNECT still works when interception is disabled.
- Real TUI controls are exercised through a PTY at 140×40, 100×30, and 80×24.

## Milestone 5 — History, sessions, and protocol coverage (implemented)

### M5 status (this workspace)

- New `rawframe-store` crate owns SQLite and a single writer thread; the proxy,
  core, and TUI never link SQLite.
- Versioned migrations (`schema_migrations` + `user_version`) create projects,
  sessions, and traffic tables with ordered-header JSON, nullable body BLOBs,
  lifecycle state, timestamps, durations, notes, tunnel metadata, and an
  `incomplete` flag for interrupted transactions.
- Captures are written by an independent event-bus subscriber, so the proxy
  request path never waits on disk. The writer batches transactions, uses WAL
  with `synchronous=FULL`, and counts captures it cannot enqueue.
- Redaction happens before SQL: sensitive header values become `<redacted>`
  unless explicitly opted in; bodies are stored as SQL `NULL` unless opted in.
  Restored entries expose that omission instead of showing an empty body.
- Sessions are listed, restored read-only into History, exported as redacted
  JSON Lines, and filtered with the existing History filters. Restored entries
  use a distinct `RESTORED` provenance and are never treated as live.
- Interrupted sessions are closed on the next open and their unfinished
  transactions stay marked incomplete; corruption, a full database, a newer
  schema, or an unwritable location disables persistence with a visible error
  while the proxy keeps running.
- The target scope is editable from Settings and applied to new requests
  without restarting the listener; the CLI and the editor share one rule parser.
- Protocol coverage was not expanded. HTTP/2, HTTP/3, and WebSocket remain
  explicitly unsupported rather than half-implemented.

Goal: durable history, sessions, and broader protocol coverage.

Scope:

- Rule editing UI and scope-aware matching.
- SQLite migrations, sessions, request/response relationships, timestamps,
  durations, and recovery from incomplete sessions.
- Redaction on write; bodies and sensitive headers opt-in.
- History export and filtering across persisted sessions.
- Protocol coverage beyond HTTP/1.1 where it can be implemented honestly.

Exit criteria / tests:

- SQLite round-trip, migration, and crash-recovery tests.
- Persistence defaults prove no bodies/sensitive headers are written.
- Export redaction tests.
- Persisted history relationships and incomplete-session recovery tests.

## Milestone 6 — Repeater (implemented)

### M6 status (this workspace)

- New `rawframe-repeater` engine opens independent HTTP/1.1 connections over
  HTTP or verified HTTPS. It does not use the proxy listener, CONNECT tunnel,
  local CA, or interception queue.
- It reuses the public `rawframe-proxy` destination resolution/address policy
  and upstream TLS configuration, so scope, private-upstream opt-in, DNS
  resolve-once, and certificate/hostname verification cannot diverge.
- Real request validation, arbitrary methods, custom ports, query strings,
  ordered duplicate headers, and binary bodies. `CONNECT` and ambiguous framing
  are rejected before DNS.
- Per-tab execution lifecycle: Draft, Validating, Connecting, Sending, Receiving,
  Completed, Failed, Cancelled, TimedOut, and Blocked. Late events cannot
  overwrite a newer execution or another tab.
- Raw, Headers, Body, Pretty JSON, Hex, and Compare inspection. Comparison covers
  status, headers, body bytes, size, and duration; the raw response model is not
  mutated by display modes.
- Safe redirects are opt-in, capped at five hops, scope-checked per hop, and
  strip credentials cross-origin. 301/302 POST→GET and 303→GET rewrite; 307/308
  preserve method/body.
- Response limits, connect/header/body-idle/total timeouts, per-execution
  cancellation, and a bounded concurrency limit are enforced.
- Completed executions are labelled `REPEATER`, optionally reference the
  original capture, and persist through the existing redaction/body policy.
  Schema version 2 adds `repeater_origin` without rewriting M5 databases.

Exit criteria/tests are satisfied by `rawframe-repeater/tests/execution.rs`
(real local HTTP and HTTPS servers), TUI controller/render tests, and store
provenance/redaction tests. No execution occurs while typing; only an explicit
send/cancel command reaches the engine.

Explicitly not included: Intruder, Decoder, durable draft documents,
HTTP/2/WebSocket, client certificates, proxy-auth, or replay through the proxy
listener.

## Later — Intruder and Decoder

Intruder:

- Payload positions and templates, bounded concurrency/rate control, scope
  enforcement, result analysis without fabricated findings.

Decoder:

- Chained transforms, raw byte inspection, conversion history, no shell
  execution of decoded content.

## Known limitations at 0.2.0

- Only HTTP/1.1 is handled. HTTP/2, HTTP/3, and WebSocket upgrade forwarding are
  not supported; `Upgrade` is stripped.
- HTTPS TLS interception is HTTP/1.1 only. Pinned clients fail the intercepted
  handshake by design; RAWFRAME does not bypass certificate pinning.
- Opaque `CONNECT` captures only destination/outcome/byte/duration metadata; no
  URL, headers, body, or tunneled certificate is visible.
- Scope rules are editable in Settings while the proxy runs. Established
  connections and already-forwarded requests keep the rules they were admitted
  under; changes apply to new requests.
- Interception is scoped per CONNECT session; a modified request cannot switch
  to a different authority inside the same intercepted TLS session.
- Persisted history is a local SQLite database with a 512 MiB default ceiling.
  Bodies and sensitive header values are off by default; changing the policy
  never rewrites entries already stored. Settings themselves (limits, accent)
  remain session-only because there is no configuration file.
- Protocol coverage is HTTP/1.1 only.
- Repeater opens direct connections and supports HTTP/1.1 only. It cannot reuse
  a captured connection, client certificate, or proxy-auth path; results may
  differ from the original capture. Drafts are session-only; completed
  executions are persisted.
- No listener authentication. Keep the proxy on loopback; remote binding
  requires `--allow-remote-bind` and host-level protection.
- Connection-limit overflow closes the socket rather than returning `503`.
- DNS/address policy is conservative and may reject special-purpose lab ranges.
- Local logs are not rotated.
- The Repeater editor seeds text with redaction applied when redaction is
  enabled; toggling redaction does not rewrite existing buffers.
- Truecolor is assumed for the intended look; 8/16-color terminals will degrade.
- The minimum usable size is 64×18; the inspector requires 108 columns.

## Recommended next step

**Milestone 7: Intruder and Decoder.** Repeater execution, history, sessions, and
export now exist. Build payload-position/rate-controlled Intruder and chained
Decoder transforms without fabricating findings or executing decoded content.
