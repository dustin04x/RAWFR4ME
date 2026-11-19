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

## Milestone 7 — Decoder and transformation workbench (implemented)

### M7 status (this workspace)

- The transformation engine lives in `rawframe-core::decoder` and operates on
  bytes, not assumed-UTF-8 text. It has no TUI, network, storage, or shell
  dependency.
- 22 transformations: Base64 standard/URL-safe encode and decode, hex encode and
  decode, URL percent encode and decode, HTML entity encode and decode, Unicode
  escape encode and decode, JWT inspection, JSON pretty/minify/validate, gzip
  compress/decompress, SHA-256/384/512, and MD5 (legacy only).
- JWT inspection decodes the header and payload, surfaces the algorithm and
  claims, formats `exp`/`nbf`/`iat`, and explicitly says the signature is not
  verified. A successful decode is never presented as a valid token.
- Pipelines execute sequentially with up to 16 steps over bounded 8 MiB input
  and output. Each step's output is retained for inspection; a failure stops the
  pipeline and reports the exact step without substituting empty data.
- The Decoder workspace provides input/output panels, a transformation selector,
  direction control, add/remove/reorder, execute, preview intermediate steps,
  swap, clear, copy, and session history. It fits 140×40, 100×30, and 80×24.
- Repeater can explicitly send the current request or response body to the
  Decoder and explicitly insert transformed output into the request body. The
  original request, stored captures, and response are not mutated.
- Gzip output is bounded; malformed, truncated, and oversized streams fail
  cleanly. Binary output is shown as a hex dump. Nothing is logged, persisted, or
  transmitted externally.

Exit criteria/tests are satisfied by core unit tests (encoding round trips,
invalid input, JWT/JSON/compression/hash vectors, pipeline failure and limits),
TUI controller tests for editing/execution/copy/swap/history/Repeater transfer,
and render tests at all three supported sizes.

Explicitly not included: Intruder, persistent Decoder history, scripting or
shell execution, and automatic background transformations.

## Milestone 8 — Intruder payload workbench (implemented)

### M8 status (this workspace)

- Payload positions use the `§value§` marker and are scanned at the byte level,
  so binary bodies work. Every marked span becomes a component-tagged position
  (URL path, query value, header value, body) with a stable ID and its own
  enabled flag. Unmatched markers, markers inside a header name, and non-UTF-8
  payloads in URL or header positions are rejected with a message that names
  the problem; an empty marker span is a valid empty literal.
- Payload sources are editable manual lists, eight harmless built-in demo
  values, session-local named lists (create, rename, inspect, delete), and local
  wordlists imported by path. Wordlists are bounded at 4 MiB, streamed line by
  line, never executed, and count invalid UTF-8 lines instead of replacing them.
- Four strategies with exact counts: Sniper (`positions × payloads`), Battering
  Ram (`payloads`), Pitchfork (shortest list, equal-length requirement), and
  Cluster Bomb (Cartesian product). Empty lists, length mismatches, and plans
  above 2048 requests are refused before execution, and the count is shown in
  the header while editing.
- Execution reuses `RepeaterEngine::execute`; there is no second HTTP stack.
  Scope, resolve-once address policy, verified TLS, and timeouts match Repeater.
  Redirects are off by default and re-validated on every hop.
- Bounded concurrency, a conservative rate gate, per-request timeouts, bounded
  response capture, pause/resume/cancel/shutdown, and typed outcomes are
  enforced in `rawframe-intruder`, not in the UI.
- A start confirmation names the target, strategy, request count, concurrency,
  rate, redirect policy, and scope. Nothing is sent before it is accepted.
- The results workspace shows real status, size, duration, payload values, and
  request/response/payload inspection, with search, status and outcome filters,
  sort, baseline comparison, and explicit Repeater transfer. No status or timing
  difference is presented as a vulnerability.
- History, Repeater, and Decoder transfer requests into the Intruder without
  mutating the origin. Completed Intruder runs persist through schema v3 with
  the payload values and optional origin capture; payload lists stay session-only.
- Fits 140×40, 100×30, and 80×24, with real PTY frames under
  `docs/screenshots/intruder/`.

Exit criteria are covered by core planning/strategy/validation tests, engine and
service integration tests against local HTTP and HTTPS origins (including
pause/resume/cancel, scope refusal, timeouts, and redirect policy), wordlist
limit tests, store migration/round-trip tests, transfer tests, and TUI render
tests at all three sizes. At the M8 exit the workspace suite was 427 passing
tests.

Explicitly not included: response-matching rules, fuzzing dictionaries beyond
payload lists, HTTP/2 or WebSocket payloads, proxy rotation, and any evasion or
rate-limit bypass.

## Milestone 9 — HTTP/2 support (implemented)

### M9 status (this workspace)

- Genuine HTTP/2 is negotiated through ALPN and spoken with Hyper's HTTP/2
  implementation. A plaintext proxy request is never relabelled: h2c is not
  implemented, and `h2` is used only on an exact ALPN match.
- Intercepted TLS offers `h2` then `http/1.1` on both the client-facing and
  upstream legs, and reads back each negotiated result independently. An HTTP/2
  client can therefore be bridged to an HTTP/1.1 upstream and the reverse.
- Multiplexed upstream streams no longer serialize behind a single mutex. The
  HTTP/1.1 path keeps its mutex unchanged; the HTTP/2 path clones a send handle
  per stream and waits for the response without holding a lock.
- Pseudo-headers stay structured: `:method`, `:scheme`, `:authority`, and `:path`
  map to the existing request fields and are never stored as ordinary headers.
  `rawframe_core::h2` is the single conversion boundary for the proxy and
  Repeater (ALPN matching, header sanitization, absolute-URI reconstruction).
- Per-stream interception works over one HTTP/2 connection: two paused streams
  are queued together, and forwarding one does not block or forward the other.
  Drop, modified forwarding, timeout, and scope revalidation remain per stream.
- The proxy, history, inspector, Repeater, and Intruder report the actual
  protocol. History gained a `PROTOCOL` column at wide sizes and the inspector
  shows the request protocol; a response reports the upstream protocol even when
  it differs from the client leg. Opaque tunnels stay labelled unknown.
- Limits: 128 concurrent streams per client connection and a 64 KiB request
  header list, on top of the existing body, timeout, connection, and queue caps.
- No schema migration was required: protocol metadata uses the existing
  `version`/`response_version` columns, and M5–M8 data remains readable.
- Fits 140×40, 100×30, and 80×24, with real PTY frames under
  `docs/screenshots/http2/`.

Exit criteria are covered by HTTP/2 integration tests that perform real ALPN
handshakes and Hyper HTTP/2 framing: both-legs h2 with concurrent streams,
HTTP/1.1 fallback, cross-protocol bridges, per-stream pause/forward/drop/modify,
interception timeout, shutdown cancellation, redirects, Intruder execution
through the Repeater, and protocol round-trips through SQLite/export. The
workspace suite is 447 passing tests.

Explicitly not included: HTTP/3, WebSocket upgrades, h2c, server push, priority
controls, QUIC, and any second networking stack.

## Milestone 10 — WebSocket interception and Repeater (implemented)

### M10 status (this workspace)

- HTTP/1.1 `Upgrade: websocket` requests are recognized before normal
  forwarding. The destination is scope-checked and address-validated, the
  upstream handshake is performed over the existing verified TCP/TLS path, and
  the client receives `101` only after upstream accepts and `Sec-WebSocket-Accept`
  is verified.
- Frames are relayed with a RAWFRAME-owned RFC 6455 codec rather than a
  message-oriented library, so boundaries, FIN, RSV, opcode, masking, binary
  payloads, fragmentation, ping/pong, unknown control frames, and close are
  preserved in both directions.
- Interception works per frame in both directions: forward unchanged, drop, or
  modify text/binary payload. A full queue forwards unchanged with a warning;
  timeout or cancellation closes with `1001`. Completed text messages are
  UTF-8-validated; protocol errors close with `1002`/`1007`.
- `Sec-WebSocket-Extensions` is stripped and compression is never negotiated;
  RSV bits are rejected. Subprotocols are preserved and recorded.
- A dedicated WebSocket workspace lists connections and frame history with
  direction, opcode, length, outcome, filter, inspector, mouse support, and a
  payload editor. It fits 140×40, 100×30, and 80×24.
- Schema v4 adds connection/frame/message tables through an additive migration.
  Captures are binary-safe and follow the storage body/redaction policy;
  `payload_omitted` distinguishes withheld payloads from empty frames.
- An authored WebSocket Repeater opens independent scoped sessions with verified
  TLS, composes text frames, shows both directions, and is labelled
  `TrafficSource::Repeater`. Frame/connection IDs start at 3,000,000.
- Limits: 64 WebSocket tunnels, 2 MiB frame, 8 MiB message, 64 KiB retained
  payload, 300 s idle timeout, and the bounded interception queue/timeout.
- Explicitly not included: HTTP/3, QUIC, RFC 8441 extended CONNECT, WebSocket
  over HTTP/2, `permessage-deflate`, and binary composition in the Repeater.
- Real PTY evidence is under `docs/screenshots/websocket/` at all three sizes:
  captured frames, an authored Repeater session, and a composed frame with its
  echo. `scripts/capture_websocket_pty.py` drives a real client and echo server.

## Known limitations at 0.2.0

- The plaintext listener is HTTP/1.1 only; h2c is not implemented. HTTP/2
  requires TLS and an `h2` ALPN result. HTTP/1.1 WebSocket upgrades are
  supported, but RFC 8441 extended CONNECT, WebSocket over HTTP/2, HTTP/3,
  QUIC, and WebSocket compression are not; other `Upgrade` protocols are
  stripped.
- HTTP/2 server push, priority, and extended CONNECT are not exposed. Pinned
  clients fail the intercepted handshake by design; RAWFRAME does not bypass
  certificate pinning.
- Opaque `CONNECT` captures only destination/outcome/byte/duration metadata; no
  URL, headers, body, or tunneled certificate is visible.
- Scope rules are editable in Settings while the proxy runs. Established
  connections and already-forwarded requests keep the rules they were admitted
  under; changes apply to new requests.
- Interception is scoped per CONNECT session; a modified request cannot switch
  to a different authority inside the same intercepted TLS session.
- HTTP/2 is automatic over TLS; there is no manual protocol override. Header
  order is preserved where HTTP/2 permits it.
- Persisted history is a local SQLite database with a 512 MiB default ceiling.
  Bodies and sensitive header values are off by default; changing the policy
  never rewrites entries already stored. Settings themselves (limits, accent)
  remain session-only because there is no configuration file.
- Repeater opens direct connections and negotiates HTTP/1.1 or HTTP/2 over TLS.
  It cannot reuse a captured connection, client certificate, or proxy-auth path;
  results may differ from the original capture. Drafts are session-only;
  completed executions are persisted.
- WebSocket interception is frame-level. Fragmented messages are decided per
  frame, and a modified fragment keeps its original FIN/RSV state. Retained
  payloads are truncated at 64 KiB with an explicit flag; the relay forwards the
  full frame while under the 2 MiB frame cap.
- WebSocket Repeater sessions seed only the destination metadata and compose
  text. They are not replays of the captured socket and do not copy headers,
  cookies, or connection state. Binary composition and per-frame editing are not
  available.
- Decoder input/output is capped at 8 MiB and pipelines at 16 steps. Decoder
  content and history are session-only and never persisted. JWT inspection does
  not verify signatures, MD5 is legacy-only, and clipboard copy relies on
  terminal OSC 52 support.
- Intruder inherits Repeater protocol negotiation; it has no response-matching
  or fuzzing engine and keeps payload lists in memory. Its rate and concurrency are local pacing, not
  a guarantee about the target.
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

**M11 — Passive security analysis.** Implementation is present and undergoing
final verification. Captured HTTP/1.1, HTTP/2 shared messages, WebSocket
handshakes, and eligible text messages are analyzed locally by a bounded
worker. Findings use session-scoped persistence and project-wide bounded
traffic paging through the existing store worker. The Security Findings
workspace supports filters, search, sorting, inspection, lifecycle actions,
related traffic, reanalysis, and JSON/Markdown exports. PTY captures exist at
140×40, 100×30, and 80×24. The inventory records tested behavior and known
limitations; M11 is not considered accepted until the final full suite and
end-to-end evidence pass. HTTP/3 / RFC 8441 coverage remains future work.
