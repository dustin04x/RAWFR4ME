# RAWFRAME Architecture

**Status:** Milestone 5 — durable history (0.2.0). HTTP/1.1 forwarding, opaque
HTTPS CONNECT tunnels, live pause/edit/forward/drop, opt-in HTTP/1.1 TLS
interception, SQLite sessions/persistence, redacted export, and live scope
editing are implemented. Repeater transmission is not.

## 1. Design constraints

1. **Separation of concerns.** Presentation, domain models, HTTP document
   parsing, networking, and (future) storage are separate crates with one-way
   dependencies.
2. **The TUI never controls sockets or databases.** It consumes application
   events and emits intents across a command boundary.
3. **No hard-coded coordinates.** Layout is computed once per frame from the
   terminal area; rendering records hit rectangles and scroll zones in the same
   coordinate space that input consumes.
4. **Security is part of the type design.** Scope is default-deny, TLS
   verification defaults on, redaction defaults on, and persistence of
   sensitive material defaults off.
5. **No fabricated behaviour.** Features that are absent are either omitted or
   clearly identified as planned. Simulated fixtures are labelled everywhere and
   are never mixed into live lifecycle events.
6. **Small, testable units.** Editing, filtering, parsing, sanitization, scope,
   address policy, and lifecycle transitions are pure enough to test without a
   terminal or external network.

## 2. Workspace

```
rawframe/
├── Cargo.toml                  workspace, shared dependency versions
├── crates/
│   ├── rawframe-core/          domain + application contracts (no I/O)
│   │   ├── models/             message, traffic/tunnel, config, session, certs
│   │   ├── events.rs           bounded EventBus, AppEvent, AppCommand
│   │   ├── filter.rs           HTTP history filtering
│   │   ├── security.rs         terminal-safe display conversion
│   │   └── fixtures.rs         17 labelled simulated transactions
│   ├── rawframe-http/          authored HTTP/1.x document parser
│   ├── rawframe-proxy/         Tokio/Hyper forwarding + CONNECT engine
│   │   ├── server.rs           listener, lifecycle commands, shutdown
│   │   ├── service.rs          HTTP forwarding and CONNECT orchestration
│   │   ├── destination.rs      authority parsing, scope, DNS/IP policy
│   │   ├── body.rs             bounded streaming body with capture
│   │   ├── tunnel.rs           opaque relay, half-close, idle timeout
│   │   └── error.rs            typed startup/worker errors
│   ├── rawframe-store/         SQLite persistence (no TUI/proxy dependency)
│   │   ├── schema.rs           versioned migrations
│   │   ├── record.rs           policy-redacted entry <-> row encoding
│   │   ├── store.rs            one writer connection, queries, export
│   │   ├── worker.rs           storage thread, batching, status events
│   │   └── error.rs            typed storage failures
│   ├── rawframe-tui/           terminal application
│   │   ├── app.rs              controller state and actions
│   │   ├── input.rs            keyboard + mouse dispatch
│   │   ├── ui.rs               shell composition
│   │   ├── layout.rs           geometry and resize rules
│   │   ├── interaction.rs      hit targets, scroll regions, render output
│   │   ├── screens/            Proxy, History, Repeater, Settings, placeholders
│   │   ├── components/         panels, buttons, inspector, editor, overlays
│   │   ├── state.rs            view-local state
│   │   ├── text.rs             editable multi-line buffer
│   │   ├── commands.rs         palette catalogue and fuzzy ranking
│   │   ├── theme.rs            visual system
│   │   ├── terminal.rs         terminal lifecycle + event loop
│   │   └── testing.rs          in-memory frame helper for tests
│   └── rawframe-cli/           composition root, args, logging
│       └── main.rs             runtime + proxy worker + store + capture pump + TUI
├── docs/
└── scripts/
```

Repeater document logic currently lives in `rawframe-core` + `rawframe-http` +
`rawframe-tui`; it can be extracted when transmission exists.

## 3. Dependency direction

```
                 ┌────────────────┐        ┌─────────────────┐
                 │  rawframe-cli  │───────▶│ rawframe-proxy  │
                 └───┬────┬───┬───┘        └────────┬────────┘
                     │    │   │                     │
        ┌────────────▼─┐  │   │            ┌────────▼────────┐
        │rawframe-store│  │   │            │  rawframe-http  │
        └──────┬───────┘  │   │            └────────┬────────┘
               │          │   │                     │
               │   ┌──────▼───▼────┐                │
               │   │  rawframe-tui │────────────────┘
               │   └──────┬────────┘
               │          │
               └──────────▼─────────┐
                          ▼          ▼
                   ┌────────────────────┐
                   │   rawframe-core    │
                   └────────────────────┘
```

Rules:

- `rawframe-core` depends on no RAWFRAME crate. It remains free of terminal,
  socket, and database APIs.
- `rawframe-http` depends only on `rawframe-core`.
- `rawframe-proxy` depends on `rawframe-core`; it **must not** depend on
  `rawframe-tui`.
- `rawframe-tui` depends on `rawframe-core` and `rawframe-http`; it **must not**
  depend on `rawframe-proxy`. It sees the engine only through shared events and
  the `CommandSender` type defined in core.
- `rawframe-store` depends on `rawframe-core` and SQLite; it must not depend on
  the proxy or the TUI. The TUI never links SQLite.
- `rawframe-cli` is the only composition root and may depend on all crates. It
  hosts the capture pump that bridges the event bus to the storage worker.

## 4. Runtime data flow

```
 client ──▶ rawframe-proxy ──AppEvent──▶ bounded EventBus ──poll()──▶ App (TUI)
                                                │
                                                └──subscribe()──▶ capture pump
                                                                     │ try_record
                                                                     ▼
                                                          storage thread (SQLite)
                                                App (TUI) ──StorageCommand──▶ store
                                                store ──StorageEvent──▶ EventBus
```

`rawframe-cli` owns a multi-thread Tokio runtime. It spawns
`rawframe_proxy::run_service(command_rx, event_sender)`, starts the storage
worker and capture pump, then runs the synchronous TUI. The UI runtime is
independent: input arrives on a Crossterm reader thread, events are polled, and
frames redraw on input or at a 250 ms idle cadence. No proxy or storage task is
awaited on the UI thread.

`rawframe_core::events::EventBus` is a **bounded** fan-out of Tokio MPSC queues
(`EVENT_QUEUE_CAPACITY = 4096`). Synchronous UI/test producers use
`EventSender::send` (non-blocking `try_send`); async proxy paths use
`send_async` and therefore apply backpressure instead of growing memory without
bound. `EventBus::subscribe` registers the capture pump. Dropped subscribers are
skipped so they cannot abort the proxy. The command channel from UI to proxy is
also bounded (capacity 32).

Commands:

- `StartProxy(Box<AppConfig>)` and `StopProxy` control the engine.
- `SetInterception` arms or disarms live pause-before-upstream.
- `SetTlsInterception` explicitly enables/disables HTTPS TLS interception for
  new CONNECT sessions in this running proxy.
- `ForwardRequest`, `ForwardModified`, and `DropRequest` resolve pending
  interception entries. Dropped requests never reach upstream.
- `UpdateScope(Scope)` replaces the live allowlist. New HTTP requests and
  CONNECT sessions use it immediately; already-forwarded work is unchanged.

Events:

- `ProxyStateChanged` drives `Idle → Starting → Listening → Stopping → Stopped`
  or `Failed`.
- `ProxyBound(SocketAddr)` reports the actual bound address.
- `TrafficCaptured` / `TrafficUpdated` carry HTTP captures, decrypted HTTPS
  requests, and CONNECT tunnel metadata.
- `InterceptionPaused` / `InterceptionQueueChanged` drive the pending queue.
- `TlsStateChanged` publishes TLS enabled/disabled state, the public CA path and
  fingerprint, or a non-secret enable error.
- `Storage(StorageEvent)` carries persistence status, stored session lists,
  restored entries, export results, and storage failures.
- `Notice` surfaces lifecycle warnings/errors.

Events carry IDs, not UI selections; the TUI resolves selected entries by
`TrafficId`. This keeps the controller stable when filters or sort order change.
Live IDs start at 1000 and are allocated by the running service. Fixtures keep
their low IDs and `TrafficSource::Simulated`.

## 5. Proxy engine

### 5.1 Listener and lifecycle

`server::start_proxy` validates configuration, binds a `TcpListener`, creates a
Hyper HTTP/1 server with HTTP/1 keep-alive, a 64 KiB read buffer cap, and header
read timeout, then starts an accept loop. Configuration validation requires a
non-zero port, bounded body/connection limits, non-zero timeouts, and a valid
scope.

- Connection concurrency uses a Tokio `Semaphore` (`max_connections`). The
  permit is held for the client connection; excess sockets are closed.
- A separate tunnel semaphore bounds CONNECT relays that outlive the upgraded
  client connection.
- `ProxyHandle::shutdown` signals a watch channel, waits for the listener and
  tracked connection tasks (up to 5 s), then aborts remaining tasks. Service
  shutdown waits up to 8 s total. Active CONNECT pumps observe shutdown, record
  their byte counts, and close.
- The listener sends an explicit warning when it starts with an empty
  default-deny scope.

`run_service` owns lifecycle commands and allocates capture IDs across restarts
in the same process. The composition root drops the command sender when the TUI
exits; `run_service` then closes any running listener.

### 5.2 HTTP/1.1 forwarding

For every request Hyper has already parsed:

1. Parse an **absolute-form** URI. `https://` on the forward path is rejected
   because it requires CONNECT. Unsupported schemes and origin-form targets are
   rejected with `400`.
2. Normalize the authority (lowercase host, strip IPv6 brackets and one trailing
   dot), default the port from the scheme, reject port 0 and unsafe characters,
   and require the destination to be path-origin-form.
3. Require a single `Host` header when present, and require it to match the
   absolute-form host and port. A missing `Host` is accepted because the
   absolute-form target already identifies the destination.
4. Check scope. A denial is recorded as a failed capture with `403` before any
   DNS lookup or connection.
5. Reject a declared request body over `max_body_bytes` with `413`.
6. Resolve and validate upstream addresses (see §6), connect, and perform an
   HTTP/1 client handshake under `connect_timeout_secs`.
7. Copy method, version, filtered headers, origin-form target, and a streaming
   guarded body upstream. The `Host` header is normalized to the destination.
8. Wait for response headers under `upstream_timeout_secs`; preflight a declared
   response body over `max_response_bytes`; then stream the response through a
   second guarded body. A per-frame idle timer aborts stalled bodies, and
   exceeding the cap terminates the downstream response.
9. Emit capture events on request capture, response headers, and terminal body
   completion/failure. A response is never reported completed unless the body
   ended normally. Hyper regenerates framing; the proxy removes
   `Transfer-Encoding` and stale response `Content-Length` while forwarding.

End-to-end headers keep order and duplicates. Both directions remove
`Connection` and the fields named by its tokens plus `Connection`,
`Proxy-Authorization`, `Proxy-Authenticate`, `TE`, `Trailer`,
`Transfer-Encoding`, and `Upgrade`. The response path also removes
`Content-Length` so Hyper can frame the filtered body correctly. No request or
response is fully buffered for forwarding; only bounded copies are retained for
capture (subject to display truncation).

The client connection is per request (`Connection: close` upstream); the
listener still accepts keep-alive client connections, but this milestone does
not pool upstream connections. This is deliberate simplicity, not a claim of
high-throughput production proxying.

### 5.3 Opaque CONNECT

1. Parse authority-form `CONNECT host:port` (with the same normalization and
   default HTTPS port 443).
2. Check scope as HTTPS before resolution. Denied tunnels produce a recorded
   `403` failure.
3. Resolve and validate addresses, connect under the connect timeout, then
   return `200`.
4. Upgrade the client connection and run two independent copy pumps with 16 KiB
   buffers. EOF on one side calls `shutdown` on the corresponding write half;
   the other direction may continue (half-close preserved).
5. Activity-based idle timeout terminates a silent tunnel. Proxy shutdown also
   terminates it. Either way, byte counters, duration, and outcome are published
   in `TunnelMetadata`; a short non-sensitive summary is stored in the entry
   note.
6. No bytes are parsed, logged, or exposed as HTTP content, and no TLS
   certificate is generated or inspected.


### 5.4 HTTPS TLS interception (opt-in)

1. `CONNECT` parsing, scope, resolve-once address policy, and upstream TCP
   connection happen before any certificate is issued.
2. A per-host leaf certificate is issued from the local CA (DNS or IP SAN,
   serverAuth EKU, bounded deduplicated cache). The leaf key is generated in a
   blocking task, never on a Tokio worker.
3. A separate upstream TLS session is established with mandatory chain and
   hostname verification against trusted roots. Only HTTP/1.1 ALPN is offered.
   Upstream verification completes before the `200` CONNECT response, so an
   untrusted chain or hostname mismatch fails closed without forwarding.
4. The client-facing TLS acceptor presents the leaf. SNI, when sent, must match
   the CONNECT authority; the certificate resolver returns no certificate on a
   mismatch, failing the handshake.
5. Decrypted HTTP/1.1 requests run through a Hyper server on the client TLS
   stream and are forwarded through the existing interception manager, body
   guards, history, lifecycle, and event pipeline. A per-session mutex serializes
   upstream HTTP/1.1 requests; multiple requests on one TLS connection reuse the
   verified upstream session.
6. Modified requests must remain `https` and within the intercepted session
   authority, and are revalidated against scope before forwarding. Dropped
   requests never reach upstream.

The CA private key stays in memory and on local disk with restrictive Unix
permissions; only the public certificate path/fingerprint is published through
events and the TUI.

### 5.5 Interception (HTTP and decrypted HTTPS, current)

- Interception is implemented as a proxy/runtime concern (`rawframe-proxy`, with runtime decision handles/queue management in proxy; core provides serializable contracts/events/models such as `EditableHttpRequest`, interception metadata, queue/config/events/commands).
- Matching HTTP requests can be paused before upstream contact while interception is enabled. Decisions: forward unchanged, forward modified (`AppCommand::ForwardModified`), or drop. Disable/stop/shutdown paths cancel pending interceptions as implemented.
- The TUI consumes interception events and renders a Proxy interception workbench (queue, raw editor, actions) with real command dispatch; UI outcomes must reflect actual proxy events (no optimistic success, no fabricated responses for dropped/cancelled).
- **TLS interception is implemented behind an explicit switch.** When disabled (default), `CONNECT` remains the opaque tunnel above. When enabled, see §5.4.

## 5.6 Durable history (SQLite)

### Ownership and threading

`rawframe-store` owns one `rusqlite::Connection` on one OS thread. The worker
receives captures on a bounded **synchronous** channel using `try_send`, so the
proxy never waits on disk; when the queue is full the capture is dropped and the
count is surfaced as `StorageStatus::dropped`. Commands (`ListSessions`,
`LoadSession`, `ExportSession`, `SetPolicy`, `Shutdown`) arrive on the async
command channel and are drained with `try_recv` between batches. Results are
published as `AppEvent::Storage`.

`rawframe-cli` subscribes to the event bus independently of the TUI and forwards
`TrafficCaptured`/`TrafficUpdated` entries whose source is `Intercepted` to the
worker. Simulations and Repeater drafts are never stored.

### Schema and migrations

Schema version 1 creates:

| Table | Contents |
|---|---|
| `schema_migrations` | applied version and timestamp |
| `projects` | id, name, created timestamp |
| `sessions` | project, name, created/closed time, close reason, recovered flag |
| `traffic` | one row per transaction, unique per `(session_id, traffic_id)` |

The traffic row preserves method, scheme, host, port, target, version, ordered
headers as a JSON array of name/value pairs (duplicates intact), request and
response body BLOBs, response status/reason, start/completion timestamps,
duration, error, note, interception metadata, tunnel metadata, original/final
subrequest JSON, a redaction count, and an `incomplete` flag. Indexes cover
session/start order, host, method, status, and state.

Migrations run in an `IMMEDIATE` transaction, are recorded in both
`schema_migrations` and `user_version`, and are idempotent. A database newer than
the build is refused instead of modified.

### Durability and failure behavior

- `journal_mode=WAL`, `synchronous=FULL`, a 5 s busy timeout, and a bounded
  `max_page_count` (512 MiB default) limit damage from crashes and disk growth.
- Batches are committed in one transaction: either all rows in the batch are
  durable or none are. Batch writes also update lifecycle rows by upsert, so a
  request captured, forwarded, and completed remains one row.
- A `quick_check` runs at open. Corruption, a newer schema, a full database, or
  an unwritable path disables persistence with an explicit `StorageStatus`
  error; the proxy keeps running and the file is never deleted.
- On the next open, sessions without a clean close are marked recovered and
  their non-terminal transactions stay `incomplete`.
- Unix database files are `0600`; directories are `0700`; exports are `0600`
  and are written to a sibling temporary file and renamed atomically.

### Redaction on write

`StoragePolicy` is applied while encoding a row, not at render time. Sensitive
header values become `<redacted>` unless `persist_sensitive_headers` is on;
bodies are written as SQL `NULL` unless `persist_bodies` is on. A policy change
affects future writes only and never rewrites stored history. Restored entries
set `body_omitted` when a body was withheld, and the inspector states that
explicitly rather than showing an empty body.

Exports are JSON Lines (`format: rawframe.history.v1`) built from the stored,
already-redacted rows. They include headers, lifecycle state, timestamps,
duration, tunnel metadata, and either UTF-8 text or a hex-encoded body, plus an
explicit `omitted` marker for bodies withheld by policy.

### Restore semantics

Restored traffic is loaded as `TrafficSource::Restored` with interface IDs based
on the row id (`1_000_000 + row_id`), never reusing live IDs. Restored entries
are read-only history: they are excluded from the Proxy workspace, cannot be
forwarded, and are labelled `RESTORED` in the table and inspector. Filters work
across live, simulated, and restored entries.

## 6. Scope and destination address policy

Scope uses the existing `rawframe_core` model:

- default empty allowlist with `block_unlisted = true`;
- exact host;
- leading-wildcard host (`*.example.test` matches the apex and subdomains);
- optional scheme (`http` for forwarding, `https` for CONNECT);
- optional port;
- case-insensitive host matching;
- default ports: 80 for HTTP, 443 for HTTPS.

Authorization happens before resolution. The engine then resolves **once**,
deduplicates and sorts the answers, checks every answer with `address_allowed`,
and connects only to that pre-validated set using `TcpStream::connect(&[..])`.
A second DNS lookup is never performed, so a hostname cannot pass the hostname
check and then be rebound between validation and connection.

Address policy:

- **Always rejected:** IPv4 unspecified, multicast/reserved (`≥224`), link-local
  (`169.254/16`, including metadata endpoints), carrier-grade NAT
  (`100.64/10`), benchmarking (`198.18/15`), documentation (`192.0.2/24`,
  `198.51.100/24`, `203.0.113/24`), and IPv6 link-local, multicast,
  unspecified, documentation (`2001:db8::/32`), and non-global-unicast space.
- **Requires `allow_private_upstreams`:** IPv4 loopback and RFC 1918 private
  ranges; IPv6 loopback and unique-local (`fc00::/7`).
- **Allowed otherwise:** public IPv4 and IPv6 global-unicast addresses.

The policy is intentionally conservative. It may reject special-purpose ranges
that a particular lab uses; that is a safe failure, not a silent bypass.
`--allow-private-upstreams` relaxes only loopback/private answers, never
link-local, metadata, multicast, or documentation ranges.

## 7. TUI architecture

### 7.1 Shell and geometry

`layout::compute` produces all rectangles:

```
┌──────────────────────────────────────────────────────────────┐
│ header (2 rows + bottom border)                              │
├───────────┬──────────────────────────────────┬───────────────┤
│ sidebar   │ workspace                        │ inspector     │
│ optional  │                                  │ optional      │
├───────────┴──────────────────────────────────┴───────────────┤
│ footer (2 rows + top border)                                 │
└──────────────────────────────────────────────────────────────┘
```

- Header is always 3 rows; footer 3 rows.
- Sidebar appears at ≥ 84 columns and is clamped to 18–30 columns.
- Inspector appears at ≥ 108 columns when enabled; clamped to 40–64 columns.
- Workspace keeps a 36-column minimum.
- Under 64 × 18 the shell renders a centered size message.
- Splitter drags update `LayoutState`; the same rectangles define one-cell hit
  regions.

### 7.2 Render–input contract

Rendering is immediate-mode and returns `RenderOutput` containing hit rectangles,
scroll zones, editor viewport geometry, and the frame area. Mouse handling
resolves the most recently registered hit, so overlays capture input naturally.
Input never references literal screen positions. Tests render through
`rawframe_tui::testing::render_frame`, which applies the hit map to the app.

### 7.3 State ownership

`App` owns navigation, focus, selections, filters, inspector state, Repeater
tabs, Settings editing, overlays, notifications, proxy lifecycle state, storage
status, the stored-session list, the live scope editor, and the bounded command
senders. Domain data comes from `rawframe-core`; the TUI never opens SQLite.

Live traffic is inserted into `App::traffic` by `TrafficCaptured` /
`TrafficUpdated`. Existing pending fixtures are retained but hidden from the
Proxy queue while live captures exist. Proxy rows use the same selection model
and inspector as History. History filtering includes live captures and fixtures;
source badges keep provenance obvious. Tunnel entries render byte counts,
outcome, duration, and a clear “payload not captured” message instead of a body.

The TUI has no Tokio runtime. It polls the bounded event bus without blocking;
the proxy and storage worker run on the CLI-owned runtime/thread and meet the UI
only at channels. Session restore replaces nothing: restored entries are merged
with unique IDs and the History line names the source session. The Settings
scope editor parses rules with `ScopeRule::parse` and sends `UpdateScope`, so it
cannot accept a rule the proxy would interpret differently.

Persistence state is always visible: footer `DB ON/OFF/ERROR`, a status toast on
failure, a dropped-capture warning, and the session browser's database line.
There is no decorative “saved” indicator.

### 7.4 Input precedence and overlays

1. `Ctrl+C` (immediate quit).
2. Confirmation dialog.
3. Command palette.
4. Context menu.
5. Scope editor / stored-session browser.
6. Help overlay.
7. Inline settings edit.
8. Global control shortcuts (`Ctrl+K`, `Ctrl+1`…`6`, `Ctrl+F`, `Ctrl+N`,
   `Ctrl+W`, `Ctrl+Enter`, `Ctrl+U`).
9. `Esc` / `Tab`.
10. Search text entry.
11. Repeater document editing.
12. Global single-letter shortcuts (`?`, `Q`, `I`, `P`, `B` for stored sessions).
13. Focus-specific navigation.

Text-entry contexts consume printable characters before shortcut handling.
`Ctrl+C` is always an immediate exit. `P` toggles the proxy only when not
editing. Overlays draw a shadow, clear their rectangle, and register a
full-screen dismiss target.

### 7.5 Visual system and disclosure

`Theme` owns a truecolor palette and semantic styles (green success, amber
warning, red danger, muted metadata) with three accent presets. The UI labels
liveness in four places:

- header badge `LIVE ENGINE` vs `SIMULATED`;
- Proxy banner and status line with actual bound address/state;
- row source badges (`LIVE`, `SIM`, `AUTH`, `RESTORED`);
- footer line stating whether live captures exist, fixtures are retained, and
  whether TLS interception is absent.

CONNECT rows say `TUNNEL` and use metadata, not fabricated HTTP payloads.
Failures display recorded error strings, not invented success.

## 8. Domain model additions

`TrafficEntry` now carries `kind: TrafficKind` (`Http` or `ConnectTunnel`) and
optional `tunnel: TunnelMetadata`.

`TunnelMetadata` records:

- `client_to_upstream_bytes`, `upstream_to_client_bytes`;
- `outcome` (`Active`, `Closed`, `TimedOut`, `Failed`);
- duration is derived from the entry timings, and a short non-sensitive summary
  is stored in the entry note.

Lifecycle remains validated: a request cannot complete unless it was forwarded;
terminal states cannot be revived. Timings store start, completion, and measured
duration. Errors and notes are sanitized before terminal rendering.

`ProxyConfiguration` defaults:

| Field | Default |
|---|---|
| bind | `127.0.0.1:8080` |
| interception | off |
| upstream TLS verification | on, locked |
| max request body | 2 MiB |
| max response body | 2 MiB |
| max connections | 128 |
| connect timeout | 10 s |
| response-header timeout | 30 s |
| idle timeout | 60 s |
| interception timeout | 120 s |
| allow private upstreams | off |
| scope | empty allowlist, default deny |
| persistence | on; SQLite under the platform data directory |
| stored bodies | off (SQL `NULL`) |
| stored sensitive headers | off (`<redacted>` placeholder) |
| database ceiling | 512 MiB |

## 9. HTTP document parser

`rawframe-http` parses the text a tester edits (absolute/origin-form requests,
responses, duplicate headers, IPv6 authorities, LF/CRLF input) and reports typed
errors. It is **not** the proxy wire parser. Hyper owns framing, chunk decoding,
header limits, and protocol errors for live traffic.

## 10. Simulated fixtures

`rawframe_core::fixtures::simulated_traffic()` returns 17 entries: completed
2xx/3xx/4xx/5xx responses, an upstream TLS failure, a dropped request, paused and
in-flight examples, sensitive headers, and a hostile control-sequence body.
Every host is under `.test`, every source is `Simulated`, and no fixture is sent.
They remain useful for demos, redaction tests, and UI development while live
captures are clearly distinguished.

## 11. Testing strategy

- **Core unit tests** cover headers, redaction, sanitization, lifecycle, scope,
  config validation, filtering, fixtures, bounded events, sessions, certificates.
- **HTTP tests** cover parser round-trips, absolute/origin forms, IPv6,
  duplicate headers, malformed inputs, and display safety.
- **Proxy unit tests** cover destination parsing, `Host` matching, scope,
  address policy, tunnel relay/half-close, and idle termination.
- **Proxy integration tests** (`crates/rawframe-proxy/tests/forwarding.rs`) use
  only local upstream servers and cover GET/POST, duplicate headers, chunked
  request/response streaming, malformed requests, invalid destinations, scope,
  exact/wildcard/scheme/port policy, IPv4/IPv6, CONNECT bidirectional traffic
  and metadata, half-close, upstream failure, response timeout, idle body
  timeout, concurrent requests, connection limit, DNS address policy, and
  graceful shutdown.
- **TUI integration** (`crates/rawframe-cli/tests/proxy_tui.rs`) presses `P`,
  starts the real worker, sends local HTTP traffic, drains real events, asserts
  the live capture reaches `App`, renders the Proxy screen with
  `LIVE ENGINE`/`LIVE REQUESTS`, stops the worker, and verifies clean exit.
- **TLS integration** (`crates/rawframe-proxy/tests/tls_interception.rs`) uses a
  self-contained local CA and local HTTPS origins for decrypted forwarding,
  pause/modify/drop, upstream verification failure, SNI/authority rejection,
  client/upstream disconnect, and proxy shutdown.
- **CA CLI tests** (`crates/rawframe-cli/tests/tls_ca_cli.rs`) run against
  isolated temporary CA directories and cover show/fingerprint/export,
  regeneration, public-only export, permissions, and refusing to replace
  invalid material.
- **Storage tests** (`crates/rawframe-store/tests/persistence.rs`) use isolated
  temporary databases and the real worker: migrations, metadata-only redaction,
  opt-in bodies/sensitive values, duplicate headers, binary bodies, lifecycle
  upserts, session isolation, restart/truncation, interrupted-session recovery,
  unknown sessions, corruption without deletion, unwritable locations,
  transaction rollback, export contents and permissions, timestamp fidelity, and
  worker status/query round-trips. A proxy integration test proves live scope
  changes apply without a listener restart.
- **PTY TLS regression** (`crates/rawframe-cli/tests/tls_pty_tui.rs` +
  `scripts/tui_tls_pty.py`) launches the real binary in a pseudo-terminal,
  enables/disables TLS through Settings keystrokes, verifies decrypted requests
  enter the queue, verifies a pre-enable CONNECT stays opaque after enabling,
  verifies new CONNECT sessions are opaque after disabling, and captures genuine
  terminal frames at 140×40, 100×30, and 80×24 under `docs/screenshots/tls/`.
- Existing TUI unit/integration tests from Milestone 1 remain in place, including
  redaction, keyboard/mouse flows, and “no fabricated response” assertions.

No test contacts an external website. TLS tests use a self-contained local CA
and local TLS servers.

## 12. Decisions and trade-offs

| Decision | Trade-off |
|---|---|
| Dedicated proxy crate, no TUI dependency | Clean boundary and testability; CLI must own all wiring |
| Per-request upstream connections | Simple, predictable isolation; no pooling/throughput optimization |
| Resolve once and connect to validated IPs | Resistant to DNS rebinding; ignores later DNS changes for that request |
| Conservative address policy | Blocks some legitimate special-purpose labs; safe by default |
| Bounded event queue + async sends | Prevents unbounded memory from fast traffic; proxy can slow under UI pressure |
| Bounded body capture with streaming | Caps memory and keeps responses flowing; captured body may be truncated |
| CONNECT opaque by default | Safe default; interception requires explicit operator opt-in |
| Separate storage crate, single writer thread | No SQLite in proxy/TUI; writes cannot block capture, and a slow disk drops counted captures instead |
| Redaction on write, immutable policy for old rows | Stored history cannot reveal secrets the operator chose to mask; changing policy cannot retroactively add bodies |
| Restored entries are a distinct provenance | Never mistaken for live traffic or forwarded; requires ID spacing and UI labels |
| Runtime-only settings (limits, accent, policy, scope) | No configuration-file commitment yet; only history and sessions are persisted |
| Simulated fixtures retained | Reproducible demos and tests; requires explicit provenance labels everywhere |

## 13. Extension path

**Milestone 3 (implemented).** Live HTTP pause/forward/edit/drop with bounded
queues, timeouts, cancellation, and TUI workbench integration.

**Milestone 4 (implemented).** Local CA with owner-only key material,
client-facing Rustls termination, separate verified upstream TLS, per-host leaf
caching, explicit trust instructions, and opt-in HTTPS interception for
HTTP/1.1. Future work: protocol coverage (HTTP/2, WebSocket) and richer CA
lifecycle UX.

**Milestone 5 (implemented).** SQLite migrations, projects/sessions, persisted
history, redaction on write, redacted JSONL export, crash recovery, and live
scope editing.

**Milestone 6.** Add real Repeater transmission through the proxy stack,
response comparison, then Intruder and Decoder.

See [roadmap.md](roadmap.md) for acceptance criteria.
