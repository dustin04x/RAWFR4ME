# RAWFRAME Architecture

**Status:** Milestone 9 — HTTP/2 (0.2.0). HTTP/1.1 forwarding, opaque HTTPS
CONNECT tunnels, live pause/edit/forward/drop, opt-in TLS interception for
HTTP/1.1 and HTTP/2 over negotiated ALPN, SQLite sessions/persistence, redacted
export, live scope editing, real Repeater execution and comparison, a Decoder
pipeline, an Intruder workbench, and multiplexed HTTP/2 streams are implemented.

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
│   │   ├── decoder.rs          byte-oriented transforms + pipeline engine
│   │   ├── intruder.rs         positions, payload sets, strategies, plan, results
│   │   └── fixtures.rs         17 labelled simulated transactions
│   ├── rawframe-proxy/         Tokio/Hyper forwarding + CONNECT engine
│   │   ├── server.rs           listener, lifecycle commands, shutdown
│   │   ├── service.rs          HTTP forwarding and CONNECT orchestration
│   │   ├── destination.rs      authority parsing, scope, DNS/IP policy (shared)
│   │   ├── body.rs             bounded streaming body with capture
│   │   ├── tunnel.rs           opaque relay, half-close, idle timeout
│   │   └── tls/                CA, leaf issuance, verified upstream TLS
│   ├── rawframe-repeater/      independent Repeater execution engine
│   │   ├── engine.rs           connections, TLS, redirects, bounded capture
│   │   ├── service.rs          bounded command service, cancellation, IDs
│   │   └── tests/execution.rs  local HTTP/HTTPS integration matrix
│   ├── rawframe-intruder/      bounded payload attack service (reuses Repeater)
│   │   ├── engine.rs           payload expansion + worker pool + rate gate
│   │   ├── service.rs          command channel, pause/resume/cancel, IDs
│   │   ├── wordlist.rs         bounded wordlist import (UTF-8 safe)
│   │   └── tests/execution.rs  local HTTP/HTTPS attack matrix
│   ├── rawframe-http/          authored HTTP/1.x document parser
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
│   │   ├── screens/            Proxy, History, Repeater, Intruder, Decoder, Settings
│   │   ├── intruder.rs         Intruder view state, candidates, prompts
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

`rawframe-repeater` owns execution only. The editable document and view state
remain in `rawframe-http` + `rawframe-tui`; shared contracts and validation live
in `rawframe-core` so the TUI never imports the engine.

## 3. Dependency direction

```
rawframe-cli ──▶ rawframe-tui ──▶ rawframe-core
     │              └───────────▶ rawframe-http ──▶ rawframe-core
     ├──▶ rawframe-proxy ─────────────────────────▶ rawframe-core
     ├──▶ rawframe-repeater ──────────────────────▶ rawframe-core
     │         └────────────▶ rawframe-proxy (public destination/TLS helpers)
     ├──▶ rawframe-intruder ──────────────────────▶ rawframe-core
     │         └────────────▶ rawframe-repeater (execution engine only)
     └──▶ rawframe-store ─────────────────────────▶ rawframe-core
```

Rules:

- `rawframe-core` depends on no RAWFRAME crate. It remains free of terminal,
  socket, and database APIs.
- `rawframe-http` depends only on `rawframe-core`.
- `rawframe-proxy` depends on `rawframe-core`; it **must not** depend on
  `rawframe-tui` or `rawframe-repeater`.
- `rawframe-repeater` depends on `rawframe-core` and reuses public
  `rawframe-proxy` destination/TLS-policy functions. It **must not** depend on
  the proxy listener, CA manager, interception queue, or TUI.
- `rawframe-intruder` depends on `rawframe-core` and calls
  `rawframe_repeater::RepeaterEngine::execute` for every generated request. It
  **must not** open its own HTTP stack, depend on the TUI, or touch storage.
- `rawframe-tui` depends on `rawframe-core` and `rawframe-http`; it **must not**
  depend on `rawframe-proxy`. It sees the proxy and Repeater only through shared
events and bounded command senders defined in core (a dev-dependency on
  `rawframe-repeater` exists only for integration tests).
- `rawframe-store` depends on `rawframe-core` and SQLite; it must not depend on
  the proxy or the TUI. The TUI never links SQLite.
- `rawframe-cli` is the only composition root and may depend on all crates. It
  hosts the capture pump that bridges the event bus to the storage worker.

## 4. Runtime data flow

```
 client ──▶ rawframe-proxy ──AppEvent──▶ bounded EventBus ──poll()──▶ App (TUI)
                                                     ▲
 Repeater tab ──RepeaterCommand──▶ rawframe-repeater┘ (Phase/Completed events)
 Intruder plan ──IntruderCommand──▶ rawframe-intruder┘ (Progress/Completed events)
                                                     │
                                                     └──subscribe()──▶ capture pump
                                                                          │ try_record
                                                                          ▼
                                                               storage thread (SQLite)
                                                App (TUI) ──StorageCommand──▶ store
                                                store ──StorageEvent──▶ EventBus
```

`rawframe-cli` owns a multi-thread Tokio runtime. It spawns
`rawframe_proxy::run_service(command_rx, event_sender)`,
`rawframe_repeater::run_service(command_rx, config, event_sender, scope)`, and
`rawframe_intruder::run_service(command_rx, config, event_sender, scope)`, starts
the storage worker and capture pump, then runs the synchronous TUI. The engines
have independent command channels and sockets, but share the scope model and
event bus. The UI runtime is independent: input arrives on a Crossterm reader
thread, events are polled, and frames redraw on input or at a 250 ms idle cadence.
No proxy, Repeater, or storage task is awaited on the UI thread.

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
- `UpdateScope(Scope)` replaces the live allowlist in both engines. New HTTP
  requests, CONNECT sessions, and Repeater executions use it immediately;
  already-forwarded work is unchanged.
- `RepeaterCommand::Execute`, `Cancel`, `UpdateScope`, and `Shutdown` are a
  separate bounded channel. `Execute` carries tab/execution IDs fixed by the UI
  and the exact request; the service assigns a Repeater traffic ID only when the
  execution completes.

Events:

- `ProxyStateChanged` drives `Idle → Starting → Listening → Stopping → Stopped`
  or `Failed`.
- `ProxyBound(SocketAddr)` reports the actual bound address.
- `TrafficCaptured` / `TrafficUpdated` carry HTTP captures, decrypted HTTPS
  requests, and CONNECT tunnel metadata.
- `AppEvent::Repeater(Phase|Completed)` drives the owning tab and, on completion,
  carries a ready-to-persist `TrafficEntry` labelled `Repeater` with an optional
  `repeater_origin` capture reference.
- `AppEvent::Intruder(IntruderEvent)` drives the Intruder workspace:
  `Started` fixes the run/total count, `Phase` carries pause/resume/cancel
  transitions, `Completed` carries one terminal result plus a ready-to-persist
  `TrafficEntry` labelled `Intruder` (payload values and optional origin
  capture), `Finished` carries the typed summary and stop reason, `Failed`
  reports a refused launch, and `Wordlist` returns an import outcome.
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

Plaintext proxying remains HTTP/1.1: RAWFRAME implements no h2c. HTTP/2 is
negotiated through ALPN inside intercepted TLS sessions (§5.4) and by the
Repeater's direct TLS connections (§5.7); §5.10 describes the shared protocol
representation and bounds.

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
   hostname verification against trusted roots. ALPN offers `h2` then
   `http/1.1`; the result is read back from the completed handshake and never
   assumed. Upstream verification completes before the `200` CONNECT response,
   so an untrusted chain or hostname mismatch fails closed without forwarding.
4. The client-facing TLS acceptor presents the leaf. SNI, when sent, must match
   the CONNECT authority; the certificate resolver returns no certificate on a
   mismatch, failing the handshake.
5. The client-facing ALPN result selects the server protocol: `h2` runs a Hyper
   HTTP/2 server, anything else keeps the HTTP/1.1 server. The two legs negotiate
   independently, so an HTTP/2 client can be bridged to an HTTP/1.1 upstream and
   the reverse. Each side's real protocol is recorded on the captured request and
   response.
6. Decrypted requests run through the existing interception manager, body
   guards, history, lifecycle, and event pipeline. HTTP/1.1 upstream requests are
   serialized by a per-session mutex. HTTP/2 uses a cloned multiplexed sender, so
   concurrent streams do not hold a lock across the response wait and are bounded
   at 128 streams per client connection and a 64 KiB header list.
7. Modified requests must remain `https` and within the intercepted session
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
`TrafficCaptured`/`TrafficUpdated` entries whose source is `Intercepted`, plus
completed `AppEvent::Repeater` entries whose source is `Repeater`, to the worker.
Simulated fixtures and unfinished Repeater drafts are never stored.

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

Schema version 2 adds `traffic.repeater_origin`, a nullable reference to the
capture a Repeater execution was seeded from. The version 1 → 2 migration uses
`ALTER TABLE`, so existing M5 databases and their rows are preserved. A fresh
database applies both versions in order.

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

## 5.7 Repeater execution

Repeater is a separate engine, not a proxy loopback client. The TUI parses the
editable HTTP document (or preserves binary bodies), then sends a
`RepeaterCommand::Execute` with fixed tab/execution IDs, the request, the tab's
follow-redirect flag, provenance, and an optional original capture. The service
validates nothing on the UI's authority: the engine validates the request again.

Execution path:

1. Validate method, target, host/port, headers, and body framing. `CONNECT`,
ambiguous `Content-Length`/`Transfer-Encoding`, malformed header names/values,
and bodies over the configured limit are rejected before DNS.
2. Re-read the shared scope snapshot and check the destination.
3. Resolve the hostname once, validate every address with the same
`rawframe-proxy::destination` policy used by forwarding, and connect only to
those addresses.
4. For HTTPS, build a Rustls client with certificate-chain and hostname
verification mandatory. No CA or verification bypass exists. A lab trust bundle
may replace roots, exactly as for proxied upstreams.
5. Send one request on a fresh connection and collect a bounded response with
connect, response-header, body-idle, and total timeouts. Cancellation is a
`CancellationToken` per execution. Over TLS, ALPN offers `h2` then `http/1.1`;
an exact `h2` result uses Hyper's HTTP/2 client and anything else keeps HTTP/1.1.
The authored document version is not treated as the wire protocol.
6. If redirects are enabled, parse `Location`, reject non-origin-form targets,
scope-check the next destination, strip credentials cross-origin, apply
301/302 POST→GET and 303→GET rules (307/308 preserve method/body), cap at five
hops, then open a new connection.
7. Convert the outcome to a `RepeaterResult` (response or partial response,
phase, timings, bytes, warnings, error) and a `TrafficEntry` labelled `Repeater`.
The entry is emitted as `RepeaterEvent::Completed`; the UI applies it only when
the tab and execution IDs still match. The storage pump persists it under the
same policy as proxy history.

The service enforces a bounded concurrency limit with owned semaphore permits;
the command channel, cancellation map, and task set are bounded. Response bodies
are capped and explicitly marked truncated. A storage failure cannot fail or
block an execution: storage is independent and only reports status.

## 5.8 Decoder transformations

Decoder is a local, inert data workbench. The engine is
`rawframe_core::decoder`; it depends only on byte buffers and established
libraries (`base64`, `flate2`, `sha2`, `md-5`, `serde_json`). It never opens a
socket, touches storage, invokes a shell, or evaluates decoded content.

Transformations operate on `Vec<u8>`. Text-only operations (hex, URL percent,
HTML entities, Unicode escapes, JSON, JWT) reject invalid UTF-8 instead of
lossily converting it. `Transform::ALL` contains 22 explicit operations; each
reports a direction (`Encode`, `Decode`, or `Inspect`) and an optional warning
(for example, MD5 is legacy-only and JWT inspection does not verify signatures).

`execute_pipeline` applies steps in order over a single byte buffer and records
every intermediate `PipelineStep` with its format, byte length, and note. The
first failure returns the completed steps plus `PipelineFailure { step_index,
transform, message }`; later steps never run and no empty output is substituted
on the first failure. Limits are 8 MiB input, 8 MiB output, and 16 steps,
enforced before and during execution.

Gzip decompression uses a `flate2` decoder wrapped in a bounded reader, so a
compression bomb stops at the output limit rather than expanding into memory.
Hashes are computed with the standard libraries; MD5 is exposed only as a legacy
checksum. Non-text output is rendered as a bounded hex dump with a format label.

The TUI owns only `DecoderState` (buffers, selection, pipeline, results,
session history) and runs each pipeline on a named background thread, polling a
channel from `App::tick`. Rendering never transforms data. Repeater transfer is
explicit: the controller copies the active request or response body into
`DecoderState::load_input`, and insertion calls `RepeaterTab::replace_body`,
which rewrites framing headers and preserves the original capture separately.

## 5.9 Intruder execution

Intruder is a planning layer over the Repeater engine, not a second HTTP stack.
The domain model lives in `rawframe_core::intruder`; the executor lives in
`rawframe-intruder`; the TUI only builds a plan and renders results.

### Positions and plans

A request template is scanned at the **byte** level for the UTF-8 marker
`§` (two bytes). `IntruderTemplate::analyze` splits the request into ordered
components (path, query values, header values, body) and records each marked
span, which is why binary bodies work without a text round-trip. Validation
rejects unmatched markers, markers inside header names, and non-UTF-8 payloads
for URL or header positions before a plan can be built. Positions carry their
own enabled flag, a stable ID, and an index into a payload list; the plan stores
per-position lists and index assignments, never the expanded request set.

`IntruderStrategy` decides assignment order and count:

| Strategy | Assignment | Generated requests |
| --- | --- | --- |
| Sniper | each payload against one position, other positions fixed | positions × payloads |
| Battering Ram | the same payload at every position | payloads |
| Pitchfork | list *i* for position *i*, in lockstep | shortest list |
| Cluster Bomb | full Cartesian product across positions | product of list lengths |

`plan.count` enumerates exactly those rules, rejects empty lists and unequal
Pitchfork lengths, and refuses plans above `MAX_GENERATED_REQUESTS` (2048)
before anything is sent. Expansion is deterministic and preview-driven.

### Execution

The service accepts `IntruderCommand::{Start, Pause, Resume, Cancel, Shutdown,
LoadWordlist}` and a `IntruderLaunch` containing the template, plan, cloned
`RepeaterConfig`, and limits. Each generated request is materialised, clamped
(concurrency ≤ 8, capture ≤ 256 KiB, body ≤ 1 MiB, rate ≤ 20/s), and executed by
`RepeaterEngine::execute`, so scope, resolve-once address checks, verified TLS,
redirect handling, and timeouts are identical to Repeater by construction.

- A worker pool of at most the configured concurrency pulls indices in order and
  records one result per index, so progress and ordering stay stable regardless
  of completion order.
- `RateGate` spaces starts using a monotonic deadline and returns
  `Started`, `Paused`, `Stopped`, or `Deadline`; a paused run keeps its queue and
  resumes without re-sending completed indices.
- Each outcome is typed: `Response`, `Blocked`, `TimedOut`, `Failed`,
  `Cancelled`, or `NotSent`, with the exact payload values that produced it.
  There are no silent retries and no fabricated results.
- Cancellation and shutdown abort the pool and mark unsent indices `NotSent`
  instead of draining gracefully.
- Everything is bounded: positions (16), payload lists (16), payloads per list
  (512), payload size (4096 bytes), generated requests (2048), concurrency (8),
  rate (20/s), and duration (1800 s).

### Results and persistence

Results are shown with real status, size, duration, and payload values. Filters,
sort, search, baseline comparison, and payload/response inspection operate on the
captured data only; nothing infers a vulnerability from a status, size, or timing
difference. `IntruderResult::to_traffic_entry` maps each completed request to the
shared persistence model with `TrafficSource::Intruder`, the payload values
(base64 JSON), and the origin capture when the template came from History.

Storage uses schema v3: the `intruder_payloads` and `intruder_origin` columns are
added by a versioned migration that preserves M5–M7 data, and only Intruder rows
populate them. Payload **lists** are session state and are never written to disk.
The export path includes those fields only for Intruder rows.

Wordlist import (`LoadWordlist`) reads a local file on the service thread, caps
it at 4 MiB total, 512 payloads, and bounded line sizes, counts and skips lines
that are not valid UTF-8 instead of replacing them, reports truncation, and
never executes file content.

## 5.10 HTTP/2 protocol support

HTTP/2 is a real protocol path, not a relabelled HTTP/1.1 exchange. Hyper's
`http2` feature provides framing and HPACK; RAWFRAME owns negotiation, the
conversion boundary, capture representation, and bounds.

**Representation.** `HttpRequest` and `HttpResponse` keep their existing
`version` string. HTTP/2 pseudo-headers are never stored as ordinary headers:

| HTTP/2 | Model |
|---|---|
| `:method` | `HttpRequest.method` |
| `:scheme` | `HttpRequest.scheme` |
| `:authority` | `HttpRequest.host` / `port` |
| `:path` | `HttpRequest.target` |

`rawframe_core::h2` is the single conversion boundary shared by the proxy and
Repeater: ALPN matching, protocol labels, `sanitize_headers_for_h2` (drops
HTTP/1.1 connection-specific fields and `Host`), and `absolute_uri` (rebuilds the
required absolute URI from the structured fields). Because `version` already
exists in the schema, no migration was needed; M5–M8 rows remain readable and
HTTP/2 rows persist through the same columns and redacted export.

**Negotiation rules.** ALPN is advertised as `h2`, then `http/1.1`, on both
intercepted legs and in the Repeater. The selected value is read back after the
handshake; `h2` must match exactly. A server that selects nothing, an unexpected
value, or an HTTP/1.1 preference falls back without special cases. Certificate
and hostname verification are unchanged and mandatory. Plaintext HTTP never
offers h2c.

**Streams and isolation.** Intercepted HTTP/2 serves bounded concurrent streams.
Each stream becomes its own traffic entry and interception decision; a paused
stream does not block other streams on the connection. A client stream reset
cancels and dequeues its pending decision without forwarding. Interception
timeouts, drop, modified forwarding, shutdown cancellation, and scope
revalidation behave per stream. Per-stream request and response versions are
recorded truthfully, including cross-protocol bridges; a modified request keeps
the negotiated protocol rather than the editor's version field.

**Bounds.** 128 concurrent streams per client connection and a 64 KiB request
header list. Request/response body caps, timeouts, connection caps, and event
queue bounds are the existing proxy limits.

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
tabs, the Intruder state, the Decoder state, Settings editing, overlays,
notifications, proxy lifecycle state, storage status, the stored-session list,
the live scope editor, and the bounded command senders. `IntruderState` owns the
template components, marked positions, payload lists and the active set index,
strategy and limit settings, view mode, the plan and its validation status,
results and their filters/sort/baseline, inspector view, prompts, and the run
phase. It never expands or sends requests itself; it sends `IntruderCommand`s
and applies events. `DecoderState` owns the input buffer and exact
input bytes, output display, pipeline steps and results, view-step selection,
session history, and the background worker channel. Each Repeater tab owns its
document, editor buffer, dirty/original state, in-flight execution ID, latest
result, execution history, view mode, and redirect toggle. Completions are matched by tab and execution ID, so late events
cannot overwrite a newer execution or another tab. Domain data comes from
`rawframe-core`; the TUI never opens SQLite.

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
11. Repeater, Intruder, or Decoder document editing.
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
- **Intruder tests** cover byte-level marker analysis and validation, strategy
  counts and ordering, plan ceilings, payload set/list operations, wordlist
  limits, bounded execution against local HTTP and HTTPS origins, pause/resume/
  cancel, scope refusal, redirect policy, persistence mapping, and TUI rendering
  at 140×40, 100×30, and 80×24.
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
- **Decoder tests** live beside `rawframe-core/src/decoder.rs` and cover
  round-trips, malformed input, JWT/JSON behaviour, known SHA/MD5 vectors, gzip
  round-trips/truncation/output limits, binary pipelines, and step failures.
  TUI tests exercise pipeline editing, preview, history, copy/swap/clear, and
  explicit Repeater body transfer without mutating stored captures.
- **HTTP/2 tests** (`crates/rawframe-proxy/tests/http2.rs`,
  `crates/rawframe-repeater/tests/http2.rs`, and an Intruder case in
  `crates/rawframe-intruder/tests/execution.rs`) negotiate real ALPN over TLS
  and speak HTTP/2 with Hyper. They cover both-legs h2, cross-protocol bridges
  with truthful per-side versions, HTTP/1.1 fallback, multiplexed concurrent
  streams, per-stream pause/forward/drop/modify, interception timeout,
  client-reset cancellation, shutdown cancellation, redirects over h2, and
  Intruder execution through the shared Repeater path. They also assert that
  pseudo-headers never enter the captured header list and that `Host` is not sent
  as an h2 regular header. Protocol metadata round-trips through SQLite and
  export without a migration.
- **Repeater tests** (`crates/rawframe-repeater/tests/execution.rs`) use real
  local HTTP/1.1 and HTTPS servers. They cover GET/query/custom port, duplicate
  ordered headers, binary POST bodies, repeated executions, response truncation,
  duplicate `Content-Length`/`Transfer-Encoding` rejection, invalid methods and
  targets, scope/private-address refusal, edited-destination revalidation,
  concurrency limits, timeout vs cancellation, redirects (including cross-origin
  credential stripping and blocked hops), valid HTTPS, hostname mismatch,
  untrusted certificates, and service lifecycle events.
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
| HTTP/2 only over negotiated TLS, never h2c | No protocol ambiguity and reuses the verified TLS path; plaintext HTTP stays HTTP/1.1 |
| Protocol stored in the existing `version` string | No migration and existing export/history keep working; no separate protocol enum in the schema |
| Independent ALPN per leg | Real client and upstream protocols can differ and are reported honestly; requires explicit conversion at the boundary |
| One multiplexed upstream h2 sender, no lock across response wait | Streams progress concurrently; requires per-stream capture/error handling |
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
| Repeater engine separate from the proxy listener | Independent execution semantics and no interception/CA coupling; reuses destination/TLS policy at the cost of one extra crate and direct-connection differences |
| Repeater completions flow through the shared event bus and storage pump | One persistence/redaction path and one history UI; requires provenance labels and late-event matching by tab/execution ID |
| Decoder engine in `rawframe-core`, no new crate | Reusable and testable without the TUI; core gains data-format dependencies (`flate2`, `sha2`, `md-5`, `base64`, `serde_json`) but remains I/O-free |
| Decoder execution on a background thread per run | Keeps decompression and hashing off the render path; costs one thread per active run and requires run-ID matching |
| Decoder state is session-only | No secrets or decoded payloads reach SQLite; history disappears on exit |

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

**Milestone 6 (implemented).** A separate Repeater engine with independent
HTTP/HTTPS connections, mandatory upstream verification, scope/address policy,
safe redirects, bounded capture, cancellation/timeouts, multi-tab state,
inspection/comparison, and persisted Repeater provenance.

**Milestone 7 (implemented).** A byte-oriented Decoder engine and chained
pipeline in `rawframe-core`, with a keyboard-first TUI workspace, bounded
compression and size limits, binary/hex display, session history, and explicit
Repeater body transfer.

**Milestone 8 (implemented).** An Intruder planner in `rawframe-core` (byte-level
`§` positions, payload lists, four strategies, exact counts, typed results) and a
`rawframe-intruder` service that executes every generated request through the
Repeater engine under concurrency/rate/duration ceilings, with pause/resume/
cancel, a results workspace, explicit transfers, and schema-v3 persistence of
payload provenance.

**Milestone 9 (implemented).** Genuine HTTP/2 support over ALPN in intercepted
TLS and the Repeater, shared pseudo-header/URI conversion in `rawframe-core`,
multiplexed streams with per-stream interception, truthful protocol display in
the inspector and history, and real h2 integration tests and PTY evidence.
Next: traffic analysis, HTTP/3 and WebSocket coverage, and release hardening.

See [roadmap.md](roadmap.md) for acceptance criteria.
