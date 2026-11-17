# Development Guide

## Prerequisites

- Rust 1.89+ (edition 2024).
- A truecolor terminal for a representative visual check. Tests use
  `TestBackend`, so they run headlessly.
- `cargo fmt`, `cargo clippy`, and `cargo test` from the standard toolchain.
- For manual proxy checks, a local HTTP server (for example
  `python3 -m http.server`) and `curl`.

```bash
git clone <repository>
cd RAWFRAME
cargo build --workspace
cargo run -p rawframe-cli --bin rawframe
```

The proxy is idle at launch. Press `P` on the Proxy screen or click **Start**.

## Quality gate

```bash
./scripts/check.sh
# or explicitly:
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

The quality gate requires zero clippy warnings. Do not add `#[allow(...)]` to
silence a lint without fixing or documenting the underlying design issue.

## Repository map

| Path | Responsibility |
|---|---|
| `crates/rawframe-core/src/models` | Domain types, config, scope, traffic/tunnel lifecycle |
| `crates/rawframe-core/src/security.rs` | Terminal-safe display conversion |
| `crates/rawframe-core/src/events.rs` | Bounded event bus, commands, event contracts |
| `crates/rawframe-core/src/filter.rs` | History search/filter semantics |
| `crates/rawframe-core/src/fixtures.rs` | Labelled simulated traffic |
| `crates/rawframe-http/src/parsing.rs` | Authored HTTP/1.x document parser |
| `crates/rawframe-proxy/src/server.rs` | Listener, lifecycle service, connection limits, shutdown |
| `crates/rawframe-proxy/src/service.rs` | HTTP forwarding, capture events, CONNECT upgrades, HTTPS interception sessions |
| `crates/rawframe-proxy/src/destination.rs` | Absolute-form parsing, scope, DNS/IP policy, connect |
| `crates/rawframe-proxy/src/body.rs` | Bounded streaming body with capture and idle timeout |
| `crates/rawframe-proxy/src/tunnel.rs` | Opaque relay, half-close, byte counters, idle timeout |
| `crates/rawframe-proxy/src/tls/` | CA management, leaf issuance/cache, TLS session helpers |
| `crates/rawframe-proxy/tests/tls_interception.rs` | Local HTTPS interception, verification, and fail-closed tests |
| `crates/rawframe-proxy/tests/forwarding.rs` | Local-only proxy integration suite |
| `crates/rawframe-store/src/schema.rs` | Versioned SQLite migrations |
| `crates/rawframe-store/src/record.rs` | Policy-applied entry <-> row encoding and restore decoding |
| `crates/rawframe-store/src/store.rs` | Connection owner, batched upserts, session queries, export |
| `crates/rawframe-store/src/worker.rs` | Storage thread, capture queue, status events |
| `crates/rawframe-store/tests/persistence.rs` | Real-SQLite integration tests |
| `crates/rawframe-tui/src/app.rs` | Application controller and actions |
| `crates/rawframe-tui/src/input.rs` | Keyboard and mouse precedence |
| `crates/rawframe-tui/src/ui.rs` | Shell composition and overlays |
| `crates/rawframe-tui/src/screens` | Workspace screens |
| `crates/rawframe-tui/src/components` | Panels, inspector, editor, overlays |
| `crates/rawframe-tui/src/layout.rs` | Shell geometry |
| `crates/rawframe-tui/src/interaction.rs` | Hit targets, scroll zones, render output |
| `crates/rawframe-tui/src/text.rs` | Editable buffer |
| `crates/rawframe-tui/src/terminal.rs` | Raw mode, alternate screen, event loop |
| `crates/rawframe-tui/src/testing.rs` | Headless frame + hit-map helper |
| `crates/rawframe-cli/src/cli.rs` | Arguments, scope parsing, safety validation |
| `crates/rawframe-cli/src/main.rs` | Composition root: runtime, proxy service, TUI |
| `crates/rawframe-cli/src/logging.rs` | Local file logging |
| `crates/rawframe-cli/tests/proxy_tui.rs` | TUI-to-engine boundary integration test |

## Development workflow

1. Choose the smallest crate that owns the change. Domain rules belong in
   `rawframe-core`; HTTP wire behavior in `rawframe-proxy`; authored HTTP text
   parsing in `rawframe-http`; interaction in the TUI.
2. Add or update unit tests next to the implementation. Add an integration test
   when the change affects a real flow. Proxy behavior must be proven with local
   servers, not external websites.
3. Run `cargo fmt --all`, then the quality gate.
4. Do not claim a feature works if its milestone’s integration test does not
   exist. Simulated fixtures are not evidence for proxy behaviour.
5. Preserve the dependency boundary: the TUI must not import `rawframe-proxy`
   or `rusqlite`. New engine/storage-facing types shared across boundaries
   belong in `rawframe-core`; only `rawframe-cli` wires all services together.

### Working on the proxy

- `rawframe-proxy` is runtime-agnostic. `run_service` is spawned by the CLI; unit
  and integration tests create their own Tokio runtime.
- Keep request and response bodies streaming. Do not call `collect()` on a live
  body for forwarding or capture; use the guarded body wrapper.
- Any new upstream connection path must call the scope check before resolution
  and use the resolve-once `connect_upstream` path. Do not use
  `TcpStream::connect("hostname:port")` directly: that performs another lookup
  and defeats the rebinding defense.
- Any new event producer must use `send_async` from async code and handle the
  full bounded queue with backpressure. Synchronous UI/test code may use `send`.
- Do not log headers, bodies, query strings, credentials, or tunnel payloads.
- Preserve hop-by-hop filtering and duplicate end-to-end headers. Add a test
  whenever the filter list changes.
- Update `TunnelMetadata` and the TUI tunnel view if relay outcomes or byte
  accounting change.

### Working on persistence

- Never open SQLite from the proxy, TUI, or an async task. The single writer
  connection belongs to the storage thread; everything else exchanges contracts
  defined in `rawframe_core::storage`.
- Apply redaction while encoding rows (`record.rs`), not at render time. A new
  sensitive header belongs in `SENSITIVE_HEADERS`; a new body path must respect
  `StoragePolicy::persist_bodies` and write SQL `NULL` when off.
- Append migrations instead of editing an applied one. Bump `SCHEMA_VERSION`,
  add the SQL to the versioned batch, and test an upgrade from an existing
  database as well as a fresh one.
- Keep writes batched and transactional. Do not make the proxy await the store,
  and do not silently drop errors: emit `StorageEvent::Failed` and keep queries
  honest.
- Use isolated `tempfile` directories in tests. Never point a test at the
  operator's real data directory.
- Do not store CA keys, TLS secrets, tunnel payloads, or logs in the database.

### Logging and debugging

The application owns stdout and the alternate screen. **Do not use `println!`
or `eprintln!` in TUI code.** Diagnostics go to the local log file:

- default: `$XDG_DATA_HOME/rawframe/logs/rawframe.log` or
  `~/.local/share/rawframe/logs/rawframe.log`;
- override with `--log-file <path>`;
- logs never contain captured headers or bodies. Add new log fields
  deliberately and keep secrets out.

For UI debugging, use `rawframe_tui::testing::render_frame` and
`testing::text` to inspect the rendered buffer instead of printing to the
terminal. For engine debugging, use `tracing` events at lifecycle/error level and
the integration suite’s assertion messages. Avoid adding verbose per-request
logging that could capture target metadata.

### Terminal restoration

`TerminalSession::start` installs a panic hook that restores raw mode, mouse
capture, bracketed paste, the cursor, and the alternate screen. If you add
terminal modes, update both `restore_terminal` and the panic hook path. Never
leave the user’s terminal in raw mode on error.

## TUI contribution guide

### The render–input contract

Every interactive element must register itself during rendering:

```rust
output.hit(rect, HitTarget::Action(ActionId::ForwardRequest));
output.zone(rect, ScrollRegion::ProxyList);
```

Mouse handling resolves hits from the previous frame; overlays registered later
take precedence. Do not compute mouse coordinates from constants or assume a
panel’s position. Use `layout::compute` and the rectangles you rendered.

For editor-like widgets, also set `repeater_rows`, `repeater_cols`,
`editor_origin`, and `editor_gutter` so click-to-caret and scrolling work.

### Adding a screen

1. Add a `NavSection` variant, its labels/shortcut, and whether it uses the
   context inspector (`interaction.rs`).
2. Add a renderer in `screens/` and dispatch it from `ui::render_workspace`.
3. Register all rows/controls in `RenderOutput`.
4. Add screen-local state in `state.rs` if needed; keep it out of `App` unless
   the controller must coordinate it.
5. Add a `TestBackend` rendering test and, if it has a workflow, an integration
   test under `crates/rawframe-tui/tests` or `crates/rawframe-cli/tests`.
6. Update the README shortcut table and `docs/architecture.md` layout section.

### Keyboard precedence

Text-entry contexts must consume printable characters before global shortcuts.
If you add a shortcut, decide whether it may fire while:
- the command palette is open;
- the search field is active;
- a Repeater document is being edited;
- a settings field is being edited;
- a modal is open.

Add a test to `crates/rawframe-tui/tests/interaction_flow.rs` for shortcuts that
could damage or transmit something. `P` must never fire while editing a document
or search field.

### Focus and overlays

Focus options are derived from visible panels: navigation, content, and context.
When the terminal narrows, panels disappear and focus must still resolve to a
valid option. Overlays capture all input until dismissed; they are rendered
after the base UI and register a full-screen dismiss target.

### Live and simulated data

Fixtures live in `rawframe-core/src/fixtures.rs`. Keep every entry
`TrafficSource::Simulated` and every host under `.test`. Never add a fixture that
looks live, contacts a service, or implies a real assessment result.

Live entries arrive only through `TrafficCaptured`/`TrafficUpdated`; do not
synthesize them in UI code. Keep the `LIVE`/`SIM` source badges, Proxy banner,
header badge, and footer disclosure accurate. CONNECT entries must never display
a fabricated HTTP body; use the tunnel metadata view.

### Visual style

- Deep charcoal background, near-black surfaces, one restrained accent.
- Green = success, amber = warning, red = error/destructive, muted gray =
  metadata. Do not use semantic colors decoratively.
- Thin rounded borders; uppercase dim labels; one-line headings.
- No gradients, giant text, ASCII art, or unnecessary decoration.
- Test at 64×18, 84×24, 108×30, and 140×40 columns. The minimum-size screen must
  remain informative.

## Testing cookbook

Core:

```bash
cargo test -p rawframe-core
```

HTTP parser:

```bash
cargo test -p rawframe-http
```

Proxy unit tests:

```bash
cargo test -p rawframe-proxy --lib
```

Proxy integration tests (all local; no external websites):

```bash
cargo test -p rawframe-proxy --test forwarding -- --nocapture
```

TUI unit tests:

```bash
cargo test -p rawframe-tui --lib
```

TUI interaction integration tests:

```bash
cargo test -p rawframe-tui --test interaction_flow
```

TUI-to-engine boundary:

```bash
cargo test -p rawframe-cli --test proxy_tui -- --nocapture
```

Storage (real SQLite, isolated temp databases):

```bash
cargo test -p rawframe-store -- --nocapture
```

CLI:

```bash
cargo test -p rawframe-cli
```

Full gate:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Driving the UI in a test:

```rust
use rawframe_tui::{App, testing};
use rawframe_tui::interaction::HitTarget;

let mut app = App::demo();
testing::render_frame(&mut app, 140, 40);
let position = testing::position_for(&app, &HitTarget::Nav(rawframe_tui::NavSection::History))?;
// send KeyEvent / MouseEvent through app.handle_key / app.handle_mouse
```

`testing::render_frame` applies `RenderOutput` to the app, so mouse hit-testing
works exactly as it does in the real terminal loop. `App::drain_events` applies
queued proxy events without a terminal, which is how the CLI boundary test waits
for real captures.

### Manual persistence check

```bash
# isolated database and an authorized local upstream
cargo run -p rawframe-cli --bin rawframe -- \
  --db /tmp/rawframe-dev.db \
  --scope http://127.0.0.1:8000 \
  --allow-private-upstreams --persist-bodies
# press P, send a request with curl, then press B and restore/export it

# inspect the real rows (redaction and NULL bodies are visible here)
sqlite3 /tmp/rawframe-dev.db 'SELECT session_id, method, host, state, request_body FROM traffic;'

# headless redacted export
cargo run -p rawframe-cli --bin rawframe -- \
  --db /tmp/rawframe-dev.db --export-history /tmp/rawframe-dev.jsonl
```

With body persistence left off, `request_body` must be SQL `NULL`, never an
empty blob. Sensitive header values must be `<redacted>` unless explicitly
enabled. Do not commit a database or export.

### Manual proxy check

```bash
# local upstream
python3 -m http.server 8000 --bind 127.0.0.1

# RAWFRAME, authorizing only that upstream
cargo run -p rawframe-cli --bin rawframe -- \
  --scope http://127.0.0.1:8000 \
  --allow-private-upstreams
# press P on the Proxy screen

# generate a real capture
curl --noproxy '' -x http://127.0.0.1:8080 http://127.0.0.1:8000/
```

Confirm a `LIVE` row appears, inspect it, then press `P` to stop and verify the
state changes to `Stopped`. With TLS interception disabled, a CONNECT test
displays tunnel metadata only; it must not show a fabricated HTTP response body.
With interception enabled, decrypted HTTP/1.1 is labelled as live HTTPS traffic.

## Code conventions

- Errors: typed errors in libraries (`thiserror`), `anyhow` only at the CLI
  boundary. Do not swallow errors; surface them in the UI or the log.
- No `unwrap`/`expect` on runtime data paths. Tests may use them when the
  invariant is the thing being tested.
- Keep modules cohesive. Prefer adding a small helper to a screen over a new
  abstraction layer.
- Preserve the one-way dependency graph. If you need a proxy type in the TUI,
  move a UI-neutral model to `rawframe-core` instead.
- Keep every user-visible string honest about simulation/offline/opaque status.
- Never add an upstream certificate-verification bypass. The only supported trust
  override is an explicit local trust bundle for lab tests; hostname verification
  still applies.
- TLS tests must use local test CAs/servers, never public websites.
- Document security- or protocol-significant decisions in the relevant docs
  before implementing them.

## Release build

```bash
cargo build --release -p rawframe-cli
./target/release/rawframe
```

The release profile enables thin LTO, one codegen unit for the final binary,
and strips symbols. Do not deploy a build that claims networking features before
their integration tests are present and passing.
