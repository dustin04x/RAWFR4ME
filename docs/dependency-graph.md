# Dependency Graph

## Internal crates

```
rawframe-cli
├── rawframe-tui
│   ├── rawframe-http
│   │   └── rawframe-core
│   ├── rawframe-core
│   ├── ratatui
│   └── chrono
├── rawframe-proxy
│   ├── rawframe-core
│   ├── hyper
│   ├── hyper-util
│   ├── http-body-util
│   ├── bytes
│   ├── tokio
│   ├── tokio-util
│   ├── chrono
│   ├── thiserror
│   └── tracing
├── rawframe-core
├── clap
├── anyhow
├── tokio
├── tracing
└── tracing-subscriber
```

`rawframe-cli` is the only composition root and binary. The library crates form
a directed acyclic graph. `rawframe-core` has no internal dependencies.
`rawframe-proxy` does **not** depend on `rawframe-tui`; `rawframe-tui` does not
depend on `rawframe-proxy`. The CLI attaches the shared `CommandSender` to the
UI, so the UI triggers engine commands without importing proxy internals.

### Dependency rules

| Crate | May depend on | Must never depend on |
|---|---|---|
| `rawframe-core` | external domain libraries only | TUI, proxy, storage, CLI |
| `rawframe-http` | `rawframe-core`, `httparse` | TUI, proxy, storage, CLI |
| `rawframe-proxy` | `rawframe-core`, Hyper/Tokio networking libraries | TUI, storage, CLI |
| `rawframe-tui` | `rawframe-core`, `rawframe-http`, Ratatui, Chrono | proxy or storage internals, sockets, Tokio runtime |
| `rawframe-cli` | all workspace crates | — |
| future `rawframe-storage` | core, SQLite driver | TUI, proxy, CLI |

Only `rawframe-cli` constructs the Tokio runtime. `rawframe-proxy` is runtime-
agnostic: its `run_service` future is spawned by the composition root.
`rawframe-tui`'s loop remains synchronous; it polls a bounded channel and never
performs network or storage work.

## External dependencies

Versions are declared once in the workspace manifest and inherited by crates.

| Crate | Version | Used by | Purpose |
|---|---|---|---|
| `serde` | 1.0 | core | derive serialization for models and config |
| `chrono` | 0.4 | core, tui, proxy | UTC timestamps and durations |
| `tokio` | 1.54 (`sync` in core; `net`, `rt`, `time`, `io-util` in proxy/CLI) | core, proxy, cli | bounded channels, runtime, async I/O, timeouts |
| `tokio-util` | 0.7 (`rt`) | proxy | `TaskTracker` for graceful task draining |
| `thiserror` | 2.0 | core, http, proxy | typed errors with context |
| `httparse` | 1.10 | http | HTTP/1.x document parsing |
| `hyper` | 1.x (`http1`, `server`, `client`) | proxy | HTTP/1.1 wire parsing, client/server connections |
| `hyper-util` | 0.1 (`tokio`) | proxy | Tokio I/O adapter |
| `http-body-util` | 0.1 | proxy | body boxing/mapping combinators |
| `bytes` | 1.10 | proxy | zero-copy body frames |
| `ratatui` | 0.30 | tui, cli tests | immediate-mode terminal rendering |
| `crossterm` | 0.29 | tui (re-exported by Ratatui) | terminal input, raw mode, mouse, paste |
| `clap` | 4.6 | cli | argument parsing |
| `anyhow` | 1.0 | cli | top-level error context |
| `tracing` | 0.1 | cli, proxy | structured local diagnostics |
| `tracing-subscriber` | 0.3 | cli | file logging subscriber |

Notes:

- Hyper and Tokio provide HTTP/1.1 parsing, framing, upgrades, and async I/O.
  RAWFRAME does not reimplement wire framing.
- `rawframe-http` remains a document parser for the Repeater, not the proxy's
  wire parser.
- `tokio-util` is used only for task tracking; no runtime is embedded in a
  library crate.
- No HTTP/2, HTTP/3, TLS, certificate-generation, SQLite, UUID, clipboard, or
  network-logging dependency is present.
- Truecolor rendering needs no extra dependency; Ratatui RGB colors are used
  directly.

## Planned dependencies (not installed)

These are listed for design transparency only. They are not in `Cargo.lock`.

| Milestone | Likely dependency | Purpose |
|---|---|---|
| 3 | `rustls`, `tokio-rustls`, `rcgen` | CA generation, client-facing termination, verified upstream TLS |
| 4 | `rusqlite` (bundled) or `sqlx` | SQLite migrations and history |
| later | `serde_json` | export formats |
| later | terminal clipboard helper | explicit copy actions, if implemented without shell execution |

Every planned addition must preserve the rule that networking and storage are
invisible to the presentation crate.

## Inspecting the graph

```bash
cargo tree --workspace --depth 2
cargo tree -p rawframe-tui --invert
cargo tree -p rawframe-proxy
cargo tree -p rawframe-core
```

`Cargo.lock` is committed so application builds are reproducible.
