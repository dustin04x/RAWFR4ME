# Changelog

All notable changes to RAWFRAME are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-11-20

First stable release. This version freezes the command-line interface, the
SQLite schema, the stored finding format, and the documented protocol coverage
described below. Everything listed here is covered by the workspace test suite
and, where marked, by real-PTY captures committed under `docs/screenshots/`.

### Added

- **Passive analysis engine (`rawframe-analysis`), as a library only.** A
  deterministic, versioned 17-rule inventory evaluates captured HTTP/1.1,
  HTTP/2 shared messages, and WebSocket handshakes and complete text messages.
  Findings carry severity, confidence, the triggering field or fixed marker,
  impact, and remediation, with stable fingerprints and redacted evidence. A
  bounded scheduler adds backpressure and cancellation. The crate is built and
  tested but is **not** linked by the application: there is no Findings
  workspace, no runtime analysis, and no findings persistence in 1.0.0. See
  [docs/analysis-rules.md](docs/analysis-rules.md).
- `CHANGELOG.md`, `.gitattributes`, and GitHub issue and pull-request templates.
- Continuous integration running formatting, workspace check, build, tests,
  Clippy with warnings denied, and a release build. A tag-triggered release
  workflow builds the Linux x86_64 binary from the tagged source, publishes
  SHA-256 checksums, and attaches both to the GitHub Release.

### Changed

- Workspace version raised from `0.2.0` to `1.0.0`. All nine crates inherit the
  workspace version, so `rawframe --version` now reports `1.0.0`.
- README rewritten as release documentation with installation, build,
  quick-start, TLS trust, configuration, testing, and troubleshooting sections.

### Fixed

- The interception end-to-end harness released its reserved port before the
  proxy bound it, so the three proxy-to-TUI tests could not start a listener
  reliably.
- The harness echo server busy-spun on a nonblocking `accept()` instead of
  sleeping, consuming a core for the duration of each test.
- The harness matched the wrong header pattern when recording `X-Rf`, so the
  modified-forwarding test always observed an empty header list.
- Unused `mut` bindings and a `needless_bool` in the destination policy failed
  `cargo clippy -- -D warnings` on newer toolchains.
- The screenshot pipeline could not reproduce the committed gallery. The ANSI
  emulator discarded SGR sequences, so every freshly rendered PNG was a single
  flat text colour, and the verifier's size floor and expected palette did not
  match the current theme. Cells now carry their own foreground and background,
  the verifier derives its bounds from the renderer, and the gallery was
  regenerated from the 1.0.0 binary.
- Removed unrunnable passive-analysis leftovers: a Findings screen that was never
  registered in the TUI module tree and referenced application state that did not
  exist, two store exports that queried a `findings` table no migration created,
  the unused `FindingExportFormat` type, and the analysis capture script and
  screenshots that described a UI the binary does not contain.

### Known limitations

- Plaintext listeners are HTTP/1.1 only; h2c is not implemented. HTTP/2 requires
  TLS with an `h2` ALPN result.
- WebSocket support is HTTP/1.1 upgrade only. No HTTP/3, QUIC, RFC 8441
  extended CONNECT, WebSocket over HTTP/2, or `permessage-deflate`.
- Opaque `CONNECT` captures destination, outcome, byte counts, and duration
  metadata only. No URL, headers, body, or tunnelled certificate is visible.
- Pinned clients fail the intercepted handshake by design. RAWFRAME does not
  bypass certificate pinning.
- TLS interception is opt-in and requires explicit local CA trust.
- Settings are session-only; there is no configuration file. The accent,
  limits, and scope edits do not persist across restarts.
- Local diagnostic logs are not rotated.
- Scope rule changes apply to new requests; established connections keep the
  rules they were admitted under.
- Connection-limit overflow closes the socket rather than returning `503`.
- The minimum usable TUI size is 64×18; the inspector requires 108 columns.
  Truecolor is assumed.
- Release artifacts are built and verified for Linux x86_64 only. Other targets
  are not claimed.
- Passive analysis has no user interface. The rule engine is a library with no
  Findings workspace, no runtime scheduler, and no findings table; storage schema
  version remains `4`.
- Rules are conservative observations, not exploit verification. Status, size,
  and timing differences are never presented as proof of a vulnerability.

See [docs/roadmap.md](docs/roadmap.md) for the full limitation list and the
planned work that is explicitly not part of 1.0.0.

## [0.2.0] — 2026-11-19

Development milestones 2 through 10. This version was never tagged or released
as a stable artifact; it is recorded here because the schema and behaviour were
introduced here. Milestone 11 was not part of it.

### Added

- HTTP/1.1 forwarding proxy with streaming bounded bodies, hop-by-hop filtering,
  duplicate header preservation, default-deny scope, resolve-once DNS policy,
  connection and body limits, and graceful shutdown.
- Opaque HTTPS `CONNECT` tunnelling with bidirectional relay, half-close, idle
  timeout, and byte and duration metadata.
- Opt-in HTTPS TLS interception with a local CA, per-host certificate issuance,
  and mandatory upstream chain and hostname verification.
- HTTP interception workbench: pause before upstream, forward unchanged,
  forward modified, or drop, with a bounded queue and operator timeout.
- Persistent sessions and history in SQLite with redaction-on-write, session and
  project restore, and redacted JSON export.
- Repeater with independent HTTP/1.1 and HTTP/2 connections, verified TLS,
  redirects re-checked per hop, and Raw, Headers, Body, Pretty JSON, Hex, and
  Compare views.
- Binary-safe Decoder with chained transformations, intermediate inspection, and
  explicit transfer to Repeater bodies and Intruder payload lists.
- Intruder with four strategies (Sniper, Battering Ram, Pitchfork, Cluster
  Bomb), payload positions, wordlist import, bounded concurrency, a local rate
  gate, pause/resume/cancel, and result analysis.
- Genuine HTTP/2 over negotiated ALPN in the proxy, Repeater, and Intruder.
- HTTP/1.1 WebSocket interception with frame-level relay, per-frame
  pause/forward/drop/modify, a dedicated workspace, and an authored WebSocket
  Repeater.

## [0.1.0] — 2026-11-16

### Added

- Cargo workspace with one-way crate dependencies and a documented graph.
- Shared request, response, traffic, session, configuration, and certificate
  models with validated interception lifecycle and default-deny scope.
- Asynchronous application event bus and outbound command contract.
- Terminal lifecycle with raw mode, alternate screen, mouse capture, bracketed
  paste, panic-safe restoration, and resize handling.
- Keyboard-first shell, command palette, inspector, theme system with semantic
  colours, and sensitive-header redaction.
- Proxy, HTTP History, Repeater, and Settings workspaces.
- Architecture, dependency, security, development, and roadmap documentation.
