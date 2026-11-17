# Contributing to RAWFRAME

Thanks for your interest in improving RAWFRAME. This repository is a Rust workspace for a terminal-native HTTP interception and security-testing workbench.

## Scope and safety

- RAWFRAME is intended **only** for systems you own or are explicitly authorized to test.
- Do not add features that weaken security defaults (default-deny scope, loopback-by-default binding, explicit private-upstream opt-in, TLS verification, redaction/sanitization).
- Do not claim unimplemented functionality (e.g. Intruder, Decoder, HTTP/2, or WebSocket support unless the code actually supports it). TLS interception, the local CA, SQLite session persistence, and real Repeater execution are implemented and tested; keep their documentation accurate.

## Development

Prerequisites: Rust **1.89+** (edition 2024). See `docs/development.md` for workflow details.

Run the quality gates before submitting changes:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Or run `./scripts/check.sh`.

## Guidelines

- Keep changes focused and consistent with the existing workspace architecture (`rawframe-core`, `rawframe-http`, `rawframe-proxy`, `rawframe-store`, `rawframe-tui`, `rawframe-cli`).
- Preserve the event/command boundaries and existing backend behavior unless a change is explicitly intended and verified.
- Add or update tests for behavioral changes where appropriate.
- Do not commit secrets, private keys/certificates, local databases, logs, or build artifacts (`target/`).

## Reporting issues

Please include steps to reproduce, expected vs actual behavior, terminal/OS details, and relevant (redacted) logs or captures. Do not include credentials or sensitive data.
