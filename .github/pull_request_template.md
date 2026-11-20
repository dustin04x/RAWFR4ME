## What changed

<!-- One or two sentences. Link the issue if there is one. -->

## Why

<!-- The problem this solves. For security-relevant changes, state the threat. -->

## Checks

- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] Tests added or updated for behavioural changes

## Security invariants

Confirm the change does not weaken any of these:

- [ ] Loopback binding by default; remote bind still requires explicit opt-in
- [ ] Scope remains default-deny and is checked before any DNS or socket work
- [ ] Upstream TLS chain and hostname verification remain mandatory
- [ ] TLS interception remains opt-in and the CA private key is never exported or logged
- [ ] Sensitive header values are still redacted before storage and rendering
- [ ] New limits (bodies, connections, queues, payloads, timeouts) are bounded
- [ ] Documentation matches what actually ships

## Compatibility

- [ ] No schema migration, or the migration is additive and reversible
- [ ] No change to the CLI surface, or it is documented in `CHANGELOG.md`
