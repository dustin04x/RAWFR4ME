# Security Policy

RAWFRAME is a security-testing workbench intended **only** for systems you own or are explicitly authorized to test.

## Supported versions

Security fixes are issued for the latest 1.0.x release line.

| Version | Supported |
| --- | --- |
| 1.0.x | Yes |
| < 1.0 | No (pre-release development only) |

Security-relevant behavior, defaults, and known gaps are documented in
[`docs/security.md`](docs/security.md). Current implementation status and
limitations are in the [README](README.md#release-status) and
[`docs/roadmap.md`](docs/roadmap.md).

## Reporting a vulnerability

Please **do not** open a public issue for a suspected security vulnerability.

- Use GitHub's private vulnerability reporting / Security Advisories for this repository if available.
- If private reporting is not available, contact the maintainers through a private channel and provide enough detail to reproduce the issue.

When reporting, include: affected component/crate, version/commit, reproduction steps or proof of concept (against authorized targets only), and impact assessment. Do not include secrets or unrelated sensitive data.

## Security notes

- Default posture: default-deny scope, loopback-by-default listener binding, explicit opt-in for private upstreams/remote bind, upstream TLS verification, and sensitive-header redaction/sanitization.
- HTTPS TLS interception and a local interception CA are implemented and **opt-in**. Opaque `CONNECT` tunnelling remains the default. CA private keys are generated only on explicit enable/CLI action, stored with owner-only permissions, and never exported or logged.
- SQLite session persistence is local, enabled by default, and redacts sensitive header values before writing. Bodies are stored only when the operator opts in with `--persist-bodies`; sensitive header values only with `--persist-sensitive-headers`. Use `--no-persist` for memory-only sessions. Exports are redacted JSON Lines written with owner-only permissions.
- The full storage data inventory and file-protection details are in `docs/security.md`.
