# Security Policy

RAWFRAME is a security-testing workbench intended **only** for systems you own or are explicitly authorized to test.

## Supported status

This project is under active development (see the README and `docs/roadmap.md` for current implementation status and limitations). Security-relevant behavior and defaults are documented in `docs/security.md`.

## Reporting a vulnerability

Please **do not** open a public issue for a suspected security vulnerability.

- Use GitHub's private vulnerability reporting / Security Advisories for this repository if available.
- If private reporting is not available, contact the maintainers through a private channel and provide enough detail to reproduce the issue.

When reporting, include: affected component/crate, version/commit, reproduction steps or proof of concept (against authorized targets only), and impact assessment. Do not include secrets or unrelated sensitive data.

## Security notes

- Default posture: default-deny scope, loopback-by-default listener binding, explicit opt-in for private upstreams/remote bind, upstream TLS verification, and sensitive-header redaction/sanitization.
- RAWFRAME does **not** currently implement TLS interception or a local CA; HTTPS `CONNECT` tunnels remain opaque.
