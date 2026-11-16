# Security Model

RAWFRAME is security-sensitive infrastructure. This document records the threat
model, the controls implemented in Milestone 2 (0.2.0), and the gaps that must
stay visible until later milestones close them.

RAWFRAME must only be used against systems for which the operator has explicit
authorization. The tool does not grant permission to test anything.

## 1. Threat model

### Hostile captured data

HTTP traffic is attacker-controlled. Without neutralization it can:

- emit terminal escape sequences that clear the screen, move the cursor, change
  colors, write fabricated text, query the terminal, or set the clipboard
  through OSC sequences;
- contain Unicode bidi overrides and C1 controls that visually reorder or hide
  content;
- include invalid UTF-8 or large binary bodies that break naive rendering;
- contain header values with control characters or extreme lengths.

### Network and destination abuse

A proxy can become an open relay, expose the operator's host, or be tricked into
reaching services that the hostname scope was meant to protect. DNS rebinding can
return a different address between an authorization check and the connection.
An HTTPS tunnel can reach any TCP service that the operator's network allows;
opaque relaying does not make the destination safe.

### Confidentiality

Captured traffic routinely contains bearer tokens, cookies, API keys, session
identifiers, and personal data. Accidental screenshots, shoulder surfing,
logging, persistence, and export can disclose them. CONNECT payloads are never
captured, but HTTP headers and bodies are.

### Resource exhaustion

Slow clients, stalled upstream servers, very large bodies, connection floods, and
silent tunnels can consume memory, sockets, or task slots. Limits must be
enforced in the data path, not only in form validation.

### Operator error

Accidental forwarding, dropping, or replaying the wrong request can alter an
authorized engagement. Destructive actions must be explicit and clearly
distinguishable from safe inspection. Running a listener on a non-loopback
interface without authentication exposes it to the local network.

### Supply chain

Every dependency increases the trust surface. Networking, TLS, parsing, and
database libraries need deliberate review and version pinning.

## 2. Controls implemented today

### Listener exposure

- The default listener is `127.0.0.1:8080`.
- A non-loopback `--bind` is refused unless `--allow-remote-bind` is supplied,
  and the CLI logs a warning.
- The TUI Settings editor refuses non-loopback addresses; remote binding is a
  CLI-only, explicit action.
- There is no proxy authentication. A remote bind trusts every client that can
  reach the port; operators must protect it with host firewall rules or a
  trusted network. This is documented as a limitation.

### Destination scope and DNS safety

- Scope is default-deny: an empty allowlist denies every HTTP request and
  CONNECT. Starting the engine with an empty scope emits a warning.
- Scope rules enforce case-insensitive exact hosts, leading-wildcard hosts,
  optional scheme, and optional port. HTTP forwarding uses `http`; CONNECT uses
  `https`; default ports are 80 and 443.
- Scope is checked before DNS resolution or any upstream connection. A denial is
  recorded as a failed capture (`403`) and no socket is opened.
- The destination hostname is resolved **once**. Every returned address is
  checked by an address policy, and the connection is made to that exact
  validated address list. No second lookup occurs, preventing a rebinding
  response from redirecting the connection after validation.
- By default only public addresses are permitted. Loopback, RFC 1918, IPv6
  loopback, and IPv6 unique-local addresses require the explicit
  `--allow-private-upstreams`/Settings opt-in for local labs.
- Link-local (including `169.254.169.254` metadata), unspecified, multicast,
  carrier-grade NAT, benchmarking, documentation, reserved, and non-global IPv6
  ranges are always rejected, even with the private-upstream opt-in.
- Absolute-form URI scheme/host/port must match the `Host` header; duplicate
  `Host` headers and invalid authorities are rejected. This prevents a client
  from presenting one authority to a log or cache and another to the upstream.
- Unsupported schemes and origin-form proxy requests are rejected with `400`.
  `https://` forward requests are rejected because TLS termination is absent.

### HTTP message handling

- Hyper performs wire parsing and framing with a bounded read buffer and header
  read timeout. Malformed requests are rejected without terminating the listener.
- Hop-by-hop headers are removed in both directions: `Connection`, every field
  named by its tokens, `Proxy-Authorization`, `Proxy-Authenticate`, `TE`,
  `Trailer`, `Transfer-Encoding`, and `Upgrade`. Response `Content-Length` is
  removed so Hyper frames the filtered body correctly.
- End-to-end headers, including duplicate fields such as `Set-Cookie`, are
  preserved in order.
- Request and response bodies are streamed through a guarded body. Declared
  lengths over the configured cap are rejected before streaming; unknown-length
  streams are terminated when the cap is crossed.
- Upstream failures, handshake failures, response-header timeouts, idle body
  stalls, and downstream disconnects are recorded as failures. A `200` is never
  fabricated, and a terminal `Completed` state requires the body to end normally.

### Opaque CONNECT handling

- CONNECT destinations pass the same scope and address policy before the
  upstream TCP connection is made.
- After a `200`, bytes are relayed opaquely in both directions. Half-close is
  preserved. No TLS is terminated, generated, or inspected; no certificate or
  private key exists.
- Tunnels have an activity-based idle timeout, are bounded by a separate tunnel
  semaphore, and are terminated on proxy shutdown.
- Captured metadata is limited to destination, outcome, duration, byte counts,
  and a short non-sensitive detail. Payload bytes and inner headers are never
  stored or logged.

### Bounded resources

| Control | Default | Behavior |
|---|---|---|
| Request body | 2 MiB | `413` before streaming for declared oversize; stream aborted when exceeded |
| Response body | 2 MiB | `502` before streaming for declared oversize; stream aborted when exceeded |
| Concurrent client connections | 128 | excess connections are closed |
| Concurrent CONNECT relays | `max_connections` | bounded by a tunnel semaphore |
| DNS/connect/handshake timeout | 10 s | `502`/`504` failure recorded |
| Response-header timeout | 30 s | `504` gateway timeout |
| Body and tunnel idle timeout | 60 s | stalled stream/tunnel is terminated |
| Event queue | 4096 events | bounded; async producers apply backpressure |
| Command queue | 32 commands | bounded |
| Read buffer | 64 KiB | Hyper server read buffer cap |

All values above are validated ranges: body limits 1 B–64 MiB, connections
1–4096, and timeouts must be non-zero. Settings changes are session-only and
network limits apply after the proxy is restarted.

### Secret redaction and terminal safety

- `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`,
  `X-Auth-Token`, and `X-Csrf-Token` are redacted by default in the inspector's
  raw, headers, and body views.
- Redaction is presentation-level; the in-memory model retains values for
  authorized inspection. Nothing is written to disk.
- The inspector shows a `REDACTED` or `UNREDACTED` indicator. Disabling redaction
  requires an explicit action through Settings, the palette, or `--no-redact`,
  and produces a warning.
- `rawframe_core::security` converts captured bytes to display text before any
  terminal rendering: ANSI/C0 controls become caret notation, C1 controls become
  `\u{xxxx}`, bidi overrides are escaped, CRLF is normalized, tabs expand, and
  invalid UTF-8 is marked lossy. Body display is capped and marked `TRUNCATED`.
- Captured CONNECT metadata and error/note strings pass through the same
  sanitization before rendering. The tunnel inspector renders byte counts and
  outcome, never payload.
- The Repeater editor accepts paste through a sanitizing path; pasted escape
  sequences cannot manipulate the terminal. The terminal cursor is hidden while
  the TUI is active.

### Logging, persistence, and telemetry

- Logs contain startup configuration, warnings, lifecycle markers, and proxy
  worker errors. The proxy does not log request/response headers, bodies, query
  strings, credentials, cookies, or CONNECT payloads.
- No SQLite database is created. Bodies and sensitive headers are off by default
  in configuration, and nothing is persisted in this build.
- Settings and history are in-memory only.
- No telemetry endpoint, external website, or shell command is used.
- No certificate authority or private key is generated.

### Lifecycle and confirmation

- Traffic transitions are validated; terminal states cannot be revived.
- Quitting with unsaved Repeater edits, or closing a dirty tab, requires
  confirmation.
- Live traffic is forwarded automatically in M2. The existing forward/drop
  controls affect only simulated paused fixtures and cannot fake a live response.
- `Ctrl+C` remains an unconditional emergency exit; terminal state is restored on
  panic and normal exit.
- Proxy shutdown stops the listener, waits briefly for tracked tasks, terminates
  tunnels, and reports `Stopped`. Closing the TUI drops the command sender, which
  also stops the service.


## Interception (current state)

- RAWFRAME includes an HTTP interception path that can pause matching HTTP requests before upstream contact and resolve them via forward unchanged, forward modified, or drop. Intercepted entries carry interception metadata and (when available) original/final request data for inspection/history.
- Interception decisions are real proxy decisions; dropped/timed-out/cancelled requests must not fabricate upstream responses.
- **TLS interception is not implemented.** HTTPS `CONNECT` tunnels remain opaque: no TLS termination, no CA/certificate generation, and no visibility into tunneled payloads/headers. Do not treat CONNECT metadata as decrypted HTTPS content.

## 3. Explicit limitations and gaps

| Gap | Consequence | Planned handling |
|---|---|---|
| No TLS interception or CA | HTTPS inside CONNECT is invisible; RAWFRAME cannot validate or inspect the tunnel's certificates | Milestone 3, with restricted key storage, separate verified upstream TLS, and explicit trust |
| Opaque CONNECT can reach any authorized TCP service | Scope authorizes host/port, not application-layer safety | Use narrow scope and private-upstream defaults; do not authorize broad wildcards casually |
| No proxy authentication | A remote listener is usable by anyone who can reach it | Keep loopback; firewall remote binds; authentication is future work |
| No per-client rate limit | One authorized client can use the global connection/body budget | Global semaphores and body caps; add quotas later if needed |
| Connection-limit overflow closes the socket | Client sees a transport error, not an HTTP `503` | Acceptable M2 behavior; document and revisit |
| No HTTP/2, HTTP/3, WebSocket forwarding | Some traffic cannot traverse the proxy; `Upgrade` is stripped | Future protocol work |
| No persistence | History and settings vanish on exit; no export | Milestone 4, with redaction on write and opt-in bodies |
| Interception controls are not live | Cannot pause/edit/forward individual live HTTP requests yet | Milestone 4 |
| DNS policy is conservative | Some special-purpose/lab ranges are refused | Explicit, reviewed policy extension rather than bypass |
| No automated dependency audit | Supply-chain drift is possible | Add `cargo audit`/`cargo deny` in CI |
| Local logs are not rotated | Log growth over long runs | Add bounded retention with logging settings |
| Redaction toggle does not rewrite existing Repeater buffers | A tab seeded while redaction was off retains visible secrets until reopened | Deliberate: editing must not silently mutate documents; warning shown |
| No clipboard/copy action | Operators cannot copy from RAWFRAME | Consider an explicit, reviewed action later |

Do not describe TLS interception, certificate generation, live pause/edit, or
persistence as working until the relevant milestone includes passing integration
tests. The interface says “no TLS interception” and “opaque tunnel” in this build.

## 4. Planned certificate authority design (Milestone 3)

The CA is the most sensitive component of an interception proxy. These
constraints are non-negotiable:

1. Generation requires an explicit operator action; it never happens silently on
   first launch.
2. The root private key is stored only on the local machine, in a dedicated
   directory, with owner-only permissions (`0600` key, `0700` directory). It is
   never serialized into traffic, logs, exports, or the repository.
3. The CA certificate is published with a clear fingerprint and explicit trust
   instructions. RAWFRAME must never install itself into a system trust store
   automatically.
4. Leaf certificates are minted per hostname on demand, cached with bounded
   lifetime, and never issued for hosts outside the configured scope.
5. Client-facing TLS termination is separate from the upstream TLS connection.
   Upstream verification uses the system/root trust store and stays enabled.
   There is no default “insecure” path.
6. Certificate generation and key access are audited in local logs without
   recording key material.
7. Tests use a self-contained test CA and local TLS servers. No public
   certificate transparency or third-party service is contacted.

## 5. Operational guidance

- Work from a dedicated testing profile or virtual machine when possible.
- Keep the CA private key off shared or backed-up locations once M3 exists.
- Remove trust in the RAWFRAME CA when an engagement ends.
- Keep target scope explicit. An empty allowlist is intentional: add only hosts
  you are authorized to test.
- Prefer exact host/port rules over wildcards, and leave
  `--allow-private-upstreams` off unless the target is local lab infrastructure.
- Do not expose the proxy on `0.0.0.0` without a firewall; there is no
  authentication.
- Treat screenshots and terminal scrollback as sensitive. Redaction is on by
  default for this reason.
- Review logs before sharing them; they are local and contain lifecycle data,
  not captured traffic.
- Do not use `--no-redact` in shared environments.

## 6. Reporting security issues

Do not open a public issue containing exploit details or captured secrets.
Contact the RAWFRAME maintainers privately through the project's security
channel. Include a minimal reproduction with synthetic values only.
