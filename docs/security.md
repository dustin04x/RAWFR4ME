# Security Model

RAWFRAME is security-sensitive infrastructure. This document records the threat
model, the controls implemented through Milestone 7 (0.2.0), and the gaps that
must stay visible until later milestones close them.

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
logging, persistence, and export can disclose them. Opaque CONNECT payloads are
never captured; when TLS interception is explicitly enabled, decrypted HTTP/1.1
headers and bodies are captured like ordinary HTTP traffic.

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
- The allowlist can be edited live in Settings. New requests and CONNECT
  sessions use the updated rules immediately; established connections and
  already-forwarded requests keep the rules they were admitted under. Rules use
  the same parser as `--scope`, and adding a rule never opens a host by
  accident: an empty allowlist with default-deny still denies everything.
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
  Direct `https://` forward requests are rejected; HTTPS inspection is performed
  through `CONNECT` and the explicit interception path.

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

### HTTP/2 handling

- HTTP/2 is used only after an exact `h2` ALPN result on a TLS leg. Each leg
  negotiates independently, and the recorded protocol reflects what was actually
  selected; nothing is relabelled by configuration. h2c is not implemented.
- Certificate-chain and hostname verification are unchanged on the upstream leg,
  and the client-facing certificate remains a per-destination leaf from the local
  CA. Negotiating h2 never weakens verification.
- Pseudo-headers are structural, not ordinary headers. `:method`, `:scheme`,
  `:authority`, and `:path` map to validated request fields, and
  connection-specific HTTP/1.1 fields are removed before an h2 send. An h2
  request cannot smuggle a second `Host` or connection-control field.
- Per-connection stream count (128) and request header list size (64 KiB) are
  bounded. Body caps, timeouts, and connection limits still apply per stream.
- Each stream is a separate interception decision and traffic entry. A paused or
  slow stream cannot hold another stream's response, and drop/modify/timeout
  apply only to that stream. A client stream reset cancels its pending decision
  and drains it from the queue without forwarding; proxy shutdown cancels all
  pending streams.
- Cross-protocol bridges keep both versions: an h2 client over an HTTP/1.1
  upstream (or the reverse) is displayed with the real protocol on each side.

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
- Redaction is applied at display time for in-memory traffic. For persistence,
  `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`,
  `X-Auth-Token`, and `X-Csrf-Token` values are replaced with `<redacted>`
  **before SQL**, and bodies are stored as `NULL`, unless the operator explicitly
  opts in with `--persist-sensitive-headers` / `--persist-bodies`.
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
- Captured traffic can be persisted to a local SQLite database (Section 2.1).
  Persistence is on by default; `--no-persist` keeps everything in memory only.
- History and sessions are stored in the database. Settings, the storage
  policy, and the target scope rules are runtime state only: they come from CLI
  flags or UI edits for the current run and are not written to a config file.
- No telemetry endpoint, external website, or shell command is used.
- CA material and private keys are never written to logs, exports, events, or history. The CA exists only when the operator explicitly enables interception or runs a CA command.

### Lifecycle and confirmation

- Traffic transitions are validated; terminal states cannot be revived.
- Quitting with unsaved Repeater edits, or closing a dirty tab, requires
  confirmation.
- With interception armed, matching live HTTP/decrypted HTTPS requests pause for
  an explicit forward/edit/drop decision. With interception off, live traffic
  forwards automatically. Neither path can fabricate an upstream response.
- `Ctrl+C` remains an unconditional emergency exit; terminal state is restored on
  panic and normal exit.
- Proxy shutdown stops the listener, waits briefly for tracked tasks, terminates
  tunnels, and reports `Stopped`. Closing the TUI drops the command sender, which
  also stops the service.

### Repeater execution

- Repeater never enters the proxy listener, interception queue, or local CA path.
  It opens its own direct connection for each execution and redirect hop.
- The request is revalidated in the engine. UI validation is advisory. `CONNECT`,
  ambiguous framing, invalid headers, unsupported schemes, and oversized bodies
  are refused before DNS.
- Scope is default-deny and re-read immediately before every connection and
  redirect hop, so edits in Settings apply without restarting Repeater. A blocked
  redirect returns the real 3xx response plus a `Blocked` error; it is not
  followed.
- The same resolve-once address policy is used as the proxy: every resolved
  address is validated and the connection uses those addresses. Loopback/private
  targets require `--allow-private-upstreams`; metadata, link-local, reserved,
  multicast, and other always-blocked ranges remain refused.
- HTTPS always uses certificate-chain and hostname verification. There is no
  insecure switch. `--tls-upstream-ca` can replace trust roots for a lab without
  disabling verification.
- Redirects are off by default and capped at five hops. Each destination is
  scope-checked. `Authorization`, `Proxy-Authorization`, `Cookie`, `X-Api-Key`,
  `X-Auth-Token`, and `X-Csrf-Token` are removed on cross-origin hops. 301/302
  POST→GET and 303→GET rewrites drop the body; 307/308 preserve it.
- Request/response body limits, connect/header/body-idle/total timeouts,
  per-execution cancellation, and a bounded concurrency semaphore are enforced in
  the engine. Late completions cannot overwrite a newer tab execution.
- Repeater response/error text passes through the same terminal sanitization as
  captured data. `Pretty JSON` and `Hex` read a display-only copy; they never
  mutate the raw response model.
- Completed Repeater entries are stored through the same redaction/body policy
  and carry `REPEATER` provenance plus an optional original-capture reference.
  Persistence failure is surfaced in the UI and never aborts an execution.

### Intruder execution

- Nothing is sent until the operator confirms a dialog that names the target,
  strategy, request count, concurrency, rate, redirect policy, and scope. The
  confirm action is a typed `ConfirmAction::IntruderStart`; there is no
  auto-start, default-yes, or “run again” shortcut that bypasses it.
- Intruder reuses `RepeaterEngine::execute` for every generated request. Scope,
  resolve-once address policy, verified upstream TLS, header/body validation, and
  timeouts are therefore identical to Repeater by construction, not reimplemented.
  Scope is re-read per request and per redirect hop.
- Redirects are off by default. When enabled, the Repeater redirect rules apply:
  five-hop cap, per-hop scope check, and cross-origin credential stripping.
- Payload expansion is bounded before execution: 16 positions, 16 payload sets,
  512 payloads per set, 4096 bytes per payload, 2048 generated requests,
  concurrency 8, rate 20/s, duration 1800 s, capture 256 KiB, body 1 MiB.
  Requests above the ceiling are refused with a count instead of truncated.
- The worker pool is finite and cancel-aware. `Pause` stops starting new
  requests, `Cancel`/`Shutdown` abort the pool and mark unsent indices `NotSent`;
  no request is retried silently, and no result is invented for an unsent index.
- Results are observations: status, size, duration, headers, and body. RAWFRAME
  does not label them as vulnerabilities, does not infer success from timing, and
  does not hide negative results. Blocked, timed-out, failed, and not-sent
  outcomes stay distinct from responses.
- Wordlist files are read locally as data. They are never executed, and invalid
  UTF-8 lines are skipped and counted rather than reinterpreted.
- Payload lists are session-only and never persisted. Completed Intruder rows are
  persisted under the same redaction policy as proxy traffic, with the payload
  values that produced them and an optional origin-capture reference; export
  includes those fields only for Intruder rows.
- Transfers are explicit and non-destructive: History/Repeater/Decoder to
  Intruder copies the request, and Intruder to Repeater opens the result as a new
  tab without overwriting an existing draft.
- No evasion capability exists: no proxy rotation, source-address spoofing,
  throttling or rate-limit bypass, CAPTCHA handling, WAF evasion, or distributed
  scanning. The local rate gate paces RAWFRAME, it does not hide the traffic.

### Decoder transformations

- Decoder runs entirely in-process on bounded byte buffers. It has no network
  access, opens no sockets, executes no shell or scripts, and never evaluates
  decoded content. Input and output are capped at 8 MiB and pipelines at 16
  steps; limits are checked in the engine, not only in the UI.
- Gzip decompression is wrapped in a bounded reader, so a decompression bomb is
  stopped at the output limit instead of being expanded into memory. Malformed,
  truncated, and oversized streams return actionable errors without panicking.
- Text-only transformations reject invalid UTF-8 rather than silently replacing
  bytes. Binary input is preserved as bytes; non-text output is rendered as a
  hex dump with a format label. Editing a binary input deliberately switches to
  its lossy visible text, and the UI states this.
- JWT inspection decodes the header and payload for display. It does not verify
  the signature, trust the algorithm, or imply that a token is valid; the UI and
  output say so explicitly. `exp`/`nbf`/`iat` are shown as informational times.
- MD5 is provided only as a legacy checksum and is labelled cryptographically
  broken and unsuitable for security verification. SHA-256/384/512 are computed
  with `sha2`; RAWFRAME does not implement cryptographic primitives itself.
- Decoder content and history are session-only. Nothing is written to SQLite,
  logs, events, exports, or any external service. Copy uses terminal OSC 52;
  the terminal's clipboard policy can ignore it, and RAWFRAME does not fall back
  to shell clipboard tools.
- Repeater integration is explicit. Sending a request/response body or inserting
  Decoder output requires an operator command. Insertion rewrites
  `Content-Length`/`Transfer-Encoding`, preserves the original request model and
  stored captures, and is visible as a dirty Repeater draft before execution.

## Interception (current state)

- RAWFRAME includes an HTTP interception path that can pause matching HTTP requests before upstream contact and resolve them via forward unchanged, forward modified, or drop. Intercepted entries carry interception metadata and (when available) original/final request data for inspection/history.
- Interception decisions are real proxy decisions; dropped/timed-out/cancelled requests must not fabricate upstream responses.
- **HTTPS TLS interception is opt-in.** When disabled (default), `CONNECT` tunnels remain opaque: no TLS termination, no certificate issuance, and no visibility into tunneled payloads. When explicitly enabled, decrypted HTTP/1.1 requests use the same interception queue, validation, history, and lifecycle as HTTP. Opaque tunnels are never represented as decrypted traffic.

## 2.1 Durable storage (implemented)

### Data inventory

When persistence is active, the database contains for each session:

- session and project identifiers, names, timestamps, close reason, and an
  `incomplete`/`recovered` marker;
- request method, scheme, host, port, target, HTTP version, ordered headers
  (including duplicates), response status/reason/version, timestamps, duration,
  error/note text, interception and tunnel metadata;
- bodies **only** when body persistence is enabled; otherwise SQL `NULL`;
- sensitive header values only when sensitive-header persistence is enabled;
  otherwise the literal `<redacted>`;
- for completed Intruder requests only, the payload values that produced the
  request (base64-encoded JSON) and the originating capture ID, if any. Payload
  **lists** and imported wordlists are session-only and never stored.

Completed Repeater transactions use the same row format and policy, with a
`repeater` stored source and a nullable `repeater_origin` reference to the
capture they were seeded from. Unfinished Repeater drafts and in-flight
executions are not stored.

Never stored: the CA private key, TLS session keys, tunnel payloads, raw TLS
bytes, terminal input, or logs. Live/decrypted HTTP traffic is stored according
to the policy above; opaque CONNECT payloads remain unreadable and unstored.

### Defaults and opt-in

| Option | Default | Effect |
|---|---|---|
| persistence | on | `--no-persist` disables the database entirely |
| bodies | off | `--persist-bodies`/Settings stores future bodies |
| sensitive headers | off | `--persist-sensitive-headers`/Settings stores future values |
| database location | platform data dir | `--db FILE` |

A policy change affects **future writes only**. Entries already stored keep the
redaction they were written with, so enabling body storage cannot retroactively
recover old bodies and disabling sensitive storage cannot erase already-written
credentials. The interface states this.

### File protection and durability

- The database, WAL, and SHM files live in a directory created/forced to `0700`
  on Unix; the database and export files are `0600`.
- SQLite runs in WAL mode with `synchronous=FULL`, a 5 s busy timeout, and a
  configurable page ceiling (512 MiB default) so a runaway capture session stops
  writing instead of filling the disk.
- Batches are written in one transaction. Every write is ordered after the
  capture event, never before it; the proxy is never blocked on I/O.
- Opening runs `quick_check`. A corrupt database, a newer schema, a full disk, or
  an unwritable location disables persistence with an explicit UI/log error. The
  file is left in place for inspection or recovery; RAWFRAME never deletes it.
- On the next run, sessions that did not close cleanly are marked `recovered`,
  and unfinished transactions remain `incomplete` rather than being reported as
  completed.

### Redacted export

Export writes redacted JSON Lines from the stored rows, not from memory. It is
built in a sibling temporary file, flushed, given `0600` permissions, and renamed
into place. Redacted header values and withheld bodies are marked explicitly.
Export does not include CA material or any value that was not already in the
database.

### Remaining storage risks

- Stored metadata (hostnames, paths, session names, non-sensitive headers) can
  still be sensitive. Protect the data directory and delete sessions you no
  longer need.
- Enabling body or sensitive-header persistence stores credentials in plain
  form in SQLite. This is an explicit operator decision and is warned about in
  the UI; full-disk encryption is strongly recommended.
- A local attacker who can read the operator's files can read the database if
  file permissions are bypassed (root, backups, sync clients).
- The database ceiling is a safety limit, not a retention policy; old sessions
  are not pruned automatically.

## 3. Explicit limitations and gaps

| Gap | Consequence | Planned handling |
|---|---|---|
| HTTP/3, WebSocket, and pinned clients cannot be inspected | Some traffic stays opaque; plaintext h2c is unsupported | Keep opaque CONNECT available; further protocol coverage is future work |
| Opaque CONNECT can reach any authorized TCP service | Scope authorizes host/port, not application-layer safety | Use narrow scope and private-upstream defaults; do not authorize broad wildcards casually |
| No proxy authentication | A remote listener is usable by anyone who can reach it | Keep loopback; firewall remote binds; authentication is future work |
| No per-client rate limit | One authorized client can use the global connection/body budget | Global semaphores and body caps; add quotas later if needed |
| Connection-limit overflow closes the socket | Client sees a transport error, not an HTTP `503` | Documented behavior; revisit with later protocol work |
| No HTTP/3 or WebSocket forwarding, no h2c | Plaintext HTTP stays HTTP/1.1 and `Upgrade` is stripped; HTTP/2 requires TLS | Future protocol work |
| HTTP/2 server push, priority, and extended CONNECT are not exposed | Applications relying on those features see standard request/response behavior only | Deliberate scope: request/response framing and multiplexing only |
| Persisted metadata can be sensitive | Hostnames, paths, and non-sensitive headers remain on disk | Protect/delete the database; body and credential storage stay opt-in |
| Stored bodies/credentials are plaintext when opted in | A local reader or backup can expose them | Owner-only permissions, warning, full-disk encryption; off by default |
| No automatic retention limit | Long-running sessions grow until the 512 MiB ceiling | Manual session management/export; retention policy is future work |
| Intercepted sessions are bound to one authority | Modified requests cannot switch to a different host/port inside an intercepted TLS session | Reject the modification and start a new connection instead |
| DNS policy is conservative | Some special-purpose/lab ranges are refused | Explicit, reviewed policy extension rather than bypass |
| No automated dependency audit | Supply-chain drift is possible | Add `cargo audit`/`cargo deny` in CI |
| Local logs are not rotated | Log growth over long runs | Add bounded retention with logging settings |
| Redaction toggle does not rewrite existing Repeater buffers | A tab seeded while redaction was off retains visible secrets until reopened | Deliberate: editing must not silently mutate documents; warning shown |
| Repeater is direct-only and negotiates automatically | HTTP/2 is used when ALPN selects it (no manual override), but WebSocket, client certificates, proxy-auth, and proxy-routed execution are unavailable | Keep the limitations visible; remaining protocol/client-auth support is future work |
| Repeater cannot reuse a captured connection | Results can differ from the original capture (different TLS session, client certificate, source address, or proxy path) | Treat Repeater as a fresh request, not an exact replay; document provenance |
| Intruder has no response-matching or fuzzing engine | Results must be reviewed by the operator; automated vulnerability tagging is not provided | Deliberate: RAWFRAME reports observations, not findings |
| Intruder rate and concurrency are local pacing | They neither guarantee target load limits nor hide the request pattern | Use conservative defaults and explicit authorization |
| Intruder payload lists are session-only | Closing the application loses named lists unless exported to a wordlist | Documented behavior; no hidden persistence |
| Intruder payload values are persisted and exported unredacted | A payload can itself be a credential, so stored/exported Intruder rows may contain secrets | Treated as execution metadata; delete or protect the database and exports, and prefer harmless wordlists |
| Intruder has no raw-socket payloads | WebSocket and raw-socket payloads are unavailable, though HTTP/2 is inherited from Repeater | Same boundary as Repeater |
| Clipboard copy uses OSC 52 only | Terminals that disable clipboard writes may ignore `Copy`; no shell helper is invoked | Treat copy as best effort; UI reports that the request was sent |

TLS interception (HTTP/1.1 and HTTP/2), CA generation, live pause/edit/drop,
SQLite persistence,
redaction-on-write, export, crash recovery, live scope updates, Repeater,
bounded in-process Decoder transformations, and bounded Intruder execution are
covered by local tests and a real-binary PTY regression. Repeater tests use real local HTTP/HTTPS origins and
verify scope,
address policy, certificate validation, redirect credential stripping, limits,
timeouts, and cancellation. Storage tests' assertions check the actual database
rows, not an in-memory mock.

## 4. Certificate authority design (implemented)

The CA is the most sensitive component of an interception proxy. These
constraints are non-negotiable:

1. Generation happens only when interception is explicitly enabled or a CA
   management command is run; it never happens on first launch or while
   interception is off.
2. The root private key is stored only on the local machine, in a dedicated
   directory, with owner-only permissions (`0600` key, `0700` directory). It is
   never serialized into traffic, logs, exports, or the repository.
3. The CA certificate is published with a clear fingerprint and explicit trust
   instructions. RAWFRAME must never install itself into a system trust store
   automatically.
4. Leaf certificates are minted per hostname on demand, cached with bounded
   lifetime, and never issued for hosts outside the configured scope.
5. Client-facing TLS termination is separate from the upstream TLS connection.
   Upstream verification uses the system/root trust store (or an explicit local
   trust bundle) and stays enabled. There is no insecure path or protocol
   downgrade.
6. CA lifecycle notices expose only the public certificate path/fingerprint;
   private key bytes are never logged, published in events, or exported.
7. Tests use a self-contained test CA and local TLS servers. No public
   certificate transparency or third-party service is contacted.
8. CA certificate/key mismatches are rejected; incomplete material is never
   automatically replaced. Regeneration is explicit and invalidates prior trust.
9. Intercepted client TLS advertises only HTTP/1.1, and SNI must match the
   authorized CONNECT authority.

## 5. Operational guidance

- Work from a dedicated testing profile or virtual machine when possible.
- Keep the CA private key off shared or backed-up locations.
- Remove trust in the RAWFRAME CA when an engagement ends (or run
  `--tls-ca-regenerate` and re-trust only if needed).
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
