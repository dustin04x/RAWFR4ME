# Passive analysis rule inventory

**Release status (v1.0.0):** this engine ships as the `rawframe-analysis` library.
It is built and tested by the workspace but is **not** wired into the TUI or CLI,
so no captures are analyzed at runtime and there is no Security Findings
workspace. Findings are not persisted: the SQLite schema has no `findings`
table. Treat this document as the rule contract for the library and as the
specification the future Findings workspace must implement.

Rules evaluate immutable captured HTTP/1.1, HTTP/2 shared-message, and WebSocket snapshots. They perform no network, DNS, URL, Repeater, or Intruder operation. IDs are stable; current ruleset version is `2`. Evidence stores references, field labels, fixed diagnostic markers, or category labels. Captured credential values and complete response/message bodies are never copied into findings.

| Rule ID | Detection / applicability | Severity / confidence | Evidence | Known false positives | Actual coverage |
|---|---|---|---|---|---|
| `http.missing_hsts` | HTTPS response lacks a non-empty HSTS field | Low / High | response field absence + traffic ID | HSTS may be configured elsewhere or already cached | `detects_contextual_https_and_html_headers_without_secrets`; header applicability boundaries |
| `http.missing_nosniff` | HTML response lacks `X-Content-Type-Options: nosniff` | Informational / High | response field absence/value | Browser and MIME context determine impact | `each_http_header_rule_has_independent_applicability_and_empty_boundary_coverage`; configured/non-HTML regression |
| `http.missing_referrer_policy` | HTML response lacks non-empty `Referrer-Policy` | Informational / High | response field absence | Browser defaults vary | same header applicability and configured-header tests |
| `http.missing_csp` | HTML response lacks non-empty CSP | Informational / High | response field absence | Absence does not establish XSS | `header_rules_cover_csp_framing_permissions_duplicates_and_non_html_context` |
| `http.missing_frame_protection` | HTML response has neither recognized `frame-ancestors` nor `DENY`/`SAMEORIGIN` XFO | Informational / High | both relevant response fields | Does not establish exploitable clickjacking; unsupported/invalid directives are treated as absent | framing positive, CSP/XFO negative, non-HTML regression in header test |
| `http.missing_permissions_policy` | HTML response lacks non-empty Permissions-Policy | Informational / High | response field absence | Most pages do not use restricted browser features | positive/configured/non-HTML and empty-field cases in header test |
| `http.cookie_missing_secure` | Parseable Set-Cookie lacks Secure | Low / High | cookie name and absent attribute; never value | Cookie may be intentionally non-sensitive | multiple Set-Cookie, attribute ordering, comma/quote handling, prefixes, redacted cookie tests |
| `http.cookie_missing_httponly` | Parseable Set-Cookie lacks HttpOnly | Low / High | cookie name and absent attribute | JavaScript access can be intentional | multiple fields, configured attributes, quoted/malformed cookie tests |
| `http.cookie_missing_samesite` | Parseable Set-Cookie lacks explicit SameSite | Informational / High | cookie name and absent attribute | Browser defaults and cross-site behavior vary | missing/present/order and multiple field tests |
| `http.plaintext_credentials` | Plain HTTP request contains Authorization, non-empty credential-named form/query field, or session-like cookie name | Medium / High | field/category label; values withheld | Parameter names can be misleading; only contextual names are accepted | `plaintext_credential_rule_is_contextual_and_redacts_basic_form_url_and_cookie_values`; omitted-body negative |
| `http.technology_banner` | Server/X-Powered-By response value contains a digit | Informational / High | header name + fixed “version-bearing” marker | Digits may not be a semantic version; identification is not a vulnerability | `disclosure_rules_require_version_debug_or_diagnostic_context` |
| `http.debug_header` | Known debug/runtime header is present | Low / High | allowlisted header name; value not stored | Runtime version headers can be expected | debug positive and synthetic value secrecy assertions in disclosure test |
| `http.response_error_disclosure` | Text-like body contains narrow stack trace, filesystem path, or detailed error marker | Low / Low | fixed marker only | Heuristic markers can occur in documentation | positive diagnostic body and ordinary text regression in disclosure test |
| `http.private_address_disclosure` | RFC1918 IPv4 appears in a diagnostic/error context in text-like body | Informational / Medium | fixed redacted-address marker | A diagnostic can intentionally describe a private IP | positive stacktrace + redaction assertion; ordinary prose regression |
| `websocket.plaintext_transport` | Captured handshake metadata identifies non-TLS `ws://` | Medium / Confirmed | handshake traffic ID and transport | Local labs may intentionally use plaintext | `websocket_rules_are_conservative_and_never_copy_payloads`; scheduler handshake-only test |
| `websocket.error_disclosure` | Complete UTF-8 text message contains narrow stack/debug marker | Low / Low | message ID + fixed marker | Marker can appear in ordinary prose | WebSocket rule test; binary/incomplete/omitted/truncated negative test |
| `websocket.sensitive_message` | Complete UTF-8 text message contains a non-empty contextually sensitive key/value, including JSON | Medium / Medium | message ID + sensitive field category; value withheld | Field naming is heuristic and does not prove credential validity | `websocket_sensitive_json_fields_are_redacted_and_deduplicated`; binary/truncation tests |

## Test inventory scope

The tests listed above are actual unit tests in `crates/rawframe-analysis`. Cross-cutting tests cover HTTP/2 shared representation, repeated-evidence stability, sensitive value exclusion from JSON/Markdown, and scheduler backpressure/cancellation/limits. No test covers findings persistence, findings lifecycle transitions against a database, or a Findings UI, because those paths do not exist in v1.0.0. Tests do not claim full RFC cookie grammar support, request-smuggling detection, WebSocket origin-policy assessment, binary payload interpretation, certificate validation, or exploitability. Missing/redacted/truncated payloads are not reconstructed.
