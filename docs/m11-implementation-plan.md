# M11 implementation record

## Architecture

`rawframe-analysis` depends on `rawframe-core` and contains deterministic rules, finding/evidence models, deduplication, report serialization, and a bounded worker. It has no TUI, store, proxy, HTTP client, WebSocket client, DNS, or socket dependency. The TUI/application layer submits immutable snapshots and associates each result with its session. `rawframe-store` is the sole SQLite writer and provides additive schema v5 findings persistence, transactional upserts/status changes, project-scoped paging, project/session restore, and private atomic JSON/Markdown exports.

## Implemented

- Ruleset v2 with 17 rules listed in [analysis-rules.md](analysis-rules.md).
- HTTP/1.1 and HTTP/2 analysis through the shared message model; WebSocket handshake and complete text-message analysis.
- Redacted evidence and stable fingerprints; repeated observations merge while analyst lifecycle is preserved.
- Bounded scheduler, snapshot limits, queue backpressure, generation cancellation, and project traffic pages of 32 records.
- Project analysis keeps session IDs on each result and excludes other project IDs at the store query boundary.
- Findings restore/export is bounded to 10,000 rows; report writes use same-directory atomic replacement and private permissions.
- TUI Security Findings workspace with search, severity/status filters, sorting, inspector, lifecycle actions, related traffic, reanalysis, and report shortcuts.
- Schema v4-to-v5 migration and storage worker path tests.

## Limits and remaining scope

Analysis only sees stored/captured metadata allowed by the active persistence policy. Project findings restore/export caps at 10,000. TUI export writes to a generated path beside the database rather than offering an interactive destination picker. Current automated TUI tests cover responsive rendering and core filters; mouse-specific finding navigation and full end-to-end WebSocket disclosure are not independently exercised. The PTY demonstration covers local HTTP captures; it does not yet provide real WebSocket-message evidence. Rules are conservative observations, not exploit verification. See the inventory for known false positives and coverage.
