//! Synthetic traffic fixtures for interface evaluation.
//!
//! Every entry is marked [`TrafficSource::Simulated`]. These transactions are
//! authored locally, never sent over a network, and are rendered with a visible
//! SIM badge and a global simulation banner. Hosts use the reserved `.test`
//! domain so no fixture can be mistaken for a real target.

use chrono::{DateTime, Duration, Utc};

use crate::models::message::{HttpRequest, HttpResponse, Scheme};
use crate::models::traffic::{
    TrafficEntry, TrafficId, TrafficSource, TrafficState, TrafficTimings,
};

/// Builds the deterministic set of simulated transactions shown in the demo
/// shell. Timestamps are relative to `Utc::now()` so the UI reads naturally.
pub fn simulated_traffic() -> Vec<TrafficEntry> {
    let now = Utc::now();

    let mut entries = vec![
        completed(
            now,
            1,
            180_000,
            143,
            request("GET", Scheme::Https, "api.rawframe.test", "/v1/users?page=2"),
            json(
                200,
                r#"{
  "data": [
    { "id": "usr_1042", "name": "Ada Lovelace", "role": "analyst" },
    { "id": "usr_1051", "name": "Grace Hopper", "role": "engineer" }
  ],
  "page": 2,
  "per_page": 2
}"#,
            ),
        ),
        completed(
            now,
            2,
            151_000,
            61,
            request(
                "GET",
                Scheme::Https,
                "api.rawframe.test",
                "/v1/orders/8842",
            ),
            json(
                404,
                r#"{
  "error": "order_not_found",
  "message": "No order exists with id 8842."
}"#,
            ),
        ),
        completed(
            now,
            3,
            130_000,
            89,
            {
                let mut request = request(
                    "POST",
                    Scheme::Https,
                    "auth.rawframe.test",
                    "/oauth/token",
                );
                request.headers.append("Content-Type", "application/x-www-form-urlencoded");
                request.body =
                    b"grant_type=client_credentials&client_id=fixture-client&client_secret=fixture-secret".to_vec();
                request
            },
            {
                let mut response = json(
                    401,
                    r#"{ "error": "invalid_client", "error_description": "Client authentication failed." }"#,
                );
                response.headers.append("WWW-Authenticate", "Basic realm=\"fixture\"");
                response
            },
        ),
        completed(
            now,
            4,
            110_000,
            238,
            request(
                "GET",
                Scheme::Https,
                "shop.rawframe.test",
                "/products/lumen-desk-lamp",
            ),
            HttpResponse::with_body(
                200,
                "text/html; charset=utf-8",
                "<!doctype html><html><head><title>Lumen desk lamp</title></head>\
                 <body><main><h1>Lumen desk lamp</h1><p class=\"price\">$129.00</p>\
                 <p>Warm, dimmable light for long review sessions.</p></main></body></html>"
                    .as_bytes()
                    .to_vec(),
            ),
        ),
        completed(
            now,
            5,
            92_000,
            167,
            {
                let mut request = request(
                    "POST",
                    Scheme::Https,
                    "shop.rawframe.test",
                    "/checkout",
                );
                request.headers.append("Content-Type", "application/json");
                request.body = br#"{"cart_id":"cart_fixture_01","payment_method":"card_fixture"}"#.to_vec();
                request
            },
            {
                let mut response = HttpResponse::with_body(302, "text/plain", "");
                response.headers.append("Location", "/orders/confirm?ref=fixture");
                response
            },
        ),
        completed(
            now,
            6,
            75_000,
            176,
            {
                let mut request = request(
                    "PUT",
                    Scheme::Https,
                    "api.rawframe.test",
                    "/v1/profile",
                );
                request.headers.append("Authorization", "Bearer fixture-access-token");
                request.headers.append("Cookie", "session=fixture-session; theme=dark");
                request.headers.append("Content-Type", "application/json");
                request.body = br#"{"display_name":"Ada L.","timezone":"UTC"}"#.to_vec();
                request
            },
            {
                let mut response = json(
                    200,
                    r#"{ "display_name": "Ada L.", "timezone": "UTC", "updated": true }"#,
                );
                response
                    .headers
                    .append("Set-Cookie", "session=fixture-session; HttpOnly; Secure; SameSite=Lax");
                response
            },
        ),
        completed(
            now,
            7,
            60_000,
            44,
            request(
                "DELETE",
                Scheme::Http,
                "legacy.rawframe.test",
                "/admin/debug",
            ),
            HttpResponse::with_body(
                403,
                "text/html; charset=utf-8",
                "<html><body><h1>Forbidden</h1><p>Administrative endpoint is not exposed.</p></body></html>"
                    .as_bytes()
                    .to_vec(),
            ),
        ),
        completed(
            now,
            8,
            48_000,
            1_204,
            request(
                "GET",
                Scheme::Https,
                "api.rawframe.test",
                "/v1/reports/2026-q3",
            ),
            json(
                500,
                r#"{
  "error": "report_generation_failed",
  "trace_id": "fixture-7f3c",
  "message": "Report worker timed out while aggregating events."
}"#,
            ),
        ),
        completed(
            now,
            9,
            35_000,
            23,
            request(
                "GET",
                Scheme::Https,
                "cdn.rawframe.test",
                "/assets/app.9f2c.js",
            ),
            {
                let mut response = HttpResponse::new(304);
                response.headers.append("ETag", "\"fixture-etag-9f2c\"");
                response.headers.append("Cache-Control", "public, max-age=31536000, immutable");
                response
            },
        ),
        completed(
            now,
            10,
            28_000,
            18,
            request("OPTIONS", Scheme::Https, "api.rawframe.test", "/v1/users"),
            {
                let mut response = HttpResponse::new(204);
                response.headers.append("Allow", "GET, POST, OPTIONS");
                response
            },
        ),
        completed(
            now,
            11,
            22_000,
            35,
            request(
                "GET",
                Scheme::Https,
                "probe.rawframe.test",
                "/diagnostics",
            ),
            HttpResponse::with_body(
                200,
                "text/plain; charset=utf-8",
                "diagnostics: ok\n\u{1b}[31mterminal-safe fixture: this escape is inert\u{1b}[0m\nbidi: \u{202e}reversed\n".as_bytes().to_vec(),
            ),
        ),
        failed(
            now,
            12,
            17_000,
            4_210,
            request(
                "GET",
                Scheme::Https,
                "expired.rawframe.test",
                "/old-endpoint",
            ),
            "upstream TLS certificate has expired",
        ),
        dropped(
            now,
            13,
            14_000,
            request(
                "GET",
                Scheme::Https,
                "internal.rawframe.test",
                "/healthz",
            ),
        ),
        pending(
            now,
            14,
            12_000,
            TrafficState::Paused,
            {
                let mut request = request(
                    "POST",
                    Scheme::Https,
                    "api.rawframe.test",
                    "/v1/orders",
                );
                request.headers.append("Authorization", "Bearer fixture-operator-token");
                request.headers.append("Content-Type", "application/json");
                request.headers.append("X-Request-Id", "fixture-4c1d9e");
                request.body = br#"{"sku":"LAMP-01","quantity":1,"note":"fixture order"}"#.to_vec();
                request
            },
        ),
        pending(
            now,
            15,
            8_000,
            TrafficState::Paused,
            {
                let mut request = request(
                    "DELETE",
                    Scheme::Https,
                    "api.rawframe.test",
                    "/v1/sessions/current",
                );
                request.headers.append("Authorization", "Bearer fixture-user-token");
                request.headers.append("Cookie", "session=fixture-session");
                request
            },
        ),
        pending(
            now,
            16,
            3_000,
            TrafficState::Captured,
            request(
                "GET",
                Scheme::Https,
                "api.rawframe.test",
                "/v1/inventory?warehouse=ams-1",
            ),
        ),
        pending(
            now,
            17,
            900,
            TrafficState::Forwarded,
            request(
                "GET",
                Scheme::Https,
                "api.rawframe.test",
                "/v1/notifications?unread=true",
            ),
        ),
    ];

    entries.sort_by_key(|entry: &TrafficEntry| entry.id);
    entries
}

fn request(method: &str, scheme: Scheme, host: &str, target: &str) -> HttpRequest {
    let mut request = HttpRequest::new(method, scheme, host, scheme.default_port(), target);
    request
        .headers
        .append("User-Agent", "rawframe-sim/0.1 (fixture)");
    request.headers.append("Accept", "*/*");
    request
}

fn json(status: u16, body: &str) -> HttpResponse {
    let mut response = HttpResponse::with_body(
        status,
        "application/json; charset=utf-8",
        body.as_bytes().to_vec(),
    );
    response.headers.append("Server", "sim-origin/1.0");
    response
}

fn completed(
    now: DateTime<Utc>,
    id: u64,
    offset_ms: i64,
    duration_ms: u64,
    request: HttpRequest,
    mut response: HttpResponse,
) -> TrafficEntry {
    if response.headers.get("Server").is_none() {
        response.headers.append("Server", "sim-origin/1.0");
    }
    let started_at = now - Duration::milliseconds(offset_ms);
    TrafficEntry {
        id: TrafficId(id),
        request,
        response: Some(response),
        state: TrafficState::Completed,
        source: TrafficSource::Simulated,
        timings: TrafficTimings {
            started_at,
            completed_at: Some(started_at + Duration::milliseconds(duration_ms as i64)),
            duration_ms: Some(duration_ms),
        },
        error: None,
        note: None,
        kind: crate::models::traffic::TrafficKind::Http,
        tunnel: None,
        original_request: None,
        final_request: None,
        interception: crate::models::traffic::InterceptionMetadata::default(),
        body_omitted: false,
        redacted_headers: 0,
        repeater_origin: None,
    }
}

fn failed(
    now: DateTime<Utc>,
    id: u64,
    offset_ms: i64,
    duration_ms: u64,
    request: HttpRequest,
    error: &str,
) -> TrafficEntry {
    let started_at = now - Duration::milliseconds(offset_ms);
    TrafficEntry {
        id: TrafficId(id),
        request,
        response: None,
        state: TrafficState::Failed,
        source: TrafficSource::Simulated,
        timings: TrafficTimings {
            started_at,
            completed_at: Some(started_at + Duration::milliseconds(duration_ms as i64)),
            duration_ms: Some(duration_ms),
        },
        error: Some(error.to_string()),
        note: None,
        kind: crate::models::traffic::TrafficKind::Http,
        tunnel: None,
        original_request: None,
        final_request: None,
        interception: crate::models::traffic::InterceptionMetadata::default(),
        body_omitted: false,
        redacted_headers: 0,
        repeater_origin: None,
    }
}

fn dropped(now: DateTime<Utc>, id: u64, offset_ms: i64, request: HttpRequest) -> TrafficEntry {
    let mut entry = TrafficEntry::simulated(
        TrafficId(id),
        request,
        now - Duration::milliseconds(offset_ms),
    );
    entry.state = TrafficState::Dropped;
    entry.timings.completed_at = Some(now - Duration::milliseconds(offset_ms / 2));
    entry.note = Some("Dropped by operator before forwarding".into());
    entry
}

fn pending(
    now: DateTime<Utc>,
    id: u64,
    offset_ms: i64,
    state: TrafficState,
    request: HttpRequest,
) -> TrafficEntry {
    let mut entry = TrafficEntry::simulated(
        TrafficId(id),
        request,
        now - Duration::milliseconds(offset_ms),
    );
    entry.state = state;
    entry
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::message::StatusClass;

    #[test]
    fn every_fixture_is_simulated_and_uses_reserved_hosts() {
        let entries = simulated_traffic();
        assert_eq!(entries.len(), 17);
        for entry in &entries {
            assert_eq!(entry.source, TrafficSource::Simulated);
            assert!(entry.source.is_simulated());
            assert!(
                entry.request.host.ends_with(".test"),
                "fixture host is not reserved: {}",
                entry.request.host
            );
        }
    }

    #[test]
    fn fixtures_cover_pending_and_terminal_states() {
        let entries = simulated_traffic();
        let paused = entries.iter().filter(|entry| entry.is_paused()).count();
        let captured = entries
            .iter()
            .filter(|entry| entry.state == TrafficState::Captured)
            .count();
        let forwarded = entries
            .iter()
            .filter(|entry| entry.state == TrafficState::Forwarded)
            .count();
        let completed = entries
            .iter()
            .filter(|entry| entry.state == TrafficState::Completed)
            .count();
        let failed = entries
            .iter()
            .filter(|entry| entry.state == TrafficState::Failed)
            .count();
        let dropped = entries
            .iter()
            .filter(|entry| entry.state == TrafficState::Dropped)
            .count();

        assert_eq!((paused, captured, forwarded), (2, 1, 1));
        assert_eq!(completed, 11);
        assert_eq!((failed, dropped), (1, 1));
        assert_eq!(
            entries
                .iter()
                .filter(|entry| entry.state.is_pending())
                .count(),
            4
        );
    }

    #[test]
    fn fixtures_include_multiple_response_classes_and_security_headers() {
        let entries = simulated_traffic();
        let classes: Vec<_> = entries
            .iter()
            .filter_map(|entry| entry.response.as_ref().map(HttpResponse::status_class))
            .collect();

        assert!(classes.contains(&StatusClass::Success));
        assert!(classes.contains(&StatusClass::Redirection));
        assert!(classes.contains(&StatusClass::ClientError));
        assert!(classes.contains(&StatusClass::ServerError));

        assert!(
            entries
                .iter()
                .any(|entry| entry.request.headers.contains("Authorization"))
        );
        assert!(entries.iter().any(|entry| {
            entry
                .response
                .as_ref()
                .is_some_and(|response| response.headers.contains("Set-Cookie"))
        }));
    }

    #[test]
    fn control_sequence_fixture_is_rendered_safely() {
        let entry = simulated_traffic()
            .into_iter()
            .find(|entry| entry.id == TrafficId(11))
            .unwrap();
        let response = entry.response.unwrap();
        let display = response.to_display_text(false);

        assert!(!display.contains('\u{1b}'));
        assert!(!display.contains('\u{202e}'));
        assert!(display.contains("terminal-safe fixture"));
    }

    #[test]
    fn timestamps_are_ordered_and_completed_entries_have_durations() {
        let entries = simulated_traffic();
        let mut previous = None;
        for entry in &entries {
            if let Some(previous) = previous {
                assert!(entry.timings.started_at >= previous);
            }
            previous = Some(entry.timings.started_at);

            if entry.state == TrafficState::Completed {
                assert!(entry.timings.completed_at.is_some());
                assert!(entry.duration_ms().is_some());
            }
        }
    }
}
