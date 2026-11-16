use rawframe_core::models::Scheme;
use rawframe_http::{parse_request, parse_response};

#[test]
fn request_round_trip_preserves_order_duplicates_and_body() {
    let raw = "PATCH /v2/items?id=9 HTTP/1.1\r\n\
               Host: shop.rawframe.test\r\n\
               X-Scope: alpha\r\n\
               X-Scope: beta\r\n\
               Content-Length: 14\r\n\
               \r\n\
               name=lamp%2F01";

    let request = parse_request(raw, Scheme::Https).unwrap();
    let reparsed = parse_request(&request.to_http_string(false), Scheme::Https).unwrap();

    assert_eq!(request, reparsed);
    assert_eq!(reparsed.headers.get_all("x-scope").count(), 2);
    assert_eq!(reparsed.body.len(), 14);
}

#[test]
fn response_display_is_terminal_safe_for_a_hostile_header() {
    let raw = "HTTP/1.1 200 OK\r\nX-Note: placeholder\r\n\r\nsafe";
    let mut response = parse_response(raw).unwrap();
    // Captured values can contain control sequences; the model accepts them so
    // they can be reported, and display rendering must neutralize them.
    response.headers.insert("X-Note", "\u{1b}[2Jwipe");
    let display = response.to_display_text(false);

    assert!(!display.contains('\u{1b}'));
    assert!(display.contains("X-Note: ^[[2Jwipe"));
}

#[test]
fn parser_rejects_control_characters_in_header_values() {
    let raw = "HTTP/1.1 200 OK\r\nX-Note: \u{1b}[2Jwipe\r\n\r\nsafe";
    assert!(parse_response(raw).is_err());
}
