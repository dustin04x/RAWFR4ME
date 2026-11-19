use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use rawframe_core::models::websocket::{
    WebSocketDirection, WebSocketFrameDecision, WebSocketInterceptionOutcome, WebSocketOpcode,
};
use rawframe_core::models::{Scope, ScopeRule};
use rawframe_core::{AppConfig, AppEvent, EventBus, EventReceiver};
use rawframe_proxy::{ProxyHandle, start_proxy};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{Instant, timeout};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::Role;
use tokio_tungstenite::{WebSocketStream, accept_async};

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    listener.local_addr().unwrap().port()
}

fn proxy_config(port: u16) -> AppConfig {
    let mut config = AppConfig::default();
    config.proxy.port = port;
    config.proxy.bind_address = "127.0.0.1".parse().unwrap();
    config.proxy.allow_private_upstreams = true;
    config.proxy.scope = Scope::allow(ScopeRule::host("127.0.0.1"));
    config.proxy.connect_timeout_secs = 2;
    config.proxy.upstream_timeout_secs = 2;
    config.proxy.idle_timeout_secs = 5;
    config.proxy.websocket_idle_timeout_secs = 10;
    config
}

async fn spawn_echo() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut ws = accept_async(stream).await.unwrap();
                while let Some(Ok(message)) = ws.next().await {
                    if message.is_text() || message.is_binary() {
                        let _ = ws.send(message).await;
                    } else if message.is_close() {
                        let _ = ws.close(None).await;
                        break;
                    }
                }
            });
        }
    });
    port
}

async fn start(port: u16, config: AppConfig) -> (ProxyHandle, EventReceiver) {
    let mut bus = EventBus::new();
    let receiver = bus.subscribe();
    let handle = start_proxy(config, bus.sender(), Arc::new(AtomicU64::new(1000)))
        .await
        .unwrap();
    assert_eq!(port, handle.local_addr().port());
    (handle, receiver)
}

/// Performs an HTTP/1.1 upgrade through the proxy and returns the raw stream
/// positioned immediately after the 101 response head.
async fn upgrade(proxy_port: u16, upstream_port: u16) -> TcpStream {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    let request = format!(
        "GET http://127.0.0.1:{upstream_port}/chat HTTP/1.1\r\n\
         Host: 127.0.0.1:{upstream_port}\r\n\
         Upgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let read = timeout(Duration::from_secs(3), stream.read(&mut byte))
            .await
            .expect("proxy did not answer the handshake")
            .unwrap();
        assert!(read > 0, "proxy closed during the handshake");
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let text = String::from_utf8_lossy(&head);
    assert!(text.starts_with("HTTP/1.1 101"), "unexpected: {text}");
    stream
}

fn masked_frame(fin: bool, opcode: u8, payload: &[u8]) -> Vec<u8> {
    let key = [0x37u8, 0xfa, 0x21, 0x3d];
    let mut frame = Vec::with_capacity(8 + payload.len());
    frame.push(if fin { 0x80 | opcode } else { opcode });
    if payload.len() <= 125 {
        frame.push(0x80 | payload.len() as u8);
    } else {
        frame.push(0x80 | 126);
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    }
    frame.extend_from_slice(&key);
    for (index, byte) in payload.iter().enumerate() {
        frame.push(byte ^ key[index % 4]);
    }
    frame
}

async fn send_frame(stream: &mut TcpStream, fin: bool, opcode: u8, payload: &[u8]) {
    stream
        .write_all(&masked_frame(fin, opcode, payload))
        .await
        .unwrap();
}

struct ReadFrame {
    opcode: u8,
    payload: Vec<u8>,
}

async fn read_frame(stream: &mut TcpStream) -> Option<ReadFrame> {
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await.ok()?;
    let opcode = header[0] & 0x0f;
    assert_eq!(header[1] & 0x80, 0, "server frames must not be masked");
    let len = match header[1] & 0x7f {
        126 => {
            let mut extended = [0u8; 2];
            stream.read_exact(&mut extended).await.ok()?;
            u16::from_be_bytes(extended) as usize
        }
        127 => {
            let mut extended = [0u8; 8];
            stream.read_exact(&mut extended).await.ok()?;
            u64::from_be_bytes(extended) as usize
        }
        other => other as usize,
    };
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await.ok()?;
    Some(ReadFrame { opcode, payload })
}

/// Waits for the next paused WebSocket frame and resolves it.
async fn pause_and_decide(
    events: &mut EventReceiver,
    handle: &ProxyHandle,
    decide: impl FnOnce(WebSocketFrameOpcodeView) -> WebSocketFrameDecision,
) -> rawframe_core::models::websocket::WebSocketFrame {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let event = timeout(remaining, events.recv())
            .await
            .expect("no paused frame arrived")
            .expect("event bus closed");
        if let AppEvent::WebSocketFramePaused(frame) = event {
            let decision = decide(WebSocketFrameOpcodeView {
                direction: frame.direction,
                opcode: frame.opcode,
                payload: frame.payload.clone(),
            });
            assert!(
                handle.resolve_websocket_frame(frame.id, decision).await,
                "frame was not pending"
            );
            return *frame;
        }
    }
}

struct WebSocketFrameOpcodeView {
    direction: WebSocketDirection,
    opcode: WebSocketOpcode,
    payload: Vec<u8>,
}

#[tokio::test]
async fn websocket_proxy_relays_text_and_binary() {
    let upstream_port = spawn_echo().await;
    let proxy_port = free_port();
    let (handle, _events) = start(proxy_port, proxy_config(proxy_port)).await;

    let stream = upgrade(handle.local_addr().port(), upstream_port).await;
    let mut ws: WebSocketStream<TcpStream> =
        WebSocketStream::from_raw_socket(stream, Role::Client, None).await;

    ws.send(Message::Text("hello".into())).await.unwrap();
    let echo = timeout(Duration::from_secs(2), ws.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(echo.into_text().unwrap(), "hello");

    let payload = bytes::Bytes::from_static(b"\x01\x02\x03");
    ws.send(Message::Binary(payload.clone())).await.unwrap();
    let echo = timeout(Duration::from_secs(2), ws.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(echo.into_data(), payload);

    let _ = ws.close(None).await;
    handle.shutdown().await;
}

#[tokio::test]
async fn fragmented_messages_are_relayed_and_reassembled() {
    let upstream_port = spawn_echo().await;
    let proxy_port = free_port();
    let (handle, mut events) = start(proxy_port, proxy_config(proxy_port)).await;

    let mut stream = upgrade(handle.local_addr().port(), upstream_port).await;
    send_frame(&mut stream, false, 0x1, b"Hel").await;
    send_frame(&mut stream, false, 0x0, b"lo, ").await;
    send_frame(&mut stream, true, 0x0, b"world").await;

    let echo = timeout(Duration::from_secs(3), read_frame(&mut stream))
        .await
        .expect("echo timed out")
        .expect("connection closed");
    assert_eq!(echo.opcode, 0x1);
    assert_eq!(echo.payload, b"Hello, world");

    // Three client frames were relayed, and one reassembled client message was
    // captured with all three frame ids.
    let mut relayed = 0;
    let mut message_payload = None;
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline && message_payload.is_none() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let Ok(Some(event)) = timeout(remaining, events.recv()).await else {
            break;
        };
        match event {
            AppEvent::WebSocketFrame(frame)
                if frame.direction == WebSocketDirection::ClientToServer =>
            {
                relayed += 1;
            }
            AppEvent::WebSocketMessage(message)
                if message.direction == WebSocketDirection::ClientToServer =>
            {
                assert_eq!(message.payload, b"Hello, world");
                assert_eq!(message.frame_ids.len(), 3);
                message_payload = Some(message);
            }
            _ => {}
        }
    }
    assert_eq!(relayed, 3);
    assert!(message_payload.is_some(), "no reassembled message captured");

    handle.shutdown().await;
}

#[tokio::test]
async fn frame_interception_modifies_and_drops_in_both_directions() {
    let upstream_port = spawn_echo().await;
    let proxy_port = free_port();
    let mut config = proxy_config(proxy_port);
    config.proxy.interception_enabled = true;
    let (handle, mut events) = start(proxy_port, config).await;

    let mut stream = upgrade(handle.local_addr().port(), upstream_port).await;

    // Client frame is modified before it reaches the upstream.
    send_frame(&mut stream, true, 0x1, b"hello").await;
    let paused = pause_and_decide(&mut events, &handle, |view| {
        assert_eq!(view.direction, WebSocketDirection::ClientToServer);
        assert_eq!(view.opcode, WebSocketOpcode::Text);
        assert_eq!(view.payload, b"hello");
        WebSocketFrameDecision::ForwardModified {
            payload: b"changed".to_vec(),
        }
    })
    .await;
    assert_eq!(paused.payload, b"hello");

    // The echoed frame is also paused because interception is bidirectional.
    let (echo_event, echo) = {
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut server_frame = None;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let event = timeout(remaining, events.recv())
                .await
                .expect("no server frame")
                .expect("bus closed");
            if let AppEvent::WebSocketFrame(frame) = &event
                && frame.direction == WebSocketDirection::ServerToClient
                && frame.interception == WebSocketInterceptionOutcome::Forwarded
            {
                server_frame = Some(*frame.clone());
            }
            if let AppEvent::WebSocketFramePaused(frame) = event
                && frame.direction == WebSocketDirection::ServerToClient
            {
                assert_eq!(frame.payload, b"changed");
                assert!(
                    handle
                        .resolve_websocket_frame(frame.id, WebSocketFrameDecision::Forward)
                        .await
                );
                break (server_frame, frame);
            }
        }
    };
    let _ = echo_event;
    let relayed = timeout(Duration::from_secs(3), read_frame(&mut stream))
        .await
        .expect("echo timed out")
        .expect("closed");
    assert_eq!(relayed.payload, b"changed");
    assert_eq!(echo.payload, b"changed");

    // A dropped client frame never reaches the upstream or the client.
    send_frame(&mut stream, true, 0x1, b"drop-me").await;
    pause_and_decide(&mut events, &handle, |_| WebSocketFrameDecision::Drop).await;
    send_frame(&mut stream, true, 0x1, b"after").await;
    pause_and_decide(&mut events, &handle, |_| WebSocketFrameDecision::Forward).await;
    // Resolve the echoed server frame.
    pause_and_decide(&mut events, &handle, |_| WebSocketFrameDecision::Forward).await;
    let after = timeout(Duration::from_secs(3), read_frame(&mut stream))
        .await
        .expect("echo timed out")
        .expect("closed");
    assert_eq!(after.payload, b"after");

    let _ = send_frame(&mut stream, true, 0x8, &[]).await;
    handle.shutdown().await;
}

#[tokio::test]
async fn binary_payloads_survive_byte_for_byte() {
    let upstream_port = spawn_echo().await;
    let proxy_port = free_port();
    let (handle, mut events) = start(proxy_port, proxy_config(proxy_port)).await;

    let mut stream = upgrade(handle.local_addr().port(), upstream_port).await;
    let payload: Vec<u8> = (0..=255u8).collect();
    send_frame(&mut stream, true, 0x2, &payload).await;
    let echo = timeout(Duration::from_secs(3), read_frame(&mut stream))
        .await
        .expect("echo timed out")
        .expect("closed");
    assert_eq!(echo.opcode, 0x2);
    assert_eq!(echo.payload, payload);

    let mut captured = false;
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline && !captured {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let Ok(Some(event)) = timeout(remaining, events.recv()).await else {
            break;
        };
        if let AppEvent::WebSocketFrame(frame) = event
            && frame.direction == WebSocketDirection::ClientToServer
            && frame.opcode == WebSocketOpcode::Binary
        {
            assert_eq!(frame.payload, payload);
            assert!(!frame.truncated);
            captured = true;
        }
    }
    assert!(captured, "binary frame was not captured");

    handle.shutdown().await;
}

#[tokio::test]
async fn oversized_frames_close_the_connection() {
    let upstream_port = spawn_echo().await;
    let proxy_port = free_port();
    let mut config = proxy_config(proxy_port);
    config.proxy.websocket_max_frame_bytes = 16;
    let (handle, _events) = start(proxy_port, config).await;

    let mut stream = upgrade(handle.local_addr().port(), upstream_port).await;
    send_frame(&mut stream, true, 0x1, &[b'a'; 32]).await;
    let close = timeout(Duration::from_secs(3), read_frame(&mut stream))
        .await
        .expect("no close frame")
        .expect("connection closed without a close frame");
    assert_eq!(close.opcode, 0x8);
    assert_eq!(&close.payload[..2], &1009u16.to_be_bytes());

    handle.shutdown().await;
}

#[tokio::test]
async fn connection_capture_reports_open_and_closed_state() {
    let upstream_port = spawn_echo().await;
    let proxy_port = free_port();
    let (handle, mut events) = start(proxy_port, proxy_config(proxy_port)).await;

    let mut stream = upgrade(handle.local_addr().port(), upstream_port).await;
    send_frame(&mut stream, true, 0x1, b"one").await;
    let _ = read_frame(&mut stream).await;
    send_frame(&mut stream, true, 0x8, &1000u16.to_be_bytes()).await;

    let mut open = false;
    let mut closed = false;
    let deadline = Instant::now() + Duration::from_secs(4);
    while Instant::now() < deadline && !closed {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let Ok(Some(event)) = timeout(remaining, events.recv()).await else {
            break;
        };
        if let AppEvent::WebSocketConnection(connection) = event {
            use rawframe_core::models::websocket::WebSocketConnectionState;
            match connection.state {
                WebSocketConnectionState::Open => open = true,
                WebSocketConnectionState::Closed | WebSocketConnectionState::Failed => {
                    closed = true;
                    assert!(connection.frames >= 1);
                    assert!(connection.bytes_client_to_server >= 3);
                }
                _ => {}
            }
        }
    }
    assert!(open, "open connection event missing");
    assert!(closed, "closed connection event missing");

    handle.shutdown().await;
}
