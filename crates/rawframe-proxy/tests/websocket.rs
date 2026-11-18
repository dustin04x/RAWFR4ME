use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use futures_util::{SinkExt, StreamExt};
use rawframe_core::EventBus;
use rawframe_core::models::{AppConfig, Scope, ScopeRule};
use rawframe_proxy::start_proxy;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::{Duration, timeout};
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
    config
}

#[tokio::test]
async fn websocket_proxy_relays_text_and_binary() {
    // Upstream WebSocket echo server.
    let upstream_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, _) = upstream_listener.accept().await.unwrap();
        let mut ws = accept_async(stream).await.unwrap();
        while let Some(Ok(msg)) = ws.next().await {
            if msg.is_text() || msg.is_binary() {
                let _ = ws.send(msg).await;
            } else if msg.is_close() {
                let _ = ws.close(None).await;
                break;
            }
        }
    });

    let proxy_port = free_port();
    let bus = EventBus::new();
    let handle = start_proxy(
        proxy_config(proxy_port),
        bus.sender(),
        Arc::new(AtomicU64::new(1000)),
    )
    .await
    .unwrap();
    let proxy_addr = handle.local_addr();

    // Manual HTTP/1.1 upgrade through the proxy.
    let mut stream = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
    let request = format!(
        "GET http://127.0.0.1:{}/chat HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        upstream_addr.port(),
        upstream_addr.port()
    );
    stream.write_all(request.as_bytes()).await.unwrap();

    // Read the 101 response.
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        let n = timeout(Duration::from_secs(2), stream.read(&mut tmp))
            .await
            .unwrap()
            .unwrap();
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let head = String::from_utf8_lossy(&buf);
    assert!(
        head.starts_with("HTTP/1.1 101"),
        "unexpected response: {}",
        head
    );

    // The bytes after the header block, if any, belong to WebSocket frames.
    let header_end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .unwrap();
    let leftover = buf[header_end..].to_vec();

    // Build a WebSocket stream over the (possibly partially consumed) TCP stream.
    // from_raw_socket cannot recover leftover bytes; in practice the 101 has none.
    assert!(
        leftover.is_empty(),
        "unexpected leftover bytes: {:?}",
        leftover
    );

    let mut ws: WebSocketStream<tokio::net::TcpStream> =
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
