use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use rawframe_core::models::traffic::{TrafficKind, TrafficSource, TrafficState, TunnelOutcome};
use rawframe_core::models::{AppConfig, Scheme, Scope, ScopeRule};
use rawframe_core::{EventBus, ProxyState};
use rawframe_proxy::{ProxyHandle, start_proxy};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    listener.local_addr().unwrap().port()
}

fn proxy_config(port: u16, host_pattern: &str) -> AppConfig {
    let mut config = AppConfig::default();
    config.proxy.port = port;
    config.proxy.bind_address = "127.0.0.1".parse().unwrap();
    config.proxy.allow_private_upstreams = true;
    config.proxy.scope = Scope::allow(ScopeRule::host(host_pattern));
    config.proxy.connect_timeout_secs = 1;
    config.proxy.upstream_timeout_secs = 1;
    config.proxy.idle_timeout_secs = 2;
    config.proxy.max_body_bytes = 4096;
    config.proxy.max_response_bytes = 4096;
    config.proxy.max_connections = 8;
    config
}

async fn start_test_proxy(host_pattern: &str) -> (ProxyHandle, SocketAddr, EventBus) {
    let port = free_port();
    let bus = EventBus::new();
    let handle = start_proxy(
        proxy_config(port, host_pattern),
        bus.sender(),
        Arc::new(AtomicU64::new(1000)),
    )
    .await
    .unwrap();
    let addr = handle.local_addr();
    (handle, addr, bus)
}

async fn spawn_http_upstream() -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let service = service_fn(|request: Request<Incoming>| async move {
                    let method = request.method().clone();
                    let uri = request.uri().clone();
                    let duplicate_count = request.headers().get_all("x-dupe").iter().count();
                    let keep_alive = request.headers().contains_key("keep-alive");
                    let proxy_connection = request.headers().contains_key("proxy-connection");
                    let body = request.into_body().collect().await.unwrap().to_bytes();
                    let payload = format!(
                        "method={method} path={} dup={duplicate_count} body={} ka={keep_alive} pc={proxy_connection}",
                        uri.path(),
                        String::from_utf8_lossy(&body)
                    );
                    let mut response = Response::new(Full::new(Bytes::from(payload)));
                    response
                        .headers_mut()
                        .append("Set-Cookie", "first=1; Path=/".parse().unwrap());
                    response
                        .headers_mut()
                        .append("Set-Cookie", "second=2; Path=/".parse().unwrap());
                    response
                        .headers_mut()
                        .append("X-Upstream", "test-origin".parse().unwrap());
                    response
                        .headers_mut()
                        .append("Keep-Alive", "timeout=5".parse().unwrap());
                    response
                        .headers_mut()
                        .append("Proxy-Connection", "keep-alive".parse().unwrap());
                    Ok::<_, Infallible>(response)
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    (addr, task)
}

fn decode_body(response: &[u8]) -> String {
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
        .unwrap_or(0);
    let headers = String::from_utf8_lossy(&response[..split]).to_ascii_lowercase();
    let body = &response[split..];
    if !headers.contains("transfer-encoding: chunked") {
        return String::from_utf8_lossy(body).to_string();
    }
    let mut decoded = Vec::new();
    let mut rest = body;
    while let Some(line_end) = rest.windows(2).position(|window| window == b"\r\n") {
        let size_text = String::from_utf8_lossy(&rest[..line_end]);
        let Ok(size) = usize::from_str_radix(size_text.trim(), 16) else {
            break;
        };
        rest = &rest[line_end + 2..];
        if size == 0 {
            break;
        }
        if rest.len() < size {
            decoded.extend_from_slice(rest);
            break;
        }
        decoded.extend_from_slice(&rest[..size]);
        rest = &rest[(size + 2).min(rest.len())..];
    }
    String::from_utf8_lossy(&decoded).to_string()
}

async fn raw_request(proxy: SocketAddr, request: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream.write_all(request).await.unwrap();
    stream.shutdown().await.unwrap();
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await.unwrap();
    bytes
}

async fn drain_entries(
    bus: &mut EventBus,
    minimum: usize,
) -> Vec<rawframe_core::models::TrafficEntry> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let mut entries = Vec::new();
    loop {
        while let Some(event) = bus.poll() {
            match event {
                rawframe_core::AppEvent::TrafficCaptured(entry)
                | rawframe_core::AppEvent::TrafficUpdated(entry) => entries.push(*entry),
                rawframe_core::AppEvent::ProxyStateChanged(ProxyState::Failed) => {
                    panic!("proxy entered failed state")
                }
                _ => {}
            }
        }
        if entries
            .iter()
            .filter(|entry| entry.state.is_terminal())
            .count()
            >= minimum
        {
            return entries;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("timed out waiting for captured traffic: {entries:?}");
        }
        sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn forwards_get_post_and_duplicate_headers() {
    let (upstream, _upstream_task) = spawn_http_upstream().await;
    let (proxy, proxy_addr, mut bus) = start_test_proxy("127.0.0.1").await;

    let get = format!(
        "GET http://{upstream}/hello?x=1 HTTP/1.1\r\nHost: {upstream}\r\nConnection: close\r\nKeep-Alive: timeout=5\r\nProxy-Connection: keep-alive\r\n\r\n"
    );
    let response = raw_request(proxy_addr, get.as_bytes()).await;
    let text = String::from_utf8_lossy(&response);
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    assert!(
        text.contains("method=GET path=/hello dup=0 body=") && text.contains("ka=false pc=false"),
        "{text}"
    );
    assert!(
        !text.to_ascii_lowercase().contains("\r\nkeep-alive:"),
        "{text}"
    );
    assert!(
        !text.to_ascii_lowercase().contains("\r\nproxy-connection:"),
        "{text}"
    );
    assert_eq!(
        text.to_ascii_lowercase().matches("set-cookie:").count(),
        2,
        "{text}"
    );

    let post = format!(
        "POST http://{upstream}/submit HTTP/1.1\r\nHost: {upstream}\r\nX-Dupe: one\r\nX-Dupe: two\r\nContent-Length: 7\r\nConnection: close\r\n\r\npayload"
    );
    let response = raw_request(proxy_addr, post.as_bytes()).await;
    let text = String::from_utf8_lossy(&response);
    assert!(
        text.contains("method=POST path=/submit dup=2 body=payload"),
        "{text}"
    );
    assert_eq!(
        text.to_ascii_lowercase().matches("set-cookie:").count(),
        2,
        "{text}"
    );

    let entries = drain_entries(&mut bus, 2).await;
    let completed: Vec<_> = entries
        .iter()
        .filter(|entry| entry.state == TrafficState::Completed)
        .collect();
    assert!(completed.len() >= 2, "entries: {entries:#?}");
    let post_capture = completed
        .iter()
        .find(|entry| entry.request.method == "POST")
        .unwrap();
    assert_eq!(post_capture.source, TrafficSource::Intercepted);
    assert_eq!(post_capture.request.body, b"payload");
    assert!(
        post_capture
            .response
            .as_ref()
            .unwrap()
            .body
            .starts_with(b"method=POST")
    );
    assert!(
        post_capture
            .response
            .as_ref()
            .unwrap()
            .headers
            .get_all("set-cookie")
            .count()
            >= 2
    );

    proxy.shutdown().await;
}

#[tokio::test]
async fn streams_chunked_request_and_response_bodies() {
    let (upstream, _upstream_task) = spawn_http_upstream().await;
    let (proxy, proxy_addr, _bus) = start_test_proxy("127.0.0.1").await;

    let head = format!(
        "POST http://{upstream}/chunked HTTP/1.1\r\nHost: {upstream}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
    );
    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    stream.write_all(head.as_bytes()).await.unwrap();
    for chunk in ["hello", " world"] {
        stream
            .write_all(format!("{:x}\r\n{chunk}\r\n", chunk.len()).as_bytes())
            .await
            .unwrap();
        sleep(Duration::from_millis(30)).await;
    }
    stream.write_all(b"0\r\n\r\n").await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let text = String::from_utf8_lossy(&response);
    assert!(
        text.contains("body=hello world"),
        "streamed request body was not forwarded: {text}"
    );

    // A raw chunked response is relayed without buffering the whole body.
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let chunked_addr = listener.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buffer = [0_u8; 4096];
        let _ = socket.read(&mut buffer).await.unwrap();
        socket
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n",
            )
            .await
            .unwrap();
        socket.write_all(b"6\r\nfirst-\r\n").await.unwrap();
        sleep(Duration::from_millis(40)).await;
        socket.write_all(b"6\r\nsecond\r\n0\r\n\r\n").await.unwrap();
        socket.shutdown().await.unwrap();
    });

    let (proxy2, proxy_addr2, mut bus2) = start_test_proxy("127.0.0.1").await;
    let request = format!(
        "GET http://{chunked_addr}/stream HTTP/1.1\r\nHost: {chunked_addr}\r\nConnection: close\r\n\r\n"
    );
    let response = raw_request(proxy_addr2, request.as_bytes()).await;
    let body = decode_body(&response);
    assert_eq!(body, "first-second");
    upstream_task.await.unwrap();
    let entries = drain_entries(&mut bus2, 1).await;
    let completed = entries
        .iter()
        .find(|entry| entry.state == TrafficState::Completed)
        .unwrap();
    assert_eq!(
        completed.response.as_ref().unwrap().body,
        b"first-second".to_vec()
    );

    proxy.shutdown().await;
    proxy2.shutdown().await;
}

#[tokio::test]
async fn enforces_scope_and_request_limits_before_connecting() {
    let (upstream, _upstream_task) = spawn_http_upstream().await;
    let (proxy, proxy_addr, mut bus) = start_test_proxy("allowed.test").await;

    let denied = format!(
        "GET http://{upstream}/secret HTTP/1.1\r\nHost: {upstream}\r\nConnection: close\r\n\r\n"
    );
    let response = raw_request(proxy_addr, denied.as_bytes()).await;
    let text = String::from_utf8_lossy(&response);
    assert!(text.starts_with("HTTP/1.1 403"), "{text}");
    assert!(text.contains("outside the configured scope"), "{text}");

    let entries = drain_entries(&mut bus, 1).await;
    assert!(
        entries
            .iter()
            .any(|entry| entry.state == TrafficState::Failed)
    );
    proxy.shutdown().await;

    let port = free_port();
    let mut config = proxy_config(port, "127.0.0.1");
    config.proxy.max_body_bytes = 8;
    let bus = EventBus::new();
    let proxy = start_proxy(config, bus.sender(), Arc::new(AtomicU64::new(2000)))
        .await
        .unwrap();
    let proxy_addr = proxy.local_addr();
    let too_large = format!(
        "POST http://{upstream}/large HTTP/1.1\r\nHost: {upstream}\r\nContent-Length: 20\r\nConnection: close\r\n\r\n01234567890123456789"
    );
    let response = raw_request(proxy_addr, too_large.as_bytes()).await;
    let text = String::from_utf8_lossy(&response);
    assert!(text.starts_with("HTTP/1.1 413"), "{text}");
    assert!(text.contains("configured limit"), "{text}");
    proxy.shutdown().await;
}

#[tokio::test]
async fn rejects_oversized_responses_and_invalid_destinations() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let upstream = listener.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buffer = [0_u8; 4096];
        let _ = socket.read(&mut buffer).await.unwrap();
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n0123456789")
            .await
            .unwrap();
        socket.shutdown().await.unwrap();
    });

    let port = free_port();
    let mut config = proxy_config(port, "127.0.0.1");
    config.proxy.max_response_bytes = 16;
    let bus = EventBus::new();
    let proxy = start_proxy(config, bus.sender(), Arc::new(AtomicU64::new(3000)))
        .await
        .unwrap();
    let proxy_addr = proxy.local_addr();
    let request = format!(
        "GET http://{upstream}/big HTTP/1.1\r\nHost: {upstream}\r\nConnection: close\r\n\r\n"
    );
    let response = raw_request(proxy_addr, request.as_bytes()).await;
    let text = String::from_utf8_lossy(&response);
    assert!(text.starts_with("HTTP/1.1 502"), "{text}");
    assert!(text.contains("exceeds the configured limit"), "{text}");
    upstream_task.await.unwrap();
    proxy.shutdown().await;

    let (proxy, proxy_addr, _bus) = start_test_proxy("127.0.0.1").await;
    let missing_authority =
        b"GET /origin-form HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    let response = raw_request(proxy_addr, missing_authority).await;
    assert!(
        String::from_utf8_lossy(&response).starts_with("HTTP/1.1 400"),
        "{}",
        String::from_utf8_lossy(&response)
    );

    let mismatched =
        format!("GET http://{upstream}/ HTTP/1.1\r\nHost: evil.test\r\nConnection: close\r\n\r\n");
    let response = raw_request(proxy_addr, mismatched.as_bytes()).await;
    assert!(
        String::from_utf8_lossy(&response).starts_with("HTTP/1.1 400"),
        "{}",
        String::from_utf8_lossy(&response)
    );
    proxy.shutdown().await;
}

#[tokio::test]
async fn supports_ipv6_authorities() {
    let listener = match TcpListener::bind(("::1", 0)).await {
        Ok(listener) => listener,
        Err(_) => return,
    };
    let upstream = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buffer = [0_u8; 4096];
        let _ = socket.read(&mut buffer).await.unwrap();
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nv6")
            .await
            .unwrap();
        socket.shutdown().await.unwrap();
    });

    let port = free_port();
    let mut config = proxy_config(port, "::1");
    config.proxy.scope = Scope::allow(ScopeRule {
        host_pattern: "::1".into(),
        scheme: Some(Scheme::Http),
        port: Some(upstream.port()),
    });
    let bus = EventBus::new();
    let proxy = start_proxy(config, bus.sender(), Arc::new(AtomicU64::new(4000)))
        .await
        .unwrap();
    let proxy_addr = proxy.local_addr();
    let request = format!(
        "GET http://[::1]:{}/v6 HTTP/1.1\r\nHost: [::1]:{}\r\nConnection: close\r\n\r\n",
        upstream.port(),
        upstream.port()
    );
    let response = raw_request(proxy_addr, request.as_bytes()).await;
    assert!(
        String::from_utf8_lossy(&response).contains("v6"),
        "{}",
        String::from_utf8_lossy(&response)
    );
    task.await.unwrap();
    proxy.shutdown().await;
}

#[tokio::test]
async fn connect_tunnel_relays_bytes_and_preserves_half_close() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let upstream = listener.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut data = Vec::new();
        socket.read_to_end(&mut data).await.unwrap();
        socket.write_all(b"echo:").await.unwrap();
        socket.write_all(&data).await.unwrap();
        socket.shutdown().await.unwrap();
    });

    let (proxy, proxy_addr, mut bus) = start_test_proxy("127.0.0.1").await;
    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    let connect = format!(
        "CONNECT {upstream} HTTP/1.1\r\nHost: {upstream}\r\nProxy-Connection: keep-alive\r\n\r\n"
    );
    stream.write_all(connect.as_bytes()).await.unwrap();
    let mut headers = Vec::new();
    timeout(Duration::from_secs(2), async {
        loop {
            let mut byte = [0_u8; 1];
            stream.read_exact(&mut byte).await.unwrap();
            headers.push(byte[0]);
            if headers.ends_with(b"\r\n\r\n") {
                return;
            }
        }
    })
    .await
    .expect("CONNECT response timed out");
    let header_text = String::from_utf8_lossy(&headers);
    assert!(header_text.starts_with("HTTP/1.1 200"), "{header_text}");

    stream.write_all(b"hello").await.unwrap();
    stream.shutdown().await.unwrap();
    let mut tunneled = Vec::new();
    stream.read_to_end(&mut tunneled).await.unwrap();
    assert_eq!(tunneled, b"echo:hello");
    upstream_task.await.unwrap();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut tunnel_entry = None;
    while tunnel_entry.is_none() {
        while let Some(event) = bus.poll() {
            if let rawframe_core::AppEvent::TrafficCaptured(entry)
            | rawframe_core::AppEvent::TrafficUpdated(entry) = event
                && entry.is_tunnel()
                && entry.state == TrafficState::Completed
            {
                tunnel_entry = Some(*entry);
            }
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("tunnel metadata event was not emitted");
        }
        sleep(Duration::from_millis(10)).await;
    }
    let entry = tunnel_entry.unwrap();
    assert_eq!(entry.kind, TrafficKind::ConnectTunnel);
    let metadata = entry.tunnel.unwrap();
    assert_eq!(metadata.outcome, TunnelOutcome::Closed);
    assert_eq!(metadata.client_to_upstream_bytes, 5);
    assert_eq!(metadata.upstream_to_client_bytes, 10);
    proxy.shutdown().await;
}

#[tokio::test]
async fn connect_scope_rejection_and_upstream_failure_are_reported() {
    let (proxy, proxy_addr, mut bus) = start_test_proxy("allowed.test").await;
    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    stream
        .write_all(b"CONNECT 127.0.0.1:9 HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    assert!(
        String::from_utf8_lossy(&response).starts_with("HTTP/1.1 403"),
        "{}",
        String::from_utf8_lossy(&response)
    );
    let entries = drain_entries(&mut bus, 1).await;
    assert!(entries.iter().any(|entry| entry.is_tunnel()
        && entry.tunnel.as_ref().unwrap().outcome == TunnelOutcome::Failed));
    proxy.shutdown().await;

    let (proxy, proxy_addr, mut bus) = start_test_proxy("127.0.0.1").await;
    let dead = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let dead_addr = dead.local_addr().unwrap();
    drop(dead);
    let request = format!(
        "GET http://{dead_addr}/ HTTP/1.1\r\nHost: {dead_addr}\r\nConnection: close\r\n\r\n"
    );
    let response = raw_request(proxy_addr, request.as_bytes()).await;
    assert!(
        String::from_utf8_lossy(&response).starts_with("HTTP/1.1 502"),
        "{}",
        String::from_utf8_lossy(&response)
    );
    let entries = drain_entries(&mut bus, 1).await;
    assert!(
        entries
            .iter()
            .any(|entry| entry.state == TrafficState::Failed)
    );
    proxy.shutdown().await;
}

#[tokio::test]
async fn upstream_response_timeout_is_reported() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let upstream = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (_socket, _) = listener.accept().await.unwrap();
        sleep(Duration::from_secs(5)).await;
    });

    let (proxy, proxy_addr, mut bus) = start_test_proxy("127.0.0.1").await;
    let request = format!(
        "GET http://{upstream}/slow HTTP/1.1\r\nHost: {upstream}\r\nConnection: close\r\n\r\n"
    );
    let response = raw_request(proxy_addr, request.as_bytes()).await;
    assert!(
        String::from_utf8_lossy(&response).starts_with("HTTP/1.1 504"),
        "{}",
        String::from_utf8_lossy(&response)
    );
    let entries = drain_entries(&mut bus, 1).await;
    assert!(
        entries
            .iter()
            .any(|entry| entry.state == TrafficState::Failed)
    );
    task.abort();
    proxy.shutdown().await;
}

#[tokio::test]
async fn rejects_private_dns_answers_without_the_opt_in() {
    let (upstream, _upstream_task) = spawn_http_upstream().await;
    let port = free_port();
    let mut config = proxy_config(port, "localhost");
    config.proxy.allow_private_upstreams = false;
    let mut bus = EventBus::new();
    let proxy = start_proxy(config, bus.sender(), Arc::new(AtomicU64::new(6000)))
        .await
        .unwrap();
    let proxy_addr = proxy.local_addr();
    let request = format!(
        "GET http://localhost:{}/dns HTTP/1.1\r\nHost: localhost:{}\r\nConnection: close\r\n\r\n",
        upstream.port(),
        upstream.port()
    );
    let response = raw_request(proxy_addr, request.as_bytes()).await;
    let text = String::from_utf8_lossy(&response);
    assert!(text.starts_with("HTTP/1.1 403"), "{text}");
    assert!(text.contains("address policy"), "{text}");
    let entries = drain_entries(&mut bus, 1).await;
    assert!(
        entries
            .iter()
            .any(|entry| entry.state == TrafficState::Failed)
    );
    proxy.shutdown().await;
}

#[tokio::test]
async fn malformed_requests_do_not_kill_the_listener() {
    let (upstream, _upstream_task) = spawn_http_upstream().await;
    let (proxy, proxy_addr, _bus) = start_test_proxy("127.0.0.1").await;

    let malformed = raw_request(proxy_addr, b"THIS IS NOT HTTP\r\n\r\n").await;
    if !malformed.is_empty() {
        assert!(
            String::from_utf8_lossy(&malformed).starts_with("HTTP/1.1 400"),
            "{}u",
            String::from_utf8_lossy(&malformed)
        );
    }

    let request = format!(
        "GET http://{upstream}/after-malformed HTTP/1.1\r\nHost: {upstream}\r\nConnection: close\r\n\r\n"
    );
    let response = raw_request(proxy_addr, request.as_bytes()).await;
    assert!(
        String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200"),
        "listener did not survive malformed input: {}",
        String::from_utf8_lossy(&response)
    );
    proxy.shutdown().await;
}

#[tokio::test]
async fn forwards_concurrent_requests() {
    let (upstream, _upstream_task) = spawn_http_upstream().await;
    let (proxy, proxy_addr, mut bus) = start_test_proxy("127.0.0.1").await;

    let mut tasks = Vec::new();
    for index in 0..4 {
        tasks.push(tokio::spawn(async move {
            let request = format!(
                "GET http://{upstream}/parallel-{index} HTTP/1.1\r\nHost: {upstream}\r\nConnection: close\r\n\r\n"
            );
            raw_request(proxy_addr, request.as_bytes()).await
        }));
    }
    for task in tasks {
        let response = task.await.unwrap();
        assert!(
            String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200"),
            "{}",
            String::from_utf8_lossy(&response)
        );
    }
    let entries = drain_entries(&mut bus, 4).await;
    assert!(
        entries
            .iter()
            .filter(|entry| entry.state == TrafficState::Completed)
            .count()
            >= 4
    );
    proxy.shutdown().await;
}

#[tokio::test]
async fn stalled_response_bodies_hit_the_idle_timeout() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let upstream = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buffer = [0_u8; 4096];
        let _ = socket.read(&mut buffer).await.unwrap();
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort")
            .await
            .unwrap();
        sleep(Duration::from_secs(3)).await;
    });

    let port = free_port();
    let mut config = proxy_config(port, "127.0.0.1");
    config.proxy.idle_timeout_secs = 1;
    let mut bus = EventBus::new();
    let proxy = start_proxy(config, bus.sender(), Arc::new(AtomicU64::new(7000)))
        .await
        .unwrap();
    let proxy_addr = proxy.local_addr();
    let request = format!(
        "GET http://{upstream}/stall HTTP/1.1\r\nHost: {upstream}\r\nConnection: close\r\n\r\n"
    );
    let response = raw_request(proxy_addr, request.as_bytes()).await;
    assert!(
        String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&response)
    );
    let entries = drain_entries(&mut bus, 1).await;
    let failed = entries
        .iter()
        .find(|entry| entry.state == TrafficState::Failed);
    assert!(failed.is_some(), "idle body timeout was not recorded");
    assert!(
        failed
            .unwrap()
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("idle timeout")
    );
    task.abort();
    proxy.shutdown().await;
}

#[tokio::test]
async fn enforces_connection_limit_and_shuts_down_cleanly() {
    let port = free_port();
    let mut config = proxy_config(port, "127.0.0.1");
    config.proxy.max_connections = 1;
    let bus = EventBus::new();
    let proxy = start_proxy(config, bus.sender(), Arc::new(AtomicU64::new(5000)))
        .await
        .unwrap();
    let proxy_addr = proxy.local_addr();

    let held = TcpStream::connect(proxy_addr).await.unwrap();
    sleep(Duration::from_millis(50)).await;
    let mut rejected = TcpStream::connect(proxy_addr).await.unwrap();
    let mut byte = [0_u8; 1];
    let read = timeout(Duration::from_millis(500), rejected.read(&mut byte)).await;
    assert!(read.is_ok(), "the over-limit connection was not closed");
    assert_eq!(read.unwrap().unwrap_or(0), 0);

    let shutdown = timeout(Duration::from_secs(2), proxy.shutdown()).await;
    assert!(shutdown.is_ok(), "graceful shutdown timed out");
    drop(held);

    let refused = TcpStream::connect(proxy_addr).await;
    assert!(refused.is_err(), "listener still accepted after shutdown");
}
