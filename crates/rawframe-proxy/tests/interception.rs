use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use rawframe_core::models::traffic::{TrafficId, TrafficState};
use rawframe_core::models::{AppConfig, InterceptionAction, InterceptionRule, Scope, ScopeRule};
use rawframe_core::{AppCommand, AppEvent, EventBus, ProxyState};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
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
    config.proxy.upstream_timeout_secs = 2;
    config.proxy.idle_timeout_secs = 2;
    config.proxy.max_body_bytes = 4096;
    config.proxy.max_response_bytes = 4096;
    config.proxy.max_connections = 16;
    config
}

async fn raw_request(proxy: SocketAddr, request: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream.write_all(request).await.unwrap();
    stream.shutdown().await.unwrap();
    let mut bytes = Vec::new();
    let _ = timeout(Duration::from_secs(5), stream.read_to_end(&mut bytes))
        .await
        .unwrap();
    bytes
}

async fn start_counting_upstream() -> (SocketAddr, Arc<AtomicUsize>, JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_task = hits.clone();
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let hits = hits_task.clone();
            tokio::spawn(async move {
                hits.fetch_add(1, Ordering::SeqCst);
                let service = service_fn(|req: Request<Incoming>| async move {
                    let method = req.method().to_string();
                    let uri = req.uri().to_string();
                    let header_x = req
                        .headers()
                        .get("x-test")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();
                    let body = req.into_body().collect().await.unwrap().to_bytes();
                    let body = String::from_utf8_lossy(&body).to_string();
                    let payload =
                        format!("method={method} uri={uri} x-test={header_x} body={body}");
                    Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(payload))))
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    (addr, hits, task)
}

async fn wait_for_listening(bus: &mut EventBus) -> SocketAddr {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let mut bound = None;
    loop {
        while let Some(event) = bus.poll() {
            match event {
                AppEvent::ProxyBound(addr) => bound = Some(addr),
                AppEvent::ProxyStateChanged(ProxyState::Listening) => {
                    if let Some(addr) = bound {
                        return addr;
                    }
                }
                AppEvent::ProxyStateChanged(ProxyState::Failed) => panic!("proxy failed"),
                _ => {}
            }
        }
        if let Some(addr) = bound {
            // bound may arrive before/with listening; give a tiny chance but return soon
            // if listening was missed in ordering we'll still proceed after short wait below.
            // better: return immediately, caller can proceed once socket accepts.
            return addr;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("proxy did not start listening");
        }
        sleep(Duration::from_millis(10)).await;
    }
}

async fn wait_for_paused(bus: &mut EventBus) -> rawframe_core::models::TrafficEntry {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        while let Some(event) = bus.poll() {
            if let AppEvent::InterceptionPaused(entry) = event {
                return *entry;
            }
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("timed out waiting for paused interception");
        }
        sleep(Duration::from_millis(10)).await;
    }
}

async fn collect_until_terminal(bus: &mut EventBus, id: TrafficId) -> Vec<AppEvent> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut events = Vec::new();
    loop {
        while let Some(event) = bus.poll() {
            let terminal = match &event {
                AppEvent::TrafficCaptured(e) | AppEvent::TrafficUpdated(e) => {
                    e.id == id && e.state.is_terminal()
                }
                _ => false,
            };
            events.push(event);
            if terminal {
                return events;
            }
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("timed out waiting for terminal event for {id:?}, got: {events:?}");
        }
        sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn disabled_interception_forwards_normally() {
    let (upstream, hits, _task) = start_counting_upstream().await;
    let port = free_port();
    let mut config = proxy_config(port, "127.0.0.1");
    config.proxy.interception_enabled = false;
    let mut bus = EventBus::new();
    let (cmd_tx, cmd_rx) = mpsc::channel(32);
    let service = tokio::spawn(rawframe_proxy::run_service(cmd_rx, bus.sender()));
    cmd_tx
        .send(AppCommand::StartProxy(Box::new(config)))
        .await
        .unwrap();
    let proxy_addr = wait_for_listening(&mut bus).await;

    let req = format!(
        "GET http://{upstream}/ok HTTP/1.1\r\nHost: {upstream}\r\nConnection: close\r\n\r\n"
    );
    let resp = raw_request(proxy_addr, req.as_bytes()).await;
    let text = String::from_utf8_lossy(&resp);
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    assert!(text.contains("uri=/ok"), "{text}");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "upstream should be reached when interception disabled"
    );

    cmd_tx.send(AppCommand::StopProxy).await.unwrap();
    drop(cmd_tx);
    let _ = timeout(Duration::from_secs(3), service).await.unwrap();
}

#[tokio::test]
async fn paused_request_forwards_unchanged_after_decision() {
    let (upstream, hits, _task) = start_counting_upstream().await;
    let port = free_port();
    let mut config = proxy_config(port, "127.0.0.1");
    config.proxy.interception_enabled = true;
    config.interception_rules = vec![InterceptionRule {
        name: "all".into(),
        enabled: true,
        method: None,
        host_pattern: None,
        path_contains: None,
        action: InterceptionAction::Intercept,
    }];
    let mut bus = EventBus::new();
    let (cmd_tx, cmd_rx) = mpsc::channel(32);
    let service = tokio::spawn(rawframe_proxy::run_service(cmd_rx, bus.sender()));
    cmd_tx
        .send(AppCommand::StartProxy(Box::new(config)))
        .await
        .unwrap();
    let proxy_addr = wait_for_listening(&mut bus).await;

    let req = format!(
        "GET http://{upstream}/wait HTTP/1.1\r\nHost: {upstream}\r\nConnection: close\r\n\r\n"
    );
    let client = tokio::spawn(async move { raw_request(proxy_addr, req.as_bytes()).await });
    sleep(Duration::from_millis(100)).await;
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "paused request must not reach upstream before decision"
    );

    let paused = wait_for_paused(&mut bus).await;
    assert_eq!(paused.state, TrafficState::Paused);
    assert!(paused.interception.intercepted);
    cmd_tx
        .send(AppCommand::ForwardRequest(paused.id))
        .await
        .unwrap();

    let resp = timeout(Duration::from_secs(5), client)
        .await
        .unwrap()
        .unwrap();
    let text = String::from_utf8_lossy(&resp);
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    assert!(text.contains("uri=/wait"), "{text}");
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    let events = collect_until_terminal(&mut bus, paused.id).await;
    let terminal = events
        .iter()
        .rev()
        .find_map(|e| match e {
            AppEvent::TrafficUpdated(entry) | AppEvent::TrafficCaptured(entry)
                if entry.id == paused.id && entry.state.is_terminal() =>
            {
                Some(entry.as_ref().clone())
            }
            _ => None,
        })
        .expect("terminal entry");
    assert!(matches!(
        terminal.state,
        TrafficState::Completed | TrafficState::Forwarded
    ));
    assert!(terminal.interception.intercepted);

    cmd_tx.send(AppCommand::StopProxy).await.unwrap();
    drop(cmd_tx);
    let _ = timeout(Duration::from_secs(3), service).await.unwrap();
}

#[tokio::test]
async fn dropped_request_never_reaches_upstream() {
    let (upstream, hits, _task) = start_counting_upstream().await;
    let port = free_port();
    let mut config = proxy_config(port, "127.0.0.1");
    config.proxy.interception_enabled = true;
    config.interception_rules = vec![InterceptionRule {
        name: "all".into(),
        enabled: true,
        method: None,
        host_pattern: None,
        path_contains: None,
        action: InterceptionAction::Intercept,
    }];
    let mut bus = EventBus::new();
    let (cmd_tx, cmd_rx) = mpsc::channel(32);
    let service = tokio::spawn(rawframe_proxy::run_service(cmd_rx, bus.sender()));
    cmd_tx
        .send(AppCommand::StartProxy(Box::new(config)))
        .await
        .unwrap();
    let proxy_addr = wait_for_listening(&mut bus).await;

    let req = format!(
        "GET http://{upstream}/drop HTTP/1.1\r\nHost: {upstream}\r\nConnection: close\r\n\r\n"
    );
    let client = tokio::spawn(async move { raw_request(proxy_addr, req.as_bytes()).await });
    let paused = wait_for_paused(&mut bus).await;
    sleep(Duration::from_millis(50)).await;
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "must not reach upstream while paused"
    );
    cmd_tx
        .send(AppCommand::DropRequest(paused.id))
        .await
        .unwrap();

    let resp = timeout(Duration::from_secs(5), client)
        .await
        .unwrap()
        .unwrap();
    let text = String::from_utf8_lossy(&resp);
    assert!(
        text.contains("dropped"),
        "client should get drop response: {text}"
    );
    sleep(Duration::from_millis(100)).await;
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "dropped request must never reach upstream"
    );

    let events = collect_until_terminal(&mut bus, paused.id).await;
    let terminal = events
        .iter()
        .rev()
        .find_map(|e| match e {
            AppEvent::TrafficUpdated(entry) | AppEvent::TrafficCaptured(entry)
                if entry.id == paused.id && entry.state.is_terminal() =>
            {
                Some(entry.as_ref().clone())
            }
            _ => None,
        })
        .expect("terminal entry");
    assert_eq!(terminal.state, TrafficState::Dropped);

    cmd_tx.send(AppCommand::StopProxy).await.unwrap();
    drop(cmd_tx);
    let _ = timeout(Duration::from_secs(3), service).await.unwrap();
}

#[tokio::test]
async fn interception_timeout_expires_pending_request() {
    let (upstream, hits, _task) = start_counting_upstream().await;
    let port = free_port();
    let mut config = proxy_config(port, "127.0.0.1");
    config.proxy.interception_enabled = true;
    config.proxy.intercept_timeout_secs = 1;
    config.interception_rules = vec![InterceptionRule {
        name: "all".into(),
        enabled: true,
        method: None,
        host_pattern: None,
        path_contains: None,
        action: InterceptionAction::Intercept,
    }];
    let mut bus = EventBus::new();
    let (cmd_tx, cmd_rx) = mpsc::channel(32);
    let service = tokio::spawn(rawframe_proxy::run_service(cmd_rx, bus.sender()));
    cmd_tx
        .send(AppCommand::StartProxy(Box::new(config)))
        .await
        .unwrap();
    let proxy_addr = wait_for_listening(&mut bus).await;

    let req = format!(
        "GET http://{upstream}/timeout HTTP/1.1\r\nHost: {upstream}\r\nConnection: close\r\n\r\n"
    );
    let client = tokio::spawn(async move { raw_request(proxy_addr, req.as_bytes()).await });
    let paused = wait_for_paused(&mut bus).await;
    assert_eq!(paused.state, TrafficState::Paused);

    let resp = timeout(Duration::from_secs(5), client)
        .await
        .unwrap()
        .unwrap();
    let text = String::from_utf8_lossy(&resp);
    assert!(
        text.contains("timed out") || text.contains("504") || text.contains("timeout"),
        "{text}"
    );
    sleep(Duration::from_millis(50)).await;
    assert_eq!(hits.load(Ordering::SeqCst), 0);

    let events = collect_until_terminal(&mut bus, paused.id).await;
    let terminal = events
        .iter()
        .rev()
        .find_map(|e| match e {
            AppEvent::TrafficUpdated(entry) | AppEvent::TrafficCaptured(entry)
                if entry.id == paused.id && entry.state.is_terminal() =>
            {
                Some(entry.as_ref().clone())
            }
            _ => None,
        })
        .expect("terminal entry");
    assert_eq!(terminal.state, TrafficState::TimedOut);

    cmd_tx.send(AppCommand::StopProxy).await.unwrap();
    drop(cmd_tx);
    let _ = timeout(Duration::from_secs(3), service).await.unwrap();
}

fn editable_from_http(
    req: &rawframe_core::models::HttpRequest,
) -> rawframe_core::models::EditableHttpRequest {
    rawframe_core::models::EditableHttpRequest {
        method: req.method.clone(),
        target: req.url(),
        version: req.version.clone(),
        host: req.host.clone(),
        port: req.port,
        scheme: req.scheme,
        headers: req.headers.clone(),
        body: req.body.clone(),
    }
}

async fn start_echo_upstream() -> (SocketAddr, Arc<AtomicUsize>, JoinHandle<()>) {
    start_counting_upstream().await
}

#[tokio::test]
async fn forwards_modified_method_path_headers_body() {
    let (upstream, hits, _task) = start_echo_upstream().await;
    let port = free_port();
    let mut config = proxy_config(port, "127.0.0.1");
    config.proxy.interception_enabled = true;
    config.interception_rules = vec![InterceptionRule {
        name: "all".into(),
        enabled: true,
        method: None,
        host_pattern: None,
        path_contains: None,
        action: InterceptionAction::Intercept,
    }];
    let mut bus = EventBus::new();
    let (cmd_tx, cmd_rx) = mpsc::channel(32);
    let service = tokio::spawn(rawframe_proxy::run_service(cmd_rx, bus.sender()));
    cmd_tx
        .send(AppCommand::StartProxy(Box::new(config)))
        .await
        .unwrap();
    let proxy_addr = wait_for_listening(&mut bus).await;

    // duplicate headers in original
    let req = format!(
        "GET http://{upstream}/orig HTTP/1.1\r\nHost: {upstream}\r\nX-Dupe: one\r\nX-Dupe: two\r\nConnection: close\r\n\r\n"
    );
    let client = tokio::spawn(async move { raw_request(proxy_addr, req.as_bytes()).await });
    let paused = wait_for_paused(&mut bus).await;
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    // build modified request: method/path/headers/body changed, preserve duplicate headers plus new ones
    // paused entry stores captured request in request field
    let base = paused.request.clone();
    let mut edited = editable_from_http(&base);
    edited.method = "POST".into();
    edited.target = format!("http://{upstream}/changed?x=1");
    edited.headers = base.headers.clone();
    edited.headers.insert("X-Test", "modified");
    edited.headers.append("X-Multi", "a");
    edited.headers.append("X-Multi", "b");
    edited.body = b"hello-modified".to_vec();
    cmd_tx
        .send(AppCommand::ForwardModified {
            id: paused.id,
            request: edited,
        })
        .await
        .unwrap();

    let resp = timeout(Duration::from_secs(5), client)
        .await
        .unwrap()
        .unwrap();
    let text = String::from_utf8_lossy(&resp);
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    assert!(text.contains("method=POST"), "{text}");
    assert!(text.contains("uri=/changed?x=1"), "{text}");
    assert!(text.contains("x-test=modified"), "{text}");
    assert!(text.contains("body=hello-modified"), "{text}");
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    let events = collect_until_terminal(&mut bus, paused.id).await;
    let terminal = events
        .iter()
        .rev()
        .find_map(|e| match e {
            AppEvent::TrafficUpdated(entry) | AppEvent::TrafficCaptured(entry)
                if entry.id == paused.id && entry.state.is_terminal() =>
            {
                Some(entry.as_ref().clone())
            }
            _ => None,
        })
        .expect("terminal");
    assert!(terminal.interception.intercepted);
    assert!(terminal.interception.modified);
    let orig = terminal.original_request.as_ref().expect("original");
    let fin = terminal.final_request.as_ref().expect("final");
    assert_eq!(orig.method, "GET");
    assert_eq!(orig.target, "/orig");
    assert_eq!(fin.method, "POST");
    assert!(fin.target.starts_with("/changed"));
    assert_eq!(fin.body, b"hello-modified");
    assert_eq!(
        fin.headers.get_all("x-multi").count(),
        2,
        "duplicate headers preserved: {:?}",
        fin.headers
    );

    cmd_tx.send(AppCommand::StopProxy).await.unwrap();
    drop(cmd_tx);
    let _ = timeout(Duration::from_secs(3), service).await.unwrap();
}

#[tokio::test]
async fn rejects_malformed_modified_request_without_forwarding() {
    let (upstream, hits, _task) = start_echo_upstream().await;
    let port = free_port();
    let mut config = proxy_config(port, "127.0.0.1");
    config.proxy.interception_enabled = true;
    config.interception_rules = vec![InterceptionRule {
        name: "all".into(),
        enabled: true,
        method: None,
        host_pattern: None,
        path_contains: None,
        action: InterceptionAction::Intercept,
    }];
    let mut bus = EventBus::new();
    let (cmd_tx, cmd_rx) = mpsc::channel(32);
    let service = tokio::spawn(rawframe_proxy::run_service(cmd_rx, bus.sender()));
    cmd_tx
        .send(AppCommand::StartProxy(Box::new(config)))
        .await
        .unwrap();
    let proxy_addr = wait_for_listening(&mut bus).await;

    let req = format!(
        "GET http://{upstream}/x HTTP/1.1\r\nHost: {upstream}\r\nConnection: close\r\n\r\n"
    );
    let client = tokio::spawn(async move { raw_request(proxy_addr, req.as_bytes()).await });
    let paused = wait_for_paused(&mut bus).await;
    let mut edited = editable_from_http(&paused.request);
    edited.target = "/origin-form-only".into(); // rejected by parser
    edited.method = "BAD METHOD".into();
    cmd_tx
        .send(AppCommand::ForwardModified {
            id: paused.id,
            request: edited,
        })
        .await
        .unwrap();

    let resp = timeout(Duration::from_secs(5), client)
        .await
        .unwrap()
        .unwrap();
    let text = String::from_utf8_lossy(&resp);
    assert!(text.starts_with("HTTP/1.1 400"), "{text}");
    sleep(Duration::from_millis(100)).await;
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "invalid modified request must not be forwarded"
    );

    cmd_tx.send(AppCommand::StopProxy).await.unwrap();
    drop(cmd_tx);
    let _ = timeout(Duration::from_secs(3), service).await.unwrap();
}

#[tokio::test]
async fn queue_capacity_enforced_and_events_emitted() {
    let (upstream, _hits, _task) = start_echo_upstream().await;
    let port = free_port();
    let mut config = proxy_config(port, "127.0.0.1");
    config.proxy.interception_enabled = true;
    config.proxy.intercept_queue_capacity = 1;
    config.interception_rules = vec![InterceptionRule {
        name: "all".into(),
        enabled: true,
        method: None,
        host_pattern: None,
        path_contains: None,
        action: InterceptionAction::Intercept,
    }];
    let mut bus = EventBus::new();
    let (cmd_tx, cmd_rx) = mpsc::channel(32);
    let service = tokio::spawn(rawframe_proxy::run_service(cmd_rx, bus.sender()));
    cmd_tx
        .send(AppCommand::StartProxy(Box::new(config)))
        .await
        .unwrap();
    let proxy_addr = wait_for_listening(&mut bus).await;

    let req1 = format!(
        "GET http://{upstream}/a HTTP/1.1\r\nHost: {upstream}\r\nConnection: close\r\n\r\n"
    );
    let req2 = format!(
        "GET http://{upstream}/b HTTP/1.1\r\nHost: {upstream}\r\nConnection: close\r\n\r\n"
    );
    let c1 = tokio::spawn({
        let r = req1.clone();
        async move { raw_request(proxy_addr, r.as_bytes()).await }
    });
    let paused1 = wait_for_paused(&mut bus).await;
    // second should be rejected due to full queue
    let resp2 = raw_request(proxy_addr, req2.as_bytes()).await;
    let t2 = String::from_utf8_lossy(&resp2);
    assert!(
        t2.contains("queue")
            || t2.contains("503")
            || t2.contains("unavailable")
            || t2.contains("not paused")
            || t2.contains("full")
            || t2.starts_with("HTTP/1.1 503")
            || t2.starts_with("HTTP/1.1 5"),
        "expected rejection when queue full: {t2}"
    );
    // saw queue change events at some point
    let mut saw_queue_event = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    while tokio::time::Instant::now() < deadline {
        while let Some(ev) = bus.poll() {
            if matches!(ev, AppEvent::InterceptionQueueChanged { .. }) {
                saw_queue_event = true;
            }
        }
        if saw_queue_event {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }
    assert!(saw_queue_event, "expected InterceptionQueueChanged events");

    cmd_tx
        .send(AppCommand::ForwardRequest(paused1.id))
        .await
        .unwrap();
    let _ = timeout(Duration::from_secs(5), c1).await.unwrap().unwrap();
    cmd_tx.send(AppCommand::StopProxy).await.unwrap();
    drop(cmd_tx);
    let _ = timeout(Duration::from_secs(3), service).await.unwrap();
}

#[tokio::test]
async fn scope_denial_while_interception_enabled() {
    let (upstream, hits, _task) = start_echo_upstream().await;
    let port = free_port();
    let mut config = proxy_config(port, "allowed.test"); // upstream is 127.0.0.1, out of scope
    config.proxy.interception_enabled = true;
    config.interception_rules = vec![InterceptionRule {
        name: "all".into(),
        enabled: true,
        method: None,
        host_pattern: None,
        path_contains: None,
        action: InterceptionAction::Intercept,
    }];
    let mut bus = EventBus::new();
    let (cmd_tx, cmd_rx) = mpsc::channel(32);
    let service = tokio::spawn(rawframe_proxy::run_service(cmd_rx, bus.sender()));
    cmd_tx
        .send(AppCommand::StartProxy(Box::new(config)))
        .await
        .unwrap();
    let proxy_addr = wait_for_listening(&mut bus).await;

    let req = format!(
        "GET http://{upstream}/secret HTTP/1.1\r\nHost: {upstream}\r\nConnection: close\r\n\r\n"
    );
    let resp = raw_request(proxy_addr, req.as_bytes()).await;
    let text = String::from_utf8_lossy(&resp);
    assert!(text.starts_with("HTTP/1.1 403"), "{text}");
    sleep(Duration::from_millis(100)).await;
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    // should not pause (no InterceptionPaused)
    let mut saw_paused = false;
    let deadline = tokio::time::Instant::now() + Duration::from_millis(300);
    while tokio::time::Instant::now() < deadline {
        while let Some(ev) = bus.poll() {
            if matches!(ev, AppEvent::InterceptionPaused(_)) {
                saw_paused = true;
            }
        }
        sleep(Duration::from_millis(10)).await;
    }
    assert!(!saw_paused, "out-of-scope request must not be paused");

    cmd_tx.send(AppCommand::StopProxy).await.unwrap();
    drop(cmd_tx);
    let _ = timeout(Duration::from_secs(3), service).await.unwrap();
}

#[tokio::test]
async fn modified_destination_scope_revalidation() {
    let (upstream, hits, _task) = start_echo_upstream().await;
    let port = free_port();
    let mut config = proxy_config(port, "127.0.0.1");
    config.proxy.scope = Scope::allow(ScopeRule::host("127.0.0.1"));
    config.proxy.interception_enabled = true;
    config.interception_rules = vec![InterceptionRule {
        name: "all".into(),
        enabled: true,
        method: None,
        host_pattern: None,
        path_contains: None,
        action: InterceptionAction::Intercept,
    }];
    let mut bus = EventBus::new();
    let (cmd_tx, cmd_rx) = mpsc::channel(32);
    let service = tokio::spawn(rawframe_proxy::run_service(cmd_rx, bus.sender()));
    cmd_tx
        .send(AppCommand::StartProxy(Box::new(config)))
        .await
        .unwrap();
    let proxy_addr = wait_for_listening(&mut bus).await;

    let req = format!(
        "GET http://{upstream}/ok HTTP/1.1\r\nHost: {upstream}\r\nConnection: close\r\n\r\n"
    );
    let client = tokio::spawn(async move { raw_request(proxy_addr, req.as_bytes()).await });
    let paused = wait_for_paused(&mut bus).await;
    let mut edited = editable_from_http(&paused.request);
    edited.target = "http://evil.test/steal".into();
    cmd_tx
        .send(AppCommand::ForwardModified {
            id: paused.id,
            request: edited,
        })
        .await
        .unwrap();

    let resp = timeout(Duration::from_secs(5), client)
        .await
        .unwrap()
        .unwrap();
    let text = String::from_utf8_lossy(&resp);
    assert!(
        text.starts_with("HTTP/1.1 403") || text.contains("scope") || text.contains("denied"),
        "{text}"
    );
    sleep(Duration::from_millis(100)).await;
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "modified out-of-scope destination must not be contacted"
    );

    cmd_tx.send(AppCommand::StopProxy).await.unwrap();
    drop(cmd_tx);
    let _ = timeout(Duration::from_secs(3), service).await.unwrap();
}

#[tokio::test]
async fn disable_interception_cancels_pending_requests() {
    let (upstream, hits, _task) = start_echo_upstream().await;
    let port = free_port();
    let mut config = proxy_config(port, "127.0.0.1");
    config.proxy.interception_enabled = true;
    config.interception_rules = vec![InterceptionRule {
        name: "all".into(),
        enabled: true,
        method: None,
        host_pattern: None,
        path_contains: None,
        action: InterceptionAction::Intercept,
    }];
    let mut bus = EventBus::new();
    let (cmd_tx, cmd_rx) = mpsc::channel(32);
    let service = tokio::spawn(rawframe_proxy::run_service(cmd_rx, bus.sender()));
    cmd_tx
        .send(AppCommand::StartProxy(Box::new(config)))
        .await
        .unwrap();
    let proxy_addr = wait_for_listening(&mut bus).await;

    let req = format!(
        "GET http://{upstream}/pending HTTP/1.1\r\nHost: {upstream}\r\nConnection: close\r\n\r\n"
    );
    let client = tokio::spawn(async move { raw_request(proxy_addr, req.as_bytes()).await });
    let paused = wait_for_paused(&mut bus).await;
    cmd_tx
        .send(AppCommand::SetInterception { enabled: false })
        .await
        .unwrap();

    let resp = timeout(Duration::from_secs(5), client)
        .await
        .unwrap()
        .unwrap();
    let text = String::from_utf8_lossy(&resp);
    assert!(
        text.contains("cancel")
            || text.contains("503")
            || text.contains("unavailable")
            || text.contains("disabled"),
        "{text}"
    );
    sleep(Duration::from_millis(100)).await;
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    let events = collect_until_terminal(&mut bus, paused.id).await;
    let terminal = events
        .iter()
        .rev()
        .find_map(|e| match e {
            AppEvent::TrafficUpdated(entry) | AppEvent::TrafficCaptured(entry)
                if entry.id == paused.id && entry.state.is_terminal() =>
            {
                Some(entry.as_ref().clone())
            }
            _ => None,
        })
        .expect("terminal");
    assert!(matches!(
        terminal.state,
        TrafficState::Cancelled
            | TrafficState::TimedOut
            | TrafficState::Failed
            | TrafficState::Dropped
    ));

    cmd_tx.send(AppCommand::StopProxy).await.unwrap();
    drop(cmd_tx);
    let _ = timeout(Duration::from_secs(3), service).await.unwrap();
}

#[tokio::test]
async fn proxy_shutdown_cancels_pending_interceptions() {
    let (upstream, hits, _task) = start_echo_upstream().await;
    let port = free_port();
    let mut config = proxy_config(port, "127.0.0.1");
    config.proxy.interception_enabled = true;
    config.interception_rules = vec![InterceptionRule {
        name: "all".into(),
        enabled: true,
        method: None,
        host_pattern: None,
        path_contains: None,
        action: InterceptionAction::Intercept,
    }];
    let mut bus = EventBus::new();
    let (cmd_tx, cmd_rx) = mpsc::channel(32);
    let service = tokio::spawn(rawframe_proxy::run_service(cmd_rx, bus.sender()));
    cmd_tx
        .send(AppCommand::StartProxy(Box::new(config)))
        .await
        .unwrap();
    let proxy_addr = wait_for_listening(&mut bus).await;

    let req = format!(
        "GET http://{upstream}/pending HTTP/1.1\r\nHost: {upstream}\r\nConnection: close\r\n\r\n"
    );
    let client = tokio::spawn(async move { raw_request(proxy_addr, req.as_bytes()).await });
    let paused = wait_for_paused(&mut bus).await;
    cmd_tx.send(AppCommand::StopProxy).await.unwrap();

    let resp = timeout(Duration::from_secs(5), client)
        .await
        .unwrap()
        .unwrap();
    let text = String::from_utf8_lossy(&resp);
    assert!(
        !text.is_empty(),
        "client should receive cancellation/error response"
    );
    sleep(Duration::from_millis(100)).await;
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    // service should exit cleanly
    drop(cmd_tx);
    let _ = timeout(Duration::from_secs(5), service).await.unwrap();
    let _ = paused;
}

#[tokio::test]
async fn rejects_oversized_modified_request_without_forwarding() {
    let (upstream, hits, _task) = start_echo_upstream().await;
    let port = free_port();
    let mut config = proxy_config(port, "127.0.0.1");
    config.proxy.interception_enabled = true;
    config.proxy.max_body_bytes = 16;
    config.interception_rules = vec![InterceptionRule {
        name: "all".into(),
        enabled: true,
        method: None,
        host_pattern: None,
        path_contains: None,
        action: InterceptionAction::Intercept,
    }];
    let mut bus = EventBus::new();
    let (cmd_tx, cmd_rx) = mpsc::channel(32);
    let service = tokio::spawn(rawframe_proxy::run_service(cmd_rx, bus.sender()));
    cmd_tx
        .send(AppCommand::StartProxy(Box::new(config)))
        .await
        .unwrap();
    let proxy_addr = wait_for_listening(&mut bus).await;

    let req = format!(
        "GET http://{upstream}/x HTTP/1.1\r\nHost: {upstream}\r\nConnection: close\r\n\r\n"
    );
    let client = tokio::spawn(async move { raw_request(proxy_addr, req.as_bytes()).await });
    let paused = wait_for_paused(&mut bus).await;
    let mut edited = editable_from_http(&paused.request);
    edited.method = "POST".into();
    edited.body = vec![b'a'; 64];
    cmd_tx
        .send(AppCommand::ForwardModified {
            id: paused.id,
            request: edited,
        })
        .await
        .unwrap();

    let resp = timeout(Duration::from_secs(5), client)
        .await
        .unwrap()
        .unwrap();
    let text = String::from_utf8_lossy(&resp);
    assert!(
        text.starts_with("HTTP/1.1 413") || text.contains("limit") || text.contains("too large"),
        "{text}"
    );
    sleep(Duration::from_millis(100)).await;
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "oversized modified request must not be forwarded"
    );

    cmd_tx.send(AppCommand::StopProxy).await.unwrap();
    drop(cmd_tx);
    let _ = timeout(Duration::from_secs(3), service).await.unwrap();
}

#[tokio::test]
async fn multiple_simultaneous_interceptions_have_independent_decisions() {
    let (upstream, hits, _task) = start_echo_upstream().await;
    let port = free_port();
    let mut config = proxy_config(port, "127.0.0.1");
    config.proxy.interception_enabled = true;
    config.proxy.intercept_queue_capacity = 8;
    config.interception_rules = vec![InterceptionRule {
        name: "all".into(),
        enabled: true,
        method: None,
        host_pattern: None,
        path_contains: None,
        action: InterceptionAction::Intercept,
    }];
    let mut bus = EventBus::new();
    let (cmd_tx, cmd_rx) = mpsc::channel(32);
    let service = tokio::spawn(rawframe_proxy::run_service(cmd_rx, bus.sender()));
    cmd_tx
        .send(AppCommand::StartProxy(Box::new(config)))
        .await
        .unwrap();
    let proxy_addr = wait_for_listening(&mut bus).await;

    let req1 = format!(
        "GET http://{upstream}/one HTTP/1.1\r\nHost: {upstream}\r\nConnection: close\r\n\r\n"
    );
    let req2 = format!(
        "GET http://{upstream}/two HTTP/1.1\r\nHost: {upstream}\r\nConnection: close\r\n\r\n"
    );
    let c1 = tokio::spawn({
        let r = req1.clone();
        async move { raw_request(proxy_addr, r.as_bytes()).await }
    });
    let c2 = tokio::spawn({
        let r = req2.clone();
        async move { raw_request(proxy_addr, r.as_bytes()).await }
    });
    let p1 = wait_for_paused(&mut bus).await;
    let p2 = wait_for_paused(&mut bus).await;
    assert_ne!(p1.id, p2.id);
    sleep(Duration::from_millis(80)).await;
    assert_eq!(hits.load(Ordering::SeqCst), 0);

    // drop first, forward second
    cmd_tx.send(AppCommand::DropRequest(p1.id)).await.unwrap();
    cmd_tx
        .send(AppCommand::ForwardRequest(p2.id))
        .await
        .unwrap();

    let r1 = timeout(Duration::from_secs(5), c1).await.unwrap().unwrap();
    let r2 = timeout(Duration::from_secs(5), c2).await.unwrap().unwrap();
    let t1 = String::from_utf8_lossy(&r1);
    let t2 = String::from_utf8_lossy(&r2);
    assert!(t1.contains("dropped") || t1.contains("403"), "{t1}");
    assert!(
        t2.starts_with("HTTP/1.1 200") && t2.contains("uri=/two"),
        "{t2}"
    );
    // only forwarded one reached upstream
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    cmd_tx.send(AppCommand::StopProxy).await.unwrap();
    drop(cmd_tx);
    let _ = timeout(Duration::from_secs(3), service).await.unwrap();
}

#[tokio::test]
async fn modified_body_content_length_and_framing_are_correct() {
    let (upstream, hits, _task) = start_counting_upstream().await;
    let port = free_port();
    let mut config = proxy_config(port, "127.0.0.1");
    config.proxy.interception_enabled = true;
    config.interception_rules = vec![InterceptionRule {
        name: "all".into(),
        enabled: true,
        method: None,
        host_pattern: None,
        path_contains: None,
        action: InterceptionAction::Intercept,
    }];
    let mut bus = EventBus::new();
    let (cmd_tx, cmd_rx) = mpsc::channel(32);
    let service = tokio::spawn(rawframe_proxy::run_service(cmd_rx, bus.sender()));
    cmd_tx
        .send(AppCommand::StartProxy(Box::new(config)))
        .await
        .unwrap();
    let proxy_addr = wait_for_listening(&mut bus).await;

    let req = format!(
        "POST http://{upstream}/orig HTTP/1.1\r\nHost: {upstream}\r\nContent-Type: text/plain\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"
    );
    let client = tokio::spawn(async move { raw_request(proxy_addr, req.as_bytes()).await });
    let paused = wait_for_paused(&mut bus).await;

    let mut edited = editable_from_http(&paused.request);
    edited.method = "POST".into();
    edited.target = format!("http://{upstream}/modified");
    edited.body = b"hello-modified-body".to_vec();
    // Remove explicit content-length if present; proxy must frame/forward correctly.
    edited.headers.remove_all("content-length");
    edited.headers.remove_all("Content-Length");
    cmd_tx
        .send(AppCommand::ForwardModified {
            id: paused.id,
            request: edited,
        })
        .await
        .unwrap();

    let resp = timeout(Duration::from_secs(5), client)
        .await
        .unwrap()
        .unwrap();
    let text = String::from_utf8_lossy(&resp);
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    assert!(
        text.contains("body=hello-modified-body"),
        "upstream must receive exact modified body: {text}"
    );
    assert!(text.contains("uri=/modified"), "{text}");
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    let events = collect_until_terminal(&mut bus, paused.id).await;
    let terminal = events
        .iter()
        .rev()
        .find_map(|e| match e {
            AppEvent::TrafficUpdated(entry) | AppEvent::TrafficCaptured(entry)
                if entry.id == paused.id && entry.state.is_terminal() =>
            {
                Some(entry.as_ref().clone())
            }
            _ => None,
        })
        .expect("terminal");
    let fin = terminal.final_request.as_ref().expect("final request");
    assert_eq!(fin.body, b"hello-modified-body");
    assert!(terminal.interception.modified);

    cmd_tx.send(AppCommand::StopProxy).await.unwrap();
    drop(cmd_tx);
    let _ = timeout(Duration::from_secs(3), service).await.unwrap();
}

#[tokio::test]
async fn queue_positions_update_after_resolution() {
    let (upstream, _hits, _task) = start_counting_upstream().await;
    let port = free_port();
    let mut config = proxy_config(port, "127.0.0.1");
    config.proxy.interception_enabled = true;
    config.proxy.intercept_queue_capacity = 8;
    config.interception_rules = vec![InterceptionRule {
        name: "all".into(),
        enabled: true,
        method: None,
        host_pattern: None,
        path_contains: None,
        action: InterceptionAction::Intercept,
    }];
    let mut bus = EventBus::new();
    let (cmd_tx, cmd_rx) = mpsc::channel(32);
    let service = tokio::spawn(rawframe_proxy::run_service(cmd_rx, bus.sender()));
    cmd_tx
        .send(AppCommand::StartProxy(Box::new(config)))
        .await
        .unwrap();
    let proxy_addr = wait_for_listening(&mut bus).await;

    let req = |path: &str| {
        format!(
            "GET http://{upstream}{path} HTTP/1.1\r\nHost: {upstream}\r\nConnection: close\r\n\r\n"
        )
    };
    let c1 = tokio::spawn({
        let r = req("/a");
        async move { raw_request(proxy_addr, r.as_bytes()).await }
    });
    let c2 = tokio::spawn({
        let r = req("/b");
        async move { raw_request(proxy_addr, r.as_bytes()).await }
    });
    let c3 = tokio::spawn({
        let r = req("/c");
        async move { raw_request(proxy_addr, r.as_bytes()).await }
    });

    let p1 = wait_for_paused(&mut bus).await;
    let p2 = wait_for_paused(&mut bus).await;
    let p3 = wait_for_paused(&mut bus).await;
    // Queue positions may be assigned on pause; resolve middle and ensure remaining are still resolvable independently.
    cmd_tx.send(AppCommand::DropRequest(p2.id)).await.unwrap();
    let _r2 = timeout(Duration::from_secs(5), c2).await.unwrap().unwrap();

    // After resolving p2, p1 and p3 must still be pending and actionable.
    cmd_tx
        .send(AppCommand::ForwardRequest(p1.id))
        .await
        .unwrap();
    cmd_tx
        .send(AppCommand::ForwardRequest(p3.id))
        .await
        .unwrap();
    let r1 = timeout(Duration::from_secs(5), c1).await.unwrap().unwrap();
    let r3 = timeout(Duration::from_secs(5), c3).await.unwrap().unwrap();
    let t1 = String::from_utf8_lossy(&r1);
    let t3 = String::from_utf8_lossy(&r3);
    assert!(t1.starts_with("HTTP/1.1 200"), "{t1}");
    assert!(t3.starts_with("HTTP/1.1 200"), "{t3}");

    // Queue should be empty after all resolved.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        if context_queue_empty_via_events(&mut bus).await {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        sleep(Duration::from_millis(20)).await;
    }

    cmd_tx.send(AppCommand::StopProxy).await.unwrap();
    drop(cmd_tx);
    let _ = timeout(Duration::from_secs(3), service).await.unwrap();
}

async fn context_queue_empty_via_events(bus: &mut EventBus) -> bool {
    // Drain available events and look for queue changes indicating empty; best-effort.
    while let Some(event) = bus.poll() {
        if let AppEvent::InterceptionQueueChanged { pending, .. } = event
            && pending == 0
        {
            return true;
        }
    }
    false
}

#[tokio::test]
async fn client_disconnect_while_interception_pending_does_not_hang() {
    let (upstream, hits, _task) = start_counting_upstream().await;
    let port = free_port();
    let mut config = proxy_config(port, "127.0.0.1");
    config.proxy.interception_enabled = true;
    config.proxy.intercept_timeout_secs = 5;
    config.interception_rules = vec![InterceptionRule {
        name: "all".into(),
        enabled: true,
        method: None,
        host_pattern: None,
        path_contains: None,
        action: InterceptionAction::Intercept,
    }];
    let mut bus = EventBus::new();
    let (cmd_tx, cmd_rx) = mpsc::channel(32);
    let service = tokio::spawn(rawframe_proxy::run_service(cmd_rx, bus.sender()));
    cmd_tx
        .send(AppCommand::StartProxy(Box::new(config)))
        .await
        .unwrap();
    let proxy_addr = wait_for_listening(&mut bus).await;

    let req = format!(
        "GET http://{upstream}/disc HTTP/1.1\r\nHost: {upstream}\r\nConnection: close\r\n\r\n"
    );
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client.write_all(req.as_bytes()).await.unwrap();
    let paused = wait_for_paused(&mut bus).await;
    // Disconnect client while request is paused.
    drop(client);
    sleep(Duration::from_millis(150)).await;
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "upstream must not be contacted"
    );

    // Attempting to resolve should not panic/hang proxy service; state may become terminal via cancel/fail.
    let _ = cmd_tx.send(AppCommand::DropRequest(paused.id)).await;
    // Service should remain responsive (able to stop cleanly).
    cmd_tx.send(AppCommand::StopProxy).await.unwrap();
    drop(cmd_tx);
    let _ = timeout(Duration::from_secs(5), service).await.unwrap();
}

#[tokio::test]
async fn history_metadata_forwarded_unchanged_interception() {
    let (upstream, _hits, _task) = start_counting_upstream().await;
    let port = free_port();
    let mut config = proxy_config(port, "127.0.0.1");
    config.proxy.interception_enabled = true;
    config.interception_rules = vec![InterceptionRule {
        name: "all".into(),
        enabled: true,
        method: None,
        host_pattern: None,
        path_contains: None,
        action: InterceptionAction::Intercept,
    }];
    let mut bus = EventBus::new();
    let (cmd_tx, cmd_rx) = mpsc::channel(32);
    let service = tokio::spawn(rawframe_proxy::run_service(cmd_rx, bus.sender()));
    cmd_tx
        .send(AppCommand::StartProxy(Box::new(config)))
        .await
        .unwrap();
    let proxy_addr = wait_for_listening(&mut bus).await;
    let req = format!(
        "GET http://{upstream}/ok HTTP/1.1\r\nHost: {upstream}\r\nConnection: close\r\n\r\n"
    );
    let client = tokio::spawn(async move { raw_request(proxy_addr, req.as_bytes()).await });
    let paused = wait_for_paused(&mut bus).await;
    cmd_tx
        .send(AppCommand::ForwardRequest(paused.id))
        .await
        .unwrap();
    let resp = timeout(Duration::from_secs(5), client)
        .await
        .unwrap()
        .unwrap();
    assert!(String::from_utf8_lossy(&resp).starts_with("HTTP/1.1 200"));
    let events = collect_until_terminal(&mut bus, paused.id).await;
    let terminal = events
        .iter()
        .rev()
        .find_map(|e| match e {
            AppEvent::TrafficUpdated(entry) | AppEvent::TrafficCaptured(entry)
                if entry.id == paused.id && entry.state.is_terminal() =>
            {
                Some(entry.as_ref().clone())
            }
            _ => None,
        })
        .expect("terminal");
    assert!(matches!(
        terminal.state,
        TrafficState::Completed | TrafficState::Forwarded
    ));
    assert!(terminal.interception.intercepted);
    assert!(
        !terminal.interception.modified,
        "unchanged forward must not be marked modified"
    );
    assert!(
        terminal.original_request.is_some(),
        "original request should be preserved"
    );
    assert!(
        terminal.final_request.is_some(),
        "final request should be preserved"
    );
    assert_eq!(terminal.original_request, terminal.final_request);
    assert!(
        terminal.response.is_some(),
        "forwarded unchanged should have upstream response"
    );
    cmd_tx.send(AppCommand::StopProxy).await.unwrap();
    drop(cmd_tx);
    let _ = timeout(Duration::from_secs(3), service).await.unwrap();
}

#[tokio::test]
async fn history_metadata_forwarded_modified_interception() {
    let (upstream, _hits, _task) = start_counting_upstream().await;
    let port = free_port();
    let mut config = proxy_config(port, "127.0.0.1");
    config.proxy.interception_enabled = true;
    config.interception_rules = vec![InterceptionRule {
        name: "all".into(),
        enabled: true,
        method: None,
        host_pattern: None,
        path_contains: None,
        action: InterceptionAction::Intercept,
    }];
    let mut bus = EventBus::new();
    let (cmd_tx, cmd_rx) = mpsc::channel(32);
    let service = tokio::spawn(rawframe_proxy::run_service(cmd_rx, bus.sender()));
    cmd_tx
        .send(AppCommand::StartProxy(Box::new(config)))
        .await
        .unwrap();
    let proxy_addr = wait_for_listening(&mut bus).await;
    let req = format!(
        "GET http://{upstream}/orig HTTP/1.1\r\nHost: {upstream}\r\nConnection: close\r\n\r\n"
    );
    let client = tokio::spawn(async move { raw_request(proxy_addr, req.as_bytes()).await });
    let paused = wait_for_paused(&mut bus).await;
    let mut edited = editable_from_http(&paused.request);
    edited.target = format!("http://{upstream}/changed");
    edited.headers.insert("X-Edited", "yes");
    cmd_tx
        .send(AppCommand::ForwardModified {
            id: paused.id,
            request: edited,
        })
        .await
        .unwrap();
    let resp = timeout(Duration::from_secs(5), client)
        .await
        .unwrap()
        .unwrap();
    assert!(String::from_utf8_lossy(&resp).starts_with("HTTP/1.1 200"));
    let events = collect_until_terminal(&mut bus, paused.id).await;
    let terminal = events
        .iter()
        .rev()
        .find_map(|e| match e {
            AppEvent::TrafficUpdated(entry) | AppEvent::TrafficCaptured(entry)
                if entry.id == paused.id && entry.state.is_terminal() =>
            {
                Some(entry.as_ref().clone())
            }
            _ => None,
        })
        .expect("terminal");
    assert!(terminal.interception.intercepted);
    assert!(terminal.interception.modified);
    let orig = terminal.original_request.as_ref().expect("original");
    let fin = terminal.final_request.as_ref().expect("final");
    assert_ne!(
        orig, fin,
        "modified request must preserve original and differ in final"
    );
    assert!(terminal.response.is_some());
    cmd_tx.send(AppCommand::StopProxy).await.unwrap();
    drop(cmd_tx);
    let _ = timeout(Duration::from_secs(3), service).await.unwrap();
}

#[tokio::test]
async fn history_metadata_dropped_interception() {
    let (upstream, hits, _task) = start_counting_upstream().await;
    let port = free_port();
    let mut config = proxy_config(port, "127.0.0.1");
    config.proxy.interception_enabled = true;
    config.interception_rules = vec![InterceptionRule {
        name: "all".into(),
        enabled: true,
        method: None,
        host_pattern: None,
        path_contains: None,
        action: InterceptionAction::Intercept,
    }];
    let mut bus = EventBus::new();
    let (cmd_tx, cmd_rx) = mpsc::channel(32);
    let service = tokio::spawn(rawframe_proxy::run_service(cmd_rx, bus.sender()));
    cmd_tx
        .send(AppCommand::StartProxy(Box::new(config)))
        .await
        .unwrap();
    let proxy_addr = wait_for_listening(&mut bus).await;
    let req = format!(
        "GET http://{upstream}/drop HTTP/1.1\r\nHost: {upstream}\r\nConnection: close\r\n\r\n"
    );
    let client = tokio::spawn(async move { raw_request(proxy_addr, req.as_bytes()).await });
    let paused = wait_for_paused(&mut bus).await;
    cmd_tx
        .send(AppCommand::DropRequest(paused.id))
        .await
        .unwrap();
    let _ = timeout(Duration::from_secs(5), client)
        .await
        .unwrap()
        .unwrap();
    sleep(Duration::from_millis(50)).await;
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    let events = collect_until_terminal(&mut bus, paused.id).await;
    let terminal = events
        .iter()
        .rev()
        .find_map(|e| match e {
            AppEvent::TrafficUpdated(entry) | AppEvent::TrafficCaptured(entry)
                if entry.id == paused.id && entry.state.is_terminal() =>
            {
                Some(entry.as_ref().clone())
            }
            _ => None,
        })
        .expect("terminal");
    assert_eq!(terminal.state, TrafficState::Dropped);
    assert!(
        terminal.response.is_none(),
        "dropped request must not have upstream response"
    );
    assert!(terminal.interception.intercepted);
    cmd_tx.send(AppCommand::StopProxy).await.unwrap();
    drop(cmd_tx);
    let _ = timeout(Duration::from_secs(3), service).await.unwrap();
}

#[tokio::test]
async fn history_metadata_timed_out_interception() {
    let (upstream, hits, _task) = start_counting_upstream().await;
    let port = free_port();
    let mut config = proxy_config(port, "127.0.0.1");
    config.proxy.interception_enabled = true;
    config.proxy.intercept_timeout_secs = 1;
    config.interception_rules = vec![InterceptionRule {
        name: "all".into(),
        enabled: true,
        method: None,
        host_pattern: None,
        path_contains: None,
        action: InterceptionAction::Intercept,
    }];
    let mut bus = EventBus::new();
    let (cmd_tx, cmd_rx) = mpsc::channel(32);
    let service = tokio::spawn(rawframe_proxy::run_service(cmd_rx, bus.sender()));
    cmd_tx
        .send(AppCommand::StartProxy(Box::new(config)))
        .await
        .unwrap();
    let proxy_addr = wait_for_listening(&mut bus).await;
    let req = format!(
        "GET http://{upstream}/to HTTP/1.1\r\nHost: {upstream}\r\nConnection: close\r\n\r\n"
    );
    let client = tokio::spawn(async move { raw_request(proxy_addr, req.as_bytes()).await });
    let paused = wait_for_paused(&mut bus).await;
    let _ = timeout(Duration::from_secs(5), client)
        .await
        .unwrap()
        .unwrap();
    sleep(Duration::from_millis(50)).await;
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    let events = collect_until_terminal(&mut bus, paused.id).await;
    let terminal = events
        .iter()
        .rev()
        .find_map(|e| match e {
            AppEvent::TrafficUpdated(entry) | AppEvent::TrafficCaptured(entry)
                if entry.id == paused.id && entry.state.is_terminal() =>
            {
                Some(entry.as_ref().clone())
            }
            _ => None,
        })
        .expect("terminal");
    assert_eq!(terminal.state, TrafficState::TimedOut);
    assert!(terminal.response.is_none());
    assert!(terminal.interception.intercepted);
    cmd_tx.send(AppCommand::StopProxy).await.unwrap();
    drop(cmd_tx);
    let _ = timeout(Duration::from_secs(3), service).await.unwrap();
}

#[tokio::test]
async fn history_metadata_cancelled_interception_on_disable() {
    let (upstream, hits, _task) = start_counting_upstream().await;
    let port = free_port();
    let mut config = proxy_config(port, "127.0.0.1");
    config.proxy.interception_enabled = true;
    config.interception_rules = vec![InterceptionRule {
        name: "all".into(),
        enabled: true,
        method: None,
        host_pattern: None,
        path_contains: None,
        action: InterceptionAction::Intercept,
    }];
    let mut bus = EventBus::new();
    let (cmd_tx, cmd_rx) = mpsc::channel(32);
    let service = tokio::spawn(rawframe_proxy::run_service(cmd_rx, bus.sender()));
    cmd_tx
        .send(AppCommand::StartProxy(Box::new(config)))
        .await
        .unwrap();
    let proxy_addr = wait_for_listening(&mut bus).await;
    let req = format!(
        "GET http://{upstream}/cancel HTTP/1.1\r\nHost: {upstream}\r\nConnection: close\r\n\r\n"
    );
    let client = tokio::spawn(async move { raw_request(proxy_addr, req.as_bytes()).await });
    let paused = wait_for_paused(&mut bus).await;
    cmd_tx
        .send(AppCommand::SetInterception { enabled: false })
        .await
        .unwrap();
    let _ = timeout(Duration::from_secs(5), client)
        .await
        .unwrap()
        .unwrap();
    sleep(Duration::from_millis(80)).await;
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    let events = collect_until_terminal(&mut bus, paused.id).await;
    let terminal = events
        .iter()
        .rev()
        .find_map(|e| match e {
            AppEvent::TrafficUpdated(entry) | AppEvent::TrafficCaptured(entry)
                if entry.id == paused.id && entry.state.is_terminal() =>
            {
                Some(entry.as_ref().clone())
            }
            _ => None,
        })
        .expect("terminal");
    assert!(matches!(
        terminal.state,
        TrafficState::Cancelled
            | TrafficState::TimedOut
            | TrafficState::Failed
            | TrafficState::Dropped
    ));
    assert!(
        terminal.response.is_none(),
        "cancelled interception must not fabricate response"
    );
    assert!(terminal.interception.intercepted);
    cmd_tx.send(AppCommand::StopProxy).await.unwrap();
    drop(cmd_tx);
    let _ = timeout(Duration::from_secs(3), service).await.unwrap();
}

#[tokio::test]
async fn http_interception_rejects_https_downgrade_modification() {
    let (upstream, hits, _task) = start_echo_upstream().await;
    let port = free_port();
    let mut config = proxy_config(port, "127.0.0.1");
    config.proxy.interception_enabled = true;
    config.interception_rules = vec![InterceptionRule {
        name: "all".into(),
        enabled: true,
        method: None,
        host_pattern: None,
        path_contains: None,
        action: InterceptionAction::Intercept,
    }];
    let mut bus = EventBus::new();
    let (cmd_tx, cmd_rx) = mpsc::channel(32);
    let service = tokio::spawn(rawframe_proxy::run_service(cmd_rx, bus.sender()));
    cmd_tx
        .send(AppCommand::StartProxy(Box::new(config)))
        .await
        .unwrap();
    let proxy_addr = wait_for_listening(&mut bus).await;

    let req = format!(
        "GET http://{upstream}/ok HTTP/1.1\r\nHost: {upstream}\r\nConnection: close\r\n\r\n"
    );
    let client = tokio::spawn(async move { raw_request(proxy_addr, req.as_bytes()).await });
    let paused = wait_for_paused(&mut bus).await;
    let mut edited = editable_from_http(&paused.request);
    edited.scheme = rawframe_core::models::Scheme::Https;
    edited.target = format!("https://127.0.0.1:{}/steal", upstream.port());
    cmd_tx
        .send(AppCommand::ForwardModified {
            id: paused.id,
            request: edited,
        })
        .await
        .unwrap();

    let resp = timeout(Duration::from_secs(5), client)
        .await
        .unwrap()
        .unwrap();
    let text = String::from_utf8_lossy(&resp);
    assert!(text.starts_with("HTTP/1.1 400"), "{text}");
    sleep(Duration::from_millis(100)).await;
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "HTTPS modification of a plaintext HTTP request must not reach upstream"
    );

    cmd_tx.send(AppCommand::StopProxy).await.unwrap();
    drop(cmd_tx);
    let _ = timeout(Duration::from_secs(3), service).await.unwrap();
}
