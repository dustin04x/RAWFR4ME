//! Genuine HTTP/2 proxy tests.
//!
//! Every test negotiates ALPN over a real TLS handshake and speaks the actual
//! HTTP/2 framing protocol with hyper. Nothing here mocks protocol negotiation.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, Version};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rawframe_core::models::traffic::{TrafficEntry, TrafficState};
use rawframe_core::models::{AppConfig, Scheme, Scope, ScopeRule};
use rawframe_core::{AppEvent, EventBus};
use rawframe_proxy::{InterceptDecision, ProxyHandle, start_proxy};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
use tokio_rustls::{TlsAcceptor, TlsConnector};

fn temp_dir(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "rawframe-h2-test-{name}-{nanos}-{}",
        std::process::id()
    ))
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    listener.local_addr().unwrap().port()
}

struct TestCa {
    cert_der: CertificateDer<'static>,
    cert: rcgen::Certificate,
    key: KeyPair,
    path: PathBuf,
}

fn make_ca(dir: &Path) -> TestCa {
    std::fs::create_dir_all(dir).unwrap();
    let mut params = CertificateParams::default();
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(DnType::CommonName, "RAWFRAME HTTP/2 Test CA");
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    let cert_pem = cert.pem();
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let path = dir.join("upstream-ca.pem");
    std::fs::write(&path, &cert_pem).unwrap();
    TestCa {
        cert_der,
        cert,
        key,
        path,
    }
}

fn server_config(ca: &TestCa, alpn: &[&[u8]]) -> ServerConfig {
    let names = ["localhost"];
    let mut params =
        CertificateParams::new(names.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(DnType::CommonName, names[0]);
    params.distinguished_name = dn;
    params.subject_alt_names = names
        .iter()
        .map(|name| SanType::DnsName((*name).try_into().unwrap()))
        .collect();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let key = KeyPair::generate().unwrap();
    let cert = params.signed_by(&key, &ca.cert, &ca.key).unwrap();
    let chain = vec![
        CertificateDer::from(cert.der().to_vec()),
        ca.cert_der.clone(),
    ];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    config
}

/// One observed upstream request, proving which protocol actually arrived.
type Seen = Arc<Mutex<Vec<String>>>;

async fn echo(request: Request<Incoming>, seen: Seen) -> Result<Response<Full<Bytes>>, Infallible> {
    let version = request.version();
    let method = request.method().to_string();
    let path = request.uri().path().to_string();
    let authority = request
        .uri()
        .authority()
        .map(|a| a.to_string())
        .unwrap_or_default();
    let x_test = request
        .headers()
        .get("x-test")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let body = request.into_body().collect().await.unwrap().to_bytes();
    seen.lock().await.push(format!(
        "version={version:?} method={method} path={path} authority={authority} x-test={x_test} body={}",
        String::from_utf8_lossy(&body)
    ));
    let payload = format!(
        "echo version={version:?} method={method} path={path} x-test={x_test} body={}",
        String::from_utf8_lossy(&body)
    );
    Ok(Response::new(Full::new(Bytes::from(payload))))
}

/// TLS origin that serves whichever protocol ALPN selected.
async fn spawn_tls_origin(
    ca: &TestCa,
    alpn: &'static [&'static [u8]],
) -> (SocketAddr, Seen, JoinHandle<()>) {
    let config = server_config(ca, alpn);
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let seen_task = seen.clone();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            let seen = seen_task.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
                let service = service_fn(move |request| {
                    let seen = seen.clone();
                    async move { echo(request, seen).await }
                });
                if h2 {
                    let builder = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
                    let _ = builder.serve_connection(TokioIo::new(tls), service).await;
                } else {
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(tls), service)
                        .await;
                }
            });
        }
    });
    (addr, seen, task)
}

fn proxy_config(port: u16, ca_dir: &Path, trust_file: &Path) -> AppConfig {
    let mut config = AppConfig::default();
    config.proxy.port = port;
    config.proxy.bind_address = "127.0.0.1".parse().unwrap();
    config.proxy.allow_private_upstreams = true;
    config.proxy.scope = Scope::allow(ScopeRule::host("localhost"));
    config.proxy.connect_timeout_secs = 2;
    config.proxy.upstream_timeout_secs = 4;
    config.proxy.idle_timeout_secs = 3;
    config.proxy.max_body_bytes = 8192;
    config.proxy.max_response_bytes = 8192;
    config.proxy.max_connections = 8;
    config.proxy.tls_interception_enabled = true;
    config.proxy.tls_ca_dir = ca_dir.to_path_buf();
    config.proxy.tls_upstream_trust_file = Some(trust_file.to_path_buf());
    config
}

async fn start_proxy_with(
    ca: &TestCa,
    interception: bool,
    timeout_secs: u64,
) -> (ProxyHandle, SocketAddr, EventBus, PathBuf) {
    let ca_dir = temp_dir("proxy-ca");
    let port = free_port();
    let mut config = proxy_config(port, &ca_dir, &ca.path);
    config.proxy.interception_enabled = interception;
    config.proxy.intercept_timeout_secs = timeout_secs;
    let bus = EventBus::new();
    let handle = start_proxy(config, bus.sender(), Arc::new(AtomicU64::new(2000)))
        .await
        .unwrap();
    let addr = handle.local_addr();
    (handle, addr, bus, ca_dir)
}

async fn wait_tls_ready(bus: &mut EventBus) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        while let Some(event) = bus.poll() {
            if let AppEvent::TlsStateChanged(status) = event
                && status.enabled
            {
                return;
            }
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("TLS interception runtime did not become ready");
        }
        sleep(Duration::from_millis(10)).await;
    }
}

async fn raw_connect(proxy: SocketAddr, authority: &str) -> TcpStream {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    let request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 1];
    while !buffer.ends_with(b"\r\n\r\n") {
        let read = timeout(Duration::from_secs(3), stream.read(&mut chunk))
            .await
            .unwrap()
            .unwrap();
        assert!(read > 0, "proxy closed before CONNECT response");
        buffer.push(chunk[0]);
    }
    let text = String::from_utf8_lossy(&buffer).to_string();
    let status: u16 = text
        .split_whitespace()
        .nth(1)
        .expect("CONNECT status line")
        .parse()
        .expect("CONNECT status code");
    if status != 200 {
        let mut body = Vec::new();
        let _ = timeout(Duration::from_secs(1), stream.read_to_end(&mut body)).await;
        panic!("CONNECT rejected: {text}{}", String::from_utf8_lossy(&body));
    }
    stream
}

fn client_config(ca_der: CertificateDer<'static>, alpn: &[&[u8]]) -> ClientConfig {
    let mut roots = RootCertStore::empty();
    roots.add(ca_der).unwrap();
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    config
}

async fn tls_connect(
    stream: TcpStream,
    ca_der: CertificateDer<'static>,
    sni: &str,
    alpn: &[&[u8]],
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let connector = TlsConnector::from(Arc::new(client_config(ca_der, alpn)));
    let name = ServerName::try_from(sni.to_string()).unwrap();
    connector.connect(name, stream).await.unwrap()
}

fn proxy_ca(ca_dir: &Path) -> CertificateDer<'static> {
    let pem = std::fs::read(ca_dir.join("rawframe-ca.crt.pem")).unwrap();
    rustls_pemfile::certs(&mut std::io::Cursor::new(pem))
        .next()
        .unwrap()
        .unwrap()
}

async fn h2_sender(
    tls: tokio_rustls::client::TlsStream<TcpStream>,
) -> hyper::client::conn::http2::SendRequest<Full<Bytes>> {
    let (sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
            .await
            .expect("HTTP/2 handshake over the intercepted TLS session");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    sender
}

fn h2_request(port: u16, path: &str, body: &str, x_test: &str) -> Request<Full<Bytes>> {
    Request::builder()
        .method("POST")
        .uri(format!("https://localhost:{port}{path}"))
        .version(Version::HTTP_2)
        .header("x-test", x_test)
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}

async fn collect_until(
    bus: &mut EventBus,
    duration: Duration,
    mut predicate: impl FnMut(&[TrafficEntry]) -> bool,
) -> Vec<TrafficEntry> {
    let deadline = tokio::time::Instant::now() + duration;
    let mut entries: Vec<TrafficEntry> = Vec::new();
    while tokio::time::Instant::now() < deadline {
        while let Some(event) = bus.poll() {
            match event {
                AppEvent::TrafficCaptured(entry) | AppEvent::TrafficUpdated(entry) => {
                    entries.push(*entry)
                }
                _ => {}
            }
        }
        if predicate(&entries) {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }
    entries
}

async fn wait_for_paused(bus: &mut EventBus, expected: usize) -> Vec<TrafficEntry> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
    let mut paused = Vec::new();
    while tokio::time::Instant::now() < deadline {
        while let Some(event) = bus.poll() {
            if let AppEvent::InterceptionPaused(entry) = event {
                paused.push(*entry);
            }
        }
        if paused.len() >= expected {
            return paused;
        }
        sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for {expected} paused HTTP/2 streams; saw {paused:?}");
}

#[tokio::test]
async fn shutdown_cancels_paused_h2_streams_without_hanging() {
    let ca = make_ca(&temp_dir("shutdown-ca"));
    let (origin, _seen, origin_task) = spawn_tls_origin(&ca, &[b"h2"]).await;
    let (handle, proxy, mut bus, ca_dir) = start_proxy_with(&ca, true, 30).await;

    wait_tls_ready(&mut bus).await;
    let connect = raw_connect(proxy, &format!("localhost:{}", origin.port())).await;
    let ca_der = proxy_ca(&ca_dir);
    let tls = tls_connect(connect, ca_der, "localhost", &[b"h2"]).await;
    let sender = h2_sender(tls).await;

    let pending = tokio::spawn({
        let mut sender = sender.clone();
        let port = origin.port();
        async move {
            sender
                .send_request(h2_request(port, "/shutdown", "x", "y"))
                .await
        }
    });
    let paused = wait_for_paused(&mut bus, 1).await;
    assert_eq!(paused[0].state, TrafficState::Paused);

    handle.shutdown().await;

    // The stream must be released rather than waiting for the interception
    // timeout, and the pending entry must be recorded as cancelled.
    let completed = timeout(Duration::from_secs(3), pending)
        .await
        .expect("shutdown must release the paused stream");
    let _ = completed;
    let entries = collect_until(&mut bus, Duration::from_secs(2), |entries| {
        entries.iter().any(|e| e.state == TrafficState::Cancelled)
    })
    .await;
    assert!(
        entries
            .iter()
            .any(|e| e.state == TrafficState::Cancelled && e.request.target == "/shutdown"),
        "{entries:?}"
    );

    origin_task.abort();
    let _ = std::fs::remove_dir_all(ca_dir);
}

#[tokio::test]
async fn client_reset_while_paused_cancels_the_decision_and_keeps_the_connection_usable() {
    let ca = make_ca(&temp_dir("reset-ca"));
    let (origin, seen, origin_task) = spawn_tls_origin(&ca, &[b"h2", b"http/1.1"]).await;
    let (handle, proxy, mut bus, ca_dir) = start_proxy_with(&ca, true, 30).await;

    wait_tls_ready(&mut bus).await;
    let connect = raw_connect(proxy, &format!("localhost:{}", origin.port())).await;
    let ca_der = proxy_ca(&ca_dir);
    let tls = tls_connect(connect, ca_der, "localhost", &[b"h2"]).await;
    let sender = h2_sender(tls).await;

    // Dropping a hyper HTTP/2 response future is the supported way for a client
    // to cancel a stream: hyper sends RST_STREAM(CANCEL). The proxy must then
    // release the pending interception instead of holding it until the timeout.
    let abandoned = sender
        .clone()
        .send_request(h2_request(origin.port(), "/reset-me", "x", "y"));
    let paused = wait_for_paused(&mut bus, 1).await;
    assert_eq!(paused[0].request.target, "/reset-me");
    drop(abandoned);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut cancelled = false;
    let mut queue_empty = false;
    while tokio::time::Instant::now() < deadline && !(cancelled && queue_empty) {
        while let Some(event) = bus.poll() {
            match event {
                AppEvent::TrafficUpdated(entry)
                    if entry.request.target == "/reset-me"
                        && entry.state == TrafficState::Cancelled =>
                {
                    cancelled = true;
                }
                AppEvent::InterceptionQueueChanged { pending: 0, .. } => queue_empty = true,
                _ => {}
            }
        }
        sleep(Duration::from_millis(10)).await;
    }
    assert!(cancelled, "a reset stream must be recorded as cancelled");
    assert!(queue_empty, "the pending interception queue must drain");
    assert!(
        seen.lock().await.is_empty(),
        "a reset stream must never be forwarded upstream"
    );

    // The connection and its remaining stream capacity are intact: a later
    // request on the same sender can still be paused, forwarded, and answered.
    let next = tokio::spawn({
        let mut sender = sender.clone();
        let port = origin.port();
        async move {
            sender
                .send_request(h2_request(port, "/after-reset", "ok", "z"))
                .await
        }
    });
    let paused = wait_for_paused(&mut bus, 1).await;
    assert_eq!(paused[0].request.target, "/after-reset");
    handle
        .resolve_interception(paused[0].id, InterceptDecision::ForwardUnchanged)
        .await;
    let response = timeout(Duration::from_secs(4), next)
        .await
        .expect("stream after a reset must complete")
        .unwrap()
        .expect("response after reset");
    let body = timeout(Duration::from_secs(4), response.into_body().collect())
        .await
        .expect("response body after reset")
        .unwrap()
        .to_bytes();
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("path=/after-reset"), "{text}");

    handle.shutdown().await;
    origin_task.abort();
    let _ = std::fs::remove_dir_all(ca_dir);
}

#[tokio::test]
async fn intercepted_https_negotiates_h2_on_both_legs_and_multiplexes() {
    let ca = make_ca(&temp_dir("shared-ca"));
    let (origin, seen, origin_task) = spawn_tls_origin(&ca, &[b"h2", b"http/1.1"]).await;
    let (handle, proxy, mut bus, ca_dir) = start_proxy_with(&ca, false, 2).await;

    wait_tls_ready(&mut bus).await;
    let connect = raw_connect(proxy, &format!("localhost:{}", origin.port())).await;
    let ca_der = proxy_ca(&ca_dir);
    let tls = tls_connect(connect, ca_der, "localhost", &[b"h2"]).await;
    assert_eq!(
        tls.get_ref().1.alpn_protocol(),
        Some(&b"h2"[..]),
        "client-facing leg must negotiate h2"
    );
    let sender = h2_sender(tls).await;

    // Two streams are dispatched before either response is read, so they are
    // genuinely in flight at the same time over one connection.
    let first = sender
        .clone()
        .send_request(h2_request(origin.port(), "/one", "first", "alpha"))
        .await
        .unwrap();
    let second = sender
        .clone()
        .send_request(h2_request(origin.port(), "/two", "second", "beta"))
        .await
        .unwrap();
    assert_eq!(first.version(), Version::HTTP_2);
    assert_eq!(second.version(), Version::HTTP_2);
    let first_body = first.into_body().collect().await.unwrap().to_bytes();
    let second_body = second.into_body().collect().await.unwrap().to_bytes();
    let first_text = String::from_utf8_lossy(&first_body);
    let second_text = String::from_utf8_lossy(&second_body);
    assert!(first_text.contains("path=/one"), "{first_text}");
    assert!(first_text.contains("x-test=alpha"), "{first_text}");
    assert!(first_text.contains("body=first"), "{first_text}");
    assert!(second_text.contains("path=/two"), "{second_text}");
    assert!(second_text.contains("body=second"), "{second_text}");

    let observed = seen.lock().await.clone();
    assert_eq!(observed.len(), 2, "upstream saw {observed:?}");
    assert!(
        observed
            .iter()
            .all(|line| line.contains("version=HTTP/2.0")),
        "upstream leg must be HTTP/2: {observed:?}"
    );
    assert!(
        observed
            .iter()
            .any(|line| line.contains("authority=localhost:")),
        ":authority must be carried: {observed:?}"
    );

    let entries = collect_until(&mut bus, Duration::from_secs(3), |entries| {
        entries
            .iter()
            .filter(|e| e.state == TrafficState::Completed && e.request.target.starts_with('/'))
            .count()
            >= 2
    })
    .await;
    let completed: Vec<_> = entries
        .iter()
        .filter(|e| e.state == TrafficState::Completed && e.request.target.starts_with('/'))
        .collect();
    assert_eq!(completed.len(), 2, "captured {entries:?}");
    for entry in completed {
        assert_eq!(entry.request.version, "HTTP/2.0");
        assert_eq!(
            entry.response.as_ref().expect("response").version,
            "HTTP/2.0"
        );
        // Pseudo-headers are structured fields, never captured as ordinary
        // headers that a later HTTP/1.1 consumer could mistake for real fields.
        assert!(
            entry
                .request
                .headers
                .iter()
                .all(|header| !header.name.starts_with(':')),
            "pseudo-headers leaked into the capture: {:?}",
            entry.request.headers
        );
        assert_eq!(entry.request.host, "localhost");
        assert_eq!(entry.request.port, origin.port());
    }

    handle.shutdown().await;
    origin_task.abort();
    let _ = std::fs::remove_dir_all(ca_dir);
}

#[tokio::test]
async fn h2_client_to_http11_upstream_is_bridged_with_truthful_versions() {
    let ca = make_ca(&temp_dir("shared-ca"));
    let (origin, seen, origin_task) = spawn_tls_origin(&ca, &[b"http/1.1"]).await;
    let (handle, proxy, mut bus, ca_dir) = start_proxy_with(&ca, false, 2).await;

    wait_tls_ready(&mut bus).await;
    let connect = raw_connect(proxy, &format!("localhost:{}", origin.port())).await;
    let ca_der = proxy_ca(&ca_dir);
    let tls = tls_connect(connect, ca_der, "localhost", &[b"h2"]).await;
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
    let sender = h2_sender(tls).await;

    let mut sender = sender;
    let response = sender
        .send_request(h2_request(origin.port(), "/bridge", "payload", "gamma"))
        .await
        .unwrap();
    assert_eq!(response.version(), Version::HTTP_2);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("path=/bridge"), "{text}");
    assert!(text.contains("body=payload"), "{text}");

    let observed = seen.lock().await.clone();
    assert_eq!(observed.len(), 1, "{observed:?}");
    assert!(
        observed[0].contains("version=HTTP/1.1"),
        "upstream must remain HTTP/1.1: {observed:?}"
    );

    let entries = collect_until(&mut bus, Duration::from_secs(3), |entries| {
        entries
            .iter()
            .any(|e| e.state == TrafficState::Completed && e.request.target == "/bridge")
    })
    .await;
    let entry = entries
        .iter()
        .find(|e| e.state == TrafficState::Completed && e.request.target == "/bridge")
        .expect("completed entry");
    assert_eq!(entry.request.version, "HTTP/2.0");
    assert_eq!(
        entry.response.as_ref().expect("response").version,
        "HTTP/1.1",
        "the response version must report the upstream protocol, not the client's"
    );

    handle.shutdown().await;
    origin_task.abort();
    let _ = std::fs::remove_dir_all(ca_dir);
}

#[tokio::test]
async fn http11_client_and_h2_upstream_negotiate_independently() {
    let ca = make_ca(&temp_dir("shared-ca"));
    let (origin, seen, origin_task) = spawn_tls_origin(&ca, &[b"h2", b"http/1.1"]).await;
    let (handle, proxy, mut bus, ca_dir) = start_proxy_with(&ca, false, 2).await;

    wait_tls_ready(&mut bus).await;
    let connect = raw_connect(proxy, &format!("localhost:{}", origin.port())).await;
    let ca_der = proxy_ca(&ca_dir);
    let mut tls = tls_connect(connect, ca_der, "localhost", &[b"http/1.1"]).await;
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"http/1.1"[..]));
    let request = format!(
        "GET /plain HTTP/1.1\r\nHost: localhost:{}\r\nConnection: close\r\n\r\n",
        origin.port()
    );
    tls.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    let _ = timeout(Duration::from_secs(4), tls.read_to_end(&mut response)).await;
    let text = String::from_utf8_lossy(&response);
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    assert!(text.contains("path=/plain"), "{text}");

    let observed = seen.lock().await.clone();
    assert!(
        observed
            .iter()
            .all(|line| line.contains("version=HTTP/2.0")),
        "upstream leg negotiates h2 independently of the client leg: {observed:?}"
    );

    let entries = collect_until(&mut bus, Duration::from_secs(3), |entries| {
        entries
            .iter()
            .any(|e| e.state == TrafficState::Completed && e.request.target == "/plain")
    })
    .await;
    let entry = entries
        .iter()
        .find(|e| e.state == TrafficState::Completed && e.request.target == "/plain")
        .expect("captured request");
    assert_eq!(entry.request.version, "HTTP/1.1");
    assert_eq!(
        entry.response.as_ref().expect("response").version,
        "HTTP/2.0"
    );

    handle.shutdown().await;
    origin_task.abort();
    let _ = std::fs::remove_dir_all(ca_dir);
}

#[tokio::test]
async fn paused_h2_streams_do_not_block_each_other_and_drop_is_isolated() {
    let ca = make_ca(&temp_dir("shared-ca"));
    let (origin, seen, origin_task) = spawn_tls_origin(&ca, &[b"h2", b"http/1.1"]).await;
    let (handle, proxy, mut bus, ca_dir) = start_proxy_with(&ca, true, 3).await;

    wait_tls_ready(&mut bus).await;
    let connect = raw_connect(proxy, &format!("localhost:{}", origin.port())).await;
    let ca_der = proxy_ca(&ca_dir);
    let tls = tls_connect(connect, ca_der, "localhost", &[b"h2"]).await;
    let sender = h2_sender(tls).await;

    // The request futures must be driven while interception is pending, so they
    // are spawned rather than awaited in sequence.
    let first = tokio::spawn({
        let mut sender = sender.clone();
        async move {
            sender
                .send_request(h2_request(origin.port(), "/paused-one", "one", "a"))
                .await
        }
    });
    let second = tokio::spawn({
        let mut sender = sender.clone();
        async move {
            sender
                .send_request(h2_request(origin.port(), "/paused-two", "two", "b"))
                .await
        }
    });

    // Both streams reached the queue together: a single paused stream cannot
    // hold the connection's other streams.
    let paused = wait_for_paused(&mut bus, 2).await;
    let one = paused
        .iter()
        .find(|entry| entry.request.target == "/paused-one")
        .expect("first stream paused");
    let two = paused
        .iter()
        .find(|entry| entry.request.target == "/paused-two")
        .expect("second stream paused");
    assert_eq!(one.request.version, "HTTP/2.0");

    handle
        .resolve_interception(one.id, InterceptDecision::ForwardUnchanged)
        .await;
    let first = first.await.unwrap().expect("forwarded stream response");
    let forwarded = timeout(Duration::from_secs(4), first.into_body().collect())
        .await
        .expect("forwarded stream completed")
        .unwrap()
        .to_bytes();
    let forwarded_text = String::from_utf8_lossy(&forwarded).to_string();
    assert!(
        forwarded_text.contains("path=/paused-one"),
        "stream association must survive interception: {forwarded_text}"
    );

    handle
        .resolve_interception(two.id, InterceptDecision::Drop)
        .await;
    let second = second.await.unwrap();
    let dropped = match second {
        Ok(response) => timeout(Duration::from_secs(4), response.into_body().collect()).await,
        Err(error) => panic!("dropped stream failed before a response: {error}"),
    };
    // A dropped request is answered with 403 on its own stream; the sibling
    // stream above already completed normally.
    match dropped {
        Ok(Ok(collected)) => {
            let text = String::from_utf8_lossy(&collected.to_bytes()).to_string();
            assert!(
                !text.contains("path=/paused-two"),
                "dropped stream was forwarded: {text}"
            );
        }
        Ok(Err(error)) => panic!("dropped stream body failed: {error}"),
        Err(_) => panic!("dropped stream did not receive a response"),
    }

    let observed = seen.lock().await.clone();
    assert_eq!(
        observed.len(),
        1,
        "dropped request reached upstream: {observed:?}"
    );
    assert!(observed[0].contains("path=/paused-one"));

    let entries = collect_until(&mut bus, Duration::from_secs(3), |entries| {
        entries.iter().any(|e| e.state == TrafficState::Dropped)
            && entries.iter().any(|e| e.state == TrafficState::Completed)
    })
    .await;
    assert!(
        entries
            .iter()
            .any(|e| e.state == TrafficState::Dropped && e.request.target == "/paused-two"),
        "{entries:?}"
    );

    handle.shutdown().await;
    origin_task.abort();
    let _ = std::fs::remove_dir_all(ca_dir);
}

#[tokio::test]
async fn modified_h2_request_is_forwarded_as_http2() {
    use rawframe_core::models::Headers;
    use rawframe_core::models::traffic::EditableHttpRequest;

    let ca = make_ca(&temp_dir("shared-ca"));
    let (origin, seen, origin_task) = spawn_tls_origin(&ca, &[b"h2", b"http/1.1"]).await;
    let (handle, proxy, mut bus, ca_dir) = start_proxy_with(&ca, true, 3).await;

    wait_tls_ready(&mut bus).await;
    let connect = raw_connect(proxy, &format!("localhost:{}", origin.port())).await;
    let ca_der = proxy_ca(&ca_dir);
    let tls = tls_connect(connect, ca_der, "localhost", &[b"h2"]).await;
    let sender = h2_sender(tls).await;

    let pending =
        sender
            .clone()
            .send_request(h2_request(origin.port(), "/original", "before", "orig"));
    let paused = wait_for_paused(&mut bus, 1).await;
    let paused = &paused[0];
    assert_eq!(paused.request.version, "HTTP/2.0");

    let edited = EditableHttpRequest {
        method: "POST".to_string(),
        target: format!("https://localhost:{}/modified", origin.port()),
        // Deliberately stale: the wire protocol is negotiated, not authored, so
        // the captured entry must still report the real HTTP/2 client protocol.
        version: "HTTP/1.1".to_string(),
        host: "localhost".to_string(),
        port: origin.port(),
        scheme: Scheme::Https,
        headers: Headers::from_pairs([
            ("x-test", "edited".to_string()),
            ("connection", "close".to_string()),
            ("transfer-encoding", "chunked".to_string()),
        ]),
        body: b"edited-body".to_vec(),
    };
    handle
        .resolve_interception(paused.id, InterceptDecision::ForwardModified(edited))
        .await;

    let response = timeout(Duration::from_secs(4), pending)
        .await
        .expect("modified stream completed")
        .unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("path=/modified"), "{text}");
    assert!(text.contains("x-test=edited"), "{text}");
    assert!(text.contains("body=edited-body"), "{text}");

    let observed = seen.lock().await.clone();
    assert_eq!(observed.len(), 1, "{observed:?}");
    assert!(
        observed[0].contains("version=HTTP/2.0"),
        "modified request must stay HTTP/2: {observed:?}"
    );
    assert!(
        !observed[0].contains("transfer-encoding"),
        "connection-specific fields must be stripped: {observed:?}"
    );

    let entries = collect_until(&mut bus, Duration::from_secs(3), |entries| {
        entries.iter().any(|e| e.state == TrafficState::Completed)
    })
    .await;
    assert!(entries.iter().any(|entry| {
        entry.state == TrafficState::Completed
            && entry.interception.modified
            && entry.request.target == "/modified"
            && entry.request.body == b"edited-body"
            && entry.request.version == "HTTP/2.0"
            && entry
                .response
                .as_ref()
                .is_some_and(|response| response.version == "HTTP/2.0")
    }));

    handle.shutdown().await;
    origin_task.abort();
    let _ = std::fs::remove_dir_all(ca_dir);
}

#[tokio::test]
async fn paused_h2_stream_times_out_without_blocking_the_connection() {
    let ca = make_ca(&temp_dir("shared-ca"));
    let (origin, _seen, origin_task) = spawn_tls_origin(&ca, &[b"h2", b"http/1.1"]).await;
    let (handle, proxy, mut bus, ca_dir) = start_proxy_with(&ca, true, 1).await;

    wait_tls_ready(&mut bus).await;
    let connect = raw_connect(proxy, &format!("localhost:{}", origin.port())).await;
    let ca_der = proxy_ca(&ca_dir);
    let tls = tls_connect(connect, ca_der, "localhost", &[b"h2"]).await;
    let sender = h2_sender(tls).await;

    let pending = sender
        .clone()
        .send_request(h2_request(origin.port(), "/slow", "x", "y"));
    let _ = wait_for_paused(&mut bus, 1).await;
    let response = timeout(Duration::from_secs(5), pending)
        .await
        .expect("timed-out stream must be answered")
        .unwrap();
    assert_eq!(response.status(), 504);

    let entries = collect_until(&mut bus, Duration::from_secs(3), |entries| {
        entries.iter().any(|e| e.state == TrafficState::TimedOut)
    })
    .await;
    assert!(
        entries
            .iter()
            .any(|e| e.state == TrafficState::TimedOut && e.request.target == "/slow"),
        "{entries:?}"
    );

    handle.shutdown().await;
    origin_task.abort();
    let _ = std::fs::remove_dir_all(ca_dir);
}
