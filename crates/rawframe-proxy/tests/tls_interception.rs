use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use rawframe_core::models::traffic::{TrafficKind, TrafficState};
use rawframe_core::models::{AppConfig, Scheme, Scope, ScopeRule};
use rawframe_core::{AppEvent, EventBus, TlsStatus};
use rawframe_proxy::{ProxyHandle, start_proxy};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
use tokio_rustls::{TlsAcceptor, TlsConnector};

fn temp_dir(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "rawframe-tls-test-{name}-{nanos}-{}",
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
    dn.push(DnType::CommonName, "RAWFRAME Test Upstream CA");
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

fn server_config(ca: &TestCa, names: &[&str]) -> ServerConfig {
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
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config
}

async fn spawn_https_upstream(
    server_config: ServerConfig,
) -> (SocketAddr, Arc<AtomicUsize>, JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_task = hits.clone();
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            let hits = hits_task.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let service = service_fn(move |req: Request<Incoming>| {
                    let hits = hits.clone();
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        let method = req.method().to_string();
                        let path = req.uri().path().to_string();
                        let x_test = req
                            .headers()
                            .get("x-test")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("")
                            .to_string();
                        let body = req.into_body().collect().await.unwrap().to_bytes();
                        let payload = format!(
                            "https-upstream method={method} path={path} x-test={x_test} body={}",
                            String::from_utf8_lossy(&body)
                        );
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(payload))))
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), service)
                    .await;
            });
        }
    });
    (addr, hits, task)
}

fn proxy_config(port: u16, tls: bool, ca_dir: &Path, trust_file: Option<&Path>) -> AppConfig {
    let mut config = AppConfig::default();
    config.proxy.port = port;
    config.proxy.bind_address = "127.0.0.1".parse().unwrap();
    config.proxy.allow_private_upstreams = true;
    config.proxy.scope = Scope::allow(ScopeRule::host("localhost"));
    config.proxy.connect_timeout_secs = 2;
    config.proxy.upstream_timeout_secs = 2;
    config.proxy.idle_timeout_secs = 3;
    config.proxy.max_body_bytes = 4096;
    config.proxy.max_response_bytes = 4096;
    config.proxy.max_connections = 8;
    config.proxy.tls_interception_enabled = tls;
    config.proxy.tls_ca_dir = ca_dir.to_path_buf();
    config.proxy.tls_upstream_trust_file = trust_file.map(|p| p.to_path_buf());
    config
}

async fn start_tls_proxy(
    tls: bool,
    ca_dir: &Path,
    trust_file: Option<&Path>,
    interception: bool,
) -> (ProxyHandle, SocketAddr, EventBus) {
    let port = free_port();
    let bus = EventBus::new();
    let mut config = proxy_config(port, tls, ca_dir, trust_file);
    config.proxy.interception_enabled = interception;
    let handle = start_proxy(config, bus.sender(), Arc::new(AtomicU64::new(1000)))
        .await
        .unwrap();
    let addr = handle.local_addr();
    (handle, addr, bus)
}

async fn raw_connect(proxy: SocketAddr, authority: &str) -> (TcpStream, u16) {
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
    let text = String::from_utf8_lossy(&buffer);
    let status = text
        .split_whitespace()
        .nth(1)
        .expect("CONNECT status line")
        .parse()
        .expect("CONNECT status code");
    (stream, status)
}

fn client_config(ca_der: CertificateDer<'static>) -> ClientConfig {
    let mut roots = RootCertStore::empty();
    roots.add(ca_der).unwrap();
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config
}

async fn tls_connect(
    stream: TcpStream,
    ca_der: CertificateDer<'static>,
    sni: &str,
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let connector = TlsConnector::from(Arc::new(client_config(ca_der)));
    let name = ServerName::try_from(sni.to_string()).unwrap();
    connector.connect(name, stream).await.unwrap()
}

async fn send_http_over_tls(
    stream: &mut tokio_rustls::client::TlsStream<TcpStream>,
    request: &[u8],
) -> Vec<u8> {
    stream.write_all(request).await.unwrap();
    stream.flush().await.unwrap();
    let mut bytes = Vec::new();
    let _ = timeout(Duration::from_secs(5), stream.read_to_end(&mut bytes)).await;
    bytes
}

async fn wait_for_status(bus: &mut EventBus) -> TlsStatus {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        while let Some(event) = bus.poll() {
            if let AppEvent::TlsStateChanged(status) = event {
                return status;
            }
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("timed out waiting for TLS state");
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
            panic!("timed out waiting for paused HTTPS interception");
        }
        sleep(Duration::from_millis(10)).await;
    }
}

async fn collect_traffic(
    bus: &mut EventBus,
    duration: Duration,
) -> Vec<rawframe_core::models::TrafficEntry> {
    let deadline = tokio::time::Instant::now() + duration;
    let mut entries = Vec::new();
    while tokio::time::Instant::now() < deadline {
        while let Some(event) = bus.poll() {
            match event {
                AppEvent::TrafficCaptured(entry) | AppEvent::TrafficUpdated(entry) => {
                    entries.push(*entry)
                }
                _ => {}
            }
        }
        sleep(Duration::from_millis(10)).await;
    }
    entries
}

#[tokio::test]
async fn disabled_interception_preserves_opaque_tunnel() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let upstream_addr = listener.local_addr().unwrap();
    let received = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let received_task = received.clone();
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let read = stream.read(&mut chunk).await.unwrap();
            if read == 0 {
                break;
            }
            buffer.extend_from_slice(&chunk[..read]);
            if buffer.len() >= 6 {
                let _ = stream.write_all(b"opaque-ok").await;
                break;
            }
        }
        *received_task.lock().await = buffer;
    });

    let ca_dir = temp_dir("opaque-ca");
    let (handle, proxy, mut bus) = start_tls_proxy(false, &ca_dir, None, false).await;
    let status = wait_for_status(&mut bus).await;
    assert!(!status.enabled);

    let (mut stream, status) =
        raw_connect(proxy, &format!("localhost:{}", upstream_addr.port())).await;
    assert_eq!(status, 200);
    stream.write_all(b"secret").await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    assert_eq!(response, b"opaque-ok");
    upstream.await.unwrap();
    assert_eq!(&*received.lock().await, b"secret");

    let entries = collect_traffic(&mut bus, Duration::from_millis(300)).await;
    assert!(
        entries
            .iter()
            .any(|entry| entry.kind == TrafficKind::ConnectTunnel),
        "opaque CONNECT should be recorded as a tunnel"
    );
    assert!(
        !entries
            .iter()
            .any(|entry| entry.kind == TrafficKind::Http && entry.request.scheme == Scheme::Https),
        "opaque tunnel must not be represented as decrypted HTTPS"
    );
    handle.shutdown().await;
    let _ = std::fs::remove_dir_all(ca_dir);
}

#[tokio::test]
async fn enabled_interception_decrypts_http11_and_serves_upstream_response() {
    let upstream_ca_dir = temp_dir("upstream-ca");
    let upstream_ca = make_ca(&upstream_ca_dir);
    let (upstream, hits, upstream_task) =
        spawn_https_upstream(server_config(&upstream_ca, &["localhost"])).await;

    let ca_dir = temp_dir("intercept-ca");
    let (handle, proxy, mut bus) =
        start_tls_proxy(true, &ca_dir, Some(&upstream_ca.path), false).await;
    let status = wait_for_status(&mut bus).await;
    assert!(status.enabled, "interception should be enabled");
    assert!(status.ca_fingerprint.is_some());
    assert!(
        status
            .ca_cert_path
            .as_deref()
            .is_some_and(|path| Path::new(path).exists())
    );

    let (connect, status) = raw_connect(proxy, &format!("localhost:{}", upstream.port())).await;
    assert_eq!(status, 200);

    let ca_cert = std::fs::read(ca_dir.join("rawframe-ca.crt.pem")).unwrap();
    let ca_der = rustls_pemfile::certs(&mut std::io::Cursor::new(ca_cert))
        .next()
        .unwrap()
        .unwrap();
    let mut tls = tls_connect(connect, ca_der, "localhost").await;
    let request = format!(
        "GET /secure HTTP/1.1\r\nHost: localhost:{}\r\nX-Test: decrypted\r\nConnection: close\r\n\r\n",
        upstream.port()
    );
    let response = send_http_over_tls(&mut tls, request.as_bytes()).await;
    let text = String::from_utf8_lossy(&response);
    assert!(text.contains("200 OK"), "response: {text}");
    assert!(text.contains("https-upstream method=GET path=/secure x-test=decrypted"));
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    let entries = collect_traffic(&mut bus, Duration::from_millis(500)).await;
    let decrypted = entries
        .iter()
        .find(|entry| {
            entry.kind == TrafficKind::Http
                && entry.request.scheme == Scheme::Https
                && entry.request.target == "/secure"
                && entry.state == TrafficState::Completed
        })
        .expect("decrypted HTTPS request should be captured");
    assert_eq!(decrypted.request.host, "localhost");
    assert_eq!(decrypted.response.as_ref().map(|r| r.status), Some(200));
    assert_eq!(decrypted.state, TrafficState::Completed);

    handle.shutdown().await;
    upstream_task.abort();
    let _ = std::fs::remove_dir_all(ca_dir);
    let _ = std::fs::remove_dir_all(upstream_ca_dir);
}

#[tokio::test]
async fn invalid_upstream_certificate_is_rejected_before_forwarding() {
    let other_ca_dir = temp_dir("other-ca");
    let other_ca = make_ca(&other_ca_dir);
    let (upstream, hits, upstream_task) =
        spawn_https_upstream(server_config(&other_ca, &["localhost"])).await;

    let trusted_ca_dir = temp_dir("trusted-ca");
    let trusted_ca = make_ca(&trusted_ca_dir);
    let ca_dir = temp_dir("reject-ca");
    let (handle, proxy, mut bus) =
        start_tls_proxy(true, &ca_dir, Some(&trusted_ca.path), false).await;
    let _ = wait_for_status(&mut bus).await;

    let (_connect, status) = raw_connect(proxy, &format!("localhost:{}", upstream.port())).await;
    assert_ne!(
        status, 200,
        "untrusted upstream must not get a CONNECT success"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 0);

    let entries = collect_traffic(&mut bus, Duration::from_millis(300)).await;
    assert!(
        entries.iter().any(|entry| entry
            .error
            .as_deref()
            .is_some_and(|error| error.contains("TLS"))),
        "failure should be reported on the CONNECT entry"
    );

    handle.shutdown().await;
    upstream_task.abort();
    let _ = std::fs::remove_dir_all(ca_dir);
    let _ = std::fs::remove_dir_all(trusted_ca_dir);
    let _ = std::fs::remove_dir_all(other_ca_dir);
}

#[tokio::test]
async fn sni_mismatch_fails_closed_without_upstream_request() {
    let upstream_ca_dir = temp_dir("sni-ca");
    let upstream_ca = make_ca(&upstream_ca_dir);
    let (upstream, hits, upstream_task) =
        spawn_https_upstream(server_config(&upstream_ca, &["localhost"])).await;

    let ca_dir = temp_dir("sni-intercept-ca");
    let (handle, proxy, mut bus) =
        start_tls_proxy(true, &ca_dir, Some(&upstream_ca.path), false).await;
    let _ = wait_for_status(&mut bus).await;

    let (connect, status) = raw_connect(proxy, &format!("localhost:{}", upstream.port())).await;
    assert_eq!(status, 200);
    let ca_cert = std::fs::read(ca_dir.join("rawframe-ca.crt.pem")).unwrap();
    let ca_der = rustls_pemfile::certs(&mut std::io::Cursor::new(ca_cert))
        .next()
        .unwrap()
        .unwrap();
    let connector = TlsConnector::from(Arc::new(client_config(ca_der)));
    let name = ServerName::try_from("other.localhost".to_string()).unwrap();
    let result = timeout(Duration::from_secs(3), connector.connect(name, connect)).await;
    assert!(
        result.is_err() || result.unwrap().is_err(),
        "SNI mismatch must fail the client TLS handshake"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 0);

    handle.shutdown().await;
    upstream_task.abort();
    let _ = std::fs::remove_dir_all(ca_dir);
    let _ = std::fs::remove_dir_all(upstream_ca_dir);
}

#[tokio::test]
async fn dropped_https_request_never_reaches_upstream() {
    let upstream_ca_dir = temp_dir("drop-ca");
    let upstream_ca = make_ca(&upstream_ca_dir);
    let (upstream, hits, upstream_task) =
        spawn_https_upstream(server_config(&upstream_ca, &["localhost"])).await;

    let ca_dir = temp_dir("drop-intercept-ca");
    let (handle, proxy, mut bus) =
        start_tls_proxy(true, &ca_dir, Some(&upstream_ca.path), true).await;
    let _ = wait_for_status(&mut bus).await;

    let (connect, status) = raw_connect(proxy, &format!("localhost:{}", upstream.port())).await;
    assert_eq!(status, 200);
    let ca_cert = std::fs::read(ca_dir.join("rawframe-ca.crt.pem")).unwrap();
    let ca_der = rustls_pemfile::certs(&mut std::io::Cursor::new(ca_cert))
        .next()
        .unwrap()
        .unwrap();
    let mut tls = tls_connect(connect, ca_der, "localhost").await;
    let request = format!(
        "GET /drop-me HTTP/1.1\r\nHost: localhost:{}\r\nConnection: close\r\n\r\n",
        upstream.port()
    );
    tls.write_all(request.as_bytes()).await.unwrap();
    tls.flush().await.unwrap();

    let paused = wait_for_paused(&mut bus).await;
    assert_eq!(paused.request.scheme, Scheme::Https);
    assert_eq!(paused.request.target, "/drop-me");
    handle
        .resolve_interception(paused.id, rawframe_proxy::InterceptDecision::Drop)
        .await;

    let mut response = Vec::new();
    let _ = timeout(Duration::from_secs(3), tls.read_to_end(&mut response)).await;
    let text = String::from_utf8_lossy(&response);
    assert!(text.contains("403"), "response: {text}");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "dropped request reached upstream"
    );

    let entries = collect_traffic(&mut bus, Duration::from_millis(300)).await;
    assert!(
        entries
            .iter()
            .any(|entry| entry.state == TrafficState::Dropped)
    );

    handle.shutdown().await;
    upstream_task.abort();
    let _ = std::fs::remove_dir_all(ca_dir);
    let _ = std::fs::remove_dir_all(upstream_ca_dir);
}

#[tokio::test]
async fn modified_https_request_is_forwarded_with_actual_content() {
    use rawframe_core::models::Headers;
    use rawframe_core::models::traffic::EditableHttpRequest;

    let upstream_ca_dir = temp_dir("modify-ca");
    let upstream_ca = make_ca(&upstream_ca_dir);
    let (upstream, hits, upstream_task) =
        spawn_https_upstream(server_config(&upstream_ca, &["localhost"])).await;

    let ca_dir = temp_dir("modify-intercept-ca");
    let (handle, proxy, mut bus) =
        start_tls_proxy(true, &ca_dir, Some(&upstream_ca.path), true).await;
    let _ = wait_for_status(&mut bus).await;

    let (connect, status) = raw_connect(proxy, &format!("localhost:{}", upstream.port())).await;
    assert_eq!(status, 200);
    let ca_cert = std::fs::read(ca_dir.join("rawframe-ca.crt.pem")).unwrap();
    let ca_der = rustls_pemfile::certs(&mut std::io::Cursor::new(ca_cert))
        .next()
        .unwrap()
        .unwrap();
    let mut tls = tls_connect(connect, ca_der, "localhost").await;
    let request = format!(
        "GET /original HTTP/1.1\r\nHost: localhost:{}\r\nX-Test: original\r\nConnection: close\r\n\r\n",
        upstream.port()
    );
    tls.write_all(request.as_bytes()).await.unwrap();
    tls.flush().await.unwrap();

    let paused = wait_for_paused(&mut bus).await;
    let headers = Headers::from_pairs([
        ("Host", format!("localhost:{}", upstream.port())),
        ("X-Test", "modified".to_string()),
        ("Connection", "close".to_string()),
    ]);
    let edited = EditableHttpRequest {
        method: "POST".to_string(),
        target: format!("https://localhost:{}/modified", upstream.port()),
        version: "HTTP/1.1".to_string(),
        host: "localhost".to_string(),
        port: upstream.port(),
        scheme: Scheme::Https,
        headers,
        body: b"edited-body".to_vec(),
    };
    handle
        .resolve_interception(
            paused.id,
            rawframe_proxy::InterceptDecision::ForwardModified(edited),
        )
        .await;

    let mut response = Vec::new();
    let _ = timeout(Duration::from_secs(3), tls.read_to_end(&mut response)).await;
    let text = String::from_utf8_lossy(&response);
    assert!(text.contains("200 OK"), "response: {text}");
    assert!(
        text.contains("method=POST path=/modified x-test=modified body=edited-body"),
        "upstream did not receive the modified request: {text}"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    let entries = collect_traffic(&mut bus, Duration::from_millis(400)).await;
    assert!(entries.iter().any(|entry| {
        entry.state == TrafficState::Completed
            && entry.interception.modified
            && entry.request.method == "POST"
            && entry.request.target == "/modified"
            && entry.request.body == b"edited-body"
    }));

    handle.shutdown().await;
    upstream_task.abort();
    let _ = std::fs::remove_dir_all(ca_dir);
    let _ = std::fs::remove_dir_all(upstream_ca_dir);
}

#[tokio::test]
async fn upstream_hostname_mismatch_is_rejected() {
    let upstream_ca_dir = temp_dir("hostname-ca");
    let upstream_ca = make_ca(&upstream_ca_dir);
    let (upstream, hits, upstream_task) =
        spawn_https_upstream(server_config(&upstream_ca, &["wrong.test"])).await;

    let ca_dir = temp_dir("hostname-intercept-ca");
    let (handle, proxy, mut bus) =
        start_tls_proxy(true, &ca_dir, Some(&upstream_ca.path), false).await;
    let _ = wait_for_status(&mut bus).await;

    let (_connect, status) = raw_connect(proxy, &format!("localhost:{}", upstream.port())).await;
    assert_ne!(
        status, 200,
        "hostname mismatch must not get a CONNECT success"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 0);

    handle.shutdown().await;
    upstream_task.abort();
    let _ = std::fs::remove_dir_all(ca_dir);
    let _ = std::fs::remove_dir_all(upstream_ca_dir);
}

#[tokio::test]
async fn intercepted_https_rejects_oversized_request_before_upstream() {
    let upstream_ca_dir = temp_dir("oversize-ca");
    let upstream_ca = make_ca(&upstream_ca_dir);
    let (upstream, hits, upstream_task) =
        spawn_https_upstream(server_config(&upstream_ca, &["localhost"])).await;

    let ca_dir = temp_dir("oversize-intercept-ca");
    let (handle, proxy, mut bus) =
        start_tls_proxy(true, &ca_dir, Some(&upstream_ca.path), false).await;
    let _ = wait_for_status(&mut bus).await;

    let (connect, status) = raw_connect(proxy, &format!("localhost:{}", upstream.port())).await;
    assert_eq!(status, 200);
    let ca_cert = std::fs::read(ca_dir.join("rawframe-ca.crt.pem")).unwrap();
    let ca_der = rustls_pemfile::certs(&mut std::io::Cursor::new(ca_cert))
        .next()
        .unwrap()
        .unwrap();
    let mut tls = tls_connect(connect, ca_der, "localhost").await;
    let request = format!(
        "POST /large HTTP/1.1\r\nHost: localhost:{}\r\nContent-Length: 9000\r\nConnection: close\r\n\r\n",
        upstream.port()
    );
    tls.write_all(request.as_bytes()).await.unwrap();
    tls.flush().await.unwrap();
    let mut response = Vec::new();
    let _ = timeout(Duration::from_secs(3), tls.read_to_end(&mut response)).await;
    let text = String::from_utf8_lossy(&response);
    assert!(text.contains("413"), "response: {text}");
    assert_eq!(hits.load(Ordering::SeqCst), 0);

    handle.shutdown().await;
    upstream_task.abort();
    let _ = std::fs::remove_dir_all(ca_dir);
    let _ = std::fs::remove_dir_all(upstream_ca_dir);
}

async fn read_one_http_response(stream: &mut tokio_rustls::client::TlsStream<TcpStream>) -> String {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 1024];
    let header_end = loop {
        if let Some(index) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            break index + 4;
        }
        let read = timeout(Duration::from_secs(3), stream.read(&mut chunk))
            .await
            .unwrap()
            .unwrap();
        assert!(read > 0, "connection closed before response headers");
        buffer.extend_from_slice(&chunk[..read]);
    };
    let headers = String::from_utf8_lossy(&buffer[..header_end]).to_ascii_lowercase();
    let length = headers
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    while buffer.len() < header_end + length {
        let read = timeout(Duration::from_secs(3), stream.read(&mut chunk))
            .await
            .unwrap()
            .unwrap();
        assert!(read > 0, "connection closed before response body");
        buffer.extend_from_slice(&chunk[..read]);
    }
    String::from_utf8_lossy(&buffer).to_string()
}

#[tokio::test]
async fn multiple_https_requests_reuse_one_intercepted_tls_connection() {
    let upstream_ca_dir = temp_dir("keepalive-ca");
    let upstream_ca = make_ca(&upstream_ca_dir);
    let (upstream, hits, upstream_task) =
        spawn_https_upstream(server_config(&upstream_ca, &["localhost"])).await;

    let ca_dir = temp_dir("keepalive-intercept-ca");
    let (handle, proxy, mut bus) =
        start_tls_proxy(true, &ca_dir, Some(&upstream_ca.path), false).await;
    let _ = wait_for_status(&mut bus).await;

    let (connect, status) = raw_connect(proxy, &format!("localhost:{}", upstream.port())).await;
    assert_eq!(status, 200);
    let ca_cert = std::fs::read(ca_dir.join("rawframe-ca.crt.pem")).unwrap();
    let ca_der = rustls_pemfile::certs(&mut std::io::Cursor::new(ca_cert))
        .next()
        .unwrap()
        .unwrap();
    let mut tls = tls_connect(connect, ca_der, "localhost").await;

    let first = format!(
        "GET /one HTTP/1.1\r\nHost: localhost:{}\r\n\r\n",
        upstream.port()
    );
    tls.write_all(first.as_bytes()).await.unwrap();
    let first_response = read_one_http_response(&mut tls).await;
    assert!(
        first_response.contains("method=GET path=/one"),
        "{first_response}"
    );

    let second = format!(
        "GET /two HTTP/1.1\r\nHost: localhost:{}\r\nConnection: close\r\n\r\n",
        upstream.port()
    );
    tls.write_all(second.as_bytes()).await.unwrap();
    let second_response = read_one_http_response(&mut tls).await;
    assert!(
        second_response.contains("method=GET path=/two"),
        "{second_response}"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 2);

    let entries = collect_traffic(&mut bus, Duration::from_millis(400)).await;
    assert!(entries.iter().any(|entry| {
        entry.state == TrafficState::Completed
            && entry.request.scheme == Scheme::Https
            && entry.request.target == "/one"
    }));
    assert!(entries.iter().any(|entry| {
        entry.state == TrafficState::Completed
            && entry.request.scheme == Scheme::Https
            && entry.request.target == "/two"
    }));

    handle.shutdown().await;
    upstream_task.abort();
    let _ = std::fs::remove_dir_all(ca_dir);
    let _ = std::fs::remove_dir_all(upstream_ca_dir);
}

async fn wait_for_entry_state(
    bus: &mut EventBus,
    target: &str,
    state: TrafficState,
) -> rawframe_core::models::TrafficEntry {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
    let mut seen = Vec::new();
    loop {
        while let Some(event) = bus.poll() {
            match event {
                AppEvent::TrafficCaptured(entry) | AppEvent::TrafficUpdated(entry) => {
                    seen.push((
                        entry.request.target.clone(),
                        entry.state,
                        entry.error.clone(),
                    ));
                    if entry.request.target == target && entry.state == state {
                        return *entry;
                    }
                }
                AppEvent::InterceptionQueueChanged { pending, .. } => {
                    seen.push((format!("queue:{pending}"), state, None));
                }
                _ => {}
            }
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("timed out waiting for {target} to reach {state:?}; seen={seen:?}");
        }
        sleep(Duration::from_millis(10)).await;
    }
}

async fn wait_for_cancelled_and_queue_empty(
    bus: &mut EventBus,
    target: &str,
) -> rawframe_core::models::TrafficEntry {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
    let mut cancelled = None;
    let mut drained = false;
    loop {
        while let Some(event) = bus.poll() {
            match event {
                AppEvent::TrafficCaptured(entry) | AppEvent::TrafficUpdated(entry) => {
                    if entry.request.target == target && entry.state == TrafficState::Cancelled {
                        cancelled = Some(*entry);
                    }
                }
                AppEvent::InterceptionQueueChanged { pending: 0, .. } => {
                    drained = true;
                }
                _ => {}
            }
        }
        if let Some(entry) = &cancelled
            && drained
        {
            return entry.clone();
        }
        if tokio::time::Instant::now() >= deadline {
            panic!(
                "timed out waiting for {target} cancellation and queue drain (cancelled={}, drained={drained})",
                cancelled.is_some()
            );
        }
        sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn client_disconnect_cancels_pending_https_interception() {
    let upstream_ca_dir = temp_dir("disconnect-ca");
    let upstream_ca = make_ca(&upstream_ca_dir);
    let (upstream, hits, upstream_task) =
        spawn_https_upstream(server_config(&upstream_ca, &["localhost"])).await;

    let ca_dir = temp_dir("disconnect-intercept-ca");
    let (handle, proxy, mut bus) =
        start_tls_proxy(true, &ca_dir, Some(&upstream_ca.path), true).await;
    let _ = wait_for_status(&mut bus).await;

    let (connect, status) = raw_connect(proxy, &format!("localhost:{}", upstream.port())).await;
    assert_eq!(status, 200);
    let ca_cert = std::fs::read(ca_dir.join("rawframe-ca.crt.pem")).unwrap();
    let ca_der = rustls_pemfile::certs(&mut std::io::Cursor::new(ca_cert))
        .next()
        .unwrap()
        .unwrap();
    let mut tls = tls_connect(connect, ca_der, "localhost").await;
    let request = format!(
        "GET /disconnect-me HTTP/1.1\r\nHost: localhost:{}\r\nConnection: close\r\n\r\n",
        upstream.port()
    );
    tls.write_all(request.as_bytes()).await.unwrap();
    tls.flush().await.unwrap();

    let paused = wait_for_paused(&mut bus).await;
    assert_eq!(paused.request.target, "/disconnect-me");

    drop(tls);
    let cancelled = wait_for_cancelled_and_queue_empty(&mut bus, "/disconnect-me").await;
    assert!(
        cancelled
            .error
            .as_deref()
            .is_some_and(|error| error.contains("client disconnected"))
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "a cancelled HTTPS request must never reach upstream"
    );

    handle.shutdown().await;
    upstream_task.abort();
    let _ = std::fs::remove_dir_all(ca_dir);
    let _ = std::fs::remove_dir_all(upstream_ca_dir);
}

async fn spawn_closing_https_upstream(
    server_config: ServerConfig,
) -> (SocketAddr, Arc<AtomicUsize>, JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_task = hits.clone();
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            let hits = hits_task.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };
                let mut buffer = Vec::new();
                let mut chunk = [0u8; 1024];
                while !buffer.windows(4).any(|w| w == b"\r\n\r\n") {
                    let read = tls.read(&mut chunk).await.unwrap_or(0);
                    if read == 0 {
                        return;
                    }
                    buffer.extend_from_slice(&chunk[..read]);
                }
                hits.fetch_add(1, Ordering::SeqCst);
                // Close abruptly without sending a response.
                drop(tls);
            });
        }
    });
    (addr, hits, task)
}

#[tokio::test]
async fn upstream_disconnect_during_https_request_fails_client_and_history() {
    let upstream_ca_dir = temp_dir("upstream-drop-ca");
    let upstream_ca = make_ca(&upstream_ca_dir);
    let (upstream, hits, upstream_task) =
        spawn_closing_https_upstream(server_config(&upstream_ca, &["localhost"])).await;

    let ca_dir = temp_dir("upstream-drop-intercept-ca");
    let (handle, proxy, mut bus) =
        start_tls_proxy(true, &ca_dir, Some(&upstream_ca.path), false).await;
    let _ = wait_for_status(&mut bus).await;

    let (connect, status) = raw_connect(proxy, &format!("localhost:{}", upstream.port())).await;
    assert_eq!(status, 200);
    let ca_cert = std::fs::read(ca_dir.join("rawframe-ca.crt.pem")).unwrap();
    let ca_der = rustls_pemfile::certs(&mut std::io::Cursor::new(ca_cert))
        .next()
        .unwrap()
        .unwrap();
    let mut tls = tls_connect(connect, ca_der, "localhost").await;
    let request = format!(
        "GET /upstream-drop HTTP/1.1\r\nHost: localhost:{}\r\nConnection: close\r\n\r\n",
        upstream.port()
    );
    let response = send_http_over_tls(&mut tls, request.as_bytes()).await;
    let text = String::from_utf8_lossy(&response);
    assert!(
        text.contains("502") || text.is_empty(),
        "client should observe an upstream failure, got: {text}"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    let failed = wait_for_entry_state(&mut bus, "/upstream-drop", TrafficState::Failed).await;
    assert!(
        failed
            .error
            .as_deref()
            .is_some_and(|error| error.contains("upstream request failed")),
        "unexpected failure detail: {:?}",
        failed.error
    );

    handle.shutdown().await;
    upstream_task.abort();
    let _ = std::fs::remove_dir_all(ca_dir);
    let _ = std::fs::remove_dir_all(upstream_ca_dir);
}

#[tokio::test]
async fn proxy_shutdown_cancels_pending_https_interception_and_closes_client() {
    use tokio::sync::mpsc;

    let upstream_ca_dir = temp_dir("shutdown-ca");
    let upstream_ca = make_ca(&upstream_ca_dir);
    let (upstream, hits, upstream_task) =
        spawn_https_upstream(server_config(&upstream_ca, &["localhost"])).await;

    let ca_dir = temp_dir("shutdown-intercept-ca");
    let port = free_port();
    let mut config = proxy_config(port, true, &ca_dir, Some(&upstream_ca.path));
    config.proxy.interception_enabled = true;
    config.proxy.intercept_timeout_secs = 30;
    let mut bus = EventBus::new();
    let (cmd_tx, cmd_rx) = mpsc::channel(32);
    let service = tokio::spawn(rawframe_proxy::run_service(cmd_rx, bus.sender()));
    cmd_tx
        .send(rawframe_core::AppCommand::StartProxy(Box::new(config)))
        .await
        .unwrap();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
    let proxy = loop {
        let mut listening = false;
        let mut bound = None;
        while let Some(event) = bus.poll() {
            match event {
                AppEvent::ProxyBound(addr) => bound = Some(addr),
                AppEvent::ProxyStateChanged(rawframe_core::ProxyState::Listening) => {
                    listening = true
                }
                _ => {}
            }
        }
        if listening && let Some(addr) = bound {
            break addr;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("proxy did not start listening");
        }
        sleep(Duration::from_millis(10)).await;
    };

    let (connect, status) = raw_connect(proxy, &format!("localhost:{}", upstream.port())).await;
    assert_eq!(status, 200);
    let ca_cert = std::fs::read(ca_dir.join("rawframe-ca.crt.pem")).unwrap();
    let ca_der = rustls_pemfile::certs(&mut std::io::Cursor::new(ca_cert))
        .next()
        .unwrap()
        .unwrap();
    let mut tls = tls_connect(connect, ca_der, "localhost").await;
    let request = format!(
        "GET /shutdown-me HTTP/1.1\r\nHost: localhost:{}\r\nConnection: close\r\n\r\n",
        upstream.port()
    );
    tls.write_all(request.as_bytes()).await.unwrap();
    tls.flush().await.unwrap();
    let paused = wait_for_paused(&mut bus).await;
    assert_eq!(paused.request.target, "/shutdown-me");

    cmd_tx
        .send(rawframe_core::AppCommand::StopProxy)
        .await
        .unwrap();
    let cancelled = wait_for_cancelled_and_queue_empty(&mut bus, "/shutdown-me").await;
    assert!(
        cancelled
            .error
            .as_deref()
            .is_some_and(|error| error.contains("proxy shutting down"))
    );
    assert_eq!(hits.load(Ordering::SeqCst), 0);

    let mut closed = Vec::new();
    let _ = timeout(Duration::from_secs(3), tls.read_to_end(&mut closed)).await;
    let text = String::from_utf8_lossy(&closed);
    assert!(
        text.contains("503") || text.is_empty(),
        "unexpected client data: {text}"
    );

    drop(cmd_tx);
    timeout(Duration::from_secs(4), service)
        .await
        .expect("proxy service did not exit")
        .unwrap();

    upstream_task.abort();
    let _ = std::fs::remove_dir_all(ca_dir);
    let _ = std::fs::remove_dir_all(upstream_ca_dir);
}
