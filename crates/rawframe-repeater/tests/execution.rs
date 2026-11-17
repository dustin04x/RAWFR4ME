//! Real execution tests against local HTTP and HTTPS servers.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::header::{HeaderName, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rawframe_core::models::config::{Scope, ScopeRule};
use rawframe_core::models::message::{HttpRequest, Scheme};
use rawframe_core::repeater::RepeaterExecutionPhase;
use rawframe_repeater::{ExecutionFailure, RepeaterConfig, RepeaterEngine};
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tempfile::NamedTempFile;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug)]
struct Seen {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

#[derive(Clone)]
struct Reply {
    status: u16,
    headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
    delay: Duration,
}

impl Reply {
    fn new(status: u16, body: &[u8]) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: body.to_vec(),
            delay: Duration::ZERO,
        }
    }

    fn header(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.headers.push((name, value.into()));
        self
    }

    fn delay(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }
}

struct Server {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve_http(reply: Reply) -> Server {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen_task = seen.clone();
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let reply = reply.clone();
            let seen = seen_task.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request| {
                    let reply = reply.clone();
                    let seen = seen.clone();
                    async move { handle_test_request(request, reply, seen).await }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    Server { addr, seen, task }
}

async fn handle_test_request(
    request: Request<hyper::body::Incoming>,
    reply: Reply,
    seen: Arc<Mutex<Vec<Seen>>>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let method = request.method().to_string();
    let target = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str().to_string())
        .unwrap_or_else(|| "/".into());
    let headers = request
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_string(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect();
    let body = request
        .into_body()
        .collect()
        .await
        .map(|collected| collected.to_bytes().to_vec())
        .unwrap_or_default();
    seen.lock().unwrap().push(Seen {
        method,
        target,
        headers,
        body,
    });
    if !reply.delay.is_zero() {
        tokio::time::sleep(reply.delay).await;
    }
    let mut response = Response::new(Full::new(Bytes::from(reply.body)));
    *response.status_mut() = StatusCode::from_u16(reply.status).unwrap();
    for (name, value) in reply.headers {
        response.headers_mut().append(
            HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_str(&value).unwrap(),
        );
    }
    Ok(response)
}

fn make_engine(scope: Scope, allow_private: bool, max_response: usize) -> RepeaterEngine {
    RepeaterEngine::new(
        RepeaterConfig {
            allow_private_upstreams: allow_private,
            max_request_body: 1024 * 1024,
            max_response_bytes: max_response,
            connect_timeout: Duration::from_secs(2),
            response_timeout: Duration::from_secs(2),
            idle_timeout: Duration::from_secs(2),
            max_concurrent: 4,
            trust_file: None,
        },
        Arc::new(std::sync::RwLock::new(scope)),
    )
}

fn scope_for(port: u16) -> Scope {
    Scope::allow(ScopeRule {
        host_pattern: "127.0.0.1".into(),
        scheme: Some(Scheme::Http),
        port: Some(port),
    })
}

fn request(port: u16, method: &str, target: &str) -> HttpRequest {
    HttpRequest::new(method, Scheme::Http, "127.0.0.1", port, target)
}

async fn execute(
    engine: &RepeaterEngine,
    request: &HttpRequest,
    follow: bool,
) -> rawframe_repeater::ExecutionOutcome {
    engine
        .execute(request, follow, CancellationToken::new(), |_| {})
        .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_get_preserves_duplicate_headers_query_and_custom_port() {
    let server =
        serve_http(Reply::new(201, b"{\"ok\":true}").header("X-Server", "rawframe-test")).await;
    let engine = make_engine(scope_for(server.addr.port()), true, 1024 * 1024);

    let mut request = request(server.addr.port(), "GET", "/v1/items?limit=2&q=a%20b");
    request.headers.append("X-Trace", "one");
    request.headers.append("X-Trace", "two");
    let outcome = execute(&engine, &request, false).await;

    assert!(outcome.is_success(), "{:?}", outcome.failure);
    let response = outcome.result.response.as_ref().unwrap();
    assert_eq!(response.status, 201);
    assert_eq!(response.body, b"{\"ok\":true}");
    assert_eq!(response.headers.get("x-server"), Some("rawframe-test"));

    let seen = server.seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].method, "GET");
    assert_eq!(seen[0].target, "/v1/items?limit=2&q=a%20b");
    let traces: Vec<&str> = seen[0]
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("x-trace"))
        .map(|(_, value)| value.as_str())
        .collect();
    assert_eq!(traces, ["one", "two"]);
    assert_eq!(
        seen[0]
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("host"))
            .map(|(_, value)| value.as_str()),
        Some(format!("127.0.0.1:{}", server.addr.port()).as_str())
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn post_sends_binary_body_and_repeated_executions_really_run() {
    let server = serve_http(Reply::new(200, b"accepted")).await;
    let engine = make_engine(scope_for(server.addr.port()), true, 1024 * 1024);
    let mut request = request(server.addr.port(), "POST", "/submit");
    request.body = vec![0x00, 0xff, 0x80, b'o', b'k'];
    request
        .headers
        .append("Content-Length", request.body.len().to_string());
    request
        .headers
        .append("Content-Type", "application/octet-stream");

    let first = execute(&engine, &request, false).await;
    let second = execute(&engine, &request, false).await;
    assert!(first.is_success());
    assert!(second.is_success());
    let seen = server.seen.lock().unwrap();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].body, vec![0x00, 0xff, 0x80, b'o', b'k']);
    assert_eq!(seen[1].body, seen[0].body);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scope_and_private_address_policy_block_before_connecting() {
    let server = serve_http(Reply::new(200, b"should-not-arrive")).await;
    let mut scope = scope_for(server.addr.port());
    scope.allowlist[0].host_pattern = "allowed.example.test".into();
    let engine = make_engine(scope, true, 1024);
    let target = request(server.addr.port(), "GET", "/");
    let outcome = execute(&engine, &target, false).await;
    assert_eq!(outcome.phase, RepeaterExecutionPhase::Blocked);
    assert!(outcome.result.response.is_none());
    assert!(outcome.result.error.unwrap().contains("scope"));

    // The same loopback target with private upstreams disabled is blocked by
    // the resolved-address policy even though scope allows it.
    let engine = make_engine(scope_for(server.addr.port()), false, 1024);
    let target = request(server.addr.port(), "GET", "/");
    let outcome = execute(&engine, &target, false).await;
    assert_eq!(outcome.phase, RepeaterExecutionPhase::Blocked);
    assert!(outcome.result.error.unwrap().contains("address policy"));
    assert!(server.seen.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn edited_destination_is_revalidated_on_every_execution() {
    let allowed = serve_http(Reply::new(200, b"ok")).await;
    let mut scope = scope_for(allowed.addr.port());
    scope.allowlist[0].host_pattern = "127.0.0.1".into();
    let engine = make_engine(scope, true, 1024);

    let first = request(allowed.addr.port(), "GET", "/");
    assert!(execute(&engine, &first, false).await.is_success());

    let mut changed = first.clone();
    changed.host = "blocked.example.test".into();
    let outcome = execute(&engine, &changed, false).await;
    assert_eq!(outcome.phase, RepeaterExecutionPhase::Blocked);
    assert!(
        outcome
            .result
            .error
            .unwrap()
            .contains("blocked.example.test")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_framing_and_oversized_requests_never_connect() {
    let server = serve_http(Reply::new(200, b"ok")).await;

    let mut too_large = request(server.addr.port(), "POST", "/");
    too_large.body = vec![b'x'; 64];
    let mut config = RepeaterConfig::from_proxy(&rawframe_core::ProxyConfiguration::default());
    config.allow_private_upstreams = true;
    config.max_request_body = 8;
    let engine = RepeaterEngine::new(
        config,
        Arc::new(std::sync::RwLock::new(scope_for(server.addr.port()))),
    );
    let outcome = execute(&engine, &too_large, false).await;
    assert_eq!(outcome.phase, RepeaterExecutionPhase::Failed);
    assert!(
        outcome
            .result
            .error
            .unwrap()
            .contains("above the configured")
    );

    let mut conflicting = request(server.addr.port(), "POST", "/");
    conflicting.headers.append("Content-Length", "0");
    conflicting.headers.append("Transfer-Encoding", "chunked");
    let outcome = execute(&engine, &conflicting, false).await;
    assert_eq!(outcome.phase, RepeaterExecutionPhase::Failed);
    assert!(outcome.result.error.unwrap().contains("Transfer-Encoding"));
    assert!(server.seen.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_response_is_truncated_and_reported() {
    let server = serve_http(Reply::new(200, b"0123456789")).await;
    let engine = make_engine(scope_for(server.addr.port()), true, 4);
    let outcome = execute(&engine, &request(server.addr.port(), "GET", "/"), false).await;
    assert!(outcome.is_success());
    let response = outcome.result.response.unwrap();
    assert_eq!(response.body, b"0123");
    assert!(outcome.result.truncated);
    assert!(outcome.result.warnings.join(" ").contains("truncated"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn response_timeout_and_cancellation_are_distinct_outcomes() {
    let server = serve_http(Reply::new(200, b"late").delay(Duration::from_millis(800))).await;
    let mut config = RepeaterConfig::from_proxy(&rawframe_core::ProxyConfiguration::default());
    config.allow_private_upstreams = true;
    config.response_timeout = Duration::from_millis(100);
    config.connect_timeout = Duration::from_secs(2);
    let engine = RepeaterEngine::new(
        config,
        Arc::new(std::sync::RwLock::new(scope_for(server.addr.port()))),
    );
    let outcome = execute(&engine, &request(server.addr.port(), "GET", "/"), false).await;
    assert_eq!(outcome.phase, RepeaterExecutionPhase::TimedOut);
    assert!(matches!(
        outcome.failure,
        Some(ExecutionFailure::Timeout(_))
    ));

    let engine = Arc::new(make_engine(scope_for(server.addr.port()), true, 1024));
    let token = CancellationToken::new();
    let task = {
        let engine = engine.clone();
        let token = token.clone();
        let request = request(server.addr.port(), "GET", "/");
        tokio::spawn(async move { engine.execute(&request, false, token, |_| {}).await })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;
    token.cancel();
    let outcome = tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("cancellation must complete promptly")
        .unwrap();
    assert_eq!(outcome.phase, RepeaterExecutionPhase::Cancelled);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_execution_limit_is_enforced() {
    let server = serve_http(Reply::new(200, b"slow").delay(Duration::from_millis(400))).await;
    let mut config = RepeaterConfig::from_proxy(&rawframe_core::ProxyConfiguration::default());
    config.allow_private_upstreams = true;
    config.max_concurrent = 1;
    let engine = Arc::new(RepeaterEngine::new(
        config,
        Arc::new(std::sync::RwLock::new(scope_for(server.addr.port()))),
    ));
    let request = request(server.addr.port(), "GET", "/");
    let first = {
        let engine = engine.clone();
        let request = request.clone();
        tokio::spawn(async move { execute(&engine, &request, false).await })
    };
    tokio::time::sleep(Duration::from_millis(60)).await;
    let second = execute(&engine, &request, false).await;
    assert!(matches!(second.failure, Some(ExecutionFailure::Busy(_))));
    assert_eq!(second.phase, RepeaterExecutionPhase::Failed);
    assert!(first.await.unwrap().is_success());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redirects_are_validated_and_cross_origin_credentials_are_stripped() {
    let destination = serve_http(Reply::new(200, b"landed")).await;
    let redirect = serve_http(
        Reply::new(302, b"")
            .header(
                "Location",
                format!("http://127.0.0.1:{}/next", destination.addr.port()),
            )
            .delay(Duration::ZERO),
    )
    .await;

    let mut scope = Scope::default();
    scope.allowlist.push(ScopeRule {
        host_pattern: "127.0.0.1".into(),
        scheme: Some(Scheme::Http),
        port: Some(redirect.addr.port()),
    });
    scope.allowlist.push(ScopeRule {
        host_pattern: "127.0.0.1".into(),
        scheme: Some(Scheme::Http),
        port: Some(destination.addr.port()),
    });
    let engine = make_engine(scope, true, 1024);

    let mut request = request(redirect.addr.port(), "POST", "/start");
    request.body = b"secret".to_vec();
    request.headers.append("Content-Length", "6");
    request
        .headers
        .append("Authorization", "Bearer secret-token");
    request.headers.append("Cookie", "sid=secret");
    request.headers.append("X-Keep", "yes");
    let outcome = execute(&engine, &request, true).await;

    assert!(outcome.is_success(), "{:?}", outcome.failure);
    assert_eq!(outcome.result.redirects.len(), 1);
    assert!(outcome.result.redirects[0].cross_origin);
    {
        let seen = destination.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].method, "GET", "302 POST becomes GET");
        assert!(seen[0].body.is_empty());
        assert_eq!(
            seen[0]
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("x-keep"))
                .map(|(_, value)| value.as_str()),
            Some("yes")
        );
        assert!(
            !seen[0]
                .headers
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        );
        assert!(
            !seen[0]
                .headers
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("cookie"))
        );
    }

    // A redirect to a destination outside scope is refused, but the real 3xx
    // response remains inspectable.
    let blocked =
        serve_http(Reply::new(302, b"").header("Location", "http://blocked.example.test/steal"))
            .await;
    let engine = make_engine(scope_for(blocked.addr.port()), true, 1024);
    let outcome = execute(&engine, &request_for(blocked.addr.port()), true).await;
    assert_eq!(outcome.phase, RepeaterExecutionPhase::Blocked);
    assert_eq!(outcome.result.response.as_ref().unwrap().status, 302);
    assert!(
        outcome
            .result
            .error
            .unwrap()
            .contains("redirect destination")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redirect_loops_stop_at_the_hop_limit() {
    let server = serve_http(
        Reply::new(302, b"")
            .header("Location", "/loop")
            .delay(Duration::ZERO),
    )
    .await;
    let engine = make_engine(scope_for(server.addr.port()), true, 1024);
    let outcome = execute(&engine, &request(server.addr.port(), "GET", "/loop"), true).await;

    assert_eq!(outcome.phase, RepeaterExecutionPhase::Failed);
    assert_eq!(outcome.result.redirects.len(), 5);
    assert_eq!(outcome.result.response.as_ref().unwrap().status, 302);
    assert!(outcome.result.error.unwrap().contains("redirect limit"));
}

fn request_for(port: u16) -> HttpRequest {
    request(port, "GET", "/")
}

fn tls_identity(name: &str) -> (String, CertificateDer<'static>, PrivateKeyDer<'static>) {
    let key = KeyPair::generate().unwrap();
    let params = CertificateParams::new(vec![name.to_string()]).unwrap();
    let cert = params.self_signed(&key).unwrap();
    let pem = cert.pem();
    let der = cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    (pem, der, key)
}

async fn serve_https(
    reply: Reply,
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> Server {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen_task = seen.clone();
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            let reply = reply.clone();
            let seen = seen_task.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let service = service_fn(move |request| {
                    let reply = reply.clone();
                    let seen = seen.clone();
                    async move { handle_test_request(request, reply, seen).await }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), service)
                    .await;
            });
        }
    });
    Server { addr, seen, task }
}

fn tls_engine(port: u16, trust_pem: &str) -> (RepeaterEngine, NamedTempFile) {
    use std::io::Write;
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(trust_pem.as_bytes()).unwrap();
    let config = RepeaterConfig {
        allow_private_upstreams: true,
        max_request_body: 1024 * 1024,
        max_response_bytes: 1024 * 1024,
        connect_timeout: Duration::from_secs(3),
        response_timeout: Duration::from_secs(3),
        idle_timeout: Duration::from_secs(3),
        max_concurrent: 4,
        trust_file: Some(file.path().to_path_buf()),
    };
    let scope = Scope::allow(ScopeRule {
        host_pattern: "localhost".into(),
        scheme: Some(Scheme::Https),
        port: Some(port),
    });
    (
        RepeaterEngine::new(config, Arc::new(std::sync::RwLock::new(scope))),
        file,
    )
}

fn https_request(port: u16, method: &str, target: &str) -> HttpRequest {
    HttpRequest::new(method, Scheme::Https, "localhost", port, target)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn https_verifies_trust_and_hostname_and_sends_bodies() {
    let (pem, cert, key) = tls_identity("localhost");
    let server = serve_https(Reply::new(200, b"secure"), cert, key).await;
    let (engine, _trust) = tls_engine(server.addr.port(), &pem);

    let mut request = https_request(server.addr.port(), "POST", "/secure");
    request.body = b"tls-body".to_vec();
    request.headers.append("Content-Length", "8");
    let outcome = execute(&engine, &request, false).await;
    assert!(outcome.is_success(), "{:?}", outcome.failure);
    assert_eq!(
        outcome.result.response.as_ref().unwrap().body,
        b"secure".to_vec()
    );
    assert_eq!(server.seen.lock().unwrap()[0].body, b"tls-body".to_vec());

    // Certificates are mandatory: a hostname mismatch fails verification.
    let (mismatch_pem, mismatch_cert, mismatch_key) = tls_identity("wrong.example.test");
    let mismatch = serve_https(
        Reply::new(200, b"must-not-load"),
        mismatch_cert,
        mismatch_key,
    )
    .await;
    let (engine, _trust) = tls_engine(mismatch.addr.port(), &mismatch_pem);
    let outcome = execute(
        &engine,
        &https_request(mismatch.addr.port(), "GET", "/"),
        false,
    )
    .await;
    assert_eq!(outcome.phase, RepeaterExecutionPhase::Failed);
    assert!(matches!(outcome.failure, Some(ExecutionFailure::Tls(_))));
    assert!(outcome.result.response.is_none());
    assert!(mismatch.seen.lock().unwrap().is_empty());

    // An unrelated trusted root must not validate this server.
    let (other_pem, _other_cert, _other_key) = tls_identity("localhost");
    let (pem, cert, key) = tls_identity("localhost");
    let untrusted = serve_https(Reply::new(200, b"nope"), cert, key).await;
    let (engine, _trust) = tls_engine(untrusted.addr.port(), &other_pem);
    let outcome = execute(
        &engine,
        &https_request(untrusted.addr.port(), "GET", "/"),
        false,
    )
    .await;
    assert_eq!(outcome.phase, RepeaterExecutionPhase::Failed);
    assert!(matches!(outcome.failure, Some(ExecutionFailure::Tls(_))));
    assert!(untrusted.seen.lock().unwrap().is_empty());
    assert!(!pem.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn service_emits_phase_and_completed_events_for_real_execution() {
    let server = serve_http(Reply::new(200, b"service")).await;
    let (tx, rx) = mpsc::channel(8);
    let mut bus = rawframe_core::EventBus::new();
    let events = bus.sender();
    let scope = Arc::new(std::sync::RwLock::new(scope_for(server.addr.port())));
    let mut config = RepeaterConfig::from_proxy(&rawframe_core::ProxyConfiguration::default());
    config.allow_private_upstreams = true;
    let task = tokio::spawn(rawframe_repeater::run_service(rx, config, events, scope));

    tx.send(rawframe_core::RepeaterCommand::Execute {
        tab: rawframe_core::models::session::RepeaterId(7),
        execution: 1,
        request: request(server.addr.port(), "GET", "/service"),
        follow_redirects: false,
        origin: None,
        origin_request: None,
    })
    .await
    .unwrap();

    let mut phases = Vec::new();
    let mut completed = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while completed.is_none() && tokio::time::Instant::now() < deadline {
        if let Some(event) = bus.poll() {
            match event {
                rawframe_core::AppEvent::Repeater(rawframe_core::RepeaterEvent::Phase {
                    phase,
                    ..
                }) => phases.push(phase),
                rawframe_core::AppEvent::Repeater(rawframe_core::RepeaterEvent::Completed {
                    entry,
                    ..
                }) => completed = Some(entry),
                _ => {}
            }
        } else {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    let entry = completed.expect("service must complete");
    assert_eq!(
        entry.source,
        rawframe_core::models::traffic::TrafficSource::Repeater
    );
    assert!(entry.response.is_some());
    assert!(phases.contains(&RepeaterExecutionPhase::Sending));
    assert!(phases.contains(&RepeaterExecutionPhase::Receiving));

    tx.send(rawframe_core::RepeaterCommand::Shutdown)
        .await
        .unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(3), task).await;
}
