//! Real Intruder execution against local HTTP and HTTPS servers.
//!
//! These tests use the packaged engine path end to end: a template is expanded,
//! every generated request goes through the Repeater engine's destination and
//! scope checks, and results are counted from real responses. Nothing contacts an
//! external host.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rawframe_core::models::config::{Scope, ScopeRule};
use rawframe_core::models::message::{HttpRequest, Scheme};
use rawframe_core::repeater::RepeaterExecutionPhase;
use rawframe_core::{
    AppEvent, AttackPlan, EventBus, IntruderEvent, IntruderLaunch, IntruderPhase,
    IntruderStopReason, IntruderTemplate, PayloadSet, PayloadSource, PositionId, Strategy,
    build_plan,
};
use rawframe_intruder::{IntruderEngine, intruder_config, run_attack};
use rawframe_repeater::RepeaterConfig;
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tempfile::NamedTempFile;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug)]
struct Seen {
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

#[derive(Clone)]
struct Reply {
    status: u16,
    body: Vec<u8>,
    delay: Duration,
    headers: Vec<(&'static str, String)>,
}

impl Reply {
    fn new(status: u16, body: &[u8]) -> Self {
        Self {
            status,
            body: body.to_vec(),
            delay: Duration::ZERO,
            headers: Vec::new(),
        }
    }

    fn delay(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }

    fn header(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.headers.push((name, value.into()));
        self
    }
}

struct Server {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
    in_flight: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
    connections: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Server {
    fn targets(&self) -> Vec<String> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .map(|seen| seen.target.clone())
            .collect()
    }

    fn count(&self) -> usize {
        self.seen.lock().unwrap().len()
    }
}

async fn serve_http(reply: Reply) -> Server {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let in_flight = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let connections = Arc::new(AtomicUsize::new(0));

    let task_seen = seen.clone();
    let task_flight = in_flight.clone();
    let task_peak = peak.clone();
    let task_connections = connections.clone();
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            task_connections.fetch_add(1, Ordering::Relaxed);
            let reply = reply.clone();
            let seen = task_seen.clone();
            let in_flight = task_flight.clone();
            let peak = task_peak.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request| {
                    let reply = reply.clone();
                    let seen = seen.clone();
                    let in_flight = in_flight.clone();
                    let peak = peak.clone();
                    async move {
                        let current = in_flight.fetch_add(1, Ordering::Relaxed) + 1;
                        peak.fetch_max(current, Ordering::Relaxed);
                        let result = handle(request, reply, seen).await;
                        in_flight.fetch_sub(1, Ordering::Relaxed);
                        result
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });

    Server {
        addr,
        seen,
        in_flight,
        peak,
        connections,
        task,
    }
}

async fn handle(
    request: Request<hyper::body::Incoming>,
    reply: Reply,
    seen: Arc<Mutex<Vec<Seen>>>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
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
            hyper::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            hyper::header::HeaderValue::from_str(&value).unwrap(),
        );
    }
    Ok(response)
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
    let loans = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let connections = Arc::new(AtomicUsize::new(0));
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let task_seen = seen.clone();
    let task_flight = loans.clone();
    let task_peak = peak.clone();
    let task_connections = connections.clone();
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            task_connections.fetch_add(1, Ordering::Relaxed);
            let acceptor = acceptor.clone();
            let reply = reply.clone();
            let seen = task_seen.clone();
            let in_flight = task_flight.clone();
            let peak = task_peak.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let service = service_fn(move |request| {
                    let reply = reply.clone();
                    let seen = seen.clone();
                    let in_flight = in_flight.clone();
                    let peak = peak.clone();
                    async move {
                        let current = in_flight.fetch_add(1, Ordering::Relaxed) + 1;
                        peak.fetch_max(current, Ordering::Relaxed);
                        let result = handle(request, reply, seen).await;
                        in_flight.fetch_sub(1, Ordering::Relaxed);
                        result
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), service)
                    .await;
            });
        }
    });

    Server {
        addr,
        seen,
        in_flight: loans,
        peak,
        connections,
        task,
    }
}

/// HTTPS origin that only offers HTTP/2, plus a count of served streams. It
/// proves the Intruder reaches the wire through the Repeater's real h2 path.
async fn serve_https_h2(
    reply: Reply,
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> (Server, Arc<AtomicUsize>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let loans = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let connections = Arc::new(AtomicUsize::new(0));
    let streams = Arc::new(AtomicUsize::new(0));
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let task_seen = seen.clone();
    let task_flight = loans.clone();
    let task_peak = peak.clone();
    let task_connections = connections.clone();
    let task_streams = streams.clone();
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            task_connections.fetch_add(1, Ordering::Relaxed);
            let acceptor = acceptor.clone();
            let reply = reply.clone();
            let seen = task_seen.clone();
            let in_flight = task_flight.clone();
            let peak = task_peak.clone();
            let streams = task_streams.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let service = service_fn(move |request| {
                    let reply = reply.clone();
                    let seen = seen.clone();
                    let in_flight = in_flight.clone();
                    let peak = peak.clone();
                    let streams = streams.clone();
                    async move {
                        streams.fetch_add(1, Ordering::Relaxed);
                        let current = in_flight.fetch_add(1, Ordering::Relaxed) + 1;
                        peak.fetch_max(current, Ordering::Relaxed);
                        let result = handle(request, reply, seen).await;
                        in_flight.fetch_sub(1, Ordering::Relaxed);
                        result
                    }
                });
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(tls), service)
                    .await;
            });
        }
    });

    (
        Server {
            addr,
            seen,
            in_flight: loans,
            peak,
            connections,
            task,
        },
        streams,
    )
}

fn scope_for(port: u16, scheme: Scheme) -> Scope {
    // HTTPS templates use `localhost` so the test certificate's hostname is
    // valid; the scope rule must match that exact authority.
    let host = if scheme == Scheme::Https {
        "localhost"
    } else {
        "127.0.0.1"
    };
    Scope::allow(ScopeRule {
        host_pattern: host.into(),
        scheme: Some(scheme),
        port: Some(port),
    })
}

fn base_config(trust_file: Option<std::path::PathBuf>) -> RepeaterConfig {
    RepeaterConfig {
        allow_private_upstreams: true,
        max_request_body: 1024 * 1024,
        max_response_bytes: 1024 * 1024,
        connect_timeout: Duration::from_secs(2),
        response_timeout: Duration::from_secs(3),
        idle_timeout: Duration::from_secs(3),
        max_concurrent: 4,
        trust_file,
    }
}

fn engine(
    port: u16,
    scheme: Scheme,
    trust_file: Option<std::path::PathBuf>,
) -> Arc<IntruderEngine> {
    let config = intruder_config(&base_config(trust_file));
    Arc::new(IntruderEngine::new(
        config,
        Arc::new(std::sync::RwLock::new(scope_for(port, scheme))),
    ))
}

fn template(port: u16, scheme: Scheme, target: &str) -> IntruderTemplate {
    let host = if scheme == Scheme::Https {
        "localhost"
    } else {
        "127.0.0.1"
    };
    let request = HttpRequest::new("GET", scheme, host, port, target);
    IntruderTemplate::from_request(&request)
}

fn sets(values: &[&[&str]]) -> Vec<PayloadSet> {
    values
        .iter()
        .enumerate()
        .map(|(index, list)| PayloadSet {
            id: index as u32,
            name: format!("set{index}"),
            source: PayloadSource::Manual,
            payloads: list.iter().map(|value| value.as_bytes().to_vec()).collect(),
        })
        .collect()
}

fn assignment(pairs: &[(u16, usize)]) -> BTreeMap<PositionId, usize> {
    pairs
        .iter()
        .map(|(id, index)| (PositionId(*id), *index))
        .collect()
}

struct PlanSpec {
    concurrency: usize,
    rate: u32,
    follow_redirects: bool,
    max_duration_secs: u64,
}

impl Default for PlanSpec {
    fn default() -> Self {
        Self {
            concurrency: 2,
            rate: 20,
            follow_redirects: false,
            max_duration_secs: 30,
        }
    }
}

fn launch(
    template: IntruderTemplate,
    strategy: Strategy,
    sets: &[PayloadSet],
    assign: &[(u16, usize)],
    spec: PlanSpec,
) -> IntruderLaunch {
    let analysis = template.analyze().expect("template analyzes");
    let positions = analysis.position_ids();
    let plan: AttackPlan =
        build_plan(strategy, &positions, &assignment(assign), sets).expect("plan builds");
    IntruderLaunch {
        template,
        analysis,
        plan,
        concurrency: spec.concurrency,
        rate_per_second: spec.rate,
        follow_redirects: spec.follow_redirects,
        max_duration_secs: spec.max_duration_secs,
        origin: None,
    }
}

async fn run(
    engine: Arc<IntruderEngine>,
    launch: IntruderLaunch,
    cancel: CancellationToken,
    paused: Arc<AtomicBool>,
) -> (
    rawframe_core::IntruderSummary,
    Vec<rawframe_core::IntruderResult>,
    Vec<AppEvent>,
) {
    let mut bus = EventBus::new();
    let events = bus.sender();
    let notify = Arc::new(tokio::sync::Notify::new());
    let summary = run_attack(engine, events, 1, launch, cancel, paused, notify).await;
    let mut collected = Vec::new();
    while let Some(event) = bus.poll() {
        collected.push(event);
    }
    let results = collected
        .iter()
        .filter_map(|event| match event {
            AppEvent::Intruder(IntruderEvent::Completed { result, .. }) => Some((**result).clone()),
            _ => None,
        })
        .collect();
    (summary, results, collected)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sniper_sends_exactly_the_previewed_requests() {
    let server = serve_http(Reply::new(200, b"ok")).await;
    let mut template = template(server.addr.port(), Scheme::Http, "/api/§users§?role=§user§");
    template
        .headers
        .push(("X-Origin".into(), "intruder".into()));
    let sets = sets(&[&["alice", "bob"], &["admin", "viewer"]]);
    let plan = launch(
        template,
        Strategy::Sniper,
        &sets,
        &[(1, 0), (2, 1)],
        PlanSpec::default(),
    );
    let expected = plan.plan.preview(&plan.template, &plan.analysis, 10);
    let expected: Vec<String> = expected
        .into_iter()
        .map(|request| request.unwrap().target)
        .collect();

    let (summary, results, _) = run(
        engine(server.addr.port(), Scheme::Http, None),
        plan,
        CancellationToken::new(),
        Arc::new(AtomicBool::new(false)),
    )
    .await;

    assert_eq!(summary.planned, 4);
    assert_eq!(summary.sent, 4);
    assert_eq!(summary.responded, 4);
    assert_eq!(results.len(), 4);
    assert_eq!(summary.reason, Some(IntruderStopReason::Complete));
    assert_eq!(
        server.targets(),
        expected,
        "wire traffic matched the preview exactly"
    );
    // Every response is real.
    assert!(results.iter().all(|result| result.status() == Some(200)));
    assert!(
        results
            .iter()
            .all(|result| result.phase == RepeaterExecutionPhase::Completed)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn battering_ram_reuses_a_single_payload_everywhere() {
    let server = serve_http(Reply::new(200, b"ok")).await;
    let template = template(server.addr.port(), Scheme::Http, "/§a§/x?q=§b§");
    let plan = launch(
        template,
        Strategy::BatteringRam,
        &sets(&[&["one", "two"]]),
        &[],
        PlanSpec::default(),
    );
    let (summary, _, _) = run(
        engine(server.addr.port(), Scheme::Http, None),
        plan,
        CancellationToken::new(),
        Arc::new(AtomicBool::new(false)),
    )
    .await;
    assert_eq!(summary.responded, 2);
    assert_eq!(server.targets(), vec!["/one/x?q=one", "/two/x?q=two"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cluster_bomb_sends_every_combination_in_order() {
    let server = serve_http(Reply::new(200, b"ok")).await;
    let template = template(server.addr.port(), Scheme::Http, "/§a§/§b§");
    let plan = launch(
        template,
        Strategy::ClusterBomb,
        &sets(&[&["1", "2"], &["x", "y", "z"]]),
        &[(1, 0), (2, 1)],
        PlanSpec::default(),
    );
    let (summary, _, _) = run(
        engine(server.addr.port(), Scheme::Http, None),
        plan,
        CancellationToken::new(),
        Arc::new(AtomicBool::new(false)),
    )
    .await;
    assert_eq!(summary.planned, 6);
    assert_eq!(summary.responded, 6);
    assert_eq!(
        server.targets(),
        vec!["/1/x", "/1/y", "/1/z", "/2/x", "/2/y", "/2/z"]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn payloads_reach_the_body_and_headers() {
    let server = serve_http(Reply::new(200, b"ok")).await;
    let mut template = template(server.addr.port(), Scheme::Http, "/submit");
    template.method = "POST".into();
    template.headers.push(("X-Token".into(), "§tok§".into()));
    template.headers.push(("Content-Length".into(), "".into()));
    template.body = "user=§who§".as_bytes().to_vec();
    let analysis = template.analyze().unwrap();
    // Both a header and a body position exist.
    assert_eq!(analysis.positions.len(), 2);

    // Rebuild the head so Content-Length matches each generated body.
    template
        .headers
        .retain(|(name, _)| !name.eq_ignore_ascii_case("Content-Length"));
    let plan = launch(
        template,
        Strategy::BatteringRam,
        &sets(&[&["abc"]]),
        &[],
        PlanSpec::default(),
    );
    let (summary, results, _) = run(
        engine(server.addr.port(), Scheme::Http, None),
        plan,
        CancellationToken::new(),
        Arc::new(AtomicBool::new(false)),
    )
    .await;
    assert_eq!(summary.responded, 1);
    {
        let seen = server.seen.lock().unwrap();
        assert_eq!(seen[0].body, b"user=abc".to_vec());
        assert_eq!(
            seen[0]
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("x-token"))
                .map(|(_, value)| value.as_str()),
            Some("abc")
        );
    }
    // One payload is applied to both enabled positions.
    assert_eq!(results[0].payload_display(), vec!["abc", "abc"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn destinations_outside_scope_are_blocked_without_traffic() {
    let server = serve_http(Reply::new(200, b"should-not-arrive")).await;
    let template = template(server.addr.port(), Scheme::Http, "/§x§");
    let plan = launch(
        template,
        Strategy::Sniper,
        &sets(&[&["a", "b", "c"]]),
        &[(1, 0)],
        PlanSpec::default(),
    );
    // A scope that deliberately excludes this port.
    let config = intruder_config(&base_config(None));
    let engine = Arc::new(IntruderEngine::new(
        config,
        Arc::new(std::sync::RwLock::new(Scope::default())),
    ));
    let (summary, results, _) = run(
        engine,
        plan,
        CancellationToken::new(),
        Arc::new(AtomicBool::new(false)),
    )
    .await;

    assert_eq!(summary.blocked, 3);
    assert_eq!(summary.responded, 0);
    assert_eq!(server.count(), 0, "blocked requests never reach the wire");
    assert!(results.iter().all(|result| {
        result.phase == RepeaterExecutionPhase::Blocked && result.status().is_none()
    }));
    assert!(
        results[0]
            .error()
            .is_some_and(|error| error.contains("outside the configured scope"))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn https_requests_are_verified_and_untrusted_servers_are_refused() {
    let (pem, cert, key) = tls_identity("localhost");
    let server = serve_https(Reply::new(200, b"secure"), cert, key).await;
    let mut trust = NamedTempFile::new().unwrap();
    {
        use std::io::Write;
        trust.write_all(pem.as_bytes()).unwrap();
    }
    let trusted_template = template(server.addr.port(), Scheme::Https, "/§p§");
    let plan = launch(
        trusted_template,
        Strategy::Sniper,
        &sets(&[&["one", "two"]]),
        &[(1, 0)],
        PlanSpec::default(),
    );
    let (summary, results, _) = run(
        engine(
            server.addr.port(),
            Scheme::Https,
            Some(trust.path().to_path_buf()),
        ),
        plan,
        CancellationToken::new(),
        Arc::new(AtomicBool::new(false)),
    )
    .await;
    assert_eq!(summary.responded, 2);
    assert_eq!(server.targets(), vec!["/one", "/two"]);
    assert_eq!(server.connections.load(Ordering::Relaxed), 2);
    assert_eq!(
        results[0].result.response.as_ref().unwrap().body,
        b"secure".to_vec()
    );

    // With an unrelated trust root, nothing is delivered to the server.
    let (other_pem, _c, _k) = tls_identity("localhost");
    let (cert, key2) = {
        let (_, cert, key) = tls_identity("localhost");
        (cert, key)
    };
    let untrusted = serve_https(Reply::new(200, b"nope"), cert, key2).await;
    let mut other_trust = NamedTempFile::new().unwrap();
    {
        use std::io::Write;
        other_trust.write_all(other_pem.as_bytes()).unwrap();
    }
    let untrusted_template = template(untrusted.addr.port(), Scheme::Https, "/§p§");
    let plan = launch(
        untrusted_template,
        Strategy::Sniper,
        &sets(&[&["one"]]),
        &[(1, 0)],
        PlanSpec::default(),
    );
    let (summary, results, _) = run(
        engine(
            untrusted.addr.port(),
            Scheme::Https,
            Some(other_trust.path().to_path_buf()),
        ),
        plan,
        CancellationToken::new(),
        Arc::new(AtomicBool::new(false)),
    )
    .await;
    assert_eq!(summary.failed, 1);
    assert!(
        results[0]
            .error()
            .is_some_and(|error| error.contains("TLS"))
    );
    assert!(untrusted.seen.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrency_is_bounded_and_observed() {
    let server = serve_http(Reply::new(200, b"slow").delay(Duration::from_millis(120))).await;
    let template = template(server.addr.port(), Scheme::Http, "/§x§");
    let plan = launch(
        template,
        Strategy::Sniper,
        &sets(&[&["a", "b", "c", "d", "e", "f"]]),
        &[(1, 0)],
        PlanSpec {
            concurrency: 3,
            rate: 20,
            ..PlanSpec::default()
        },
    );
    let (summary, _, _) = run(
        engine(server.addr.port(), Scheme::Http, None),
        plan,
        CancellationToken::new(),
        Arc::new(AtomicBool::new(false)),
    )
    .await;
    assert_eq!(summary.responded, 6);
    let peak = server.peak.load(Ordering::Relaxed);
    assert!(peak > 1, "requests should overlap, peak={peak}");
    assert!(peak <= 3, "concurrency limit exceeded, peak={peak}");
    assert_eq!(server.in_flight.load(Ordering::Relaxed), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_configured_rate_spaces_request_starts() {
    let server = serve_http(Reply::new(200, b"ok")).await;
    let template = template(server.addr.port(), Scheme::Http, "/§x§");
    let plan = launch(
        template,
        Strategy::Sniper,
        &sets(&[&["a", "b", "c", "d"]]),
        &[(1, 0)],
        PlanSpec {
            concurrency: 4,
            rate: 4,
            ..PlanSpec::default()
        },
    );
    let started = std::time::Instant::now();
    let (summary, _, _) = run(
        engine(server.addr.port(), Scheme::Http, None),
        plan,
        CancellationToken::new(),
        Arc::new(AtomicBool::new(false)),
    )
    .await;
    let elapsed = started.elapsed();
    assert_eq!(summary.responded, 4);
    // Four starts at 4/s need at least three 250 ms intervals.
    assert!(
        elapsed >= Duration::from_millis(700),
        "rate limit not applied: {elapsed:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pause_stops_dispatch_and_resume_continues() {
    let server = serve_http(Reply::new(200, b"ok").delay(Duration::from_millis(60))).await;
    let template = template(server.addr.port(), Scheme::Http, "/§x§");
    let plan = launch(
        template,
        Strategy::Sniper,
        &sets(&[&["a", "b", "c", "d", "e", "f"]]),
        &[(1, 0)],
        PlanSpec {
            concurrency: 2,
            ..PlanSpec::default()
        },
    );
    let paused = Arc::new(AtomicBool::new(false));
    let flag = paused.clone();
    let token = CancellationToken::new();
    let task = tokio::spawn(run(
        engine(server.addr.port(), Scheme::Http, None),
        plan,
        token.clone(),
        paused.clone(),
    ));

    // Wait for the first request, then pause.
    for _ in 0..100 {
        if server.count() >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    flag.store(true, Ordering::Relaxed);
    tokio::time::sleep(Duration::from_millis(80)).await;
    let settled = server.count();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        server.count(),
        settled,
        "a paused run must not dispatch new requests"
    );
    assert!(settled < 6, "the run should still have work queued");

    flag.store(false, Ordering::Relaxed);
    let (summary, _, events) = tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("run finishes after resume")
        .unwrap();
    assert_eq!(summary.responded, 6);
    assert!(events.iter().any(|event| matches!(
        event,
        AppEvent::Intruder(IntruderEvent::Phase {
            phase: IntruderPhase::Paused,
            ..
        })
    )));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_stops_the_run_and_reports_what_was_not_sent() {
    let server = serve_http(Reply::new(200, b"ok").delay(Duration::from_millis(50))).await;
    let template = template(server.addr.port(), Scheme::Http, "/§x§");
    let plan = launch(
        template,
        Strategy::Sniper,
        &sets(&[&["a", "b", "c", "d", "e", "f", "g", "h"]]),
        &[(1, 0)],
        PlanSpec {
            concurrency: 1,
            ..PlanSpec::default()
        },
    );
    let token = CancellationToken::new();
    let task = tokio::spawn(run(
        engine(server.addr.port(), Scheme::Http, None),
        plan,
        token.clone(),
        Arc::new(AtomicBool::new(false)),
    ));
    for _ in 0..100 {
        if server.count() >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    token.cancel();
    let (summary, _, _) = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("cancellation completes promptly")
        .unwrap();
    assert_eq!(summary.reason, Some(IntruderStopReason::Cancelled));
    assert!(
        summary.sent < 8,
        "cancellation must stop remaining requests (sent {})",
        summary.sent
    );
    assert!(summary.not_sent > 0);
    assert!(summary.planned == 8);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_duration_ceiling_ends_a_slow_run() {
    let server = serve_http(Reply::new(200, b"ok").delay(Duration::from_millis(250))).await;
    let template = template(server.addr.port(), Scheme::Http, "/§x§");
    let plan = launch(
        template,
        Strategy::Sniper,
        &sets(&[&["a", "b", "c", "d", "e", "f", "g", "h"]]),
        &[(1, 0)],
        PlanSpec {
            concurrency: 1,
            rate: 20,
            max_duration_secs: 1,
            ..PlanSpec::default()
        },
    );
    let (summary, _, _) = run(
        engine(server.addr.port(), Scheme::Http, None),
        plan,
        CancellationToken::new(),
        Arc::new(AtomicBool::new(false)),
    )
    .await;
    assert_eq!(summary.reason, Some(IntruderStopReason::DurationLimit));
    assert!(summary.duration_ms >= 900);
    assert!(summary.not_sent > 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redirects_are_not_followed_by_default() {
    let destination = serve_http(Reply::new(200, b"landed")).await;
    let redirect = serve_http(Reply::new(302, b"").header(
        "Location",
        format!("http://127.0.0.1:{}/next", destination.addr.port()),
    ))
    .await;
    let template = template(redirect.addr.port(), Scheme::Http, "/§x§");
    let plan = launch(
        template,
        Strategy::Sniper,
        &sets(&[&["a", "b"]]),
        &[(1, 0)],
        PlanSpec::default(),
    );
    let (summary, results, _) = run(
        engine(redirect.addr.port(), Scheme::Http, None),
        plan,
        CancellationToken::new(),
        Arc::new(AtomicBool::new(false)),
    )
    .await;
    assert_eq!(summary.responded, 2);
    assert!(results.iter().all(|result| result.status() == Some(302)));
    assert!(
        results
            .iter()
            .all(|result| result.result.redirects.is_empty())
    );
    assert_eq!(destination.count(), 0, "no redirect was followed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_connection_is_reported_once_and_never_retried() {
    // Bind then drop the listener so the port is closed but known.
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let template = template(port, Scheme::Http, "/§x§");
    let plan = launch(
        template,
        Strategy::Sniper,
        &sets(&[&["a", "b", "c"]]),
        &[(1, 0)],
        PlanSpec::default(),
    );
    let (summary, results, events) = run(
        engine(port, Scheme::Http, None),
        plan,
        CancellationToken::new(),
        Arc::new(AtomicBool::new(false)),
    )
    .await;
    assert_eq!(summary.planned, 3);
    assert_eq!(summary.sent, 3, "each request is attempted exactly once");
    assert_eq!(summary.failed, 3);
    assert_eq!(results.len(), 3);
    assert!(results.iter().all(|result| result.status().is_none()));
    let completed = events
        .iter()
        .filter(|event| matches!(event, AppEvent::Intruder(IntruderEvent::Completed { .. })))
        .count();
    assert_eq!(completed, 3, "no hidden retry produced extra results");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn response_capture_is_bounded_for_attack_traffic() {
    let big = vec![b'x'; 300 * 1024];
    let server = serve_http(Reply::new(200, &big)).await;
    let template = template(server.addr.port(), Scheme::Http, "/§x§");
    let plan = launch(
        template,
        Strategy::Sniper,
        &sets(&[&["a"]]),
        &[(1, 0)],
        PlanSpec::default(),
    );
    let (summary, results, _) = run(
        engine(server.addr.port(), Scheme::Http, None),
        plan,
        CancellationToken::new(),
        Arc::new(AtomicBool::new(false)),
    )
    .await;
    assert_eq!(summary.responded, 1);
    assert_eq!(
        results[0].size(),
        rawframe_intruder::MAX_CAPTURED_RESPONSE_BYTES
    );
    assert!(results[0].result.truncated);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn results_carry_entries_with_intruder_provenance() {
    let server = serve_http(Reply::new(201, b"created")).await;
    let template = template(server.addr.port(), Scheme::Http, "/§x§");
    let plan = launch(
        template,
        Strategy::Sniper,
        &sets(&[&["one"]]),
        &[(1, 0)],
        PlanSpec::default(),
    );
    let (_, results, events) = run(
        engine(server.addr.port(), Scheme::Http, None),
        plan,
        CancellationToken::new(),
        Arc::new(AtomicBool::new(false)),
    )
    .await;
    let entry = events
        .iter()
        .find_map(|event| match event {
            AppEvent::Intruder(IntruderEvent::Completed { entry, .. }) => Some((**entry).clone()),
            _ => None,
        })
        .expect("a completed entry");
    assert_eq!(
        entry.source,
        rawframe_core::models::traffic::TrafficSource::Intruder
    );
    assert!(entry.is_intruder());
    assert!(!entry.is_live_capture());
    assert_eq!(entry.intruder_payloads, Some(vec![b"one".to_vec()]));
    assert_eq!(entry.response.as_ref().unwrap().status, 201);
    assert_eq!(
        entry.state,
        rawframe_core::models::traffic::TrafficState::Completed
    );
    assert_eq!(results[0].id, entry.id);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_attacks_run_through_the_shared_repeater_engine() {
    let (pem, cert, key) = tls_identity("localhost");
    let (server, streams) = serve_https_h2(Reply::new(200, b"h2-ok"), cert, key).await;
    let mut trust = NamedTempFile::new().unwrap();
    {
        use std::io::Write;
        trust.write_all(pem.as_bytes()).unwrap();
    }
    let plan = launch(
        template(server.addr.port(), Scheme::Https, "/§p§"),
        Strategy::Sniper,
        &sets(&[&["alpha", "beta"]]),
        &[(1, 0)],
        PlanSpec {
            concurrency: 2,
            ..PlanSpec::default()
        },
    );
    let (summary, results, _) = run(
        engine(
            server.addr.port(),
            Scheme::Https,
            Some(trust.path().to_path_buf()),
        ),
        plan,
        CancellationToken::new(),
        Arc::new(AtomicBool::new(false)),
    )
    .await;

    assert_eq!(summary.responded, 2, "{summary:?}");
    assert_eq!(summary.failed, 0, "{summary:?}");
    assert_eq!(server.targets(), vec!["/alpha", "/beta"]);
    assert_eq!(streams.load(Ordering::Relaxed), 2, "real h2 streams served");
    assert_eq!(server.connections.load(Ordering::Relaxed), 2);
    for result in &results {
        let response = result.result.response.as_ref().expect("response");
        assert_eq!(
            response.version, "HTTP/2.0",
            "Intruder must report the negotiated protocol"
        );
        assert_eq!(response.body, b"h2-ok".to_vec());
    }
}
