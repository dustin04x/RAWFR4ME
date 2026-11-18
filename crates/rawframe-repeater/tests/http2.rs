//! Repeater HTTP/2 tests against a real TLS origin that negotiates ALPN.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http2;
use hyper::service::service_fn;
use hyper::{Response, StatusCode, Version};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rawframe_core::models::config::{Scope, ScopeRule};
use rawframe_core::models::message::{HttpRequest, Scheme};
use rawframe_core::repeater::RepeaterExecutionPhase;
use rawframe_repeater::{RepeaterConfig, RepeaterEngine};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, SanType,
};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

fn temp_dir(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "rawframe-repeater-h2-{name}-{nanos}-{}",
        std::process::id()
    ))
}

struct Ca {
    cert: rcgen::Certificate,
    key: KeyPair,
    cert_der: CertificateDer<'static>,
    file: PathBuf,
}

fn make_ca(dir: &PathBuf) -> Ca {
    std::fs::create_dir_all(dir).unwrap();
    let mut params = CertificateParams::default();
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(DnType::CommonName, "RAWFRAME Repeater h2 CA");
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    let file = dir.join("ca.pem");
    std::fs::write(&file, cert.pem()).unwrap();
    Ca {
        cert_der: CertificateDer::from(cert.der().to_vec()),
        cert,
        key,
        file,
    }
}

fn server_config(ca: &Ca, alpn: &[&[u8]]) -> ServerConfig {
    let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(DnType::CommonName, "localhost");
    params.distinguished_name = dn;
    params.subject_alt_names = vec![SanType::DnsName("localhost".try_into().unwrap())];
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

#[derive(Clone)]
struct Reply {
    status: u16,
    body: Vec<u8>,
    location: Option<String>,
    delay: Duration,
}

impl Reply {
    fn new(status: u16, body: &str) -> Self {
        Self {
            status,
            body: body.as_bytes().to_vec(),
            location: None,
            delay: Duration::ZERO,
        }
    }
}

struct Seen {
    version: Version,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

struct Origin {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Origin {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn spawn_origin(ca: &Ca, alpn: &[&[u8]], reply: Reply) -> Origin {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen_task = seen.clone();
    let acceptor = TlsAcceptor::from(Arc::new(server_config(ca, alpn)));
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            let seen = seen_task.clone();
            let reply = reply.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
                let service = service_fn(move |request: hyper::Request<Incoming>| {
                    let seen = seen.clone();
                    let reply = reply.clone();
                    async move {
                        let version = request.version();
                        let target = request
                            .uri()
                            .path_and_query()
                            .map(|p| p.as_str().to_string());
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
                            .map(|c| c.to_bytes().to_vec())
                            .unwrap_or_default();
                        seen.lock().unwrap().push(Seen {
                            version,
                            target: target.clone().unwrap_or_else(|| "/".into()),
                            headers,
                            body,
                        });
                        if !reply.delay.is_zero() {
                            tokio::time::sleep(reply.delay).await;
                        }
                        // Only the first hop redirects; the target answers 200.
                        let redirecting = reply
                            .location
                            .as_ref()
                            .is_some_and(|_| target.as_deref() == Some("/start"));
                        let body = if reply.location.is_some() && !redirecting {
                            b"final-body".to_vec()
                        } else {
                            reply.body.clone()
                        };
                        let mut response = Response::new(Full::new(Bytes::from(body)));
                        *response.status_mut() =
                            StatusCode::from_u16(if redirecting { reply.status } else { 200 })
                                .unwrap();
                        if redirecting && let Some(location) = &reply.location {
                            response
                                .headers_mut()
                                .insert("location", location.parse().unwrap());
                        }
                        Ok::<_, std::convert::Infallible>(response)
                    }
                });
                if h2 {
                    let _ = http2::Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(tls), service)
                        .await;
                } else {
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(tls), service)
                        .await;
                }
            });
        }
    });
    Origin { addr, seen, task }
}

fn engine(ca: &Ca, port: u16) -> RepeaterEngine {
    let scope = Scope::allow(ScopeRule {
        host_pattern: "localhost".into(),
        scheme: Some(Scheme::Https),
        port: Some(port),
    });
    RepeaterEngine::new(
        RepeaterConfig {
            allow_private_upstreams: true,
            max_request_body: 1024 * 1024,
            max_response_bytes: 1024 * 1024,
            connect_timeout: Duration::from_secs(3),
            response_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(3),
            max_concurrent: 4,
            trust_file: Some(ca.file.clone()),
        },
        Arc::new(std::sync::RwLock::new(scope)),
    )
}

fn request(port: u16, method: &str, target: &str) -> HttpRequest {
    HttpRequest::new(method, Scheme::Https, "localhost", port, target)
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
async fn repeater_negotiates_h2_and_reports_the_actual_protocol() {
    let dir = temp_dir("negotiate");
    let ca = make_ca(&dir);
    let origin = spawn_origin(&ca, &[b"h2", b"http/1.1"], Reply::new(200, "h2-body")).await;
    let engine = engine(&ca, origin.addr.port());

    let mut request = request(origin.addr.port(), "POST", "/h2?q=1");
    request.body = b"request-body".to_vec();
    request.headers.append("Content-Type", "text/plain");
    request.headers.append("X-Trace", "keep-me");
    let outcome = execute(&engine, &request, false).await;

    assert!(outcome.is_success(), "{:?}", outcome.failure);
    let response = outcome.result.response.as_ref().unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(
        response.version, "HTTP/2.0",
        "the result must report the negotiated protocol"
    );
    assert_eq!(response.body, b"h2-body");

    let seen = origin.seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].version, Version::HTTP_2);
    assert_eq!(seen[0].target, "/h2?q=1");
    assert_eq!(seen[0].body, b"request-body");
    assert!(
        seen[0]
            .headers
            .iter()
            .any(|(name, value)| name == "x-trace" && value == "keep-me")
    );
    // The authority is carried by the absolute URI; an HTTP/1.1 Host field must
    // not appear as a regular HTTP/2 header.
    assert!(
        !seen[0].headers.iter().any(|(name, _)| name == "host"),
        "Host leaked into the HTTP/2 header list: {:?}",
        seen[0].headers
    );

    drop(seen);
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http11_fallback_is_used_and_reported_when_alpn_declines_h2() {
    let dir = temp_dir("fallback");
    let ca = make_ca(&dir);
    let origin = spawn_origin(&ca, &[b"http/1.1"], Reply::new(200, "h1-body")).await;
    let engine = engine(&ca, origin.addr.port());

    let outcome = execute(
        &engine,
        &request(origin.addr.port(), "GET", "/fallback"),
        false,
    )
    .await;
    assert!(outcome.is_success(), "{:?}", outcome.failure);
    let response = outcome.result.response.as_ref().unwrap();
    assert_eq!(response.version, "HTTP/1.1");
    assert_eq!(response.body, b"h1-body");

    let seen = origin.seen.lock().unwrap();
    assert_eq!(seen[0].version, Version::HTTP_11);

    drop(seen);
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_redirects_are_followed_and_remain_http2() {
    let dir = temp_dir("redirect");
    let ca = make_ca(&dir);
    // The origin always redirects; following one hop proves the redirect target
    // is executed through a fresh, independently negotiated h2 connection.
    let origin = spawn_origin(
        &ca,
        &[b"h2"],
        Reply {
            status: 302,
            body: Vec::new(),
            location: Some("/final".into()),
            delay: Duration::ZERO,
        },
    )
    .await;
    let engine = engine(&ca, origin.addr.port());

    let outcome = execute(&engine, &request(origin.addr.port(), "GET", "/start"), true).await;
    assert!(
        !outcome.result.redirects.is_empty(),
        "{:?}",
        outcome.failure
    );
    let response = outcome.result.response.as_ref().unwrap();
    assert_eq!(response.version, "HTTP/2.0");
    assert_eq!(outcome.result.redirects[0].status, 302);

    let seen = origin.seen.lock().unwrap();
    assert_eq!(seen.len(), 2, "{:?}", seen.len());
    assert!(seen.iter().all(|entry| entry.version == Version::HTTP_2));
    assert_eq!(seen[1].target, "/final");

    drop(seen);
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_execution_is_cancellable() {
    let dir = temp_dir("cancel");
    let ca = make_ca(&dir);
    let origin = spawn_origin(
        &ca,
        &[b"h2"],
        Reply {
            status: 200,
            body: b"late".to_vec(),
            location: None,
            delay: Duration::from_secs(3),
        },
    )
    .await;
    let engine = engine(&ca, origin.addr.port());
    let cancel = CancellationToken::new();
    let trigger = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(150)).await;
        trigger.cancel();
    });

    let outcome = engine
        .execute(
            &request(origin.addr.port(), "GET", "/slow"),
            false,
            cancel,
            |_| {},
        )
        .await;
    assert!(
        outcome.result.response.is_none(),
        "a cancelled execution must not report a response"
    );
    assert_eq!(outcome.phase, RepeaterExecutionPhase::Cancelled);

    let _ = std::fs::remove_dir_all(dir);
}
