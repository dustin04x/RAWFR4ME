//! Development-only HTTP/2 TLS origin for PTY evidence.
//!
//! This binary is not part of the shipped application. It binds a loopback
//! listener, serves only `h2` via ALPN, and prints its address and certificate
//! path so `scripts/capture_http2_pty.py` can drive the real TUI against a
//! genuine HTTP/2 server. Nothing here is used by the proxy or Repeater.

use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, SanType,
};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

async fn echo(
    request: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let version = request.version();
    let method = request.method().to_string();
    let path = request.uri().path().to_string();
    let body = request
        .into_body()
        .collect()
        .await
        .map(|collected| collected.to_bytes())
        .unwrap_or_default();
    let payload = format!(
        "h2-origin version={version:?} method={method} path={path} body={}",
        String::from_utf8_lossy(&body)
    );
    Ok(Response::new(Full::new(Bytes::from(payload))))
}

#[tokio::main]
async fn main() {
    let cert_path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: h2_origin <cert-out.pem>");
        std::process::exit(2);
    });

    let mut ca_params = CertificateParams::default();
    let mut ca_dn = rcgen::DistinguishedName::new();
    ca_dn.push(DnType::CommonName, "RAWFRAME h2 evidence CA");
    ca_params.distinguished_name = ca_dn;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(DnType::CommonName, "localhost");
    params.distinguished_name = dn;
    params.subject_alt_names = vec![SanType::DnsName("localhost".try_into().unwrap())];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = params.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();
    std::fs::write(&cert_path, ca_cert.pem()).unwrap();

    let chain = vec![
        CertificateDer::from(leaf.der().to_vec()),
        CertificateDer::from(ca_cert.der().to_vec()),
    ];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    println!("ADDR={addr}");
    println!("CERT={cert_path}");
    println!("READY");

    loop {
        let Ok((stream, _)) = listener.accept().await else {
            break;
        };
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let Ok(tls) = acceptor.accept(stream).await else {
                return;
            };
            debug_assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
            let service = service_fn(echo);
            if let Err(error) = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(tls), service)
                .await
                && error.is_incomplete_message()
            {
                // Client closed mid-stream; evidence traffic is short-lived.
            }
        });
    }
}
