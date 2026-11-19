//! Operator-driven WebSocket client used by the WebSocket Repeater.
//!
//! This is a client, not a relay: it resolves and validates the destination
//! through the same address policy as the proxy, verifies upstream TLS with the
//! same configuration, and exchanges whole RFC 6455 frames. It never negotiates
//! compression and never accepts reserved bits.

use std::sync::Arc;
use std::time::Duration;

use rawframe_core::models::message::Scheme;
use rawframe_core::models::websocket::WebSocketOpcode;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;

use crate::destination::{Destination, connect_upstream};
use crate::tls::intercept::{
    build_upstream_tls_config_with_trust_file, upstream_connector, upstream_server_name,
};

use super::frame::{FrameError, RawFrame, close_frame, mask_key, read_frame, write_frame};
use super::{
    MAX_HANDSHAKE_HEAD_BYTES, header_contains_token, header_value, parse_response_head,
    read_handshake_head,
};

trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}

#[derive(Debug, Clone)]
pub struct WebSocketClientConfig {
    pub allow_private_upstreams: bool,
    pub connect_timeout: Duration,
    pub max_frame_bytes: usize,
    pub trust_file: Option<std::path::PathBuf>,
}

#[derive(Debug, thiserror::Error)]
pub enum WebSocketClientError {
    #[error("{0}")]
    Rejected(String),
    #[error("upstream connect failed: {0}")]
    Connect(String),
    #[error("upstream TLS failed: {0}")]
    Tls(String),
    #[error("upstream handshake failed: {0}")]
    Handshake(String),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("upstream idle timeout")]
    Idle,
    #[error("connection closed")]
    Closed,
}

impl From<FrameError> for WebSocketClientError {
    fn from(error: FrameError) -> Self {
        match error {
            FrameError::Closed => Self::Closed,
            FrameError::Protocol(reason) => Self::Protocol(reason.into()),
            FrameError::TooLarge { len, max } => {
                Self::Protocol(format!("frame of {len} bytes exceeds the {max} byte limit"))
            }
            FrameError::Io(error) => Self::Connect(error.to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientFrame {
    pub fin: bool,
    pub opcode: WebSocketOpcode,
    pub payload: Vec<u8>,
}

pub struct WebSocketClient {
    stream: Option<Box<dyn AsyncStream>>,
    max_frame_bytes: usize,
    subprotocol: Option<String>,
    mask_sequence: u64,
}

impl WebSocketClient {
    /// Connects and performs the HTTP/1.1 upgrade. Scope enforcement belongs to
    /// the caller and must happen before this function is reached.
    pub async fn connect(
        destination: &Destination,
        subprotocol: Option<&str>,
        config: &WebSocketClientConfig,
    ) -> Result<Self, WebSocketClientError> {
        if destination.scheme == Scheme::Https && config.trust_file.is_none() {
            // System roots are still verified; this branch documents that no
            // insecure mode exists rather than enabling one.
        }
        let tcp = connect_upstream(
            destination,
            config.allow_private_upstreams,
            config.connect_timeout,
        )
        .await
        .map_err(|rejection| WebSocketClientError::Rejected(rejection.message))?;

        let stream: Box<dyn AsyncStream> = if destination.scheme == Scheme::Https {
            let tls = build_upstream_tls_config_with_trust_file(config.trust_file.as_deref())
                .map_err(|error| WebSocketClientError::Tls(error.to_string()))?;
            let connector = upstream_connector(Arc::new(tls));
            let server_name = upstream_server_name(&destination.host)
                .map_err(|error| WebSocketClientError::Tls(error.to_string()))?;
            match timeout(config.connect_timeout, connector.connect(server_name, tcp)).await {
                Ok(Ok(stream)) => Box::new(stream),
                Ok(Err(error)) => {
                    return Err(WebSocketClientError::Tls(format!(
                        "upstream TLS verification failed: {error}"
                    )));
                }
                Err(_) => {
                    return Err(WebSocketClientError::Tls(
                        "upstream TLS handshake timed out".into(),
                    ));
                }
            }
        } else {
            Box::new(tcp)
        };

        Self::handshake(stream, destination, subprotocol, config).await
    }

    async fn handshake(
        mut stream: Box<dyn AsyncStream>,
        destination: &Destination,
        subprotocol: Option<&str>,
        config: &WebSocketClientConfig,
    ) -> Result<Self, WebSocketClientError> {
        let key = generate_client_key();
        let accept = derive_accept_key(key.as_bytes());
        let authority = if destination.port == destination.scheme.default_port() {
            destination.host.clone()
        } else {
            format!("{}:{}", destination.host, destination.port)
        };
        let target = if destination.target.is_empty() {
            "/"
        } else {
            destination.target.as_str()
        };
        if let Some(protocol) = subprotocol
            && (protocol.is_empty()
                || !protocol
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(ch)))
        {
            return Err(WebSocketClientError::Handshake(
                "invalid Sec-WebSocket-Protocol token".into(),
            ));
        }

        let mut head = String::with_capacity(512);
        head.push_str(&format!("GET {target} HTTP/1.1\r\n"));
        head.push_str(&format!("Host: {authority}\r\n"));
        head.push_str("Upgrade: websocket\r\nConnection: Upgrade\r\n");
        head.push_str(&format!("Sec-WebSocket-Key: {key}\r\n"));
        head.push_str("Sec-WebSocket-Version: 13\r\n");
        if let Some(protocol) = subprotocol {
            head.push_str(&format!("Sec-WebSocket-Protocol: {protocol}\r\n"));
        }
        head.push_str("\r\n");

        stream
            .write_all(head.as_bytes())
            .await
            .map_err(|error| WebSocketClientError::Handshake(error.to_string()))?;
        stream
            .flush()
            .await
            .map_err(|error| WebSocketClientError::Handshake(error.to_string()))?;

        let head = match timeout(config.connect_timeout, read_handshake_head(&mut stream)).await {
            Ok(Ok(head)) => head,
            Ok(Err(error)) => {
                return Err(WebSocketClientError::Handshake(error.to_string()));
            }
            Err(_) => {
                return Err(WebSocketClientError::Handshake(
                    "handshake timed out".into(),
                ));
            }
        };
        if head.len() > MAX_HANDSHAKE_HEAD_BYTES {
            return Err(WebSocketClientError::Handshake(
                "response head exceeds the limit".into(),
            ));
        }
        let response = parse_response_head(&head).map_err(WebSocketClientError::Handshake)?;
        if response.status != 101 {
            return Err(WebSocketClientError::Handshake(format!(
                "upstream answered {} {} instead of 101",
                response.status, response.reason
            )));
        }
        if !header_contains_token(&response, "upgrade", "websocket")
            || !header_contains_token(&response, "connection", "upgrade")
        {
            return Err(WebSocketClientError::Handshake(
                "101 response is missing WebSocket upgrade headers".into(),
            ));
        }
        if header_value(&response, "sec-websocket-accept").unwrap_or("") != accept {
            return Err(WebSocketClientError::Handshake(
                "Sec-WebSocket-Accept did not match the client key".into(),
            ));
        }
        if header_value(&response, "sec-websocket-extensions").is_some() {
            return Err(WebSocketClientError::Handshake(
                "compression extensions are not supported".into(),
            ));
        }
        let selected = header_value(&response, "sec-websocket-protocol").map(str::to_string);
        if let Some(selected) = &selected
            && subprotocol != Some(selected.as_str())
        {
            return Err(WebSocketClientError::Handshake(
                "upstream selected a subprotocol that was not offered".into(),
            ));
        }

        Ok(Self {
            stream: Some(stream),
            max_frame_bytes: config.max_frame_bytes,
            subprotocol: selected,
            mask_sequence: 1,
        })
    }

    /// Splits the connection so a reader task can wait for frames while the
    /// session loop remains responsive to operator commands. Both halves share
    /// the frame limit; only the writer holds a mask sequence.
    pub fn into_split(mut self) -> (ClientReader, ClientWriter) {
        let stream = self.stream.take().expect("client stream is present");
        let (reader, writer) = tokio::io::split(stream);
        (
            ClientReader {
                reader,
                max_frame_bytes: self.max_frame_bytes,
            },
            ClientWriter {
                writer,
                max_frame_bytes: self.max_frame_bytes,
                mask_sequence: self.mask_sequence,
            },
        )
    }

    pub fn subprotocol(&self) -> Option<&str> {
        self.subprotocol.as_deref()
    }
}

pub struct ClientReader {
    reader: ReadHalf<Box<dyn AsyncStream>>,
    max_frame_bytes: usize,
}

impl ClientReader {
    /// Reads one frame, including control frames. Callers own ping/pong and
    /// close semantics so the session loop can respond deterministically.
    pub async fn receive(&mut self) -> Result<ClientFrame, WebSocketClientError> {
        let frame = read_frame(&mut self.reader, self.max_frame_bytes, false).await?;
        Ok(ClientFrame {
            fin: frame.fin,
            opcode: frame.opcode,
            payload: frame.payload,
        })
    }
}

pub struct ClientWriter {
    writer: WriteHalf<Box<dyn AsyncStream>>,
    max_frame_bytes: usize,
    mask_sequence: u64,
}

impl ClientWriter {
    /// Sends one complete frame. Client frames are always masked.
    pub async fn send(
        &mut self,
        opcode: WebSocketOpcode,
        payload: Vec<u8>,
    ) -> Result<(), WebSocketClientError> {
        if payload.len() > self.max_frame_bytes {
            return Err(WebSocketClientError::Protocol(format!(
                "frame of {} bytes exceeds the {} byte limit",
                payload.len(),
                self.max_frame_bytes
            )));
        }
        if opcode.is_control() && payload.len() > 125 {
            return Err(WebSocketClientError::Protocol(
                "control frames may not exceed 125 bytes".into(),
            ));
        }
        let frame = RawFrame {
            fin: true,
            rsv1: false,
            opcode,
            masked: true,
            payload,
        };
        let masked = mask_key(self.mask_sequence);
        self.mask_sequence = self.mask_sequence.wrapping_add(1);
        write_frame(&mut self.writer, &frame, Some(masked))
            .await
            .map_err(|error| WebSocketClientError::Connect(error.to_string()))
    }

    pub async fn send_close(&mut self, code: u16, reason: &str) {
        let frame = close_frame(code, reason);
        let masked = mask_key(self.mask_sequence);
        self.mask_sequence = self.mask_sequence.wrapping_add(1);
        let _ = write_frame(&mut self.writer, &frame, Some(masked)).await;
        let _ = self.writer.flush().await;
    }
}

/// RFC 6455 requires a 16-byte, base64-encoded nonce. The value only has to be
/// unpredictable to the peer; `tungstenite` provides the same generator the
/// proxy already depends on for handshake parsing.
fn generate_client_key() -> String {
    tokio_tungstenite::tungstenite::handshake::client::generate_key()
}
