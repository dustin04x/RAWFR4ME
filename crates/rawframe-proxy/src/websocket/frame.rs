//! RFC 6455 frame codec used by the interception relay.
//!
//! RAWFRAME parses frames itself instead of forwarding whole messages so that
//! every frame boundary, FIN bit, opcode, and control frame is observable and
//! can be paused, modified, dropped, or cancelled. The parser is deliberately
//! strict: unknown opcodes, non-zero reserved bits, oversized frames, and
//! masking violations end the connection with a protocol close instead of being
//! guessed at.

use std::io;

use rawframe_core::models::websocket::WebSocketOpcode;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// A control frame's payload must fit in a single, unfragmented frame.
pub const MAX_CONTROL_PAYLOAD: usize = 125;

#[derive(Debug)]
pub enum FrameError {
    /// Peer closed the TCP stream between frames.
    Closed,
    Io(io::Error),
    Protocol(&'static str),
    /// The declared payload length exceeded the configured frame ceiling.
    TooLarge {
        len: usize,
        max: usize,
    },
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => write!(formatter, "peer closed the connection"),
            Self::Io(error) => write!(formatter, "stream error: {error}"),
            Self::Protocol(reason) => write!(formatter, "protocol error: {reason}"),
            Self::TooLarge { len, max } => {
                write!(
                    formatter,
                    "frame of {len} bytes exceeds the {max} byte limit"
                )
            }
        }
    }
}

impl From<io::Error> for FrameError {
    fn from(error: io::Error) -> Self {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            Self::Closed
        } else {
            Self::Io(error)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawFrame {
    pub fin: bool,
    pub rsv1: bool,
    pub opcode: WebSocketOpcode,
    pub masked: bool,
    pub payload: Vec<u8>,
}

/// Reads one frame. `require_mask` is true for the client-to-server direction.
pub async fn read_frame<R>(
    reader: &mut R,
    max_bytes: usize,
    require_mask: bool,
) -> Result<RawFrame, FrameError>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 2];
    reader.read_exact(&mut header).await?;

    let fin = header[0] & 0x80 != 0;
    let rsv1 = header[0] & 0x40 != 0;
    if header[0] & 0x30 != 0 {
        return Err(FrameError::Protocol("reserved bits are not negotiated"));
    }
    let opcode = match header[0] & 0x0f {
        0x0 => WebSocketOpcode::Continuation,
        0x1 => WebSocketOpcode::Text,
        0x2 => WebSocketOpcode::Binary,
        0x8 => WebSocketOpcode::Close,
        0x9 => WebSocketOpcode::Ping,
        0xa => WebSocketOpcode::Pong,
        _ => return Err(FrameError::Protocol("unknown frame opcode")),
    };

    let masked = header[1] & 0x80 != 0;
    if masked != require_mask {
        return Err(FrameError::Protocol(if require_mask {
            "client frame was not masked"
        } else {
            "server frame was masked"
        }));
    }

    let short_len = (header[1] & 0x7f) as usize;
    let payload_len = match short_len {
        126 => {
            let mut extended = [0u8; 2];
            reader.read_exact(&mut extended).await?;
            u16::from_be_bytes(extended) as usize
        }
        127 => {
            let mut extended = [0u8; 8];
            reader.read_exact(&mut extended).await?;
            let value = u64::from_be_bytes(extended);
            if value > usize::MAX as u64 {
                return Err(FrameError::TooLarge {
                    len: usize::MAX,
                    max: max_bytes,
                });
            }
            value as usize
        }
        len => len,
    };

    // The mask key belongs to the frame header, so consume it before any
    // validation that may abort mid-frame. Callers draining a refused payload
    // then know exactly how many payload bytes remain.
    let mut key = [0u8; 4];
    if masked {
        reader.read_exact(&mut key).await?;
    }

    if opcode.is_control() {
        if !fin {
            return Err(FrameError::Protocol("control frames may not be fragmented"));
        }
        if payload_len > MAX_CONTROL_PAYLOAD {
            return Err(FrameError::Protocol(
                "control frame payload exceeds 125 bytes",
            ));
        }
    }
    if payload_len > max_bytes {
        return Err(FrameError::TooLarge {
            len: payload_len,
            max: max_bytes,
        });
    }

    let mut payload = vec![0u8; payload_len];
    reader.read_exact(&mut payload).await?;
    if masked {
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= key[index % 4];
        }
    }

    Ok(RawFrame {
        fin,
        rsv1,
        opcode,
        masked,
        payload,
    })
}

/// Encodes and writes one frame. Client-to-server frames are masked with a
/// caller-provided key; server-to-client frames are never masked.
pub async fn write_frame<W>(
    writer: &mut W,
    frame: &RawFrame,
    mask_key: Option<[u8; 4]>,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let payload_len = frame.payload.len();
    let mut header = Vec::with_capacity(14);
    let mut first = 0u8;
    if frame.fin {
        first |= 0x80;
    }
    if frame.rsv1 {
        first |= 0x40;
    }
    first |= match frame.opcode {
        WebSocketOpcode::Continuation => 0x0,
        WebSocketOpcode::Text => 0x1,
        WebSocketOpcode::Binary => 0x2,
        WebSocketOpcode::Close => 0x8,
        WebSocketOpcode::Ping => 0x9,
        WebSocketOpcode::Pong => 0xa,
        WebSocketOpcode::Unknown(value) => value & 0x0f,
    };
    header.push(first);

    let mask_bit = if mask_key.is_some() { 0x80 } else { 0 };
    if payload_len <= 125 {
        header.push(mask_bit | payload_len as u8);
    } else if payload_len <= u16::MAX as usize {
        header.push(mask_bit | 126);
        header.extend_from_slice(&(payload_len as u16).to_be_bytes());
    } else {
        header.push(mask_bit | 127);
        header.extend_from_slice(&(payload_len as u64).to_be_bytes());
    }

    match mask_key {
        Some(key) => {
            header.extend_from_slice(&key);
            let mut masked = Vec::with_capacity(payload_len);
            for (index, byte) in frame.payload.iter().enumerate() {
                masked.push(byte ^ key[index % 4]);
            }
            writer.write_all(&header).await?;
            writer.write_all(&masked).await?;
        }
        None => {
            writer.write_all(&header).await?;
            writer.write_all(&frame.payload).await?;
        }
    }
    writer.flush().await
}

/// Deterministic, non-secret mask key. RFC 6455 requires masking to prevent
/// cache-poisoning attacks on intermediaries, not for confidentiality; a
/// rotating counter keeps the mask unpredictable enough for that purpose.
pub fn mask_key(sequence: u64) -> [u8; 4] {
    let mut value = sequence.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0xA5A5_5A5A_1234_5678;
    let mut key = [0u8; 4];
    for slot in &mut key {
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        *slot = (value & 0xff) as u8;
    }
    if key == [0, 0, 0, 0] {
        key = [0x12, 0x34, 0x56, 0x78];
    }
    key
}

/// Builds the close payload for a status code with an optional reason.
pub fn close_frame(code: u16, reason: &str) -> RawFrame {
    let mut payload = Vec::with_capacity(2 + reason.len());
    payload.extend_from_slice(&code.to_be_bytes());
    let reason = reason.as_bytes();
    let take = reason.len().min(MAX_CONTROL_PAYLOAD - 2);
    payload.extend_from_slice(&reason[..take]);
    RawFrame {
        fin: true,
        rsv1: false,
        opcode: WebSocketOpcode::Close,
        masked: false,
        payload,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn masked_frames_round_trip_between_roles() {
        let (mut client, mut server) = duplex(4096);
        let frame = RawFrame {
            fin: true,
            rsv1: false,
            opcode: WebSocketOpcode::Text,
            masked: false,
            payload: b"hello websocket".to_vec(),
        };
        write_frame(&mut client, &frame, Some(mask_key(7)))
            .await
            .unwrap();
        let decoded = read_frame(&mut server, 1024, true).await.unwrap();
        assert_eq!(decoded.opcode, WebSocketOpcode::Text);
        assert!(decoded.masked);
        assert_eq!(decoded.payload, b"hello websocket");
    }

    #[tokio::test]
    async fn extended_lengths_and_empty_payloads_are_supported() {
        let (mut writer, mut reader) = duplex(5 * 1024 * 1024);
        let payload = vec![0xab; 70_000];
        let frame = RawFrame {
            fin: true,
            rsv1: false,
            opcode: WebSocketOpcode::Binary,
            masked: false,
            payload: payload.clone(),
        };
        write_frame(&mut writer, &frame, None).await.unwrap();
        let decoded = read_frame(&mut reader, 128 * 1024, false).await.unwrap();
        assert_eq!(decoded.payload, payload);

        let empty = RawFrame {
            fin: true,
            rsv1: false,
            opcode: WebSocketOpcode::Ping,
            masked: false,
            payload: Vec::new(),
        };
        write_frame(&mut writer, &empty, None).await.unwrap();
        let decoded = read_frame(&mut reader, 1024, false).await.unwrap();
        assert!(decoded.payload.is_empty());
    }

    #[tokio::test]
    async fn oversized_frames_are_refused_before_allocation() {
        let (mut writer, mut reader) = duplex(4096);
        // A 64 KiB frame with a 1 KiB ceiling must be rejected from the header.
        // Writing the payload would block past the duplex buffer, so write the
        // header only.
        writer.write_all(&[0x82, 127]).await.unwrap();
        writer.write_all(&(65_536u64).to_be_bytes()).await.unwrap();
        let error = read_frame(&mut reader, 1024, false).await.unwrap_err();
        assert!(matches!(error, FrameError::TooLarge { .. }));
    }

    #[tokio::test]
    async fn protocol_violations_are_rejected() {
        let (mut writer, mut reader) = duplex(1024);
        // Unmasked client frame.
        writer.write_all(&[0x81, 0x01, b'x']).await.unwrap();
        let error = read_frame(&mut reader, 1024, true).await.unwrap_err();
        assert!(matches!(error, FrameError::Protocol(_)));

        // Fragmented control frame.
        writer.write_all(&[0x09, 0x80, 1, 2, 3, 4]).await.unwrap();
        let error = read_frame(&mut reader, 1024, true).await.unwrap_err();
        assert!(matches!(error, FrameError::Protocol(_)));
    }
}
