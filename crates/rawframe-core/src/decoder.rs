//! Bounded, binary-safe data transformations for the Decoder workspace.
//!
//! Every operation takes and returns bytes. Text-only formats validate UTF-8
//! instead of replacing invalid sequences, and every output is checked against
//! a limit before it is returned. A pipeline is deterministic and sequential:
//! the first failing step stops execution and reports its index.
//!
//! JWT inspection decodes only. It does not verify signatures and never labels
//! a token as valid. MD5 is provided as a legacy checksum and is explicitly
//! marked as unsuitable for security verification.

use std::io::{Read, Write};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use chrono::{TimeZone, Utc};
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use md5::Md5;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256, Sha384, Sha512};
use thiserror::Error;

/// Default input ceiling for a single Decoder operation or pipeline.
pub const DECODER_DEFAULT_MAX_INPUT: usize = 8 * 1024 * 1024;
/// Default output ceiling for every transformation step.
pub const DECODER_DEFAULT_MAX_OUTPUT: usize = 8 * 1024 * 1024;
/// A bounded chain keeps intermediate buffers and execution time predictable.
pub const DECODER_MAX_PIPELINE_STEPS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Encode,
    Decode,
    Inspect,
}

impl Direction {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Encode => "Encode",
            Self::Decode => "Decode",
            Self::Inspect => "Inspect",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transform {
    Base64Encode,
    Base64Decode,
    Base64UrlEncode,
    Base64UrlDecode,
    HexEncode,
    HexDecode,
    UrlEncode,
    UrlDecode,
    HtmlEntityEncode,
    HtmlEntityDecode,
    UnicodeEscapeEncode,
    UnicodeEscapeDecode,
    JwtInspect,
    JsonPretty,
    JsonMinify,
    JsonValidate,
    GzipCompress,
    GzipDecompress,
    Sha256,
    Sha384,
    Sha512,
    Md5Legacy,
}

impl Transform {
    pub const ALL: [Self; 22] = [
        Self::Base64Encode,
        Self::Base64Decode,
        Self::Base64UrlEncode,
        Self::Base64UrlDecode,
        Self::HexEncode,
        Self::HexDecode,
        Self::UrlEncode,
        Self::UrlDecode,
        Self::HtmlEntityEncode,
        Self::HtmlEntityDecode,
        Self::UnicodeEscapeEncode,
        Self::UnicodeEscapeDecode,
        Self::JwtInspect,
        Self::JsonPretty,
        Self::JsonMinify,
        Self::JsonValidate,
        Self::GzipCompress,
        Self::GzipDecompress,
        Self::Sha256,
        Self::Sha384,
        Self::Sha512,
        Self::Md5Legacy,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Base64Encode => "Base64 encode",
            Self::Base64Decode => "Base64 decode",
            Self::Base64UrlEncode => "Base64 URL-safe encode",
            Self::Base64UrlDecode => "Base64 URL-safe decode",
            Self::HexEncode => "Hex encode",
            Self::HexDecode => "Hex decode",
            Self::UrlEncode => "URL percent encode",
            Self::UrlDecode => "URL percent decode",
            Self::HtmlEntityEncode => "HTML entity encode",
            Self::HtmlEntityDecode => "HTML entity decode",
            Self::UnicodeEscapeEncode => "Unicode escape encode",
            Self::UnicodeEscapeDecode => "Unicode escape decode",
            Self::JwtInspect => "JWT inspect",
            Self::JsonPretty => "JSON pretty print",
            Self::JsonMinify => "JSON minify",
            Self::JsonValidate => "JSON validate",
            Self::GzipCompress => "Gzip compress",
            Self::GzipDecompress => "Gzip decompress",
            Self::Sha256 => "SHA-256",
            Self::Sha384 => "SHA-384",
            Self::Sha512 => "SHA-512",
            Self::Md5Legacy => "MD5 (legacy checksum)",
        }
    }

    pub const fn direction(self) -> Direction {
        match self {
            Self::Base64Encode
            | Self::Base64UrlEncode
            | Self::HexEncode
            | Self::UrlEncode
            | Self::HtmlEntityEncode
            | Self::UnicodeEscapeEncode
            | Self::GzipCompress => Direction::Encode,
            Self::Base64Decode
            | Self::Base64UrlDecode
            | Self::HexDecode
            | Self::UrlDecode
            | Self::HtmlEntityDecode
            | Self::UnicodeEscapeDecode
            | Self::GzipDecompress => Direction::Decode,
            Self::JwtInspect
            | Self::JsonPretty
            | Self::JsonMinify
            | Self::JsonValidate
            | Self::Sha256
            | Self::Sha384
            | Self::Sha512
            | Self::Md5Legacy => Direction::Inspect,
        }
    }

    /// Returns the paired direction for reversible operations.
    pub const fn toggled_direction(self) -> Option<Self> {
        Some(match self {
            Self::Base64Encode => Self::Base64Decode,
            Self::Base64Decode => Self::Base64Encode,
            Self::Base64UrlEncode => Self::Base64UrlDecode,
            Self::Base64UrlDecode => Self::Base64UrlEncode,
            Self::HexEncode => Self::HexDecode,
            Self::HexDecode => Self::HexEncode,
            Self::UrlEncode => Self::UrlDecode,
            Self::UrlDecode => Self::UrlEncode,
            Self::HtmlEntityEncode => Self::HtmlEntityDecode,
            Self::HtmlEntityDecode => Self::HtmlEntityEncode,
            Self::UnicodeEscapeEncode => Self::UnicodeEscapeDecode,
            Self::UnicodeEscapeDecode => Self::UnicodeEscapeEncode,
            Self::GzipCompress => Self::GzipDecompress,
            Self::GzipDecompress => Self::GzipCompress,
            _ => return None,
        })
    }

    pub const fn warning(self) -> Option<&'static str> {
        match self {
            Self::JwtInspect => Some(
                "JWT decoding does not verify the signature. A decoded token is not a valid token.",
            ),
            Self::Md5Legacy => Some(
                "MD5 is a legacy checksum and is cryptographically broken; never use it for security verification.",
            ),
            Self::GzipDecompress => Some(
                "Decompression is bounded by the configured output limit; a decompression bomb is rejected.",
            ),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransformLimits {
    pub max_input_bytes: usize,
    pub max_output_bytes: usize,
}

impl Default for TransformLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: DECODER_DEFAULT_MAX_INPUT,
            max_output_bytes: DECODER_DEFAULT_MAX_OUTPUT,
        }
    }
}

impl TransformLimits {
    pub const fn new(max_input_bytes: usize, max_output_bytes: usize) -> Self {
        Self {
            max_input_bytes,
            max_output_bytes,
        }
    }
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum TransformError {
    #[error("input is {actual} bytes; the limit is {limit} bytes")]
    InputTooLarge { actual: usize, limit: usize },
    #[error("output would exceed the {limit}-byte limit")]
    OutputTooLarge { limit: usize },
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("pipeline is limited to {0} steps")]
    TooManySteps(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputFormat {
    Text,
    Json,
    Jwt,
    Binary,
}

impl OutputFormat {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Text => "TEXT",
            Self::Json => "JSON",
            Self::Jwt => "JWT INSPECTION",
            Self::Binary => "BINARY",
        }
    }

    pub const fn is_binary(self) -> bool {
        matches!(self, Self::Binary)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransformOutput {
    pub bytes: Vec<u8>,
    pub format: OutputFormat,
    pub note: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PipelineStep {
    pub index: usize,
    pub transform: Transform,
    pub input_bytes: usize,
    pub output_bytes: usize,
    pub format: OutputFormat,
    pub output: Vec<u8>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipelineFailure {
    /// Zero-based step index. `0` with no transform means the input itself was
    /// rejected before execution.
    pub step_index: usize,
    pub transform: Option<Transform>,
    pub message: String,
}

impl PipelineFailure {
    pub fn label(&self) -> String {
        match self.transform {
            Some(transform) => format!("Step {} · {}", self.step_index + 1, transform.label()),
            None => "Input".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PipelineRun {
    pub input_bytes: usize,
    pub steps: Vec<PipelineStep>,
    pub output: Option<TransformOutput>,
    pub error: Option<PipelineFailure>,
}

impl PipelineRun {
    pub const fn succeeded(&self) -> bool {
        self.error.is_none() && self.output.is_some()
    }

    pub fn total_output_bytes(&self) -> usize {
        self.output.as_ref().map_or(0, |output| output.bytes.len())
    }
}

/// Executes a deterministic, sequential pipeline. The original input is never
/// modified. A failed step stops execution and retains only completed steps.
pub fn execute_pipeline(input: &[u8], steps: &[Transform], limits: TransformLimits) -> PipelineRun {
    if input.len() > limits.max_input_bytes {
        return PipelineRun {
            input_bytes: input.len(),
            steps: Vec::new(),
            output: None,
            error: Some(PipelineFailure {
                step_index: 0,
                transform: None,
                message: TransformError::InputTooLarge {
                    actual: input.len(),
                    limit: limits.max_input_bytes,
                }
                .to_string(),
            }),
        };
    }
    if steps.len() > DECODER_MAX_PIPELINE_STEPS {
        return PipelineRun {
            input_bytes: input.len(),
            steps: Vec::new(),
            output: None,
            error: Some(PipelineFailure {
                step_index: DECODER_MAX_PIPELINE_STEPS,
                transform: None,
                message: TransformError::TooManySteps(DECODER_MAX_PIPELINE_STEPS).to_string(),
            }),
        };
    }

    let mut current = input.to_vec();
    let mut completed = Vec::new();
    for (index, step) in steps.iter().copied().enumerate() {
        match transform(&current, step, limits) {
            Ok(output) => {
                completed.push(PipelineStep {
                    index,
                    transform: step,
                    input_bytes: current.len(),
                    output_bytes: output.bytes.len(),
                    format: output.format,
                    output: output.bytes.clone(),
                    note: output.note,
                });
                current = output.bytes;
            }
            Err(error) => {
                return PipelineRun {
                    input_bytes: input.len(),
                    steps: completed,
                    output: None,
                    error: Some(PipelineFailure {
                        step_index: index,
                        transform: Some(step),
                        message: error.to_string(),
                    }),
                };
            }
        }
    }

    let format = detect_format(&current);
    PipelineRun {
        input_bytes: input.len(),
        steps: completed,
        output: Some(TransformOutput {
            bytes: current,
            format,
            note: None,
        }),
        error: None,
    }
}

/// Applies one bounded transformation to a byte buffer.
pub fn transform(
    input: &[u8],
    operation: Transform,
    limits: TransformLimits,
) -> Result<TransformOutput, TransformError> {
    if input.len() > limits.max_input_bytes {
        return Err(TransformError::InputTooLarge {
            actual: input.len(),
            limit: limits.max_input_bytes,
        });
    }

    let output = match operation {
        Transform::Base64Encode => TransformOutput {
            bytes: STANDARD.encode(input).into_bytes(),
            format: OutputFormat::Text,
            note: None,
        },
        Transform::Base64Decode => {
            let cleaned = without_ascii_whitespace(input);
            let bytes = STANDARD
                .decode(&cleaned)
                .map_err(|error| invalid(format!("Base64 decode failed: {error}")))?;
            detected_output(bytes, None)
        }
        Transform::Base64UrlEncode => TransformOutput {
            bytes: URL_SAFE_NO_PAD.encode(input).into_bytes(),
            format: OutputFormat::Text,
            note: None,
        },
        Transform::Base64UrlDecode => {
            let cleaned = without_ascii_whitespace(input);
            let bytes = URL_SAFE_NO_PAD
                .decode(&cleaned)
                .or_else(|_| URL_SAFE.decode(&cleaned))
                .map_err(|error| invalid(format!("Base64 URL-safe decode failed: {error}")))?;
            detected_output(bytes, None)
        }
        Transform::HexEncode => {
            let mut text = String::with_capacity(input.len() * 2);
            for byte in input {
                use std::fmt::Write as _;
                let _ = write!(text, "{byte:02x}");
            }
            TransformOutput {
                bytes: text.into_bytes(),
                format: OutputFormat::Text,
                note: None,
            }
        }
        Transform::HexDecode => {
            let cleaned = without_ascii_whitespace(input);
            if !cleaned.len().is_multiple_of(2) {
                return Err(invalid("hex input must contain an even number of digits"));
            }
            let mut bytes = Vec::with_capacity(cleaned.len() / 2);
            for index in (0..cleaned.len()).step_by(2) {
                let text = std::str::from_utf8(&cleaned[index..index + 2])
                    .map_err(|_| invalid("hex input contains non-ASCII bytes"))?;
                let byte = u8::from_str_radix(text, 16)
                    .map_err(|_| invalid(format!("invalid hex pair '{text}'")))?;
                bytes.push(byte);
            }
            detected_output(bytes, None)
        }
        Transform::UrlEncode => TransformOutput {
            bytes: url_encode(input).into_bytes(),
            format: OutputFormat::Text,
            note: None,
        },
        Transform::UrlDecode => detected_output(url_decode(input)?, None),
        Transform::HtmlEntityEncode => {
            let text = text_input(input, operation)?;
            let mut output = String::with_capacity(text.len());
            for ch in text.chars() {
                match ch {
                    '&' => output.push_str("&amp;"),
                    '<' => output.push_str("&lt;"),
                    '>' => output.push_str("&gt;"),
                    '"' => output.push_str("&quot;"),
                    '\'' => output.push_str("&#39;"),
                    _ => output.push(ch),
                }
            }
            TransformOutput {
                bytes: output.into_bytes(),
                format: OutputFormat::Text,
                note: None,
            }
        }
        Transform::HtmlEntityDecode => {
            let text = text_input(input, operation)?;
            detected_output(html_decode(text)?.into_bytes(), None)
        }
        Transform::UnicodeEscapeEncode => {
            let text = text_input(input, operation)?;
            TransformOutput {
                bytes: unicode_encode(text).into_bytes(),
                format: OutputFormat::Text,
                note: None,
            }
        }
        Transform::UnicodeEscapeDecode => {
            let text = text_input(input, operation)?;
            detected_output(unicode_decode(text)?.into_bytes(), None)
        }
        Transform::JwtInspect => jwt_inspect(input)?,
        Transform::JsonPretty => {
            let value = parse_json(input)?;
            let bytes = serde_json::to_vec_pretty(&value)
                .map_err(|error| invalid(format!("JSON formatting failed: {error}")))?;
            TransformOutput {
                bytes,
                format: OutputFormat::Json,
                note: Some("Formatted JSON. No network request was made.".into()),
            }
        }
        Transform::JsonMinify => {
            let value = parse_json(input)?;
            let bytes = serde_json::to_vec(&value)
                .map_err(|error| invalid(format!("JSON minification failed: {error}")))?;
            TransformOutput {
                bytes,
                format: OutputFormat::Json,
                note: None,
            }
        }
        Transform::JsonValidate => {
            let _ = parse_json(input)?;
            TransformOutput {
                bytes: input.to_vec(),
                format: OutputFormat::Json,
                note: Some(
                    "Valid JSON syntax. This is not a schema or security validation.".into(),
                ),
            }
        }
        Transform::GzipCompress => TransformOutput {
            bytes: gzip_compress(input, limits.max_output_bytes)?,
            format: OutputFormat::Binary,
            note: Some(
                "Gzip-compressed bytes. Displayed as hexadecimal when not valid UTF-8.".into(),
            ),
        },
        Transform::GzipDecompress => {
            let bytes = gzip_decompress(input, limits.max_output_bytes)?;
            TransformOutput {
                format: detect_format(&bytes),
                bytes,
                note: Some("Bounded gzip decompression.".into()),
            }
        }
        Transform::Sha256 => hash_output::<Sha256>(input, "SHA-256"),
        Transform::Sha384 => hash_output::<Sha384>(input, "SHA-384"),
        Transform::Sha512 => hash_output::<Sha512>(input, "SHA-512"),
        Transform::Md5Legacy => hash_output::<Md5>(
            input,
            "MD5 (legacy checksum; cryptographically broken and unsuitable for security verification)",
        ),
    };

    if output.bytes.len() > limits.max_output_bytes {
        return Err(TransformError::OutputTooLarge {
            limit: limits.max_output_bytes,
        });
    }
    Ok(output)
}

fn invalid(message: impl Into<String>) -> TransformError {
    TransformError::InvalidInput(message.into())
}

fn without_ascii_whitespace(input: &[u8]) -> Vec<u8> {
    input
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect()
}

fn text_input(input: &[u8], operation: Transform) -> Result<&str, TransformError> {
    std::str::from_utf8(input).map_err(|_| {
        invalid(format!(
            "{} requires valid UTF-8 text; use Hex or Base64 for binary data",
            operation.label()
        ))
    })
}

fn detected_output(bytes: Vec<u8>, note: Option<String>) -> TransformOutput {
    TransformOutput {
        bytes: bytes.clone(),
        format: detect_format(&bytes),
        note,
    }
}

pub fn detect_format(bytes: &[u8]) -> OutputFormat {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return OutputFormat::Binary;
    };
    if serde_json::from_slice::<Value>(bytes).is_ok() {
        return OutputFormat::Json;
    }
    if text
        .chars()
        .all(|ch| !ch.is_control() || matches!(ch, '\n' | '\r' | '\t'))
    {
        OutputFormat::Text
    } else {
        OutputFormat::Binary
    }
}

fn url_encode(input: &[u8]) -> String {
    let mut output = String::with_capacity(input.len());
    for &byte in input {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            output.push(byte as char);
        } else {
            use std::fmt::Write as _;
            let _ = write!(output, "%{byte:02X}");
        }
    }
    output
}

fn url_decode(input: &[u8]) -> Result<Vec<u8>, TransformError> {
    let mut output = Vec::with_capacity(input.len());
    let mut index = 0;
    while index < input.len() {
        if input[index] == b'%' {
            if index + 2 >= input.len() {
                return Err(invalid("URL decode found a truncated percent escape"));
            }
            let pair = std::str::from_utf8(&input[index + 1..index + 3])
                .map_err(|_| invalid("URL percent escape is not ASCII"))?;
            let byte = u8::from_str_radix(pair, 16)
                .map_err(|_| invalid(format!("invalid URL percent escape '%{pair}'")))?;
            output.push(byte);
            index += 3;
        } else {
            output.push(input[index]);
            index += 1;
        }
    }
    Ok(output)
}

fn html_decode(text: &str) -> Result<String, TransformError> {
    let mut output = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(index) = rest.find('&') {
        output.push_str(&rest[..index]);
        let after = &rest[index + 1..];
        let Some(end) = after.find(';') else {
            output.push('&');
            rest = after;
            continue;
        };
        if end > 32 {
            output.push('&');
            rest = after;
            continue;
        }
        let entity = &after[..end];
        match entity {
            "amp" => output.push('&'),
            "lt" => output.push('<'),
            "gt" => output.push('>'),
            "quot" => output.push('"'),
            "apos" => output.push('\''),
            _ if entity.starts_with("#x") || entity.starts_with("#X") => {
                let value = u32::from_str_radix(&entity[2..], 16)
                    .map_err(|_| invalid(format!("invalid numeric HTML entity '&{entity};'")))?;
                output.push(char::from_u32(value).ok_or_else(|| {
                    invalid(format!("HTML entity '&{entity};' is not a Unicode scalar"))
                })?);
            }
            _ if entity.starts_with('#') => {
                let value = entity[1..]
                    .parse::<u32>()
                    .map_err(|_| invalid(format!("invalid numeric HTML entity '&{entity};'")))?;
                output.push(char::from_u32(value).ok_or_else(|| {
                    invalid(format!("HTML entity '&{entity};' is not a Unicode scalar"))
                })?);
            }
            _ => return Err(invalid(format!("unknown HTML entity '&{entity};'"))),
        }
        rest = &after[end + 1..];
    }
    output.push_str(rest);
    Ok(output)
}

fn unicode_encode(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            ' '..='~' => output.push(ch),
            ch if (ch as u32) <= 0xffff => {
                use std::fmt::Write as _;
                let _ = write!(output, "\\u{:04X}", ch as u32);
            }
            ch => {
                let value = ch as u32 - 0x1_0000;
                let high = 0xd800 + (value >> 10);
                let low = 0xdc00 + (value & 0x3ff);
                use std::fmt::Write as _;
                let _ = write!(output, "\\u{high:04X}\\u{low:04X}");
            }
        }
    }
    output
}

fn unicode_decode(text: &str) -> Result<String, TransformError> {
    let mut output = String::with_capacity(text.len());
    let chars: Vec<char> = text.chars().collect();
    let mut index = 0;
    while index < chars.len() {
        if chars[index] != '\\' {
            output.push(chars[index]);
            index += 1;
            continue;
        }
        index += 1;
        let Some(&escape) = chars.get(index) else {
            return Err(invalid("Unicode input ends with a lone backslash"));
        };
        index += 1;
        match escape {
            '\\' => output.push('\\'),
            'n' => output.push('\n'),
            'r' => output.push('\r'),
            't' => output.push('\t'),
            '0' => output.push('\0'),
            '"' => output.push('"'),
            '\'' => output.push('\''),
            'u' => {
                let first = parse_hex4(&chars, index)?;
                index += 4;
                let scalar = if (0xd800..=0xdbff).contains(&first) {
                    if chars.get(index) != Some(&'\\') || chars.get(index + 1) != Some(&'u') {
                        return Err(invalid("high surrogate is not followed by a low surrogate"));
                    }
                    index += 2;
                    let second = parse_hex4(&chars, index)?;
                    index += 4;
                    if !(0xdc00..=0xdfff).contains(&second) {
                        return Err(invalid("invalid low surrogate in Unicode escape"));
                    }
                    0x10000 + ((first - 0xd800) << 10) + (second - 0xdc00)
                } else if (0xdc00..=0xdfff).contains(&first) {
                    return Err(invalid("lone low surrogate in Unicode escape"));
                } else {
                    first
                };
                output.push(
                    char::from_u32(scalar)
                        .ok_or_else(|| invalid("Unicode escape is not a valid scalar"))?,
                );
            }
            other => return Err(invalid(format!("unknown Unicode escape '\\{other}'"))),
        }
    }
    Ok(output)
}

fn parse_hex4(chars: &[char], start: usize) -> Result<u32, TransformError> {
    let slice: String = chars
        .get(start..start + 4)
        .ok_or_else(|| invalid("Unicode escape is truncated; expected four hexadecimal digits"))?
        .iter()
        .collect();
    u32::from_str_radix(&slice, 16)
        .map_err(|_| invalid(format!("invalid Unicode escape '\\u{slice}'")))
}

fn parse_json(input: &[u8]) -> Result<Value, TransformError> {
    serde_json::from_slice(input).map_err(|error| {
        invalid(format!(
            "JSON parse error at line {}, column {}: {}",
            error.line(),
            error.column(),
            error
        ))
    })
}

fn gzip_compress(input: &[u8], limit: usize) -> Result<Vec<u8>, TransformError> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(input)
        .map_err(|error| invalid(format!("gzip compression failed: {error}")))?;
    let bytes = encoder
        .finish()
        .map_err(|error| invalid(format!("gzip compression failed: {error}")))?;
    if bytes.len() > limit {
        return Err(TransformError::OutputTooLarge { limit });
    }
    Ok(bytes)
}

fn gzip_decompress(input: &[u8], limit: usize) -> Result<Vec<u8>, TransformError> {
    let mut decoder = GzDecoder::new(input);
    let mut output = Vec::new();
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let read = decoder
            .read(&mut buffer)
            .map_err(|error| invalid(format!("invalid or truncated gzip stream: {error}")))?;
        if read == 0 {
            break;
        }
        if output.len().saturating_add(read) > limit {
            return Err(TransformError::OutputTooLarge { limit });
        }
        output.extend_from_slice(&buffer[..read]);
    }
    Ok(output)
}

fn hash_output<D: Digest>(input: &[u8], label: &str) -> TransformOutput {
    let digest = D::digest(input);
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    TransformOutput {
        bytes: hex.into_bytes(),
        format: OutputFormat::Text,
        note: Some(format!("{label} digest (lowercase hexadecimal).")),
    }
}

fn jwt_inspect(input: &[u8]) -> Result<TransformOutput, TransformError> {
    let token = text_input(input, Transform::JwtInspect)?.trim();
    let sections: Vec<&str> = token.split('.').collect();
    if sections.len() != 3 {
        return Err(invalid(format!(
            "JWT must contain three dot-separated sections; found {}",
            sections.len()
        )));
    }
    if sections[0].is_empty() || sections[1].is_empty() {
        return Err(invalid("JWT header and payload sections must not be empty"));
    }
    let header_bytes = decode_jwt_section(sections[0], "header")?;
    let payload_bytes = decode_jwt_section(sections[1], "payload")?;
    let header = parse_json(&header_bytes)
        .map_err(|error| invalid(format!("JWT header is not valid JSON: {error}")))?;
    let payload = parse_json(&payload_bytes)
        .map_err(|error| invalid(format!("JWT payload is not valid JSON: {error}")))?;
    let header_object = header
        .as_object()
        .ok_or_else(|| invalid("JWT header must be a JSON object"))?;
    let payload_object = payload
        .as_object()
        .ok_or_else(|| invalid("JWT payload must be a JSON object"))?;

    let algorithm = header_object
        .get("alg")
        .and_then(Value::as_str)
        .unwrap_or("<missing>");
    let expiration = match payload_object.get("exp") {
        None => "not present".to_string(),
        Some(value) => {
            let seconds = value
                .as_i64()
                .ok_or_else(|| invalid("JWT exp claim must be an integer Unix timestamp"))?;
            match Utc.timestamp_opt(seconds, 0).single() {
                Some(time) => {
                    let status = if time < Utc::now() {
                        "EXPIRED"
                    } else {
                        "not expired"
                    };
                    format!("{} UTC ({status})", time.format("%Y-%m-%d %H:%M:%S"))
                }
                None => format!("{seconds} (outside the supported timestamp range)"),
            }
        }
    };
    let signature = if sections[2].is_empty() {
        "absent (unsigned token); not checked".to_string()
    } else {
        format!("present ({} encoded bytes); not checked", sections[2].len())
    };

    let header_pretty = serde_json::to_string_pretty(&header)
        .map_err(|error| invalid(format!("JWT header formatting failed: {error}")))?;
    let payload_pretty = serde_json::to_string_pretty(&payload)
        .map_err(|error| invalid(format!("JWT payload formatting failed: {error}")))?;
    let report = format!(
        "JWT DECODED — SIGNATURE NOT VERIFIED\n\
         Decoding is not verification. This token has not been validated.\n\n\
         Algorithm: {algorithm}\n\
         Expiration: {expiration}\n\
         Signature: {signature}\n\n\
         Header:\n{header_pretty}\n\n\
         Payload:\n{payload_pretty}\n"
    );
    Ok(TransformOutput {
        bytes: report.into_bytes(),
        format: OutputFormat::Jwt,
        note: Some(
            "Decoded only; the signature, issuer, audience, and token validity were not verified."
                .into(),
        ),
    })
}

fn decode_jwt_section(section: &str, name: &str) -> Result<Vec<u8>, TransformError> {
    URL_SAFE_NO_PAD
        .decode(section)
        .or_else(|_| URL_SAFE.decode(section))
        .map_err(|error| invalid(format!("JWT {name} is not valid Base64 URL-safe: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> TransformLimits {
        TransformLimits::default()
    }

    fn text(bytes: &[u8]) -> String {
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    fn run(input: &[u8], operation: Transform) -> TransformOutput {
        transform(input, operation, limits()).unwrap()
    }

    #[test]
    fn base64_standard_and_url_safe_round_trip_binary() {
        let input = vec![0x00, 0xff, 0x80, b'o', b'k', b'?', b'>'];
        let encoded = run(&input, Transform::Base64Encode);
        assert_eq!(encoded.format, OutputFormat::Text);
        let decoded = run(&encoded.bytes, Transform::Base64Decode);
        assert_eq!(decoded.bytes, input);

        let url = run(&input, Transform::Base64UrlEncode);
        assert!(!text(&url.bytes).contains(['+', '/', '=']));
        let decoded = run(&url.bytes, Transform::Base64UrlDecode);
        assert_eq!(decoded.bytes, input);

        assert!(matches!(
            transform(b"%%%", Transform::Base64Decode, limits()),
            Err(TransformError::InvalidInput(_))
        ));
    }

    #[test]
    fn hex_round_trips_and_rejects_malformed_input() {
        let input = vec![0x00, 0x0f, 0xff, 0x80];
        let encoded = run(&input, Transform::HexEncode);
        assert_eq!(text(&encoded.bytes), "000fff80");
        assert_eq!(run(&encoded.bytes, Transform::HexDecode).bytes, input);
        assert!(transform(b"abc", Transform::HexDecode, limits()).is_err());
        assert!(transform(b"zz", Transform::HexDecode, limits()).is_err());
    }

    #[test]
    fn url_encoding_is_binary_safe_and_strict_on_decode() {
        let encoded = run(b"a b&c/\xff", Transform::UrlEncode);
        assert_eq!(text(&encoded.bytes), "a%20b%26c%2F%FF");
        assert_eq!(
            run(&encoded.bytes, Transform::UrlDecode).bytes,
            b"a b&c/\xff"
        );
        assert!(transform(b"%2", Transform::UrlDecode, limits()).is_err());
        assert!(transform(b"%zz", Transform::UrlDecode, limits()).is_err());
    }

    #[test]
    fn html_entities_round_trip_named_and_numeric_forms() {
        let encoded = run(b"<a href=\"x\">&'", Transform::HtmlEntityEncode);
        assert_eq!(
            text(&encoded.bytes),
            "&lt;a href=&quot;x&quot;&gt;&amp;&#39;"
        );
        assert_eq!(
            run(&encoded.bytes, Transform::HtmlEntityDecode).bytes,
            b"<a href=\"x\">&'"
        );
        assert_eq!(
            run(b"&#x1F600; &#65;", Transform::HtmlEntityDecode).bytes,
            "😀 A".as_bytes()
        );
        assert!(transform(b"&bogus;", Transform::HtmlEntityDecode, limits()).is_err());
    }

    #[test]
    fn unicode_escapes_round_trip_ascii_controls_and_surrogates() {
        let original = "a\\b\n\tλ😀";
        let encoded = run(original.as_bytes(), Transform::UnicodeEscapeEncode);
        assert_eq!(text(&encoded.bytes), "a\\\\b\\n\\t\\u03BB\\uD83D\\uDE00");
        assert_eq!(
            run(&encoded.bytes, Transform::UnicodeEscapeDecode).bytes,
            original.as_bytes()
        );
        assert!(transform(b"\\u12", Transform::UnicodeEscapeDecode, limits()).is_err());
        assert!(transform(b"\\x41", Transform::UnicodeEscapeDecode, limits()).is_err());
    }

    #[test]
    fn json_formats_validates_and_reports_parse_errors() {
        let nested = br#"{"a":{"b":[1,2,{"c":true}]},"n":null}"#;
        let pretty = run(nested, Transform::JsonPretty);
        assert_eq!(pretty.format, OutputFormat::Json);
        assert!(text(&pretty.bytes).contains("\n"));
        let minified = run(&pretty.bytes, Transform::JsonMinify);
        assert_eq!(minified.bytes, nested);
        let validated = run(nested, Transform::JsonValidate);
        assert_eq!(validated.bytes, nested);
        assert!(validated.note.unwrap().contains("not a schema"));

        let error = transform(b"{\"a\":", Transform::JsonPretty, limits()).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("line 1") && message.contains("column"));
    }

    #[test]
    fn jwt_inspection_reports_claims_without_claiming_verification() {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(br#"{"sub":"alice","exp":4102444800}"#);
        let token = format!("{header}.{payload}.signature");
        let output = run(token.as_bytes(), Transform::JwtInspect);
        let report = text(&output.bytes);
        assert_eq!(output.format, OutputFormat::Jwt);
        assert!(report.contains("SIGNATURE NOT VERIFIED"));
        assert!(report.contains("Algorithm: HS256"));
        assert!(report.contains("2100-01-01 00:00:00 UTC"));
        assert!(report.contains("not expired"));
        assert!(output.note.unwrap().contains("not verified"));
    }

    #[test]
    fn jwt_malformed_missing_and_expired_tokens_are_handled() {
        assert!(transform(b"only.two", Transform::JwtInspect, limits()).is_err());
        assert!(transform(b"", Transform::JwtInspect, limits()).is_err());
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
        let payload = URL_SAFE_NO_PAD.encode(br#"{"exp":1,"sub":"old"}"#);
        let token = format!("{header}.{payload}.");
        let report = text(&run(token.as_bytes(), Transform::JwtInspect).bytes);
        assert!(report.contains("EXPIRED"));
        assert!(report.contains("absent (unsigned token)"));
        assert!(report.contains("Algorithm: none"));

        let bad_header = URL_SAFE_NO_PAD.encode(b"not json");
        let token = format!("{bad_header}.{payload}.sig");
        assert!(transform(token.as_bytes(), Transform::JwtInspect, limits()).is_err());
    }

    #[test]
    fn gzip_round_trip_and_invalid_or_truncated_streams() {
        let original = b"compress me please".repeat(100);
        let compressed = run(&original, Transform::GzipCompress);
        assert_eq!(compressed.format, OutputFormat::Binary);
        let decompressed = run(&compressed.bytes, Transform::GzipDecompress);
        assert_eq!(decompressed.bytes, original);

        assert!(transform(b"not gzip", Transform::GzipDecompress, limits()).is_err());
        let truncated = &compressed.bytes[..compressed.bytes.len() / 2];
        assert!(transform(truncated, Transform::GzipDecompress, limits()).is_err());
    }

    #[test]
    fn gzip_output_limit_stops_decompression_bombs() {
        let bomb = vec![b'a'; 4096];
        let compressed = run(&bomb, Transform::GzipCompress);
        let limited = TransformLimits::new(1024 * 1024, 128);
        assert!(matches!(
            transform(&compressed.bytes, Transform::GzipDecompress, limited),
            Err(TransformError::OutputTooLarge { .. })
        ));
    }

    #[test]
    fn hashes_match_known_vectors_and_md5_is_labelled_legacy() {
        assert_eq!(
            text(&run(b"abc", Transform::Sha256).bytes),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            text(&run(b"abc", Transform::Sha384).bytes),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
        );
        assert_eq!(
            text(&run(b"abc", Transform::Sha512).bytes),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
        let md5 = run(b"abc", Transform::Md5Legacy);
        assert_eq!(text(&md5.bytes), "900150983cd24fb0d6963f7d28e17f72");
        assert!(md5.note.unwrap().contains("cryptographically broken"));
    }

    #[test]
    fn pipeline_runs_in_order_and_exposes_intermediate_results() {
        let json = br#"{"hello":"world"}"#;
        let encoded = STANDARD.encode(json);
        let piped = url_encode(encoded.as_bytes());
        let steps = [
            Transform::UrlDecode,
            Transform::Base64Decode,
            Transform::JsonPretty,
        ];
        let run = execute_pipeline(piped.as_bytes(), &steps, limits());
        assert!(run.succeeded(), "{:?}", run.error);
        assert_eq!(run.steps.len(), 3);
        assert_eq!(run.steps[0].output, encoded.as_bytes());
        assert_eq!(run.steps[1].output, json);
        assert_eq!(run.steps[2].format, OutputFormat::Json);
        assert_eq!(
            run.total_output_bytes(),
            run.output.as_ref().unwrap().bytes.len()
        );

        let reversed = [Transform::JsonPretty, Transform::Base64Decode];
        let run = execute_pipeline(encoded.as_bytes(), &reversed, limits());
        assert!(!run.succeeded());
        assert_eq!(run.error.as_ref().unwrap().step_index, 0);
    }

    #[test]
    fn pipeline_stops_at_the_failing_step_without_substitution() {
        let steps = [Transform::Base64Decode, Transform::HexDecode];
        let run = execute_pipeline(b"AAAA", &steps, limits());
        assert_eq!(run.steps.len(), 1);
        assert!(run.output.is_none());
        let failure = run.error.unwrap();
        assert_eq!(failure.step_index, 1);
        assert_eq!(failure.transform, Some(Transform::HexDecode));
        assert!(failure.label().contains("Step 2"));
    }

    #[test]
    fn pipeline_handles_empty_binary_and_limits() {
        let empty = execute_pipeline(b"", &[Transform::Base64Decode], limits());
        assert!(empty.succeeded());
        assert_eq!(empty.output.unwrap().bytes, b"");

        let binary = execute_pipeline(
            b"00ff80",
            &[Transform::HexDecode, Transform::Base64Encode],
            limits(),
        );
        assert!(binary.succeeded());
        let decoded = execute_pipeline(
            binary.output.unwrap().bytes.as_slice(),
            &[Transform::Base64Decode],
            limits(),
        );
        assert_eq!(decoded.output.unwrap().bytes, vec![0x00, 0xff, 0x80]);

        let tiny = TransformLimits::new(2, 1024);
        let run = execute_pipeline(b"abc", &[Transform::Sha256], tiny);
        assert!(run.output.is_none());
        assert!(run.error.unwrap().message.contains("limit"));

        let too_many = vec![Transform::Base64Encode; DECODER_MAX_PIPELINE_STEPS + 1];
        let run = execute_pipeline(b"x", &too_many, limits());
        assert!(run.error.unwrap().message.contains("limited"));
    }

    #[test]
    fn non_utf8_text_transformations_fail_cleanly() {
        assert!(transform(b"\xff", Transform::HtmlEntityEncode, limits()).is_err());
        assert!(transform(b"\xff", Transform::UnicodeEscapeEncode, limits()).is_err());
        assert!(transform(b"\xff", Transform::JsonPretty, limits()).is_err());
    }
}
