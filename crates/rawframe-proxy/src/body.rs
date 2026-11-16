//! Streaming body guards with bounded capture.
//!
//! Bodies are never fully buffered before forwarding. Data frames are forwarded
//! immediately while a bounded copy is retained for the inspector. Exceeding a
//! limit or stalling for longer than the idle timeout turns into a body error.

use std::pin::Pin;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use hyper::body::{Body, Frame, SizeHint};
use tokio::time::{Instant, Sleep};

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type ProxyBody = BoxBody<Bytes, BoxError>;

const FAILURE_NONE: u8 = 0;
const FAILURE_LIMIT: u8 = 1;
const FAILURE_IDLE: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyEnd {
    Complete,
    LimitExceeded,
    IdleTimeout,
    Aborted,
}

#[derive(Debug, Clone, Default)]
pub struct BodyCapture {
    bytes: Arc<Mutex<Vec<u8>>>,
    failure: Arc<AtomicU8>,
}

impl BodyCapture {
    pub fn bytes(&self) -> Vec<u8> {
        self.bytes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub fn exceeded(&self) -> bool {
        self.failure.load(Ordering::Relaxed) == FAILURE_LIMIT
    }

    pub fn timed_out(&self) -> bool {
        self.failure.load(Ordering::Relaxed) == FAILURE_IDLE
    }

    fn append(&self, data: &[u8], remaining: usize) {
        let take = data.len().min(remaining);
        if take == 0 {
            return;
        }
        self.bytes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .extend_from_slice(&data[..take]);
    }

    fn set_failure(&self, value: u8) {
        let _ = self.failure.compare_exchange(
            FAILURE_NONE,
            value,
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
    }
}

#[derive(Debug, thiserror::Error)]
enum GuardError {
    #[error("body exceeded the configured limit of {0} bytes")]
    Limit(usize),
    #[error("body stalled for longer than the configured idle timeout")]
    IdleTimeout,
}

impl GuardError {
    fn boxed(self) -> BoxError {
        Box::new(self)
    }
}

/// An HTTP body wrapper that forwards frames, enforces a byte limit, applies an
/// idle timeout, and keeps a bounded capture copy.
pub struct GuardedBody<B> {
    inner: B,
    limit: usize,
    seen: usize,
    capture: BodyCapture,
    idle: Duration,
    expected_len: Option<usize>,
    sleep: Pin<Box<Sleep>>,
    on_end: Option<Box<dyn FnOnce(BodyEnd) + Send + Sync>>,
    finished: bool,
}

impl<B> GuardedBody<B> {
    pub fn new(
        inner: B,
        limit: usize,
        capture: BodyCapture,
        idle: Duration,
        expected_len: Option<usize>,
        on_end: Option<Box<dyn FnOnce(BodyEnd) + Send + Sync>>,
    ) -> Self {
        Self {
            inner,
            limit,
            seen: 0,
            capture,
            idle,
            expected_len,
            sleep: Box::pin(tokio::time::sleep(idle)),
            on_end,
            finished: false,
        }
    }

    fn finish(&mut self, end: BodyEnd) {
        if self.finished {
            return;
        }
        self.finished = true;
        if let Some(callback) = self.on_end.take() {
            callback(end);
        }
    }

    fn reset_idle(&mut self) {
        self.sleep.as_mut().reset(Instant::now() + self.idle);
    }
}

impl<B> Body for GuardedBody<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<BoxError>,
{
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.sleep.as_mut().poll(cx).is_ready() {
            self.capture.set_failure(FAILURE_IDLE);
            self.finish(BodyEnd::IdleTimeout);
            return Poll::Ready(Some(Err(GuardError::IdleTimeout.boxed())));
        }

        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                self.reset_idle();
                match frame.into_data() {
                    Ok(data) => {
                        if self.seen.saturating_add(data.len()) > self.limit {
                            self.capture.set_failure(FAILURE_LIMIT);
                            self.finish(BodyEnd::LimitExceeded);
                            return Poll::Ready(Some(Err(GuardError::Limit(self.limit).boxed())));
                        }
                        self.seen += data.len();
                        self.capture
                            .append(&data, self.limit - self.seen + data.len());
                        if self.inner.is_end_stream() || self.expected_len == Some(self.seen) {
                            self.finish(BodyEnd::Complete);
                        }
                        Poll::Ready(Some(Ok(Frame::data(data))))
                    }
                    Err(frame) => Poll::Ready(Some(Ok(frame))),
                }
            }
            Poll::Ready(Some(Err(error))) => {
                self.finish(BodyEnd::Aborted);
                Poll::Ready(Some(Err(error.into())))
            }
            Poll::Ready(None) => {
                self.finish(BodyEnd::Complete);
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl<B> Drop for GuardedBody<B> {
    fn drop(&mut self) {
        if self.expected_len == Some(self.seen) {
            self.finish(BodyEnd::Complete);
        } else {
            self.finish(BodyEnd::Aborted);
        }
    }
}
