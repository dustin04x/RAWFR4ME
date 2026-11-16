//! Opaque bidirectional CONNECT relay.
//!
//! Bytes are forwarded without parsing. Half-close is preserved: EOF in one
//! direction shuts down the corresponding write half while the other direction
//! may continue.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use rawframe_core::models::traffic::TunnelOutcome;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::watch;
use tokio::time::{Instant, MissedTickBehavior, interval};

const RELAY_BUFFER: usize = 16 * 1024;
const IDLE_TICK: Duration = Duration::from_millis(250);

#[derive(Debug, Clone)]
pub struct RelayOutcome {
    pub client_to_upstream_bytes: u64,
    pub upstream_to_client_bytes: u64,
    pub outcome: TunnelOutcome,
    pub detail: String,
}

pub async fn relay<C, U>(
    client: C,
    upstream: U,
    idle_timeout: Duration,
    mut shutdown: watch::Receiver<bool>,
) -> RelayOutcome
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let (client_read, client_write) = tokio::io::split(client);
    let (upstream_read, upstream_write) = tokio::io::split(upstream);

    let client_to_upstream = Arc::new(AtomicU64::new(0));
    let upstream_to_client = Arc::new(AtomicU64::new(0));

    let mut upload = Box::pin(pump(
        client_read,
        upstream_write,
        client_to_upstream.clone(),
    ));
    let mut download = Box::pin(pump(
        upstream_read,
        client_write,
        upstream_to_client.clone(),
    ));

    let mut upload_done = false;
    let mut download_done = false;
    let mut result = None;
    let mut outcome = TunnelOutcome::Closed;
    let mut detail = "Both directions closed".to_string();
    let mut last_activity = Instant::now();
    let mut last_total = 0_u64;
    let mut ticker = interval(IDLE_TICK);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    while !(upload_done && download_done) {
        tokio::select! {
            value = &mut upload, if !upload_done => {
                upload_done = true;
                if let Err(error) = value {
                    result = Some(error);
                    break;
                }
            }
            value = &mut download, if !download_done => {
                download_done = true;
                if let Err(error) = value {
                    result = Some(error);
                    break;
                }
            }
            _ = ticker.tick() => {
                let total = client_to_upstream.load(Ordering::Relaxed)
                    + upstream_to_client.load(Ordering::Relaxed);
                if total != last_total {
                    last_total = total;
                    last_activity = Instant::now();
                } else if last_activity.elapsed() >= idle_timeout {
                    outcome = TunnelOutcome::TimedOut;
                    detail = format!("Idle for more than {} seconds", idle_timeout.as_secs());
                    break;
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    detail = "Closed by proxy shutdown".to_string();
                    break;
                }
            }
        }
    }

    if let Some(error) = result {
        outcome = TunnelOutcome::Failed;
        detail = format!("Tunnel I/O error: {error}");
    }

    RelayOutcome {
        client_to_upstream_bytes: client_to_upstream.load(Ordering::Relaxed),
        upstream_to_client_bytes: upstream_to_client.load(Ordering::Relaxed),
        outcome,
        detail,
    }
}

async fn pump<R, W>(mut reader: R, mut writer: W, counter: Arc<AtomicU64>) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0_u8; RELAY_BUFFER];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            writer.shutdown().await?;
            return Ok(());
        }
        writer.write_all(&buffer[..read]).await?;
        counter.fetch_add(read as u64, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn relay_copies_both_directions_and_preserves_half_close() {
        let (client_proxy, client_peer) = duplex(64);
        let (upstream_proxy, upstream_peer) = duplex(64);
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);

        let task = tokio::spawn(relay(
            client_proxy,
            upstream_proxy,
            Duration::from_secs(5),
            shutdown_rx,
        ));

        let (mut client_read, mut client_write) = tokio::io::split(client_peer);
        let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream_peer);

        client_write.write_all(b"ping").await.unwrap();
        client_write.shutdown().await.unwrap();
        let mut buf = [0_u8; 4];
        upstream_read.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");

        upstream_write.write_all(b"pong").await.unwrap();
        upstream_write.shutdown().await.unwrap();
        let mut buf = [0_u8; 4];
        client_read.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");

        let outcome = task.await.unwrap();
        assert_eq!(outcome.outcome, TunnelOutcome::Closed);
        assert_eq!(outcome.client_to_upstream_bytes, 4);
        assert_eq!(outcome.upstream_to_client_bytes, 4);
    }

    #[tokio::test]
    async fn idle_tunnels_are_terminated() {
        let (client_proxy, _client_peer) = duplex(64);
        let (upstream_proxy, _upstream_peer) = duplex(64);
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);

        let outcome = relay(
            client_proxy,
            upstream_proxy,
            Duration::from_millis(300),
            shutdown_rx,
        )
        .await;
        assert_eq!(outcome.outcome, TunnelOutcome::TimedOut);
    }
}
