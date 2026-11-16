//! End-to-end TUI boundary test: keyboard starts the real proxy, live captures
//! flow through the existing event bus, and the Proxy screen renders them.

use std::net::SocketAddr;
use std::time::Duration;

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use rawframe_core::ProxyState;
use rawframe_core::models::{AppConfig, Scope, ScopeRule};
use rawframe_tui::App;
use rawframe_tui::testing;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    listener.local_addr().unwrap().port()
}

async fn spawn_upstream() -> SocketAddr {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buffer = [0_u8; 4096];
                let _ = socket.read(&mut buffer).await;
                socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await
                    .unwrap();
                let _ = socket.shutdown().await;
            });
        }
    });
    addr
}

async fn pump_events(app: &mut App) {
    app.drain_events();
}

#[tokio::test]
async fn keyboard_starts_proxy_and_live_capture_reaches_proxy_screen() {
    let upstream = spawn_upstream().await;
    let proxy_port = free_port();
    let mut config = AppConfig::default();
    config.proxy.bind_address = "127.0.0.1".parse().unwrap();
    config.proxy.port = proxy_port;
    config.proxy.allow_private_upstreams = true;
    config.proxy.scope = Scope::allow(ScopeRule::host("127.0.0.1"));
    config.proxy.connect_timeout_secs = 1;
    config.proxy.upstream_timeout_secs = 2;
    config.proxy.idle_timeout_secs = 2;

    let mut app = App::new(config);
    let events = app.event_sender();
    let (command_tx, command_rx) = tokio::sync::mpsc::channel(8);
    app.attach_proxy_commands(command_tx);
    let service = tokio::spawn(rawframe_proxy::run_service(command_rx, events));

    app.handle_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::NONE));

    timeout(Duration::from_secs(4), async {
        while app.proxy_state() != ProxyState::Listening {
            pump_events(&mut app).await;
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("proxy did not reach Listening through the TUI command boundary");

    let request = format!(
        "GET http://{upstream}/live HTTP/1.1\r\nHost: {upstream}\r\nConnection: close\r\n\r\n"
    );
    let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    client.write_all(request.as_bytes()).await.unwrap();
    client.shutdown().await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    assert!(
        String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&response)
    );

    timeout(Duration::from_secs(3), async {
        loop {
            pump_events(&mut app).await;
            if app
                .traffic()
                .iter()
                .any(|entry| entry.is_live_capture() && entry.state.is_terminal())
            {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("live capture did not reach the application event bus");

    assert!(app.live_capture_count() >= 1);
    let buffer = testing::render_frame(&mut app, 140, 40);
    let text = testing::text(&buffer);
    assert!(
        text.contains("LISTENING") || text.contains("Listening"),
        "{text}"
    );
    assert!(
        text.contains("TRAFFIC") || text.contains("Traffic"),
        "{text}"
    );
    assert!(
        text.contains("127.0.0.1") || text.contains("/live") || text.contains("1000"),
        "{text}"
    );
    assert!(
        app.traffic()
            .iter()
            .any(|entry| entry.is_live_capture() && entry.request.target == "/live")
    );

    app.handle_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::NONE));
    timeout(Duration::from_secs(4), async {
        while app.proxy_state() != ProxyState::Stopped {
            pump_events(&mut app).await;
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("proxy did not stop through the TUI command boundary");

    drop(app);
    timeout(Duration::from_secs(3), service)
        .await
        .expect("proxy worker did not exit when the UI channel closed")
        .unwrap();
}
