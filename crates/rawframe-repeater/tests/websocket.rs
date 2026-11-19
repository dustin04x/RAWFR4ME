//! WebSocket Repeater end-to-end tests against a local echo server.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use rawframe_core::models::config::{Scope, ScopeRule};
use rawframe_core::models::websocket::{WebSocketDirection, WebSocketOpcode};
use rawframe_core::websocket::{
    WebSocketRepeaterCommand, WebSocketRepeaterEvent, WebSocketRepeaterTarget,
};
use rawframe_core::{AppEvent, EventBus};
use rawframe_repeater::{WebSocketRepeaterConfig, run_websocket_service};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

fn config() -> WebSocketRepeaterConfig {
    WebSocketRepeaterConfig {
        allow_private_upstreams: true,
        connect_timeout: Duration::from_secs(2),
        idle_timeout: Duration::from_secs(5),
        max_frame_bytes: 64 * 1024,
        max_message_bytes: 256 * 1024,
        max_sessions: 2,
        capture_bytes: 1024,
        trust_file: None,
    }
}

async fn echo_server() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let mut socket = tokio_tungstenite::accept_async(stream)
            .await
            .expect("accept ws");
        while let Some(Ok(message)) = socket.next().await {
            if message.is_text() {
                let reply = format!("echo:{}", message.to_text().unwrap());
                socket
                    .send(Message::Text(reply.into()))
                    .await
                    .expect("reply");
            }
        }
    });
    (port, task)
}

#[tokio::test]
async fn authored_session_sends_and_receives_frames() {
    let (port, server) = echo_server().await;
    let mut bus = EventBus::new();
    let mut events = bus.subscribe();
    let (tx, rx) = tokio::sync::mpsc::channel(8);
    let scope = Arc::new(RwLock::new(Scope::allow(ScopeRule::host("127.0.0.1"))));
    let service = tokio::spawn(run_websocket_service(rx, config(), bus.sender(), scope));

    tx.send(WebSocketRepeaterCommand::Open {
        session: 1,
        host: "127.0.0.1".into(),
        port,
        path: "/socket".into(),
        tls: false,
        subprotocol: None,
    })
    .await
    .unwrap();

    let mut opened = false;
    let mut sent = false;
    let mut echoed = false;
    let mut closed = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !closed {
        let event = tokio::time::timeout_at(deadline, events.recv())
            .await
            .expect("event timeout")
            .expect("event");
        match event {
            AppEvent::WebSocketRepeater(WebSocketRepeaterEvent::Opened {
                session,
                connection,
            }) => {
                assert_eq!(session, 1);
                assert_eq!(
                    connection.source,
                    rawframe_core::models::traffic::TrafficSource::Repeater
                );
                assert_eq!(
                    WebSocketRepeaterTarget::from_connection(&connection).path,
                    "/socket"
                );
                opened = true;
                tx.send(WebSocketRepeaterCommand::Send {
                    session: 1,
                    opcode: WebSocketOpcode::Text,
                    payload: b"hello".to_vec(),
                })
                .await
                .unwrap();
            }
            AppEvent::WebSocketFrame(frame) => {
                assert_eq!(
                    frame.connection_id.0,
                    rawframe_core::websocket::session_connection_id(1).0
                );
                match frame.direction {
                    WebSocketDirection::ClientToServer => {
                        assert_eq!(frame.payload, b"hello");
                        sent = true;
                    }
                    WebSocketDirection::ServerToClient => {
                        assert_eq!(frame.payload, b"echo:hello");
                        echoed = true;
                        tx.send(WebSocketRepeaterCommand::Close { session: 1 })
                            .await
                            .unwrap();
                    }
                }
            }
            AppEvent::WebSocketRepeater(WebSocketRepeaterEvent::Closed { session, .. }) => {
                assert_eq!(session, 1);
                closed = true;
            }
            AppEvent::WebSocketRepeater(WebSocketRepeaterEvent::Failed { error, .. }) => {
                panic!("session failed: {error}");
            }
            _ => {}
        }
    }
    assert!(opened && sent && echoed);
    service.abort();
    server.abort();
}

#[tokio::test]
async fn out_of_scope_sessions_never_reach_upstream() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let mut bus = EventBus::new();
    let mut events = bus.subscribe();
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    let scope = Arc::new(RwLock::new(Scope::allow(ScopeRule::host("allowed.test"))));
    let service = tokio::spawn(run_websocket_service(rx, config(), bus.sender(), scope));

    tx.send(WebSocketRepeaterCommand::Open {
        session: 7,
        host: "127.0.0.1".into(),
        port,
        path: "/".into(),
        tls: false,
        subprotocol: None,
    })
    .await
    .unwrap();

    match tokio::time::timeout(Duration::from_secs(2), events.recv())
        .await
        .expect("event")
        .expect("event")
    {
        AppEvent::WebSocketRepeater(WebSocketRepeaterEvent::Failed {
            session, blocked, ..
        }) => {
            assert_eq!(session, 7);
            assert!(blocked, "scope refusal must be reported as a local block");
        }
        other => panic!("unexpected event: {other:?}"),
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(250), listener.accept())
            .await
            .is_err(),
        "an out-of-scope session must not connect"
    );
    service.abort();
}
