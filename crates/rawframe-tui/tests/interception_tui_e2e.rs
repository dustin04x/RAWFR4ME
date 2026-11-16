use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

use rawframe_core::models::ScopeRule;
use rawframe_core::models::traffic::TrafficState;
use rawframe_core::{AppCommand, AppConfig, EventBus, Scope};
use rawframe_tui::App;
use tokio::sync::mpsc;

fn reserve_local_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("reserve local port")
        .local_addr()
        .expect("local addr")
        .port()
}

#[allow(clippy::type_complexity)]
fn start_upstream_echo(
    extra_header_name: &'static str,
) -> (
    String,
    Arc<Mutex<Vec<String>>>,
    Arc<AtomicUsize>,
    thread::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind upstream");
    listener
        .set_nonblocking(true)
        .expect("nonblocking upstream");
    let addr = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
    let seen = Arc::new(Mutex::new(Vec::<String>::new()));
    let hits = Arc::new(AtomicUsize::new(0));
    let seen_t = Arc::clone(&seen);
    let hits_t = Arc::clone(&hits);
    let handle = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(25);
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_nonblocking(false).ok();
                    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 4096];
                    let header_end;
                    loop {
                        match stream.read(&mut tmp) {
                            Ok(0) => {
                                header_end = None;
                                break;
                            }
                            Ok(n) => {
                                buf.extend_from_slice(&tmp[..n]);
                                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                                    header_end = Some(pos + 4);
                                    break;
                                }
                                if buf.len() > 64 * 1024 {
                                    header_end = None;
                                    break;
                                }
                            }
                            Err(_) => {
                                header_end = None;
                                break;
                            }
                        }
                    }
                    let Some(end) = header_end else {
                        continue;
                    };
                    let headers_text = String::from_utf8_lossy(&buf[..end]).to_string();
                    let content_len = headers_text
                        .lines()
                        .find_map(|line| {
                            let (k, v) = line.split_once(':')?;
                            if k.eq_ignore_ascii_case("content-length") {
                                v.trim().parse::<usize>().ok()
                            } else {
                                None
                            }
                        })
                        .unwrap_or(0);
                    while buf.len() < end + content_len {
                        match stream.read(&mut tmp) {
                            Ok(0) => break,
                            Ok(n) => buf.extend_from_slice(&tmp[..n]),
                            Err(_) => break,
                        }
                    }
                    let body = if buf.len() >= end + content_len {
                        &buf[end..end + content_len]
                    } else {
                        &buf[end..]
                    };
                    let val = headers_text
                        .lines()
                        .find_map(|line| {
                            let (k, v) = line.split_once(':')?;
                            if k.trim().eq_ignore_ascii_case(extra_header_name) {
                                Some(v.trim().to_string())
                            } else {
                                None
                            }
                        })
                        .unwrap_or_default();
                    if headers_text
                        .to_ascii_lowercase()
                        .contains(&format!("{}:", extra_header_name.to_ascii_lowercase()))
                    {
                        seen_t.lock().unwrap().push(val);
                    }
                    hits_t.fetch_add(1, Ordering::SeqCst);
                    let resp_body = format!("ok:{}", String::from_utf8_lossy(body));
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        resp_body.len(),
                        resp_body
                    );
                    let _ = stream.write_all(resp.as_bytes());
                    let _ = stream.flush();
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(_) => break,
            }
        }
    });
    (addr, seen, hits, handle)
}

fn pump_app_until(app: &mut App, timeout: Duration, mut pred: impl FnMut(&App) -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        app.drain_events();
        if pred(app) {
            return true;
        }
        thread::sleep(Duration::from_millis(20));
    }
    app.drain_events();
    pred(app)
}

#[test]
fn tui_drop_via_action_path_never_reaches_upstream() {
    let (upstream_addr, _seen, hits, upstream_thread) = start_upstream_echo("X-Rf");
    let proxy_port = reserve_local_port();
    let mut config = AppConfig::default();
    config.proxy.port = proxy_port;
    config.proxy.scope = Scope::allow(ScopeRule::host("127.0.0.1"));
    config.proxy.allow_private_upstreams = true;
    config.proxy.interception_enabled = true; // armed; no rules => catch-all

    let (cmd_tx, cmd_rx) = mpsc::channel::<AppCommand>(64);
    let events = EventBus::new();
    let mut app = App::with_event_bus(config.clone(), events);
    app.attach_proxy_commands(cmd_tx);

    let rt = tokio::runtime::Runtime::new().unwrap();
    let event_sender = app.event_sender();
    let svc = rt.spawn(rawframe_proxy::run_service(cmd_rx, event_sender));

    app.dispatch_app_command(AppCommand::StartProxy(Box::new(config.clone())));
    assert!(
        pump_app_until(&mut app, Duration::from_secs(8), |a| {
            a.proxy_state() == rawframe_core::ProxyState::Listening
        }),
        "proxy did not reach listening state"
    );

    let url = format!("http://{upstream_addr}/drop");
    let proxy = format!("127.0.0.1:{proxy_port}");
    let client = thread::spawn(move || {
        std::process::Command::new("curl")
            .args(["-sS", "--max-time", "10", "-x", &proxy, &url])
            .output()
            .expect("curl")
    });

    assert!(
        pump_app_until(&mut app, Duration::from_secs(8), |a| {
            a.interception_pending_count() > 0
        }),
        "no pending interception appeared in TUI"
    );

    app.interception_drop_action();

    let out = client.join().expect("client join");
    assert!(
        out.status.success(),
        "curl failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let body = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        body.to_ascii_lowercase().contains("drop")
            || body.to_ascii_lowercase().contains("intercept"),
        "unexpected client body: {body}"
    );

    assert!(
        pump_app_until(&mut app, Duration::from_secs(5), |a| {
            a.traffic()
                .iter()
                .any(|e| e.is_live_capture() && matches!(e.state, TrafficState::Dropped))
        }),
        "dropped state not observed in TUI traffic"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "upstream must not receive dropped request"
    );

    app.dispatch_app_command(AppCommand::StopProxy);
    let _ = pump_app_until(&mut app, Duration::from_secs(5), |a| {
        matches!(
            a.proxy_state(),
            rawframe_core::ProxyState::Stopped | rawframe_core::ProxyState::Failed
        )
    });
    drop(app);
    rt.block_on(async {
        let _ = svc.await;
    });
    let _ = upstream_thread.join();
}

#[test]
fn tui_forward_modified_via_editor_path_reaches_upstream_with_modified_header() {
    let (upstream_addr, seen, hits, upstream_thread) = start_upstream_echo("X-Rf");
    let proxy_port = reserve_local_port();
    let mut config = AppConfig::default();
    config.proxy.port = proxy_port;
    config.proxy.scope = Scope::allow(ScopeRule::host("127.0.0.1"));
    config.proxy.allow_private_upstreams = true;
    config.proxy.interception_enabled = true;

    let (cmd_tx, cmd_rx) = mpsc::channel::<AppCommand>(64);
    let events = EventBus::new();
    let mut app = App::with_event_bus(config.clone(), events);
    app.attach_proxy_commands(cmd_tx);

    let rt = tokio::runtime::Runtime::new().unwrap();
    let event_sender = app.event_sender();
    let svc = rt.spawn(rawframe_proxy::run_service(cmd_rx, event_sender));

    app.dispatch_app_command(AppCommand::StartProxy(Box::new(config.clone())));
    assert!(pump_app_until(&mut app, Duration::from_secs(8), |a| {
        a.proxy_state() == rawframe_core::ProxyState::Listening
    }));

    let url = format!("http://{upstream_addr}/modify");
    let proxy = format!("127.0.0.1:{proxy_port}");
    let client = thread::spawn(move || {
        std::process::Command::new("curl")
            .args([
                "-sS",
                "--max-time",
                "10",
                "-x",
                &proxy,
                "-H",
                "X-Rf: original",
                &url,
            ])
            .output()
            .expect("curl")
    });

    assert!(
        pump_app_until(&mut app, Duration::from_secs(8), |a| {
            a.interception_pending_count() > 0
        }),
        "no pending interception appeared in TUI"
    );

    let id = app.interception_selected().expect("selected interception");
    let original_text = app.interception_editor_text();
    let modified_text = original_text
        .replace("X-Rf: original", "X-Rf: modified")
        .replace("x-rf: original", "x-rf: modified");
    assert_ne!(
        original_text, modified_text,
        "editor text did not contain header to modify: {original_text}"
    );
    app.set_interception_editor_text(&modified_text);

    app.interception_forward_modified_action();

    let out = client.join().expect("client join");
    assert!(
        out.status.success(),
        "curl failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let body = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(body.contains("ok:"), "unexpected client body: {body}");

    assert!(
        pump_app_until(&mut app, Duration::from_secs(6), |a| {
            a.traffic().iter().any(|e| {
                e.id == id && matches!(e.state, TrafficState::Completed | TrafficState::Forwarded)
            })
        }),
        "modified request did not reach terminal/completed state in TUI"
    );

    let vals = seen.lock().unwrap().clone();
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "upstream should receive exactly one request"
    );
    assert!(
        vals.iter().any(|v| v == "modified"),
        "upstream did not see modified header, saw: {vals:?}"
    );

    let entry = app
        .traffic()
        .iter()
        .find(|e| e.id == id)
        .cloned()
        .expect("entry present");
    assert!(
        entry.interception.modified,
        "entry should be marked modified"
    );
    assert!(
        entry.response.is_some(),
        "actual upstream response should be present"
    );
    assert_ne!(
        entry.original_request, entry.final_request,
        "original/final should differ for modified request"
    );

    app.dispatch_app_command(AppCommand::StopProxy);
    let _ = pump_app_until(&mut app, Duration::from_secs(5), |a| {
        matches!(
            a.proxy_state(),
            rawframe_core::ProxyState::Stopped | rawframe_core::ProxyState::Failed
        )
    });
    drop(app);
    rt.block_on(async {
        let _ = svc.await;
    });
    let _ = upstream_thread.join();
}

#[test]
fn tui_forward_unchanged_via_action_path_reaches_upstream() {
    let (upstream_addr, _seen, hits, upstream_thread) = start_upstream_echo("X-Rf");
    let proxy_port = reserve_local_port();
    let mut config = AppConfig::default();
    config.proxy.port = proxy_port;
    config.proxy.scope = Scope::allow(ScopeRule::host("127.0.0.1"));
    config.proxy.allow_private_upstreams = true;
    config.proxy.interception_enabled = true;

    let (cmd_tx, cmd_rx) = mpsc::channel::<AppCommand>(64);
    let events = EventBus::new();
    let mut app = App::with_event_bus(config.clone(), events);
    app.attach_proxy_commands(cmd_tx);

    let rt = tokio::runtime::Runtime::new().unwrap();
    let event_sender = app.event_sender();
    let svc = rt.spawn(rawframe_proxy::run_service(cmd_rx, event_sender));

    app.dispatch_app_command(AppCommand::StartProxy(Box::new(config.clone())));
    assert!(pump_app_until(&mut app, Duration::from_secs(8), |a| {
        a.proxy_state() == rawframe_core::ProxyState::Listening
    }));

    let url = format!("http://{upstream_addr}/inspect");
    let proxy = format!("127.0.0.1:{proxy_port}");
    let client = thread::spawn(move || {
        std::process::Command::new("curl")
            .args(["-sS", "--max-time", "10", "-x", &proxy, &url])
            .output()
            .expect("curl")
    });

    assert!(pump_app_until(&mut app, Duration::from_secs(8), |a| {
        a.interception_pending_count() > 0
    }));
    app.interception_forward_unchanged_action();
    let out = client.join().expect("client");
    assert!(
        out.status.success(),
        "curl failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    assert!(pump_app_until(&mut app, Duration::from_secs(6), |a| {
        a.traffic().iter().any(|e| {
            e.is_live_capture()
                && matches!(e.state, TrafficState::Completed | TrafficState::Forwarded)
                && e.response.is_some()
        })
    }));
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    app.dispatch_app_command(AppCommand::StopProxy);
    let _ = pump_app_until(&mut app, Duration::from_secs(5), |a| {
        matches!(
            a.proxy_state(),
            rawframe_core::ProxyState::Stopped | rawframe_core::ProxyState::Failed
        )
    });
    drop(app);
    rt.block_on(async {
        let _ = svc.await;
    });
    let _ = upstream_thread.join();
}
