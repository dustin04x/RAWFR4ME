use ratatui::crossterm::event::{
    KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use rawframe_core::models::HttpRequest;
use rawframe_core::models::message::Scheme;
use rawframe_core::models::traffic::{TrafficEntry, TrafficId, TrafficState};
use rawframe_core::{AppCommand, AppEvent};
use rawframe_tui::interaction::{Focus, HitTarget, NavSection, SettingId};
use rawframe_tui::{App, testing};

fn press(app: &mut App, code: KeyCode) {
    app.handle_key(KeyEvent::new(code, KeyModifiers::NONE));
}

fn ctrl(app: &mut App, ch: char) {
    app.handle_key(KeyEvent::new(KeyCode::Char(ch), KeyModifiers::CONTROL));
}

fn type_text(app: &mut App, text: &str) {
    for ch in text.chars() {
        press(app, KeyCode::Char(ch));
    }
}

fn mouse(app: &mut App, kind: MouseEventKind, column: u16, row: u16) {
    app.handle_mouse(MouseEvent {
        kind,
        column,
        row,
        modifiers: KeyModifiers::NONE,
    });
}

fn click_at(app: &mut App, column: u16, row: u16) {
    mouse(app, MouseEventKind::Down(MouseButton::Left), column, row);
    mouse(app, MouseEventKind::Up(MouseButton::Left), column, row);
}

fn pause_live_request(app: &mut App, id: u64) {
    let mut entry = TrafficEntry::new(
        TrafficId(id),
        HttpRequest::new("GET", Scheme::Http, "pause.example.test", 80, "/pending"),
    );
    entry.state = TrafficState::Paused;
    entry.interception.intercepted = true;
    app.handle_event(AppEvent::InterceptionPaused(Box::new(entry)));
}

#[test]
fn interception_editor_typing_never_fires_global_shortcuts() {
    let mut app = App::demo();
    testing::render_frame(&mut app, 140, 40);
    pause_live_request(&mut app, 801);

    press(&mut app, KeyCode::Char('e'));
    type_text(&mut app, "qp");

    assert!(!app.should_quit());
    assert!(!app.config().proxy.interception_enabled);
    let text = app.interception_editor_text();
    assert!(
        text.contains("qp"),
        "typing was swallowed by shortcuts: {text:?}"
    );
}

#[test]
fn modified_forward_needs_an_edit_and_an_explicit_send() {
    let mut app = App::demo();
    let (sender, mut receiver) = tokio::sync::mpsc::channel(8);
    app.attach_proxy_commands(sender);
    testing::render_frame(&mut app, 140, 40);
    pause_live_request(&mut app, 802);

    press(&mut app, KeyCode::Char('s'));
    assert!(
        receiver.try_recv().is_err(),
        "unmodified request must not be sent as modified"
    );

    app.set_interception_editor_text(
        "GET /edited HTTP/1.1\r\nHost: pause.example.test\r\nX-Rf: edited\r\n\r\n",
    );
    press(&mut app, KeyCode::Char('s'));

    match receiver.try_recv() {
        Ok(AppCommand::ForwardModified { id, request }) => {
            assert_eq!(id, TrafficId(802));
            assert!(request.target.ends_with("/edited"), "{request:?}");
            assert_eq!(request.headers.get("x-rf"), Some("edited"));
        }
        other => panic!("expected an explicit forward-modified command, got {other:?}"),
    }
}

#[test]
fn keyboard_navigation_search_and_palette_work_end_to_end() {
    let mut app = App::demo();
    testing::render_frame(&mut app, 140, 40);

    ctrl(&mut app, '2');
    assert_eq!(app.nav(), NavSection::History);

    ctrl(&mut app, 'f');
    type_text(&mut app, "orders");
    press(&mut app, KeyCode::Enter);
    let filtered = app.history_entries();
    assert!(!filtered.is_empty());
    assert!(filtered.iter().all(|entry| {
        entry.request.target.contains("orders")
            || entry.request.host.contains("orders")
            || entry.request.method.contains("orders")
    }));

    ctrl(&mut app, 'k');
    type_text(&mut app, "redact");
    press(&mut app, KeyCode::Enter);
    assert!(!app.config().appearance.redact_sensitive_headers);

    press(&mut app, KeyCode::Char('?'));
    assert!(app.overlay_open());
    press(&mut app, KeyCode::Esc);
    assert!(!app.overlay_open());
}

#[test]
fn mouse_navigation_panel_dragging_and_double_click_inspector() {
    let mut app = App::demo();
    testing::render_frame(&mut app, 140, 40);

    let history =
        testing::position_for(&app, &HitTarget::Nav(NavSection::History)).expect("history nav hit");
    click_at(&mut app, history.x, history.y);
    assert_eq!(app.nav(), NavSection::History);

    testing::render_frame(&mut app, 140, 40);
    let before = app.current_layout().sidebar.expect("sidebar").width;
    let splitter = testing::position_for(
        &app,
        &HitTarget::Splitter(rawframe_tui::layout::DragTarget::Sidebar),
    )
    .expect("sidebar splitter");
    mouse(
        &mut app,
        MouseEventKind::Down(MouseButton::Left),
        splitter.x,
        splitter.y,
    );
    mouse(
        &mut app,
        MouseEventKind::Drag(MouseButton::Left),
        splitter.x + 4,
        splitter.y,
    );
    mouse(
        &mut app,
        MouseEventKind::Up(MouseButton::Left),
        splitter.x + 4,
        splitter.y,
    );
    assert!(app.current_layout().sidebar.expect("sidebar").width > before);

    let proxy = testing::position_for(&app, &HitTarget::Nav(NavSection::Proxy)).expect("proxy nav");
    click_at(&mut app, proxy.x, proxy.y);

    // The live Proxy workspace only lists real captures, so inject one.
    let mut live = TrafficEntry::new(
        TrafficId(777),
        HttpRequest::new("GET", Scheme::Http, "live.example.test", 80, "/session"),
    );
    live.state = TrafficState::Completed;
    app.handle_event(AppEvent::TrafficCaptured(Box::new(live)));
    testing::render_frame(&mut app, 140, 40);

    let row = app
        .proxy_entries()
        .first()
        .map(|entry| HitTarget::ProxyRow(entry.id))
        .expect("live proxy row");
    let row_position = testing::position_for(&app, &row).expect("row hit");
    click_at(&mut app, row_position.x, row_position.y);
    click_at(&mut app, row_position.x, row_position.y);

    assert_eq!(app.focus(), Focus::Context);
    assert_eq!(app.nav(), NavSection::Proxy);
}

#[test]
fn repeater_typing_never_fires_global_shortcuts() {
    let mut app = App::demo();
    ctrl(&mut app, '3');
    testing::render_frame(&mut app, 120, 36);

    press(&mut app, KeyCode::Enter);
    assert!(app.active_repeater_tab().is_some());
    type_text(&mut app, "qdf");

    assert!(!app.should_quit());
    assert!(!app.config().proxy.interception_enabled);
    let editor = &app.active_repeater_tab().unwrap().editor;
    assert!(
        editor.text().starts_with("qdf"),
        "unexpected editor text: {:?}",
        editor.text()
    );

    // Tab leaves text entry rather than inserting a tab.
    press(&mut app, KeyCode::Tab);
    assert!(!app.repeater_is_editing());
    assert!(app.active_repeater_tab().unwrap().dirty);
}

#[test]
fn dirty_repeater_quit_requires_confirmation() {
    let mut app = App::demo();
    ctrl(&mut app, '3');
    press(&mut app, KeyCode::Enter);
    type_text(&mut app, "x");
    press(&mut app, KeyCode::Esc);
    press(&mut app, KeyCode::Char('q'));

    assert!(!app.should_quit());
    assert!(app.overlay_open());

    press(&mut app, KeyCode::Enter);
    assert!(app.should_quit());
}

#[test]
fn settings_edits_are_validated_and_applied() {
    let mut app = App::demo();
    ctrl(&mut app, '4');
    testing::render_frame(&mut app, 130, 36);

    press(&mut app, KeyCode::Down);
    assert_eq!(app.settings_selected(), SettingId::Port);
    press(&mut app, KeyCode::Enter);
    for _ in 0..4 {
        press(&mut app, KeyCode::Backspace);
    }
    type_text(&mut app, "9090");
    press(&mut app, KeyCode::Enter);

    assert_eq!(app.config().proxy.port, 9090);
}

#[test]
fn scroll_wheel_moves_the_history_selection() {
    let mut app = App::demo();
    ctrl(&mut app, '2');
    testing::render_frame(&mut app, 130, 36);

    let first = app.history_selected_id();
    let list = testing::position_for(&app, &HitTarget::HistoryRow(first.expect("selection")))
        .expect("row hit");
    mouse(&mut app, MouseEventKind::ScrollDown, list.x, list.y);
    assert_ne!(app.history_selected_id(), first);
}
