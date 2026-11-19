//! Keyboard and mouse handling.
//!
//! Input is resolved against hit rectangles recorded by the most recent frame.
//! Overlays capture input first; text-entry contexts prevent single-letter
//! shortcuts from firing while the operator is typing.

use std::time::Instant;

use ratatui::crossterm::event::{
    KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use ratatui::layout::Position;

use crate::app::App;
use crate::interaction::{
    Focus, HitTarget, InspectorView, MessageSide, NavSection, ScrollRegion, SettingId,
};
use crate::layout::DragTarget;
use crate::state::{DecoderFocus, RepeaterView};

const DOUBLE_CLICK_WINDOW_MS: u128 = 450;

impl App {
    pub fn handle_key(&mut self, key: KeyEvent) {
        if key.kind == KeyEventKind::Release {
            return;
        }

        let control = key.modifiers.contains(KeyModifiers::CONTROL);

        // Emergency quit always wins and never requires confirmation.
        if control && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('C')) {
            self.should_quit = true;
            return;
        }

        if self.confirm.is_some() {
            self.handle_confirm_key(key);
            return;
        }
        if self.intruder.prompt.is_some() {
            self.handle_intruder_prompt_key(key);
            return;
        }
        if self.palette.is_some() {
            self.handle_palette_key(key);
            return;
        }
        if self.context_menu.is_some() {
            self.handle_menu_key(key);
            return;
        }
        if self.scope_editor.is_some() {
            self.handle_scope_editor_key(key);
            return;
        }
        if self.sessions_open {
            self.handle_sessions_key(key);
            return;
        }
        if self.help_open {
            if matches!(key.code, KeyCode::Esc) || plain_char(&key) == Some('?') {
                self.help_open = false;
            }
            return;
        }
        if self.settings.edit.is_some() {
            self.handle_setting_edit_key(key);
            return;
        }

        if control && self.handle_control_shortcut(&key) {
            return;
        }

        match key.code {
            KeyCode::Esc => {
                if self.search.active {
                    self.search.active = false;
                } else if self.interception.editing {
                    self.interception.editing = false;
                } else if self.websocket.editing() {
                    self.websocket.cancel_edit();
                } else if self.websocket.searching {
                    self.websocket.stop_search();
                } else if self.repeater.editing {
                    self.repeater.editing = false;
                } else if self.intruder.editing {
                    self.intruder.editing = false;
                    self.intruder.apply_edit();
                } else if self.focus == Focus::Context {
                    self.focus = Focus::Content;
                }
                return;
            }
            KeyCode::Tab => {
                self.leave_text_entry();
                self.cycle_focus(false);
                return;
            }
            KeyCode::BackTab => {
                self.leave_text_entry();
                self.cycle_focus(true);
                return;
            }
            _ => {}
        }

        if self.search.active {
            self.handle_search_key(key);
            return;
        }

        if self.nav == NavSection::Proxy
            && self.focus == Focus::Content
            && self.interception.editing
        {
            self.handle_interception_editor_key(key);
            return;
        }

        if self.nav == NavSection::Repeater && self.focus == Focus::Content && self.repeater.editing
        {
            self.handle_editor_key(key);
            return;
        }

        if self.nav == NavSection::Decoder && self.decoder.history_open {
            self.handle_decoder_history_key(key);
            return;
        }

        if self.nav == NavSection::Decoder && self.focus == Focus::Content && self.decoder.editing {
            self.handle_decoder_editor_key(key);
            return;
        }

        if self.nav == NavSection::Intruder && self.focus == Focus::Content && self.intruder.editing
        {
            self.handle_intruder_editor_key(key);
            return;
        }

        if self.nav == NavSection::Intruder && self.focus == Focus::Content {
            self.handle_intruder_key(key);
            return;
        }

        if self.nav == NavSection::WebSocket && self.focus == Focus::Content {
            if self.websocket.editing() {
                self.handle_websocket_editor_key(key);
                return;
            }
            if self.websocket.searching {
                self.handle_websocket_search_key(key);
                return;
            }
        }

        if let Some(ch) = plain_char(&key) {
            match ch {
                '?' => {
                    self.help_open = true;
                    return;
                }
                'B' => {
                    self.open_sessions();
                    return;
                }
                'q' => {
                    self.request_quit();
                    return;
                }
                'i' => {
                    // Proxy and WebSocket use I for interception; Repeater,
                    // History, and Decoder use it to send a request or payload
                    // to Intruder. Other workspaces keep the inspector toggle.
                    let workspace = matches!(
                        self.nav,
                        NavSection::Proxy
                            | NavSection::WebSocket
                            | NavSection::History
                            | NavSection::Repeater
                            | NavSection::Decoder
                    );
                    if !(workspace && self.focus == Focus::Content) {
                        self.toggle_inspector();
                        return;
                    }
                }
                _ => {}
            }
        }

        match self.focus {
            Focus::Nav => self.handle_nav_key(key),
            Focus::Content => self.handle_content_key(key),
            Focus::Context => self.handle_context_key(key),
        }
    }

    pub fn handle_paste(&mut self, text: &str) {
        if self.scope_editor.is_some() {
            for ch in single_line(text).chars() {
                self.scope_input_push(ch);
            }
            return;
        }
        if self.settings.edit.is_some() {
            let single_line = single_line(text);
            if let Some(edit) = &mut self.settings.edit {
                edit.buffer.push_str(&single_line);
                edit.buffer.truncate(128);
            }
            return;
        }

        if self.palette.is_some() {
            let single_line = single_line(text);
            if let Some(palette) = &mut self.palette {
                let mut query = palette.query.clone();
                query.push_str(&single_line);
                palette.set_query(query);
            }
            return;
        }

        if self.search.active {
            let single_line = single_line(text);
            self.history_filter.query.push_str(&single_line);
            self.ensure_selections();
            return;
        }

        if self.nav == NavSection::Proxy
            && self.focus == Focus::Content
            && self.interception.editing
        {
            let rows = self.render.repeater_rows;
            let cols = self.render.repeater_cols;
            self.interception.editor.insert_str(text);
            self.interception.dirty = true;
            self.interception.parse_error = None;
            self.interception.validation_error = None;
            self.interception.editor.ensure_visible(rows, cols);
            return;
        }

        if self.nav == NavSection::Decoder && self.focus == Focus::Content && self.decoder.editing {
            let rows = self.render.repeater_rows;
            let cols = self.render.repeater_cols;
            self.decoder.input.insert_str(text);
            self.decoder.sync_input();
            self.decoder.input.ensure_visible(rows, cols);
            if self.decoder.input_bytes.len() > self.decoder.limits.max_input_bytes {
                self.notify_warning(format!(
                    "Decoder input is {} bytes; the execution limit is {} bytes.",
                    self.decoder.input_bytes.len(),
                    self.decoder.limits.max_input_bytes
                ));
            }
            return;
        }

        if self.nav == NavSection::Repeater && self.focus == Focus::Content && self.repeater.editing
        {
            let rows = self.render.repeater_rows;
            let cols = self.render.repeater_cols;
            if let Some(tab) = self.repeater.active_tab_mut() {
                tab.editor.insert_str(text);
                tab.dirty = true;
                tab.refresh_parse();
                tab.editor.ensure_visible(rows, cols);
            }
            return;
        }

        if self.nav == NavSection::WebSocket && self.focus == Focus::Content {
            if self.websocket.searching {
                for ch in single_line(text).chars() {
                    self.websocket.push_filter_char(ch);
                }
                return;
            }
            if self.websocket.editing() {
                let rows = self.render.repeater_rows.max(1);
                let cols = self.render.repeater_cols.max(1);
                if let Some(editor) = self.websocket.editor_mut() {
                    editor.insert_str(text);
                    editor.ensure_visible(rows, cols);
                }
            }
        }
    }

    pub fn handle_mouse(&mut self, mouse: MouseEvent) {
        if !self.config.appearance.mouse_enabled {
            return;
        }

        self.pointer = Some(Position::new(mouse.column, mouse.row));
        if matches!(mouse.kind, MouseEventKind::Moved) {
            self.hover = self.render.hit_at(mouse.column, mouse.row).cloned();
            return;
        }

        if self.palette.is_some()
            || self.context_menu.is_some()
            || self.help_open
            || self.confirm.is_some()
        {
            self.handle_overlay_mouse(mouse);
            return;
        }

        match mouse.kind {
            MouseEventKind::Down(MouseButton::Left) => self.handle_left_click(mouse),
            MouseEventKind::Down(MouseButton::Right) => self.handle_right_click(mouse),
            MouseEventKind::Up(MouseButton::Left) => self.drag = None,
            MouseEventKind::Drag(MouseButton::Left) => {
                if let Some(target) = self.drag {
                    match target {
                        DragTarget::Sidebar => {
                            self.layout.resize_sidebar(self.last_area, mouse.column)
                        }
                        DragTarget::Context => {
                            self.layout.resize_context(self.last_area, mouse.column)
                        }
                    }
                }
            }
            MouseEventKind::ScrollUp => self.scroll_at(mouse.column, mouse.row, true),
            MouseEventKind::ScrollDown => self.scroll_at(mouse.column, mouse.row, false),
            _ => {}
        }
    }

    fn handle_control_shortcut(&mut self, key: &KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('k') | KeyCode::Char('K') => {
                self.open_palette();
                true
            }
            KeyCode::Char('1') => {
                self.navigate(NavSection::Proxy);
                true
            }
            KeyCode::Char('2') => {
                self.navigate(NavSection::History);
                true
            }
            KeyCode::Char('3') => {
                self.navigate(NavSection::Repeater);
                true
            }
            KeyCode::Char('4') => {
                self.navigate(NavSection::Settings);
                true
            }
            KeyCode::Char('5') => {
                self.navigate(NavSection::Intruder);
                true
            }
            KeyCode::Char('6') => {
                self.navigate(NavSection::Decoder);
                true
            }
            KeyCode::Char('7') => {
                self.navigate(NavSection::WebSocket);
                true
            }
            KeyCode::Char('f') | KeyCode::Char('F') => {
                self.start_search();
                true
            }
            KeyCode::Char('n') | KeyCode::Char('N') => {
                self.navigate(NavSection::Repeater);
                self.repeater.new_blank();
                self.repeater.editing = true;
                self.notify_info("New Repeater tab.");
                true
            }
            KeyCode::Char('w') | KeyCode::Char('W') => {
                if self.nav == NavSection::Repeater {
                    self.request_close_repeater_tab();
                }
                true
            }
            KeyCode::Enter => {
                match self.nav {
                    NavSection::Repeater => self.send_repeater_request(),
                    NavSection::Decoder => self.execute_decoder(),
                    _ => return false,
                }
                true
            }
            KeyCode::Char('u') | KeyCode::Char('U') => {
                if self.nav == NavSection::History {
                    self.clear_filters();
                    self.notify_info("History filters cleared.");
                }
                true
            }
            _ => false,
        }
    }

    fn leave_text_entry(&mut self) {
        self.search.active = false;
        self.repeater.editing = false;
        self.decoder.editing = false;
    }

    fn cycle_focus(&mut self, reverse: bool) {
        let layout = self.current_layout();
        let mut options = vec![Focus::Content];
        if layout.sidebar.is_some() {
            options.insert(0, Focus::Nav);
        }
        if layout.context.is_some() && self.nav.uses_context() {
            options.push(Focus::Context);
        }

        let index = options
            .iter()
            .position(|focus| *focus == self.focus)
            .unwrap_or(0);
        let next = if reverse {
            (index + options.len() - 1) % options.len()
        } else {
            (index + 1) % options.len()
        };
        self.focus = options[next];
    }

    fn handle_nav_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                let previous = self.nav.previous();
                self.navigate(previous);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let next = self.nav.next();
                self.navigate(next);
            }
            KeyCode::Enter | KeyCode::Right => {
                self.focus = Focus::Content;
            }
            KeyCode::Home => self.navigate(NavSection::Proxy),
            KeyCode::End => self.navigate(NavSection::Settings),
            _ => {}
        }
    }

    fn handle_content_key(&mut self, key: KeyEvent) {
        match self.nav {
            NavSection::Proxy => self.handle_proxy_key(key),
            NavSection::History => self.handle_history_key(key),
            NavSection::Repeater => self.handle_repeater_key(key),
            NavSection::Settings => self.handle_settings_key(key),
            NavSection::Decoder => self.handle_decoder_key(key),
            NavSection::WebSocket => self.handle_websocket_key(key),
            NavSection::Intruder => {}
        }
    }

    fn handle_websocket_key(&mut self, key: KeyEvent) {
        if key.modifiers.contains(KeyModifiers::CONTROL) {
            return;
        }
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.websocket.move_frame(-1),
            KeyCode::Down | KeyCode::Char('j') => self.websocket.move_frame(1),
            KeyCode::PageUp => self.websocket.move_frame(-8),
            KeyCode::PageDown => self.websocket.move_frame(8),
            KeyCode::Home => self.websocket.select_frame_edge(false),
            KeyCode::End => self.websocket.select_frame_edge(true),
            KeyCode::Left | KeyCode::Char('h') | KeyCode::Char('[') => {
                self.websocket.move_connection(-1)
            }
            KeyCode::Right | KeyCode::Char('l') | KeyCode::Char(']') => {
                self.websocket.move_connection(1)
            }
            _ => match plain_char(&key) {
                Some('/') => self.websocket.start_search(),
                Some('f') => self.websocket_forward(),
                Some('d') => self.websocket_drop(),
                Some('m') => self.websocket_begin_edit(),
                Some('i') => self.toggle_interception(),
                Some('n') => self.websocket_next_paused(),
                Some('c') => self.websocket_clear(),
                Some('o') => self.websocket_open_repeater(),
                Some('t') => self.websocket_compose(),
                Some('s') => self.websocket_close_repeater(),
                Some('x') => {
                    self.websocket.clear_filter();
                    self.notify_info("WebSocket filter cleared.");
                }
                _ => {}
            },
        }
    }

    fn handle_websocket_editor_key(&mut self, key: KeyEvent) {
        let rows = self.render.repeater_rows.max(1);
        let cols = self.render.repeater_cols.max(1);
        match key.code {
            KeyCode::Esc => {
                self.websocket.cancel_edit();
                return;
            }
            KeyCode::Enter if key.modifiers.contains(KeyModifiers::CONTROL) => {
                if self.websocket.composing() {
                    self.websocket_submit_compose();
                } else {
                    self.websocket_submit_edit();
                }
                return;
            }
            KeyCode::Tab => {
                self.websocket.cancel_edit();
                self.cycle_focus(false);
                return;
            }
            _ => {}
        }
        if key.modifiers.contains(KeyModifiers::CONTROL)
            || key.modifiers.contains(KeyModifiers::ALT)
        {
            return;
        }
        let Some(editor) = self.websocket.editor_mut() else {
            return;
        };
        match key.code {
            KeyCode::Enter => editor.newline(),
            KeyCode::Backspace => editor.backspace(),
            KeyCode::Delete => editor.delete(),
            KeyCode::Left => editor.move_left(),
            KeyCode::Right => editor.move_right(),
            KeyCode::Up => editor.move_up(),
            KeyCode::Down => editor.move_down(),
            KeyCode::Home => editor.move_home(),
            KeyCode::End => editor.move_end(),
            KeyCode::PageUp => editor.page_up(rows),
            KeyCode::PageDown => editor.page_down(rows),
            KeyCode::Char(ch) => editor.insert_char(ch),
            _ => return,
        }
        editor.ensure_visible(rows, cols);
    }

    fn handle_websocket_search_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc | KeyCode::Enter => {
                self.websocket.stop_search();
                return;
            }
            KeyCode::Up => {
                self.websocket.move_frame(-1);
                return;
            }
            KeyCode::Down => {
                self.websocket.move_frame(1);
                return;
            }
            KeyCode::Backspace => {
                self.websocket.pop_filter_char();
                return;
            }
            KeyCode::Char('u') | KeyCode::Char('U')
                if key.modifiers.contains(KeyModifiers::CONTROL) =>
            {
                self.websocket.clear_filter();
                return;
            }
            _ => {}
        }
        if let KeyCode::Char(ch) = key.code
            && !key.modifiers.contains(KeyModifiers::CONTROL)
            && !key.modifiers.contains(KeyModifiers::ALT)
            && !ch.is_control()
        {
            self.websocket.push_filter_char(ch);
        }
    }

    fn handle_proxy_key(&mut self, key: KeyEvent) {
        // If there are real pending interceptions, use interception workbench controls.
        let interception_mode =
            !self.pending_interceptions().is_empty() || self.interception.selected.is_some();
        if interception_mode {
            // Ctrl+Enter forwards modified request when not typing in editor (editor path handled earlier).
            if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Enter {
                self.forward_interception_modified();
                return;
            }
            match key.code {
                KeyCode::Up | KeyCode::Char('k') => self.move_interception_selection(-1),
                KeyCode::Down | KeyCode::Char('j') => self.move_interception_selection(1),
                KeyCode::PageUp => self.move_interception_selection(-8),
                KeyCode::PageDown => self.move_interception_selection(8),
                KeyCode::Home => self.select_interception_edge(false),
                KeyCode::End => self.select_interception_edge(true),
                KeyCode::Enter => {
                    if self.interception.selected.is_some() {
                        self.interception.editing = false;
                    }
                }
                KeyCode::Esc => {
                    self.interception.editing = false;
                }
                _ => match plain_char(&key) {
                    Some('f') => self.forward_interception_unchanged(),
                    Some('s') => {
                        if self.interception.dirty {
                            self.forward_interception_modified();
                        } else {
                            self.notify_info(
                                "Nothing edited yet. Press E to edit, then S to send the modified request.",
                            );
                        }
                    }
                    Some('d') => self.drop_interception(),
                    Some('e') => {
                        if self.interception.selected.is_some() {
                            self.interception.editing = true;
                        }
                    }
                    Some('i') => self.toggle_interception(),
                    Some('r') => {
                        if let Some(id) = self.interception.selected.or(self.selected_id()) {
                            self.open_in_repeater(id, false);
                        }
                    }
                    Some('p') => self.toggle_proxy(),
                    _ => {}
                },
            }
            return;
        }

        // Legacy/simulated proxy view behavior.
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
            KeyCode::PageUp => self.move_selection(-8),
            KeyCode::PageDown => self.move_selection(8),
            KeyCode::Home => self.select_edge(false),
            KeyCode::End => self.select_edge(true),
            KeyCode::Enter => self.inspect_selected(),
            _ => match plain_char(&key) {
                Some('f') => self.forward_selected_request(),
                Some('d') => self.drop_selected_request(),
                Some('r') => {
                    if let Some(id) = self.selected_id() {
                        self.open_in_repeater(id, false);
                    }
                }
                Some('e') => {
                    if let Some(id) = self.selected_id() {
                        self.open_in_repeater(id, true);
                    }
                }
                Some('i') => self.toggle_interception(),
                Some('p') => self.toggle_proxy(),
                Some(' ') => self.toggle_interception(),
                _ => {}
            },
        }
    }

    fn handle_history_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
            KeyCode::PageUp => self.move_selection(-8),
            KeyCode::PageDown => self.move_selection(8),
            KeyCode::Home => self.select_edge(false),
            KeyCode::End => self.select_edge(true),
            KeyCode::Enter => self.inspect_selected(),
            _ => match plain_char(&key) {
                Some('/') => self.start_search(),
                Some('m') => self.cycle_method_filter(),
                Some('s') => self.cycle_status_filter(),
                Some('h') => self.cycle_host_filter(),
                Some('f') => self.forward_selected_request(),
                Some('d') => self.drop_selected_request(),
                Some('r') => {
                    if let Some(id) = self.selected_id() {
                        self.open_in_repeater(id, false);
                    }
                }
                Some('e') => {
                    if let Some(id) = self.selected_id() {
                        self.open_in_repeater(id, true);
                    }
                }
                Some('i') => {
                    if let Some(id) = self.selected_id() {
                        self.open_in_intruder(id);
                    } else {
                        self.notify_warning("Select a request first.");
                    }
                }
                _ => {}
            },
        }
    }

    fn handle_repeater_key(&mut self, key: KeyEvent) {
        if key.modifiers.contains(KeyModifiers::CONTROL) {
            return;
        }
        match key.code {
            KeyCode::Enter | KeyCode::Char('e') | KeyCode::Char('E') => {
                self.repeater.editing = true;
            }
            KeyCode::Left => self.repeater.select_previous(),
            KeyCode::Right => self.repeater.select_next(),
            KeyCode::Char('s') | KeyCode::Char('S') => self.send_repeater_request(),
            KeyCode::Char('c') | KeyCode::Char('C') => self.cancel_repeater_request(),
            KeyCode::Char('n') | KeyCode::Char('N') => {
                self.repeater.new_blank();
                self.repeater.editing = true;
            }
            KeyCode::Char('d') | KeyCode::Char('D') => self.duplicate_repeater_tab(),
            KeyCode::Char('w') | KeyCode::Char('W') => self.request_close_repeater_tab(),
            KeyCode::Char('r') | KeyCode::Char('R') => self.reset_repeater_edits(),
            KeyCode::Char('x') | KeyCode::Char('X') => self.clear_repeater_response(),
            KeyCode::Char('f') | KeyCode::Char('F') => self.toggle_repeater_redirects(),
            KeyCode::Char('b') | KeyCode::Char('B') => self.send_repeater_request_body_to_decoder(),
            KeyCode::Char('m') | KeyCode::Char('M') => {
                self.send_repeater_response_body_to_decoder()
            }
            KeyCode::Char('i') | KeyCode::Char('I') => self.send_repeater_request_to_intruder(),
            KeyCode::Char('v') | KeyCode::Char('V') => self.repeater.view_next(),
            KeyCode::Char('1') => self.repeater.view(RepeaterView::Raw),
            KeyCode::Char('2') => self.repeater.view(RepeaterView::Headers),
            KeyCode::Char('3') => self.repeater.view(RepeaterView::Body),
            KeyCode::Char('4') => self.repeater.view(RepeaterView::Json),
            KeyCode::Char('5') => self.repeater.view(RepeaterView::Hex),
            KeyCode::Char('6') => self.repeater.view(RepeaterView::Compare),
            _ => {}
        }
    }

    fn handle_decoder_history_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc | KeyCode::Char('h') | KeyCode::Char('H') => {
                self.decoder.history_open = false
            }
            KeyCode::Up | KeyCode::Char('k') => self.decoder.select_history(-1),
            KeyCode::Down | KeyCode::Char('j') => self.decoder.select_history(1),
            KeyCode::PageUp => self.decoder.select_history(-8),
            KeyCode::PageDown => self.decoder.select_history(8),
            KeyCode::Home => self.decoder.history_scroll = 0,
            KeyCode::End => {
                self.decoder.history_scroll = self.decoder.history.len().saturating_sub(1) as u16;
            }
            _ => {}
        }
    }

    fn handle_decoder_key(&mut self, key: KeyEvent) {
        let control = key.modifiers.contains(KeyModifiers::CONTROL);
        if control {
            match key.code {
                KeyCode::Enter => self.execute_decoder(),
                KeyCode::Up => self.move_decoder_step(-1),
                KeyCode::Down => self.move_decoder_step(1),
                _ => {}
            }
            return;
        }
        match key.code {
            KeyCode::Char('i') | KeyCode::Char('I') => {
                self.send_decoder_output_to_intruder_payloads()
            }
            KeyCode::Char('1') => self.decoder.focus = DecoderFocus::Input,
            KeyCode::Char('2') => self.decoder.focus = DecoderFocus::Pipeline,
            KeyCode::Char('3') => self.decoder.focus = DecoderFocus::Output,
            KeyCode::Enter | KeyCode::Char('e') | KeyCode::Char('E') => {
                if self.decoder.focus == DecoderFocus::Input {
                    self.decoder.editing = true;
                } else if self.decoder.focus == DecoderFocus::Pipeline {
                    self.preview_decoder_step();
                }
            }
            KeyCode::Left | KeyCode::Char('[') => self.decoder.select_transform(-1),
            KeyCode::Right | KeyCode::Char(']') => self.decoder.select_transform(1),
            KeyCode::Up | KeyCode::Char('k') => {
                if self.decoder.focus == DecoderFocus::Pipeline {
                    self.decoder.select_step(-1);
                } else {
                    self.decoder.output_scroll = self.decoder.output_scroll.saturating_sub(1);
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.decoder.focus == DecoderFocus::Pipeline {
                    self.decoder.select_step(1);
                } else {
                    self.decoder.output_scroll = self.decoder.output_scroll.saturating_add(1);
                }
            }
            KeyCode::PageUp => {
                self.decoder.output_scroll = self.decoder.output_scroll.saturating_sub(10)
            }
            KeyCode::PageDown => {
                self.decoder.output_scroll = self.decoder.output_scroll.saturating_add(10)
            }
            KeyCode::Home => self.decoder.output_scroll = 0,
            KeyCode::End => self.decoder.output_scroll = u16::MAX / 2,
            KeyCode::Char('a') | KeyCode::Char('A') => self.add_decoder_step(),
            KeyCode::Delete => self.remove_decoder_step(),
            KeyCode::Char('d') | KeyCode::Char('D') => self.toggle_decoder_direction(),
            KeyCode::Char('r') | KeyCode::Char('R') => self.execute_decoder(),
            KeyCode::Char('s') | KeyCode::Char('S') => self.swap_decoder_input_output(),
            KeyCode::Char('c') | KeyCode::Char('C') => self.clear_decoder(),
            KeyCode::Char('y') | KeyCode::Char('Y') => self.copy_decoder_output(),
            KeyCode::Char('h') | KeyCode::Char('H') => self.toggle_decoder_history(),
            KeyCode::Char('v') | KeyCode::Char('V') => self.preview_decoder_step(),
            KeyCode::Char('0') => self.show_decoder_final_output(),
            _ => {}
        }
    }

    fn handle_decoder_editor_key(&mut self, key: KeyEvent) {
        let rows = self.render.repeater_rows;
        let cols = self.render.repeater_cols;
        match key.code {
            KeyCode::Esc => {
                self.decoder.editing = false;
                return;
            }
            KeyCode::Tab => {
                self.decoder.editing = false;
                self.cycle_focus(false);
                return;
            }
            KeyCode::BackTab => {
                self.decoder.editing = false;
                self.cycle_focus(true);
                return;
            }
            KeyCode::Enter if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.execute_decoder();
                return;
            }
            _ => {}
        }
        if key.modifiers.contains(KeyModifiers::CONTROL)
            || key.modifiers.contains(KeyModifiers::ALT)
        {
            return;
        }
        match key.code {
            KeyCode::Enter => self.decoder.input.newline(),
            KeyCode::Backspace => self.decoder.input.backspace(),
            KeyCode::Delete => self.decoder.input.delete(),
            KeyCode::Left => self.decoder.input.move_left(),
            KeyCode::Right => self.decoder.input.move_right(),
            KeyCode::Up => self.decoder.input.move_up(),
            KeyCode::Down => self.decoder.input.move_down(),
            KeyCode::Home => self.decoder.input.move_home(),
            KeyCode::End => self.decoder.input.move_end(),
            KeyCode::PageUp => self.decoder.input.page_up(rows),
            KeyCode::PageDown => self.decoder.input.page_down(rows),
            KeyCode::Char(ch) => self.decoder.input.insert_char(ch),
            _ => return,
        }
        self.decoder.sync_input();
        self.decoder.input.ensure_visible(rows, cols);
    }

    fn handle_sessions_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc | KeyCode::Char('B') => self.close_sessions(),
            KeyCode::Up | KeyCode::Char('k') => self.move_sessions_selection(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_sessions_selection(1),
            KeyCode::PageUp => self.move_sessions_selection(-8),
            KeyCode::PageDown => self.move_sessions_selection(8),
            KeyCode::Home => self.select_session_edge(false),
            KeyCode::End => self.select_session_edge(true),
            KeyCode::Enter => self.restore_selected_session(),
            KeyCode::Char('e') | KeyCode::Char('E') => self.export_selected_session(),
            KeyCode::Char('r') | KeyCode::Char('R') => self.refresh_sessions(),
            _ => {}
        }
    }

    fn handle_scope_editor_key(&mut self, key: KeyEvent) {
        let control = key.modifiers.contains(KeyModifiers::CONTROL);
        if control && matches!(key.code, KeyCode::Char('b') | KeyCode::Char('B')) {
            self.toggle_scope_block_unlisted();
            return;
        }
        match key.code {
            KeyCode::Esc => self.close_scope_editor(),
            KeyCode::Up => self.move_scope_selection(-1),
            KeyCode::Down => self.move_scope_selection(1),
            KeyCode::Home => self.select_scope_edge(false),
            KeyCode::End => self.select_scope_edge(true),
            KeyCode::Enter => self.commit_scope_rule(),
            KeyCode::Backspace => self.scope_input_backspace(),
            KeyCode::Delete => self.remove_selected_scope_rule(),
            KeyCode::Char(ch) if !control => self.scope_input_push(ch),
            _ => {}
        }
    }

    fn handle_settings_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.settings.select_previous(),
            KeyCode::Down | KeyCode::Char('j') => self.settings.select_next(),
            KeyCode::PageUp => {
                for _ in 0..8 {
                    self.settings.select_previous();
                }
            }
            KeyCode::PageDown => {
                for _ in 0..8 {
                    self.settings.select_next();
                }
            }
            KeyCode::Home => self.settings.selected = 0,
            KeyCode::End => self.settings.selected = SettingId::ALL.len() - 1,
            KeyCode::Enter | KeyCode::Char(' ') => self.activate_setting(),
            _ => {}
        }
    }

    fn handle_context_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.scroll_context(-1),
            KeyCode::Down | KeyCode::Char('j') => self.scroll_context(1),
            KeyCode::PageUp => self.scroll_context(-10),
            KeyCode::PageDown => self.scroll_context(10),
            KeyCode::Home => self.set_context_scroll(0),
            KeyCode::End => self.set_context_scroll(u16::MAX / 2),
            KeyCode::Left | KeyCode::Char('[') => {
                if self.nav != NavSection::Repeater {
                    self.inspector.side = MessageSide::Request;
                    self.inspector.scroll = 0;
                }
            }
            KeyCode::Right | KeyCode::Char(']') => {
                if self.nav != NavSection::Repeater {
                    self.inspector.side = MessageSide::Response;
                    self.inspector.scroll = 0;
                }
            }
            KeyCode::Char('1') if self.nav == NavSection::Repeater => {
                self.repeater.view(RepeaterView::Raw)
            }
            KeyCode::Char('2') if self.nav == NavSection::Repeater => {
                self.repeater.view(RepeaterView::Headers)
            }
            KeyCode::Char('3') if self.nav == NavSection::Repeater => {
                self.repeater.view(RepeaterView::Body)
            }
            KeyCode::Char('4') if self.nav == NavSection::Repeater => {
                self.repeater.view(RepeaterView::Json)
            }
            KeyCode::Char('5') if self.nav == NavSection::Repeater => {
                self.repeater.view(RepeaterView::Hex)
            }
            KeyCode::Char('6') if self.nav == NavSection::Repeater => {
                self.repeater.view(RepeaterView::Compare)
            }
            KeyCode::Char('1') => self.set_inspector_view(InspectorView::Raw),
            KeyCode::Char('2') => self.set_inspector_view(InspectorView::Headers),
            KeyCode::Char('3') => self.set_inspector_view(InspectorView::Body),
            _ => match plain_char(&key) {
                Some('x') if self.nav == NavSection::Repeater => self.clear_repeater_response(),
                Some('x') => self.toggle_redaction(),
                Some('f') if self.nav != NavSection::Repeater => self.forward_selected_request(),
                Some('d') if self.nav != NavSection::Repeater => self.drop_selected_request(),
                Some('r') if self.nav != NavSection::Repeater => {
                    if let Some(id) = self.selected_id() {
                        self.open_in_repeater(id, false);
                    }
                }
                Some('e') if self.nav != NavSection::Repeater => {
                    if let Some(id) = self.selected_id() {
                        self.open_in_repeater(id, true);
                    }
                }
                _ => {}
            },
        }
    }

    fn set_inspector_view(&mut self, view: InspectorView) {
        if self.nav != NavSection::Repeater {
            self.inspector.view = view;
            self.inspector.scroll = 0;
        }
    }

    fn scroll_context(&mut self, delta: i32) {
        if self.nav == NavSection::Repeater {
            let next = if delta.is_negative() {
                self.repeater
                    .response_scroll
                    .saturating_sub(delta.unsigned_abs() as u16)
            } else {
                self.repeater.response_scroll.saturating_add(delta as u16)
            };
            self.repeater.response_scroll = next;
        } else {
            self.inspector.scroll_by(delta);
        }
    }

    fn set_context_scroll(&mut self, value: u16) {
        if self.nav == NavSection::Repeater {
            self.repeater.response_scroll = value;
        } else {
            self.inspector.scroll = value;
        }
    }

    fn handle_editor_key(&mut self, key: KeyEvent) {
        let rows = self.render.repeater_rows;
        let cols = self.render.repeater_cols;

        match key.code {
            KeyCode::Esc => {
                self.repeater.editing = false;
                return;
            }
            KeyCode::Tab => {
                self.repeater.editing = false;
                self.cycle_focus(false);
                return;
            }
            KeyCode::BackTab => {
                self.repeater.editing = false;
                self.cycle_focus(true);
                return;
            }
            _ => {}
        }

        if key.modifiers.contains(KeyModifiers::CONTROL)
            || key.modifiers.contains(KeyModifiers::ALT)
        {
            return;
        }

        let mut changed = false;
        let mut handled = true;
        let Some(tab) = self.repeater.active_tab_mut() else {
            return;
        };

        match key.code {
            KeyCode::Enter => {
                tab.editor.newline();
                changed = true;
            }
            KeyCode::Backspace => {
                tab.editor.backspace();
                changed = true;
            }
            KeyCode::Delete => {
                tab.editor.delete();
                changed = true;
            }
            KeyCode::Left => tab.editor.move_left(),
            KeyCode::Right => tab.editor.move_right(),
            KeyCode::Up => tab.editor.move_up(),
            KeyCode::Down => tab.editor.move_down(),
            KeyCode::Home => tab.editor.move_home(),
            KeyCode::End => tab.editor.move_end(),
            KeyCode::PageUp => tab.editor.page_up(rows.max(1)),
            KeyCode::PageDown => tab.editor.page_down(rows.max(1)),
            KeyCode::Char(ch) => {
                tab.editor.insert_char(ch);
                changed = true;
            }
            _ => handled = false,
        }

        if !handled {
            return;
        }
        if changed {
            tab.dirty = true;
            tab.refresh_parse();
        }
        tab.editor.ensure_visible(rows, cols);
    }

    fn handle_search_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc | KeyCode::Enter => {
                self.search.active = false;
                return;
            }
            KeyCode::Tab => {
                self.search.active = false;
                self.cycle_focus(false);
                return;
            }
            KeyCode::BackTab => {
                self.search.active = false;
                self.cycle_focus(true);
                return;
            }
            KeyCode::Up => {
                self.move_selection(-1);
                return;
            }
            KeyCode::Down => {
                self.move_selection(1);
                return;
            }
            KeyCode::Backspace => {
                self.history_filter.query.pop();
                self.ensure_selections();
                return;
            }
            KeyCode::Char('u') | KeyCode::Char('U')
                if key.modifiers.contains(KeyModifiers::CONTROL) =>
            {
                self.history_filter.query.clear();
                self.ensure_selections();
                return;
            }
            _ => {}
        }

        if let KeyCode::Char(ch) = key.code
            && !key.modifiers.contains(KeyModifiers::CONTROL)
            && !key.modifiers.contains(KeyModifiers::ALT)
            && !ch.is_control()
        {
            self.history_filter.query.push(ch);
            self.ensure_selections();
        }
    }

    fn handle_palette_key(&mut self, key: KeyEvent) {
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('k') | KeyCode::Char('K'))
        {
            self.close_palette();
            return;
        }
        match key.code {
            KeyCode::Esc => self.close_palette(),
            KeyCode::Enter => self.execute_palette_selection(),
            KeyCode::Up => self.palette_move(-1),
            KeyCode::Down => self.palette_move(1),
            KeyCode::PageUp => self.palette_move(-8),
            KeyCode::PageDown => self.palette_move(8),
            KeyCode::Home => self.palette_select(0),
            KeyCode::End => {
                let len = self.palette_results().len();
                if len > 0 {
                    self.palette_select(len - 1);
                }
            }
            KeyCode::Backspace => {
                if let Some(palette) = &mut self.palette {
                    let mut query = palette.query.clone();
                    query.pop();
                    palette.set_query(query);
                }
            }
            KeyCode::Char(ch)
                if !key.modifiers.contains(KeyModifiers::CONTROL)
                    && !key.modifiers.contains(KeyModifiers::ALT)
                    && !ch.is_control() =>
            {
                if let Some(palette) = &mut self.palette {
                    let mut query = palette.query.clone();
                    query.push(ch);
                    palette.set_query(query);
                }
            }
            _ => {}
        }
    }

    fn palette_move(&mut self, delta: i32) {
        let len = self.palette_results().len();
        if len == 0 {
            return;
        }
        if let Some(palette) = &mut self.palette {
            let next = (palette.selected as i32 + delta).clamp(0, len as i32 - 1);
            palette.selected = next as usize;
        }
    }

    fn palette_select(&mut self, selected: usize) {
        if let Some(palette) = &mut self.palette {
            palette.selected = selected;
        }
    }

    fn execute_palette_selection(&mut self) {
        let results = self.palette_results();
        let selected = self.palette.as_ref().map_or(0, |palette| palette.selected);
        if let Some(command) = results.get(selected) {
            let id = command.id;
            self.execute_command(id);
        } else {
            self.close_palette();
        }
    }

    fn handle_menu_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => self.context_menu = None,
            KeyCode::Up | KeyCode::Char('k') => self.menu_move(-1),
            KeyCode::Down | KeyCode::Char('j') => self.menu_move(1),
            KeyCode::Home => self.menu_select(0),
            KeyCode::End => {
                if let Some(menu) = &self.context_menu {
                    let last = menu.items.len().saturating_sub(1);
                    self.menu_select(last);
                }
            }
            KeyCode::Enter => {
                let action = self.context_menu.as_ref().and_then(|menu| {
                    menu.items
                        .get(menu.selected)
                        .map(|item| item.action.clone())
                });
                if let Some(action) = action {
                    self.execute_menu_action(action);
                }
            }
            _ => {}
        }
    }

    fn menu_move(&mut self, delta: i32) {
        if let Some(menu) = &mut self.context_menu {
            if menu.items.is_empty() {
                return;
            }
            let next = (menu.selected as i32 + delta).clamp(0, menu.items.len() as i32 - 1);
            menu.selected = next as usize;
        }
    }

    fn menu_select(&mut self, selected: usize) {
        if let Some(menu) = &mut self.context_menu {
            menu.selected = selected.min(menu.items.len().saturating_sub(1));
        }
    }

    fn handle_confirm_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter | KeyCode::Char('y') | KeyCode::Char('Y') => self.confirm_yes(),
            KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => self.confirm_no(),
            _ => {}
        }
    }

    fn handle_setting_edit_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.settings.edit = None;
                self.notify_info("Edit cancelled.");
            }
            KeyCode::Enter => self.commit_setting_edit(),
            KeyCode::Tab => {
                self.commit_setting_edit();
                if self.settings.edit.is_none() {
                    self.cycle_focus(false);
                }
            }
            KeyCode::BackTab => {
                self.commit_setting_edit();
                if self.settings.edit.is_none() {
                    self.cycle_focus(true);
                }
            }
            KeyCode::Backspace => {
                if let Some(edit) = &mut self.settings.edit {
                    edit.buffer.pop();
                }
            }
            KeyCode::Char(ch)
                if !key.modifiers.contains(KeyModifiers::CONTROL)
                    && !key.modifiers.contains(KeyModifiers::ALT)
                    && !ch.is_control() =>
            {
                if let Some(edit) = &mut self.settings.edit {
                    edit.buffer.push(ch);
                }
            }
            _ => {}
        }
    }

    fn handle_left_click(&mut self, mouse: MouseEvent) {
        let position = Position::new(mouse.column, mouse.row);
        let Some(target) = self.render.hit_at(mouse.column, mouse.row).cloned() else {
            return;
        };

        let now = Instant::now();
        let double = self
            .last_click
            .as_ref()
            .is_some_and(|(at, at_position, at_target)| {
                now.duration_since(*at).as_millis() <= DOUBLE_CLICK_WINDOW_MS
                    && *at_position == position
                    && *at_target == target
            });

        match target.clone() {
            HitTarget::Splitter(drag) => {
                self.drag = Some(drag);
                return;
            }
            HitTarget::Nav(section) => self.navigate(section),
            HitTarget::ProxyRow(id) => {
                self.proxy_selected = Some(id);
                self.focus = Focus::Content;
                if double {
                    self.inspect_selected();
                }
            }
            HitTarget::HistoryRow(id) => {
                self.history_selected = Some(id);
                self.focus = Focus::Content;
                if double {
                    self.inspect_selected();
                }
            }
            HitTarget::WebSocketConnection(id) => {
                self.websocket.select_connection(id);
                self.focus = Focus::Content;
            }
            HitTarget::WebSocketFrame(id) => {
                self.websocket.select_frame(id);
                self.focus = Focus::Content;
            }
            HitTarget::Action(action) => self.dispatch_action(action),
            HitTarget::InspectorSide(side) => {
                if self.nav != NavSection::Repeater {
                    self.inspector.side = side;
                    self.inspector.scroll = 0;
                    self.focus = Focus::Context;
                }
            }
            HitTarget::InspectorView(view) => {
                if self.nav != NavSection::Repeater {
                    self.inspector.view = view;
                    self.inspector.scroll = 0;
                    self.focus = Focus::Context;
                }
            }
            HitTarget::RepeaterView(view) => {
                self.repeater.view(view);
                self.focus = if self.current_layout().context.is_some() {
                    Focus::Context
                } else {
                    Focus::Content
                };
            }
            HitTarget::InspectorClose => {
                self.layout.context_open = false;
                self.focus = Focus::Content;
            }
            HitTarget::RepeaterTab(index) => {
                self.repeater.select(index);
                self.focus = Focus::Content;
            }
            HitTarget::RepeaterEditor => {
                self.focus = Focus::Content;
                self.set_editor_cursor_from_mouse(mouse.column, mouse.row);
            }
            HitTarget::DecoderEditor => {
                self.focus = Focus::Content;
                self.decoder.focus = DecoderFocus::Input;
                self.decoder.editing = true;
                self.set_decoder_editor_cursor_from_mouse(mouse.column, mouse.row);
            }
            HitTarget::DecoderHistoryRow(index) => {
                self.decoder.history_scroll = index as u16;
            }
            HitTarget::InterceptionEditor => {
                self.focus = Focus::Content;
                self.interception.editing = true;
                self.set_interception_editor_cursor_from_mouse(mouse.column, mouse.row);
            }
            HitTarget::InterceptionRow(id) => {
                self.select_interception(id);
                self.focus = Focus::Content;
            }
            HitTarget::Setting(id) => {
                if let Some(index) = SettingId::ALL.iter().position(|candidate| *candidate == id) {
                    self.settings.selected = index;
                }
                self.focus = Focus::Content;
                self.activate_setting();
            }
            HitTarget::IntruderCandidate(index) => {
                self.intruder.selection = index;
                self.intruder.focus = crate::intruder::IntruderFocus::Request;
                self.focus = Focus::Content;
                if double {
                    self.intruder_mark_selected();
                }
            }
            HitTarget::IntruderPositionRow(index) => {
                self.intruder.position_selection = index;
                self.intruder.focus = crate::intruder::IntruderFocus::Positions;
                self.focus = Focus::Content;
            }
            HitTarget::IntruderResultRow(index) => {
                self.intruder.result_selection = index;
                self.intruder.focus = crate::intruder::IntruderFocus::Results;
                self.focus = Focus::Content;
            }
            HitTarget::IntruderEditor => {
                self.focus = Focus::Content;
                self.intruder.focus = crate::intruder::IntruderFocus::Request;
            }
            HitTarget::SearchField => self.start_search(),
            HitTarget::SessionRow(index) => {
                self.sessions_selected = index;
                if double {
                    self.restore_selected_session();
                }
            }
            HitTarget::ScopeRuleRow(index) => {
                if let Some(editor) = &mut self.scope_editor {
                    editor.selected = index;
                }
            }
            HitTarget::PaletteRow(_)
            | HitTarget::MenuItem(_)
            | HitTarget::DismissOverlay
            | HitTarget::OverlaySurface
            | HitTarget::Confirm(_) => {}
        }

        self.last_click = if double {
            None
        } else {
            Some((now, position, target))
        };
    }

    fn handle_right_click(&mut self, mouse: MouseEvent) {
        let Some(target) = self.render.hit_at(mouse.column, mouse.row).cloned() else {
            return;
        };
        match &target {
            HitTarget::ProxyRow(id) => {
                self.proxy_selected = Some(*id);
                self.focus = Focus::Content;
            }
            HitTarget::HistoryRow(id) => {
                self.history_selected = Some(*id);
                self.focus = Focus::Content;
            }
            HitTarget::RepeaterTab(index) => {
                self.repeater.select(*index);
                self.focus = Focus::Content;
            }
            HitTarget::Setting(id) => {
                if let Some(index) = SettingId::ALL
                    .iter()
                    .position(|candidate| *candidate == *id)
                {
                    self.settings.selected = index;
                }
            }
            HitTarget::RepeaterEditor => {
                self.focus = Focus::Content;
                self.set_editor_cursor_from_mouse(mouse.column, mouse.row);
            }
            HitTarget::DecoderEditor => {
                self.focus = Focus::Content;
                self.decoder.focus = DecoderFocus::Input;
                self.decoder.editing = true;
                self.set_decoder_editor_cursor_from_mouse(mouse.column, mouse.row);
            }
            HitTarget::InterceptionEditor => {
                self.focus = Focus::Content;
                self.interception.editing = true;
                self.set_interception_editor_cursor_from_mouse(mouse.column, mouse.row);
            }
            HitTarget::InterceptionRow(id) => {
                self.select_interception(*id);
                self.focus = Focus::Content;
            }
            _ => {}
        }
        self.open_context_menu(mouse.column, mouse.row, target);
    }

    fn handle_overlay_mouse(&mut self, mouse: MouseEvent) {
        if matches!(mouse.kind, MouseEventKind::Moved) {
            self.hover = self.render.hit_at(mouse.column, mouse.row).cloned();
            return;
        }

        if self.palette.is_some() {
            match mouse.kind {
                MouseEventKind::Down(MouseButton::Left) => {
                    match self.render.hit_at(mouse.column, mouse.row).cloned() {
                        Some(HitTarget::PaletteRow(index)) => {
                            self.palette_select(index);
                            self.execute_palette_selection();
                        }
                        Some(HitTarget::DismissOverlay) => self.close_palette(),
                        _ => {}
                    }
                }
                MouseEventKind::ScrollUp => self.palette_move(-1),
                MouseEventKind::ScrollDown => self.palette_move(1),
                _ => {}
            }
            return;
        }

        if self.context_menu.is_some() {
            match mouse.kind {
                MouseEventKind::Down(MouseButton::Left) => {
                    match self.render.hit_at(mouse.column, mouse.row).cloned() {
                        Some(HitTarget::MenuItem(index)) => {
                            self.menu_select(index);
                            let action = self.context_menu.as_ref().and_then(|menu| {
                                menu.items.get(index).map(|item| item.action.clone())
                            });
                            if let Some(action) = action {
                                self.execute_menu_action(action);
                            }
                        }
                        Some(HitTarget::DismissOverlay) => self.context_menu = None,
                        _ => {}
                    }
                }
                MouseEventKind::ScrollUp => self.menu_move(-1),
                MouseEventKind::ScrollDown => self.menu_move(1),
                _ => {}
            }
            return;
        }

        if self.confirm.is_some() {
            if matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left)) {
                match self.render.hit_at(mouse.column, mouse.row).cloned() {
                    Some(HitTarget::Confirm(true)) => self.confirm_yes(),
                    Some(HitTarget::Confirm(false)) | Some(HitTarget::DismissOverlay) => {
                        self.confirm_no()
                    }
                    _ => {}
                }
            }
            return;
        }

        if self.help_open
            && matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left))
            && matches!(
                self.render.hit_at(mouse.column, mouse.row),
                Some(HitTarget::DismissOverlay)
            )
        {
            self.help_open = false;
        }
    }

    fn scroll_at(&mut self, x: u16, y: u16, up: bool) {
        let Some(region) = self.render.zone_at(x, y) else {
            return;
        };
        let delta = if up { -3 } else { 3 };
        match region {
            ScrollRegion::ProxyList | ScrollRegion::HistoryList => self.move_selection(delta),
            ScrollRegion::Inspector => self.scroll_context(delta),
            ScrollRegion::RepeaterEditor => {
                if let Some(tab) = self.repeater.active_tab_mut() {
                    tab.editor.scroll_by(delta);
                }
            }
            ScrollRegion::DecoderEditor => self.decoder.input.scroll_by(delta),
            ScrollRegion::DecoderOutput => {
                self.decoder.output_scroll = if delta.is_negative() {
                    self.decoder
                        .output_scroll
                        .saturating_sub(delta.unsigned_abs() as u16)
                } else {
                    self.decoder.output_scroll.saturating_add(delta as u16)
                }
            }
            ScrollRegion::DecoderPipeline => self.decoder.select_step(delta),
            ScrollRegion::DecoderHistory => self.decoder.select_history(delta),
            ScrollRegion::InterceptionEditor => {
                self.interception.editor.scroll_by(delta);
            }
            ScrollRegion::InterceptionQueue => {
                self.move_interception_selection(delta);
            }
            ScrollRegion::IntruderResults => {
                let step = delta.signum();
                self.intruder.select_result(step);
            }
            ScrollRegion::IntruderRequest | ScrollRegion::IntruderPreview => {
                self.intruder.select_candidate(delta.signum());
            }
            ScrollRegion::IntruderInspector => {}
            ScrollRegion::WebSocketConnections => self.websocket.move_connection(delta.signum()),
            ScrollRegion::WebSocketFrames => self.websocket.move_frame(delta),
            ScrollRegion::WebSocketInspector => self.websocket.scroll_inspector(delta),
            ScrollRegion::Settings => self.move_selection(delta),
            ScrollRegion::Palette => {
                if self.palette.is_some() {
                    self.palette_move(if up { -1 } else { 1 });
                }
            }
            ScrollRegion::Menu => {
                if self.context_menu.is_some() {
                    self.menu_move(if up { -1 } else { 1 });
                }
            }
        }
    }
}

fn plain_char(key: &KeyEvent) -> Option<char> {
    if key.modifiers.contains(KeyModifiers::CONTROL) || key.modifiers.contains(KeyModifiers::ALT) {
        return None;
    }
    match key.code {
        KeyCode::Char(ch) => Some(ch.to_ascii_lowercase()),
        _ => None,
    }
}

fn single_line(text: &str) -> String {
    text.chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect::<String>()
        .trim()
        .to_string()
}

impl App {
    fn handle_interception_editor_key(&mut self, key: KeyEvent) {
        let rows = self.render.repeater_rows;
        let cols = self.render.repeater_cols;

        match key.code {
            KeyCode::Esc => {
                self.interception.editing = false;
                return;
            }
            KeyCode::Tab => {
                self.interception.editing = false;
                self.cycle_focus(false);
                return;
            }
            KeyCode::BackTab => {
                self.interception.editing = false;
                self.cycle_focus(true);
                return;
            }
            KeyCode::Enter if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.interception.editing = false;
                self.forward_interception_modified();
                return;
            }
            _ => {}
        }

        if key.modifiers.contains(KeyModifiers::CONTROL)
            || key.modifiers.contains(KeyModifiers::ALT)
        {
            return;
        }

        let mut changed = false;
        let mut handled = true;
        match key.code {
            KeyCode::Enter => {
                self.interception.editor.newline();
                changed = true;
            }
            KeyCode::Backspace => {
                self.interception.editor.backspace();
                changed = true;
            }
            KeyCode::Delete => {
                self.interception.editor.delete();
                changed = true;
            }
            KeyCode::Left => self.interception.editor.move_left(),
            KeyCode::Right => self.interception.editor.move_right(),
            KeyCode::Up => self.interception.editor.move_up(),
            KeyCode::Down => self.interception.editor.move_down(),
            KeyCode::Home => self.interception.editor.move_home(),
            KeyCode::End => self.interception.editor.move_end(),
            KeyCode::PageUp => self.interception.editor.page_up(rows.max(1)),
            KeyCode::PageDown => self.interception.editor.page_down(rows.max(1)),
            KeyCode::Char(ch) => {
                self.interception.editor.insert_char(ch);
                changed = true;
            }
            _ => handled = false,
        }

        if !handled {
            return;
        }
        if changed {
            self.interception.dirty = true;
            self.interception.parse_error = None;
            self.interception.validation_error = None;
        }
        self.interception.editor.ensure_visible(rows, cols);
    }

    pub(crate) fn set_interception_editor_cursor_from_mouse(&mut self, x: u16, y: u16) {
        let Some(origin) = self.render.editor_origin else {
            return;
        };
        let gutter = self.render.editor_gutter;
        let row =
            y.saturating_sub(origin.y) as usize + usize::from(self.interception.editor.scroll());
        let col = x.saturating_sub(origin.x).saturating_sub(gutter) as usize
            + usize::from(self.interception.editor.hscroll());
        self.interception.editor.set_cursor(row, col);
        let rows = self.render.repeater_rows;
        let cols = self.render.repeater_cols;
        self.interception.editor.ensure_visible(rows, cols);
        self.interception.editing = true;
    }
}

/// Intruder workspace input. Kept in one place so the key map in the footer and
/// the handler can never drift apart.
impl App {
    pub(crate) fn handle_intruder_prompt_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.intruder.prompt = None;
                self.focus = Focus::Content;
            }
            KeyCode::Enter => self.commit_intruder_prompt(),
            KeyCode::Backspace => {
                if let Some(prompt) = &mut self.intruder.prompt {
                    prompt.buffer.pop();
                }
            }
            KeyCode::Char('u') | KeyCode::Char('U')
                if key.modifiers.contains(KeyModifiers::CONTROL) =>
            {
                if let Some(prompt) = &mut self.intruder.prompt {
                    prompt.buffer.clear();
                }
            }
            KeyCode::Char(ch)
                if !key.modifiers.contains(KeyModifiers::CONTROL)
                    && !key.modifiers.contains(KeyModifiers::ALT)
                    && !ch.is_control() =>
            {
                if let Some(prompt) = &mut self.intruder.prompt
                    && prompt.buffer.chars().count() < 512
                {
                    prompt.buffer.push(ch);
                }
            }
            _ => {}
        }
    }

    fn commit_intruder_prompt(&mut self) {
        let Some(prompt) = self.intruder.prompt.clone() else {
            return;
        };
        match prompt.kind {
            crate::intruder::PromptKind::NewListName => {
                match self.intruder.add_list(&prompt.buffer) {
                    Ok(()) => {
                        self.intruder.prompt = None;
                        self.notify_info(
                            "Payload list created. Select it and press Enter to type payloads.",
                        );
                    }
                    Err(error) => self.notify_error(error),
                }
            }
            crate::intruder::PromptKind::RenameList => {
                match self.intruder.rename_active_set(&prompt.buffer) {
                    Ok(()) => {
                        self.intruder.prompt = None;
                        self.notify_info("Payload list renamed.");
                    }
                    Err(error) => self.notify_error(error),
                }
            }
            crate::intruder::PromptKind::WordlistPath => self.import_intruder_wordlist(),
            crate::intruder::PromptKind::FilterQuery => {
                self.intruder.filter.query = prompt.buffer;
                self.intruder.result_selection = 0;
                self.intruder.prompt = None;
                self.focus = Focus::Content;
            }
        }
    }

    fn handle_intruder_editor_key(&mut self, key: KeyEvent) {
        let rows = self.render.repeater_rows.max(1);
        let cols = self.render.repeater_cols.max(1);

        match key.code {
            KeyCode::Esc => {
                self.intruder.editing = false;
                self.intruder.apply_edit();
                return;
            }
            KeyCode::Tab => {
                self.intruder.editing = false;
                self.intruder.apply_edit();
                self.cycle_focus(false);
                return;
            }
            KeyCode::BackTab => {
                self.intruder.editing = false;
                self.intruder.apply_edit();
                self.cycle_focus(true);
                return;
            }
            _ => {}
        }

        if key.modifiers.contains(KeyModifiers::CONTROL)
            || key.modifiers.contains(KeyModifiers::ALT)
        {
            return;
        }

        let mut changed = false;
        let mut handled = true;
        let buffer = match self.intruder.edit_target {
            crate::intruder::EditTarget::Head => &mut self.intruder.head,
            crate::intruder::EditTarget::Body => &mut self.intruder.body,
            crate::intruder::EditTarget::Payloads => &mut self.intruder.payload_text,
        };

        match key.code {
            KeyCode::Enter => {
                buffer.newline();
                changed = true;
            }
            KeyCode::Backspace => {
                buffer.backspace();
                changed = true;
            }
            KeyCode::Delete => {
                buffer.delete();
                changed = true;
            }
            KeyCode::Left => buffer.move_left(),
            KeyCode::Right => buffer.move_right(),
            KeyCode::Up => buffer.move_up(),
            KeyCode::Down => buffer.move_down(),
            KeyCode::Home => buffer.move_home(),
            KeyCode::End => buffer.move_end(),
            KeyCode::PageUp => buffer.page_up(rows),
            KeyCode::PageDown => buffer.page_down(rows),
            KeyCode::Char(ch) => {
                buffer.insert_char(ch);
                changed = true;
            }
            _ => handled = false,
        }

        if !handled {
            return;
        }
        if changed {
            self.intruder.apply_edit();
        }
        let buffer = match self.intruder.edit_target {
            crate::intruder::EditTarget::Head => &mut self.intruder.head,
            crate::intruder::EditTarget::Body => &mut self.intruder.body,
            crate::intruder::EditTarget::Payloads => &mut self.intruder.payload_text,
        };
        buffer.ensure_visible(rows, cols);
    }

    fn handle_intruder_key(&mut self, key: KeyEvent) {
        use crate::intruder::{EditTarget, IntruderFocus, IntruderView};

        if plain_char(&key) == Some('?') {
            self.help_open = true;
            return;
        }

        if key.modifiers.contains(KeyModifiers::CONTROL) {
            if matches!(key.code, KeyCode::Enter) {
                self.request_intruder_start();
            }
            return;
        }

        match key.code {
            KeyCode::Esc => {
                self.focus = Focus::Content;
                return;
            }
            KeyCode::Tab => {
                self.cycle_focus(false);
                return;
            }
            KeyCode::BackTab => {
                self.cycle_focus(true);
                return;
            }
            _ => {}
        }

        let setup = self.intruder.view == IntruderView::Setup;
        let active = self.intruder.is_active();

        match key.code {
            KeyCode::Up => self.intruder_move(-1),
            KeyCode::Down => self.intruder_move(1),
            KeyCode::PageUp => self.intruder_move(-8),
            KeyCode::PageDown => self.intruder_move(8),
            KeyCode::Home => self.intruder_move(i32::MIN / 2),
            KeyCode::End => self.intruder_move(i32::MAX / 2),
            KeyCode::Left => {
                if setup {
                    self.intruder.cycle_position_set(-1);
                }
            }
            KeyCode::Right => {
                if setup {
                    self.intruder.cycle_position_set(1);
                }
            }
            KeyCode::Enter => {
                if setup {
                    self.intruder_edit_request();
                } else {
                    self.intruder.inspector_view = self.intruder.inspector_view.next();
                }
            }
            KeyCode::Char(ch) => match ch {
                'j' => self.intruder_move(1),
                'k' => self.intruder_move(-1),
                'g' => self.intruder_toggle_view(),
                'M' => self.intruder_mark_selected(),
                ' ' => self.intruder.toggle_position_enabled(),
                // Setup cycles the strategy; Results cycles the sort order, as
                // the on-screen "Sort S" control advertises. Changing the
                // strategy while reviewing results would silently mutate the
                // next run.
                'S' => {
                    if setup {
                        self.intruder.strategy_next();
                    } else {
                        self.intruder.cycle_sort();
                    }
                }
                'C' => self.intruder.cycle_concurrency(),
                'D' => self.intruder.cycle_duration(),
                '+' | '=' => self.intruder.cycle_rate(),
                '-' => self.intruder.cycle_rate(),
                'R' => {
                    self.intruder.toggle_redirects();
                    self.notify_info(format!(
                        "Redirects {}: every hop is validated on its own.",
                        if self.intruder.follow_redirects {
                            "ON"
                        } else {
                            "OFF"
                        }
                    ));
                }
                'A' => self.add_intruder_list(),
                'L' if setup => self.rename_intruder_list(),
                'X' => {
                    if active {
                        self.cancel_intruder_run();
                    } else if setup {
                        self.delete_intruder_list();
                    } else {
                        self.cancel_intruder_run();
                    }
                }
                'W' => {
                    self.intruder.prompt = Some(crate::intruder::IntruderPrompt::new(
                        crate::intruder::PromptKind::WordlistPath,
                        String::new(),
                    ));
                }
                'N' => self.intruder.next_set(),
                'B' => {
                    if setup {
                        self.intruder.previous_set();
                    } else {
                        self.intruder.set_baseline();
                    }
                }
                'E' => self.intruder_edit_request(),
                '2' => {
                    if setup {
                        if self.intruder.body_editable {
                            self.intruder.editing = true;
                            self.intruder.edit_target = EditTarget::Body;
                            self.intruder.focus = IntruderFocus::Request;
                        } else {
                            self.notify_warning(
                                "This body is binary; markers are placed from the component list instead of editing it as text.",
                            );
                        }
                    }
                }
                'P' => self.toggle_intruder_pause(),
                'V' => {
                    if !setup {
                        self.intruder.cycle_view();
                    }
                }
                'F' => {
                    if !setup {
                        self.intruder.cycle_status_filter();
                    }
                }
                'O' => {
                    if !setup {
                        self.intruder.cycle_outcome_filter();
                    }
                }
                'U' => {
                    if !setup {
                        self.intruder.clear_filters();
                    }
                }
                '/' => {
                    if !setup {
                        self.intruder.prompt = Some(crate::intruder::IntruderPrompt::new(
                            crate::intruder::PromptKind::FilterQuery,
                            self.intruder.filter.query.clone(),
                        ));
                    }
                }
                'T' => {
                    if !setup {
                        self.send_intruder_result_to_repeater();
                    }
                }
                'Y' => {
                    if !setup {
                        self.send_intruder_result_to_decoder();
                    }
                }
                'Z' if setup => {
                    self.intruder.clear_positions();
                    self.notify_info("All payload positions cleared.");
                }
                _ => {}
            },
            _ => {}
        }
    }

    fn intruder_move(&mut self, delta: i32) {
        use crate::intruder::IntruderFocus;

        match self.intruder.focus {
            IntruderFocus::Positions => {
                let len = self.intruder.position_rows().len() as i32;
                if len > 0 {
                    self.intruder.position_selection =
                        (self.intruder.position_selection as i32 + delta).clamp(0, len - 1)
                            as usize;
                }
            }
            IntruderFocus::Payloads => {
                if delta > 0 {
                    self.intruder.next_set();
                } else {
                    self.intruder.previous_set();
                }
            }
            IntruderFocus::Strategy => {
                if delta > 0 {
                    self.intruder.strategy_next();
                } else {
                    self.intruder.strategy_previous();
                }
            }
            IntruderFocus::Results => {
                let step = if delta.abs() > 1 {
                    delta.signum()
                } else {
                    delta
                };
                self.intruder.select_result(step);
            }
            _ => {
                if delta.abs() >= 8 {
                    let step = if delta > 0 { 8 } else { -8 };
                    self.intruder.select_candidate(step);
                } else {
                    self.intruder.select_candidate(delta);
                }
            }
        }
    }
}
