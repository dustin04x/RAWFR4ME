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
        if self.palette.is_some() {
            self.handle_palette_key(key);
            return;
        }
        if self.context_menu.is_some() {
            self.handle_menu_key(key);
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
                } else if self.repeater.editing {
                    self.repeater.editing = false;
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

        if let Some(ch) = plain_char(&key) {
            match ch {
                '?' => {
                    self.help_open = true;
                    return;
                }
                'q' => {
                    self.request_quit();
                    return;
                }
                'i' => {
                    // On Proxy workbench, I toggles interception for live traffic.
                    if self.nav == NavSection::Proxy && self.focus == Focus::Content {
                        // fall through to proxy/content handling
                    } else {
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
                if self.nav == NavSection::Repeater {
                    self.send_repeater_request();
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
            NavSection::Intruder | NavSection::Decoder => {}
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
                _ => {}
            },
        }
    }

    fn handle_repeater_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter | KeyCode::Char('e') | KeyCode::Char('E') => {
                self.repeater.editing = true;
            }
            KeyCode::Left => self.repeater.select_previous(),
            KeyCode::Right => self.repeater.select_next(),
            KeyCode::Char('s') | KeyCode::Char('S') => self.send_repeater_request(),
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
            KeyCode::Char('1') => self.set_inspector_view(InspectorView::Raw),
            KeyCode::Char('2') => self.set_inspector_view(InspectorView::Headers),
            KeyCode::Char('3') => self.set_inspector_view(InspectorView::Body),
            _ => match plain_char(&key) {
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
            HitTarget::SearchField => self.start_search(),
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
            ScrollRegion::InterceptionEditor => {
                self.interception.editor.scroll_by(delta);
            }
            ScrollRegion::InterceptionQueue => {
                self.move_interception_selection(delta);
            }
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
