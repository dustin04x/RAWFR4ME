//! WebSocket workspace state.
//!
//! The workspace is a bounded, in-memory projection of the events the proxy
//! already emits. It never opens a socket: captured frames are shown as they
//! arrive, paused frames are resolved through the proxy command queue, and the
//! retained history is capped so a long-lived socket cannot exhaust the UI.

use rawframe_core::models::websocket::{
    WebSocketConnection, WebSocketConnectionId, WebSocketConnectionState, WebSocketDirection,
    WebSocketFrame, WebSocketFrameId, WebSocketInterceptionOutcome, WebSocketMessage,
    WebSocketOpcode,
};

use crate::text::TextBuffer;

/// Connections kept for navigation. Older connections are dropped together
/// with their frames so the list never references a pruned connection.
pub const MAX_RETAINED_CONNECTIONS: usize = 64;
/// Frames kept across all connections.
pub const MAX_RETAINED_FRAMES: usize = 4_000;
/// Reassembled messages kept for the inspector.
pub const MAX_RETAINED_MESSAGES: usize = 1_000;
/// Longest accepted filter expression.
pub const MAX_FILTER_CHARS: usize = 64;

#[derive(Debug, Default)]
pub struct WebSocketState {
    connections: Vec<WebSocketConnection>,
    frames: Vec<WebSocketFrame>,
    messages: Vec<WebSocketMessage>,
    selected_connection: Option<WebSocketConnectionId>,
    selected_frame: Option<WebSocketFrameId>,
    paused: Vec<WebSocketFrameId>,
    filter: String,
    pub searching: bool,
    inspector_scroll: u16,
    /// Payload editor for a paused text frame. Binary frames are forwarded or
    /// dropped unchanged because rewriting them as text would corrupt bytes.
    editor: Option<TextBuffer>,
    editing_frame: Option<WebSocketFrameId>,
    /// True when the editor composes a new Repeater frame instead of modifying
    /// a captured one.
    composing: bool,
    received_live: bool,
}

impl WebSocketState {
    pub fn connections(&self) -> &[WebSocketConnection] {
        &self.connections
    }

    pub fn frames(&self) -> &[WebSocketFrame] {
        &self.frames
    }

    pub fn messages(&self) -> &[WebSocketMessage] {
        &self.messages
    }

    pub fn frame_total(&self) -> usize {
        self.frames.len()
    }

    pub fn pending_count(&self) -> usize {
        self.paused.len()
    }

    pub fn received_live(&self) -> bool {
        self.received_live
    }

    pub fn filter(&self) -> &str {
        &self.filter
    }

    pub fn inspector_scroll(&self) -> u16 {
        self.inspector_scroll
    }

    pub fn selected_connection_id(&self) -> Option<WebSocketConnectionId> {
        self.selected_connection
    }

    pub fn selected_connection(&self) -> Option<&WebSocketConnection> {
        let id = self.selected_connection?;
        self.connections
            .iter()
            .find(|connection| connection.id == id)
    }

    pub fn selected_frame_id(&self) -> Option<WebSocketFrameId> {
        self.selected_frame
    }

    pub fn selected_frame(&self) -> Option<&WebSocketFrame> {
        let id = self.selected_frame?;
        self.frames.iter().find(|frame| frame.id == id)
    }

    pub fn is_paused(&self, id: WebSocketFrameId) -> bool {
        self.paused.contains(&id)
    }

    pub fn selected_frame_paused(&self) -> bool {
        self.selected_frame.is_some_and(|id| self.is_paused(id))
    }

    pub fn editor(&self) -> Option<&TextBuffer> {
        self.editor.as_ref()
    }

    pub fn editor_mut(&mut self) -> Option<&mut TextBuffer> {
        self.editor.as_mut()
    }

    pub fn editing(&self) -> bool {
        self.editor.is_some()
    }

    pub fn composing(&self) -> bool {
        self.composing
    }

    /// Opens an empty editor for a new text frame in a Repeater session.
    pub fn begin_compose(&mut self) {
        self.editor = Some(TextBuffer::from_text(""));
        self.editing_frame = None;
        self.composing = true;
    }

    pub fn compose_payload(&self) -> Option<Vec<u8>> {
        if !self.composing {
            return None;
        }
        self.editor
            .as_ref()
            .map(|editor| editor.text().into_bytes())
    }

    /// Frames for the selected connection that match the current filter.
    pub fn visible_frames(&self) -> Vec<&WebSocketFrame> {
        self.frames_for(self.selected_connection)
    }

    pub fn frames_for(&self, connection: Option<WebSocketConnectionId>) -> Vec<&WebSocketFrame> {
        let Some(connection) = connection else {
            return Vec::new();
        };
        self.frames
            .iter()
            .filter(|frame| frame.connection_id == connection && self.matches_filter(frame))
            .collect()
    }

    pub fn visible_frame_count(&self) -> usize {
        self.visible_frames().len()
    }

    /// Messages belonging to the selected connection, oldest first.
    pub fn messages_for_selected(&self) -> Vec<&WebSocketMessage> {
        let Some(connection) = self.selected_connection else {
            return Vec::new();
        };
        self.messages
            .iter()
            .filter(|message| message.connection_id == connection)
            .collect()
    }

    pub fn connection_state(&self, id: WebSocketConnectionId) -> Option<WebSocketConnectionState> {
        self.connections
            .iter()
            .find(|connection| connection.id == id)
            .map(|connection| connection.state)
    }

    pub fn upsert_connection(&mut self, connection: WebSocketConnection) {
        self.received_live = true;
        match self
            .connections
            .iter_mut()
            .find(|existing| existing.id == connection.id)
        {
            Some(existing) => *existing = connection,
            None => self.connections.push(connection),
        }
        self.sort_connections();
        self.prune();
        self.ensure_selection();
    }

    /// Records a captured frame. The relay emits the same frame again when an
    /// interception decision changes its outcome, so frames are upserted by id.
    pub fn push_frame(&mut self, frame: WebSocketFrame) {
        self.received_live = true;
        match self
            .frames
            .iter_mut()
            .find(|existing| existing.id == frame.id)
        {
            Some(existing) => *existing = frame.clone(),
            None => self.frames.push(frame.clone()),
        }
        if frame.interception != WebSocketInterceptionOutcome::Forwarded {
            self.paused.retain(|id| *id != frame.id);
        }
        if self.selected_connection.is_none() {
            self.selected_connection = Some(frame.connection_id);
        }
        if self.selected_connection == Some(frame.connection_id) && self.selected_frame.is_none() {
            self.selected_frame = Some(frame.id);
        }
        self.prune();
        self.ensure_selection();
    }

    /// Registers a frame awaiting an operator decision and focuses it, so the
    /// pause is visible without the operator hunting through the list.
    pub fn mark_paused(&mut self, frame: WebSocketFrame) {
        self.push_frame(frame.clone());
        if !self.paused.contains(&frame.id) {
            self.paused.push(frame.id);
        }
        self.selected_connection = Some(frame.connection_id);
        self.selected_frame = Some(frame.id);
        self.inspector_scroll = 0;
    }

    pub fn push_message(&mut self, message: WebSocketMessage) {
        self.received_live = true;
        match self
            .messages
            .iter_mut()
            .find(|existing| existing.id == message.id)
        {
            Some(existing) => *existing = message,
            None => self.messages.push(message),
        }
        self.prune();
    }

    pub fn select_connection(&mut self, id: WebSocketConnectionId) {
        self.selected_connection = Some(id);
        self.inspector_scroll = 0;
        let ids: Vec<WebSocketFrameId> = self.frames_for(Some(id)).iter().map(|f| f.id).collect();
        if self
            .selected_frame
            .is_none_or(|current| !ids.contains(&current))
        {
            self.selected_frame = ids.last().copied();
        }
    }

    pub fn select_frame(&mut self, id: WebSocketFrameId) {
        self.selected_frame = Some(id);
        self.inspector_scroll = 0;
        if let Some(frame) = self.frames.iter().find(|frame| frame.id == id) {
            self.selected_connection = Some(frame.connection_id);
        }
    }

    pub fn move_connection(&mut self, delta: i32) {
        let ids: Vec<WebSocketConnectionId> = self
            .connections
            .iter()
            .map(|connection| connection.id)
            .collect();
        let Some(id) = step(&ids, self.selected_connection, delta) else {
            return;
        };
        self.select_connection(id);
    }

    pub fn move_frame(&mut self, delta: i32) {
        let ids: Vec<WebSocketFrameId> = self.visible_frames().iter().map(|f| f.id).collect();
        if let Some(id) = step(&ids, self.selected_frame, delta) {
            self.select_frame(id);
        }
    }

    pub fn select_frame_edge(&mut self, last: bool) {
        let ids: Vec<WebSocketFrameId> = self.visible_frames().iter().map(|f| f.id).collect();
        self.selected_frame = if last { ids.last() } else { ids.first() }.copied();
        self.inspector_scroll = 0;
    }

    /// Jumps to the oldest unresolved pause.
    pub fn select_next_paused(&mut self) -> bool {
        let Some(frame) = self
            .paused
            .iter()
            .filter_map(|id| self.frames.iter().find(|frame| frame.id == *id))
            .min_by_key(|frame| frame.id)
            .cloned()
        else {
            return false;
        };
        self.select_frame(frame.id);
        true
    }

    pub fn scroll_inspector(&mut self, delta: i32) {
        self.inspector_scroll = if delta.is_negative() {
            self.inspector_scroll
                .saturating_sub(delta.unsigned_abs().min(u16::MAX as u32) as u16)
        } else {
            self.inspector_scroll
                .saturating_add(delta.min(u16::MAX as i32) as u16)
        };
    }

    pub fn start_search(&mut self) {
        self.searching = true;
    }

    pub fn stop_search(&mut self) {
        self.searching = false;
    }

    pub fn push_filter_char(&mut self, ch: char) {
        if self.filter.chars().count() < MAX_FILTER_CHARS {
            self.filter.push(ch);
            self.ensure_frame_selection();
        }
    }

    pub fn pop_filter_char(&mut self) {
        self.filter.pop();
        self.ensure_frame_selection();
    }

    pub fn clear_filter(&mut self) {
        self.filter.clear();
        self.searching = false;
        self.ensure_frame_selection();
    }

    /// Opens the payload editor for a paused text frame. Returns the reason the
    /// frame cannot be edited when it is binary or no longer paused.
    pub fn begin_edit(&mut self) -> Result<(), &'static str> {
        let Some(frame) = self.selected_frame().cloned() else {
            return Err("Select a captured frame first.");
        };
        if !self.is_paused(frame.id) {
            return Err("Only a paused frame can be modified.");
        }
        if frame.opcode == WebSocketOpcode::Binary {
            return Err("Binary frames can only be forwarded or dropped.");
        }
        let text = String::from_utf8(frame.payload.clone())
            .map_err(|_| "The frame payload is not valid UTF-8.")?;
        self.editor = Some(TextBuffer::from_text(&text));
        self.editing_frame = Some(frame.id);
        self.composing = false;
        Ok(())
    }

    /// Returns the edited payload of the frame currently in the editor.
    pub fn edited_payload(&self) -> Option<(WebSocketFrameId, Vec<u8>)> {
        let id = self.editing_frame?;
        let editor = self.editor.as_ref()?;
        Some((id, editor.text().into_bytes()))
    }

    pub fn cancel_edit(&mut self) {
        self.editor = None;
        self.editing_frame = None;
        self.composing = false;
    }

    pub fn clear(&mut self) {
        self.connections.clear();
        self.frames.clear();
        self.messages.clear();
        self.paused.clear();
        self.selected_connection = None;
        self.selected_frame = None;
        self.inspector_scroll = 0;
        self.cancel_edit();
    }

    fn matches_filter(&self, frame: &WebSocketFrame) -> bool {
        if self.filter.is_empty() {
            return true;
        }
        let needle = self.filter.to_ascii_lowercase();
        if frame.id.0.to_string().contains(&needle)
            || frame.opcode.label().contains(&needle)
            || direction_label(frame.direction).contains(&needle)
        {
            return true;
        }
        if frame.payload.is_empty() {
            return false;
        }
        String::from_utf8_lossy(&frame.payload)
            .to_ascii_lowercase()
            .contains(&needle)
    }

    fn sort_connections(&mut self) {
        self.connections
            .sort_by_key(|connection| connection.started_at);
    }

    fn prune(&mut self) {
        let live: Vec<WebSocketConnectionId> = self
            .connections
            .iter()
            .map(|connection| connection.id)
            .collect();
        self.frames
            .retain(|frame| live.contains(&frame.connection_id));
        self.messages
            .retain(|message| live.contains(&message.connection_id));
        if self.frames.len() > MAX_RETAINED_FRAMES {
            let excess = self.frames.len() - MAX_RETAINED_FRAMES;
            self.frames.drain(0..excess);
        }
        if self.messages.len() > MAX_RETAINED_MESSAGES {
            let excess = self.messages.len() - MAX_RETAINED_MESSAGES;
            self.messages.drain(0..excess);
        }
        if self.connections.len() > MAX_RETAINED_CONNECTIONS {
            let excess = self.connections.len() - MAX_RETAINED_CONNECTIONS;
            self.connections.drain(0..excess);
            let live: Vec<WebSocketConnectionId> = self
                .connections
                .iter()
                .map(|connection| connection.id)
                .collect();
            self.frames
                .retain(|frame| live.contains(&frame.connection_id));
            self.messages
                .retain(|message| live.contains(&message.connection_id));
        }
        let frame_ids: Vec<WebSocketFrameId> = self.frames.iter().map(|frame| frame.id).collect();
        self.paused.retain(|id| frame_ids.contains(id));
    }

    fn ensure_selection(&mut self) {
        if self.selected_connection.is_some_and(|id| {
            !self
                .connections
                .iter()
                .any(|connection| connection.id == id)
        }) {
            self.selected_connection = self.connections.last().map(|connection| connection.id);
            self.selected_frame = None;
        }
        if self.selected_connection.is_none() {
            self.selected_connection = self.connections.last().map(|connection| connection.id);
        }
        self.ensure_frame_selection();
    }

    fn ensure_frame_selection(&mut self) {
        let ids: Vec<WebSocketFrameId> = self
            .frames_for(self.selected_connection)
            .iter()
            .map(|frame| frame.id)
            .collect();
        if self
            .selected_frame
            .is_none_or(|current| !ids.contains(&current))
        {
            self.selected_frame = ids.last().copied();
        }
    }
}

fn step<T: Copy + PartialEq>(ids: &[T], current: Option<T>, delta: i32) -> Option<T> {
    if ids.is_empty() {
        return None;
    }
    let Some(index) = current.and_then(|current| ids.iter().position(|id| *id == current)) else {
        return if delta >= 0 { ids.first() } else { ids.last() }.copied();
    };
    let next = (index as i64 + i64::from(delta)).clamp(0, ids.len() as i64 - 1) as usize;
    ids.get(next).copied()
}

pub fn direction_label(direction: WebSocketDirection) -> &'static str {
    match direction {
        WebSocketDirection::ClientToServer => "client_to_server",
        WebSocketDirection::ServerToClient => "server_to_client",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn connection(id: u64) -> WebSocketConnection {
        WebSocketConnection {
            id: WebSocketConnectionId(id),
            source: rawframe_core::models::traffic::TrafficSource::Intercepted,
            host: format!("ws{id}.rawframe.test"),
            port: 443,
            path: "/stream".into(),
            tls: true,
            subprotocol: None,
            extensions: None,
            state: WebSocketConnectionState::Open,
            started_at: Utc::now(),
            closed_at: None,
            frames: 0,
            messages: 0,
            bytes_client_to_server: 0,
            bytes_server_to_client: 0,
            error: None,
        }
    }

    fn frame(id: u64, connection: u64, payload: &[u8]) -> WebSocketFrame {
        WebSocketFrame::new(
            WebSocketFrameId(id),
            WebSocketConnectionId(connection),
            WebSocketDirection::ClientToServer,
            WebSocketOpcode::Text,
            true,
            true,
            payload.to_vec(),
            false,
        )
    }

    #[test]
    fn paused_frames_are_focused_and_resolved_by_outcome() {
        let mut state = WebSocketState::default();
        state.upsert_connection(connection(1));
        state.push_frame(frame(10, 1, b"hello"));
        state.mark_paused(frame(11, 1, b"review me"));

        assert_eq!(state.pending_count(), 1);
        assert_eq!(state.selected_frame_id(), Some(WebSocketFrameId(11)));
        assert!(state.selected_frame_paused());

        let mut resolved = frame(11, 1, b"review me");
        resolved.interception = WebSocketInterceptionOutcome::Dropped;
        state.push_frame(resolved);

        assert_eq!(state.pending_count(), 0);
        assert_eq!(
            state.frame_total(),
            2,
            "the outcome replaces, not duplicates"
        );
        assert!(!state.selected_frame_paused());
    }

    #[test]
    fn filtering_narrows_frames_and_selection() {
        let mut state = WebSocketState::default();
        state.upsert_connection(connection(1));
        state.push_frame(frame(1, 1, b"alpha"));
        state.push_frame(frame(2, 1, b"beta"));
        state.select_frame(WebSocketFrameId(2));

        state.start_search();
        for ch in "alpha".chars() {
            state.push_filter_char(ch);
        }
        assert_eq!(state.visible_frame_count(), 1);
        assert_eq!(state.selected_frame_id(), Some(WebSocketFrameId(1)));

        state.clear_filter();
        assert_eq!(state.visible_frame_count(), 2);
        assert!(!state.searching);
    }

    #[test]
    fn retention_caps_history_and_drops_stale_connections() {
        let mut state = WebSocketState::default();
        state.upsert_connection(connection(1));
        for id in 0..(MAX_RETAINED_FRAMES as u64 + 25) {
            state.push_frame(frame(id, 1, b"x"));
        }
        assert_eq!(state.frame_total(), MAX_RETAINED_FRAMES);

        for id in 2..(MAX_RETAINED_CONNECTIONS as u64 + 5) {
            state.upsert_connection(connection(id));
        }
        assert_eq!(state.connections().len(), MAX_RETAINED_CONNECTIONS);
        assert!(
            state.frames().iter().all(|frame| frame.connection_id.0 > 1),
            "frames belonging to pruned connections are dropped"
        );
    }

    #[test]
    fn binary_frames_cannot_be_modified_as_text() {
        let mut state = WebSocketState::default();
        state.upsert_connection(connection(1));
        let mut binary = frame(1, 1, &[0xff, 0x00]);
        binary.opcode = WebSocketOpcode::Binary;
        state.mark_paused(binary);

        assert!(state.begin_edit().is_err());

        state.mark_paused(frame(2, 1, b"text"));
        assert!(state.begin_edit().is_ok());
        state.cancel_edit();
    }
}
