//! A small, dependency-free multi-line editor buffer.
//!
//! The Repeater edits request documents as text. Cursor movement, insertion,
//! deletion, and scrolling are implemented here so behaviour can be tested
//! without a terminal. Pasted content is sanitized before it enters the buffer,
//! preventing captured escape sequences from reaching the screen.

use rawframe_core::security::sanitize_for_display;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextBuffer {
    lines: Vec<String>,
    row: usize,
    col: usize,
    scroll: u16,
    hscroll: u16,
}

impl TextBuffer {
    pub fn from_text(text: &str) -> Self {
        let normalized = text.replace("\r\n", "\n").replace('\r', "");
        let lines: Vec<String> = normalized.split('\n').map(ToOwned::to_owned).collect();
        Self {
            lines: if lines.is_empty() {
                vec![String::new()]
            } else {
                lines
            },
            row: 0,
            col: 0,
            scroll: 0,
            hscroll: 0,
        }
    }

    pub fn text(&self) -> String {
        self.lines.join("\n")
    }

    pub fn lines(&self) -> &[String] {
        &self.lines
    }

    pub fn line_count(&self) -> usize {
        self.lines.len()
    }

    pub fn line(&self, index: usize) -> Option<&str> {
        self.lines.get(index).map(String::as_str)
    }

    pub fn row(&self) -> usize {
        self.row
    }

    pub fn col(&self) -> usize {
        self.col
    }

    pub fn scroll(&self) -> u16 {
        self.scroll
    }

    pub fn hscroll(&self) -> u16 {
        self.hscroll
    }

    pub fn is_empty(&self) -> bool {
        self.lines.len() == 1 && self.lines[0].is_empty()
    }

    pub fn cursor_line_len(&self) -> usize {
        self.lines[self.row].chars().count()
    }

    pub fn set_cursor(&mut self, row: usize, col: usize) {
        self.row = row.min(self.lines.len() - 1);
        self.col = col.min(self.cursor_line_len());
    }

    pub fn insert_char(&mut self, ch: char) {
        if ch == '\n' {
            self.newline();
            return;
        }
        if ch.is_control() {
            return;
        }
        let index = self.byte_index(self.row, self.col);
        self.lines[self.row].insert(index, ch);
        self.col += 1;
    }

    /// Inserts text, splitting lines. Control characters are escaped rather than
    /// inserted so terminal state cannot be altered from pasted content.
    pub fn insert_str(&mut self, text: &str) {
        let sanitized = sanitize_for_display(text);
        for (segment_index, segment) in sanitized.split('\n').enumerate() {
            if segment_index > 0 {
                self.newline();
            }
            for ch in segment.chars() {
                if !ch.is_control() {
                    self.insert_char(ch);
                }
            }
        }
    }

    pub fn newline(&mut self) {
        let index = self.byte_index(self.row, self.col);
        let rest = self.lines[self.row].split_off(index);
        self.lines.insert(self.row + 1, rest);
        self.row += 1;
        self.col = 0;
    }

    pub fn backspace(&mut self) {
        if self.col > 0 {
            let index = self.byte_index(self.row, self.col - 1);
            self.lines[self.row].remove(index);
            self.col -= 1;
        } else if self.row > 0 {
            let current = self.lines.remove(self.row);
            self.row -= 1;
            self.col = self.lines[self.row].chars().count();
            self.lines[self.row].push_str(&current);
        }
    }

    pub fn delete(&mut self) {
        let line_len = self.cursor_line_len();
        if self.col < line_len {
            let index = self.byte_index(self.row, self.col);
            self.lines[self.row].remove(index);
        } else if self.row + 1 < self.lines.len() {
            let next = self.lines.remove(self.row + 1);
            self.lines[self.row].push_str(&next);
        }
    }

    pub fn move_left(&mut self) {
        if self.col > 0 {
            self.col -= 1;
        } else if self.row > 0 {
            self.row -= 1;
            self.col = self.cursor_line_len();
        }
    }

    pub fn move_right(&mut self) {
        if self.col < self.cursor_line_len() {
            self.col += 1;
        } else if self.row + 1 < self.lines.len() {
            self.row += 1;
            self.col = 0;
        }
    }

    pub fn move_up(&mut self) {
        if self.row > 0 {
            self.row -= 1;
            self.col = self.col.min(self.cursor_line_len());
        }
    }

    pub fn move_down(&mut self) {
        if self.row + 1 < self.lines.len() {
            self.row += 1;
            self.col = self.col.min(self.cursor_line_len());
        }
    }

    pub fn move_home(&mut self) {
        self.col = 0;
    }

    pub fn move_end(&mut self) {
        self.col = self.cursor_line_len();
    }

    pub fn page_up(&mut self, rows: u16) {
        let rows = usize::from(rows.max(1));
        self.row = self.row.saturating_sub(rows);
        self.col = self.col.min(self.cursor_line_len());
    }

    pub fn page_down(&mut self, rows: u16) {
        let rows = usize::from(rows.max(1));
        self.row = (self.row + rows).min(self.lines.len() - 1);
        self.col = self.col.min(self.cursor_line_len());
    }

    pub fn scroll_by(&mut self, delta: i32) {
        let max = self.lines.len().saturating_sub(1);
        let next = if delta.is_negative() {
            self.scroll.saturating_sub(delta.unsigned_abs() as u16)
        } else {
            self.scroll.saturating_add(delta as u16)
        };
        self.scroll = next.min(max as u16);
    }

    /// Keeps the cursor inside the viewport reported by the last render. The
    /// caller supplies content dimensions (line-number gutter excluded).
    pub fn ensure_visible(&mut self, rows: u16, cols: u16) {
        let rows = usize::from(rows.max(1));
        let cols = usize::from(cols.max(1));

        if self.row < usize::from(self.scroll) {
            self.scroll = self.row as u16;
        } else if self.row >= usize::from(self.scroll) + rows {
            self.scroll = (self.row + 1 - rows) as u16;
        }
        let max_scroll = self.lines.len().saturating_sub(rows);
        self.scroll = self.scroll.min(max_scroll as u16);

        if self.col < usize::from(self.hscroll) {
            self.hscroll = self.col as u16;
        } else if self.col >= usize::from(self.hscroll) + cols {
            self.hscroll = (self.col + 1 - cols) as u16;
        }
    }

    fn byte_index(&self, row: usize, col: usize) -> usize {
        self.lines[row]
            .char_indices()
            .nth(col)
            .map_or(self.lines[row].len(), |(index, _)| index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inserts_newlines_and_characters_at_the_cursor() {
        let mut buffer = TextBuffer::from_text("GET / HTTP/1.1");
        buffer.move_end();
        buffer.newline();
        buffer.insert_str("Host: api.rawframe.test");

        assert_eq!(buffer.text(), "GET / HTTP/1.1\nHost: api.rawframe.test");
        assert_eq!((buffer.row(), buffer.col()), (1, 23));
    }

    #[test]
    fn backspace_joins_lines_and_delete_merges_next() {
        let mut buffer = TextBuffer::from_text("one\ntwo\nthree");
        buffer.move_down();
        buffer.move_home();
        buffer.backspace();
        assert_eq!(buffer.text(), "onetwo\nthree");
        assert_eq!((buffer.row(), buffer.col()), (0, 3));

        buffer.move_end();
        buffer.delete();
        assert_eq!(buffer.text(), "onetwothree");
    }

    #[test]
    fn cursor_moves_across_line_boundaries() {
        let mut buffer = TextBuffer::from_text("ab\ncd");
        buffer.move_home();
        buffer.move_left();
        assert_eq!((buffer.row(), buffer.col()), (0, 0));

        buffer.move_end();
        buffer.move_right();
        assert_eq!((buffer.row(), buffer.col()), (1, 0));

        buffer.move_left();
        assert_eq!((buffer.row(), buffer.col()), (0, 2));
    }

    #[test]
    fn utf8_editing_respects_character_boundaries() {
        let mut buffer = TextBuffer::from_text("héllo");
        buffer.move_end();
        buffer.backspace();
        assert_eq!(buffer.text(), "héll");
        buffer.insert_char('ø');
        assert_eq!(buffer.text(), "héllø");

        buffer.move_home();
        buffer.move_right();
        buffer.move_right();
        buffer.insert_char('x');
        assert_eq!(buffer.text(), "héxllø");
    }

    #[test]
    fn pasted_escape_sequences_are_neutralized() {
        let mut buffer = TextBuffer::from_text("");
        buffer.insert_str("safe\u{1b}[31mred\u{1b}[0m");
        assert!(!buffer.text().contains('\u{1b}'));
        assert!(buffer.text().contains("^[[31m"));
    }

    #[test]
    fn vertical_and_horizontal_scrolling_follow_the_cursor() {
        let mut buffer = TextBuffer::from_text("0\n1\n2\n3\n4\n5\n6\n7\n8\n9");
        buffer.ensure_visible(4, 40);
        for _ in 0..7 {
            buffer.move_down();
        }
        buffer.ensure_visible(4, 40);
        assert_eq!(buffer.scroll(), 4);

        let mut long = TextBuffer::from_text(&"x".repeat(100));
        long.move_end();
        long.ensure_visible(10, 20);
        assert!(long.hscroll() > 0);
        long.move_home();
        long.ensure_visible(10, 20);
        assert_eq!(long.hscroll(), 0);
    }

    #[test]
    fn cursor_stays_within_bounds_when_lines_are_shorter() {
        let mut buffer = TextBuffer::from_text("long line\nx");
        buffer.move_end();
        buffer.move_down();
        assert_eq!(buffer.col(), 1);
        buffer.move_up();
        assert_eq!(buffer.col(), 1);
    }

    #[test]
    fn paging_clamps_at_document_edges() {
        let mut buffer = TextBuffer::from_text("0\n1\n2\n3");
        buffer.page_down(10);
        assert_eq!(buffer.row(), 3);
        buffer.page_up(10);
        assert_eq!(buffer.row(), 0);
    }
}
