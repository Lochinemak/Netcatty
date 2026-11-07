//! Terminal log sanitizer (port of `electron/bridges/terminalLogSanitizer.cjs`).
//!
//! This is intentionally stateful: terminal output is a stream of cursor and
//! erase operations, not plain text with decoration. The renderer keeps a
//! small virtual text buffer so plain-text and HTML logs reflect what common
//! line-editing output actually leaves on screen.
//!
//! Full-screen TUIs (vim/less/htop) use the alternate screen buffer
//! (DECSET 47/1047/1049). While that mode is active, paint is omitted so
//! session logs keep shell history instead of tilde rows and status lines.
//!
//! The behaviour (including its quirks) mirrors the Electron renderer so both
//! backends write byte-identical txt / html logs. Deliberate differences, all
//! for inputs that would hang or crash the JavaScript version:
//! * numeric CSI parameters are clamped to ±[`MAX_CSI_PARAM`], so a hostile
//!   `ESC [ 999999999 B` cannot allocate millions of rows;
//! * the cursor never moves to a negative row / column.

/// Largest magnitude a CSI parameter is clamped to.
pub const MAX_CSI_PARAM: i64 = 65_535;

const DEFAULT_FOREGROUND: &str = "#d4d4d4";
const DEFAULT_BACKGROUND: &str = "#1e1e1e";
// ANSI palette colors are emitted as CSS variables (with hex fallbacks) so the
// wrapping HTML page can provide light and dark palettes. Indexes 0-7 are the
// basic colors, 8-15 the bright colors.
const BASIC_COLORS: [&str; 8] = [
    "#000000", "#cd3131", "#0dbc79", "#e5e510", "#2472c8", "#bc3fbc", "#11a8cd", "#e5e5e5",
];
const BRIGHT_COLORS: [&str; 8] = [
    "#666666", "#f14c4c", "#23d18b", "#f5f543", "#3b8eea", "#d670d6", "#29b8db", "#ffffff",
];

/// A cell colour: one of the 16 themeable ANSI colours or a fixed RGB value
/// (256-colour cube / grey ramp and true colour).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Color {
    Ansi(u8),
    Rgb(u8, u8, u8),
}

impl Color {
    fn ansi_fallback(index: u8) -> &'static str {
        if index < 8 {
            BASIC_COLORS[index as usize]
        } else {
            BRIGHT_COLORS[(index - 8) as usize]
        }
    }

    /// CSS value: `var(--ansi-N, #fallback)` or `#rrggbb`.
    fn css(self) -> String {
        match self {
            Color::Ansi(i) => format!("var(--ansi-{i}, {})", Self::ansi_fallback(i)),
            Color::Rgb(r, g, b) => format!("#{r:02x}{g:02x}{b:02x}"),
        }
    }

    /// The hex colour without the theme variable.
    fn hex(self) -> String {
        match self {
            Color::Ansi(i) => Self::ansi_fallback(i).to_string(),
            Color::Rgb(..) => self.css(),
        }
    }
}

/// SGR state of a cell.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Style {
    pub fg: Option<Color>,
    pub bg: Option<Color>,
    pub bold: bool,
    pub italic: bool,
    pub underline: bool,
    pub inverse: bool,
}

impl Style {
    /// Whether [`style_to_css`] yields any declaration (non-default style).
    fn has_css(&self) -> bool {
        *self != Style::default()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Cell {
    ch: char,
    style: Style,
}

impl Cell {
    fn blank() -> Self {
        Cell {
            ch: ' ',
            style: Style::default(),
        }
    }
}

/// One rendered row plus the arrival time of the last write that changed it.
#[derive(Debug, Clone, Default)]
struct Line {
    cells: Vec<Cell>,
    timestamp: Option<i64>,
}

static EMPTY_LINE: Line = Line {
    cells: Vec::new(),
    timestamp: None,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParseState {
    Normal,
    Esc,
    Csi,
    Osc,
    OscEsc,
}

#[derive(Debug, Clone)]
struct PendingClearedScreen {
    lines: Vec<Line>,
    base_row: usize,
}

/// Per-line formatter: `(rendered line, line timestamp) -> output line`.
pub type FormatLine<'a> = &'a dyn Fn(&str, Option<i64>) -> String;

/// Options for [`TerminalTextRenderer::to_text`] / [`TerminalTextRenderer::to_html_content`].
#[derive(Default, Clone, Copy)]
pub struct RenderOptions<'a> {
    /// Include a cleared screen that has not been committed yet (live
    /// snapshots), without mutating the renderer.
    pub include_pending_cleared_screen: bool,
    pub format_line: Option<FormatLine<'a>>,
}

/// Stateful terminal replay (`TerminalTextRenderer` in Electron).
#[derive(Debug, Clone)]
pub struct TerminalTextRenderer {
    lines: Vec<Line>,
    row: usize,
    col: usize,
    screen_base_row: usize,
    state: ParseState,
    escape_buffer: String,
    style: Style,
    cursor_moved_home_by_csi: bool,
    just_started_log_screen: bool,
    has_preserved_screen_history: bool,
    pending_cleared_screen: Option<PendingClearedScreen>,
    alternate_screen_active: bool,
    timestamp: Option<i64>,
}

impl Default for TerminalTextRenderer {
    fn default() -> Self {
        Self::new(false)
    }
}

impl TerminalTextRenderer {
    /// `alternate_screen_active` seeds the mode when a log starts while
    /// vim/less is already on the alternate buffer.
    pub fn new(alternate_screen_active: bool) -> Self {
        Self {
            lines: vec![Line::default()],
            row: 0,
            col: 0,
            screen_base_row: 0,
            state: ParseState::Normal,
            escape_buffer: String::new(),
            style: Style::default(),
            cursor_moved_home_by_csi: false,
            just_started_log_screen: false,
            has_preserved_screen_history: false,
            pending_cleared_screen: None,
            alternate_screen_active,
            timestamp: None,
        }
    }

    /// Whether the alternate screen is active after the input fed so far.
    pub fn alternate_screen_active(&self) -> bool {
        self.alternate_screen_active
    }

    /// Feed decoded terminal output. `timestamp` (ms) is recorded on every
    /// line this chunk changes.
    pub fn feed(&mut self, input: &str, timestamp: Option<i64>) {
        if input.is_empty() {
            return;
        }
        self.timestamp = timestamp;
        for ch in input.chars() {
            self.consume(ch);
        }
    }

    /// End of stream: drop an unterminated escape, commit a pending cleared
    /// screen and return the plain text.
    pub fn finish(&mut self) -> String {
        self.state = ParseState::Normal;
        self.escape_buffer.clear();
        self.commit_pending_cleared_screen();
        self.to_text(RenderOptions::default())
    }

    /// The line under the cursor (trailing cells included).
    pub fn cursor_line(&self) -> String {
        self.lines
            .get(self.row)
            .map(|line| line.cells.iter().map(|c| c.ch).collect())
            .unwrap_or_default()
    }

    /// Plain text: trailing blanks trimmed per line, trailing empty lines removed.
    pub fn to_text(&self, options: RenderOptions<'_>) -> String {
        let lines = self.render_lines(options.include_pending_cleared_screen);
        let rendered: Vec<String> = lines
            .iter()
            .map(|line| {
                let text: String = line.cells.iter().map(|c| c.ch).collect();
                let text = text.trim_end_matches([' ', '\t']);
                format_line(options.format_line, text, line.timestamp)
            })
            .collect();
        strip_trailing_newlines(rendered.join("\n"))
    }

    /// HTML fragment: escaped text with `<span style>` runs for styled cells.
    pub fn to_html_content(&self, options: RenderOptions<'_>) -> String {
        let lines = self.render_lines(options.include_pending_cleared_screen);
        let rendered: Vec<String> = lines
            .iter()
            .map(|line| format_line(options.format_line, &render_line_html(line), line.timestamp))
            .collect();
        strip_trailing_newlines(rendered.join("\n"))
    }

    fn render_lines(&self, include_pending: bool) -> Vec<&Line> {
        match (&self.pending_cleared_screen, include_pending) {
            (Some(pending), true) => self.build_lines_with_pending(pending).0,
            _ => self.lines.iter().collect(),
        }
    }

    fn consume(&mut self, ch: char) {
        match self.state {
            ParseState::Esc => {
                self.consume_esc(ch);
                return;
            }
            ParseState::Csi => {
                self.escape_buffer.push(ch);
                if ('@'..='~').contains(&ch) {
                    let sequence = std::mem::take(&mut self.escape_buffer);
                    self.apply_csi(&sequence);
                    self.state = ParseState::Normal;
                }
                return;
            }
            ParseState::Osc => {
                if ch == '\x07' {
                    self.state = ParseState::Normal;
                    self.escape_buffer.clear();
                } else if ch == '\x1b' {
                    self.state = ParseState::OscEsc;
                }
                return;
            }
            ParseState::OscEsc => {
                self.state = if ch == '\\' {
                    ParseState::Normal
                } else {
                    ParseState::Osc
                };
                return;
            }
            ParseState::Normal => {}
        }

        match ch {
            '\x1b' => {
                self.state = ParseState::Esc;
                self.escape_buffer.clear();
            }
            // 8-bit C1 CSI (single-byte form of ESC [). Same private modes as
            // the 7-bit sequence, including alternate-screen enter/leave.
            '\u{9b}' => {
                self.state = ParseState::Csi;
                self.escape_buffer.clear();
            }
            _ if self.alternate_screen_active => {}
            '\x08' => self.col = self.col.saturating_sub(1),
            '\r' => {
                self.col = 0;
                self.cursor_moved_home_by_csi = false;
            }
            '\n' => {
                self.row += 1;
                self.col = 0;
                self.cursor_moved_home_by_csi = false;
                self.ensure_line();
            }
            '\t' => {
                let spaces = " ".repeat(8 - (self.col % 8));
                self.write_text(&spaces);
            }
            _ => {
                if is_printable(ch) {
                    let mut buf = [0u8; 4];
                    self.write_text(ch.encode_utf8(&mut buf));
                }
            }
        }
    }

    fn consume_esc(&mut self, ch: char) {
        match ch {
            '[' => {
                self.state = ParseState::Csi;
                self.escape_buffer.clear();
                return;
            }
            ']' => {
                self.state = ParseState::Osc;
                self.escape_buffer.clear();
                return;
            }
            // RIS (ESC c) fully resets the terminal: leave the alternate
            // buffer, clear SGR, and rebase the log screen so post-reset
            // cursor homes cannot overwrite preserved history.
            'c' => self.apply_ris_reset(),
            _ => {}
        }
        // Single-character ESC sequences are terminal controls. Ignore them
        // for logs, but consume them so they never leak into txt/html output.
        self.state = ParseState::Normal;
        self.escape_buffer.clear();
    }

    fn apply_ris_reset(&mut self) {
        self.alternate_screen_active = false;
        self.style = Style::default();
        self.pending_cleared_screen = None;

        // Drop trailing blank rows so "before\n" + RIS does not leave an empty
        // separator before the new screen, then base cursor-home on a fresh row.
        while self
            .lines
            .last()
            .is_some_and(|line| trimmed_line_length(line) == 0)
        {
            self.lines.pop();
        }

        if self.lines.is_empty() {
            self.lines = vec![Line::default()];
            self.row = 0;
            self.col = 0;
            self.screen_base_row = 0;
            self.has_preserved_screen_history = false;
        } else {
            self.lines.push(Line::default());
            self.screen_base_row = self.lines.len() - 1;
            self.row = self.screen_base_row;
            self.col = 0;
            self.has_preserved_screen_history = true;
        }

        self.cursor_moved_home_by_csi = false;
        self.just_started_log_screen = true;
    }

    fn apply_csi(&mut self, sequence: &str) {
        let Some(final_ch) = sequence.chars().last() else {
            return;
        };
        let params = &sequence[..sequence.len() - final_ch.len_utf8()];
        let is_private_mode = params.contains('?');
        let stripped: String = params
            .chars()
            .filter(|c| !matches!(c, '?' | '>' | '<' | '='))
            .collect();
        let values: Vec<Option<i64>> = stripped.split(';').map(js_parse_int).collect();
        let first = values.first().copied().flatten();
        let n = match first {
            Some(v) if v != 0 => v,
            _ => 1,
        };

        if (final_ch == 'h' || final_ch == 'l') && is_private_mode {
            let alternate = values
                .iter()
                .any(|v| matches!(v, Some(47) | Some(1047) | Some(1049)));
            if alternate {
                self.alternate_screen_active = final_ch == 'h';
                return;
            }
        }

        if self.alternate_screen_active {
            return;
        }

        let base = self.screen_base_row as i64;
        let row = self.row as i64;
        let col = self.col as i64;
        match final_ch {
            'A' => {
                self.row = to_index(base.max(row - n));
                self.cursor_moved_home_by_csi = false;
                self.ensure_line();
            }
            'B' | 'E' => {
                self.row = to_index(row + n);
                if final_ch == 'E' {
                    self.col = 0;
                }
                self.cursor_moved_home_by_csi = false;
                self.ensure_line();
            }
            'C' => {
                self.col = to_index(col + n);
                self.cursor_moved_home_by_csi = false;
            }
            'D' => {
                self.col = to_index(col - n);
                self.cursor_moved_home_by_csi = false;
            }
            'F' => {
                self.row = to_index(base.max(row - n));
                self.col = 0;
                self.cursor_moved_home_by_csi = false;
                self.ensure_line();
            }
            'G' => {
                self.col = to_index(n - 1);
                self.cursor_moved_home_by_csi = false;
            }
            'H' | 'f' => {
                let target_row = or_one(first);
                let target_col = or_one(values.get(1).copied().flatten());
                self.row = to_index(base + (target_row - 1).max(0));
                self.col = to_index(target_col - 1);
                self.cursor_moved_home_by_csi = self.row == self.screen_base_row && self.col == 0;
                self.ensure_line();
            }
            'J' => self.erase_display(first.unwrap_or(0)),
            'K' => self.erase_line(first.unwrap_or(0)),
            'm' => self.apply_sgr(&values),
            // Unsupported CSI controls are intentionally ignored.
            _ => {}
        }
    }

    fn apply_sgr(&mut self, codes: &[Option<i64>]) {
        let mut style = self.style;
        let mut i = 0;
        while i < codes.len() {
            let code = codes[i].unwrap_or(0);
            match code {
                0 => style = Style::default(),
                1 => style.bold = true,
                3 => style.italic = true,
                4 => style.underline = true,
                7 => style.inverse = true,
                22 => style.bold = false,
                23 => style.italic = false,
                24 => style.underline = false,
                27 => style.inverse = false,
                30..=37 => style.fg = Some(Color::Ansi((code - 30) as u8)),
                39 => style.fg = None,
                40..=47 => style.bg = Some(Color::Ansi((code - 40) as u8)),
                49 => style.bg = None,
                90..=97 => style.fg = Some(Color::Ansi((8 + code - 90) as u8)),
                100..=107 => style.bg = Some(Color::Ansi((8 + code - 100) as u8)),
                38 | 48 if codes.get(i + 1) == Some(&Some(5)) => {
                    if let Some(color) = color_from_ansi256(codes.get(i + 2).copied().flatten()) {
                        if code == 38 {
                            style.fg = Some(color);
                        } else {
                            style.bg = Some(color);
                        }
                    }
                    i += 2;
                }
                38 | 48 if codes.get(i + 1) == Some(&Some(2)) => {
                    let part = |offset: usize| codes.get(i + offset).copied().flatten();
                    if let Some(color) = color_from_rgb(part(2), part(3), part(4)) {
                        if code == 38 {
                            style.fg = Some(color);
                        } else {
                            style.bg = Some(color);
                        }
                    }
                    i += 4;
                }
                _ => {}
            }
            i += 1;
        }
        self.style = style;
    }

    fn write_text(&mut self, text: &str) {
        self.ensure_line();
        let timestamp = self.timestamp;
        let style = self.style;
        let col = &mut self.col;
        let line = &mut self.lines[self.row];
        if timestamp.is_some() {
            line.timestamp = timestamp;
        }
        while line.cells.len() < *col {
            line.cells.push(Cell::blank());
        }
        for ch in text.chars() {
            let cell = Cell { ch, style };
            if *col < line.cells.len() {
                line.cells[*col] = cell;
            } else {
                line.cells.push(cell);
            }
            *col += 1;
        }
        self.cursor_moved_home_by_csi = false;
        self.just_started_log_screen = false;
    }

    fn erase_line(&mut self, mode: i64) {
        self.ensure_line();
        let col = self.col;
        let timestamp = self.timestamp;
        let line = &mut self.lines[self.row];
        let trimmed = trimmed_line_length(line);
        let changes_content = match mode {
            1 => line.cells[..(col + 1).min(trimmed)]
                .iter()
                .any(|cell| cell.ch != ' ' || cell.style != Style::default()),
            2 => trimmed > 0,
            _ => col < trimmed,
        };
        if changes_content && timestamp.is_some() {
            line.timestamp = timestamp;
        }
        match mode {
            1 => {
                let end = (col + 1).min(line.cells.len());
                for cell in &mut line.cells[..end] {
                    *cell = Cell::blank();
                }
            }
            2 => self.lines[self.row] = Line::default(),
            _ => line.cells.truncate(col),
        }
    }

    fn erase_display(&mut self, mode: i64) {
        self.ensure_line();
        if mode == 3 {
            if self.pending_cleared_screen.is_some() {
                self.commit_pending_cleared_screen();
            } else {
                self.pending_cleared_screen = None;
            }
            return;
        }
        if mode == 2 {
            if self.has_preserved_screen_history {
                self.clear_current_log_screen(true);
            } else {
                self.start_new_log_screen();
            }
            return;
        }
        if mode == 1 {
            for i in self.screen_base_row..self.row {
                self.lines[i] = Line::default();
            }
            self.erase_line(1);
            return;
        }
        if self.row == self.screen_base_row
            && self.col == 0
            && self.cursor_moved_home_by_csi
            && !self.has_preserved_screen_history
        {
            self.start_new_log_screen();
            return;
        }
        self.erase_line(0);
        self.lines.truncate(self.row + 1);
    }

    fn clear_current_log_screen(&mut self, keep_pending: bool) {
        let target_row = self.row;
        if keep_pending && self.current_log_screen_has_content() {
            self.pending_cleared_screen = Some(PendingClearedScreen {
                lines: self.lines[self.screen_base_row..].to_vec(),
                base_row: self.screen_base_row,
            });
        } else if !keep_pending {
            self.pending_cleared_screen = None;
        }
        for line in self.lines.iter_mut().skip(self.screen_base_row) {
            *line = Line::default();
        }
        self.row = self.screen_base_row.max(target_row);
        self.ensure_line();
        self.cursor_moved_home_by_csi = false;
        self.just_started_log_screen = true;
    }

    fn commit_pending_cleared_screen(&mut self) {
        let Some(pending) = self.pending_cleared_screen.take() else {
            return;
        };
        let relative_row = self.row.saturating_sub(pending.base_row);
        let col = self.col;
        let (lines, screen_base_row) = {
            let (lines, base) = self.build_lines_with_pending(&pending);
            (lines.into_iter().cloned().collect::<Vec<Line>>(), base)
        };
        self.lines = lines;
        self.screen_base_row = screen_base_row;
        self.row = self.screen_base_row + relative_row;
        self.col = col;
        self.ensure_line();
        self.cursor_moved_home_by_csi = false;
        self.just_started_log_screen = true;
        self.has_preserved_screen_history = true;
    }

    /// `prefix + trimmed pending screen + blank separator + active screen`,
    /// and the base row of the active screen in that layout.
    fn build_lines_with_pending<'a>(
        &'a self,
        pending: &'a PendingClearedScreen,
    ) -> (Vec<&'a Line>, usize) {
        let split = pending.base_row.min(self.lines.len());
        let prefix = &self.lines[..split];
        let active = &self.lines[split..];
        let pending_len = trimmed_lines_length(&pending.lines);
        let mut out: Vec<&Line> = Vec::with_capacity(self.lines.len() + pending_len + 2);
        out.extend(prefix.iter());
        out.extend(pending.lines[..pending_len].iter());
        out.push(&EMPTY_LINE);
        if active.is_empty() {
            out.push(&EMPTY_LINE);
        } else {
            out.extend(active.iter());
        }
        (out, prefix.len() + pending_len + 1)
    }

    fn start_new_log_screen(&mut self) {
        if self.just_started_log_screen {
            return;
        }
        let has_content = self.lines.iter().any(|line| trimmed_line_length(line) > 0);
        if has_content {
            self.lines.push(Line::default());
            self.row = self.lines.len() - 1;
        } else {
            self.lines = vec![Line::default()];
            self.row = 0;
        }
        self.screen_base_row = self.row;
        self.col = 0;
        self.cursor_moved_home_by_csi = false;
        self.just_started_log_screen = true;
        self.has_preserved_screen_history = has_content;
        self.pending_cleared_screen = None;
    }

    fn current_log_screen_has_content(&self) -> bool {
        self.lines
            .iter()
            .skip(self.screen_base_row)
            .any(|line| trimmed_line_length(line) > 0)
    }

    fn ensure_line(&mut self) {
        while self.lines.len() <= self.row {
            self.lines.push(Line::default());
        }
    }
}

/// Replay `terminal_data` and return the plain text a txt log contains.
pub fn terminal_data_to_plain_text(terminal_data: &str) -> String {
    let mut renderer = TerminalTextRenderer::new(false);
    renderer.feed(terminal_data, None);
    renderer.finish()
}

/// Replay `terminal_data` and return the HTML fragment (no page wrapper).
pub fn terminal_data_to_html_content(terminal_data: &str) -> String {
    let mut renderer = TerminalTextRenderer::new(false);
    renderer.feed(terminal_data, None);
    renderer.finish();
    renderer.to_html_content(RenderOptions::default())
}

/// CSS declarations for a style (`styleToCss`).
pub fn style_to_css(style: &Style) -> String {
    #[derive(Clone, Copy)]
    enum Value {
        Color(Color),
        DefaultBg,
        DefaultFg,
    }
    impl Value {
        fn css(self) -> String {
            match self {
                Value::Color(c) => c.css(),
                Value::DefaultBg => format!("var(--term-default-bg, {DEFAULT_BACKGROUND})"),
                Value::DefaultFg => format!("var(--term-default-fg, {DEFAULT_FOREGROUND})"),
            }
        }
        fn original(self) -> String {
            match self {
                Value::Color(c) => c.hex(),
                Value::DefaultBg => DEFAULT_BACKGROUND.to_string(),
                Value::DefaultFg => DEFAULT_FOREGROUND.to_string(),
            }
        }
    }

    let (fg, bg) = if style.inverse {
        (
            Some(style.bg.map(Value::Color).unwrap_or(Value::DefaultBg)),
            Some(style.fg.map(Value::Color).unwrap_or(Value::DefaultFg)),
        )
    } else {
        (style.fg.map(Value::Color), style.bg.map(Value::Color))
    };

    // Theme the normal page foreground, but preserve the original color pair
    // when output supplies a background (including a foreground inverted into
    // one). Darkening foregrounds independently can make these runs unreadable.
    let (fg, bg) = if style.bg.is_some() || (style.inverse && style.fg.is_some()) {
        (
            Some(
                fg.map(Value::original)
                    .unwrap_or_else(|| DEFAULT_FOREGROUND.to_string()),
            ),
            bg.map(Value::original),
        )
    } else if let Some(Value::Color(Color::Rgb(..))) = fg {
        // The wrapper supplies a readable light variant for extended/true colors.
        let hex = fg.map(Value::css).unwrap_or_default();
        (
            Some(format!("var(--term-custom-{}, {hex})", &hex[1..])),
            bg.map(Value::css),
        )
    } else {
        (fg.map(Value::css), bg.map(Value::css))
    };

    let mut declarations: Vec<String> = Vec::new();
    if let Some(fg) = fg {
        declarations.push(format!("color: {fg}"));
    }
    if let Some(bg) = bg {
        declarations.push(format!("background-color: {bg}"));
    }
    if style.bold {
        declarations.push("font-weight: 700".into());
    }
    if style.italic {
        declarations.push("font-style: italic".into());
    }
    if style.underline {
        declarations.push("text-decoration: underline".into());
    }
    declarations.join("; ")
}

/// Escape `& < > " '` like the Electron bridge.
pub fn escape_html(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#039;"),
            _ => out.push(ch),
        }
    }
    out
}

fn render_line_html(line: &Line) -> String {
    let mut html = String::new();
    let mut run_text = String::new();
    let mut run_style: Option<Style> = None;

    let flush = |html: &mut String, run_text: &mut String, run_style: Option<Style>| {
        if run_text.is_empty() {
            return;
        }
        let escaped = escape_html(run_text);
        let css = run_style.map(|s| style_to_css(&s)).unwrap_or_default();
        if css.is_empty() {
            html.push_str(&escaped);
        } else {
            html.push_str(&format!("<span style=\"{css}\">{escaped}</span>"));
        }
        run_text.clear();
    };

    let trimmed = trimmed_line_length(line);
    for cell in &line.cells[..trimmed] {
        if run_style != Some(cell.style) {
            flush(&mut html, &mut run_text, run_style);
            run_style = Some(cell.style);
        }
        run_text.push(cell.ch);
    }
    flush(&mut html, &mut run_text, run_style);
    html
}

/// Length of a line without trailing unstyled blanks.
fn trimmed_line_length(line: &Line) -> usize {
    let mut length = line.cells.len();
    while length > 0 {
        let cell = &line.cells[length - 1];
        if cell.ch != ' ' && cell.ch != '\t' {
            break;
        }
        if cell.style.has_css() {
            break;
        }
        length -= 1;
    }
    length
}

/// Number of leading lines left after dropping trailing blank lines.
fn trimmed_lines_length(lines: &[Line]) -> usize {
    let mut length = lines.len();
    while length > 0 && trimmed_line_length(&lines[length - 1]) == 0 {
        length -= 1;
    }
    length
}

fn format_line(format: Option<FormatLine<'_>>, line: &str, timestamp: Option<i64>) -> String {
    match format {
        Some(f) => f(line, timestamp),
        None => line.to_string(),
    }
}

fn strip_trailing_newlines(mut text: String) -> String {
    let len = text.trim_end_matches('\n').len();
    text.truncate(len);
    text
}

fn is_printable(ch: char) -> bool {
    let code = ch as u32;
    code >= 0x20 && code != 0x7f
}

fn or_one(value: Option<i64>) -> i64 {
    match value {
        Some(v) if v != 0 => v,
        _ => 1,
    }
}

fn to_index(value: i64) -> usize {
    value.max(0) as usize
}

/// JavaScript `Number.parseInt(part, 10)` for CSI parameters: optional
/// leading whitespace and sign, then decimal digits (anything after the
/// digits is ignored); `None` when there are no digits (JS `NaN` / empty).
/// Clamped to ±[`MAX_CSI_PARAM`].
fn js_parse_int(part: &str) -> Option<i64> {
    let s = part.trim_start_matches(|c: char| c.is_whitespace() || c == '\u{feff}');
    let (negative, digits) = match s.as_bytes().first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    let mut value: i64 = 0;
    let mut any = false;
    for b in digits.bytes() {
        if !b.is_ascii_digit() {
            break;
        }
        any = true;
        value = (value * 10 + i64::from(b - b'0')).min(MAX_CSI_PARAM);
    }
    if !any {
        return None;
    }
    Some(if negative { -value } else { value })
}

fn color_from_ansi256(value: Option<i64>) -> Option<Color> {
    let value = value?;
    if !(0..=255).contains(&value) {
        return None;
    }
    if value < 16 {
        return Some(Color::Ansi(value as u8));
    }
    if value < 232 {
        let n = value - 16;
        let cube = |n: i64| if n == 0 { 0 } else { (55 + n * 40) as u8 };
        return Some(Color::Rgb(cube(n / 36), cube((n % 36) / 6), cube(n % 6)));
    }
    let level = (8 + (value - 232) * 10) as u8;
    Some(Color::Rgb(level, level, level))
}

fn color_from_rgb(r: Option<i64>, g: Option<i64>, b: Option<i64>) -> Option<Color> {
    let channel = |v: Option<i64>| v.filter(|v| (0..=255).contains(v)).map(|v| v as u8);
    Some(Color::Rgb(channel(r)?, channel(g)?, channel(b)?))
}

#[cfg(test)]
mod tests {
    //! Ported from `electron/bridges/terminalLogSanitizer.test.cjs`.
    use super::*;

    fn plain(data: &str) -> String {
        terminal_data_to_plain_text(data)
    }

    fn html_of(r: &TerminalTextRenderer) -> String {
        r.to_html_content(RenderOptions::default())
    }

    fn ts_format(line: &str, ts: Option<i64>) -> String {
        if line.is_empty() {
            String::new()
        } else {
            format!("[{}] {line}", ts.map(|t| t.to_string()).unwrap_or_default())
        }
    }

    fn with_ts(pending: bool) -> RenderOptions<'static> {
        RenderOptions {
            include_pending_cleared_screen: pending,
            format_line: Some(&ts_format),
        }
    }

    #[test]
    fn line_editing_controls() {
        assert_eq!(plain("hellp\x08o\n"), "hello");
        assert_eq!(plain("progress 10%\rprogress 100%\n"), "progress 100%");
        assert_eq!(plain("loading...\r\x1b[Kdone\n"), "done");
        assert_eq!(plain("progress 10%\r\x1b[Jprogress 20%\n"), "progress 20%");
    }

    #[test]
    fn csi_split_across_chunks() {
        let mut r = TerminalTextRenderer::default();
        r.feed("red \x1b[", None);
        r.feed("31mtext\x1b[0m\n", None);
        assert_eq!(r.finish(), "red text");
    }

    #[test]
    fn osc_payloads_are_removed() {
        assert_eq!(plain("before\x1b]0;secret title\x07after\n"), "beforeafter");
        assert_eq!(plain("a\x1b]2;t\x1b\\b\n"), "ab");
    }

    #[test]
    fn display_clears_preserve_history() {
        assert_eq!(
            plain("login banner\n$ tmux\n\x1b[H\x1b[2Jtmux pane\n"),
            "login banner\n$ tmux\n\ntmux pane"
        );
        assert_eq!(
            plain("login banner\n$ clear\n\x1b[H\x1b[2J\x1b[3Jafter clear\n"),
            "login banner\n$ clear\n\nafter clear"
        );
        assert_eq!(plain("old1\nold2\n\x1b[2J\x1b[Hnew\n"), "old1\nold2\n\nnew");
        assert_eq!(plain("old\n\x1b[2Jnew\x1b[1Jafter\n"), "old\n\n   after");
        assert_eq!(
            plain("before zellij\n$ zellij\n\x1b[H\x1b[Jzellij pane\n"),
            "before zellij\n$ zellij\n\nzellij pane"
        );
        assert_eq!(
            plain("before tui\n\x1b[H\x1b[Jframe one\n\x1b[H\x1b[Jframe two\n"),
            "before tui\n\nframe two"
        );
        assert_eq!(
            plain("before tui\n\x1b[H\x1b[2Jframe one\n\x1b[H\x1b[2Jframe two\n"),
            "before tui\n\nframe one\n\nframe two"
        );
        assert_eq!(
            plain("before tui\n\x1b[2Jframe one\r\x1b[2Jframe two\n"),
            "before tui\n\nframe one\n\nframe two"
        );
        assert_eq!(
            plain("before\n\x1b[2Jfirst\x1b[2J\x1b[2Jsecond\n"),
            "before\n\nfirst\n\n     second"
        );
        assert_eq!(
            plain("before\n\x1b[H\x1b[2Jone\n\x1b[H\x1b[2Jtwo\n"),
            "before\n\none\n\ntwo"
        );
        assert_eq!(
            plain("before tui\n\x1b[H\x1b[2Jframe one\n\x1b[H\x1b[2Jframe two\n\x1b[H\x1b[2Jframe three\n"),
            "before tui\n\nframe two\n\nframe three"
        );
        assert_eq!(
            plain("before\n\x1b[H\x1b[2Jone\n\x1b[2J\x1b[10;5Htext\n"),
            "before\n\none\n\n\n\n\n\n\n\n\n\n\n    text"
        );
        assert_eq!(
            plain("before\n\x1b[H\x1b[2Jfirst screen\n\x1b[H\x1b[2J\x1b[3Jsecond screen\n"),
            "before\n\nfirst screen\n\nsecond screen"
        );
        assert_eq!(
            plain("before\n\x1b[H\x1b[2Jscreen\n\x1b[3Jafter\n"),
            "before\n\nscreen\nafter"
        );
    }

    #[test]
    fn pending_snapshot_does_not_mutate_repaint_state() {
        let mut r = TerminalTextRenderer::default();
        r.feed(
            "before tui\n\x1b[H\x1b[2Jframe one\n\x1b[H\x1b[2Jframe two\n",
            None,
        );
        assert_eq!(
            r.to_text(RenderOptions {
                include_pending_cleared_screen: true,
                format_line: None
            }),
            "before tui\n\nframe one\n\nframe two"
        );
        r.feed("\x1b[H\x1b[2Jframe three\n", None);
        assert_eq!(r.finish(), "before tui\n\nframe two\n\nframe three");
    }

    #[test]
    fn alternate_screen_is_omitted() {
        assert_eq!(
            plain("$ vim file\n\x1b[?1049h\x1b[H~\n~\n\"file\" 0L, 0B\x1b[?1049l$ ls\n"),
            "$ vim file\n$ ls"
        );
        let mut r = TerminalTextRenderer::default();
        r.feed("$ vim\n\x1b[?1049", None);
        r.feed("h\x1b[H~\nstatus line", None);
        r.feed("\x1b[?1049l$ done\n", None);
        assert_eq!(r.finish(), "$ vim\n$ done");

        let mut seeded = TerminalTextRenderer::new(true);
        seeded.feed("~\nstatus line\n", None);
        seeded.feed("\x1b[?1049l$ done\n", None);
        assert_eq!(seeded.finish(), "$ done");

        assert_eq!(
            plain("shell\n\x1b[?47hTUI\n\x1b[?47lafter\n"),
            "shell\nafter"
        );
        assert_eq!(
            plain("shell\n\x1b[?1047hTUI\n\x1b[?1047lafter\n"),
            "shell\nafter"
        );
    }

    #[test]
    fn ris_resets_terminal_state() {
        assert_eq!(
            plain("before\n\x1b[?1049hTUI\x1bcshell-after\n"),
            "before\nshell-after"
        );
        let mut r = TerminalTextRenderer::default();
        r.feed("before\n\x1b[?1049hTUI\x1b", None);
        r.feed("cshell-after\n", None);
        assert_eq!(r.finish(), "before\nshell-after");
        assert_eq!(
            plain("before\x1b[?1049hTUI\x1bcshell-after\n"),
            "before\nshell-after"
        );
        assert_eq!(plain("before\x1bcshell\x1b[Hnew"), "before\nnewll");

        let mut colored = TerminalTextRenderer::default();
        colored.feed("\x1b[31mbefore\x1b[?1049hTUI\x1bcshell-after\n", None);
        assert_eq!(
            html_of(&colored),
            "<span style=\"color: var(--ansi-1, #cd3131)\">before</span>\nshell-after"
        );
    }

    #[test]
    fn c1_csi_alternate_screen() {
        assert_eq!(
            plain("before\n\u{9b}?1049hTUI\n\u{9b}?1049lafter\n"),
            "before\nafter"
        );
        assert_eq!(
            plain("before\n\u{9b}?47hTUI\n\u{9b}?47lafter\n"),
            "before\nafter"
        );
        let mut r = TerminalTextRenderer::default();
        r.feed("before\n\u{9b}?1049", None);
        r.feed("h~\nstatus\n", None);
        r.feed("\u{9b}?1049l$ done\n", None);
        assert_eq!(r.finish(), "before\n$ done");
    }

    #[test]
    fn sgr_colors_are_themeable() {
        let mut r = TerminalTextRenderer::default();
        r.feed(
            "\x1b[31mred \x1b[91mbright-red \x1b[44mbg-blue \x1b[0mplain\n",
            None,
        );
        assert_eq!(
            html_of(&r),
            "<span style=\"color: var(--ansi-1, #cd3131)\">red </span>\
             <span style=\"color: var(--ansi-9, #f14c4c)\">bright-red </span>\
             <span style=\"color: #f14c4c; background-color: #2472c8\">bg-blue </span>plain"
        );

        let mut r = TerminalTextRenderer::default();
        r.feed("\x1b[38;5;1mbase\x1b[0m \x1b[38;5;208mcube\n", None);
        assert_eq!(
            html_of(&r),
            "<span style=\"color: var(--ansi-1, #cd3131)\">base</span> \
             <span style=\"color: var(--term-custom-ff8700, #ff8700)\">cube</span>"
        );

        let mut r = TerminalTextRenderer::default();
        r.feed("\x1b[7minversed\x1b[0m\n", None);
        assert_eq!(
            html_of(&r),
            "<span style=\"color: var(--term-default-bg, #1e1e1e); background-color: var(--term-default-fg, #d4d4d4)\">inversed</span>"
        );
    }

    #[test]
    fn explicit_backgrounds_keep_original_pairs() {
        let mut r = TerminalTextRenderer::default();
        r.feed("\x1b[37;41mERROR\x1b[0m \x1b[40mTEXT\x1b[0m \x1b[38;5;15;48;5;1mindexed\x1b[0m \x1b[31;7minverse\x1b[0m \x1b[48;2;0;0;0mRGB background\x1b[0m", None);
        let html = html_of(&r);
        for expected in [
            "color: #e5e5e5; background-color: #cd3131\">ERROR",
            "color: #d4d4d4; background-color: #000000\">TEXT",
            "color: #ffffff; background-color: #cd3131\">indexed",
            "color: #1e1e1e; background-color: #cd3131\">inverse",
            "color: #d4d4d4; background-color: #000000\">RGB background",
        ] {
            assert!(html.contains(expected), "{expected} missing in {html}");
        }
    }

    #[test]
    fn line_timestamps_follow_writes_and_cleared_screens() {
        let mut r = TerminalTextRenderer::default();
        r.feed("before tui\n", Some(89));
        r.feed("\x1b[H\x1b[2Jframe one\n", Some(389));
        r.feed("\x1b[H\x1b[2Jframe two\n", Some(489));
        let expected = "[89] before tui\n\n[389] frame one\n\n[489] frame two";
        assert_eq!(r.to_text(with_ts(true)), expected);
        r.finish();
        assert_eq!(r.to_text(with_ts(false)), expected);
        assert_eq!(r.to_html_content(with_ts(false)), expected);
    }

    #[test]
    fn line_timestamps_track_split_writes_and_partial_erasure() {
        let mut r = TerminalTextRenderer::default();
        r.feed("unchanged\r\nlong tail", Some(89));
        r.feed("\r\x1b[", Some(389));
        r.feed("31mshort\x1b[K", Some(489));
        assert_eq!(r.to_text(with_ts(false)), "[89] unchanged\n[489] short");
        assert!(r
            .to_html_content(with_ts(false))
            .contains("[489] <span style=\"color: var(--ansi-1, #cd3131)\">short</span>"));
    }

    #[test]
    fn noop_erasure_keeps_timestamp() {
        let mut r = TerminalTextRenderer::default();
        r.feed("completed", Some(1000));
        r.feed("\x1b[K", Some(9000));
        assert_eq!(r.to_text(with_ts(false)), "[1000] completed");
        r.feed("\r\x1b[4C\x1b[K", Some(10000));
        assert_eq!(r.to_text(with_ts(false)), "[10000] comp");
    }

    #[test]
    fn erasing_styled_spaces_updates_timestamp() {
        let mut r = TerminalTextRenderer::default();
        r.feed("\x1b[41m   \x1b[0mtext", Some(1000));
        assert!(r
            .to_html_content(with_ts(false))
            .contains("background-color"));
        r.feed("\r\x1b[2C\x1b[1K", Some(9000));
        assert_eq!(r.to_html_content(with_ts(false)), "[9000]    text");
    }

    #[test]
    fn sgr_changes_do_not_recolor_earlier_output() {
        let mut r = TerminalTextRenderer::default();
        r.feed("ab\x1b[31mcd\x1b[1mef\x1b[0mgh", None);
        assert_eq!(r.to_text(RenderOptions::default()), "abcdefgh");
        assert_eq!(
            html_of(&r),
            "ab<span style=\"color: var(--ansi-1, #cd3131)\">cd</span><span style=\"color: var(--ansi-1, #cd3131); font-weight: 700\">ef</span>gh"
        );
    }

    #[test]
    fn sgr_resets() {
        let mut r = TerminalTextRenderer::default();
        r.feed("\x1b[1;3;4;7;38;5;196;48;2;1;2;3mA", None);
        assert_eq!(
            r.lines[0].cells[0].style,
            Style {
                fg: Some(Color::Rgb(255, 0, 0)),
                bg: Some(Color::Rgb(1, 2, 3)),
                bold: true,
                italic: true,
                underline: true,
                inverse: true,
            }
        );
        r.feed("\x1b[22;23;24;27;39;49mB\x1b[0;32;1mC\x1b[mD", None);
        assert_eq!(r.lines[0].cells[1].style, Style::default());
        assert_eq!(r.to_text(RenderOptions::default()), "ABCD");
        assert_eq!(
            html_of(&r),
            "<span style=\"color: #010203; background-color: #ff0000; font-weight: 700; font-style: italic; text-decoration: underline\">A</span>B<span style=\"color: var(--ansi-2, #0dbc79); font-weight: 700\">C</span>D"
        );
    }

    #[test]
    fn cursor_overwrites_and_erasure() {
        let mut r = TerminalTextRenderer::default();
        r.feed("\x1b[31mabcd\r\x1b[32mX\x1b[3G\x1b[0mY", None);
        assert_eq!(r.to_text(RenderOptions::default()), "XbYd");
        assert_eq!(
            html_of(&r),
            "<span style=\"color: var(--ansi-2, #0dbc79)\">X</span><span style=\"color: var(--ansi-1, #cd3131)\">b</span>Y<span style=\"color: var(--ansi-1, #cd3131)\">d</span>"
        );
        r.feed("\x1b[1K", None);
        assert_eq!(html_of(&r), "");
    }

    #[test]
    fn pending_cleared_screen_keeps_independent_cells() {
        let mut r = TerminalTextRenderer::default();
        r.feed("first\x1b[H\x1b[2J\x1b[31mold", Some(10));
        r.feed("\x1b[H\x1b[2J", None);
        let saved = &r.pending_cleared_screen.as_ref().unwrap().lines[0];
        assert_eq!(saved.timestamp, Some(10));
        assert_eq!(saved.cells[0].style.fg, Some(Color::Ansi(1)));
        r.feed("\x1b[32mnew", Some(20));
        let pending = RenderOptions {
            include_pending_cleared_screen: true,
            format_line: None,
        };
        assert_eq!(r.to_text(pending), "first\nold\n\nnew");
        assert_eq!(
            r.to_html_content(pending),
            "first\n<span style=\"color: var(--ansi-1, #cd3131)\">old</span>\n\n<span style=\"color: var(--ansi-2, #0dbc79)\">new</span>"
        );
    }

    #[test]
    fn manual_log_fixtures() {
        // `startStreamToFile can write human-readable text logs ...`
        assert_eq!(
            plain("\x1b[01;32mroot@MyNAS\x1b[00m:\x1b[01;34m~\x1b[00m# ip a\r\n1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\r\n\x1b[01;32mroot@MyNAS\x1b[00m:\x1b[01;34m~\x1b[00m# "),
            "root@MyNAS:~# ip a\n1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\nroot@MyNAS:~#"
        );
        // `manual session logs honor the configured plain-text format`
        assert_eq!(
            plain("root@host:~# \u{1b}[31mdisplay\u{1b}[0m\r\npage 1\r\n--More--\r        \rpage 2\r\n"),
            "root@host:~# display\npage 1\npage 2"
        );
    }

    #[test]
    fn hostile_parameters_are_bounded() {
        let out = plain("a\x1b[999999999Bb\x1b[-5Cc\x1b[999999999Gd");
        assert_eq!(out.lines().count(), MAX_CSI_PARAM as usize + 1);
        assert!(out.starts_with('a'));
        assert_eq!(js_parse_int(" 12x"), Some(12));
        assert_eq!(js_parse_int("-3"), Some(-3));
        assert_eq!(js_parse_int(""), None);
        assert_eq!(js_parse_int("x1"), None);
    }

    #[test]
    fn non_printable_and_tabs() {
        assert_eq!(plain("a\tb\x7f\x00c\n"), "a       bc");
        // Only the byte after ESC is consumed (Electron quirk): `ESC ( B`
        // leaves the `B`.
        assert_eq!(plain("\x1b(Bx\x1b=y"), "Bxy");
    }
}
