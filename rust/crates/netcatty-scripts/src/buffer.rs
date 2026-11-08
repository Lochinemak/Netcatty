//! Per-session output buffer the script waits run against. Port of
//! `electron/scripts/sessionOutputBuffer.cjs`.
//!
//! The buffer keeps the newest [`DEFAULT_BUFFER_SIZE`] bytes of decoded
//! terminal output. Waits (`waitFor`, `waitForText`, `waitForRegex`,
//! `waitForAny`) only accept *fresh* matches: output past `scan_offset` (what
//! earlier waits consumed) and, for the live tail, within
//! [`FRESH_MATCH_TAIL_SLACK`] bytes of the end — so scrollback never satisfies
//! a wait. A viewport seeded at script start (`replace_with_visible_screen`)
//! is fully waitable, and a shell prompt already on screen can be consumed
//! once by `waitForPrompt` (`preserved_tail_match`).
//!
//! Electron resolves waits from timers and promises; here each wait is an
//! async task that re-checks the buffer whenever it changes (a `watch`
//! channel), polls the abort predicate every 50 ms, and registers a waiter
//! slot so trimming / re-seeding can adjust its fresh boundary.

use crate::pattern::{
    advance_offset, compile_pattern, compile_text_pattern, next_char_boundary, prev_char_boundary,
    try_match_with_end, try_regex_match_with_end, MatchEnd, PatternError, RegexMatch, WaitPattern,
};
use crate::prompt_patterns::shell_prompt_patterns;
use parking_lot::Mutex;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::watch;

pub const DEFAULT_BUFFER_SIZE: usize = 1024 * 1024;
/// Matches within this many bytes of the buffer end count as live output.
pub const FRESH_MATCH_TAIL_SLACK: usize = 512;
const ABORT_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Abort predicate of a wait (Electron's `shouldAbort`).
pub type AbortCheck = Arc<dyn Fn() -> bool + Send + Sync>;

/// Why a wait ended without a match.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WaitError {
    /// `"<label> timed out after <ms>ms"`.
    #[error("{0}")]
    Timeout(String),
    /// `"Script stopped"`, `"Session output buffer disposed"` or the
    /// `abort_waiters` reason.
    #[error("{0}")]
    Aborted(String),
    #[error("{0}")]
    Pattern(#[from] PatternError),
}

impl WaitError {
    pub fn message(&self) -> String {
        match self {
            WaitError::Timeout(m) | WaitError::Aborted(m) => m.clone(),
            WaitError::Pattern(e) => e.to_string(),
        }
    }

    pub fn is_timeout(&self) -> bool {
        matches!(self, WaitError::Timeout(_))
    }
}

fn is_fresh_tail_match(text_length: usize, match_end_absolute: usize) -> bool {
    match_end_absolute + FRESH_MATCH_TAIL_SLACK >= text_length
}

/// `stripTrailingBlankLines`: `/(?:[ \t]*\r?\n)*$/`.
pub fn strip_trailing_blank_lines(text: &str) -> &str {
    let mut end = text.len();
    loop {
        let candidate = &text[..end];
        let Some(line_end) = candidate.strip_suffix('\n') else {
            break;
        };
        let line_end = line_end.strip_suffix('\r').unwrap_or(line_end);
        let trimmed = line_end.trim_end_matches([' ', '\t']);
        end = trimmed.len();
    }
    &text[..end]
}

/// `trimOverlappingTrailingFresh`: drop any prefix of `trailing_fresh` that
/// the viewport snapshot already shows.
pub fn trim_overlapping_trailing_fresh(
    viewport_text: &str,
    trailing_fresh: &str,
    sync_start_text: &str,
) -> String {
    let trailing = trailing_fresh;
    if trailing.is_empty() {
        return String::new();
    }
    let viewport = viewport_text;
    let viewport_core = strip_trailing_blank_lines(viewport);
    let trailing_core = strip_trailing_blank_lines(trailing);
    let sync_core = strip_trailing_blank_lines(sync_start_text);

    // Stale snapshot: still showing pre-sync content → keep all trailingFresh.
    if !sync_core.is_empty()
        && !viewport_core.is_empty()
        && (viewport_core == sync_core
            || (sync_core.len() > viewport_core.len() && sync_core.ends_with(viewport_core)))
    {
        return trailing.to_string();
    }

    if viewport.ends_with(trailing)
        || (!trailing_core.is_empty() && viewport_core.ends_with(trailing_core))
    {
        return String::new();
    }

    // Partial overlap: prefer the unpadded core so blank-padded snapshots
    // still trim, then fall back to the full viewport.
    for candidate in [viewport_core, viewport] {
        if candidate.is_empty() {
            continue;
        }
        let max = candidate.len().min(trailing.len());
        let mut len = prev_char_boundary(trailing, max);
        while len > 0 {
            if candidate.ends_with(&trailing[..len]) {
                let mut remainder = &trailing[len..];
                while remainder.starts_with('\n') && viewport.ends_with('\n') {
                    remainder = &remainder[1..];
                }
                return remainder.to_string();
            }
            len = prev_char_boundary(trailing, len - 1);
        }
    }
    trailing.to_string()
}

fn stale_advance_end_offset(matched: &MatchEnd) -> usize {
    matched.end_offset.max(1)
}

fn stale_regex_advance_end_offset(matched: &RegexMatch) -> usize {
    (matched.start_offset + 1).max(1)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnyMatch {
    pub index: usize,
    pub matched: MatchEnd,
}

fn find_fresh_tail_match_any(
    text: &str,
    patterns: &[WaitPattern],
) -> Result<Option<AnyMatch>, PatternError> {
    for (index, pattern) in patterns.iter().enumerate() {
        let mut offset = 0;
        while offset <= text.len() {
            let Some(matched) = try_match_with_end(&text[offset..], pattern, compile_pattern)?
            else {
                break;
            };
            let absolute_end = offset + matched.end_offset;
            if is_fresh_tail_match(text.len(), absolute_end) {
                return Ok(Some(AnyMatch {
                    index,
                    matched: MatchEnd {
                        value: matched.value,
                        end_offset: absolute_end,
                    },
                }));
            }
            offset = advance_offset(text, absolute_end.max(offset + 1));
        }
    }
    Ok(None)
}

fn find_matching_preserved_tail_match(
    text: &str,
    patterns: &[WaitPattern],
    preserved: &PreservedTailMatch,
) -> Result<Option<AnyMatch>, PatternError> {
    for (index, pattern) in patterns.iter().enumerate() {
        let mut offset = 0;
        while offset <= text.len() {
            let Some(matched) = try_match_with_end(&text[offset..], pattern, compile_pattern)?
            else {
                break;
            };
            let absolute_end = offset + matched.end_offset;
            if absolute_end == preserved.end_offset && matched.value == preserved.value {
                return Ok(Some(AnyMatch {
                    index,
                    matched: MatchEnd {
                        value: matched.value,
                        end_offset: absolute_end,
                    },
                }));
            }
            offset = advance_offset(text, absolute_end.max(offset + 1));
        }
    }
    Ok(None)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreservedTailMatch {
    pub text_length: usize,
    pub value: String,
    pub end_offset: usize,
}

/// A registered wait: its fresh boundary follows buffer trimming and
/// re-seeding; `aborted` carries the `abort_waiters` reason.
#[derive(Debug, Default)]
struct WaiterSlot {
    fresh_boundary: Option<usize>,
    aborted: Option<String>,
}

/// Synchronous buffer state (the JavaScript class minus its timers).
#[derive(Debug)]
pub struct BufferState {
    pub session_id: String,
    max_size: usize,
    text: String,
    chunk_lengths: VecDeque<usize>,
    scan_offset: usize,
    preserved_tail_match: Option<PreservedTailMatch>,
    /// Absolute end of a seeded visible viewport that stays fully waitable.
    seeded_length: Option<usize>,
    waiters: HashMap<u64, WaiterSlot>,
    next_waiter: u64,
}

impl BufferState {
    pub fn new(session_id: &str, max_size: usize) -> Self {
        Self {
            session_id: session_id.to_string(),
            max_size,
            text: String::new(),
            chunk_lengths: VecDeque::new(),
            scan_offset: 0,
            preserved_tail_match: None,
            seeded_length: None,
            waiters: HashMap::new(),
            next_waiter: 1,
        }
    }

    pub fn append(&mut self, data: &str) {
        if data.is_empty() {
            return;
        }
        self.preserved_tail_match = None;
        self.text.push_str(data);
        self.chunk_lengths.push_back(data.len());
        while self.text.len() > self.max_size && self.chunk_lengths.len() > 1 {
            let removed = self.chunk_lengths.pop_front().unwrap_or(0);
            self.text.drain(..removed);
            self.scan_offset = self.scan_offset.saturating_sub(removed);
            if let Some(seeded) = self.seeded_length {
                self.seeded_length = Some(seeded.saturating_sub(removed));
            }
            for waiter in self.waiters.values_mut() {
                if let Some(boundary) = waiter.fresh_boundary {
                    waiter.fresh_boundary = Some(boundary.saturating_sub(removed));
                }
            }
        }
    }

    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn scan_offset(&self) -> usize {
        self.scan_offset
    }

    pub fn seeded_length(&self) -> Option<usize> {
        self.seeded_length
    }

    pub fn preserved_tail_match(&self) -> Option<&PreservedTailMatch> {
        self.preserved_tail_match.as_ref()
    }

    pub fn pending_text(&self) -> &str {
        &self.text[self.scan_offset..]
    }

    pub fn try_match_pending(&self, pattern: &WaitPattern) -> Result<Option<MatchEnd>, PatternError> {
        try_match_with_end(self.pending_text(), pattern, compile_pattern)
    }

    pub fn try_match_pending_text(
        &self,
        pattern: &WaitPattern,
    ) -> Result<Option<MatchEnd>, PatternError> {
        try_match_with_end(self.pending_text(), pattern, compile_text_pattern)
    }

    pub fn try_match_pending_regex(
        &self,
        pattern: &WaitPattern,
    ) -> Result<Option<RegexMatch>, PatternError> {
        try_regex_match_with_end(self.pending_text(), pattern)
    }

    /// Freshness for `waitFor` / `waitForText` / `waitForRegex` / generic
    /// `waitForAny`: the live tail window, widened to the whole seeded
    /// viewport while it is still unconsumed.
    pub fn current_fresh_boundary(&mut self) -> usize {
        let text_length = self.text.len();
        let normal = self
            .scan_offset
            .max(text_length.saturating_sub(FRESH_MATCH_TAIL_SLACK));
        if let Some(seeded) = self.seeded_length {
            if self.scan_offset < seeded {
                return self.scan_offset;
            }
            self.seeded_length = None;
        }
        normal
    }

    /// Freshness for `waitForPrompt`: live tail only, never inside the
    /// still-unconsumed seeded viewport.
    pub fn current_tail_fresh_boundary(&mut self) -> usize {
        let text_length = self.text.len();
        let mut boundary = self
            .scan_offset
            .max(text_length.saturating_sub(FRESH_MATCH_TAIL_SLACK));
        if let Some(seeded) = self.seeded_length {
            if self.scan_offset >= seeded {
                self.seeded_length = None;
            } else {
                boundary = boundary.max(seeded);
            }
        }
        boundary
    }

    /// Replace the contents with the visible terminal screen. The whole
    /// seeded viewport is fresh for `waitFor*`; `trailing_fresh` (bytes that
    /// arrived during the snapshot sync) stays outside `seeded_length`.
    pub fn replace_with_visible_screen(
        &mut self,
        screen_text: &str,
        trailing_fresh: &str,
        sync_start_text: &str,
    ) {
        let normalized = if screen_text.ends_with('\n') {
            screen_text.to_string()
        } else {
            format!("{screen_text}\n")
        };
        let trailing = trim_overlapping_trailing_fresh(&normalized, trailing_fresh, sync_start_text);
        self.clear();
        self.append(&normalized);
        self.seeded_length = Some(self.text.len());
        self.scan_offset = 0;
        // Re-open pending waiters onto the seeded viewport (#1960).
        for waiter in self.waiters.values_mut() {
            if waiter.fresh_boundary.is_some() {
                waiter.fresh_boundary = Some(0);
            }
        }
        self.preserved_tail_match = None;
        let fresh = find_fresh_tail_match_any(&self.text, &shell_prompt_patterns())
            .ok()
            .flatten();
        if !trailing.is_empty() {
            self.append(&trailing);
        }
        if let Some(fresh) = fresh {
            self.preserved_tail_match = Some(PreservedTailMatch {
                text_length: self.text.len(),
                value: fresh.matched.value,
                end_offset: fresh.matched.end_offset,
            });
        }
    }

    /// After automated input, startup snapshot content must not satisfy
    /// later waits: consume everything currently buffered.
    pub fn invalidate_startup_seed(&mut self) {
        self.seeded_length = None;
        self.preserved_tail_match = None;
        self.scan_offset = self.text.len();
    }

    /// Mark output through `absolute_length` as seen without consuming what
    /// arrived after it (`sendLine`: prompts between body and CR stay waitable).
    pub fn consume_through_absolute(&mut self, absolute_length: usize) {
        self.seeded_length = None;
        self.preserved_tail_match = None;
        let capped = next_char_boundary(&self.text, absolute_length.min(self.text.len()));
        self.scan_offset = self.scan_offset.max(capped);
    }

    pub fn consume_fresh_pending_match(
        &mut self,
        pattern: &WaitPattern,
        fresh_boundary: usize,
    ) -> Result<Option<MatchEnd>, PatternError> {
        loop {
            let Some(matched) = self.try_match_pending(pattern)? else {
                return Ok(None);
            };
            let absolute_end = self.scan_offset + matched.end_offset;
            if absolute_end >= fresh_boundary {
                return Ok(Some(matched));
            }
            self.advance_scan_offset(stale_advance_end_offset(&matched));
        }
    }

    pub fn consume_fresh_pending_text(
        &mut self,
        pattern: &WaitPattern,
        fresh_boundary: usize,
    ) -> Result<Option<MatchEnd>, PatternError> {
        loop {
            let Some(matched) = self.try_match_pending_text(pattern)? else {
                return Ok(None);
            };
            let absolute_end = self.scan_offset + matched.end_offset;
            if absolute_end >= fresh_boundary {
                return Ok(Some(matched));
            }
            self.advance_scan_offset(stale_advance_end_offset(&matched));
        }
    }

    /// `consumeFreshPendingRegex`. `min_fresh_start_absolute` is the fresh
    /// boundary the match *core* must start at or after.
    pub fn consume_fresh_pending_regex(
        &mut self,
        pattern: &WaitPattern,
        min_fresh_start_absolute: Option<usize>,
    ) -> Result<Option<RegexMatch>, PatternError> {
        let fallback_boundary = self.current_fresh_boundary();
        let text_len = self.text.len();
        let base_offset = self.scan_offset;
        let pending_len = text_len - base_offset;
        let mut relative_offset = 0;
        while relative_offset <= pending_len {
            let matched = {
                let pending = &self.text[base_offset + relative_offset..];
                try_regex_match_with_end(pending, pattern)?
            };
            let Some(matched) = matched else {
                if relative_offset > 0 {
                    self.scan_offset = (base_offset + relative_offset).min(text_len);
                }
                return Ok(None);
            };
            let absolute_start = base_offset + relative_offset + matched.fresh_start_offset;
            let match_start_absolute = base_offset + relative_offset + matched.start_offset;
            let fresh_boundary = min_fresh_start_absolute.unwrap_or(fallback_boundary);
            if absolute_start >= fresh_boundary {
                let mut value = matched.value.clone();
                if let Some(min_fresh) = min_fresh_start_absolute {
                    if match_start_absolute < min_fresh {
                        let value_fresh_start = matched.fresh_start_offset - matched.start_offset;
                        // `lastIndexOf("\n", max(0, valueFreshStart - 1))`
                        let search_end = if value_fresh_start == 0 {
                            prev_char_boundary(&matched.value, 1)
                        } else {
                            value_fresh_start
                        };
                        let line_start = matched.value[..search_end].rfind('\n');
                        let value_start = line_start.unwrap_or(value_fresh_start);
                        value = matched.value[value_start..].to_string();
                    }
                }
                return Ok(Some(RegexMatch {
                    value,
                    end_offset: relative_offset + matched.end_offset,
                    ..matched
                }));
            }
            relative_offset = advance_offset(
                &self.text[base_offset..],
                relative_offset + stale_regex_advance_end_offset(&matched),
            );
        }
        self.scan_offset = (base_offset + relative_offset).min(text_len);
        Ok(None)
    }

    pub fn consume_fresh_pending_match_any(
        &mut self,
        patterns: &[WaitPattern],
        fresh_boundary: usize,
    ) -> Result<Option<AnyMatch>, PatternError> {
        for (index, pattern) in patterns.iter().enumerate() {
            loop {
                let Some(matched) = self.try_match_pending(pattern)? else {
                    break;
                };
                let absolute_end = self.scan_offset + matched.end_offset;
                if absolute_end >= fresh_boundary {
                    return Ok(Some(AnyMatch { index, matched }));
                }
                self.advance_scan_offset(stale_advance_end_offset(&matched));
            }
        }
        Ok(None)
    }

    pub fn advance_scan_offset(&mut self, end_offset: usize) {
        let absolute_end = self.scan_offset + end_offset;
        self.scan_offset = next_char_boundary(&self.text, absolute_end.min(self.text.len()));
        if let Some(preserved) = &self.preserved_tail_match {
            if self.scan_offset > preserved.end_offset {
                self.preserved_tail_match = None;
            }
        }
        if let Some(seeded) = self.seeded_length {
            if self.scan_offset >= seeded {
                self.seeded_length = None;
            }
        }
    }

    pub fn mark_current_output_consumed(&mut self, preserve_tail_patterns: &[WaitPattern]) {
        self.mark_output_consumed_through(self.text.len(), preserve_tail_patterns);
    }

    pub fn mark_output_consumed_through(
        &mut self,
        length: usize,
        preserve_tail_patterns: &[WaitPattern],
    ) {
        let consumed_length = prev_char_boundary(&self.text, length.min(self.text.len()));
        self.scan_offset = consumed_length;
        self.preserved_tail_match = None;
        if let Some(seeded) = self.seeded_length {
            if self.scan_offset >= seeded {
                self.seeded_length = None;
            }
        }
        if preserve_tail_patterns.is_empty() || consumed_length == 0 {
            return;
        }
        let consumed_text = &self.text[..consumed_length];
        let Ok(Some(fresh)) = find_fresh_tail_match_any(consumed_text, preserve_tail_patterns)
        else {
            return;
        };
        self.preserved_tail_match = Some(PreservedTailMatch {
            text_length: consumed_length,
            value: fresh.matched.value,
            end_offset: fresh.matched.end_offset,
        });
    }

    pub fn consume_preserved_tail_match_any(
        &mut self,
        patterns: &[WaitPattern],
    ) -> Result<Option<AnyMatch>, PatternError> {
        let Some(preserved) = self.preserved_tail_match.clone() else {
            return Ok(None);
        };
        if self.text.len() != preserved.text_length {
            self.preserved_tail_match = None;
            return Ok(None);
        }
        let Some(fresh) = find_matching_preserved_tail_match(&self.text, patterns, &preserved)?
        else {
            return Ok(None);
        };
        self.preserved_tail_match = None;
        // Consuming the startup prompt also consumes the whole seeded viewport.
        let consume_through = match self.seeded_length {
            Some(seeded) => fresh.matched.end_offset.max(seeded),
            None => fresh.matched.end_offset.max(preserved.text_length),
        };
        self.scan_offset = self.scan_offset.max(consume_through);
        // Sync-race trailingFresh sits past the original seededLength: keep
        // it fully waitable even when longer than FRESH_MATCH_TAIL_SLACK.
        let text_length = self.text.len();
        self.seeded_length = if text_length > self.scan_offset {
            Some(text_length)
        } else {
            None
        };
        Ok(Some(fresh))
    }

    pub fn clear(&mut self) {
        self.text.clear();
        self.chunk_lengths.clear();
        self.scan_offset = 0;
        self.preserved_tail_match = None;
        self.seeded_length = None;
    }

    fn register_waiter(&mut self, fresh_boundary: Option<usize>) -> u64 {
        let id = self.next_waiter;
        self.next_waiter += 1;
        self.waiters.insert(
            id,
            WaiterSlot {
                fresh_boundary,
                aborted: None,
            },
        );
        id
    }

    fn waiter_boundary(&self, id: u64) -> Option<usize> {
        self.waiters.get(&id).and_then(|w| w.fresh_boundary)
    }

    fn waiter_aborted(&self, id: u64) -> Option<String> {
        self.waiters.get(&id).and_then(|w| w.aborted.clone())
    }

    fn abort_all(&mut self, reason: &str) {
        for waiter in self.waiters.values_mut() {
            waiter.aborted = Some(reason.to_string());
        }
    }

    pub fn waiter_count(&self) -> usize {
        self.waiters.len()
    }
}

struct Inner {
    state: Mutex<BufferState>,
    changed: watch::Sender<u64>,
}

/// Shared handle to one session's output buffer.
#[derive(Clone)]
pub struct OutputBuffer {
    inner: Arc<Inner>,
}

impl OutputBuffer {
    pub fn new(session_id: &str) -> Self {
        Self::with_capacity(session_id, DEFAULT_BUFFER_SIZE)
    }

    pub fn with_capacity(session_id: &str, max_size: usize) -> Self {
        let (changed, _) = watch::channel(0);
        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(BufferState::new(session_id, max_size)),
                changed,
            }),
        }
    }

    fn notify(&self) {
        self.inner.changed.send_modify(|v| *v = v.wrapping_add(1));
    }

    /// Run `f` on the locked state. The buffer counts as changed afterwards
    /// (waiters re-check).
    pub fn with_state<T>(&self, f: impl FnOnce(&mut BufferState) -> T) -> T {
        let result = f(&mut self.inner.state.lock());
        self.notify();
        result
    }

    pub fn append(&self, data: &str) {
        if data.is_empty() {
            return;
        }
        self.inner.state.lock().append(data);
        self.notify();
    }

    pub fn text(&self) -> String {
        self.inner.state.lock().text().to_string()
    }

    pub fn text_len(&self) -> usize {
        self.inner.state.lock().text().len()
    }

    pub fn scan_offset(&self) -> usize {
        self.inner.state.lock().scan_offset()
    }

    pub fn replace_with_visible_screen(
        &self,
        screen_text: &str,
        trailing_fresh: &str,
        sync_start_text: &str,
    ) {
        self.inner.state.lock().replace_with_visible_screen(
            screen_text,
            trailing_fresh,
            sync_start_text,
        );
        self.notify();
    }

    pub fn invalidate_startup_seed(&self) {
        self.inner.state.lock().invalidate_startup_seed();
    }

    pub fn consume_through_absolute(&self, absolute_length: usize) {
        self.inner
            .state
            .lock()
            .consume_through_absolute(absolute_length);
    }

    pub fn mark_current_output_consumed(&self, preserve_tail_patterns: &[WaitPattern]) {
        self.inner
            .state
            .lock()
            .mark_current_output_consumed(preserve_tail_patterns);
    }

    pub fn mark_output_consumed_through(&self, length: usize, preserve_tail_patterns: &[WaitPattern]) {
        self.inner
            .state
            .lock()
            .mark_output_consumed_through(length, preserve_tail_patterns);
    }

    pub fn clear(&self) {
        self.inner.state.lock().clear();
        self.notify();
    }

    /// Reject every pending wait with `reason` (`"Script stopped"`).
    pub fn abort_waiters(&self, reason: &str) {
        self.inner.state.lock().abort_all(reason);
        self.notify();
    }

    /// Reject pending waits with `"Session output buffer disposed"` and drop
    /// the contents.
    pub fn dispose(&self) {
        let mut state = self.inner.state.lock();
        state.abort_all("Session output buffer disposed");
        state.clear();
        drop(state);
        self.notify();
    }

    pub fn waiter_count(&self) -> usize {
        self.inner.state.lock().waiter_count()
    }

    /// Generic wait loop: `check` runs under the lock with the waiter's
    /// current fresh boundary and consumes a match when it finds one.
    async fn wait_with<T>(
        &self,
        label: &str,
        timeout_ms: u64,
        should_abort: Option<AbortCheck>,
        fresh_boundary: Option<usize>,
        mut check: impl FnMut(&mut BufferState, Option<usize>) -> Result<Option<T>, PatternError>,
    ) -> Result<T, WaitError> {
        let mut rx = self.inner.changed.subscribe();
        let waiter = self.inner.state.lock().register_waiter(fresh_boundary);
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        let result = loop {
            {
                let mut state = self.inner.state.lock();
                if let Some(reason) = state.waiter_aborted(waiter) {
                    break Err(WaitError::Aborted(reason));
                }
                let boundary = state.waiter_boundary(waiter);
                match check(&mut state, boundary) {
                    Ok(Some(value)) => break Ok(value),
                    Ok(None) => {}
                    Err(err) => break Err(WaitError::Pattern(err)),
                }
            }
            if should_abort.as_ref().is_some_and(|f| f()) {
                break Err(WaitError::Aborted("Script stopped".into()));
            }
            tokio::select! {
                _ = rx.changed() => {}
                _ = tokio::time::sleep(ABORT_POLL_INTERVAL) => {}
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {
                    break Err(WaitError::Timeout(format!("{label} timed out after {timeout_ms}ms")));
                }
            }
        };
        self.inner.state.lock().waiters.remove(&waiter);
        result
    }

    /// `waitFor`: string → literal (or `/body/flags` regex); RegExp → regex
    /// with stale-core protection.
    pub async fn wait_for(
        &self,
        pattern: &WaitPattern,
        timeout_ms: u64,
        should_abort: Option<AbortCheck>,
    ) -> Result<String, WaitError> {
        let fresh_boundary = self.inner.state.lock().current_fresh_boundary();
        if pattern.is_regex() {
            return self
                .wait_with("waitFor", timeout_ms, should_abort, Some(fresh_boundary), |state, boundary| {
                    let matched = state.consume_fresh_pending_regex(pattern, boundary)?;
                    Ok(matched.map(|m| {
                        state.advance_scan_offset(m.end_offset);
                        m.value
                    }))
                })
                .await;
        }
        self.wait_with("waitFor", timeout_ms, should_abort, Some(fresh_boundary), |state, boundary| {
            let boundary = boundary.unwrap_or_else(|| state.current_fresh_boundary());
            let matched = state.consume_fresh_pending_match(pattern, boundary)?;
            Ok(matched.map(|m| {
                state.advance_scan_offset(m.end_offset);
                m.value
            }))
        })
        .await
    }

    pub async fn wait_for_text(
        &self,
        pattern: &WaitPattern,
        timeout_ms: u64,
        should_abort: Option<AbortCheck>,
    ) -> Result<String, WaitError> {
        let fresh_boundary = self.inner.state.lock().current_fresh_boundary();
        self.wait_with("waitForText", timeout_ms, should_abort, Some(fresh_boundary), |state, boundary| {
            let boundary = boundary.unwrap_or_else(|| state.current_fresh_boundary());
            let matched = state.consume_fresh_pending_text(pattern, boundary)?;
            Ok(matched.map(|m| {
                state.advance_scan_offset(m.end_offset);
                m.value
            }))
        })
        .await
    }

    pub async fn wait_for_regex(
        &self,
        pattern: &WaitPattern,
        timeout_ms: u64,
        should_abort: Option<AbortCheck>,
    ) -> Result<String, WaitError> {
        let fresh_boundary = self.inner.state.lock().current_fresh_boundary();
        self.wait_with("waitForRegex", timeout_ms, should_abort, Some(fresh_boundary), |state, boundary| {
            let matched = state.consume_fresh_pending_regex(pattern, boundary)?;
            Ok(matched.map(|m| {
                state.advance_scan_offset(m.end_offset);
                m.value
            }))
        })
        .await
    }

    /// `waitForAny`: index of the first pattern that matches fresh output.
    /// `allow_preserved_tail_match` (waitForPrompt) also accepts the startup
    /// prompt preserved by the seeded viewport, once.
    pub async fn wait_for_any(
        &self,
        patterns: &[WaitPattern],
        timeout_ms: u64,
        should_abort: Option<AbortCheck>,
        allow_preserved_tail_match: bool,
    ) -> Result<usize, WaitError> {
        if patterns.is_empty() {
            return Err(WaitError::Pattern(PatternError::Type(
                "waitForAny requires a non-empty patterns array".into(),
            )));
        }
        let fresh_boundary = {
            let mut state = self.inner.state.lock();
            if allow_preserved_tail_match {
                if let Some(preserved) = state.consume_preserved_tail_match_any(patterns)? {
                    return Ok(preserved.index);
                }
                state.current_tail_fresh_boundary()
            } else {
                state.current_fresh_boundary()
            }
        };
        self.wait_with("waitForAny", timeout_ms, should_abort, Some(fresh_boundary), |state, boundary| {
            if allow_preserved_tail_match {
                if let Some(preserved) = state.consume_preserved_tail_match_any(patterns)? {
                    return Ok(Some(preserved.index));
                }
            }
            let boundary = boundary.unwrap_or_else(|| state.current_fresh_boundary());
            let fresh = state.consume_fresh_pending_match_any(patterns, boundary)?;
            Ok(fresh.map(|f| {
                state.advance_scan_offset(f.matched.end_offset);
                f.index
            }))
        })
        .await
    }
}

/// Registry of per-session buffers (`getOrCreateBuffer` / `removeSessionBuffer`).
#[derive(Default)]
pub struct BufferRegistry {
    buffers: Mutex<HashMap<String, OutputBuffer>>,
}

impl BufferRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get_or_create(&self, session_id: &str) -> OutputBuffer {
        self.buffers
            .lock()
            .entry(session_id.to_string())
            .or_insert_with(|| OutputBuffer::new(session_id))
            .clone()
    }

    pub fn get(&self, session_id: &str) -> Option<OutputBuffer> {
        self.buffers.lock().get(session_id).cloned()
    }

    pub fn append(&self, session_id: &str, data: &str) {
        self.get_or_create(session_id).append(data);
    }

    pub fn remove(&self, session_id: &str) {
        if let Some(buffer) = self.buffers.lock().remove(session_id) {
            buffer.dispose();
        }
    }

    pub fn contains(&self, session_id: &str) -> bool {
        self.buffers.lock().contains_key(session_id)
    }
}
