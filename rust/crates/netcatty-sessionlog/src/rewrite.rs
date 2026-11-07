//! Hide Netcatty's own injected commands from session logs.
//!
//! * [`ProgrammaticCommandLogRewriter`] (Electron: `programmaticCommandLog.cjs`)
//!   replaces the shell echo of a command Netcatty typed on the user's behalf
//!   (directory-tracking setup, protected snippets) with its display form.
//! * [`SudoAutofill`] (Electron: the sudo helpers in
//!   `sessionLogStreamManager.cjs`) removes the `sudo -p '…__NETCATTY_SUDO_x__'`
//!   prompt marker the renderer's sudo password autofill relies on.
//!
//! Offsets are byte offsets on UTF-8 strings; every split happens on a char
//! boundary, so behaviour matches the UTF-16 JavaScript version.

use regex::Regex;
use std::sync::OnceLock;

#[derive(Debug, Clone)]
struct Rewrite {
    sent_command: String,
    display_command: String,
}

/// Longest suffix of `value` that is a proper prefix of `prefix`.
fn longest_suffix_matching_prefix(value: &str, prefix: &str) -> usize {
    let max = value.len().min(prefix.len().saturating_sub(1));
    for length in (1..=max).rev() {
        let start = value.len() - length;
        if !value.is_char_boundary(start) {
            continue;
        }
        if prefix.as_bytes().starts_with(&value.as_bytes()[start..]) {
            return length;
        }
    }
    0
}

/// Streaming rewriter for programmatic command echoes.
#[derive(Debug, Default, Clone)]
pub struct ProgrammaticCommandLogRewriter {
    pending: String,
    rewrites: Vec<Rewrite>,
}

impl ProgrammaticCommandLogRewriter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue a rewrite; ignored when `sent_command` is empty.
    pub fn queue_rewrite(&mut self, sent_command: &str, display_command: &str) {
        if sent_command.is_empty() {
            return;
        }
        self.rewrites.push(Rewrite {
            sent_command: sent_command.to_string(),
            display_command: display_command.to_string(),
        });
    }

    /// Feed output; returns what can be logged now. A tail that may be the
    /// start of a queued command is held back until it is decided.
    pub fn append(&mut self, input: &str) -> String {
        if input.is_empty() {
            return String::new();
        }
        let mut data = std::mem::take(&mut self.pending);
        data.push_str(input);
        if self.rewrites.is_empty() {
            return data;
        }

        let mut output = String::new();
        while !data.is_empty() && !self.rewrites.is_empty() {
            // Earliest match; ties go to the earlier queued rewrite.
            let earliest = self
                .rewrites
                .iter()
                .enumerate()
                .filter_map(|(i, r)| data.find(&r.sent_command).map(|index| (index, i)))
                .min();
            if let Some((index, rewrite_index)) = earliest {
                let rewrite = self.rewrites.remove(rewrite_index);
                output.push_str(&data[..index]);
                output.push_str(&rewrite.display_command);
                data = data[index + rewrite.sent_command.len()..].to_string();
                continue;
            }

            let retained = self
                .rewrites
                .iter()
                .map(|r| longest_suffix_matching_prefix(&data, &r.sent_command))
                .max()
                .unwrap_or(0);
            let emit_length = data.len() - retained;
            output.push_str(&data[..emit_length]);
            self.pending = data[emit_length..].to_string();
            return output;
        }
        output.push_str(&data);
        output
    }

    /// End of stream: release the held tail and drop queued rewrites.
    pub fn finish(&mut self) -> String {
        self.rewrites.clear();
        std::mem::take(&mut self.pending)
    }
}

#[derive(Debug, Clone)]
struct SudoRewrite {
    marker: String,
    prepared_command: String,
    original_command: String,
}

fn sudo_rewrite_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\x15?((?:builtin\s+|command\s+)?sudo)\s+-p\s+'\[sudo\] password for %p: (__NETCATTY_SUDO_[a-z0-9_]+__)'([^\r\n]*)(?:\r\n|\r|\n|$)",
        )
        .expect("valid regex")
    })
}

fn sudo_marker_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)__NETCATTY_SUDO_[a-z0-9_]+__").expect("valid regex"))
}

/// Sudo autofill sanitizer state for one stream.
#[derive(Debug, Default, Clone)]
pub struct SudoAutofill {
    rewrites: Vec<SudoRewrite>,
    pending: String,
}

impl SudoAutofill {
    /// Remember the sudo command the renderer typed (`registerSudoAutofillInput`).
    /// Keeps the 8 most recent.
    pub fn register_input(&mut self, input: &str) {
        let Some(caps) = sudo_rewrite_pattern().captures(input) else {
            return;
        };
        let marker = caps[2].to_string();
        let rewrite = SudoRewrite {
            prepared_command: format!(
                "{} -p '[sudo] password for %p: {marker}'{}",
                &caps[1], &caps[3]
            ),
            original_command: format!("{}{}", &caps[1], &caps[3]),
            marker,
        };
        self.rewrites.insert(0, rewrite);
        self.rewrites.truncate(8);
    }

    /// Bytes held back waiting for a line break.
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    fn apply_rewrites(&self, data: &str) -> String {
        if data.is_empty() || self.rewrites.is_empty() {
            return data.to_string();
        }
        let mut next = data.to_string();
        for rewrite in &self.rewrites {
            next = next.replace(&rewrite.prepared_command, &rewrite.original_command);
            next = next.replace(&rewrite.marker, "");
        }
        sudo_marker_pattern().replace_all(&next, "").into_owned()
    }

    fn is_potential_command_pending(&self, data: &str) -> bool {
        if data.is_empty() {
            return true;
        }
        self.rewrites
            .iter()
            .any(|r| r.prepared_command.starts_with(data) || data.starts_with(&r.prepared_command))
    }

    fn has_marker_prefix(&self, data: &str) -> bool {
        if data.is_empty() {
            return false;
        }
        self.rewrites.iter().any(|r| {
            let max = data.len().min(r.marker.len().saturating_sub(1));
            (1..=max)
                .rev()
                .any(|length| data.as_bytes().ends_with(&r.marker.as_bytes()[..length]))
        })
    }

    /// Sanitize a chunk (`sanitizeSudoAutofillLogData`). Without registered
    /// rewrites the chunk passes through untouched; otherwise data is
    /// released line by line so a command / marker split across chunks is
    /// still recognised. `final_flush` releases everything.
    pub fn sanitize(&mut self, chunk: &str, final_flush: bool) -> String {
        if self.rewrites.is_empty() {
            return chunk.to_string();
        }
        self.pending.push_str(chunk);
        let last_line_break = self.pending.rfind(['\n', '\r']);
        if !final_flush && last_line_break.is_none() {
            if self.is_potential_command_pending(&self.pending)
                || self.has_marker_prefix(&self.pending)
            {
                return String::new();
            }
            let pending = std::mem::take(&mut self.pending);
            return self.apply_rewrites(&pending);
        }
        let ready_length = if final_flush {
            self.pending.len()
        } else {
            last_line_break.map(|i| i + 1).unwrap_or(0)
        };
        let ready: String = self.pending.drain(..ready_length).collect();
        self.apply_rewrites(&ready)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewriter_handles_split_commands() {
        let sent = "sh -c 'private setup' && eval 'wrapped command'";
        let display = "sudo apt update && sudo apt upgrade -y";
        let mut r = ProgrammaticCommandLogRewriter::new();
        r.queue_rewrite(sent, display);
        let mut out = r.append(&sent[..12]);
        out.push_str(&r.append(&format!("{}\r\nok\r\n", &sent[12..])));
        out.push_str(&r.finish());
        assert_eq!(out, format!("{display}\r\nok\r\n"));
    }

    #[test]
    fn rewriter_without_rewrites_passes_through() {
        let mut r = ProgrammaticCommandLogRewriter::new();
        assert_eq!(r.append("plain"), "plain");
        r.queue_rewrite("", "x");
        assert_eq!(r.append("中文"), "中文");
    }

    #[test]
    fn rewriter_holds_ambiguous_multibyte_tail() {
        let mut r = ProgrammaticCommandLogRewriter::new();
        r.queue_rewrite("中文命令", "");
        assert_eq!(r.append("前缀中文"), "前缀");
        assert_eq!(r.append("其他"), "中文其他");
    }

    #[test]
    fn suffix_prefix_respects_char_boundaries() {
        assert_eq!(longest_suffix_matching_prefix("abc", "bcd"), 2);
        assert_eq!(longest_suffix_matching_prefix("abc", "abc"), 0);
        assert_eq!(longest_suffix_matching_prefix("x中", "中文"), 3);
    }
}
