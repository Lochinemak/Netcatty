//! Streaming charset handling for terminal sessions.
//!
//! Mirrors `electron/bridges/terminalEncoding.cjs`: the renderer picks a
//! charset label per session, output bytes are decoded with a *streaming*
//! decoder (multi-byte sequences split across two reads are reassembled)
//! and input text is encoded back into the same charset.
//!
//! Supported labels: `utf-8` (default), `gb18030` (+ `gbk`, `gb2312`,
//! `cp936`), `big5`, `shift_jis`, `euc-kr`, `latin1` / `iso-8859-1`.
//! Unknown labels fall back to UTF-8.

use encoding_rs::{CoderResult, Decoder, Encoding};

pub const DEFAULT_CHARSET: &str = "utf-8";

/// Which decoder backs a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Charset {
    /// A WHATWG encoding handled by `encoding_rs`.
    Encoding(&'static Encoding),
    /// True ISO-8859-1 (byte == code point). `encoding_rs` maps the
    /// `latin1` label to windows-1252, which differs in `0x80..=0x9F`, so it
    /// is handled by hand to match the Electron (`iconv-lite`) behaviour.
    Latin1,
}

impl Charset {
    /// Normalised label of this charset (what `netcatty:data` was decoded with).
    pub fn label(self) -> &'static str {
        match self {
            Charset::Latin1 => "latin1",
            Charset::Encoding(e) => e.name(),
        }
    }
}

/// Resolve a renderer charset label. `None`/empty → UTF-8.
pub fn resolve_charset(label: Option<&str>) -> Charset {
    let normalized = label
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
        .replace('_', "-");
    match normalized.as_str() {
        "" | "utf8" | "utf-8" => Charset::Encoding(encoding_rs::UTF_8),
        "gb18030" | "gbk" | "gb2312" | "cp936" | "ms936" | "gb-18030" => {
            Charset::Encoding(encoding_rs::GB18030)
        }
        "big5" | "big-5" | "cp950" => Charset::Encoding(encoding_rs::BIG5),
        "shift-jis" | "shiftjis" | "sjis" | "cp932" | "ms932" => {
            Charset::Encoding(encoding_rs::SHIFT_JIS)
        }
        "euc-kr" | "euckr" | "cp949" => Charset::Encoding(encoding_rs::EUC_KR),
        "latin1" | "latin-1" | "iso-8859-1" | "iso8859-1" | "l1" => Charset::Latin1,
        other => match Encoding::for_label(other.as_bytes()) {
            Some(e) => Charset::Encoding(e),
            None => Charset::Encoding(encoding_rs::UTF_8),
        },
    }
}

/// Encode input text for the remote side with the session charset.
pub fn encode_input(charset: Charset, text: &str) -> Vec<u8> {
    match charset {
        Charset::Latin1 => text
            .chars()
            .map(|c| if (c as u32) < 0x100 { c as u8 } else { b'?' })
            .collect(),
        Charset::Encoding(e) => {
            if e == encoding_rs::UTF_8 {
                return text.as_bytes().to_vec();
            }
            // `Encoding::encode` picks the output encoding for this encoding
            // (UTF-8 for replacement/UTF-16, otherwise the encoding itself)
            // and substitutes unmappable chars with numeric references.
            let (bytes, _, _) = e.encode(text);
            bytes.into_owned()
        }
    }
}

/// A stateful decoder for one session's output stream.
pub struct StreamDecoder {
    charset: Charset,
    inner: Option<Decoder>,
    finished: bool,
}

impl StreamDecoder {
    pub fn new(label: Option<&str>) -> Self {
        let charset = resolve_charset(label);
        let inner = match charset {
            Charset::Encoding(e) => Some(e.new_decoder_without_bom_handling()),
            Charset::Latin1 => None,
        };
        Self {
            charset,
            inner,
            finished: false,
        }
    }

    pub fn charset(&self) -> Charset {
        self.charset
    }

    /// Decode `bytes`. With `last == false` an incomplete trailing sequence is
    /// retained until the next call; with `last == true` it is flushed as a
    /// replacement character and the decoder must not be used again.
    pub fn decode(&mut self, bytes: &[u8], last: bool) -> String {
        if self.finished {
            // Defensive: a finished decoder yields nothing more.
            return String::new();
        }
        if last {
            self.finished = true;
        }
        match &mut self.inner {
            None => bytes.iter().map(|&b| b as char).collect(),
            Some(dec) => decode_with(dec, bytes, last),
        }
    }
}

fn decode_with(dec: &mut Decoder, src: &[u8], last: bool) -> String {
    let mut out = String::with_capacity(
        dec.max_utf8_buffer_length(src.len())
            .unwrap_or(src.len().saturating_mul(3) + 16),
    );
    let mut offset = 0usize;
    loop {
        let (result, read, _had_errors) = dec.decode_to_string(&src[offset..], &mut out, last);
        offset += read;
        match result {
            CoderResult::InputEmpty => break,
            CoderResult::OutputFull => {
                let more = dec
                    .max_utf8_buffer_length(src.len() - offset)
                    .unwrap_or(1024)
                    .max(16);
                out.reserve(more);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf8_sequence_split_across_chunks() {
        let mut d = StreamDecoder::new(None);
        // "é" = C3 A9; "中" = E4 B8 AD
        let a = d.decode(&[b'a', 0xC3], false);
        let b = d.decode(&[0xA9, 0xE4, 0xB8], false);
        let c = d.decode(&[0xAD, b'!'], false);
        assert_eq!(a, "a");
        assert_eq!(b, "é");
        assert_eq!(c, "中!");
        assert_eq!(d.decode(&[], true), "");
    }

    #[test]
    fn gb18030_sequence_split_across_chunks() {
        let mut d = StreamDecoder::new(Some("gb18030"));
        // "中文" in GB18030/GBK: D6 D0 CE C4
        let a = d.decode(&[0xD6], false);
        let b = d.decode(&[0xD0, 0xCE], false);
        let c = d.decode(&[0xC4], false);
        assert_eq!(a, "");
        assert_eq!(b, "中");
        assert_eq!(c, "文");
    }

    #[test]
    fn gb18030_four_byte_sequence_split() {
        // Supplementary-plane characters always take the four-byte GB18030
        // form. Derive the bytes from the encoder so the test cannot drift
        // from the mapping table, then split them 2 + 2.
        let (bytes, _, _) = encoding_rs::GB18030.encode("😀");
        assert_eq!(bytes.len(), 4);
        let mut d = StreamDecoder::new(Some("gbk"));
        let a = d.decode(&bytes[..2], false);
        let b = d.decode(&bytes[2..], false);
        assert_eq!(a, "");
        assert_eq!(b, "😀");
    }

    #[test]
    fn truncated_sequence_flushes_replacement_on_last() {
        let mut d = StreamDecoder::new(None);
        assert_eq!(d.decode(&[0xE4, 0xB8], false), "");
        assert_eq!(d.decode(&[], true), "\u{FFFD}");
        assert_eq!(d.decode(b"ignored", false), "");
    }

    #[test]
    fn label_normalisation() {
        assert_eq!(
            resolve_charset(Some("GBK")),
            Charset::Encoding(encoding_rs::GB18030)
        );
        assert_eq!(
            resolve_charset(Some("gb2312")),
            Charset::Encoding(encoding_rs::GB18030)
        );
        assert_eq!(
            resolve_charset(Some("Shift_JIS")),
            Charset::Encoding(encoding_rs::SHIFT_JIS)
        );
        assert_eq!(
            resolve_charset(Some("euc-kr")),
            Charset::Encoding(encoding_rs::EUC_KR)
        );
        assert_eq!(
            resolve_charset(Some("big5")),
            Charset::Encoding(encoding_rs::BIG5)
        );
        assert_eq!(resolve_charset(Some("ISO-8859-1")), Charset::Latin1);
        assert_eq!(resolve_charset(Some("latin1")), Charset::Latin1);
        assert_eq!(
            resolve_charset(Some("utf8")),
            Charset::Encoding(encoding_rs::UTF_8)
        );
        assert_eq!(
            resolve_charset(Some("nonsense-charset")),
            Charset::Encoding(encoding_rs::UTF_8)
        );
        assert_eq!(resolve_charset(None), Charset::Encoding(encoding_rs::UTF_8));
    }

    #[test]
    fn latin1_is_true_iso_8859_1() {
        let mut d = StreamDecoder::new(Some("latin1"));
        assert_eq!(d.decode(&[0xE9, 0x80, 0x41], false), "é\u{80}A");
        assert_eq!(encode_input(Charset::Latin1, "é€"), vec![0xE9, b'?']);
    }

    #[test]
    fn input_encoding_round_trips() {
        let gb = resolve_charset(Some("gb18030"));
        assert_eq!(encode_input(gb, "中"), vec![0xD6, 0xD0]);
        let utf8 = resolve_charset(None);
        assert_eq!(encode_input(utf8, "中"), "中".as_bytes().to_vec());
    }
}
