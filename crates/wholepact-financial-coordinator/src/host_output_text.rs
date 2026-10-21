//! Bounded observation-only Host output text. No terminal interpreter, input,
//! prompt recognizer, command emitter, authority or runtime callsite exists here.
//! LF stays a line break; backslashes and all nonprinting controls are visible
//! escapes. Invalid UTF-8 is shown byte-for-byte, never replacement characters.
//! Only an incomplete UTF-8 suffix (at most three bytes) spans input chunks.
//!
//! The future caller MUST latch shared/local R on any error. Fixed transcript
//! overflow fails the entire stream; it never scrolls away or truncates retained
//! bytes to claim a successful complete transcript. Security/outcome transport
//! remains separate. Owned storage is zeroizing; GUI/OS copies are not covered.
#![allow(dead_code)] // Deliberately no endpoint or App callsite.

use zeroize::{Zeroize, Zeroizing};

const MAX_CHUNK: usize = 4096;
const MAX_RAW: usize = 256 * 1024;
const MAX_TEXT: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum OutputFailure {
    Closed,
    ChunkTooLarge,
    RawLimit,
    TextLimit,
    InvalidCarry,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum OutputState {
    Open,
    Eof,
    Failed(OutputFailure),
}

pub(super) struct HostOutputText {
    text: Zeroizing<String>,
    carry: Zeroizing<Vec<u8>>,
    raw_bytes: usize,
    raw_limit: usize,
    text_limit: usize,
    state: OutputState,
}
impl HostOutputText {
    pub(super) fn new() -> Self {
        Self {
            text: Zeroizing::new(String::new()),
            carry: Zeroizing::new(Vec::with_capacity(3)),
            raw_bytes: 0,
            raw_limit: MAX_RAW,
            text_limit: MAX_TEXT,
            state: OutputState::Open,
        }
    }
    pub(super) fn text(&self) -> &str {
        &self.text
    }
    pub(super) fn state(&self) -> OutputState {
        self.state
    }

    /// Consume one real bounded output chunk. Never log or interpret its text.
    /// Failed chunks are not partially committed to a purportedly valid stream.
    pub(super) fn push_chunk(&mut self, chunk: Zeroizing<Vec<u8>>) -> Result<(), OutputFailure> {
        self.require_open()?;
        if chunk.len() > MAX_CHUNK {
            return self.fail(OutputFailure::ChunkTooLarge);
        }
        let Some(total) = self
            .raw_bytes
            .checked_add(chunk.len())
            .filter(|n| *n <= self.raw_limit)
        else {
            return self.fail(OutputFailure::RawLimit);
        };
        if self.carry.len() > 3 {
            return self.fail(OutputFailure::InvalidCarry);
        }
        // Both the bounded joined bytes and incoming original have zeroizing
        // owners. No unbounded retained raw transcript or lossy decoder exists.
        let mut bytes = std::mem::take(&mut self.carry);
        bytes.extend_from_slice(&chunk);
        let (escaped, carry) = match escaped_chunk(&bytes) {
            Ok(value) => value,
            Err(error) => return self.fail(error),
        };
        if self
            .text
            .len()
            .checked_add(escaped.len())
            .is_none_or(|n| n > self.text_limit)
        {
            return self.fail(OutputFailure::TextLimit);
        }
        self.text.push_str(&escaped);
        self.carry = carry;
        self.raw_bytes = total;
        Ok(())
    }

    /// End this one stream; show any incomplete suffix as its exact raw bytes.
    /// EOF is observation only, never successful Host work or source disposal.
    pub(super) fn finish_eof(&mut self) -> Result<(), OutputFailure> {
        self.require_open()?;
        let mut escaped = Zeroizing::new(String::new());
        for byte in &*self.carry {
            escape_byte(&mut escaped, *byte);
        }
        if self
            .text
            .len()
            .checked_add(escaped.len())
            .is_none_or(|n| n > self.text_limit)
        {
            return self.fail(OutputFailure::TextLimit);
        }
        self.text.push_str(&escaped);
        self.carry.zeroize();
        self.state = OutputState::Eof;
        Ok(())
    }
    /// Explicit terminal UI cleanup. Never restart/reset this stream in place.
    pub(super) fn clear_and_close(&mut self) {
        self.text.zeroize();
        self.carry.zeroize();
        self.state = OutputState::Failed(OutputFailure::Closed);
    }
    fn require_open(&self) -> Result<(), OutputFailure> {
        match self.state {
            OutputState::Open => Ok(()),
            OutputState::Eof => Err(OutputFailure::Closed),
            OutputState::Failed(error) => Err(error),
        }
    }
    fn fail(&mut self, error: OutputFailure) -> Result<(), OutputFailure> {
        self.carry.zeroize();
        self.state = OutputState::Failed(error);
        // Keep only the prior, complete bounded text for an explicit failure
        // display. There is no successful truncation, rotation or auto-retry.
        Err(error)
    }
}

fn escaped_chunk(bytes: &[u8]) -> Result<(Zeroizing<String>, Zeroizing<Vec<u8>>), OutputFailure> {
    let mut text = Zeroizing::new(String::new());
    let mut remaining = bytes;
    let mut carry = Zeroizing::new(Vec::with_capacity(3));
    loop {
        match std::str::from_utf8(remaining) {
            Ok(valid) => {
                escape_text(&mut text, valid);
                break;
            }
            Err(error) => {
                let (prefix, rest) = remaining.split_at(error.valid_up_to());
                let prefix =
                    std::str::from_utf8(prefix).map_err(|_| OutputFailure::InvalidCarry)?;
                escape_text(&mut text, prefix);
                match error.error_len() {
                    Some(length) => {
                        for byte in &rest[..length] {
                            escape_byte(&mut text, *byte);
                        }
                        remaining = &rest[length..];
                    }
                    None => {
                        if rest.len() > 3 {
                            return Err(OutputFailure::InvalidCarry);
                        }
                        carry.extend_from_slice(rest);
                        break;
                    }
                }
            }
        }
    }
    Ok((text, carry))
}
fn escape_text(out: &mut String, text: &str) {
    for character in text.chars() {
        match character {
            '\n' => out.push('\n'),
            '\\' => out.push_str("\\\\"),
            '\x20'..='\x7e' => out.push(character),
            // Stable std char escaping uses the compiler's Unicode tables for
            // controls, format/default-ignorable/bidi controls, nonspacing marks
            // and unassigned codepoints. Do not invent a partial Cf range list.
            // https://doc.rust-lang.org/std/primitive.char.html#method.escape_debug
            _ => out.extend(character.escape_debug()),
        }
    }
}
fn escape_byte(out: &mut String, byte: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push_str("\\x");
    out.push(HEX[usize::from(byte >> 4)] as char);
    out.push(HEX[usize::from(byte & 15)] as char);
}

#[cfg(test)]
mod tests {
    use super::*;
    // Public synthetic text/bytes only. No GUI, terminal, endpoint or filesystem.
    fn chunk(bytes: &[u8]) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(bytes.to_vec())
    }
    fn limited(raw: usize, text: usize) -> HostOutputText {
        let mut value = HostOutputText::new();
        value.raw_limit = raw;
        value.text_limit = text;
        value
    }
    #[test]
    fn utf8_is_identical_across_every_chunk_split_and_carry_never_exceeds_three() {
        let sample = "Synthetic é 東京 🙂\nnext";
        for at in 0..=sample.len() {
            let mut output = HostOutputText::new();
            output.push_chunk(chunk(&sample.as_bytes()[..at])).unwrap();
            assert!(output.carry.len() <= 3);
            output.push_chunk(chunk(&sample.as_bytes()[at..])).unwrap();
            output.finish_eof().unwrap();
            assert_eq!(output.text(), sample);
            assert!(output.carry.is_empty());
        }
    }
    #[test]
    fn control_escapes_and_literal_backslashes_are_unambiguous_not_executed() {
        let mut output = HostOutputText::new();
        output
            .push_chunk(chunk(b"before\r\n\x1b[2J\t\\x1b\0after"))
            .unwrap();
        output.finish_eof().unwrap();
        assert_eq!(output.text(), "before\\r\n\\u{1b}[2J\\t\\\\x1b\\0after");
        assert!(!output.text().contains('\x1b') && !output.text().contains('\r'));
    }
    #[test]
    fn nonprinting_unicode_format_and_bidi_controls_are_visible() {
        for control in [
            '\u{ad}',
            '\u{61c}',
            '\u{6dd}',
            '\u{200b}',
            '\u{200d}',
            '\u{202e}',
            '\u{2066}',
            '\u{2069}',
            '\u{feff}',
            '\u{fff9}',
            '\u{13432}',
            '\u{e0001}',
            '\u{e0041}',
        ] {
            let mut output = HostOutputText::new();
            let input = format!("before{control}after");
            output.push_chunk(chunk(input.as_bytes())).unwrap();
            output.finish_eof().unwrap();
            assert!(!output.text().contains(control));
            assert!(output.text().starts_with("before\\u{") && output.text().ends_with("}after"));
        }
    }
    #[test]
    fn invalid_utf8_is_exact_bytes_without_replacement_or_normalization() {
        let mut output = HostOutputText::new();
        output
            .push_chunk(chunk(&[b'A', 0xf0, 0x28, 0x8c, 0x28, 0xc0, 0xaf, 0xff]))
            .unwrap();
        output.finish_eof().unwrap();
        assert_eq!(output.text(), "A\\xf0(\\x8c(\\xc0\\xaf\\xff");
        assert!(!output.text().contains('\u{fffd}'));
    }
    #[test]
    fn incomplete_eof_suffix_is_visible_and_no_later_chunk_can_reopen() {
        for length in 1..=3 {
            let bytes = [0xf0, 0x9f, 0x99];
            let mut output = HostOutputText::new();
            output.push_chunk(chunk(&bytes[..length])).unwrap();
            assert!(output.text().is_empty());
            output.finish_eof().unwrap();
            let mut expected = String::new();
            for byte in &bytes[..length] {
                escape_byte(&mut expected, *byte);
            }
            assert_eq!(output.text(), expected);
            assert_eq!(output.state(), OutputState::Eof);
            assert_eq!(
                output.push_chunk(chunk(b"late")),
                Err(OutputFailure::Closed)
            );
        }
    }
    #[test]
    fn raw_and_text_overflow_are_terminal_not_transcript_rotation() {
        let mut output = limited(3, 20);
        output.push_chunk(chunk(b"abc")).unwrap();
        assert_eq!(output.push_chunk(chunk(b"d")), Err(OutputFailure::RawLimit));
        assert_eq!(output.text(), "abc");
        assert_eq!(output.push_chunk(chunk(b"")), Err(OutputFailure::RawLimit));
        let mut output = limited(20, 3);
        output.push_chunk(chunk(b"ok")).unwrap();
        assert_eq!(
            output.push_chunk(chunk(&[0xff])),
            Err(OutputFailure::TextLimit)
        );
        assert_eq!(output.text(), "ok");
        assert_eq!(
            output.state(),
            OutputState::Failed(OutputFailure::TextLimit)
        );
    }
    #[test]
    fn oversized_chunk_fails_without_partial_commit_and_eof_can_also_hit_cap() {
        let mut output = HostOutputText::new();
        assert_eq!(
            output.push_chunk(chunk(&vec![b'x'; MAX_CHUNK + 1])),
            Err(OutputFailure::ChunkTooLarge)
        );
        assert!(output.text().is_empty());
        let mut output = limited(20, 3);
        output.push_chunk(chunk(&[0xf0])).unwrap();
        assert_eq!(output.finish_eof(), Err(OutputFailure::TextLimit));
        assert!(output.carry.is_empty() && output.text().is_empty());
    }
    #[test]
    fn explicit_clear_closes_owned_storage_without_resetting_stream_count() {
        let mut output = HostOutputText::new();
        output.push_chunk(chunk(b"synthetic")).unwrap();
        let count = output.raw_bytes;
        output.clear_and_close();
        assert!(output.text().is_empty() && output.carry.is_empty());
        assert_eq!(output.raw_bytes, count);
        assert_eq!(
            output.push_chunk(chunk(b"again")),
            Err(OutputFailure::Closed)
        );
    }
}
