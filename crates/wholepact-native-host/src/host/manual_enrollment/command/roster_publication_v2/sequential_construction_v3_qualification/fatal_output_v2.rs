//! Finite lexical observations from existing complete PTY lines, never a cause.
//! No raw text, locations, names, sizes, IO, clocks or authority are retained.
use serde::Serialize;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub(super) struct Observation {
    state: &'static str,
    observed_bits: Option<u8>,
}
impl Observation {
    pub(super) const fn withheld() -> Self {
        Self { state: "withheld", observed_bits: None }
    }
    pub(super) fn for_process(self, verified: bool) -> Self {
        if verified { self } else { Self::withheld() }
    }
}

#[derive(Default)]
pub(super) struct Capture {
    bits: u8,
    incomplete: bool,
}
impl Capture {
    pub(super) fn lost(&mut self) { self.incomplete = true; }
    pub(super) fn observe(&mut self, complete_line: &[u8]) {
        let line = complete_line.strip_suffix(b"\r").unwrap_or(complete_line);
        self.bits |= line_bits(line);
    }
    pub(super) fn observation(&self, verified: bool) -> Observation {
        if !verified { return Observation::withheld(); }
        Observation {
            state: if self.incomplete { "incomplete" } else { "complete" },
            observed_bits: Some(self.bits),
        }
    }
}

fn decimal(value: &[u8]) -> bool {
    !value.is_empty() && value.len() <= 20 && value.iter().all(u8::is_ascii_digit)
}
fn printable(value: &[u8], limit: usize) -> bool {
    !value.is_empty() && value.len() <= limit && value.iter().all(|b| (b' '..=b'~').contains(b))
}
fn panic_header(line: &[u8]) -> bool {
    let Some(rest) = line.strip_prefix(b"thread '") else { return false; };
    let Some(end_name) = rest.iter().position(|b| *b == b'\'') else { return false; };
    if !printable(&rest[..end_name], 128) { return false; }
    let mut rest = &rest[end_name + 1..];
    if let Some(pid) = rest.strip_prefix(b" (") {
        let Some(end_pid) = pid.iter().position(|b| *b == b')') else { return false; };
        if !decimal(&pid[..end_pid]) { return false; }
        rest = &pid[end_pid + 1..];
    }
    let Some(location) = rest.strip_prefix(b" panicked at ").and_then(|s| s.strip_suffix(b":")) else { return false; };
    let Some(column_separator) = location.iter().rposition(|b| *b == b':') else { return false; };
    if !decimal(&location[column_separator + 1..]) { return false; }
    let location = &location[..column_separator];
    let Some(line_separator) = location.iter().rposition(|b| *b == b':') else { return false; };
    decimal(&location[line_separator + 1..]) && printable(&location[..line_separator], 4096)
}
fn line_bits(line: &[u8]) -> u8 {
    if line == b"fatal runtime error: stack overflow, aborting" { return 1; }
    if panic_header(line) { return 2; }
    if line.strip_prefix(b"memory allocation of ")
        .and_then(|s| s.strip_suffix(b" bytes failed")).is_some_and(decimal) { return 4; }
    if matches!(line,
        b"thread caused non-unwinding panic. aborting."
        | b"thread caused panic while panicking. aborting."
        | b"panic in a destructor during cleanup"
        | b"fatal runtime error: Rust panics must be rethrown, aborting"
        | b"fatal runtime error: Rust cannot catch foreign exceptions, aborting") { return 8; }
    0
}
