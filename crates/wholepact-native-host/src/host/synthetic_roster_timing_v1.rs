//! Fixed synthetic diagnostics only. No value here is an authority clock.
//! Offsets share one diagnostic origin; aggregate durations are inclusive.
//! ObservedReadRequest starts AFTER the original wall sample. Its diagnostic
//! offset has sampling skew and is NOT exact age, remaining authority, or an
//! upper bound; earlier original minimum ceilings remain independently binding.
#![cfg(all(test, feature = "synthetic-born-joined-qualification"))]
use serde::{Deserialize, Serialize};
use std::{cell::{Cell, RefCell}, io::Write, time::Instant};

pub(crate) const PREFIX: &str = "[JOINED_TIMING_V1 ";
pub(crate) const MAX_LINE: usize = 512;
const MAX_OFFSET: u64 = 900_000;
const MAX_TOTAL: u64 = 900_000_000;
const MAX_COUNT: u64 = 1_000_000;

macro_rules! names {
    ($name:ident { $($variant:ident),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
        pub(crate) enum $name { $($variant),+ }
        impl $name {
            const ALL: &'static [Self] = &[$(Self::$variant),+];
            fn parse(value: &str) -> Option<Self> {
                match value { $(stringify!($variant) => Some(Self::$variant),)+ _ => None }
            }
        }
    };
}
names! { Phase {
    ObservedReadRequest, ObservedReadAdmitted, ObservedReadOpen, ObservedReadPair,
    ObservedReadFinish, ObservedReadPark, ObservedBarrier,
    ConstructedPendingReview, ConstructedConsume, ConstructedSignerPark,
    ConstructedServerSeal, ConstructedCheckpoint, CompletionReentryFinish,
    CompletionConstructionFinish, CheckpointEngine
} }
names! { Ordinal { First, Second, All } }
names! { AggregatePhase {
    CompletionClaimCheck, CompletionClaimSign, CompletionClaimGranted,
    CompletionClaimClaim, CompletionClaimClaimed, CompletionClaimObserve,
    CompletionClaimHistory, CompletionClaimReentered, CompletionClaimSend,
    ConstructionReserve, ConstructionReservedAppend, ConstructionConsume,
    ConstructionConsumedAppend, ConstructionNamedOwner, ConstructionIntoNamed,
    ConstructionFinalOwner
} }
impl Phase {
    fn permits(self, ordinal: Ordinal) -> bool {
        let all = matches!(self, Self::ObservedBarrier | Self::ConstructedCheckpoint | Self::CheckpointEngine);
        all == (ordinal == Ordinal::All)
    }
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Landmark {
    phase: Phase,
    ordinal: Ordinal,
    start_ms: Option<u64>,
    end_ms: Option<u64>,
    errors: u8,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Aggregate {
    phase: AggregatePhase,
    started: u64,
    completed: u64,
    errors: u64,
    total_ms: u64,
    max_ms: u64,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
enum Record { Landmark(Landmark), Aggregate(Aggregate) }
const SLOT_COUNT: usize = Phase::ALL.len() * 3;
fn index(phase: Phase, ordinal: Ordinal) -> usize { phase as usize * 3 + ordinal as usize }
fn empty(phase: Phase, ordinal: Ordinal) -> Landmark {
    Landmark { phase, ordinal, start_ms: None, end_ms: None, errors: 0 }
}

struct Recorder {
    origin: Instant,
    ordinal: Ordinal,
    slots: [Option<Landmark>; SLOT_COUNT],
    invalid: bool,
}
impl Recorder {
    fn record(&mut self, phase: Phase, begin: bool, error: bool, elapsed: u64) {
        let ordinal = if matches!(phase, Phase::ObservedBarrier | Phase::ConstructedCheckpoint | Phase::CheckpointEngine) {
            Ordinal::All
        } else { self.ordinal };
        if !phase.permits(ordinal) || elapsed > MAX_OFFSET {
            self.invalid = true;
            return;
        }
        let slot = self.slots[index(phase, ordinal)].get_or_insert_with(|| empty(phase, ordinal));
        if begin {
            if slot.start_ms.is_some() { self.invalid = true; return; }
            slot.start_ms = Some(elapsed);
        } else {
            if slot.start_ms.is_none() || slot.end_ms.is_some() || Some(elapsed) < slot.start_ms {
                self.invalid = true;
                return;
            }
            slot.end_ms = Some(elapsed);
            slot.errors = u8::from(error);
        }
    }
}
thread_local! {
    static RECORDER: RefCell<Option<Recorder>> = const { RefCell::new(None) };
    static RECORDING_LOST: Cell<bool> = const { Cell::new(false) };
}
fn lost() { RECORDING_LOST.with(|flag| flag.set(true)); }
/// Enable only once in the actual full child, before any genuine scenario work.
pub(crate) fn enable() {
    RECORDER.with(|cell| {
        if let Ok(mut state) = cell.try_borrow_mut() {
            if state.is_none() {
                *state = Some(Recorder { origin: Instant::now(), ordinal: Ordinal::All,
                    slots: [None; SLOT_COUNT], invalid: false });
            } else if let Some(state) = state.as_mut() { state.invalid = true; }
        } else { lost(); }
    });
}
pub(crate) fn select(index: usize) {
    RECORDER.with(|cell| {
        if let Ok(mut state) = cell.try_borrow_mut() {
            if let Some(state) = state.as_mut() {
                match index { 0 => state.ordinal = Ordinal::First, 1 => state.ordinal = Ordinal::Second,
                    _ => state.invalid = true }
            }
        } else { lost(); }
    });
}
/// Closed-name lookup ignores all unselected existing diagnostic phases.
pub(crate) fn event(name: &str, begin: bool, error: bool) {
    let Some(phase) = Phase::parse(name) else { return; };
    RECORDER.with(|cell| {
        if let Ok(mut state) = cell.try_borrow_mut() {
            if let Some(state) = state.as_mut() {
                let elapsed = state.origin.elapsed().as_millis();
                if elapsed > u128::from(MAX_OFFSET) { state.invalid = true; return; }
                state.record(phase, begin, error, elapsed as u64);
            }
        } else { lost(); }
    });
}
/// Runs after the full scenario returned, including error teardown. Never used
/// for success, cancellation, admission or cleanup decisions.
pub(crate) fn emit_summary() {
    RECORDER.with(|cell| {
        let Ok(mut state) = cell.try_borrow_mut() else {
            lost();
            let _ = writeln!(std::io::stderr().lock(), "\n[JOINED_TIMING_INVALID_V1 source=Host]");
            return;
        };
        let Some(state) = state.take() else { return; };
        let stderr = std::io::stderr();
        let mut output = stderr.lock();
        if state.invalid || RECORDING_LOST.with(Cell::get) { let _ = writeln!(output, "\n[JOINED_TIMING_INVALID_V1 source=Host]"); }
        for &phase in Phase::ALL {
            for &ordinal in Ordinal::ALL {
                if !phase.permits(ordinal) { continue; }
                let row = state.slots[index(phase, ordinal)].unwrap_or_else(|| empty(phase, ordinal));
                match serde_json::to_string(&Record::Landmark(row)) {
                    Ok(json) => { let _ = writeln!(output, "\n{PREFIX}{json}]"); }
                    Err(_) => { let _ = writeln!(output, "\n[JOINED_TIMING_INVALID_V1 source=Host]"); }
                }
            }
        }
        let _ = writeln!(output, "\n[JOINED_TIMING_END_V1 source=Host]");
    });
}

/// Fixed parent state. Timing corruption can only mark this optional projection
/// invalid; it never returns a failure to the scenario or transcript driver.
pub(crate) struct Capture {
    landmarks: [Option<Landmark>; SLOT_COUNT],
    aggregates: [Option<Aggregate>; AggregatePhase::ALL.len()],
    host_end: bool,
    signer_end: bool,
    invalid: bool,
    line: [u8; MAX_LINE],
    line_len: usize,
    discarding: bool,
    capture_incomplete: bool,
}
impl Drop for Capture {
    fn drop(&mut self) { zeroize::Zeroize::zeroize(&mut self.line); }
}
impl Default for Capture {
    fn default() -> Self {
        Self { landmarks: [None; SLOT_COUNT], aggregates: [None; AggregatePhase::ALL.len()],
            host_end: false, signer_end: false, invalid: false,
            line: [0; MAX_LINE], line_len: 0, discarding: false, capture_incomplete: false }
    }
}
impl Capture {
    // Reserved fixed state is charged to the existing aggregate transcript cap.
    pub(crate) const RETAINED_BYTES: usize = std::mem::size_of::<Self>();
    pub(crate) fn feed(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            if byte == b'\n' {
                if !self.discarding {
                    let mut line = self.line;
                    let len = self.line_len;
                    match std::str::from_utf8(&line[..len]) {
                        Ok(text) => self.line(text.trim_end_matches('\r')),
                        Err(_) if line[..len].starts_with(b"[JOINED_TIMING_") => self.invalid = true,
                        Err(_) => {}
                    }
                    // Temporary stack bytes can include an incomplete private
                    // line, even though only the closed timing prefix parses.
                    zeroize::Zeroize::zeroize(&mut line);
                }
                zeroize::Zeroize::zeroize(&mut self.line);
                self.line_len = 0;
                self.discarding = false;
            } else if !self.discarding {
                if self.line_len == MAX_LINE {
                    if self.line.starts_with(b"[JOINED_TIMING_") { self.invalid = true; }
                    zeroize::Zeroize::zeroize(&mut self.line);
                    self.line_len = 0;
                    self.discarding = true;
                } else {
                    self.line[self.line_len] = byte;
                    self.line_len += 1;
                }
            }
        }
    }
    pub(crate) fn line(&mut self, line: &str) {
        if !line.starts_with("[JOINED_TIMING_") { return; }
        if line.len() > MAX_LINE { self.invalid = true; return; }
        match line {
            "[JOINED_TIMING_END_V1 source=Host]" => {
                if self.host_end { self.invalid = true; } self.host_end = true; return;
            }
            "[JOINED_TIMING_END_V1 source=Signer]" => {
                if self.signer_end { self.invalid = true; } self.signer_end = true; return;
            }
            "[JOINED_TIMING_INVALID_V1 source=Host]" | "[JOINED_TIMING_INVALID_V1 source=Signer]" => {
                self.invalid = true; return;
            }
            _ => {}
        }
        let Some(json) = line.strip_prefix(PREFIX).and_then(|s| s.strip_suffix(']')) else {
            self.invalid = true; return;
        };
        let Ok(record) = serde_json::from_str::<Record>(json) else { self.invalid = true; return; };
        match record {
            Record::Landmark(row) => {
                let valid = row.phase.permits(row.ordinal)
                    && row.start_ms.is_none_or(|v| v <= MAX_OFFSET)
                    && row.end_ms.is_none_or(|v| v <= MAX_OFFSET)
                    && row.errors <= 1
                    && match (row.start_ms, row.end_ms) {
                        (None, None) | (Some(_), None) => row.errors == 0,
                        (Some(start), Some(end)) => end >= start,
                        (None, Some(_)) => false,
                    };
                let slot = &mut self.landmarks[index(row.phase, row.ordinal)];
                if !valid || self.host_end || slot.is_some() { self.invalid = true; return; }
                *slot = Some(row);
            }
            Record::Aggregate(row) => {
                let valid = row.started <= MAX_COUNT && row.completed <= row.started
                    && row.errors <= row.completed && row.total_ms <= MAX_TOTAL
                    && row.max_ms <= row.total_ms
                    && (row.completed != 0 || (row.total_ms == 0 && row.max_ms == 0));
                let slot = &mut self.aggregates[row.phase as usize];
                if !valid || self.signer_end || slot.is_some() { self.invalid = true; return; }
                *slot = Some(row);
            }
        }
    }
    pub(crate) fn finish_input(&mut self, drained: bool) {
        self.capture_incomplete |= !drained || self.line_len != 0 || self.discarding;
        zeroize::Zeroize::zeroize(&mut self.line);
        self.line_len = 0;
        self.discarding = false;
    }
    pub(crate) fn public_json(&self) -> Option<String> {
        let landmarks: Vec<_> = self.landmarks.iter().flatten().copied().map(Record::Landmark).collect();
        let aggregates: Vec<_> = self.aggregates.iter().flatten().copied().map(Record::Aggregate).collect();
        let host_count = Phase::ALL.iter().map(|phase| Ordinal::ALL.iter().filter(|&&o| phase.permits(o)).count()).sum::<usize>();
        let complete = !self.invalid && !self.capture_incomplete && self.host_end && self.signer_end
            && landmarks.len() == host_count && aggregates.len() == AggregatePhase::ALL.len();
        serde_json::to_string(&serde_json::json!({
            "version": 1, "complete": complete, "invalid": self.invalid,
            "host_dump_complete": self.host_end, "signer_dump_complete": self.signer_end,
            "inclusive_aggregates": true, "landmarks": landmarks, "aggregates": aggregates,
        })).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn row(phase: Phase, ordinal: Ordinal, start: Option<u64>, end: Option<u64>, errors: u8) -> String {
        format!("{PREFIX}{}]", serde_json::to_string(&Record::Landmark(Landmark { phase, ordinal, start_ms:start, end_ms:end, errors })).unwrap())
    }
    #[test]
    fn timing_records_keep_incomplete_and_failed_spans_distinct() {
        let mut r = Recorder { origin: Instant::now(), ordinal: Ordinal::First, slots:[None; SLOT_COUNT], invalid:false };
        r.record(Phase::ObservedReadRequest, true, false, 7);
        assert_eq!(r.slots[index(Phase::ObservedReadRequest, Ordinal::First)].unwrap().end_ms, None);
        r.record(Phase::ObservedReadRequest, false, true, 11);
        let row = r.slots[index(Phase::ObservedReadRequest, Ordinal::First)].unwrap();
        assert_eq!((row.start_ms,row.end_ms,row.errors), (Some(7),Some(11),1));
        assert!(!r.invalid);
        r.record(Phase::ObservedReadRequest, true, false, 12);
        assert!(r.invalid);
        RECORDER.with(|cell| {
            let held = cell.borrow_mut();
            event("ObservedReadRequest", true, false);
            assert!(RECORDING_LOST.with(Cell::get));
            drop(held);
        });
        RECORDING_LOST.with(|flag| flag.set(false));
    }
    #[test]
    fn timing_capture_refuses_unknown_duplicate_and_out_of_bound_data() {
        let valid = row(Phase::ObservedReadRequest,Ordinal::First,Some(1),None,0);
        let mut c = Capture::default(); c.line(&valid); assert!(!c.invalid); c.line(&valid); assert!(c.invalid);
        for invalid in [
            valid.replace("ObservedReadRequest", "private-payload"),
            valid.replace("\"errors\":0", "\"errors\":0,\"errors\":0"),
            valid.replace("\"errors\":0", "\"errors\":0,\"private\":1"),
            row(Phase::ObservedReadRequest,Ordinal::All,Some(1),None,0),
            row(Phase::ObservedReadRequest,Ordinal::First,Some(MAX_OFFSET+1),None,0),
            row(Phase::ObservedReadRequest,Ordinal::First,None,Some(1),0),
        ] { let mut c=Capture::default(); c.line(&invalid); assert!(c.invalid); assert!(c.landmarks.iter().all(Option::is_none)); }
    }
    #[test]
    fn timing_stream_framing_discards_oversized_lines_and_erases_partial_bytes() {
        let valid=row(Phase::ObservedReadRequest,Ordinal::First,Some(3),Some(4),0);
        let mut c=Capture::default();
        c.feed(&vec![b'x'; MAX_LINE+1]); c.feed(valid.as_bytes()); c.feed(b"\n");
        assert!(c.landmarks.iter().all(Option::is_none));
        for part in valid.as_bytes().chunks(7) { c.feed(part); }
        assert!(c.landmarks.iter().all(Option::is_none));
        c.feed(b"\r\n"); assert!(c.landmarks.iter().any(Option::is_some));
        c.feed(b"private unfinished text"); c.finish_input(true);
        assert!(c.capture_incomplete); assert!(c.line.iter().all(|b| *b == 0));
        assert_eq!(c.line_len,0);
        let mut malformed=Capture::default();
        malformed.feed(b"[JOINED_TIMING_V1 \xff]\n");
        assert!(malformed.invalid);
        assert!(malformed.line.iter().all(|b| *b == 0));
        let mut private=Capture::default(); private.feed(b"private \xff\n");
        assert!(!private.invalid);
    }
    #[test]
    fn timing_aggregate_bounds_do_not_sum_nested_durations() {
        for raw in [
            r#"{"kind":"aggregate","phase":"ConstructionReserve","started":1,"completed":2,"errors":0,"total_ms":1,"max_ms":1}"#,
            r#"{"kind":"aggregate","phase":"ConstructionReserve","started":1,"completed":1,"errors":2,"total_ms":1,"max_ms":1}"#,
            r#"{"kind":"aggregate","phase":"ConstructionReserve","started":1,"completed":1,"errors":0,"total_ms":1,"max_ms":2}"#,
            r#"{"kind":"aggregate","phase":"ConstructionReserve","started":1,"completed":1,"errors":0,"total_ms":900000001,"max_ms":1}"#,
        ] { let mut c=Capture::default();c.line(&format!("{PREFIX}{raw}]"));assert!(c.invalid); }
        let mut c=Capture::default();
        for phase in ["CompletionClaimCheck","ConstructionReserve"] {
            c.line(&format!("{PREFIX}{{\"kind\":\"aggregate\",\"phase\":\"{phase}\",\"started\":1,\"completed\":1,\"errors\":0,\"total_ms\":10,\"max_ms\":10}}]"));
        }
        let json=c.public_json().unwrap(); assert!(!c.invalid);
        let value:serde_json::Value=serde_json::from_str(&json).unwrap();
        assert_eq!(value["aggregates"][0]["total_ms"],10);
        assert_eq!(value["aggregates"][1]["total_ms"],10);
        assert_eq!(value["inclusive_aggregates"],true);
    }
    #[test]
    fn timing_complete_dump_is_not_success_or_finished_work() {
        let mut c=Capture::default();
        for &p in Phase::ALL { for &o in Ordinal::ALL { if p.permits(o) { c.line(&row(p,o,Some(1),None,0)); } } }
        for &p in AggregatePhase::ALL {
            let r=Record::Aggregate(Aggregate { phase:p,started:2,completed:1,errors:1,total_ms:50,max_ms:50 });
            c.line(&format!("{PREFIX}{}]",serde_json::to_string(&r).unwrap()));
        }
        c.line("[JOINED_TIMING_END_V1 source=Host]"); c.line("[JOINED_TIMING_END_V1 source=Signer]");
        let v:serde_json::Value=serde_json::from_str(&c.public_json().unwrap()).unwrap();
        assert_eq!(v["complete"],true); assert_eq!(v["inclusive_aggregates"],true);
        assert_eq!(v["aggregates"][0]["started"],2); assert_eq!(v["aggregates"][0]["completed"],1);
        let missing:serde_json::Value=serde_json::from_str(&Capture::default().public_json().unwrap()).unwrap();
        assert_eq!(missing["complete"],false); assert_eq!(missing["landmarks"],serde_json::json!([]));
        assert!(Capture::RETAINED_BYTES < 4096);
    }
}
