//! Bounded, synthetic-only inclusive operation timing. These observations never
//! feed an owner, deadline, result, or effect. Hot paths use only a separate
//! monotonic sample and fixed atomics; output occurs after scenario teardown.
use super::synthetic_diagnostics::Operation;
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::time::Instant;

const COUNT_LIMIT: u64 = 1_000_000;
const MILLIS_LIMIT: u64 = 900_000_000;
const PHASES: [&str; 16] = [
    "CompletionClaimCheck", "CompletionClaimSign", "CompletionClaimGranted",
    "CompletionClaimClaim", "CompletionClaimClaimed", "CompletionClaimObserve",
    "CompletionClaimHistory", "CompletionClaimReentered", "CompletionClaimSend",
    "ConstructionReserve", "ConstructionReservedAppend", "ConstructionConsume",
    "ConstructionConsumedAppend", "ConstructionNamedOwner", "ConstructionIntoNamed",
    "ConstructionFinalOwner",
];
fn slot(operation: Operation) -> Option<usize> {
    Some(match operation {
        Operation::CompletionClaimCheck => 0,
        Operation::CompletionClaimSign => 1,
        Operation::CompletionClaimGranted => 2,
        Operation::CompletionClaimClaim => 3,
        Operation::CompletionClaimClaimed => 4,
        Operation::CompletionClaimObserve => 5,
        Operation::CompletionClaimHistory => 6,
        Operation::CompletionClaimReentered => 7,
        Operation::CompletionClaimSend => 8,
        Operation::ConstructionReserve => 9,
        Operation::ConstructionReservedAppend => 10,
        Operation::ConstructionConsume => 11,
        Operation::ConstructionConsumedAppend => 12,
        Operation::ConstructionNamedOwner => 13,
        Operation::ConstructionIntoNamed => 14,
        Operation::ConstructionFinalOwner => 15,
        _ => return None,
    })
}
struct Counter {
    started: AtomicU64,
    completed: AtomicU64,
    errors: AtomicU64,
    total_ms: AtomicU64,
    max_ms: AtomicU64,
    invalid: AtomicBool,
}
#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    started: u64,
    completed: u64,
    errors: u64,
    total_ms: u64,
    max_ms: u64,
    invalid: bool,
}
impl Counter {
    const fn new() -> Self {
        Self {
            started: AtomicU64::new(0), completed: AtomicU64::new(0),
            errors: AtomicU64::new(0), total_ms: AtomicU64::new(0),
            max_ms: AtomicU64::new(0), invalid: AtomicBool::new(false),
        }
    }
    fn add(&self, counter: &AtomicU64, value: u64, limit: u64) {
        let previous = counter.fetch_update(Relaxed, Relaxed, |old| {
            Some(old.saturating_add(value).min(limit))
        }).unwrap_or_else(|old| old);
        if previous.saturating_add(value) > limit {
            self.invalid.store(true, Relaxed);
        }
    }
    fn start(&self) {
        self.add(&self.started, 1, COUNT_LIMIT);
    }
    fn finish_ms(&self, elapsed: u128, failed: bool) {
        if elapsed > u128::from(MILLIS_LIMIT) {
            self.invalid.store(true, Relaxed);
        }
        let elapsed = elapsed.min(u128::from(MILLIS_LIMIT)) as u64;
        self.add(&self.total_ms, elapsed, MILLIS_LIMIT);
        self.max_ms.fetch_max(elapsed, Relaxed);
        if failed { self.add(&self.errors, 1, COUNT_LIMIT); }
        // Count a returned result last. Dropping an unfinished Span never calls
        // this, so unwind/interruption remains started > completed, not success.
        self.add(&self.completed, 1, COUNT_LIMIT);
    }
    fn snapshot(&self) -> Snapshot {
        let started = self.started.load(Relaxed);
        let completed = self.completed.load(Relaxed);
        let errors = self.errors.load(Relaxed);
        let total_ms = self.total_ms.load(Relaxed);
        let max_ms = self.max_ms.load(Relaxed);
        Snapshot {
            started, completed, errors, total_ms, max_ms,
            invalid: self.invalid.load(Relaxed) || completed > started
                || errors > completed || max_ms > total_ms
                || (completed == 0 && total_ms != 0),
        }
    }
}
static COUNTERS: [Counter; 16] = [const { Counter::new() }; 16];

pub(super) struct Span {
    index: usize,
    started: Instant,
}
pub(super) fn begin(operation: Operation) -> Option<Span> {
    let index = slot(operation)?;
    COUNTERS[index].start();
    Some(Span { index, started: Instant::now() })
}
impl Span {
    pub(super) fn finish(self, failed: bool) {
        COUNTERS[self.index].finish_ms(self.started.elapsed().as_millis(), failed);
    }
}

/// A fixed inert summary only. Call after scenario locals and worker joins have
/// finished; an interrupted child may never dump, which the parent marks missing.
/// Nested aggregates are inclusive and must not be summed as elapsed wall time.
pub(super) fn emit_summary() {
    let mut output = std::io::stderr().lock();
    let mut invalid = false;
    for (phase, counter) in PHASES.iter().zip(COUNTERS.iter()) {
        let s = counter.snapshot();
        invalid |= s.invalid;
        let _ = writeln!(output,
            "\n[JOINED_TIMING_V1 {{\"kind\":\"aggregate\",\"phase\":\"{}\",\"started\":{},\"completed\":{},\"errors\":{},\"total_ms\":{},\"max_ms\":{}}}]",
            phase, s.started, s.completed, s.errors, s.total_ms, s.max_ms);
    }
    if invalid { let _ = writeln!(output, "\n[JOINED_TIMING_INVALID_V1 source=Signer]"); }
    let _ = writeln!(output, "\n[JOINED_TIMING_END_V1 source=Signer]");
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn aggregate_counts_only_returned_results_and_keeps_incomplete() {
        let counter = Counter::new();
        assert_eq!(counter.snapshot(), Snapshot {
            started: 0, completed: 0, errors: 0, total_ms: 0, max_ms: 0, invalid: false,
        });
        counter.start(); counter.finish_ms(12, false);
        counter.start(); counter.finish_ms(7, true);
        counter.start(); // Interrupted call: no synthetic completion on Drop.
        assert_eq!(counter.snapshot(), Snapshot {
            started: 3, completed: 2, errors: 1, total_ms: 19, max_ms: 12, invalid: false,
        });
    }
    #[test]
    fn aggregate_saturation_is_bounded_and_marked_invalid() {
        let counter = Counter::new();
        counter.started.store(COUNT_LIMIT, Relaxed);
        counter.start();
        counter.finish_ms(u128::from(MILLIS_LIMIT) + 1, false);
        counter.finish_ms(1, true);
        let s = counter.snapshot();
        assert!(s.invalid);
        assert_eq!(s.started, COUNT_LIMIT);
        assert_eq!(s.total_ms, MILLIS_LIMIT);
        assert_eq!(s.max_ms, MILLIS_LIMIT);
        assert_eq!(s.completed, 2);
        assert_eq!(s.errors, 1);
    }
    #[test]
    fn aggregate_catalogue_is_fixed_and_unselected_operations_are_inert() {
        let operations = [
            Operation::CompletionClaimCheck, Operation::CompletionClaimSign,
            Operation::CompletionClaimGranted, Operation::CompletionClaimClaim,
            Operation::CompletionClaimClaimed, Operation::CompletionClaimObserve,
            Operation::CompletionClaimHistory, Operation::CompletionClaimReentered,
            Operation::CompletionClaimSend, Operation::ConstructionReserve,
            Operation::ConstructionReservedAppend, Operation::ConstructionConsume,
            Operation::ConstructionConsumedAppend, Operation::ConstructionNamedOwner,
            Operation::ConstructionIntoNamed, Operation::ConstructionFinalOwner,
        ];
        for (index, operation) in operations.into_iter().enumerate() {
            assert_eq!(slot(operation), Some(index));
        }
        assert_eq!(PHASES.len(), 16);
        let unique: std::collections::BTreeSet<_> = PHASES.iter().copied().collect();
        assert_eq!(unique.len(), 16);
        assert!(begin(Operation::Other).is_none());
        assert!(begin(Operation::CompletionWitnessCheck).is_none());
        assert!(begin(Operation::CommitCompletionClaim).is_none());
    }
}
