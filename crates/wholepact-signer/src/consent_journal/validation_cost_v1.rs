//! Opt-in, test-only observations of the real journal validation expressions.
//! Durations are hierarchical, inclusive, and non-additive: a parent includes
//! its children, and repeated passes are counted rather than deduplicated.
//! This does not measure or qualify source, certificate, privacy, native receipt,
//! or other owners outside this journal. No observation changes a Result.

use std::{
    cell::{Cell, RefCell},
    io::Write,
    marker::PhantomData,
    rc::Rc,
    time::Instant,
};

const MAX_CALLS: u64 = 1_000_000;
const MAX_INCLUSIVE_US: u64 = 86_400_000_000;

#[derive(Clone, Copy)]
#[repr(usize)]
pub(super) enum Phase {
    SampleTotal,
    SnapshotTotal,
    ConnectionLock,
    IdentityBefore,
    TransactionBegin,
    ValidationTotal,
    GenesisValidation,
    AccountState,
    SupportedTablePolicy,
    Inventory,
    LocalCells,
    NamespaceBinding,
    IdentityAfter,
    TransactionCommit,
    SchemaTotal,
    SchemaReferenceOpen,
    SchemaReferenceBuild,
    SchemaCompare,
    SchemaCapacity,
    SchemaBounds,
    OfflineHistory,
    OfflineReceipts,
    SchemaAccountUse,
    NamedRecipientHistory,
    AdmissionIntents,
    DurableMaterialRows,
    ConstructionAudit,
    CommonAudit,
}

const PHASE_COUNT: usize = Phase::CommonAudit as usize + 1;
const PHASES: [Phase; PHASE_COUNT] = [
    Phase::SampleTotal,
    Phase::SnapshotTotal,
    Phase::ConnectionLock,
    Phase::IdentityBefore,
    Phase::TransactionBegin,
    Phase::ValidationTotal,
    Phase::GenesisValidation,
    Phase::AccountState,
    Phase::SupportedTablePolicy,
    Phase::Inventory,
    Phase::LocalCells,
    Phase::NamespaceBinding,
    Phase::IdentityAfter,
    Phase::TransactionCommit,
    Phase::SchemaTotal,
    Phase::SchemaReferenceOpen,
    Phase::SchemaReferenceBuild,
    Phase::SchemaCompare,
    Phase::SchemaCapacity,
    Phase::SchemaBounds,
    Phase::OfflineHistory,
    Phase::OfflineReceipts,
    Phase::SchemaAccountUse,
    Phase::NamedRecipientHistory,
    Phase::AdmissionIntents,
    Phase::DurableMaterialRows,
    Phase::ConstructionAudit,
    Phase::CommonAudit,
];

impl Phase {
    fn label(self) -> &'static str {
        match self {
            Self::SampleTotal => "sample_total",
            Self::SnapshotTotal => "snapshot_total",
            Self::ConnectionLock => "connection_lock",
            Self::IdentityBefore => "identity_before",
            Self::TransactionBegin => "transaction_begin",
            Self::ValidationTotal => "validation_total",
            Self::GenesisValidation => "genesis_validation",
            Self::AccountState => "account_state",
            Self::SupportedTablePolicy => "supported_table_policy",
            Self::Inventory => "inventory",
            Self::LocalCells => "local_cells",
            Self::NamespaceBinding => "namespace_binding",
            Self::IdentityAfter => "identity_after",
            Self::TransactionCommit => "transaction_commit",
            Self::SchemaTotal => "schema_total",
            Self::SchemaReferenceOpen => "schema_reference_open",
            Self::SchemaReferenceBuild => "schema_reference_build",
            Self::SchemaCompare => "schema_compare",
            Self::SchemaCapacity => "schema_capacity",
            Self::SchemaBounds => "schema_bounds",
            Self::OfflineHistory => "offline_history",
            Self::OfflineReceipts => "offline_receipts",
            Self::SchemaAccountUse => "schema_account_use",
            Self::NamedRecipientHistory => "named_recipient_history",
            Self::AdmissionIntents => "admission_intents",
            Self::DurableMaterialRows => "durable_material_rows",
            Self::ConstructionAudit => "construction_audit",
            Self::CommonAudit => "common_audit",
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum Sample {
    Setup,
    EmptyControl,
    First,
    Repeat1,
    Repeat2,
    Material,
    Request,
    Outbox,
}

impl Sample {
    fn label(self) -> &'static str {
        match self {
            Self::Setup => "setup",
            Self::EmptyControl => "empty_control",
            Self::First => "first",
            Self::Repeat1 => "repeat1",
            Self::Repeat2 => "repeat2",
            Self::Material => "material",
            Self::Request => "request",
            Self::Outbox => "outbox",
        }
    }
}

#[derive(Clone, Copy, Default)]
struct Metric {
    calls: u64,
    inclusive_us: u64,
}

#[derive(Default)]
pub(super) struct Measurement {
    metrics: [Metric; PHASE_COUNT],
    clamped: bool,
    incomplete: bool,
}

impl Measurement {
    pub(super) fn calls(&self, phase: Phase) -> u64 {
        self.metrics[phase as usize].calls
    }

    pub(super) fn inclusive_us(&self, phase: Phase) -> u64 {
        self.metrics[phase as usize].inclusive_us
    }

    pub(super) fn is_clamped(&self) -> bool {
        self.clamped
    }

    pub(super) fn is_incomplete(&self) -> bool {
        self.incomplete
    }
}

struct Active {
    id: u64,
    open_spans: u64,
    measurement: Measurement,
}

#[derive(Default)]
struct State {
    next_id: u64,
    active: Option<Active>,
}

thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::default());
    static LOST_OBSERVATIONS: Cell<bool> = const { Cell::new(false) };
}

fn lost_observation() {
    let _ = LOST_OBSERVATIONS.try_with(|lost| lost.set(true));
}

fn bounded_add(value: &mut u64, amount: u64, maximum: u64, clamped: &mut bool) {
    if amount > maximum.saturating_sub(*value) {
        *value = maximum;
        *clamped = true;
    } else {
        *value += amount;
    }
}

/// A disabled observer does not read a clock. The guard is thread-confined and
/// finalizes even when the observed expression returns an error or unwinds.
pub(super) struct Span {
    started: Option<(u64, Instant)>,
    phase: Phase,
    _thread: PhantomData<Rc<()>>,
}

pub(super) fn enter(phase: Phase) -> Span {
    let id = STATE
        .try_with(|state| {
            let Ok(mut state) = state.try_borrow_mut() else {
                lost_observation();
                return None;
            };
            let active = state.active.as_mut()?;
            bounded_add(
                &mut active.measurement.metrics[phase as usize].calls,
                1,
                MAX_CALLS,
                &mut active.measurement.clamped,
            );
            if active.open_spans == MAX_CALLS {
                active.measurement.clamped = true;
                active.measurement.incomplete = true;
                return None;
            }
            active.open_spans += 1;
            Some(active.id)
        })
        .ok()
        .flatten();
    Span {
        started: id.map(|id| (id, Instant::now())),
        phase,
        _thread: PhantomData,
    }
}

impl Drop for Span {
    fn drop(&mut self) {
        let Some((id, started)) = self.started else {
            return;
        };
        let elapsed = started.elapsed().as_micros();
        let _ = STATE.try_with(|state| {
            let Ok(mut state) = state.try_borrow_mut() else {
                lost_observation();
                return;
            };
            let Some(active) = state.active.as_mut().filter(|active| active.id == id) else {
                return;
            };
            if elapsed > u128::from(MAX_INCLUSIVE_US) {
                active.measurement.clamped = true;
            }
            bounded_add(
                &mut active.measurement.metrics[self.phase as usize].inclusive_us,
                elapsed.min(u128::from(MAX_INCLUSIVE_US)) as u64,
                MAX_INCLUSIVE_US,
                &mut active.measurement.clamped,
            );
            active.open_spans = active.open_spans.saturating_sub(1);
        });
    }
}

struct Session(u64);

impl Session {
    fn finish(&self) -> Measurement {
        let mut measurement = STATE
            .try_with(|state| {
                let Ok(mut state) = state.try_borrow_mut() else {
                    lost_observation();
                    return None;
                };
                if state.active.as_ref().map(|active| active.id) != Some(self.0) {
                    return None;
                }
                let mut active = state.active.take()?;
                active.measurement.incomplete |= active.open_spans != 0;
                Some(active.measurement)
            })
            .ok()
            .flatten()
            .unwrap_or_else(|| Measurement {
                incomplete: true,
                ..Measurement::default()
            });
        measurement.incomplete |= LOST_OBSERVATIONS
            .try_with(|lost| lost.replace(false))
            .unwrap_or(true);
        measurement
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // Reset on unwind as well. Never retain an active collector for later
        // tests or change the original operation's error/panic behavior.
        let _ = self.finish();
    }
}

pub(super) fn measure<T>(operation: impl FnOnce() -> T) -> (T, Measurement) {
    let id = STATE
        .try_with(|state| {
            let Ok(mut state) = state.try_borrow_mut() else {
                lost_observation();
                return None;
            };
            if state.active.is_some() {
                // Nested measurements are deliberately unsupported, not silently
                // substituted for or merged with the enclosing sample.
                lost_observation();
                return None;
            }
            let Some(id) = state.next_id.checked_add(1) else {
                return None;
            };
            state.next_id = id;
            let _ = LOST_OBSERVATIONS.try_with(|lost| lost.set(false));
            state.active = Some(Active {
                id,
                open_spans: 0,
                measurement: Measurement::default(),
            });
            Some(id)
        })
        .ok()
        .flatten();
    let Some(id) = id else {
        return (
            operation(),
            Measurement {
                incomplete: true,
                ..Measurement::default()
            },
        );
    };
    let session = Session(id);
    let total = enter(Phase::SampleTotal);
    let result = operation();
    drop(total);
    let measurement = session.finish();
    (result, measurement)
}

/// Optional output contains fixed labels and bounded counters only. Each
/// inclusive_us value is non-additive, including across overlapping phases.
/// Output errors are ignored and cannot change the measured operation's Result.
pub(super) fn emit(sample: Sample, measurement: &Measurement) {
    let mut output = std::io::stderr().lock();
    for phase in PHASES {
        let _ = writeln!(
            output,
            "LOCAL_DURABLE_VALIDATION_COST_V1 sample={} phase={} calls={} inclusive_us={} clamped={} incomplete={}",
            sample.label(),
            phase.label(),
            measurement.calls(phase),
            measurement.inclusive_us(phase),
            measurement.is_clamped(),
            measurement.is_incomplete(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_observation_has_no_clock() {
        assert!(enter(Phase::SchemaTotal).started.is_none());
    }

    #[test]
    fn failure_is_measured_once_and_preserved() {
        let calls = Cell::new(0);
        let (result, measurement) = measure(|| {
            calls.set(calls.get() + 1);
            let _span = enter(Phase::SchemaTotal);
            Err::<(), _>(7)
        });
        assert_eq!(result, Err(7));
        assert_eq!(calls.get(), 1);
        assert_eq!(measurement.calls(Phase::SampleTotal), 1);
        assert_eq!(measurement.calls(Phase::SchemaTotal), 1);
        assert!(!measurement.is_clamped());
        assert!(!measurement.is_incomplete());
        assert!(enter(Phase::SchemaTotal).started.is_none());
    }

    #[test]
    fn unwind_resets_opt_in_collection() {
        let result = std::panic::catch_unwind(|| {
            measure(|| {
                let _span = enter(Phase::SchemaTotal);
                panic!("synthetic observer unwind");
            })
        });
        assert!(result.is_err());
        let (_, measurement) = measure(|| ());
        assert_eq!(measurement.calls(Phase::SampleTotal), 1);
        assert_eq!(measurement.calls(Phase::SchemaTotal), 0);
        assert!(!measurement.is_incomplete());
    }

    #[test]
    fn counts_and_durations_are_bounded() {
        let mut calls = MAX_CALLS;
        let mut clamped = false;
        bounded_add(&mut calls, 1, MAX_CALLS, &mut clamped);
        assert_eq!(calls, MAX_CALLS);
        assert!(clamped);
        let mut duration = MAX_INCLUSIVE_US - 1;
        clamped = false;
        bounded_add(&mut duration, 2, MAX_INCLUSIVE_US, &mut clamped);
        assert_eq!(duration, MAX_INCLUSIVE_US);
        assert!(clamped);
    }

    #[test]
    fn escaped_span_and_nested_collection_are_incomplete() {
        let (span, escaped) = measure(|| enter(Phase::SchemaTotal));
        assert!(escaped.is_incomplete());
        let (_, next) = measure(|| drop(span));
        assert_eq!(next.calls(Phase::SchemaTotal), 0);
        assert!(!next.is_incomplete());
        let ((result, nested), outer) = measure(|| measure(|| 9));
        assert_eq!(result, 9);
        assert!(nested.is_incomplete());
        assert!(outer.is_incomplete());
    }
}
