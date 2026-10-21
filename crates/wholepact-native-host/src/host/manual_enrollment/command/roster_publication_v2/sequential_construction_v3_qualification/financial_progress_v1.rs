//! Qualification-only, nonrenewing parent supervision. Never protocol authority.
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use wholepact_signer::native_ui::synthetic_born_joined_qualification::FinancialNativeStageV1;
const PREFIX: &str = "[FINANCIAL_PROGRESS_V1 ";
const WINDOW: Duration = Duration::from_secs(120);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum Phase {
    SourceOpen,
    ReadContinue,
    Continue,
    Admission,
    ReadAcquire,
    Acquire,
    ReadActivate,
    Activate,
    Wallet,
    ReadSign,
    Sign,
    PairHistory,
    Return,
    FinalRetention,
    Shutdown,
    ReaderHostOpen,
    ReaderWitnessReopen,
    ReaderProviderReopen,
    ReaderFirstSummary,
    ReaderInitialHistoryA,
    ReaderInitialHistoryB,
    ReaderPartialDispatch,
    ReaderReconcileHistoryA,
    ReaderReconcileHistoryB,
    ReaderPartialSummary,
    ReaderStaleProbe,
    ReaderFinalDispatch,
    ReaderFinalSummary,
    ReaderFinalHistoryA,
    ReaderFinalHistoryB,
    ReaderShutdown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub(super) enum Record {
    Call {
        call: Call,
    },
    Begin {
        owner: u8,
        phase: Phase,
    },
    Job {
        owner: u8,
        job_id: u32,
        sequence: u32,
        stage: FinancialNativeStageV1,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum Call {
    Begin,
    BeginFinancial,
    ReadRequest,
    WitnessStart,
    ReadHistory,
    BindHistory,
    AwaitReturn,
    WaitPhase,
    Approve,
    SendAdmission,
    WitnessFinish,
    StartServer,
    DropServer,
    ReadPeer,
    Intake,
    Preserve,
    Complete,
    Shutdown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Job {
    pub owner: u8,
    pub job_id: u32,
    pub sequence: u32,
    pub stage: FinancialNativeStageV1,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Observation {
    pub window: u8,
    pub owner: u8,
    pub phase: Phase,
    pub call: Call,
    pub last_native: Option<Job>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum Reason {
    PhaseDeadline,
    InvalidProgress,
    GlobalDeadline,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Failure {
    pub reason: Reason,
    pub last: Option<Observation>,
}
const LEGACY_TIMING_LIMIT_MS: u32 = 900_000;
pub(super) const FINANCIAL_TIMING_LIMIT_MS: u32 = 1_800_000;
pub(super) const FINANCIAL_PROFILE: &str = "durable_financial_1800_v2";
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, try_from = "TimingWire")]
pub(super) struct Timing {
    pub budget_ms: u32,
    pub elapsed_before_first_window_ms: Option<u32>,
    pub completed_window_elapsed_ms: Vec<u32>,
    pub current_window_elapsed_ms: Option<u32>,
    pub total_elapsed_ms: u32,
    pub clamped: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TimingWire {
    budget_ms: u32,
    elapsed_before_first_window_ms: Option<u32>,
    completed_window_elapsed_ms: Vec<u32>,
    current_window_elapsed_ms: Option<u32>,
    total_elapsed_ms: u32,
    clamped: bool,
}
impl TryFrom<TimingWire> for Timing {
    type Error = &'static str;
    fn try_from(w: TimingWire) -> Result<Self, Self::Error> {
        let value = Self {
            budget_ms: w.budget_ms,
            elapsed_before_first_window_ms: w.elapsed_before_first_window_ms,
            completed_window_elapsed_ms: w.completed_window_elapsed_ms,
            current_window_elapsed_ms: w.current_window_elapsed_ms,
            total_elapsed_ms: w.total_elapsed_ms,
            clamped: w.clamped,
        };
        if value.is_valid() {
            Ok(value)
        } else {
            Err("invalid bounded financial phase timing")
        }
    }
}
impl Timing {
    pub(super) fn is_valid(&self) -> bool {
        if !matches!(
            self.budget_ms,
            LEGACY_TIMING_LIMIT_MS | FINANCIAL_TIMING_LIMIT_MS
        ) || self.total_elapsed_ms > self.budget_ms
            || self.completed_window_elapsed_ms.len() > 26
            || (self.clamped && self.total_elapsed_ms != self.budget_ms)
        {
            return false;
        }
        match (
            self.elapsed_before_first_window_ms,
            self.current_window_elapsed_ms,
        ) {
            (None, None) => self.completed_window_elapsed_ms.is_empty(),
            (Some(before), Some(current)) => {
                before <= self.budget_ms
                    && current <= self.budget_ms
                    && self
                        .completed_window_elapsed_ms
                        .iter()
                        .all(|v| *v <= self.budget_ms)
                    && u64::from(before)
                        + u64::from(current)
                        + self
                            .completed_window_elapsed_ms
                            .iter()
                            .map(|v| u64::from(*v))
                            .sum::<u64>()
                        == u64::from(self.total_elapsed_ms)
            }
            _ => false,
        }
    }
    pub(super) fn matches_observation(&self, last: Option<Observation>) -> bool {
        self.is_valid()
            && match last {
                None => self.elapsed_before_first_window_ms.is_none(),
                Some(last) => {
                    self.elapsed_before_first_window_ms.is_some()
                        && self.completed_window_elapsed_ms.len() == usize::from(last.window)
                }
            }
    }
}
fn ordinal(owner: u8, phase: Phase) -> Option<u8> {
    let local = match phase {
        Phase::SourceOpen => Some(0),
        Phase::ReadContinue => Some(1),
        Phase::Continue => Some(2),
        Phase::Admission => Some(3),
        Phase::ReadAcquire => Some(4),
        Phase::Acquire => Some(5),
        Phase::ReadActivate => Some(6),
        Phase::Activate => Some(7),
        Phase::Wallet => Some(8),
        Phase::ReadSign => Some(9),
        Phase::Sign => Some(10),
        _ => None,
    };
    if let Some(local) = local {
        return if (1..=2).contains(&owner) {
            Some((owner - 1) * 11 + local)
        } else {
            None
        };
    }
    match (owner, phase) {
        (0, Phase::PairHistory) => Some(22),
        (1, Phase::Return) => Some(23),
        (2, Phase::Return) => Some(24),
        (0, Phase::FinalRetention) => Some(25),
        (0, Phase::Shutdown) => Some(26),
        _ => None,
    }
}
fn reader_ordinal(owner: u8, phase: Phase) -> Option<u8> {
    if owner != 0 {
        return None;
    }
    match phase {
        Phase::ReaderHostOpen => Some(0),
        Phase::ReaderWitnessReopen => Some(1),
        Phase::ReaderProviderReopen => Some(2),
        Phase::ReaderFirstSummary => Some(3),
        Phase::ReaderInitialHistoryA => Some(4),
        Phase::ReaderInitialHistoryB => Some(5),
        Phase::ReaderPartialDispatch => Some(6),
        Phase::ReaderReconcileHistoryA => Some(7),
        Phase::ReaderReconcileHistoryB => Some(8),
        Phase::ReaderPartialSummary => Some(9),
        Phase::ReaderStaleProbe => Some(10),
        Phase::ReaderFinalDispatch => Some(11),
        Phase::ReaderFinalSummary => Some(12),
        Phase::ReaderFinalHistoryA => Some(13),
        Phase::ReaderFinalHistoryB => Some(14),
        Phase::ReaderShutdown => Some(15),
        _ => None,
    }
}
pub(super) fn emit_begin(owner: u8, phase: Phase) {
    emit(Record::Begin { owner, phase });
}
pub(super) fn emit_call(call: Call) {
    emit(Record::Call { call });
}
pub(super) fn emit_job(owner: u8, job_id: u32, sequence: u32, stage: FinancialNativeStageV1) {
    emit(Record::Job {
        owner,
        job_id,
        sequence,
        stage,
    });
}
thread_local! {static LAST_EMITTED:std::cell::Cell<Option<Record>>=const {std::cell::Cell::new(None)};}
fn emit(record: Record) {
    if LAST_EMITTED.with(|last| {
        if last.get() == Some(record) {
            true
        } else {
            last.set(Some(record));
            false
        }
    }) {
        return;
    }
    use std::io::Write;
    if let Ok(json) = serde_json::to_string(&record) {
        let line = format!("\n{PREFIX}{json}]\n");
        let _ = std::io::stderr().lock().write_all(line.as_bytes());
    }
}
#[derive(Default)]
pub(super) struct Capture {
    reader: bool,
    reader_exit_at: Option<Instant>,
    budget_ms: Option<u32>,
    observation: Option<Observation>,
    workflow_start: Option<Instant>,
    first_offset: Option<u32>,
    window_offset: Option<u32>,
    completed: Vec<u32>,
    timing_frozen: Option<Timing>,
    started: Option<Instant>,
    last_job: Option<Job>,
    records: u16,
    failure: Option<Failure>,
}
impl Capture {
    pub(super) fn with_workflow_start(start: Instant) -> Self {
        Self {
            workflow_start: Some(start),
            ..Default::default()
        }
    }
    pub(super) fn financial_producer(start: Instant) -> Self {
        Self {
            workflow_start: Some(start),
            budget_ms: Some(FINANCIAL_TIMING_LIMIT_MS),
            ..Default::default()
        }
    }
    pub(super) fn financial_reader(start: Instant) -> Self {
        Self {
            reader: true,
            budget_ms: Some(FINANCIAL_TIMING_LIMIT_MS),
            workflow_start: Some(start),
            first_offset: Some(0),
            window_offset: Some(0),
            started: Some(start),
            observation: Some(Observation {
                window: 0,
                owner: 0,
                phase: Phase::ReaderHostOpen,
                call: Call::Begin,
                last_native: None,
            }),
            ..Default::default()
        }
    }
    // Only successful reader exit may defer parsing until the bounded terminal
    // drain. Neither elapsed cleanup time nor buffered markers renew a window.
    pub(super) fn observe_reader_exit(&mut self, now: Instant) {
        if self.reader && self.reader_exit_at.is_none() && self.timing_frozen.is_none() {
            let _ = self.failure_at(now);
            self.reader_exit_at = Some(now);
        }
    }
    fn budget(&self) -> u32 {
        self.budget_ms.unwrap_or(LEGACY_TIMING_LIMIT_MS)
    }
    fn offset(&self, now: Instant) -> u32 {
        self.workflow_start
            .map(|start| {
                now.saturating_duration_since(start)
                    .as_millis()
                    .min(u128::from(self.budget())) as u32
            })
            .unwrap_or(0)
    }
    pub(super) fn freeze_timing(&mut self, now: Instant) {
        let now = self.reader_exit_at.unwrap_or(now);
        if self.timing_frozen.is_some() {
            return;
        }
        let Some(start) = self.workflow_start else {
            return;
        };
        let total = self.offset(now);
        self.timing_frozen = Some(Timing {
            budget_ms: self.budget(),
            elapsed_before_first_window_ms: self.first_offset,
            completed_window_elapsed_ms: self.completed.clone(),
            current_window_elapsed_ms: self
                .window_offset
                .map(|offset| total.saturating_sub(offset)),
            total_elapsed_ms: total,
            clamped: now.saturating_duration_since(start)
                > Duration::from_millis(u64::from(self.budget())),
        });
    }
    pub(super) fn timing(&self) -> Option<Timing> {
        self.timing_frozen.clone()
    }

    pub(super) fn line(&mut self, line: &str, now: Instant) {
        let now = self.reader_exit_at.unwrap_or(now);
        let Some(payload) = line.strip_prefix(PREFIX) else {
            return;
        };
        if self.failure.is_some() {
            return;
        }
        if line.len() > 512 || self.records >= 1024 {
            self.refuse_at(now);
            return;
        }
        self.records += 1;
        let Some(payload) = payload.strip_suffix(']') else {
            self.refuse_at(now);
            return;
        };
        let Ok(record) = serde_json::from_str::<Record>(payload) else {
            self.refuse_at(now);
            return;
        };
        // Teardown/drain may validate framing but cannot rewrite the terminal
        // parent timing/location snapshot.
        if self.timing_frozen.is_some() {
            return;
        }
        match record {
            Record::Call { call } => {
                if let Some(observation) = self.observation.as_mut() {
                    observation.call = call;
                }
            }
            Record::Begin { owner, phase } => {
                let Some(window) = (if self.reader {
                    reader_ordinal(owner, phase)
                } else {
                    ordinal(owner, phase)
                }) else {
                    self.refuse_at(now);
                    return;
                };
                if let Some(old) = self.observation {
                    if window == old.window && owner == old.owner && phase == old.phase {
                        return;
                    }
                    if window != old.window + 1 {
                        self.refuse_at(now);
                        return;
                    }
                    // A late new marker cannot rescue an already expired window.
                    if self.failure_at(now).is_some() {
                        return;
                    }
                } else if window != 0 {
                    self.refuse_at(now);
                    return;
                }
                if self.timing_frozen.is_none() && self.workflow_start.is_some() {
                    let offset = self.offset(now);
                    if let Some(previous) = self.window_offset {
                        self.completed.push(offset.saturating_sub(previous));
                    } else {
                        self.first_offset = Some(offset);
                    }
                    self.window_offset = Some(offset);
                }
                self.observation = Some(Observation {
                    window,
                    owner,
                    phase,
                    call: Call::Begin,
                    last_native: self.last_job,
                });
                self.started = Some(now);
            }
            Record::Job {
                owner,
                job_id,
                sequence,
                stage,
            } => {
                if self.reader
                    || !(1..=2).contains(&owner)
                    || job_id == 0
                    || sequence == 0
                    || sequence > 0x00ff_ffff
                {
                    self.refuse_at(now);
                    return;
                }
                let job = Job {
                    owner,
                    job_id,
                    sequence,
                    stage,
                };
                self.last_job = Some(job);
                if let Some(observation) = self.observation.as_mut() {
                    observation.last_native = Some(job);
                }
                // Observed job changes are location only, never a new time budget.
            }
        }
    }
    pub(super) fn finish_partial(&mut self, bytes: &[u8]) {
        if self.failure.is_none()
            && !bytes.is_empty()
            && (bytes.starts_with(PREFIX.as_bytes()) || PREFIX.as_bytes().starts_with(bytes))
        {
            self.refuse_at(Instant::now());
        }
    }
    fn refuse_at(&mut self, now: Instant) {
        self.freeze_timing(now);
        self.failure = Some(Failure {
            reason: Reason::InvalidProgress,
            last: self.observation,
        });
    }
    pub(super) fn failure_at(&mut self, now: Instant) -> Option<Failure> {
        if self.failure.is_none()
            && self
                .started
                .is_some_and(|start| now.saturating_duration_since(start) >= WINDOW)
        {
            self.freeze_timing(now);
            self.failure = Some(Failure {
                reason: Reason::PhaseDeadline,
                last: self.observation,
            });
        }
        self.failure
    }
    pub(super) fn global_deadline(&mut self) {
        if self.failure.is_none() {
            self.freeze_timing(Instant::now());
            self.failure = Some(Failure {
                reason: Reason::GlobalDeadline,
                last: self.observation,
            });
        }
    }
    pub(super) fn failure(&self) -> Option<Failure> {
        self.failure
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn line(record: Record) -> String {
        format!("{PREFIX}{}]", serde_json::to_string(&record).unwrap())
    }
    #[test]
    fn phase_window_never_renews_from_duplicate_or_job_pulses() {
        let start = Instant::now();
        let mut c = Capture::default();
        let begin = line(Record::Begin {
            owner: 1,
            phase: Phase::SourceOpen,
        });
        c.line(&begin, start);
        c.line(&begin, start + Duration::from_secs(100));
        c.line(
            &line(Record::Job {
                owner: 1,
                job_id: 1,
                sequence: 1,
                stage: FinancialNativeStageV1::AuthorityAdmit,
            }),
            start + Duration::from_secs(119),
        );
        assert_eq!(
            c.failure_at(start + WINDOW).unwrap().reason,
            Reason::PhaseDeadline
        );
        c.line(
            &line(Record::Begin {
                owner: 1,
                phase: Phase::ReadContinue,
            }),
            start + WINDOW,
        );
        assert_eq!(c.failure().unwrap().last.unwrap().phase, Phase::SourceOpen);
    }
    #[test]
    fn phase_order_and_closed_records_refuse() {
        let start = Instant::now();
        let mut c = Capture::default();
        c.line(
            &line(Record::Begin {
                owner: 2,
                phase: Phase::SourceOpen,
            }),
            start,
        );
        assert_eq!(c.failure().unwrap().reason, Reason::InvalidProgress);
        for raw in ["[FINANCIAL_PROGRESS_V1 {\"kind\":\"Begin\",\"owner\":1,\"phase\":\"SourceOpen\",\"extra\":1}]","[FINANCIAL_PROGRESS_V1 invalid]"] {let mut c=Capture::default();c.line(raw,start);assert_eq!(c.failure().unwrap().reason,Reason::InvalidProgress);}
        let mut c = Capture::default();
        c.line(
            &line(Record::Begin {
                owner: 1,
                phase: Phase::SourceOpen,
            }),
            start,
        );
        c.line(
            &line(Record::Begin {
                owner: 1,
                phase: Phase::Acquire,
            }),
            start,
        );
        assert!(c.failure().is_some());
    }
    #[test]
    fn exact_next_action_gets_new_supervisory_window_only_before_expiry() {
        let start = Instant::now();
        let mut c = Capture::default();
        c.line(
            &line(Record::Begin {
                owner: 1,
                phase: Phase::SourceOpen,
            }),
            start,
        );
        c.line(
            &line(Record::Begin {
                owner: 1,
                phase: Phase::ReadContinue,
            }),
            start + Duration::from_secs(20),
        );
        assert!(c.failure_at(start + Duration::from_secs(139)).is_none());
        assert!(c.failure_at(start + Duration::from_secs(140)).is_some());
    }
    #[test]
    fn calls_partial_records_and_global_bound_keep_last_location() {
        let start = Instant::now();
        let mut c = Capture::default();
        c.line(
            &line(Record::Begin {
                owner: 1,
                phase: Phase::SourceOpen,
            }),
            start,
        );
        c.line(
            &line(Record::Call {
                call: Call::WaitPhase,
            }),
            start + Duration::from_secs(50),
        );
        c.line(
            &line(Record::Call {
                call: Call::DropServer,
            }),
            start + Duration::from_secs(119),
        );
        let failure = c.failure_at(start + WINDOW).unwrap();
        assert_eq!(failure.last.unwrap().call, Call::DropServer);
        let mut c = Capture::default();
        c.line(
            &line(Record::Begin {
                owner: 1,
                phase: Phase::SourceOpen,
            }),
            start,
        );
        c.finish_partial(b"[FINANCIAL_PROGRESS_V1 {\"kind\":");
        assert_eq!(c.failure().unwrap().reason, Reason::InvalidProgress);
        assert_eq!(c.failure().unwrap().last.unwrap().phase, Phase::SourceOpen);
        let mut short = Capture::default();
        short.finish_partial(b"[FINANCIAL_PRO");
        assert_eq!(short.failure().unwrap().reason, Reason::InvalidProgress);
        let mut c = Capture::default();
        assert!(c.failure_at(start + WINDOW).is_none());
        c.global_deadline();
        assert_eq!(
            c.failure(),
            Some(Failure {
                reason: Reason::GlobalDeadline,
                last: None
            })
        );
    }

    #[test]
    fn exact_twenty_seven_windows_are_finite_and_backward_owner_refuses() {
        let start = Instant::now();
        let mut c = Capture::default();
        let mut count = 0;
        for owner in 1..=2 {
            for phase in [
                Phase::SourceOpen,
                Phase::ReadContinue,
                Phase::Continue,
                Phase::Admission,
                Phase::ReadAcquire,
                Phase::Acquire,
                Phase::ReadActivate,
                Phase::Activate,
                Phase::Wallet,
                Phase::ReadSign,
                Phase::Sign,
            ] {
                c.line(&line(Record::Begin { owner, phase }), start);
                assert!(c.failure().is_none());
                count += 1;
            }
        }
        for (owner, phase) in [
            (0, Phase::PairHistory),
            (1, Phase::Return),
            (2, Phase::Return),
            (0, Phase::FinalRetention),
            (0, Phase::Shutdown),
        ] {
            c.line(&line(Record::Begin { owner, phase }), start);
            assert!(c.failure().is_none());
            count += 1;
        }
        assert_eq!(count, 27);
        assert_eq!(c.observation.unwrap().window, 26);
        c.line(
            &line(Record::Begin {
                owner: 1,
                phase: Phase::SourceOpen,
            }),
            start,
        );
        assert_eq!(c.failure().unwrap().reason, Reason::InvalidProgress);
    }

    #[test]
    fn phase_timing_accounts_prelude_completed_current_without_heartbeat_reset() {
        let start = Instant::now();
        let mut c = Capture::with_workflow_start(start);
        let begin = line(Record::Begin {
            owner: 1,
            phase: Phase::SourceOpen,
        });
        c.line(&begin, start + Duration::from_millis(1001));
        c.line(&begin, start + Duration::from_millis(2000));
        c.line(
            &line(Record::Call {
                call: Call::WaitPhase,
            }),
            start + Duration::from_millis(2500),
        );
        c.line(
            &line(Record::Begin {
                owner: 1,
                phase: Phase::ReadContinue,
            }),
            start + Duration::from_millis(3002),
        );
        c.freeze_timing(start + Duration::from_millis(5004));
        let t = c.timing().unwrap();
        assert_eq!(t.elapsed_before_first_window_ms, Some(1001));
        assert_eq!(t.completed_window_elapsed_ms, vec![2001]);
        assert_eq!(t.current_window_elapsed_ms, Some(2002));
        assert_eq!(t.total_elapsed_ms, 5004);
        assert!(t.matches_observation(c.observation));
        c.line(
            &line(Record::Begin {
                owner: 1,
                phase: Phase::Continue,
            }),
            start + Duration::from_secs(7),
        );
        c.freeze_timing(start + Duration::from_secs(8));
        assert_eq!(c.timing().unwrap(), t);
        assert_eq!(c.observation.unwrap().window, 1);
    }
    #[test]
    fn phase_timing_caps_global_no_marker_and_refuses_invalid_serialized_shape() {
        let start = Instant::now();
        let mut c = Capture::with_workflow_start(start);
        c.freeze_timing(start + Duration::from_secs(901));
        let t = c.timing().unwrap();
        assert_eq!(t.total_elapsed_ms, 900000);
        assert!(t.clamped);
        assert!(t.matches_observation(None));
        let mut value = serde_json::to_value(&t).unwrap();
        value["completed_window_elapsed_ms"] = serde_json::json!([1]);
        assert!(serde_json::from_value::<Timing>(value).is_err());
        let mut value = serde_json::to_value(&t).unwrap();
        value["total_elapsed_ms"] = serde_json::json!(900001);
        assert!(serde_json::from_value::<Timing>(value).is_err());
        let mut value = serde_json::to_value(&t).unwrap();
        value["extra"] = serde_json::json!(0);
        assert!(serde_json::from_value::<Timing>(value).is_err());
        let mut value = serde_json::to_value(&t).unwrap();
        value["total_elapsed_ms"] = serde_json::json!(899999);
        assert!(serde_json::from_value::<Timing>(value).is_err());
        let mut value = serde_json::to_value(&t).unwrap();
        value["elapsed_before_first_window_ms"] = serde_json::json!(900000);
        value["current_window_elapsed_ms"] = serde_json::json!(0);
        value["completed_window_elapsed_ms"] = serde_json::json!(vec![0u32; 27]);
        assert!(serde_json::from_value::<Timing>(value).is_err());
        let mut c = Capture::with_workflow_start(start);
        c.line(
            &line(Record::Begin {
                owner: 1,
                phase: Phase::SourceOpen,
            }),
            start + Duration::from_secs(10),
        );
        c.line(
            "[FINANCIAL_PROGRESS_V1 invalid]",
            start + Duration::from_secs(12),
        );
        c.freeze_timing(start + Duration::from_secs(25));
        let t = c.timing().unwrap();
        assert_eq!(t.total_elapsed_ms, 12000);
        assert_eq!(t.current_window_elapsed_ms, Some(2000));
        assert!(t.matches_observation(c.failure().unwrap().last));
    }

    #[test]
    fn financial_reader_initial_watchdog_and_profile_are_nonrenewing() {
        let start = Instant::now();
        let mut reader = Capture::financial_reader(start);
        assert!(reader
            .failure_at(start + Duration::from_secs(119))
            .is_none());
        reader.line(
            &line(Record::Begin {
                owner: 0,
                phase: Phase::ReaderHostOpen,
            }),
            start + Duration::from_secs(119),
        );
        reader.line(
            &line(Record::Call {
                call: Call::WaitPhase,
            }),
            start + Duration::from_secs(119),
        );
        assert_eq!(
            reader
                .failure_at(start + WINDOW)
                .unwrap()
                .last
                .unwrap()
                .phase,
            Phase::ReaderHostOpen
        );
        let mut no_marker = Capture::financial_reader(start);
        assert!(no_marker.failure_at(start + WINDOW).is_some());
        let mut financial = Capture::financial_producer(start);
        financial.freeze_timing(start + Duration::from_secs(1801));
        let t = financial.timing().unwrap();
        assert_eq!(t.budget_ms, 1800000);
        assert_eq!(t.total_elapsed_ms, 1800000);
        assert!(t.clamped);
        let mut legacy = Capture::with_workflow_start(start);
        legacy.freeze_timing(start + Duration::from_secs(901));
        assert_eq!(legacy.timing().unwrap().budget_ms, 900000);
        let mut invalid = serde_json::to_value(t).unwrap();
        invalid["budget_ms"] = serde_json::json!(1800001);
        assert!(serde_json::from_value::<Timing>(invalid).is_err());
    }
    #[test]
    fn financial_reader_exact_order_and_no_native_jobs() {
        let start = Instant::now();
        let mut reader = Capture::financial_reader(start);
        for phase in [
            Phase::ReaderHostOpen,
            Phase::ReaderWitnessReopen,
            Phase::ReaderProviderReopen,
            Phase::ReaderFirstSummary,
            Phase::ReaderInitialHistoryA,
            Phase::ReaderInitialHistoryB,
            Phase::ReaderPartialDispatch,
            Phase::ReaderReconcileHistoryA,
            Phase::ReaderReconcileHistoryB,
            Phase::ReaderPartialSummary,
            Phase::ReaderStaleProbe,
            Phase::ReaderFinalDispatch,
            Phase::ReaderFinalSummary,
            Phase::ReaderFinalHistoryA,
            Phase::ReaderFinalHistoryB,
            Phase::ReaderShutdown,
        ] {
            reader.line(&line(Record::Begin { owner: 0, phase }), start);
            assert!(reader.failure().is_none());
        }
        reader.freeze_timing(start + Duration::from_secs(1));
        let t = reader.timing().unwrap();
        assert_eq!(t.completed_window_elapsed_ms.len(), 15);
        assert!(t.matches_observation(reader.observation));
        let mut reader = Capture::financial_reader(start);
        reader.line(
            &line(Record::Job {
                owner: 1,
                job_id: 1,
                sequence: 1,
                stage: FinancialNativeStageV1::AuthorityAdmit,
            }),
            start,
        );
        assert!(reader.failure().is_some());
    }
    #[test]
    fn financial_reader_buffered_shutdown_uses_exit_time_without_rescue() {
        let start = Instant::now();
        let mut reader = Capture::financial_reader(start);
        // This fixture starts at the last active window, without fabricating
        // production authority. The tested parser is the real parent capture.
        reader.observation = Some(Observation {
            window: 14,
            owner: 0,
            phase: Phase::ReaderFinalHistoryB,
            call: Call::Begin,
            last_native: None,
        });
        reader.completed = vec![0; 14];
        reader.observe_reader_exit(start + Duration::from_secs(10));
        reader.line(
            &line(Record::Begin {
                owner: 0,
                phase: Phase::ReaderShutdown,
            }),
            start + Duration::from_secs(30),
        );
        reader.freeze_timing(start + Duration::from_secs(40));
        let timing = reader.timing().unwrap();
        assert_eq!(timing.completed_window_elapsed_ms.len(), 15);
        assert_eq!(timing.total_elapsed_ms, 10000);
        assert_eq!(timing.current_window_elapsed_ms, Some(0));
        assert!(reader.failure().is_none());
        let mut expired = Capture::financial_reader(start);
        expired.observe_reader_exit(start + WINDOW);
        expired.line(
            &line(Record::Begin {
                owner: 0,
                phase: Phase::ReaderWitnessReopen,
            }),
            start + WINDOW + Duration::from_secs(5),
        );
        assert_eq!(
            expired.failure().unwrap().last.unwrap().phase,
            Phase::ReaderHostOpen
        );
        assert_eq!(expired.timing().unwrap().total_elapsed_ms, 120000);
    }
}
