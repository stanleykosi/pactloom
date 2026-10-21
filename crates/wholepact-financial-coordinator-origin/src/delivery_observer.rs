//! Separate CI-only observation. No input, role/FD import, source access, effect
//! method or product restriction is provided. Failure invalidates evidence only.
use crate::{process::Role, DeliveryOutcomeV1, DeliveryReadyV1, DeliveryFailureV1};
use serde::Serialize;
use std::{collections::BTreeMap, fs::OpenOptions, io::Write, os::unix::fs::{MetadataExt, OpenOptionsExt}, sync::{Arc, OnceLock, Mutex, atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering}, mpsc}, thread, time::{Duration, Instant}};
const DIRECTORY: &str = "/run/wholepact-delivery-evidence";
const MAX_RECORDS: u32 = 512;
const MAX_BYTES: usize = 256 * 1024;
const QUEUE: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum DeliveryUiPhaseV1 { Selecting, Preparing, Reading, Acknowledging, Armed, InFlight, Revoked, Finished }
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum DeliveryWidgetIdV1 { Endpoint, ServerName, WitnessId, ServerCertificateDigest, NetworkProfile, AccountId, StorageKeyPath, ServerCertificatePath, ServerPrivateKeyPath, ClientRootPath, OwnerCertificate, Request, Prepare, Review, Continue, Acknowledge, Arm, Cancel, Close }
#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
pub struct DeliveryRectV1 { pub left: f32, pub top: f32, pub right: f32, pub bottom: f32 }
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct DeliveryWidgetRectV1 { pub widget: DeliveryWidgetIdV1, pub rect: DeliveryRectV1, pub enabled: bool }
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct DeliveryWidgetSnapshotV1 {
    pub frame: u64, pub pass: u64, pub pixels_per_point: f32, pub phase: DeliveryUiPhaseV1,
    pub viewport: DeliveryRectV1, pub presentation_digest: Option<String>, pub focused: bool,
    pub raw_blur: bool, pub revoked: bool, pub read_to_end: bool, pub continued: bool, pub acknowledged: bool,
    pub widgets: Vec<DeliveryWidgetRectV1>,
}
// CI-only closed shape classes: no input bytes, lengths, hashes or paths.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum DeliveryInputClassV1 {
    Valid, PacketEncoding, PacketLimit, Empty, Length, Endpoint, ServerName,
    Identifier, Hash, Path, CertificateHex, CertificateDer, RequestJson,
    RequestVariant, RequestBinding, RequestShape, Unclassified,
}
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "observation", content = "facts")]
pub enum DeliveryObservationV1 {
    WidgetSnapshot(DeliveryWidgetSnapshotV1),
    InputValidation { field: Option<DeliveryWidgetIdV1>, class: DeliveryInputClassV1 },
    RawInterruption { blur: bool, focused: bool, escape: bool, close: bool },
    PresentationCleared { presentation_digest: Option<String>, admitted: bool },
    WorkerJoined { presentation_digest: Option<String> },
    DriverJoined { clean: bool },
}
#[derive(Clone, Serialize)]
pub(super) struct ChildBinding { pub(super) role: String, pub(super) pid: i32 }
#[derive(Clone, Serialize)]
#[serde(tag = "event", content = "detail")]
pub(super) enum Event {
    RetainedBindings { children: Vec<ChildBinding>, startup_deadline_ms: u64, session_deadline_ms: u64 },
    Observation(DeliveryObservationV1),
    Review { direction: Direction, presentation_digest: String, prepared_at_ms: u64, expires_at_ms: u64, monotonic_deadline_ms: u64 },
    Ready { direction: Direction, data: DeliveryReadyV1, monotonic_deadline_ms: u64 },
    Arm { direction: Direction, presentation_digest: String },
    Admit { direction: Direction, presentation_digest: String, effect_commitment: String },
    Cancel { direction: Direction },
    Outcome { direction: Direction, data: DeliveryOutcomeV1 },
    FirstFailure { direction: Direction, data: DeliveryFailureV1 },
    PreparationFailed { direction: Direction },
    Disposed { direction: Direction },
    Prepare { direction: Direction, original_ceiling_ms: Option<u64> },
    OwnedReap { child_role: String, child_pid: i32, exit_code: Option<i32>, signal: Option<i32>, forced: bool },
    RoleFinished { exit_code: i32 },
    EvidenceClosed { complete: bool },
}
#[derive(Clone, Copy, Serialize)]
pub(super) enum Direction { Native, Sent, Received }
#[derive(Serialize)]
struct Record {
    version: u8, sequence: u32, role: String, pid: i32, ppid: i32,
    original_parent_pid: i32, elapsed_ms: u64,
    #[serde(flatten)] event: Event,
}
struct Shared {
    role: Role, pid: i32, original_parent: i32, epoch: Instant, hard_end: Instant,
    stamp: AtomicU64, snapshots: AtomicU32, failed: AtomicBool, finish: AtomicBool,
}
struct Observer { shared: Arc<Shared>, tx: mpsc::SyncSender<Record>, writer: Mutex<Option<thread::JoinHandle<()>>> }
static OBSERVER: OnceLock<Observer> = OnceLock::new();

pub(super) fn initialize(role: Role, original_parent: i32, session: Instant, children: Vec<ChildBinding>) {
    // No observer is initialized before the fixed forks. C calls this only
    // AFTER its single-threaded desktop-coordinate restoration has completed.
    let epoch = session - Duration::from_secs(300);
    let shared = Arc::new(Shared { role, pid: unsafe { libc::getpid() }, original_parent, epoch,
        hard_end: session + Duration::from_secs(5), stamp: AtomicU64::new(0), snapshots: AtomicU32::new(0), failed: AtomicBool::new(false), finish: AtomicBool::new(false) });
    let (tx, rx) = mpsc::sync_channel(QUEUE);
    let state = Arc::clone(&shared);
    let writer = thread::Builder::new().name("delivery-ci-evidence".into()).spawn(move || write_records(state, rx)).ok();
    if writer.is_none() { shared.failed.store(true, Ordering::Release); }
    if OBSERVER.set(Observer { shared, tx, writer: Mutex::new(writer) }).is_err() { return; }
    record(Event::RetainedBindings { children, startup_deadline_ms: 30_000, session_deadline_ms: 300_000 });
}
fn next_stamp(old: u64, sampled: u32) -> Option<u64> {
    let sequence = ((old >> 32) as u32).checked_add(1)?;
    if sequence > MAX_RECORDS { return None; }
    Some(((sequence as u64) << 32) | sampled.max(old as u32) as u64)
}
fn make_record(shared: &Shared, event: Event) -> Option<Record> {
    if shared.failed.load(Ordering::Acquire) { return None; }
    let sampled = shared.epoch.elapsed().as_millis().min(u32::MAX as u128) as u32;
    // One lock-free stamp orders sequence/time together at the real hook, not
    // at filesystem write time. No callback, lock, I/O or authority transition.
    let mut old = shared.stamp.load(Ordering::Acquire);
    let (sequence, elapsed) = loop {
        let Some(next) = next_stamp(old, sampled) else { shared.failed.store(true, Ordering::Release); return None; };
        let sequence = (next >> 32) as u32; let elapsed = next as u32;
        match shared.stamp.compare_exchange_weak(old, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => break (sequence, elapsed), Err(actual) => old = actual,
        }
    };
    Some(Record { version: 1, sequence, role: format!("{:?}", shared.role), pid: shared.pid,
        ppid: unsafe { libc::getppid() }, original_parent_pid: shared.original_parent,
        elapsed_ms: elapsed as u64, event })
}
pub(super) fn record(event: Event) {
    let Some(observer) = OBSERVER.get() else { return; };
    // All real producers have ended before final flush. A future misplaced
    // hook is refused, not silently accepted after the closing record.
    if observer.shared.finish.load(Ordering::Acquire) { observer.shared.failed.store(true, Ordering::Release); return; }
    if let Some(value) = make_record(&observer.shared, event) {
        if observer.tx.try_send(value).is_err() { observer.shared.failed.store(true, Ordering::Release); }
    }
}
pub(super) fn deadline_ms(deadline: Instant) -> u64 {
    OBSERVER.get().map_or(0, |observer| deadline.saturating_duration_since(observer.shared.epoch).as_millis().min(u64::MAX as u128) as u64)
}
/// CI-only inert records. The branch role is never supplied by callers. Only
/// real private native/worker/join call sites use the corresponding closed item.
pub fn record_delivery_observation_for_ci(value: DeliveryObservationV1) {
    let Some(observer) = OBSERVER.get() else { return; };
    let allowed = match &value {
        DeliveryObservationV1::WorkerJoined { .. } => observer.shared.role == Role::Owner1V3DeliveryAdmission,
        _ => observer.shared.role == Role::Coordinator,
    };
    let overflow = matches!(&value, DeliveryObservationV1::WidgetSnapshot(_)) && observer.shared.snapshots.fetch_add(1, Ordering::AcqRel) >= 256;
    if !allowed || overflow || !valid_observation(&value) { observer.shared.failed.store(true, Ordering::Release); return; }
    record(Event::Observation(value));
}
fn valid_observation(value: &DeliveryObservationV1) -> bool {
    fn digest(value: &Option<String>) -> bool { value.as_ref().is_none_or(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))) }
    fn rect(r: &DeliveryRectV1) -> bool { [r.left, r.top, r.right, r.bottom].iter().all(|v| v.is_finite() && v.abs() <= 16384.0) && r.left < r.right && r.top < r.bottom }
    match value {
        DeliveryObservationV1::WidgetSnapshot(s) => s.pixels_per_point.is_finite() && s.pixels_per_point > 0.0 && s.pixels_per_point <= 8.0
            && rect(&s.viewport) && digest(&s.presentation_digest) && s.widgets.len() <= 20 && s.widgets.iter().all(|w| rect(&w.rect))
            && s.widgets.iter().all(|w| w.rect.left >= s.viewport.left && w.rect.top >= s.viewport.top && w.rect.right <= s.viewport.right && w.rect.bottom <= s.viewport.bottom)
            && s.widgets.iter().enumerate().all(|(i, w)| !s.widgets[..i].iter().any(|old| old.widget == w.widget)),
        DeliveryObservationV1::WorkerJoined { presentation_digest } | DeliveryObservationV1::PresentationCleared { presentation_digest, .. } => digest(presentation_digest),
        _ => true,
    }
}
fn write_records(shared: Arc<Shared>, receive: mpsc::Receiver<Record>) {
    let mut pending = BTreeMap::new(); let mut next = 1; let mut bytes = 0usize;
    loop {
        match receive.recv_timeout(Duration::from_millis(5)) {
            Ok(record) => { pending.insert(record.sequence, record); }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => if shared.finish.load(Ordering::Acquire) { break; },
        }
        while let Some(record) = pending.remove(&next) {
            if append_record(&shared, &record, &mut bytes).is_err() { shared.failed.store(true, Ordering::Release); return; }
            next += 1;
        }
        if shared.failed.load(Ordering::Acquire) { break; }
    }
    let complete = !shared.failed.load(Ordering::Acquire) && pending.is_empty() && next == ((shared.stamp.load(Ordering::Acquire) >> 32) as u32 + 1);
    if !complete { shared.failed.store(true, Ordering::Release); return; }
    if let Some(record) = make_record(&shared, Event::EvidenceClosed { complete: true }) {
        if append_record(&shared, &record, &mut bytes).is_err() { shared.failed.store(true, Ordering::Release); }
    }
}
fn append_record(shared: &Shared, record: &Record, count: &mut usize) -> std::io::Result<()> {
    let directory = std::fs::symlink_metadata(DIRECTORY)?;
    if !directory.is_dir() || directory.uid() != unsafe { libc::geteuid() } || directory.mode() & 0o7777 != 0o700 {
        return Err(std::io::ErrorKind::PermissionDenied.into());
    }
    let path = format!("{DIRECTORY}/{}.jsonl", shared.pid);
    let mut options = OpenOptions::new(); options.write(true).append(true).mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    if record.sequence == 1 { options.create_new(true); }
    let mut file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o7777 != 0o600 || metadata.nlink() != 1 || metadata.len() != *count as u64 {
        return Err(std::io::ErrorKind::PermissionDenied.into());
    }
    let mut bytes = serde_json::to_vec(record)?; bytes.push(b'\n');
    if bytes.len() > 16 * 1024 || *count + bytes.len() > MAX_BYTES { return Err(std::io::ErrorKind::InvalidData.into()); }
    file.write_all(&bytes)?; *count += bytes.len(); Ok(()) // FD closes here, every record.
}
/// Evidence cleanup only, after product ownership has already reached its
/// terminal path. It cannot extend a product clock or change an effect outcome.
/// The pinned call sites establish producer quiescence: C has returned from
/// eframe and joined its driver; H/S/other W have only their finishing main
/// thread; selected W has only monitor hooks (even on error, its possibly blocked
/// source worker never writes observer records). The writer is the only remaining
/// record constructor and emits EvidenceClosed. Panic paths missing this call
/// cannot claim complete evidence.
pub fn finish_delivery_observation_for_ci(exit_code: i32) {
    let Some(observer) = OBSERVER.get() else { return; };
    record(Event::RoleFinished { exit_code }); observer.shared.finish.store(true, Ordering::Release);
    let end = (Instant::now() + Duration::from_millis(250)).min(observer.shared.hard_end);
    let Ok(mut writer) = observer.writer.lock() else { observer.shared.failed.store(true, Ordering::Release); return; };
    let Some(handle) = writer.take() else { return; };
    while !handle.is_finished() && Instant::now() < end { thread::sleep(Duration::from_millis(1)); }
    if handle.is_finished() { if handle.join().is_err() { observer.shared.failed.store(true, Ordering::Release); } }
    else { observer.shared.failed.store(true, Ordering::Release); } // detached only until immediate process exit
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn snapshot_validation_is_finite_geometry_only() {
        let r = DeliveryRectV1 { left: 0.0, top: 0.0, right: 100.0, bottom: 100.0 };
        let mut s = DeliveryWidgetSnapshotV1 { frame: 1, pass: 1, pixels_per_point: 1.0, phase: DeliveryUiPhaseV1::Selecting,
            viewport: r, presentation_digest: None, focused: true, raw_blur: false, revoked: false, read_to_end: false, continued: false, acknowledged: false,
            widgets: vec![DeliveryWidgetRectV1 { widget: DeliveryWidgetIdV1::Prepare, rect: r, enabled: true }] };
        assert!(valid_observation(&DeliveryObservationV1::WidgetSnapshot(s.clone())));
        s.widgets.push(s.widgets[0].clone()); assert!(!valid_observation(&DeliveryObservationV1::WidgetSnapshot(s.clone())));
        s.widgets.pop(); s.pixels_per_point = f32::NAN; assert!(!valid_observation(&DeliveryObservationV1::WidgetSnapshot(s)));
    }
    #[test]
    fn stamp_is_monotone_and_capped_without_any_process_or_file() {
        let first = next_stamp(0, 50).unwrap(); assert_eq!(first >> 32, 1); assert_eq!(first as u32, 50);
        let second = next_stamp(first, 49).unwrap(); assert_eq!(second >> 32, 2); assert_eq!(second as u32, 50);
        assert_eq!(next_stamp(second, 80).unwrap() as u32, 80);
        assert!(next_stamp((MAX_RECORDS as u64) << 32, 100).is_none());
    }
    #[test]
    fn ordinary_observer_serialization_has_closed_envelope_and_no_input_values() {
        let record = Record { version: 1, sequence: 1, role: "Coordinator".into(), pid: 2, ppid: 1, original_parent_pid: 1,
            elapsed_ms: 8, event: Event::Observation(DeliveryObservationV1::DriverJoined { clean: true }) };
        let value = serde_json::to_value(record).unwrap();
        let object = value.as_object().unwrap(); assert_eq!(object.len(), 9);
        for name in ["version", "sequence", "role", "pid", "ppid", "original_parent_pid", "elapsed_ms", "event", "detail"] { assert!(object.contains_key(name)); }
        assert_eq!(value["event"], "Observation"); assert_eq!(value["detail"]["observation"], "DriverJoined");
        assert_eq!(value["detail"]["facts"]["clean"], true);
    }

}
