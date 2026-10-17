//! Finite Linux test-runner cleanup ownership. Source alone is not runtime evidence.
//! Owns only the successful `setsid` child and the root allocated for that child.
//! No /proc scan, command-line/environment read, subreaper, or namespace change.
//! The reviewed fixture OpenSSL children inherit this group and do not daemonize.
//! Group absence is NOT evidence that the runner reaped those grandchildren.
//! Contract: this exact isolated test invocation is the exclusive child waiter;
//! no concurrent thread/handler may reap its children or mutate SIGCHLD policy.
//! Read-only policy checks reject unsafe inheritance, but cannot enforce that
//! contract against arbitrary injected code or a concurrent signal-policy writer.

use std::{
    io,
    process::{Child, Command, ExitStatus},
    time::{Duration, Instant},
};

const CLEANUP_LIMIT: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(5);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChildWaitPolicyV1 {
    DefaultPreservesZombie,
    Unsupported,
    Unverified,
}
fn classify_wait_policy(handler: libc::sighandler_t, flags: libc::c_int) -> ChildWaitPolicyV1 {
    if handler == libc::SIG_DFL && flags & libc::SA_NOCLDWAIT == 0 {
        ChildWaitPolicyV1::DefaultPreservesZombie
    } else {
        // Explicit SIG_IGN, SA_NOCLDWAIT and every custom handler are refused.
        ChildWaitPolicyV1::Unsupported
    }
}
fn read_wait_policy() -> ChildWaitPolicyV1 {
    let mut action = std::mem::MaybeUninit::<libc::sigaction>::zeroed();
    // Null new-action pointer: observe only, never install/alter a disposition.
    if unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), action.as_mut_ptr()) } != 0 {
        return ChildWaitPolicyV1::Unverified;
    }
    let action = unsafe { action.assume_init() };
    classify_wait_policy(action.sa_sigaction, action.sa_flags)
}
fn under_verified_wait_policy<T>(
    policy: ChildWaitPolicyV1,
    operation: impl FnOnce() -> io::Result<T>,
) -> io::Result<T> {
    if policy != ChildWaitPolicyV1::DefaultPreservesZombie {
        return Err(io::Error::other("synthetic child wait policy unverified"));
    }
    operation()
}
/// Check before TLS preparation too: that helper also creates direct children.
/// Caller retains its exact root if this policy cannot preserve child anchors.
pub(super) fn require_default_child_wait_policy() -> io::Result<()> {
    under_verified_wait_policy(read_wait_policy(), || Ok(()))
}
/// Re-check immediately before the main spawn; no policy mutation is performed.
/// Exclusive waiting and no concurrent SIGCHLD-policy writers remain required.
pub(super) fn spawn_with_checked_wait_policy(command: &mut Command) -> io::Result<Child> {
    under_verified_wait_policy(read_wait_policy(), || command.spawn())
}

/// Before successful main-child spawn, unwinding must retain the root: a TLS
/// preparation child may still be alive. Explicit known-safe close is separate.
pub(super) struct PreSpawnTemporaryRootV1(Option<tempfile::TempDir>);
impl PreSpawnTemporaryRootV1 {
    pub(super) fn new(root: tempfile::TempDir) -> Self {
        Self(Some(root))
    }
    pub(super) fn path(&self) -> &std::path::Path {
        self.0
            .as_ref()
            .expect("owned pre-spawn temporary root")
            .path()
    }
    pub(super) fn into_tempdir(mut self) -> tempfile::TempDir {
        self.0.take().expect("owned pre-spawn temporary root")
    }
    pub(super) fn keep(self) {
        drop(self);
    }
}
impl Drop for PreSpawnTemporaryRootV1 {
    fn drop(&mut self) {
        if let Some(root) = self.0.take() {
            let _ = root.keep();
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum GroupSignalV1 {
    SentWhileLeaderOwned,
    AlreadyAbsentWhileLeaderOwned,
    Unverified,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum GroupAbsenceV1 {
    OriginalGroupAbsentObserved,
    Unverified,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DirectChildV1 {
    Reaped,
    Unverified,
}

pub(super) struct ProcessCleanupV1<S = ExitStatus> {
    pub(super) group_signal: GroupSignalV1,
    pub(super) group_absence: GroupAbsenceV1,
    pub(super) direct_child: DirectChildV1,
    pub(super) status: Option<S>,
}
impl<S> ProcessCleanupV1<S> {
    pub(super) fn verified(&self) -> bool {
        self.group_signal != GroupSignalV1::Unverified
            && self.group_absence == GroupAbsenceV1::OriginalGroupAbsentObserved
            && self.direct_child == DirectChildV1::Reaped
            && self.status.is_some()
    }
}

/// A root is returned only after verified process cleanup. The caller may read
/// its one allowlisted outcome sidecar, then must explicitly close the TempDir
/// and verify exact-path absence before publishing success. Never log the path.
pub(super) struct FinishedOwnedGroupV1 {
    pub(super) process: ProcessCleanupV1,
    pub(super) root_for_explicit_close: Option<tempfile::TempDir>,
}

pub(super) struct OwnedTestProcessGroupV1 {
    process: Option<OwnedChildOps>,
    root: Option<tempfile::TempDir>,
}
impl OwnedTestProcessGroupV1 {
    /// Call immediately after the existing Command's successful spawn. Its
    /// pre_exec must have completed setsid after spawn_with_checked_wait_policy;
    /// no caller-selected PID/PGID is taken. The exclusive-wait/no-concurrent-
    /// SIGCHLD-policy-mutation contract must hold throughout this child's life.
    pub(super) fn from_spawned_session(child: Child, root: tempfile::TempDir) -> Self {
        Self {
            process: Some(OwnedChildOps {
                child,
                deadline: Instant::now(),
                anchor_available: true,
            }),
            root: Some(root),
        }
    }
    pub(super) fn temporary_root(&self) -> &std::path::Path {
        self.root
            .as_ref()
            .expect("owned synthetic temporary root")
            .path()
    }
    /// Observe exit without reaping. Retaining the exact zombie child anchors
    /// its PID/PGID until the single nonzero group signal in finish/drop.
    pub(super) fn observe_exit(&mut self) -> io::Result<Option<bool>> {
        let process = self
            .process
            .as_mut()
            .ok_or_else(|| io::Error::other("synthetic process owner already finished"))?;
        let result = observe_unreaped_child(&process.child);
        if result.is_err() {
            // In particular, ECHILD may mean an unexpected external waiter or
            // auto-reap policy removed the anchor. Never signal that numeric ID.
            process.anchor_available = false;
        }
        result
    }
    pub(super) fn finish(mut self) -> FinishedOwnedGroupV1 {
        let mut process = self.process.take().expect("owned synthetic child");
        process.deadline = Instant::now() + CLEANUP_LIMIT;
        let outcome = finish_owned_process(&mut process);
        let root = self.root.take();
        let root_for_explicit_close = if outcome.verified() {
            root
        } else {
            if let Some(root) = root {
                // Unknown descendants must not lose files beneath them. A
                // disposable job owner must handle retained-root cleanup later.
                let _ = root.keep();
            }
            None
        };
        FinishedOwnedGroupV1 {
            process: outcome,
            root_for_explicit_close,
        }
    }
}
pub(super) fn observe_unreaped_child(child: &Child) -> io::Result<Option<bool>> {
    let mut information = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            child.id() as libc::id_t,
            information.as_mut_ptr(),
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    let information = unsafe { information.assume_init() };
    let observed = unsafe { information.si_pid() };
    if observed == 0 {
        return Ok(None);
    }
    if observed < 0 || observed as u32 != child.id() {
        return Err(io::Error::other(
            "synthetic exact child observation mismatch",
        ));
    }
    if !matches!(
        information.si_code,
        libc::CLD_EXITED | libc::CLD_KILLED | libc::CLD_DUMPED
    ) {
        return Err(io::Error::other(
            "synthetic exact child exit kind uncertain",
        ));
    }
    Ok(Some(
        information.si_code == libc::CLD_EXITED && unsafe { information.si_status() } == 0,
    ))
}

impl Drop for OwnedTestProcessGroupV1 {
    fn drop(&mut self) {
        // Unwind fallback bounds process polling and cannot be reported as
        // success. Recursive filesystem close below is not preemptible and is
        // NOT a hard wall-clock bound on total Drop. Taking process first also
        // ensures explicit finish never sends a second nonzero signal.
        let verified = self.process.take().is_some_and(|mut process| {
            process.deadline = Instant::now() + CLEANUP_LIMIT;
            finish_owned_process(&mut process).verified()
        });
        if let Some(root) = self.root.take() {
            if verified {
                let _ = root.close();
            } else {
                let _ = root.keep();
            }
        }
    }
}

enum ReapAttempt<S> {
    Pending,
    Reaped(S),
    Unverified,
}
enum GroupObservation {
    Present,
    Absent,
    Unverified,
}

/// Private injection boundary permits pure policy tests without spawning a
/// process, opening a socket, inspecting /proc, or signalling any process.
trait CleanupOps {
    type Status;
    fn owns_unreaped_child(&mut self) -> bool;
    fn wait_policy_preserves_anchor(&mut self) -> bool;
    fn signal_owned_group_once(&mut self) -> GroupSignalV1;
    fn try_reap_exact_child(&mut self) -> ReapAttempt<Self::Status>;
    fn observe_group_with_signal_zero(&mut self) -> GroupObservation;
    fn expired(&self) -> bool;
    fn pause(&mut self);
}
fn finish_owned_process<O: CleanupOps>(operations: &mut O) -> ProcessCleanupV1<O::Status> {
    let mut outcome = ProcessCleanupV1 {
        group_signal: GroupSignalV1::Unverified,
        group_absence: GroupAbsenceV1::Unverified,
        direct_child: DirectChildV1::Unverified,
        status: None,
    };
    if !operations.owns_unreaped_child() {
        return outcome;
    }
    // A live WNOWAIT result alone is insufficient: SIG_IGN/SA_NOCLDWAIT could
    // auto-reap on exit before the signal. Re-check read-only disposition now.
    if !operations.wait_policy_preserves_anchor() {
        return outcome;
    }
    // This is the ONLY nonzero signal. WNOWAIT + preserving default disposition
    // anchor the leader under the explicit exclusive-wait/no-policy-writer contract.
    outcome.group_signal = operations.signal_owned_group_once();
    while !operations.expired() {
        match operations.try_reap_exact_child() {
            ReapAttempt::Reaped(status) => {
                outcome.direct_child = DirectChildV1::Reaped;
                outcome.status = Some(status);
                break;
            }
            ReapAttempt::Unverified => return outcome,
            ReapAttempt::Pending => operations.pause(),
        }
    }
    if outcome.direct_child != DirectChildV1::Reaped {
        return outcome;
    }
    // After leader reap, never send another nonzero signal. A reused group ID
    // can only cause conservative failure here; signal zero mutates no process.
    while !operations.expired() {
        match operations.observe_group_with_signal_zero() {
            GroupObservation::Absent => {
                outcome.group_absence = GroupAbsenceV1::OriginalGroupAbsentObserved;
                break;
            }
            GroupObservation::Unverified => break,
            GroupObservation::Present => operations.pause(),
        }
    }
    outcome
}

struct OwnedChildOps {
    child: Child,
    deadline: Instant,
    anchor_available: bool,
}
impl OwnedChildOps {
    fn owned_group(&self) -> Option<libc::pid_t> {
        libc::pid_t::try_from(self.child.id())
            .ok()
            .filter(|pid| *pid > 1)
    }
}
impl CleanupOps for OwnedChildOps {
    type Status = ExitStatus;
    fn owns_unreaped_child(&mut self) -> bool {
        // Exclusive waiting is a scope precondition. A fresh read-only policy
        // check follows this observation before any nonzero group signal.
        if !self.anchor_available || observe_unreaped_child(&self.child).is_err() {
            self.anchor_available = false;
            return false;
        }
        true
    }
    fn wait_policy_preserves_anchor(&mut self) -> bool {
        let preserving = read_wait_policy() == ChildWaitPolicyV1::DefaultPreservesZombie;
        if !preserving {
            self.anchor_available = false;
        }
        preserving
    }
    fn signal_owned_group_once(&mut self) -> GroupSignalV1 {
        let Some(group) = self.owned_group() else {
            return GroupSignalV1::Unverified;
        };
        let result = unsafe { libc::kill(-group, libc::SIGKILL) };
        if result == 0 {
            GroupSignalV1::SentWhileLeaderOwned
        } else if io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
            GroupSignalV1::AlreadyAbsentWhileLeaderOwned
        } else {
            GroupSignalV1::Unverified
        }
    }
    fn try_reap_exact_child(&mut self) -> ReapAttempt<ExitStatus> {
        match self.child.try_wait() {
            Ok(Some(status)) => ReapAttempt::Reaped(status),
            Ok(None) => ReapAttempt::Pending,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => ReapAttempt::Pending,
            Err(_) => ReapAttempt::Unverified,
        }
    }
    fn observe_group_with_signal_zero(&mut self) -> GroupObservation {
        let Some(group) = self.owned_group() else {
            return GroupObservation::Unverified;
        };
        let result = unsafe { libc::kill(-group, 0) };
        if result == 0 {
            GroupObservation::Present
        } else if io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
            GroupObservation::Absent
        } else {
            GroupObservation::Unverified
        }
    }
    fn expired(&self) -> bool {
        Instant::now() >= self.deadline
    }
    fn pause(&mut self) {
        std::thread::sleep(
            POLL_INTERVAL.min(self.deadline.saturating_duration_since(Instant::now())),
        );
    }
}

#[cfg(test)]
mod pure_tests {
    use super::*;
    use std::collections::VecDeque;
    struct Model {
        owns_child: bool,
        wait_policy: ChildWaitPolicyV1,
        signal: GroupSignalV1,
        reaps: VecDeque<ReapAttempt<u8>>,
        observations: VecDeque<GroupObservation>,
        remaining: usize,
        calls: Vec<&'static str>,
    }
    impl Model {
        fn new(reaps: Vec<ReapAttempt<u8>>, observations: Vec<GroupObservation>) -> Self {
            Self {
                owns_child: true,
                wait_policy: ChildWaitPolicyV1::DefaultPreservesZombie,
                signal: GroupSignalV1::SentWhileLeaderOwned,
                reaps: reaps.into(),
                observations: observations.into(),
                remaining: 4,
                calls: Vec::new(),
            }
        }
    }
    impl CleanupOps for Model {
        type Status = u8;
        fn owns_unreaped_child(&mut self) -> bool {
            self.calls.push("anchor");
            self.owns_child
        }
        fn wait_policy_preserves_anchor(&mut self) -> bool {
            self.calls.push("policy");
            self.wait_policy == ChildWaitPolicyV1::DefaultPreservesZombie
        }
        fn signal_owned_group_once(&mut self) -> GroupSignalV1 {
            self.calls.push("signal");
            self.signal
        }
        fn try_reap_exact_child(&mut self) -> ReapAttempt<u8> {
            self.calls.push("reap");
            self.reaps.pop_front().unwrap_or(ReapAttempt::Pending)
        }
        fn observe_group_with_signal_zero(&mut self) -> GroupObservation {
            self.calls.push("zero");
            self.observations
                .pop_front()
                .unwrap_or(GroupObservation::Present)
        }
        fn expired(&self) -> bool {
            self.remaining == 0
        }
        fn pause(&mut self) {
            self.remaining = self.remaining.saturating_sub(1);
        }
    }
    #[test]
    fn pure_cleanup_orders_one_signal_before_reap_then_only_observation() {
        let mut model = Model::new(
            vec![ReapAttempt::Pending, ReapAttempt::Reaped(7)],
            vec![GroupObservation::Present, GroupObservation::Absent],
        );
        let result = finish_owned_process(&mut model);
        assert!(result.verified());
        assert_eq!(result.status, Some(7));
        assert_eq!(
            model.calls,
            ["anchor", "policy", "signal", "reap", "reap", "zero", "zero"]
        );
    }
    #[test]
    fn pure_cleanup_never_observes_or_resignals_after_failed_or_expired_reap() {
        for reaps in [vec![ReapAttempt::Unverified], vec![]] {
            let mut model = Model::new(reaps, vec![GroupObservation::Absent]);
            let result = finish_owned_process(&mut model);
            assert!(!result.verified());
            assert_eq!(result.direct_child, DirectChildV1::Unverified);
            assert_eq!(model.calls.iter().filter(|v| **v == "signal").count(), 1);
            assert!(!model.calls.contains(&"zero"));
        }
    }
    #[test]
    fn pure_cleanup_uncertain_or_reused_group_is_not_success() {
        for observations in [vec![GroupObservation::Unverified], vec![]] {
            let mut model = Model::new(vec![ReapAttempt::Reaped(0)], observations);
            let result = finish_owned_process(&mut model);
            assert!(!result.verified());
            assert_eq!(result.direct_child, DirectChildV1::Reaped);
            assert_eq!(result.group_absence, GroupAbsenceV1::Unverified);
            assert_eq!(model.calls.iter().filter(|v| **v == "signal").count(), 1);
        }
    }
    #[test]
    fn pure_cleanup_does_not_hide_an_unverified_signal() {
        let mut model = Model::new(vec![ReapAttempt::Reaped(0)], vec![GroupObservation::Absent]);
        model.signal = GroupSignalV1::Unverified;
        assert!(!finish_owned_process(&mut model).verified());
        assert_eq!(model.calls, ["anchor", "policy", "signal", "reap", "zero"]);
    }
    #[test]
    fn pure_cleanup_lost_child_ownership_never_signals_numeric_group() {
        let mut model = Model::new(vec![ReapAttempt::Reaped(0)], vec![GroupObservation::Absent]);
        model.owns_child = false;
        let result = finish_owned_process(&mut model);
        assert!(!result.verified());
        assert_eq!(result.direct_child, DirectChildV1::Unverified);
        assert_eq!(model.calls, ["anchor"]);
    }
    #[test]
    fn pure_wait_policy_requires_default_without_automatic_reaping() {
        assert_eq!(
            classify_wait_policy(libc::SIG_DFL, 0),
            ChildWaitPolicyV1::DefaultPreservesZombie
        );
        assert_eq!(
            classify_wait_policy(libc::SIG_IGN, 0),
            ChildWaitPolicyV1::Unsupported
        );
        assert_eq!(
            classify_wait_policy(libc::SIG_DFL, libc::SA_NOCLDWAIT),
            ChildWaitPolicyV1::Unsupported
        );
        // Inert non-default/non-ignore handler value; never installed or called.
        let custom = libc::SIG_IGN.wrapping_add(1);
        assert_ne!(custom, libc::SIG_DFL);
        assert_eq!(
            classify_wait_policy(custom, 0),
            ChildWaitPolicyV1::Unsupported
        );
    }
    #[test]
    fn pure_unsupported_or_unknown_wait_policy_never_calls_spawn() {
        for policy in [
            ChildWaitPolicyV1::Unsupported,
            ChildWaitPolicyV1::Unverified,
        ] {
            let mut called = false;
            let result = under_verified_wait_policy(policy, || {
                called = true;
                Ok(())
            });
            assert!(result.is_err());
            assert!(!called);
            // The parent maps this error to keep(), never implicit root Drop.
        }
    }
    #[test]
    fn pure_live_child_with_unsafe_or_unknown_policy_never_signals_and_retains_root() {
        for policy in [
            ChildWaitPolicyV1::Unsupported,
            ChildWaitPolicyV1::Unverified,
        ] {
            let mut model =
                Model::new(vec![ReapAttempt::Reaped(0)], vec![GroupObservation::Absent]);
            model.wait_policy = policy;
            let result = finish_owned_process(&mut model);
            assert!(!result.verified()); // finish() maps false to owned root.keep().
            assert_eq!(result.group_signal, GroupSignalV1::Unverified);
            assert_eq!(result.direct_child, DirectChildV1::Unverified);
            assert_eq!(model.calls, ["anchor", "policy"]);
        }
    }
}
