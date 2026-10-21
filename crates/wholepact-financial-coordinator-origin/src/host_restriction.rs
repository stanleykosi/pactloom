//! One original C/H/S/financial-W monotone restriction cell, not an approval issuer.
//! The mapping is RW in trusted whole-image roles; H/S/W sealed APIs expose only
//! checks, plus separate private S-only entered WalletObserve and journal gates.
//! This is NOT
//! OS isolation from hostile code in those trusted roles.
//! Bootstrap alone creates/prunes it. No pointer, FD, path, reset or importer
//! escapes, and no successful observation may be cached as an effect permit.
use crate::{
    bootstrap::PhaseDeadlinesV1,
    channel::require_time,
    process::{DirectChild, ForkOriginV1, PeerLifetime, Role},
    rejected,
    signer_continue_state::CheckedPeer,
    Result,
};
use std::{
    ptr::NonNull,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
    time::Instant,
};

const CURRENT: u32 = 0;
const REVOKED: u32 = 1;
const SIGNER1_IMPORT_BUSY: u32 = 1 << 1;
const SIGNER2_IMPORT_BUSY: u32 = 1 << 2;
const IMPORT_BUSY: u32 = SIGNER1_IMPORT_BUSY | SIGNER2_IMPORT_BUSY;
const SIGNER1_JOURNAL_BUSY: u32 = 1 << 3;
const SIGNER2_JOURNAL_BUSY: u32 = 1 << 4;
const JOURNAL_BUSY: u32 = SIGNER1_JOURNAL_BUSY | SIGNER2_JOURNAL_BUSY;
const KNOWN_BITS: u32 = REVOKED | IMPORT_BUSY | JOURNAL_BUSY;

fn restriction_current(word: u32) -> bool {
    // Only honest actor busy bits may accompany CURRENT. Unknown state retains
    // the original check-only cell's fail-closed behavior.
    word & (REVOKED | !KNOWN_BITS) == 0
}

// Only the genuine monotone R bit is an ordinary restricted outcome. Unknown
// state is always an error, including when R is also present; callers must not
// turn corruption/authentication/lifetime failures into successful draining.
fn current_or_restricted(word: u32) -> Result<bool> {
    if word & !KNOWN_BITS != 0 {
        return Err(rejected("unknown original restriction state"));
    }
    Ok(word & REVOKED == 0)
}

/// Private atomic exclusion only; neither a public permit nor a purpose grant.
/// The exact nominal caller chooses the operation and original actor before
/// entry. R denies new entries but does not roll back an entered operation.
struct EnteredActorOperation<'a> {
    word: &'a AtomicU32,
    bit: u32,
}
impl<'a> EnteredActorOperation<'a> {
    fn enter(word: &'a AtomicU32, bit: u32, actor_busy: u32) -> Result<Self> {
        let mut old = word.load(Ordering::SeqCst);
        loop {
            if !restriction_current(old) || old & actor_busy != 0 {
                return Err(rejected("actor operation already entered or restricted"));
            }
            match word.compare_exchange_weak(old, old | bit, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => return Ok(Self { word, bit }),
                Err(actual) => old = actual,
            }
        }
    }
}
impl Drop for EnteredActorOperation<'_> {
    fn drop(&mut self) {
        // Preserve R, other actors, other purposes and every unknown bit.
        // Process death may leave a sticky bit; a timeout cannot invent drain.
        self.word.fetch_and(!self.bit, Ordering::SeqCst);
    }
}

fn actor_busy_mask(role: Role) -> Result<u32> {
    match role {
        Role::Signer1 => Ok(SIGNER1_IMPORT_BUSY | SIGNER1_JOURNAL_BUSY),
        Role::Signer2 => Ok(SIGNER2_IMPORT_BUSY | SIGNER2_JOURNAL_BUSY),
        _ => Err(rejected("entered operation requires original Signer actor")),
    }
}

struct EnteredWalletImport<'a> {
    _entered: EnteredActorOperation<'a>,
}
impl<'a> EnteredWalletImport<'a> {
    fn enter(word: &'a AtomicU32, role: Role) -> Result<Self> {
        let bit = match role {
            Role::Signer1 => SIGNER1_IMPORT_BUSY,
            Role::Signer2 => SIGNER2_IMPORT_BUSY,
            _ => return Err(rejected("wallet import requires original Signer actor")),
        };
        Ok(Self {
            _entered: EnteredActorOperation::enter(word, bit, actor_busy_mask(role)?)?,
        })
    }
}

struct EnteredJournalPublication<'a> {
    _entered: EnteredActorOperation<'a>,
}
impl<'a> EnteredJournalPublication<'a> {
    fn enter(word: &'a AtomicU32, role: Role) -> Result<Self> {
        let bit = match role {
            Role::Signer1 => SIGNER1_JOURNAL_BUSY,
            Role::Signer2 => SIGNER2_JOURNAL_BUSY,
            _ => {
                return Err(rejected(
                    "journal publication requires original Signer actor",
                ))
            }
        };
        Ok(Self {
            _entered: EnteredActorOperation::enter(word, bit, actor_busy_mask(role)?)?,
        })
    }
}

/// Each process owns its inherited virtual mapping, not another process's
/// mapping or child reaper. Anonymous MAP_SHARED keeps the atomic cell common.
struct SharedCell {
    word: NonNull<AtomicU32>,
}
// SAFETY: after the single prefork initialization, every access to the aligned
// live cell is atomic. An owner is never unmapped while borrowed, and Send/Sync
// do not expose its pointer or a non-atomic reference. Each fork unmaps only its
// own address space. No process shares a Rust allocator/refcount allocation.
unsafe impl Send for SharedCell {}
unsafe impl Sync for SharedCell {}
impl SharedCell {
    fn create() -> Result<Self> {
        let length = std::mem::size_of::<AtomicU32>();
        let raw = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                length,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if raw == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }
        let Some(word) = NonNull::new(raw.cast::<AtomicU32>()) else {
            unsafe {
                libc::munmap(raw, length);
            }
            return Err(rejected("shared Host restriction address unavailable"));
        };
        if word
            .as_ptr()
            .align_offset(std::mem::align_of::<AtomicU32>())
            != 0
        {
            unsafe {
                libc::munmap(raw, length);
            }
            return Err(rejected("shared Host restriction alignment unavailable"));
        }
        // SAFETY: fresh writable, sufficiently sized/aligned mapping, before
        // any fork or other reference exists. Initialization is exactly once.
        unsafe {
            word.as_ptr().write(AtomicU32::new(CURRENT));
        }
        Ok(Self { word })
    }
    fn sample(&self) -> u32 {
        // SAFETY: self owns this live RW mapping for the full shared borrow.
        unsafe { self.word.as_ref() }.load(Ordering::SeqCst)
    }
    fn revoke(&self) {
        // R is irreversible. Preserve every entered import/publication bit.
        unsafe { self.word.as_ref() }.fetch_or(REVOKED, Ordering::SeqCst);
    }
}
impl Drop for SharedCell {
    fn drop(&mut self) {
        // No owned FD, external named object or other actor's mapping is closed.
        unsafe {
            libc::munmap(self.word.as_ptr().cast(), std::mem::size_of::<AtomicU32>());
        }
    }
}

/// Created before the fixed forks. Every C failure/drop from this instant
/// publishes R, including failures before a writer enters the full C Core.
/// Inherited H/S/W copies only unmap on drop; they never gain a write API.
pub(super) struct CreatedHostRestrictionV1 {
    cell: Option<SharedCell>,
    creator_pid: libc::pid_t,
    creator_uid: libc::uid_t,
    clocks: PhaseDeadlinesV1,
}
impl CreatedHostRestrictionV1 {
    pub(super) fn create(clocks: PhaseDeadlinesV1) -> Result<Self> {
        crate::process::require_single_thread()?;
        require_time(clocks.workflow().startup())?;
        Ok(Self {
            cell: Some(SharedCell::create()?),
            creator_pid: unsafe { libc::getpid() },
            creator_uid: unsafe { libc::geteuid() },
            clocks,
        })
    }
    pub(super) fn into_coordinator(
        mut self,
        host: &DirectChild,
    ) -> Result<CoordinatorHostRestrictionV1> {
        if unsafe { libc::getpid() } != self.creator_pid
            || unsafe { libc::geteuid() } != self.creator_uid
            || host.role() != Role::Host
        {
            return Err(rejected("shared restriction requires original C/H birth"));
        }
        require_time(self.clocks.workflow().startup())?;
        host.check_alive()?;
        Ok(CoordinatorHostRestrictionV1 {
            cell: self
                .cell
                .take()
                .ok_or_else(|| rejected("shared restriction consumed"))?,
        })
    }
    /// Only the real H->S child branch may retain this inherited mapping. No
    /// extra FD is created: the full Core separately owns original C/H checks.
    pub(super) fn into_signer(
        mut self,
        origin: &ForkOriginV1,
        coordinator: &PeerLifetime,
    ) -> Result<SignerSharedRestrictionV1> {
        if !matches!(origin.role(), Role::Signer1 | Role::Signer2)
            || coordinator.role() != Role::Coordinator
            || coordinator.pid() != self.creator_pid
            || coordinator.uid() != self.creator_uid
            || unsafe { libc::geteuid() } != self.creator_uid
            || unsafe { libc::getpid() } == self.creator_pid
        {
            return Err(rejected(
                "shared restriction requires original Signer birth",
            ));
        }
        require_time(self.clocks.workflow().startup())?;
        origin.check_parent_alive()?;
        coordinator.check_alive()?;
        let observer = SignerSharedRestrictionV1 {
            cell: self
                .cell
                .take()
                .ok_or_else(|| rejected("shared restriction consumed"))?,
            owner_pid: unsafe { libc::getpid() },
            owner_uid: self.creator_uid,
            role: origin.role(),
            deadline: self.clocks.session,
        };
        observer.check_current()?;
        Ok(observer)
    }
    /// Exactly the seven fixed original History/Continuation/Signing/Pair W
    /// branches retain this same prefork cell. Other W copies only unmap.
    pub(super) fn into_financial_witness(
        mut self,
        origin: &ForkOriginV1,
    ) -> Result<WitnessSharedRestrictionV1> {
        if crate::bootstrap::financial_witness_kind(origin.role()).is_err()
            || !origin.has_original_coordinator(self.creator_pid, self.creator_uid)
            || unsafe { libc::geteuid() } != self.creator_uid
        {
            return Err(rejected(
                "shared restriction requires original financial Witness birth",
            ));
        }
        require_time(self.clocks.workflow().startup())?;
        origin.check_parent_alive()?;
        let result = WitnessSharedRestrictionV1 {
            cell: self
                .cell
                .take()
                .ok_or_else(|| rejected("shared restriction consumed"))?,
            owner_pid: unsafe { libc::getpid() },
            owner_uid: self.creator_uid,
            deadline: self.clocks.session,
        };
        result.check_current()?;
        Ok(result)
    }
    pub(super) fn into_host(
        mut self,
        origin: &ForkOriginV1,
    ) -> Result<(
        HostOriginalRestrictionV1,
        crate::host_interstage::HostLifecycleOwner,
    )> {
        let coordinator = origin.retain_host_coordinator_lifetime()?;
        let owner_pid = unsafe { libc::getpid() };
        if coordinator.pid() != self.creator_pid
            || coordinator.uid() != self.creator_uid
            || unsafe { libc::geteuid() } != self.creator_uid
            || owner_pid == self.creator_pid
        {
            return Err(rejected(
                "shared restriction not inherited by original Host",
            ));
        }
        require_time(self.clocks.workflow().startup())?;
        let peer = origin.continue_observer()?;
        let checks = Arc::new(HostRestrictionChecks {
            cell: self
                .cell
                .take()
                .ok_or_else(|| rejected("shared restriction consumed"))?,
            peer,
            owner_pid,
            owner_uid: self.creator_uid,
            deadline: self.clocks.session,
        });
        checks.check_current()?;
        let (owner, lifecycle) = crate::host_interstage::HostLifecycle::create(
            Arc::clone(&checks),
            self.clocks.workflow(),
        );
        Ok((HostOriginalRestrictionV1 { checks, lifecycle }, owner))
    }
}
impl Drop for CreatedHostRestrictionV1 {
    fn drop(&mut self) {
        if unsafe { libc::getpid() } == self.creator_pid {
            if let Some(cell) = &self.cell {
                cell.revoke();
            }
        }
    }
}

/// Only the genuine C branch obtains this private writer. Phases::revoke must
/// call this BEFORE publishing its local R; Drop covers construction/errors.
pub(super) struct CoordinatorHostRestrictionV1 {
    cell: SharedCell,
}
impl CoordinatorHostRestrictionV1 {
    pub(super) fn revoke(&self) {
        self.cell.revoke();
    }
    /// Conservative import evidence after restriction, not worker quiescence,
    /// clean source disposal, rollback, or permission for a later operation.
    /// An entered journal publication also delays this positive observation.
    pub(super) fn wallet_imports_drained_after_revoke(&self) -> bool {
        self.cell.sample() == REVOKED
    }
}
impl Drop for CoordinatorHostRestrictionV1 {
    fn drop(&mut self) {
        self.revoke();
    }
}

/// Sealed check-only custody from the actual original Host/C edge. It cannot
/// approve a TTY challenge, read a source, construct a permit, or renew a clock.
pub struct HostOriginalRestrictionV1 {
    checks: Arc<HostRestrictionChecks>,
    lifecycle: Arc<crate::host_interstage::HostLifecycle>,
}
pub(super) struct HostRestrictionChecks {
    cell: SharedCell,
    peer: CheckedPeer,
    owner_pid: libc::pid_t,
    owner_uid: libc::uid_t,
    deadline: Instant,
}
impl HostRestrictionChecks {
    pub(super) fn check_current(&self) -> Result<()> {
        if !self.check_current_or_restricted()? {
            return Err(rejected("original C restricted Host"));
        }
        Ok(())
    }

    /// A denial-only observer for the already-owned original H result path.
    /// False means exactly C's monotone R after authenticating actor/lifetimes;
    /// no other error may be suppressed as ordinary restriction. This grants
    /// no foreground ownership, metadata publication or subsequent action.
    pub(super) fn check_current_or_restricted(&self) -> Result<bool> {
        if unsafe { libc::getpid() } != self.owner_pid
            || unsafe { libc::geteuid() } != self.owner_uid
        {
            return Err(rejected("shared Host restriction outside original actor"));
        }
        self.peer.check()?;
        require_time(self.deadline)?;
        current_or_restricted(self.cell.sample())
    }
}

impl HostOriginalRestrictionV1 {
    /// Compare-only same actual lifecycle check, also valid while parked. No
    /// foreground release or service construction follows from this observer.
    pub fn check_completed_pair_service(
        &self,
        service: &crate::HostCompletedPairServiceV1,
    ) -> Result<()> {
        service.matches_lifecycle(&self.lifecycle)?;
        self.checks.check_current()
    }
    pub fn deadline(&self) -> Instant {
        self.checks.deadline
    }
    /// Zero-wait restriction sample. Same-H park/poison is checked before the
    /// final shared C-R SeqCst load; neither observation creates consent.
    pub fn check_current(&self) -> Result<()> {
        self.lifecycle.check_foreground()?;
        self.checks.check_current()
    }
}

/// Private inherited mapping. Core calls only AFTER its actual C/H checks.
/// No C-revocation writer, clone, mapping importer or reaper is available to S.
pub(super) struct SignerSharedRestrictionV1 {
    cell: SharedCell,
    owner_pid: libc::pid_t,
    owner_uid: libc::uid_t,
    role: Role,
    deadline: Instant,
}
impl SignerSharedRestrictionV1 {
    pub(super) fn check_current(&self) -> Result<()> {
        if unsafe { libc::getpid() } != self.owner_pid
            || unsafe { libc::geteuid() } != self.owner_uid
            || !matches!(self.role, Role::Signer1 | Role::Signer2)
        {
            return Err(rejected("shared restriction used outside original Signer"));
        }
        require_time(self.deadline)?;
        if !restriction_current(self.cell.sample()) {
            return Err(rejected("original Coordinator restricted Signer operation"));
        }
        Ok(())
    }
    /// Only genuine per-purpose V3 Finals may call this private primitive,
    /// after validating their same-Core/source/request binding and acquiring
    /// every application and database lock. It grants no purpose by itself.
    ///
    /// CAS admits one already-entered synchronous journal transaction. Execute
    /// that transaction/commit directly: no await, queue, detached worker,
    /// network operation or later application-lock acquisition. R remains
    /// immediate denial of new work; this admitted transaction may settle.
    /// The caller must preserve its actual commit/rollback/uncertain outcome
    /// after R or report loss and must not retry it. Clearing the bit means
    /// only that the synchronous closure/rollback/unwind has ceased, not that
    /// its effect succeeded or was rolled back. The guard never escapes.
    pub(super) fn execute_journal_publication(
        &self,
        publication: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        self.check_current()?;
        // SAFETY: this borrow retains the inherited mapping for the closure
        // and guard; the cell is accessed only atomically.
        let entered =
            EnteredJournalPublication::enter(unsafe { self.cell.word.as_ref() }, self.role)?;
        let result = publication();
        drop(entered);
        // Do not turn a committed result into a pre-effect refusal on late R.
        result
    }

    /// Integration hook ONLY for the future genuine one-use WalletObserveFinal.
    /// Its owner must consume that exact action, validate same-Core purpose,
    /// source, presentation, original C/H lifetimes and immutable deadlines,
    /// and hold required application/source locks BEFORE invoking this hook.
    /// No ordinary DTO, bool, cached check or other purpose may call it.
    ///
    /// Successful CAS is the start of this single synchronous import. Invoke
    /// the actual import directly: no enqueue, await, later application-lock
    /// wait, detached worker or subsequent synchronization inside the closure.
    /// An entered import may settle after R; no later effect inherits this
    /// exception. Return/unwind must mean import/rollback execution has ceased.
    /// A deadline is an admission ceiling, not proof a blocked syscall stopped.
    /// This unconnected hook creates no WalletObserve action or public permit.
    pub(super) fn execute_wallet_observe_import<T>(
        &self,
        import: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        self.check_current()?;
        // SAFETY: self keeps its inherited mapping alive until import and guard
        // have finished. Only atomic accesses touch the shared cell.
        let entered = EnteredWalletImport::enter(unsafe { self.cell.word.as_ref() }, self.role)?;
        let result = import();
        drop(entered);
        result
    }
}

/// Private actual C->fixed-W inherited check-only map. Trusted W still has a RW
/// virtual mapping; the API is not hostile-W OS isolation.
pub(super) struct WitnessSharedRestrictionV1 {
    cell: SharedCell,
    owner_pid: libc::pid_t,
    owner_uid: libc::uid_t,
    deadline: Instant,
}
impl WitnessSharedRestrictionV1 {
    pub(super) fn check_current(&self) -> Result<()> {
        if unsafe { libc::getpid() } != self.owner_pid
            || unsafe { libc::geteuid() } != self.owner_uid
        {
            return Err(rejected("financial Witness restriction actor mismatch"));
        }
        require_time(self.deadline)?;
        if !restriction_current(self.cell.sample()) {
            return Err(rejected("original C restricted financial Witness"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod wallet_import_gate_tests {
    use super::*;

    // Pure atomics only: no mmap, fork, native UI, source or wallet execution.
    #[test]
    fn revoke_before_import_denies_both_actors() {
        let word = AtomicU32::new(REVOKED);
        assert!(EnteredWalletImport::enter(&word, Role::Signer1).is_err());
        assert!(EnteredWalletImport::enter(&word, Role::Signer2).is_err());
        assert_eq!(word.load(Ordering::SeqCst), REVOKED);
    }

    #[test]
    fn entered_import_settles_without_clearing_revoke() {
        let word = AtomicU32::new(CURRENT);
        let entered = EnteredWalletImport::enter(&word, Role::Signer1).unwrap();
        word.fetch_or(REVOKED, Ordering::SeqCst);
        assert_eq!(word.load(Ordering::SeqCst), REVOKED | SIGNER1_IMPORT_BUSY);
        assert!(EnteredWalletImport::enter(&word, Role::Signer2).is_err());
        drop(entered);
        assert_eq!(word.load(Ordering::SeqCst), REVOKED);
        assert!(EnteredWalletImport::enter(&word, Role::Signer1).is_err());
    }

    #[test]
    fn both_actors_drain_independently_and_duplicate_entry_fails() {
        let word = AtomicU32::new(CURRENT);
        let first = EnteredWalletImport::enter(&word, Role::Signer1).unwrap();
        assert!(EnteredWalletImport::enter(&word, Role::Signer1).is_err());
        let second = EnteredWalletImport::enter(&word, Role::Signer2).unwrap();
        assert_eq!(word.load(Ordering::SeqCst), IMPORT_BUSY);
        // Busy is not R: unrelated restriction-only checks remain current.
        assert_eq!(word.load(Ordering::SeqCst) & REVOKED, 0);
        word.fetch_or(REVOKED, Ordering::SeqCst);
        drop(first);
        assert_eq!(word.load(Ordering::SeqCst), REVOKED | SIGNER2_IMPORT_BUSY);
        drop(second);
        assert_eq!(word.load(Ordering::SeqCst), REVOKED);
    }

    #[test]
    fn non_signer_cannot_enter_import() {
        let word = AtomicU32::new(CURRENT);
        assert!(EnteredWalletImport::enter(&word, Role::Coordinator).is_err());
        assert!(EnteredWalletImport::enter(&word, Role::Host).is_err());
        assert_eq!(word.load(Ordering::SeqCst), CURRENT);
    }

    #[test]
    fn unknown_bits_deny_currentness_admission_and_drain() {
        for bit_index in 5..32 {
            let unknown = 1u32 << bit_index;
            for known in 0..=KNOWN_BITS {
                let value = unknown | known;
                let word = AtomicU32::new(value);
                assert!(!restriction_current(value));
                assert!(EnteredWalletImport::enter(&word, Role::Signer1).is_err());
                assert!(EnteredWalletImport::enter(&word, Role::Signer2).is_err());
                // Exact same predicate as C's import-only drain observation.
                assert_ne!(word.load(Ordering::SeqCst), REVOKED);
                assert_eq!(word.load(Ordering::SeqCst), value);
            }
        }
    }

    #[test]
    fn known_busy_bits_are_current_but_never_drained() {
        for value in [
            CURRENT,
            SIGNER1_IMPORT_BUSY,
            SIGNER2_IMPORT_BUSY,
            IMPORT_BUSY,
        ] {
            assert!(restriction_current(value));
            assert!(!restriction_current(value | REVOKED));
            assert_eq!((value | REVOKED) == REVOKED, value == CURRENT);
        }
    }

    #[test]
    fn synchronous_unwind_releases_only_its_import_bit() {
        let word = AtomicU32::new(CURRENT);
        let other = EnteredWalletImport::enter(&word, Role::Signer2).unwrap();
        let outcome = std::panic::catch_unwind(|| {
            let _entered = EnteredWalletImport::enter(&word, Role::Signer1).unwrap();
            word.fetch_or(REVOKED, Ordering::SeqCst);
            panic!("pure import unwind");
        });
        assert!(outcome.is_err());
        assert_eq!(word.load(Ordering::SeqCst), REVOKED | SIGNER2_IMPORT_BUSY);
        drop(other);
        assert_eq!(word.load(Ordering::SeqCst), REVOKED);
    }
}

#[cfg(test)]
mod journal_publication_gate_tests {
    use super::*;

    #[test]
    fn revoke_before_publication_denies_both_original_actors() {
        let word = AtomicU32::new(REVOKED);
        assert!(EnteredJournalPublication::enter(&word, Role::Signer1).is_err());
        assert!(EnteredJournalPublication::enter(&word, Role::Signer2).is_err());
        assert_eq!(word.load(Ordering::SeqCst), REVOKED);
    }

    #[test]
    fn same_actor_cannot_overlap_wallet_and_journal_in_either_order() {
        for role in [Role::Signer1, Role::Signer2] {
            let word = AtomicU32::new(CURRENT);
            let journal = EnteredJournalPublication::enter(&word, role).unwrap();
            assert!(EnteredJournalPublication::enter(&word, role).is_err());
            assert!(EnteredWalletImport::enter(&word, role).is_err());
            drop(journal);
            assert_eq!(word.load(Ordering::SeqCst), CURRENT);
            let wallet = EnteredWalletImport::enter(&word, role).unwrap();
            assert!(EnteredJournalPublication::enter(&word, role).is_err());
            drop(wallet);
            assert_eq!(word.load(Ordering::SeqCst), CURRENT);
        }
    }

    #[test]
    fn simultaneous_same_actor_wallet_and_journal_have_one_winner() {
        use std::sync::Barrier;
        let word = AtomicU32::new(CURRENT);
        let winners = AtomicU32::new(0);
        let attempted = Barrier::new(3);
        let finish = Barrier::new(3);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let entered = EnteredWalletImport::enter(&word, Role::Signer1);
                if entered.is_ok() {
                    winners.fetch_add(1, Ordering::SeqCst);
                }
                attempted.wait();
                finish.wait();
                drop(entered);
            });
            scope.spawn(|| {
                let entered = EnteredJournalPublication::enter(&word, Role::Signer1);
                if entered.is_ok() {
                    winners.fetch_add(1, Ordering::SeqCst);
                }
                attempted.wait();
                finish.wait();
                drop(entered);
            });
            attempted.wait();
            // Both attempts have finished and the winner remains entered.
            // R does not wait for or overwrite its independently held bit.
            word.fetch_or(REVOKED, Ordering::SeqCst);
            finish.wait();
        });
        assert_eq!(winners.load(Ordering::SeqCst), 1);
        assert_eq!(word.load(Ordering::SeqCst), REVOKED);
    }

    #[test]
    fn independent_actors_publish_and_release_only_their_own_bits() {
        let word = AtomicU32::new(CURRENT);
        let first = EnteredJournalPublication::enter(&word, Role::Signer1).unwrap();
        let second = EnteredJournalPublication::enter(&word, Role::Signer2).unwrap();
        assert_eq!(word.load(Ordering::SeqCst), JOURNAL_BUSY);
        assert!(restriction_current(word.load(Ordering::SeqCst)));
        word.fetch_or(REVOKED, Ordering::SeqCst);
        assert!(EnteredJournalPublication::enter(&word, Role::Signer1).is_err());
        drop(first);
        assert_eq!(word.load(Ordering::SeqCst), REVOKED | SIGNER2_JOURNAL_BUSY);
        drop(second);
        assert_eq!(word.load(Ordering::SeqCst), REVOKED);
    }

    #[test]
    fn independent_actor_wallet_does_not_share_journal_release() {
        let word = AtomicU32::new(CURRENT);
        let wallet = EnteredWalletImport::enter(&word, Role::Signer1).unwrap();
        let journal = EnteredJournalPublication::enter(&word, Role::Signer2).unwrap();
        word.fetch_or(REVOKED, Ordering::SeqCst);
        drop(journal);
        assert_eq!(word.load(Ordering::SeqCst), REVOKED | SIGNER1_IMPORT_BUSY);
        drop(wallet);
        assert_eq!(word.load(Ordering::SeqCst), REVOKED);
    }

    #[test]
    fn publication_unwind_preserves_revoke_other_actor_and_unknown_bits() {
        let word = AtomicU32::new(CURRENT);
        let other = EnteredJournalPublication::enter(&word, Role::Signer2).unwrap();
        let unknown = 1 << 31;
        let result = std::panic::catch_unwind(|| {
            let _entered = EnteredJournalPublication::enter(&word, Role::Signer1).unwrap();
            word.fetch_or(REVOKED | unknown, Ordering::SeqCst);
            panic!("pure publication unwind");
        });
        assert!(result.is_err());
        assert_eq!(
            word.load(Ordering::SeqCst),
            REVOKED | unknown | SIGNER2_JOURNAL_BUSY
        );
        drop(other);
        assert_eq!(word.load(Ordering::SeqCst), REVOKED | unknown);
    }

    #[test]
    fn unknown_bits_deny_every_publication_without_mutation() {
        for index in 5..32 {
            for known in 0..=KNOWN_BITS {
                let value = (1u32 << index) | known;
                let word = AtomicU32::new(value);
                assert!(!restriction_current(value));
                assert!(EnteredJournalPublication::enter(&word, Role::Signer1).is_err());
                assert!(EnteredJournalPublication::enter(&word, Role::Signer2).is_err());
                assert_ne!(value, REVOKED);
                assert_eq!(word.load(Ordering::SeqCst), value);
            }
        }
    }

    #[test]
    fn non_signer_cannot_publish_and_known_publication_is_not_drain() {
        let word = AtomicU32::new(CURRENT);
        assert!(EnteredJournalPublication::enter(&word, Role::Coordinator).is_err());
        assert!(EnteredJournalPublication::enter(&word, Role::Host).is_err());
        assert_eq!(word.load(Ordering::SeqCst), CURRENT);
        for value in [SIGNER1_JOURNAL_BUSY, SIGNER2_JOURNAL_BUSY, JOURNAL_BUSY] {
            assert!(restriction_current(value));
            assert!(!restriction_current(value | REVOKED));
            assert_ne!(value | REVOKED, REVOKED);
        }
    }
}

#[cfg(test)]
mod restriction_observation_tests {
    use super::*;

    #[test]
    fn only_known_monotone_r_is_an_ordinary_restricted_observation() {
        for known in 0..=KNOWN_BITS {
            assert_eq!(current_or_restricted(known).unwrap(), known & REVOKED == 0);
            assert_eq!(
                current_or_restricted(known).unwrap(),
                restriction_current(known)
            );
        }
    }

    #[test]
    fn unknown_state_is_never_suppressed_even_when_also_revoked() {
        for index in 5..32 {
            for known in 0..=KNOWN_BITS {
                let word = (1u32 << index) | known;
                assert!(current_or_restricted(word).is_err());
                assert!(current_or_restricted(word | REVOKED).is_err());
            }
        }
    }
}
