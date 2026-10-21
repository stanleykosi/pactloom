//! Fixed actual process tree and inert global barrier. The bootstrap-only profile
//! opens no role namespace, source, key, GUI or service. The separate cancel-only
//! profile may hand the retained tree to C and one genuine W preparation after
//! the barrier; this never enables financial approval or a serving role.
use crate::{
    channel::{require_time, Message},
    image::PinnedCommonImageV1,
    process::{self, DirectChild, ForkOriginV1, Forked, Role, WITNESS_ROLES},
    rejected, Result,
};
use std::{os::fd::{AsRawFd, FromRawFd, OwnedFd}, sync::atomic::{AtomicBool, Ordering}, time::{Duration, Instant}};

const ROOT_CHILDREN: usize = 14; // H plus the 13 fixed Witness purposes.
const ALL_ROOT_CHILDREN: u16 = (1 << ROOT_CHILDREN) - 1;
const BOOTSTRAP_BUDGET: Duration = Duration::from_secs(30);

#[derive(Clone, Copy)]
pub(super) struct PhaseDeadlinesV1 { startup: Instant, pub(super) session: Instant }
impl PhaseDeadlinesV1 {
    fn stop(self) -> Instant {
        if cfg!(any(feature = "cancel-only-witness-review", feature = "coordinated-witness-delivery-append")) { self.session + Duration::from_secs(5) } else { self.startup }
    }
    fn drain(self) -> Instant {
        // Called once after this role's one STOP. This is a subordinate local
        // bound, never a renewal of C's separately retained root cleanup budget.
        if cfg!(any(feature = "cancel-only-witness-review", feature = "coordinated-witness-delivery-append")) { (Instant::now() + Duration::from_secs(5)).min(self.stop()) } else { self.startup }
    }
}

/// Closed actual branch custody from the one real fixed startup. No variant's
/// payload can be constructed, cloned or reconstructed by a caller.
pub enum BootstrappedRoleV1 {
    Coordinator(CoordinatorOriginV1),
    #[cfg(feature = "coordinated-witness-delivery-append")]
    WitnessDelivery(crate::delivery_origin::WitnessDeliveryOriginV1),
    Host(HostOriginV1),
    Signer(SignerOriginV1),
    InertWitness(InertWitnessOriginV1),
    #[cfg(feature = "cancel-only-witness-review")]
    CancelOnlyWitness(CancelOnlyWitnessOriginV1),
}

pub struct CoordinatorOriginV1 {
    tree: InertTreeV1,
    clocks: PhaseDeadlinesV1,
    #[cfg(any(feature = "cancel-only-witness-review", feature = "coordinated-witness-delivery-append"))]
    display: crate::desktop_launch::DesktopLaunchV1,
}
impl CoordinatorOriginV1 {
    #[cfg(feature = "coordinated-witness-delivery-append")]
    pub fn into_delivery_review(self) -> Result<(crate::delivery_origin::CoordinatorDeliveryNativeV1, crate::delivery_origin::CoordinatorDeliveryEndpointV1)> {
        require_time(self.clocks.session)?;
        self.tree.check_alive()?;
        self.display.restore_in_coordinator()?;
        crate::delivery_origin::split_coordinator(self.tree, self.clocks.session)
    }

    #[cfg(not(any(feature = "cancel-only-witness-review", feature = "coordinated-witness-delivery-append")))]
    pub fn finish_inert(self) -> Result<()> { self.tree.stop_and_reap(self.clocks.startup) }

    /// Consume C's opaque original coordinate record before the caller starts
    /// its sole driver or GUI. No coordinate data or imported display FD escapes.
    #[cfg(feature = "cancel-only-witness-review")]
    pub fn into_cancel_review(self) -> Result<CoordinatorCancelOriginV1> {
        require_time(self.clocks.session)?;
        self.tree.check_alive()?;
        self.display.restore_in_coordinator()?;
        Ok(CoordinatorCancelOriginV1 { tree: self.tree, session: self.clocks.session, cleanup_deadline: None })
    }
}

pub struct HostOriginV1 {
    origin: ForkOriginV1,
    signers: [Option<DirectChild>; 2],
    clocks: PhaseDeadlinesV1,
}
impl HostOriginV1 {
    pub fn run_until_stop(self) -> ! { child_exit(finish_host(self)) }
}
pub(super) struct LeafCustody { pub(super) origin: ForkOriginV1, pub(super) clocks: PhaseDeadlinesV1 }
pub struct SignerOriginV1 { leaf: LeafCustody }
impl SignerOriginV1 {
    pub fn run_until_stop(self) -> ! { child_exit(finish_leaf(self.leaf, Ok(()))) }
}
pub struct InertWitnessOriginV1 { leaf: LeafCustody }
impl InertWitnessOriginV1 {
    pub fn run_until_stop(self) -> ! { child_exit(finish_leaf(self.leaf, Ok(()))) }
}

#[cfg(feature = "cancel-only-witness-review")]
pub struct CoordinatorCancelOriginV1 {
    tree: InertTreeV1,
    session: Instant,
    cleanup_deadline: Option<Instant>,
}
#[cfg(feature = "cancel-only-witness-review")]
impl CoordinatorCancelOriginV1 {
    pub fn session_deadline(&self) -> Instant { self.session }
    pub fn check_alive(&self) -> Result<()> { self.tree.check_alive() }
    pub fn send_prepare_once(&self, input: crate::cancel_review::CancelReviewInputsV1) -> Result<()> {
        self.tree.witness()?.review_send(&crate::cancel_review::Packet::PrepareOnce(input))
    }
    pub fn send_cancel(&mut self) -> Result<()> {
        let ceiling = (Instant::now() + Duration::from_secs(5)).min(self.session + Duration::from_secs(5));
        self.cleanup_deadline.get_or_insert(ceiling);
        self.tree.witness()?.review_send(&crate::cancel_review::Packet::Cancel)
    }
    pub fn try_receive_cancel_response(&self) -> Result<Option<crate::cancel_review::CancelReviewResponseV1>> {
        use crate::cancel_review::{Packet, CancelReviewResponseV1 as Response};
        self.tree.witness()?.review_try_receive()?.map(|packet| match packet {
            Packet::PreparedDisplay(data) => Ok(Response::PreparedDisplay(data)),
            Packet::Disposed => Ok(Response::Disposed),
            Packet::PreparationFailed => Ok(Response::PreparationFailed),
            _ => Err(rejected("wrong cancel-only response direction")),
        }).transpose()
    }
    pub fn stop_and_reap(self, deadline: Instant) -> Result<()> {
        // The caller may shorten this disposal/teardown attempt, never extend
        // the retained original session ceiling or start per-child budgets.
        let cleanup = self.cleanup_deadline.unwrap_or_else(|| Instant::now() + Duration::from_secs(5));
        self.tree.stop_and_reap(deadline.min(cleanup).min(self.session + Duration::from_secs(5)))
    }
}

#[cfg(feature = "cancel-only-witness-review")]
pub struct CancelOnlyWitnessOriginV1 { leaf: LeafCustody }
#[cfg(feature = "cancel-only-witness-review")]
impl CancelOnlyWitnessOriginV1 {
    pub fn session_deadline(&self) -> Instant { self.leaf.clocks.session }
    pub fn check_coordinator_alive(&self) -> Result<()> { self.leaf.origin.check_parent_alive() }
    pub fn try_receive_cancel_request(&self) -> Result<Option<crate::cancel_review::CancelReviewRequestV1>> {
        use crate::cancel_review::{Packet, CancelReviewRequestV1 as Request};
        self.leaf.origin.review_try_receive()?.map(|packet| match packet {
            Packet::PrepareOnce(data) => Ok(Request::PrepareOnce(data)),
            Packet::Cancel => Ok(Request::Cancel),
            _ => Err(rejected("wrong cancel-only request direction")),
        }).transpose()
    }
    pub fn send_display(&self, data: crate::cancel_review::CancelReviewPresentationV1) -> Result<()> {
        self.leaf.origin.review_send(&crate::cancel_review::Packet::PreparedDisplay(data))
    }
    pub fn send_preparation_failed(&self) -> Result<()> {
        self.leaf.origin.review_send(&crate::cancel_review::Packet::PreparationFailed)
    }
    pub fn send_disposed(&self) -> Result<()> {
        self.leaf.origin.review_send(&crate::cancel_review::Packet::Disposed)
    }
    /// No fallthrough into a copied parent path, even on source-worker failure.
    /// A success claim here does not prove disposal; the private W worker must
    /// have observed actual join/drop before sending its finite Disposed frame.
    pub fn complete(self, work: Result<()>) -> ! { child_exit(finish_leaf(self.leaf, work)) }
}

/// Sole C-owned original tree. A GUI driver may move this owner after the
/// complete inert barrier; it cannot clone/reconstruct children or their origin.
pub(super) struct InertTreeV1 {
    children: [Option<DirectChild>; ROOT_CHILDREN],
    _image: PinnedCommonImageV1,
}
impl InertTreeV1 {
    #[cfg(feature = "coordinated-witness-delivery-append")]
    pub(super) fn observation_pidfds(&self) -> Result<[OwnedFd; ROOT_CHILDREN]> {
        let mut descriptors = Vec::with_capacity(ROOT_CHILDREN);
        for child in self.children.iter().flatten() { descriptors.push(child.duplicate_lifetime_for_delivery()?); }
        descriptors.try_into().map_err(|_| rejected("fixed observation inventory missing"))
    }

    #[cfg(any(feature = "cancel-only-witness-review", feature = "coordinated-witness-delivery-append"))]
    pub(super) fn check_alive(&self) -> Result<()> {
        for child in self.children.iter().flatten() { child.check_alive()?; }
        Ok(())
    }
    #[cfg(any(feature = "cancel-only-witness-review", feature = "coordinated-witness-delivery-append"))]
    pub(super) fn witness(&self) -> Result<&DirectChild> {
        self.children.iter().flatten().find(|c| c.role() == Role::Owner1V3DeliveryAdmission)
            .ok_or_else(|| rejected("original review witness missing"))
    }
    pub(super) fn stop_and_reap(mut self, deadline: Instant) -> Result<()> {
        for child in self.children.iter().flatten() { child.send(Message::Stop, deadline)?; }
        for child in self.children.iter().flatten() { child.receive(Message::Stopped, deadline)?; }
        for child in self.children.iter().flatten() { child.send(Message::Exit, deadline)?; }
        for child in &mut self.children {
            child.take().ok_or_else(|| rejected("fixed child missing"))?.finish(deadline)?;
        }
        Ok(())
    }
}

/// Perform the one exact-image startup. Only the reviewed binary's private main
/// calls this before any runtime/GUI/thread-capable or source initialization.
/// A different executable fails the whole-image pin; this is not a late worker
/// launcher or proof against historical injection in the trusted initial image.
pub fn bootstrap_common_image_v1() -> Result<BootstrappedRoleV1> {
    static ENTERED: AtomicBool = AtomicBool::new(false);
    // Set before any fork. Every child inherits an already-consumed entry, and
    // failure also permanently consumes this process's only entry attempt.
    claim_entry(&ENTERED)?;
    harden_first()?;
    process::require_single_thread()?;
    if unsafe { libc::getuid() != libc::geteuid() || libc::getgid() != libc::getegid() } {
        return Err(rejected("set-id coordinator launch unsupported"));
    }
    if std::env::args_os().count() != 1 { return Err(rejected("no external worker entry")); }
    #[cfg(any(feature = "cancel-only-witness-review", feature = "coordinated-witness-delivery-append"))]
    let display = crate::desktop_launch::DesktopLaunchV1::capture()?;
    discard_ambient_descriptors()?;
    // Trusted launch is still required: this cannot undo already-run loader
    // injection, imported memory, or a malicious initial native launcher.
    // clearenv drops bindings, NOT the original strings/historical copies.
    // The trusted initial launcher must already provide a credential-free
    // environment/address space with no secret inherited input.
    if unsafe { libc::clearenv() } != 0 { return Err(std::io::Error::last_os_error()); }
    #[cfg(wholepact_bootstrap_ci)]
    crate::ci::initialize()?;
    let image = PinnedCommonImageV1::load_running_image()?;
    process::require_single_thread()?;
    let phase_start = Instant::now();
    let deadline = phase_start + BOOTSTRAP_BUDGET;
    let clocks = PhaseDeadlinesV1 {
        startup: deadline,
        session: if cfg!(any(feature = "cancel-only-witness-review", feature = "coordinated-witness-delivery-append")) { phase_start + Duration::from_secs(300) } else { deadline },
    };
    #[cfg(wholepact_bootstrap_ci)]
    crate::ci::deadline(deadline)?;
    let mut children: [Option<DirectChild>; ROOT_CHILDREN] = std::array::from_fn(|_| None);
    match process::fork_edge(Role::Coordinator, Role::Host)? {
        Forked::Parent(host) => children[0] = Some(host),
        Forked::Child(origin) => {
            drop(children);
            drop(image);
            #[cfg(any(feature = "cancel-only-witness-review", feature = "coordinated-witness-delivery-append"))]
            drop(display);
            return child_branch(prepare_host(origin, clocks));
        }
    }
    for (index, role) in WITNESS_ROLES.into_iter().enumerate() {
        require_time(deadline)?;
        match process::fork_edge(Role::Coordinator, role)? {
            Forked::Parent(witness) => children[index + 1] = Some(witness),
            Forked::Child(origin) => {
                // Includes H and EVERY earlier Witness channel/pidfd. Copied
                // DirectChild drops disarm reapers before closing their FDs.
                drop(children);
                drop(image);
                #[cfg(any(feature = "cancel-only-witness-review", feature = "coordinated-witness-delivery-append"))]
                drop(display);
                return child_branch(prepare_leaf(origin, clocks));
            }
        }
    }
    #[cfg(wholepact_bootstrap_ci)]
    {
        let mut fds = vec![0, 1, 2, image.ci_fd()];
        for child in children.iter().flatten() { fds.extend(child.ci_descriptors()); }
        crate::ci::ready(Role::Coordinator, fds, unsafe { libc::getppid() }, deadline)?;
    }
    let mut barrier = InertBarrier::new();
    for (index, child) in children.iter().enumerate() {
        child.as_ref().ok_or_else(|| rejected("fixed child missing"))?.receive(Message::Prepared, deadline)?;
        barrier.prepared(index)?;
    }
    for child in children.iter().flatten() { child.check_alive()?; }
    barrier.decide_release()?;
    #[cfg(wholepact_bootstrap_ci)]
    crate::ci::release_decision()?;
    // Delivery is NOT atomic. Some inert children may ACK while a different
    // edge fails. Any error drops owned children; no successor authority exists.
    for child in children.iter().flatten() { child.send(Message::Release, deadline)?; }
    for (index, child) in children.iter().enumerate() {
        child.as_ref().ok_or_else(|| rejected("fixed child missing"))?.receive(Message::Released, deadline)?;
        barrier.released(index)?;
    }
    barrier.finish_inert_release()?;
    let tree = InertTreeV1 { children, _image: image };
    Ok(BootstrappedRoleV1::Coordinator(CoordinatorOriginV1 {
        tree, clocks,
        #[cfg(any(feature = "cancel-only-witness-review", feature = "coordinated-witness-delivery-append"))]
        display,
    }))
}

fn prepare_host(origin: ForkOriginV1, clocks: PhaseDeadlinesV1) -> Result<BootstrappedRoleV1> {
    let deadline = clocks.startup;
    #[cfg(wholepact_bootstrap_ci)]
    crate::ci::enter_role(Role::Host);
    if origin.role() != Role::Host { return Err(rejected("wrong host birth")); }
    verify_child_start(&origin)?;
    let mut signers: [Option<DirectChild>; 2] = std::array::from_fn(|_| None);
    for (index, role) in [Role::Signer1, Role::Signer2].into_iter().enumerate() {
        require_time(deadline)?;
        match process::fork_edge(Role::Host, role)? {
            Forked::Parent(signer) => signers[index] = Some(signer),
            Forked::Child(signer_origin) => {
                // S2 must close its copied S1 owner/channel, and both signers
                // close H's C-facing channel. No signer can send directly to C.
                drop(signers);
                drop(origin);
                return child_branch(prepare_leaf(signer_origin, clocks));
            }
        }
    }
    for signer in signers.iter().flatten() { signer.receive(Message::Prepared, deadline)?; }
    for signer in signers.iter().flatten() { signer.check_alive()?; }
    #[cfg(wholepact_bootstrap_ci)]
    {
        let mut fds = vec![0, 1, 2];
        fds.extend(origin.ci_descriptors());
        for signer in signers.iter().flatten() { fds.extend(signer.ci_descriptors()); }
        crate::ci::ready(Role::Host, fds, origin.ci_parent_pid(), deadline)?;
    }
    // This is subtree closure/preparedness, NOT readiness of any live service.
    origin.send(Message::Prepared, deadline)?;
    origin.receive(Message::Release, deadline)?;
    for signer in signers.iter().flatten() { signer.send(Message::Release, deadline)?; }
    for signer in signers.iter().flatten() { signer.receive(Message::Released, deadline)?; }
    origin.send(Message::Released, deadline)?;
    Ok(BootstrappedRoleV1::Host(HostOriginV1 { origin, signers, clocks }))
}

fn finish_host(host: HostOriginV1) -> Result<()> {
    let HostOriginV1 { origin, mut signers, clocks } = host;
    #[cfg(any(feature = "cancel-only-witness-review", feature = "coordinated-witness-delivery-append"))]
    origin.wait_host_stop(&signers, clocks.stop())?;
    #[cfg(not(any(feature = "cancel-only-witness-review", feature = "coordinated-witness-delivery-append")))]
    origin.receive(Message::Stop, clocks.startup)?;
    let deadline = clocks.drain();
    for signer in signers.iter().flatten() { signer.send(Message::Stop, deadline)?; }
    for signer in signers.iter().flatten() { signer.receive(Message::Stopped, deadline)?; }
    origin.send(Message::Stopped, deadline)?;
    origin.receive(Message::Exit, deadline)?;
    for signer in signers.iter().flatten() { signer.send(Message::Exit, deadline)?; }
    for signer in &mut signers {
        signer.take().ok_or_else(|| rejected("fixed signer missing"))?.finish(deadline)?;
    }
    Ok(())
}

fn prepare_leaf(origin: ForkOriginV1, clocks: PhaseDeadlinesV1) -> Result<BootstrappedRoleV1> {
    let deadline = clocks.startup;
    #[cfg(wholepact_bootstrap_ci)]
    crate::ci::enter_role(origin.role());
    if !matches!(origin.role(), Role::Signer1 | Role::Signer2) && !WITNESS_ROLES.contains(&origin.role()) {
        return Err(rejected("wrong leaf birth"));
    }
    verify_child_start(&origin)?;
    #[cfg(wholepact_bootstrap_ci)]
    {
        let mut fds = vec![0, 1, 2];
        fds.extend(origin.ci_descriptors());
        crate::ci::ready(origin.role(), fds, origin.ci_parent_pid(), deadline)?;
    }
    origin.send(Message::Prepared, deadline)?;
    origin.receive(Message::Release, deadline)?;
    origin.send(Message::Released, deadline)?;
    let leaf = LeafCustody { origin, clocks };
    if matches!(leaf.origin.role(), Role::Signer1 | Role::Signer2) {
        return Ok(BootstrappedRoleV1::Signer(SignerOriginV1 { leaf }));
    }
    #[cfg(feature = "cancel-only-witness-review")]
    if leaf.origin.role() == crate::cancel_review::WITNESS {
        return Ok(BootstrappedRoleV1::CancelOnlyWitness(CancelOnlyWitnessOriginV1 { leaf }));
    }
    #[cfg(feature = "coordinated-witness-delivery-append")]
    if leaf.origin.role() == Role::Owner1V3DeliveryAdmission {
        return Ok(BootstrappedRoleV1::WitnessDelivery(crate::delivery_origin::WitnessDeliveryOriginV1::from_leaf(leaf)?));
    }
    Ok(BootstrappedRoleV1::InertWitness(InertWitnessOriginV1 { leaf }))
}

fn child_branch(result: Result<BootstrappedRoleV1>) -> Result<BootstrappedRoleV1> {
    match result { Ok(role) => Ok(role), Err(error) => child_exit(Err(error)) }
}

fn claim_entry(entered: &AtomicBool) -> Result<()> {
    if entered.swap(true, Ordering::AcqRel) { return Err(rejected("common image entry already consumed")); }
    Ok(())
}

pub(super) fn finish_leaf(leaf: LeafCustody, work: Result<()>) -> Result<()> {
    work?;
    leaf.origin.receive(Message::Stop, leaf.clocks.stop())?;
    let deadline = leaf.clocks.drain();
    leaf.origin.send(Message::Stopped, deadline)?;
    leaf.origin.receive(Message::Exit, deadline)
}

fn verify_child_start(origin: &ForkOriginV1) -> Result<()> {
    let mut limit = libc::rlimit { rlim_cur: 1, rlim_max: 1 };
    if unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) } != 0
        || limit.rlim_cur != 0 || limit.rlim_max != 0
        || unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) } != 0
    { return Err(rejected("fork child hardening not retained")); }
    origin.check_parent_alive()
}

pub(super) fn child_exit(result: Result<()>) -> ! {
    // No unwinding/fallthrough into a copied parent spawn loop or main. Role
    // function locals already dropped (including H-owned signer reapers).
    let code = if result.is_ok() { 0 } else { 1 };
    #[cfg(wholepact_bootstrap_ci)]
    crate::ci::finished(code);
    unsafe { libc::_exit(code) }
}

fn harden_first() -> Result<()> {
    // Same fail-closed process hardening as wholepact_signer::harden_process.
    // No security setting is weakened; no installation or machine setting is
    // changed by creating this source. This runs only upon later binary launch.
    let limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } != 0
        || unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0
    { return Err(rejected("common-image process hardening unavailable")); }
    Ok(())
}

fn discard_ambient_descriptors() -> Result<()> {
    // Fail closed if close_range is unavailable. No caller descriptor, source,
    // socket, inherited role selector or arbitrary terminal survives startup.
    if unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let raw = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW) };
    if raw < 0 { return Err(std::io::Error::last_os_error()); }
    // Reserve >=3 even when the caller left a standard descriptor closed.
    let duplicate = unsafe { libc::fcntl(raw, libc::F_DUPFD_CLOEXEC, 3) };
    let open_error = std::io::Error::last_os_error();
    unsafe { libc::close(raw); }
    if duplicate < 0 { return Err(open_error); }
    let null = unsafe { OwnedFd::from_raw_fd(duplicate) };
    for stdio in 0..=2 {
        if unsafe { libc::dup3(null.as_raw_fd(), stdio, libc::O_CLOEXEC) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase { Collecting, Releasing, InertReleased, Aborted }
struct InertBarrier { prepared: u16, released: u16, phase: Phase }
impl InertBarrier {
    fn new() -> Self { Self { prepared: 0, released: 0, phase: Phase::Collecting } }
    fn fail<T>(&mut self) -> Result<T> { self.phase = Phase::Aborted; Err(rejected("inert barrier transition rejected")) }
    fn prepared(&mut self, index: usize) -> Result<()> {
        if self.phase != Phase::Collecting || index >= ROOT_CHILDREN || self.prepared & (1 << index) != 0 {
            return self.fail();
        }
        self.prepared |= 1 << index;
        Ok(())
    }
    fn decide_release(&mut self) -> Result<()> {
        if self.phase != Phase::Collecting || self.prepared != ALL_ROOT_CHILDREN { return self.fail(); }
        self.phase = Phase::Releasing;
        Ok(())
    }
    fn released(&mut self, index: usize) -> Result<()> {
        if self.phase != Phase::Releasing || index >= ROOT_CHILDREN || self.released & (1 << index) != 0 {
            return self.fail();
        }
        self.released |= 1 << index;
        Ok(())
    }
    fn finish_inert_release(&mut self) -> Result<()> {
        if self.phase != Phase::Releasing || self.released != ALL_ROOT_CHILDREN { return self.fail(); }
        self.phase = Phase::InertReleased;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn entry_claim_is_consumed_once_without_reset() {
        let entered = AtomicBool::new(false);
        claim_entry(&entered).unwrap();
        assert!(entered.load(Ordering::Acquire));
        assert!(claim_entry(&entered).is_err());
        assert!(claim_entry(&entered).is_err());
    }
    fn prepared() -> InertBarrier {
        let mut gate = InertBarrier::new();
        for index in 0..ROOT_CHILDREN { gate.prepared(index).unwrap(); }
        gate
    }
    #[test]
    fn missing_duplicate_and_abort_cannot_release() {
        let mut gate = InertBarrier::new();
        assert!(gate.decide_release().is_err());
        assert!(gate.prepared(0).is_err());
        let mut gate = InertBarrier::new();
        gate.prepared(0).unwrap();
        assert!(gate.prepared(0).is_err());
        assert!(gate.decide_release().is_err());
    }
    #[test]
    fn partial_release_never_finishes_or_retries() {
        let mut gate = prepared();
        gate.decide_release().unwrap();
        gate.released(0).unwrap();
        assert!(gate.finish_inert_release().is_err());
        assert!(gate.released(1).is_err());
        assert!(gate.decide_release().is_err());
        let mut gate = prepared();
        gate.decide_release().unwrap();
        assert!(gate.decide_release().is_err());
    }
    #[test]
    fn complete_release_is_inert_and_one_shot() {
        let mut gate = prepared();
        gate.decide_release().unwrap();
        for index in 0..ROOT_CHILDREN { gate.released(index).unwrap(); }
        gate.finish_inert_release().unwrap();
        assert!(gate.finish_inert_release().is_err());
        assert!(gate.decide_release().is_err());
    }
}
