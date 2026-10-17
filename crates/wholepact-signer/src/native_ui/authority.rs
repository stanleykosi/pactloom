//! The signer-owned native entry and exact decision provenance. A binary digest
//! is reproducibility evidence, not proof of an installer/publisher or a human.
//! Security relies on the correctly operating signer and trusted OS/compositor.
use crate::{Error, Result};
use sha2::{Digest, Sha256};
use std::{
    io::Read,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

#[derive(Clone)]
pub(crate) struct NativeAuthorityBinding {
    instance: Arc<AtomicBool>,
    publication: Arc<std::sync::RwLock<()>>,
    // Immutable optional deadline belongs to this actual native instance. It is
    // copied into every binding, decision and worker scope, never refreshed.
    expires_at: Option<Instant>,
    // Only the dedicated retirement entry installs its actual inherited parent.
    // The immutable restriction follows this exact instance into grant/peer and
    // every concrete pair/evidence write check, even without GUI redraw.
    #[cfg(feature = "authority-signing")]
    retirement_parent: Option<crate::native_launch::ParentChannel>,
    // A process-local entry commitment, never a deserialized authority.
    identity: String,
    #[cfg(feature = "pending-birth-owner-signing")]
    construction_transport: Arc<
        std::sync::Mutex<Option<wholepact_authority::transport::ConstructionTransportRevocationV1>>,
    >,
}
impl PartialEq for NativeAuthorityBinding {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.instance, &other.instance)
            && Arc::ptr_eq(&self.publication, &other.publication)
            && self.expires_at == other.expires_at
    }
}
impl Eq for NativeAuthorityBinding {}
#[cfg(feature = "authority-signing")]
pub(crate) struct NativePublicationLease<'a> {
    _guard: std::sync::RwLockReadGuard<'a, ()>,
}
impl NativeAuthorityBinding {
    #[cfg(feature = "authority-signing")]
    pub(crate) fn deadline(&self) -> Option<Instant> {
        self.expires_at
    }
    #[cfg(feature = "pending-birth-owner-signing")]
    pub(crate) fn bounded_deadline(&self) -> Result<Instant> {
        self.check_current()?;
        self.expires_at.ok_or(Error::Locked)
    }

    /// Linearizes durable publication against native lock/focus invalidation.
    /// A previously admitted short commit drains before lock returns; no new
    /// publication lease can be obtained after invalidation.
    #[cfg(feature = "authority-signing")]
    pub(crate) fn publication_lease(&self) -> Result<NativePublicationLease<'_>> {
        let guard = self.publication.read().map_err(|_| Error::Locked)?;
        self.check_current()?;
        Ok(NativePublicationLease { _guard: guard })
    }

    #[cfg(feature = "pending-birth-owner-signing")]
    pub(crate) fn retain_construction_transport_revocation(
        &self,
        revoke: wholepact_authority::transport::ConstructionTransportRevocationV1,
    ) -> Result<()> {
        let mut slot = self
            .construction_transport
            .lock()
            .map_err(|_| Error::Locked)?;
        if !self.instance.load(Ordering::Acquire)
            || self.expires_at.is_some_and(|d| Instant::now() >= d)
            || slot.is_some()
        {
            // Dropping the unregistered owner closes/zeroizes the exact channel.
            return Err(Error::Locked);
        }
        *slot = Some(revoke);
        Ok(())
    }
    fn revoke_construction_transport(&self) {
        #[cfg(feature = "pending-birth-owner-signing")]
        {
            let revoke = self
                .construction_transport
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .take();
            drop(revoke);
        }
    }

    pub(crate) fn entry_digest(&self) -> &str {
        &self.identity
    }

    pub(crate) fn check_current(&self) -> Result<()> {
        if !self.instance.load(Ordering::Acquire)
            || self
                .expires_at
                .is_some_and(|deadline| Instant::now() >= deadline)
        {
            self.revoke_construction_transport();
            return Err(Error::Locked);
        }
        #[cfg(feature = "authority-signing")]
        if let Some(parent) = &self.retirement_parent {
            parent.check_connected()?;
        }
        Ok(())
    }
}
/// Owned by the real pending-account native UI lifecycle before generation.
/// Only a private runtime entry token from its focused primary-click branch can
/// construct this. Generic open-account NativeAuthority cannot be converted.
#[cfg(feature = "pending-birth-owner-signing")]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum PendingEntryPurpose {
    Ordinary,
    ConsumedBornNamed,
}
#[cfg(feature = "authority-signing")]
pub(crate) struct PendingAccountNativeAuthority {
    #[cfg(feature = "pending-birth-owner-signing")]
    purpose: PendingEntryPurpose,
    native: NativeAuthority,
    parent_channel: Option<crate::native_launch::ParentChannel>,
    focus_epoch: u64,
}
#[cfg(feature = "authority-signing")]
impl PendingAccountNativeAuthority {
    pub(super) fn enter(entry: super::runtime::PendingBirthEntry) -> Result<Self> {
        let (focus_epoch, parent_channel) = entry.into_parts();
        if let Some(channel) = &parent_channel {
            channel.check_connected()?;
        }
        let owner = Self {
            #[cfg(feature = "pending-birth-owner-signing")]
            purpose: PendingEntryPurpose::Ordinary,
            native: NativeAuthority::entered_native_window()?,
            parent_channel,
            focus_epoch,
        };
        owner.check_current()?;
        Ok(owner)
    }
    /// A private explicit audit/disclosure entry may shorten the generic owner
    /// lifetime. The caller captures this deadline BEFORE native entry/KDF;
    /// expiry is enforced by the actual shared binding even if the GUI stalls.
    /// A new review or worker result can never extend this same owner's scope.
    #[cfg(feature = "pending-birth-owner-signing")]
    pub(super) fn enter_bounded(
        entry: super::runtime::PendingBirthEntry,
        deadline: Instant,
    ) -> Result<Self> {
        require_bounded_entry_deadline(deadline, Instant::now())?;
        let mut owner = Self::enter(entry)?;
        owner.native.binding.expires_at = Some(deadline);
        owner.check_current()?;
        Ok(owner)
    }
    /// A distinct fresh entry for an actual key-free consumed-origin token.
    /// This cannot extend an old owner or any original financial clock.
    #[cfg(feature = "pending-birth-owner-signing")]
    pub(super) fn enter_consumed_born_named(
        entry: super::runtime::PendingBirthEntry,
        dormant: &crate::account::birth::enrollment::roster_v2::inventory::common_context_reentry_v1::named_recipient::DormantConsumedBornNamedSourceV1,
    ) -> Result<Self> {
        let deadline = Instant::now() + Duration::from_secs(15 * 60);
        dormant.check_current()?;
        let mut owner = Self::enter(entry)?;
        owner.purpose = PendingEntryPurpose::ConsumedBornNamed;
        owner.native.binding.expires_at = Some(deadline);
        dormant.check_current()?;
        owner.check_current()?;
        Ok(owner)
    }
    #[cfg(feature = "pending-birth-owner-signing")]
    pub(super) fn entry_purpose(&self) -> PendingEntryPurpose {
        self.purpose
    }
    #[cfg(feature = "pending-birth-owner-signing")]
    pub(super) fn publish_pending_endpoint(&self, path: &std::path::Path) -> Result<()> {
        self.check_current()?;
        if let Some(channel) = &self.parent_channel {
            channel.publish_endpoint(path)?;
        }
        self.check_current()
    }
    /// Retains only the original parent-channel liveness obligation. It cannot
    /// approve a review, publish an endpoint, or access the account or a grant.
    #[cfg(feature = "pending-birth-owner-signing")]
    pub(crate) fn dormant_lifetime(&self) -> Result<DormantNativeLifetime> {
        self.check_current()?;
        Ok(DormantNativeLifetime {
            parent_channel: self.parent_channel.clone(),
        })
    }
    pub(crate) fn native(&self) -> &NativeAuthority {
        &self.native
    }
    pub(crate) fn check_current(&self) -> Result<()> {
        self.native.check_current()?;
        if let Some(channel) = &self.parent_channel {
            if channel.check_connected().is_err() {
                self.native.binding.revoke_construction_transport();
                return Err(Error::Locked);
            }
        }
        Ok(())
    }
    pub(super) fn focus_epoch(&self) -> u64 {
        self.focus_epoch
    }
    pub(super) fn invalidate(&self) {
        self.native.invalidate();
    }
    /// Immediately closes admission without waiting for a worker's previously
    /// acquired short publication lease. The UI retains/drains that worker and
    /// reports its result as uncertain after cancellation. No fresh lease can
    /// pass check_current after this store. Generic account invalidation keeps
    /// its existing draining semantics.
    #[cfg(feature = "pending-birth-owner-signing")]
    pub(super) fn revoke_pending_now(&self) {
        self.native.binding.instance.store(false, Ordering::Release);
        self.native.binding.revoke_construction_transport();
    }
}

/// Purpose-specific non-authorizing lifetime witness, with no native binding.
#[cfg(feature = "pending-birth-owner-signing")]
pub(crate) struct DormantNativeLifetime {
    parent_channel: Option<crate::native_launch::ParentChannel>,
}
#[cfg(feature = "pending-birth-owner-signing")]
impl DormantNativeLifetime {
    pub(crate) fn check_connected(&self) -> Result<()> {
        if let Some(channel) = &self.parent_channel {
            channel.check_connected()?;
        }
        Ok(())
    }
}

pub(crate) struct NativeAuthority {
    binding: NativeAuthorityBinding,
    principal: String,
    measurement: String,
}
impl NativeAuthority {
    /// Called only by the private native UI account activation or the typed
    /// pending-account primary-click entry. Never derived from an argv/env flag.
    pub(super) fn entered_native_window() -> Result<Self> {
        let mut executable = std::fs::File::open("/proc/self/exe")?;
        let mut hasher = Sha256::new();
        hasher.update(b"wholepact:installed-native-signer-image:v1\0");
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let n = executable.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }
        Ok(Self {
            binding: NativeAuthorityBinding {
                instance: Arc::new(AtomicBool::new(true)),
                publication: Arc::new(std::sync::RwLock::new(())),
                expires_at: None,
                #[cfg(feature = "authority-signing")]
                retirement_parent: None,
                identity: hex::encode(crate::vault::random::<32>()?),
                #[cfg(feature = "pending-birth-owner-signing")]
                construction_transport: Arc::new(std::sync::Mutex::new(None)),
            },
            principal: format!("local-owner-uid-{}", unsafe { libc::geteuid() }),
            measurement: hex::encode(hasher.finalize()),
        })
    }
    /// Fresh named-verifier key entry inherits the original peer-request ceiling.
    /// Captured before profile KDF; publication checks cannot extend this deadline.
    #[cfg(all(feature = "authority-signing", feature = "offline-review-foundation"))]
    pub(super) fn entered_named_verifier_window(deadline: Instant) -> Result<Self> {
        require_bounded_entry_deadline(deadline, Instant::now())?;
        let mut owner = Self::entered_native_window()?;
        owner.binding.expires_at = Some(deadline);
        owner.check_current()?;
        Ok(owner)
    }
    /// Dedicated informational entry captures this ceiling before either KDF.
    /// Only the private retirement runtime token reaches this constructor; it
    /// cannot revive the ordinary native owner or any revoked peer grant.
    #[cfg(feature = "authority-signing")]
    pub(super) fn entered_retirement_window(
        deadline: Instant,
        parent_channel: Option<crate::native_launch::ParentChannel>,
    ) -> Result<Self> {
        require_bounded_entry_deadline(deadline, Instant::now())?;
        let mut owner = Self::entered_native_window()?;
        owner.binding.expires_at = Some(deadline);
        owner.binding.retirement_parent = parent_channel;
        owner.check_current()?;
        Ok(owner)
    }
    pub(crate) fn check_current(&self) -> Result<()> {
        self.binding.check_current()
    }
    pub(crate) fn binding(&self) -> NativeAuthorityBinding {
        self.binding.clone()
    }
    pub(crate) fn principal_id(&self) -> &str {
        &self.principal
    }
    pub(crate) fn measurement(&self) -> &str {
        &self.measurement
    }
    /// Close new informational admissions immediately. The restricted native
    /// state never registers construction transport; its background drain owns
    /// the eventual blocking invalidate/drop. An already held final publication
    /// lease may be draining, so cancellation cannot promise to recall output.
    #[cfg(feature = "authority-signing")]
    pub(super) fn revoke_informational_now(&self) {
        self.binding.instance.store(false, Ordering::Release);
    }
    /// Active named-recipient Lock closes this exact owner immediately. The
    /// runtime removes it from GUI state and retains it in the existing close
    /// worker until publication/transport/session drain completes. This is
    /// revocation only; it cannot create or refresh an authority instance.
    #[cfg(all(feature = "authority-signing", feature = "offline-review-foundation"))]
    pub(super) fn revoke_named_recipient_now(&self) {
        self.binding.instance.store(false, Ordering::Release);
    }
    pub(super) fn invalidate(&self) {
        self.binding.revoke_construction_transport();
        let _publication = self
            .binding
            .publication
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.binding.instance.store(false, Ordering::Release);
        // A registration may race the first revoke while an older publication
        // lease drains. Once the instance is closed, drain that slot again;
        // no later registration can pass its in-lock instance check.
        self.binding.revoke_construction_transport();
    }
}
impl Drop for NativeAuthority {
    fn drop(&mut self) {
        self.invalidate();
    }
}

/// Non-serializable, non-cloneable one-shot event. Only this module's private
/// review machine can construct it; callers cannot provide a bool or digest.
pub(crate) struct NativeDecision {
    source: NativeAuthorityBinding,
    digest: String,
    // Actual consuming native click, never serialized or supplied by a request.
    consumed_at: Instant,
}
impl NativeDecision {
    #[cfg(feature = "authority-signing")]
    pub(crate) fn consumed_at(&self) -> Instant {
        self.consumed_at
    }
    pub(crate) fn binding(&self) -> &NativeAuthorityBinding {
        &self.source
    }
    pub(crate) fn reviewed_digest(&self) -> &str {
        &self.digest
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Reading,
    Confirming,
}
pub(super) struct ExactNativeReview {
    source: NativeAuthorityBinding,
    digest: String,
    display: zeroize::Zeroizing<String>,
    created: Instant,
    stage: Stage,
    focus_epoch: u64,
}
impl ExactNativeReview {
    pub(super) fn stage(
        authority: &NativeAuthority,
        digest: &str,
        display: String,
        focus_epoch: u64,
    ) -> Result<Self> {
        authority.binding.check_current()?;
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::InvalidData);
        }
        Ok(Self {
            source: authority.binding(),
            digest: digest.into(),
            display: zeroize::Zeroizing::new(super::state::inert_text(&display)),
            created: Instant::now(),
            stage: Stage::Reading,
            focus_epoch,
        })
    }
    pub(super) fn display(&self) -> &str {
        &self.display
    }
    pub(super) fn digest(&self) -> &str {
        &self.digest
    }
    pub(super) fn confirming(&self) -> bool {
        self.stage == Stage::Confirming
    }
    pub(super) fn expired(&self) -> bool {
        self.created.elapsed() >= Duration::from_secs(120)
    }
    fn check(&self, focused: bool, epoch: u64) -> Result<()> {
        self.source.check_current()?;
        if !focused || epoch != self.focus_epoch || self.expired() {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    pub(super) fn continue_from_native_click(&mut self, focused: bool, epoch: u64) -> Result<()> {
        self.check(focused, epoch)?;
        if self.stage != Stage::Reading {
            return Err(Error::ReviewMismatch);
        }
        self.stage = Stage::Confirming;
        Ok(())
    }
    pub(super) fn consume_native_click(
        self,
        focused: bool,
        epoch: u64,
        entered: &str,
    ) -> Result<NativeDecision> {
        self.check(focused, epoch)?;
        if self.stage != Stage::Confirming || entered != format!("AUTHORIZE {}", &self.digest[..12])
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(NativeDecision {
            source: self.source,
            digest: self.digest,
            consumed_at: Instant::now(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Isolated state-machine fixtures never become a production launch source.
    fn source() -> NativeAuthority {
        NativeAuthority {
            binding: NativeAuthorityBinding {
                instance: Arc::new(AtomicBool::new(true)),
                publication: Arc::new(std::sync::RwLock::new(())),
                expires_at: None,
                #[cfg(feature = "authority-signing")]
                retirement_parent: None,
                identity: "a1".repeat(32),
                #[cfg(feature = "pending-birth-owner-signing")]
                construction_transport: Arc::new(std::sync::Mutex::new(None)),
            },
            principal: "synthetic-principal".into(),
            measurement: "12".repeat(32),
        }
    }
    #[test]
    #[ignore = "explicit real Unix IPC qualification; no substituted peer source"]
    fn held_journal_lease_rechecks_real_grant_revocation_and_expiry() {
        use crate::ipc::{LocalEvent, LocalIpc};
        use std::io::{BufRead, BufReader, Write};
        use std::os::unix::{fs::PermissionsExt, net::UnixStream};
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let key = wholepact_storage_security::DatabaseKey::from_bytes([0x64; 32]);
        let journal = crate::consent_journal::SignerConsentJournal::create_encrypted(
            &temp.path().join("synthetic-peer.db"),
            &key,
            "synthetic-account",
            1,
            false,
        )
        .unwrap();
        let authority = source();
        for expire in [false, true] {
            let directory = crate::files::PrivateDirectory::create(&temp.path().join(if expire {
                "expiry"
            } else {
                "revocation"
            }))
            .unwrap();
            let mut ipc = LocalIpc::bind(directory).unwrap();
            let path = ipc.socket_path().to_path_buf();
            let client = std::thread::spawn(move || {
                let mut pair = UnixStream::connect(&path).unwrap();
                pair.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                writeln!(pair, "{}", serde_json::json!({"command":"request_pairing", "schema_version":1,
                    "application_label":"fixed-synthetic-client", "scope":{"account_id":"synthetic-account",
                    "agreement_id":"synthetic-agreement","participant_id":"synthetic-participant",
                    "manifest_digest":"13".repeat(32)}})).unwrap();
                let mut response = String::new();
                BufReader::new(pair).read_line(&mut response).unwrap();
                let response: serde_json::Value = serde_json::from_str(&response).unwrap();
                let mut request = UnixStream::connect(path).unwrap();
                request
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                writeln!(
                    request,
                    "{}",
                    serde_json::json!({"command":"request","schema_version":1,
                    "grant_id":response["grant_id"],"token_hex":response["token_hex"],
                    "request":{"operation":"status"}})
                )
                .unwrap();
                let mut result = String::new();
                BufReader::new(request).read_line(&mut result).unwrap();
                assert!(result.contains("REQUEST_ONLY"));
            });
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut peer = loop {
                assert!(Instant::now() < deadline, "actual IPC event deadline");
                match ipc.next_event() {
                    Some(LocalEvent::Pairing(pending)) => {
                        let digest = pending.review_digest(ipc.generation()).unwrap();
                        let mut review = ExactNativeReview::stage(
                            &authority,
                            &digest,
                            "synthetic pairing".into(),
                            1,
                        )
                        .unwrap();
                        review.continue_from_native_click(true, 1).unwrap();
                        let decision = review
                            .consume_native_click(true, 1, &format!("AUTHORIZE {}", &digest[..12]))
                            .unwrap();
                        ipc.approve_pairing(pending, decision, &authority).unwrap();
                    }
                    Some(LocalEvent::Request { peer, .. }) => break peer,
                    Some(_) => panic!("unexpected operation"),
                    None => std::thread::sleep(Duration::from_millis(5)),
                }
            };
            client.join().unwrap();
            if expire {
                peer.shorten_expiry_for_test(Duration::from_secs(1));
            }
            crate::consent_journal::assert_native_peer_revocation(
                &journal,
                authority.binding(),
                authority.principal_id(),
                authority.measurement(),
                peer,
                || {
                    if expire {
                        std::thread::sleep(Duration::from_millis(1100));
                    } else {
                        ipc.revoke_all();
                    }
                },
            );
        }
    }
    #[test]
    fn journal_decisions_reject_other_window_and_revoked_native_origin() {
        let temp = tempfile::tempdir().unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let key = wholepact_storage_security::DatabaseKey::from_bytes([0x61; 32]);
        let journal = crate::consent_journal::SignerConsentJournal::create_encrypted(
            &temp.path().join("synthetic-native-source.db"),
            &key,
            "synthetic-account",
            1,
            false,
        )
        .unwrap();
        let first = source();
        let other = source();
        let session = crate::consent_journal::native_fixture_session(
            &journal,
            first.binding(),
            first.principal_id(),
            first.measurement(),
        );
        let digest = "34".repeat(32);
        let decision = |authority: &NativeAuthority| {
            let mut r =
                ExactNativeReview::stage(authority, &digest, "synthetic exact record".into(), 1)
                    .unwrap();
            r.continue_from_native_click(true, 1).unwrap();
            r.consume_native_click(true, 1, &format!("AUTHORIZE {}", &digest[..12]))
                .unwrap()
        };
        assert!(session.native_decision(decision(&other)).is_err());
        assert!(session.native_decision(decision(&first)).is_ok());
        let pending = decision(&first);
        first.invalidate();
        assert!(session.native_decision(pending).is_err());
    }
    #[test]
    fn exact_native_decision_requires_second_focused_click_same_epoch_and_phrase() {
        let authority = source();
        let digest = "34".repeat(32);
        let mut r =
            ExactNativeReview::stage(&authority, &digest, "synthetic exact record".into(), 7)
                .unwrap();
        assert!(r.continue_from_native_click(false, 7).is_err());
        r.continue_from_native_click(true, 7).unwrap();
        let d = r
            .consume_native_click(true, 7, &format!("AUTHORIZE {}", &digest[..12]))
            .unwrap();
        assert_eq!(d.reviewed_digest(), digest);
        assert!(d.binding() == &authority.binding());
    }
    #[test]
    fn revoked_replaced_expired_and_focus_changed_decisions_fail() {
        for mode in 0..4 {
            let authority = source();
            let digest = "34".repeat(32);
            let mut r =
                ExactNativeReview::stage(&authority, &digest, "synthetic".into(), 7).unwrap();
            r.continue_from_native_click(true, 7).unwrap();
            if mode == 0 {
                authority.invalidate();
            }
            if mode == 1 {
                r.created = Instant::now() - Duration::from_secs(121);
            }
            assert!(
                r.consume_native_click(
                    mode != 2,
                    if mode == 3 { 8 } else { 7 },
                    &format!("AUTHORIZE {}", &digest[..12])
                )
                .is_err()
            );
        }
    }
}

/// Synthetic test issuer only; absent from every production build.
#[cfg(all(test, feature = "authority-signing"))]
pub(crate) fn recovery_test_authority() -> NativeAuthority {
    NativeAuthority {
        binding: NativeAuthorityBinding {
            instance: Arc::new(AtomicBool::new(true)),
            publication: Arc::new(std::sync::RwLock::new(())),
            expires_at: None,
            #[cfg(feature = "authority-signing")]
            retirement_parent: None,
            identity: "a2".repeat(32),
            #[cfg(feature = "pending-birth-owner-signing")]
            construction_transport: Arc::new(std::sync::Mutex::new(None)),
        },
        principal: "synthetic-recovery-owner".into(),
        measurement: "71".repeat(32),
    }
}
#[cfg(all(test, feature = "authority-signing"))]
pub(crate) fn recovery_test_decision(authority: &NativeAuthority, digest: &str) -> NativeDecision {
    NativeDecision {
        consumed_at: Instant::now(),
        source: authority.binding(),
        digest: digest.into(),
    }
}

#[cfg(all(test, feature = "authority-signing"))]
mod publication_tests {
    use super::*;
    #[cfg(feature = "offline-review-foundation")]
    #[test]
    fn named_lock_revokes_without_waiting_for_already_admitted_publication() {
        let authority = Arc::new(recovery_test_authority());
        let binding = authority.binding();
        let lease = binding.publication_lease().unwrap();
        let closing = Arc::clone(&authority);
        let (send, recv) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            closing.revoke_named_recipient_now();
            send.send(()).unwrap();
        });
        let immediate = recv.recv_timeout(Duration::from_secs(2)).is_ok();
        // Release before joining even when a regression blocks the worker.
        drop(lease);
        worker.join().unwrap();
        assert!(immediate);
        assert!(binding.check_current().is_err());
        assert!(binding.publication_lease().is_err());
        authority.invalidate();
    }
    #[test]
    fn native_lock_drains_admitted_publication_then_rejects_new_leases() {
        let authority = Arc::new(recovery_test_authority());
        let binding = authority.binding();
        let lease = binding.publication_lease().unwrap();
        let locking = authority.clone();
        let (started, waiting) = std::sync::mpsc::channel();
        let (finished, done) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            started.send(()).unwrap();
            locking.invalidate();
            finished.send(()).unwrap();
        });
        waiting.recv().unwrap();
        assert!(done.try_recv().is_err());
        binding.check_current().unwrap();
        drop(lease);
        done.recv_timeout(Duration::from_secs(5)).unwrap();
        worker.join().unwrap();
        assert!(binding.check_current().is_err());
        assert!(binding.publication_lease().is_err());
    }
}

/// Pure bound check; timestamps are data, never a native entry or approval.
#[cfg(any(feature = "pending-birth-owner-signing", feature = "authority-signing"))]
fn require_bounded_entry_deadline(deadline: Instant, now: Instant) -> Result<()> {
    if deadline <= now || deadline > now + Duration::from_secs(120) {
        return Err(Error::ReviewMismatch);
    }
    Ok(())
}

#[cfg(all(test, feature = "pending-birth-owner-signing"))]
mod bounded_deadline_tests {
    use super::*;
    #[test]
    fn pending_revoke_closes_registered_transport_before_publication_drains() {
        // Inert cancellation only: no socket, exporter, credentials, account,
        // provider, authority effect or native decision is created.
        let owner = PendingAccountNativeAuthority {
            purpose: PendingEntryPurpose::Ordinary,
            native: recovery_test_authority(),
            parent_channel: None,
            focus_epoch: 1,
        };
        let binding = owner.native().binding();
        binding
            .retain_construction_transport_revocation(
                wholepact_authority::transport::ConstructionTransportRevocationV1::new(),
            )
            .unwrap();
        let admitted = binding.publication_lease().unwrap();
        owner.revoke_pending_now();
        assert!(binding.construction_transport.lock().unwrap().is_none());
        assert!(binding.check_current().is_err());
        assert!(
            binding
                .retain_construction_transport_revocation(
                    wholepact_authority::transport::ConstructionTransportRevocationV1::new(),
                )
                .is_err()
        );
        drop(admitted);
    }
    #[test]
    fn modeled_deadline_rejects_expired_and_extended_entry() {
        let now = Instant::now();
        assert!(require_bounded_entry_deadline(now, now).is_err());
        assert!(require_bounded_entry_deadline(now - Duration::from_secs(1), now).is_err());
        assert!(require_bounded_entry_deadline(now + Duration::from_secs(121), now).is_err());
    }
    #[test]
    fn expired_binding_denies_publication_without_waiting_for_gui_revocation() {
        // Negative source model only: no PendingBirthEntry, native owner,
        // NativeDecision, successful publication lease or approval is fabricated.
        let binding = NativeAuthorityBinding {
            instance: Arc::new(AtomicBool::new(true)),
            publication: Arc::new(std::sync::RwLock::new(())),
            expires_at: Some(Instant::now() - Duration::from_secs(1)),
            #[cfg(feature = "authority-signing")]
            retirement_parent: None,
            identity: "a3".repeat(32),
            #[cfg(feature = "pending-birth-owner-signing")]
            construction_transport: Arc::new(std::sync::Mutex::new(None)),
        };
        let handed_off = binding.clone();
        assert!(binding.check_current().is_err());
        assert!(handed_off.check_current().is_err());
        assert!(handed_off.publication_lease().is_err());
        assert!(binding.instance.load(Ordering::Acquire));
    }
}
