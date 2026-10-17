//! Actual process-local ownership of one completed common-context read.
//! Focus loss may preserve this key-free receipt; no journal, request, callback
//! or serialized lineage can create it. Every fresh-entry failure consumes it.
pub(crate) mod named_recipient;
use super::common_context_read_v1::NativeCommonContextReadAdmission;
use super::*;
use std::os::unix::fs::MetadataExt;
use wholepact_signer_origin::roster_common_context_read_v1::RosterCommonContextReadEvidenceV1;

/// Key-free identity of an exact original source. Inodes prevent replacing a
/// byte-identical source at the same pathname; encrypted originals are also
/// hashed. Mutable journal contents are independently authenticated on reopen.
struct SourceFileIdentity {
    name: &'static str,
    device: u64,
    inode: u64,
    digest: Option<String>,
}
struct OriginalSourceIdentity {
    root: PathBuf,
    device: u64,
    inode: u64,
    files: Vec<SourceFileIdentity>,
}
impl OriginalSourceIdentity {
    fn capture(retained: &RetainedBornManualRosterEnrollmentV2) -> Result<Self> {
        let root = retained.account.directory.root().to_path_buf();
        let metadata = std::fs::symlink_metadata(&root)?;
        let mut files = Vec::new();
        for (name, immutable) in [
            ("signer.lock", false),
            ("account.wp", true),
            ("birth-owner-request.wp", true),
            (INTENT, true),
            (ROSTER_ACQUIRE, true),
            (ROSTER_COMMIT, true),
            (JOURNAL, false),
        ] {
            let metadata = std::fs::symlink_metadata(root.join(name))?;
            if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.nlink() != 1 {
                return Err(Error::ReviewMismatch);
            }
            files.push(SourceFileIdentity {
                name,
                device: metadata.dev(),
                inode: metadata.ino(),
                digest: if immutable {
                    Some(hex::encode(Sha256::digest(
                        retained.account.directory.read(name, 512 * 1024)?,
                    )))
                } else {
                    None
                },
            });
        }
        let identity = Self {
            root,
            device: metadata.dev(),
            inode: metadata.ino(),
            files,
        };
        identity.check_path()?;
        Ok(identity)
    }
    fn check_path(&self) -> Result<()> {
        require_canonical_existing_root(&self.root)?;
        let metadata = std::fs::symlink_metadata(&self.root)?;
        if !metadata.is_dir() || metadata.dev() != self.device || metadata.ino() != self.inode {
            return Err(Error::ReviewMismatch);
        }
        for file in &self.files {
            let metadata = std::fs::symlink_metadata(self.root.join(file.name))?;
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || metadata.dev() != file.device
                || metadata.ino() != file.inode
                || metadata.nlink() != 1
            {
                return Err(Error::ReviewMismatch);
            }
        }
        Ok(())
    }
    fn check_opened(&self, retained: &RetainedBornManualRosterEnrollmentV2) -> Result<()> {
        self.check_path()?;
        if retained.account.directory.root() != self.root {
            return Err(Error::ReviewMismatch);
        }
        for file in &self.files {
            if let Some(expected) = &file.digest {
                if &hex::encode(Sha256::digest(
                    retained.account.directory.read(file.name, 512 * 1024)?,
                )) != expected
                {
                    return Err(Error::ReviewMismatch);
                }
            }
        }
        Ok(())
    }
}

/// No AccountVault, encryption key, FVK, journal, witness client, peer token,
/// native authority, or publication grant survives inside this identity.
pub(super) struct DormantReadOrigin {
    source: OriginalSourceIdentity,
    record: BornManualRosterEnrollmentRecordV2,
    intent_digest: String,
    // Exact process-local identity survives; no database/key does.
    journal_binding: crate::consent_journal::SignerJournalBinding,
    native_binding_digest: String,
    host_process_digest: String,
    host: crate::native_peer::PeerProcess,
    lifetime: crate::native_ui::DormantNativeLifetime,
}
impl DormantReadOrigin {
    pub(super) fn capture(
        source: &BornRosterInventorySourceV2,
        peer: &AuthenticatedPeer,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<Self> {
        source.check(peer, owner)?;
        let retained = &source.enrolled.retained;
        let result = Self {
            source: OriginalSourceIdentity::capture(retained)?,
            record: retained.record.clone(),
            intent_digest: retained.intent_digest.clone(),
            journal_binding: source.enrolled.journal.binding(),
            native_binding_digest: owner.native().binding().entry_digest().to_owned(),
            host_process_digest: canonical(
                "wholepact:common-context-original-host-process:v1",
                &(peer.peer.uid(), peer.peer.pid(), peer.peer.instance()),
            )?,
            host: peer.peer.clone(),
            lifetime: owner.dormant_lifetime()?,
        };
        result.check()?;
        Ok(result)
    }
    fn check(&self) -> Result<()> {
        if !is_hash(&self.native_binding_digest) || !is_hash(&self.host_process_digest) {
            return Err(Error::Authentication);
        }
        self.host.check_alive().map_err(|_| Error::Authentication)?;
        self.lifetime.check_connected()?;
        self.source.check_path()
    }
}

/// Moved only from the completed actual producer. Deliberately neither Clone
/// nor Deserialize. Dropping it permanently ends this completion path.
pub(crate) struct DormantCommonContextReadAdmission {
    original: NativeCommonContextReadAdmission,
    origin: DormantReadOrigin,
}
impl BornRosterInventorySourceV2 {
    pub(crate) fn check_common_context_completion_only(&self) -> Result<()> {
        let read = self
            .common_context_read
            .as_ref()
            .ok_or(Error::ReviewMismatch)?;
        read.check_completion_at(now()?, Instant::now())?;
        read.dormant_origin
            .as_ref()
            .ok_or(Error::ReviewMismatch)?
            .check()
    }
    pub(crate) fn detach_dormant_common_context(
        &mut self,
    ) -> Result<DormantCommonContextReadAdmission> {
        if !self.exact_observation_attempted || self.exact_observation.is_some() {
            return Err(Error::ReviewMismatch);
        }
        let mut original = self
            .common_context_read
            .take()
            .ok_or(Error::ReviewMismatch)?;
        let evidence = original
            .completed_evidence
            .as_ref()
            .ok_or(Error::ReviewMismatch)?;
        if self.common_context_plan.as_ref() != Some(&evidence.request.plan)
            || original.request != evidence.request
            || original.evidence_digest()? != evidence.digest().map_err(|_| Error::InvalidData)?
        {
            return Err(Error::ReviewMismatch);
        }
        let origin = original
            .dormant_origin
            .take()
            .ok_or(Error::ReviewMismatch)?;
        origin.check()?;
        // Only these two fields move. The UI revokes and retires the stripped
        // source and every other foreground owner off its rendering thread.
        Ok(DormantCommonContextReadAdmission { original, origin })
    }
}
impl DormantCommonContextReadAdmission {
    pub(crate) fn check_current(&self) -> Result<()> {
        self.original.check_completion_at(now()?, Instant::now())?;
        self.origin.check()
    }
    pub(crate) fn completion_deadline(&self) -> Instant {
        self.original.completion_deadline
    }

    /// The caller takes its unique dormant slot BEFORE invoking this KDF. No
    /// error returns the receipt. A fresh genuine native entry is mandatory.
    pub(crate) fn unlock(
        self,
        path: &Path,
        password: &[u8],
        owner: &PendingAccountNativeAuthority,
    ) -> Result<FreshCommonContextReentrySource> {
        self.check_current()?;
        owner.check_current()?;
        if path != self.origin.source.root
            || owner.native().binding().entry_digest() == self.origin.native_binding_digest
        {
            return Err(Error::ReviewMismatch);
        }
        let account = Arc::new(AccountVault::unlock_born_for_manual_roster_enrollment_v2(
            path, password, owner,
        )?);
        self.check_current()?;
        let retained = read_roster_retained(account)?;
        if retained.record != self.origin.record
            || retained.intent_digest != self.origin.intent_digest
        {
            return Err(Error::ReviewMismatch);
        }
        self.origin.source.check_opened(&retained)?;
        let original_read = self
            .original
            .completed_evidence
            .as_ref()
            .ok_or(Error::ReviewMismatch)?;
        super::super::retention::read_exact_with_ciphertext_digest(
            &retained,
            &original_read.request.plan.retained,
            &original_read.request.plan.retained_evidence_digest,
            &original_read.request.original_durable_receipt_digest,
        )?;
        let journal = SignerConsentJournal::reopen_common_context_completion(
            &FreshCommonContextJournalReopen {
                dormant: &self,
                retained: &retained,
                owner,
            },
        )?;
        let source = FreshCommonContextReentrySource {
            dormant: self,
            retained,
            journal: Arc::new(journal),
            native: owner.native().binding(),
        };
        source.check(owner)?;
        Ok(source)
    }
}

/// Borrowed genuine owner proof for the journal's private checked reopen.
/// Fields are private and there is no data/JSON constructor or binding setter.
pub(crate) struct FreshCommonContextJournalReopen<'a> {
    dormant: &'a DormantCommonContextReadAdmission,
    retained: &'a RetainedBornManualRosterEnrollmentV2,
    owner: &'a PendingAccountNativeAuthority,
}
impl FreshCommonContextJournalReopen<'_> {
    pub(crate) fn check_current(&self) -> Result<()> {
        self.dormant.check_current()?;
        self.owner.check_current()?;
        self.retained.check_current_source(self.owner)?;
        if self.owner.native().binding().entry_digest() == self.dormant.origin.native_binding_digest
            || self.retained.record != self.dormant.origin.record
            || self.retained.intent_digest != self.dormant.origin.intent_digest
        {
            return Err(Error::ReviewMismatch);
        }
        self.dormant.origin.source.check_opened(self.retained)?;
        let read = self.original_read()?;
        super::super::retention::read_exact_with_ciphertext_digest(
            self.retained,
            &read.request.plan.retained,
            &read.request.plan.retained_evidence_digest,
            &read.request.original_durable_receipt_digest,
        )?;
        Ok(())
    }
    pub(crate) fn journal_path(&self) -> PathBuf {
        self.retained.account.directory.root().join(JOURNAL)
    }
    pub(crate) fn journal_key(&self) -> DatabaseKey {
        DatabaseKey::from_bytes(*self.retained.journal_key)
    }
    pub(crate) fn genesis(&self) -> &AccountUseGenesis {
        &self.retained.record.account_record.genesis
    }
    pub(crate) fn writer_epoch(&self) -> u64 {
        self.retained
            .record
            .account_record
            .terms
            .signer
            .writer_epoch
    }
    pub(crate) fn original_read(&self) -> Result<&RosterCommonContextReadEvidenceV1> {
        self.dormant
            .original
            .completed_evidence
            .as_ref()
            .ok_or(Error::ReviewMismatch)
    }
    pub(crate) fn original_authorization_digest(&self) -> Result<String> {
        let signed = self
            .dormant
            .original
            .handoff_authorization
            .as_ref()
            .ok_or(Error::ReviewMismatch)?;
        signed
            .verify(
                &self
                    .retained
                    .record
                    .account_record
                    .terms
                    .signer
                    .owner_certificate_digest,
            )
            .map_err(|_| Error::Authentication)?;
        signed.digest().map_err(|_| Error::InvalidData)
    }
    pub(crate) fn original_binding(&self) -> &crate::consent_journal::SignerJournalBinding {
        &self.dormant.origin.journal_binding
    }
}

/// Freshly decrypted actual original source for this one completion only.
/// Never constructed by ordinary restart, history inspection or DTO parsing.
pub(crate) struct FreshCommonContextReentrySource {
    dormant: DormantCommonContextReadAdmission,
    retained: RetainedBornManualRosterEnrollmentV2,
    journal: Arc<SignerConsentJournal>,
    native: NativeAuthorityBinding,
}
impl FreshCommonContextReentrySource {
    pub(crate) fn check(&self, owner: &PendingAccountNativeAuthority) -> Result<()> {
        owner.check_current()?;
        self.native.check_current()?;
        if owner.native().binding() != self.native
            || self.journal.binding() != self.dormant.origin.journal_binding
        {
            return Err(Error::ReviewMismatch);
        }
        self.dormant.check_current()?;
        self.retained.check_current_source(owner)?;
        self.dormant.origin.source.check_opened(&self.retained)?;
        let read = self.original_read();
        self.journal.check_common_context_authorized_reentry_owner(
            &CommonContextAuthorizedReentryOwnerInput {
                genesis: &self.retained.record.account_record.genesis,
                epoch: self
                    .retained
                    .record
                    .account_record
                    .terms
                    .signer
                    .writer_epoch,
                read_digest: &read.digest().map_err(|_| Error::InvalidData)?,
                attempt_digest: &read.current_attempt_digest,
                attempt_sequence: read.current_attempt_sequence,
                plan: &read.request.plan,
                authorization_digest: &self
                    .original_authorization()
                    .digest()
                    .map_err(|_| Error::InvalidData)?,
            },
            false,
        )?;
        Ok(())
    }
    pub(crate) fn original_authorization(&self) -> &wholepact_authority::construction_transport_handoff_v1::SignedConstructionTransportPreauthorizationV1{
        self.dormant
            .original
            .handoff_authorization
            .as_ref()
            .expect("actual signed original handoff source")
    }
    pub(crate) fn require_exact_change(
        &self,
        request: &wholepact_core::manual_roster_construction_v3::ManualRosterConstructionRequestV3,
    ) -> Result<()> {
        if request.plan != self.original_read().request.plan {
            return Err(Error::ReviewMismatch);
        }
        let fvk = self.retained.account.account().fvk()?;
        let change = wholepact_protocol::review::decode_testnet_receiver(
            &request.plan.retained.change_address,
        )
        .map_err(|_| Error::ReviewMismatch)?;
        if fvk.scope_for_address(&change) != Some(orchard::keys::Scope::Internal) {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    pub(crate) fn journal(&self) -> &SignerConsentJournal {
        &self.journal
    }
    pub(crate) fn check_peer(
        &self,
        peer: &AuthenticatedPeer,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<()> {
        self.check(owner)?;
        peer.check_current()?;
        self.dormant
            .origin
            .host
            .same_live_process(&peer.peer)
            .map_err(|_| Error::Authentication)?;
        let t = &self.retained.record.account_record.terms;
        if peer.scope.account_id != t.identity.account_id
            || peer.scope.agreement_id != t.scope.agreement_id
            || peer.scope.participant_id != t.scope.participant_id
            || peer.scope.manifest_digest
                != self
                    .original_read()
                    .request
                    .plan
                    .digest()
                    .map_err(|_| Error::InvalidData)?
            || peer.scope.history_read
            || peer.scope.authorization_export
            || peer.scope.preconstruction_export
            || wholepact_signer_origin::manual_current_caller_binding_digest(
                &peer.grant_id,
                &peer.scope,
            )
            .map_err(|_| Error::InvalidData)?
                == self.original_read().request.current_caller_binding_digest
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    pub(crate) fn check_pairing(
        &self,
        pair: &crate::ipc::PendingPairing,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<()> {
        self.check(owner)?;
        pair.same_live_process(&self.dormant.origin.host)?;
        let t = &self.retained.record.account_record.terms;
        if pair.scope.account_id != t.identity.account_id
            || pair.scope.agreement_id != t.scope.agreement_id
            || pair.scope.participant_id != t.scope.participant_id
            || pair.scope.manifest_digest
                != self
                    .original_read()
                    .request
                    .plan
                    .digest()
                    .map_err(|_| Error::InvalidData)?
            || pair.scope.history_read
            || pair.scope.authorization_export
            || pair.scope.preconstruction_export
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    pub(crate) fn original_history(&self) -> Result<wholepact_authority::ConstructionHistoryV2> {
        let read = self.original_read();
        let row = self.journal.check_common_context_authorized_reentry_owner(
            &CommonContextAuthorizedReentryOwnerInput {
                genesis: &self.retained.record.account_record.genesis,
                epoch: self
                    .retained
                    .record
                    .account_record
                    .terms
                    .signer
                    .writer_epoch,
                read_digest: &read.digest().map_err(|_| Error::InvalidData)?,
                attempt_digest: &read.current_attempt_digest,
                attempt_sequence: read.current_attempt_sequence,
                plan: &read.request.plan,
                authorization_digest: &self
                    .original_authorization()
                    .digest()
                    .map_err(|_| Error::InvalidData)?,
            },
            false,
        )?;
        let crate::consent_journal::CommonContextSignerAuditV1::ReadAdmitted {
            witness_history,
            ..
        } = row
        else {
            return Err(Error::ReviewMismatch);
        };
        Ok(*witness_history)
    }
    pub(crate) fn require_current_handoff_history(
        &self,
        history: &wholepact_authority::ReconciledAuthorityHistory,
        pending: &wholepact_authority::construction_transport_handoff_v1::PendingConstructionTransportGrantV1,
    ) -> Result<()> {
        pending.validate().map_err(|_| Error::InvalidData)?;
        let old = self.original_history()?;
        let current = history
            .construction_history_with_transport_v1()
            .map_err(|_| Error::ReviewMismatch)?;
        current.validate().map_err(|_| Error::ReviewMismatch)?;
        // The reconciled public projection carries the authenticated exclusion
        // state. Do not call Authority's crate-private mutation helper here.
        if history.account_use_history().exclusion().is_some() {
            return Err(Error::ReviewMismatch);
        }
        if pending.grant.authorization != *self.original_authorization()
            || pending.grant.expected_head != old.observed_snapshot().head
            || current.observed_snapshot().head != pending.committed_head
            || current.observed_snapshot().last_witness_time_ms
                < old.observed_snapshot().last_witness_time_ms
            || current.original.witness() != old.witness()
            || current.original.original_birth() != old.original_birth()
            || current.original.approvals() != old.approvals()
            || current.original.origins() != old.origins()
            || current.transport.grants.as_slice() != [pending.clone()]
            || !current.transport.credentials.is_empty()
            || !current.transport.reservations.is_empty()
            || !current.transport.consumptions.is_empty()
        {
            return Err(Error::ReviewMismatch);
        }
        require_same_active_session(
            current.observed_snapshot(),
            &self.original_authorization().authorization.original_session,
            now()?,
        )?;
        if old.observed_snapshot().transport_fences.is_some()
            || current
                .observed_snapshot()
                .transport_fences
                .as_ref()
                .is_none_or(|f| f.version != 1 || !f.fenced_session_ids.is_empty())
        {
            return Err(Error::ReviewMismatch);
        }
        let mut expected = old.observed_snapshot().clone();
        expected.head = pending.committed_head.clone();
        expected.transport_fences = current.observed_snapshot().transport_fences.clone();
        expected.last_witness_time_ms = current.observed_snapshot().last_witness_time_ms;
        if current.observed_snapshot() != &expected {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    pub(crate) fn shared_wall_high_water(&self) -> Arc<std::sync::atomic::AtomicU64> {
        self.dormant.original.maximum_wall_seen.clone()
    }
    pub(crate) fn retained(&self) -> &RetainedBornManualRosterEnrollmentV2 {
        &self.retained
    }
    pub(crate) fn reopen_retained(
        &self,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<RetainedBornManualRosterEnrollmentV2> {
        self.check(owner)?;
        self.retained.reopen_exact(owner)
    }
    pub(crate) fn original_read(&self) -> &RosterCommonContextReadEvidenceV1 {
        // Only unlock constructs this type after requiring completed evidence.
        self.dormant
            .original
            .completed_evidence
            .as_ref()
            .expect("completed producer-owned read")
    }
    pub(crate) fn completion_deadline(&self) -> Instant {
        self.dormant.completion_deadline()
    }
}

/// Actual original foreground source for the separate future-handoff consent.
/// It cannot be made from the read DTO or a retained signature.
pub(crate) struct OriginalCommonContextHandoffSource {
    source: BornRosterInventorySourceV2,
    peer: AuthenticatedPeer,
    native: NativeAuthorityBinding,
}
impl OriginalCommonContextHandoffSource {
    pub(crate) fn prepare(
        source: BornRosterInventorySourceV2,
        peer: AuthenticatedPeer,
        owner: &PendingAccountNativeAuthority,
        read_digest: &str,
        caller_digest: &str,
    ) -> Result<Self> {
        source.check(&peer, owner)?;
        Self::require_exact_read_input(&source, &peer, read_digest, caller_digest)?;
        let value = Self {
            source,
            peer,
            native: owner.native().binding(),
        };
        value.check(owner)?;
        Ok(value)
    }
    /// The original data predicate, shared with borrowed probes on the actual
    /// prepared owner. This accepts no substitute source or peer constructor.
    fn require_exact_read_input(
        source: &BornRosterInventorySourceV2,
        peer: &AuthenticatedPeer,
        read_digest: &str,
        caller_digest: &str,
    ) -> Result<()> {
        let read = source
            .common_context_read
            .as_ref()
            .ok_or(Error::ReviewMismatch)?;
        let evidence = read
            .completed_evidence
            .as_ref()
            .ok_or(Error::ReviewMismatch)?;
        if read.evidence_digest()? != read_digest
            || evidence.request.current_caller_binding_digest != caller_digest
            || peer.grant_id != read.peer_grant_id
            || caller_digest
                != wholepact_signer_origin::manual_current_caller_binding_digest(
                    &peer.grant_id,
                    &peer.scope,
                )
                .map_err(|_| Error::InvalidData)?
            || read.handoff_authorization.is_some()
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub(crate) fn require_exact_read_for_qualification(
        &self,
        read_digest: &str,
        caller_digest: &str,
    ) -> Result<()> {
        Self::require_exact_read_input(&self.source, &self.peer, read_digest, caller_digest)
    }
    pub(crate) fn check(&self, owner: &PendingAccountNativeAuthority) -> Result<()> {
        self.source.check(&self.peer, owner)?;
        if self.native != owner.native().binding() {
            return Err(Error::ReviewMismatch);
        }
        let read = self
            .source
            .common_context_read
            .as_ref()
            .ok_or(Error::ReviewMismatch)?;
        read.check_completion_at(now()?, Instant::now())?;
        let origin = read.dormant_origin.as_ref().ok_or(Error::ReviewMismatch)?;
        if origin.native_binding_digest != self.native.entry_digest() {
            return Err(Error::ReviewMismatch);
        }
        origin.check()?;
        origin
            .host
            .same_live_process(&self.peer.peer)
            .map_err(|_| Error::Authentication)?;
        Ok(())
    }
    pub(crate) fn read(&self) -> &RosterCommonContextReadEvidenceV1 {
        self.source
            .common_context_read
            .as_ref()
            .and_then(|r| r.completed_evidence.as_ref())
            .expect("actual completed source")
    }
    pub(crate) fn record(&self) -> &BornManualRosterEnrollmentRecordV2 {
        &self.source.enrolled.retained.record
    }
    pub(crate) fn session(&self) -> &wholepact_authority::WriterSessionReceipt {
        self.source.enrolled.witness.session()
    }
    pub(crate) fn journal(&self) -> &SignerConsentJournal {
        &self.source.enrolled.journal
    }
    pub(crate) fn host_commitment(&self) -> &str {
        &self
            .source
            .common_context_read
            .as_ref()
            .and_then(|r| r.dormant_origin.as_ref())
            .expect("actual source identity")
            .host_process_digest
    }
    pub(crate) fn native_binding_digest(&self) -> &str {
        self.native.entry_digest()
    }
    pub(crate) fn completion_deadline(&self) -> Instant {
        self.source
            .common_context_read
            .as_ref()
            .expect("actual completed source")
            .completion_deadline
    }
    pub(crate) fn finish(
        mut self,
        authorization: wholepact_authority::construction_transport_handoff_v1::SignedConstructionTransportPreauthorizationV1,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<BornRosterInventorySourceV2> {
        owner.check_current()?;
        if owner.native().binding() != self.native {
            return Err(Error::ReviewMismatch);
        }
        let read = self
            .source
            .common_context_read
            .as_mut()
            .ok_or(Error::ReviewMismatch)?;
        if read.handoff_authorization.is_some() {
            return Err(Error::ReviewMismatch);
        }
        read.handoff_authorization = Some(authorization);
        self.check(owner)?;
        Ok(self.source)
    }
}

/// Current eligibility is checked against the SAME unchanged original receipt.
/// An archive or historical receipt cannot substitute for current active state.
fn require_same_active_session(
    snapshot: &wholepact_authority::AccountSnapshot,
    original: &wholepact_authority::WriterSessionReceipt,
    wall: u64,
) -> Result<()> {
    if wall >= original.expires_at_ms
        || snapshot.writer_status != wholepact_authority::WriterStatus::Active
        || snapshot.active_writer_session.as_ref() != Some(original)
        || snapshot.writer_certificate_digest != original.writer_certificate_digest
        || snapshot.writer_epoch != original.writer_epoch
    {
        return Err(Error::ReviewMismatch);
    }
    Ok(())
}
#[cfg(test)]
mod exact_session_tests {
    use super::*;
    fn original() -> (
        wholepact_authority::AccountSnapshot,
        wholepact_authority::WriterSessionReceipt,
    ) {
        // Inert never-funded archived data. No source, key, signature, native
        // decision, provider, socket or witness admission is produced.
        let raw: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../../consent_journal/fixtures/common-context-authority-audit.synthetic.json"
        ))
        .unwrap();
        let history: wholepact_authority::ConstructionHistoryV2 =
            serde_json::from_value(raw["pre_reserve_history"].clone()).unwrap();
        let snapshot = history.observed_snapshot().clone();
        let session = snapshot.active_writer_session.clone().unwrap();
        (snapshot, session)
    }
    #[test]
    fn expired_paused_replaced_or_missing_current_session_refuses_original_receipt() {
        let (snapshot, session) = original();
        let wall = session.expires_at_ms - 1;
        assert!(require_same_active_session(&snapshot, &session, wall).is_ok());
        assert!(require_same_active_session(&snapshot, &session, session.expires_at_ms).is_err());
        let mut changed = snapshot.clone();
        changed.active_writer_session = None;
        assert!(require_same_active_session(&changed, &session, wall).is_err());
        let mut changed = snapshot.clone();
        changed.writer_epoch += 1;
        assert!(require_same_active_session(&changed, &session, wall).is_err());
        let mut changed = snapshot.clone();
        changed.active_writer_session.as_mut().unwrap().session_id = "ff".repeat(32);
        assert!(require_same_active_session(&changed, &session, wall).is_err());
        let mut changed = snapshot;
        changed.writer_status = wholepact_authority::WriterStatus::Paused;
        assert!(require_same_active_session(&changed, &session, wall).is_err());
    }
}
