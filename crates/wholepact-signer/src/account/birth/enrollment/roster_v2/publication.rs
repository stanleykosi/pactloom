//! STAGED, UNCOMPILED. Actual held born source + current authenticated V2
//! witness proof + current native decision. No public data-to-owner conversion.
use super::*;
use wholepact_authority::manual_roster_witness_v2::{
    AuthenticatedBornManualRosterEnrollmentV2, BornManualRosterAdmissionRecordV2,
    ManualRosterSessionContinuationV2,
};
use wholepact_signer_origin::manual::ManualCurrentState;
use wholepact_signer_origin::manual_roster_v2::{
    DurableManualRosterAdmissionV2, HostManualRosterPublicationRequestV2,
    ManualRosterEnrollmentEvidenceV2, ManualRosterPublicationAttemptV2,
};

pub(crate) struct PreparedBornManualRosterPublicationV2 {
    retained: RetainedBornManualRosterEnrollmentV2,
    history: ReconciledAuthorityHistory,
    witness: AuthenticatedBornManualRosterEnrollmentV2,
    request: HostManualRosterPublicationRequestV2,
    source: NativeAuthorityBinding,
    peer: AuthenticatedPeer,
    digest: String,
    display: Zeroizing<String>,
}
fn actual_attempt(
    witness: &AuthenticatedBornManualRosterEnrollmentV2,
) -> Result<ManualRosterPublicationAttemptV2> {
    witness.check_current().map_err(|_| Error::ReviewMismatch)?;
    Ok(match witness.continuation() {
        None => ManualRosterPublicationAttemptV2::InitialV2 {},
        Some(c) => ManualRosterPublicationAttemptV2::ContinuationV2 {
            continuation_digest: c
                .digest_for(witness.extension())
                .map_err(|_| Error::InvalidData)?,
            attempt_sequence: c.sequence(),
        },
    })
}
pub(super) fn check_history(
    retained: &RetainedBornManualRosterEnrollmentV2,
    history: &ReconciledAuthorityHistory,
    witness: &AuthenticatedBornManualRosterEnrollmentV2,
) -> Result<()> {
    retained.check()?;
    witness.check_current().map_err(|_| Error::ReviewMismatch)?;
    let origin = original(&retained.account)?;
    let audit = origin
        .anchor()
        .audit_original_roster_preconstruction_witness_link(
            history,
            &retained.record.extension()?,
        )?;
    history
        .require_original_roster_preconstruction_history()
        .map_err(|_| Error::Unavailable)?;
    let t = &retained.record.account_record.terms;
    let s = history.snapshot();
    let ext = retained.record.extension()?;
    let attempt = history
        .latest_manual_roster_attempt_v2(&ext.account_extension.enrollment_ref)
        .map_err(|_| Error::RecoveryRequired)?;
    if history
        .manual_roster_enrollment_extension(&ext.account_extension.enrollment_ref)
        .map_err(|_| Error::Authentication)?
        != Some(&ext)
        || witness.extension() != &ext
        || witness.snapshot() != s
        || history.pending_birth_commit() != Some(origin.witness_commit())
        || audit.permanent_exclusion().is_some()
        || attempt.continuation.as_ref() != witness.continuation()
        || attempt.admission.as_ref() != Some(witness.record())
        || s.writer_status != WriterStatus::Active
        || s.writer_epoch != t.signer.writer_epoch
        || s.writer_certificate_digest != t.signer.writer_certificate_digest
        || s.active_writer_session.as_ref() != Some(witness.session())
        || s.outstanding_reservations != 0
        || s.outstanding_debit_zatoshis != 0
        || s.settled_debit_zatoshis != 0
        || history.reservation_evidence().next().is_some()
        || !history.automatic_key_use_admissions().is_empty()
        || !history.recovery_fences().is_empty()
        || now_ms()? >= t.scope.expires_at_ms
    {
        return Err(Error::RecoveryRequired);
    }
    Ok(())
}
impl PreparedBornManualRosterPublicationV2 {
    pub(crate) fn prepare(
        retained: RetainedBornManualRosterEnrollmentV2,
        history: ReconciledAuthorityHistory,
        witness: AuthenticatedBornManualRosterEnrollmentV2,
        request: HostManualRosterPublicationRequestV2,
        pairing: &AuthenticatedPairing,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<Self> {
        retained.check_current_source(owner)?;
        pairing.check_current()?;
        request
            .require_original(&retained.record.request()?)
            .map_err(|_| Error::ReviewMismatch)?;
        let peer = pairing.current_peer();
        let t = &retained.record.account_record.terms;
        if pairing.native_origin() != &owner.native().binding()
            || peer.scope.account_id != t.identity.account_id
            || peer.scope.agreement_id != t.scope.agreement_id
            || peer.scope.participant_id != t.scope.participant_id
            || peer.scope.manifest_digest != request.digest().map_err(|_| Error::InvalidData)?
            || peer.scope.history_read
            || peer.scope.authorization_export
            || peer.scope.preconstruction_export
            || request.attempt != actual_attempt(&witness)?
            || !retained.account.directory.exists(ROSTER_ACQUIRE)?
        {
            return Err(Error::Authentication);
        }
        continuation::require_attempted_journal(&retained)?;
        check_history(&retained, &history, &witness)?;
        let digest = canonical(
            "wholepact:native-born-manual-roster-publication:v2",
            &(
                &retained.record,
                &retained.intent_digest,
                &request,
                witness.record(),
                witness.continuation(),
                witness.extension(),
                witness.session(),
                pairing.binding(),
                owner.native().principal_id(),
                owner.native().measurement(),
            ),
        )?;
        let display = Zeroizing::new(format!(
            "CREATE OR FINISH THIS EXACT ROSTER-BOUND ACCOUNT JOURNAL\n\n{}\n{}\n{}\n\nThis is the original born account and original ledger. Host roster linkage is immutable and separate from account witness/session ancestry. The finite witness admission cannot renew on retry. A later continuation uses a separately approved fresh witness attempt and preserves every original. No financial action is authorized.\nExact review: {}",
            serde_json::to_string_pretty(&retained.record).map_err(|_| Error::InvalidData)?,
            serde_json::to_string_pretty(&request).map_err(|_| Error::InvalidData)?,
            serde_json::to_string_pretty(witness.record()).map_err(|_| Error::InvalidData)?,
            digest
        ));
        Ok(Self {
            retained,
            history,
            witness,
            request,
            source: owner.native().binding(),
            peer,
            digest,
            display,
        })
    }
    pub(crate) fn reviewed_digest(&self) -> &str {
        &self.digest
    }
    pub(crate) fn review_json(&self) -> Result<String> {
        self.check()?;
        Ok(self.display.to_string())
    }
    fn check(&self) -> Result<()> {
        self.source.check_current()?;
        self.peer.check_current()?;
        self.request
            .require_original(&self.retained.record.request()?)
            .map_err(|_| Error::ReviewMismatch)?;
        if self.request.attempt != actual_attempt(&self.witness)? {
            return Err(Error::ReviewMismatch);
        }
        check_history(&self.retained, &self.history, &self.witness)
    }
    pub(crate) fn approve_and_publish(
        self,
        decision: NativeDecision,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<BornManualRosterEnrolledSignerV2> {
        owner.check_current()?;
        owner.native().binding().bounded_deadline()?;
        self.check()?;
        if owner.native().binding() != self.source
            || decision.binding() != &self.source
            || decision.reviewed_digest() != self.digest
        {
            return Err(Error::ReviewMismatch);
        }
        let publication = BornRosterEnrollmentPublicationV2 {
            prepared: &self,
            _native: self.source.publication_lease()?,
        };
        if self.witness.continuation().is_some() {
            continuation::retain_admission(&self.retained, &self.witness)?;
        }
        let journal = SignerConsentJournal::publish_born_roster_enrollment_v2(&publication)?;
        let complete = BornManualRosterCommitV2 {
            version: 2,
            signer_roster_record_digest: self.retained.record.reference()?,
            intent_digest: self.retained.intent_digest.clone(),
            extension: self.witness.extension().clone(),
            original_continuation: self.witness.continuation().cloned(),
            original_admission: self.witness.record().clone(),
        };
        complete.validate_for(&self.retained)?;
        if self.retained.account.directory.exists(ROSTER_COMMIT)? {
            let original = read_commit(&self.retained)?;
            if original.signer_roster_record_digest != complete.signer_roster_record_digest
                || original.intent_digest != complete.intent_digest
                || original.extension != complete.extension
            {
                return Err(Error::ReviewMismatch);
            }
            // Keep the first publication admission and exact times unchanged.
        } else {
            let plain =
                Zeroizing::new(serde_json::to_vec(&complete).map_err(|_| Error::InvalidData)?);
            let bytes = vault::encrypt(
                &self.retained.account.encryption_key,
                &commit_domain(&self.retained)?,
                &plain,
            )?;
            self.retained
                .account
                .directory
                .write(ROSTER_COMMIT, &bytes)?;
        }
        self.retained.account.directory.sync_all_files()?;
        require_retained_admission(&self.retained, &self.witness)?;
        drop(publication);
        Ok(BornManualRosterEnrolledSignerV2 {
            retained: self.retained,
            journal: Arc::new(journal),
            history: self.history,
            witness: self.witness,
            source: self.source,
            peer: self.peer,
        })
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BornManualRosterCommitV2 {
    version: u16,
    signer_roster_record_digest: String,
    intent_digest: String,
    extension: ManualRosterEnrollmentExtensionV2,
    original_continuation: Option<ManualRosterSessionContinuationV2>,
    original_admission: BornManualRosterAdmissionRecordV2,
}
impl BornManualRosterCommitV2 {
    fn validate_for(&self, retained: &RetainedBornManualRosterEnrollmentV2) -> Result<()> {
        self.original_admission
            .validate_for(&self.extension, self.original_continuation.as_ref())
            .map_err(|_| Error::Authentication)?;
        if self.version != 2
            || self.signer_roster_record_digest != retained.record.reference()?
            || self.intent_digest != retained.intent_digest
            || self.extension != retained.record.extension()?
        {
            return Err(Error::Authentication);
        }
        if let Some(c) = &self.original_continuation {
            let own = continuation::load(retained)?
                .into_iter()
                .find(|entry| &entry.proposal.continuation == c)
                .ok_or(Error::RecoveryRequired)?;
            if own.admission.as_ref() != Some(&self.original_admission) {
                return Err(Error::Authentication);
            }
        }
        Ok(())
    }
}
fn commit_domain(retained: &RetainedBornManualRosterEnrollmentV2) -> Result<Vec<u8>> {
    let mut bytes = b"wholepact:born-manual-roster-enrollment-commit:v2\0".to_vec();
    bytes.extend_from_slice(retained.record.reference()?.as_bytes());
    Ok(bytes)
}
pub(super) fn read_commit(
    retained: &RetainedBornManualRosterEnrollmentV2,
) -> Result<BornManualRosterCommitV2> {
    let bytes = retained.account.directory.read(ROSTER_COMMIT, MAX_INTENT)?;
    let plain = vault::decrypt(
        &retained.account.encryption_key,
        &commit_domain(retained)?,
        &bytes,
    )?;
    let commit: BornManualRosterCommitV2 =
        serde_json::from_slice(&plain).map_err(|_| Error::InvalidData)?;
    commit.validate_for(retained)?;
    Ok(commit)
}
pub(super) fn require_retained_admission(
    retained: &RetainedBornManualRosterEnrollmentV2,
    witness: &AuthenticatedBornManualRosterEnrollmentV2,
) -> Result<()> {
    let original = read_commit(retained)?;
    if let Some(c) = witness.continuation() {
        let own = continuation::load(retained)?
            .into_iter()
            .find(|entry| &entry.proposal.continuation == c)
            .ok_or(Error::RecoveryRequired)?;
        if own.admission.as_ref() != Some(witness.record()) {
            return Err(Error::Authentication);
        }
    } else if original.original_continuation.is_some()
        || &original.original_admission != witness.record()
    {
        return Err(Error::Authentication);
    }
    Ok(())
}

/// Concrete private journal publication owner, only constructed after consuming
/// an actual native decision while retaining the actual witness and source.
pub(crate) struct BornRosterEnrollmentPublicationV2<'a> {
    prepared: &'a PreparedBornManualRosterPublicationV2,
    _native: crate::native_ui::NativePublicationLease<'a>,
}
impl BornRosterEnrollmentPublicationV2<'_> {
    pub(crate) fn check_current(&self) -> Result<()> {
        self.prepared.check()
    }
    pub(crate) fn journal_path(&self) -> PathBuf {
        self.prepared
            .retained
            .account
            .directory
            .root()
            .join(JOURNAL)
    }
    pub(crate) fn journal_source_owner(
        &self,
    ) -> Result<Arc<crate::consent_journal::SignerJournalSourceOwner>> {
        self.prepared
            .retained
            .account
            .directory
            .signer_journal_source_owner()
    }
    pub(crate) fn journal_key(&self) -> DatabaseKey {
        DatabaseKey::from_bytes(*self.prepared.retained.journal_key)
    }
    pub(crate) fn genesis(&self) -> &AccountUseGenesis {
        &self.prepared.retained.record.account_record.genesis
    }
    pub(crate) fn writer_epoch(&self) -> u64 {
        self.prepared
            .retained
            .record
            .account_record
            .terms
            .signer
            .writer_epoch
    }
    pub(crate) fn intent_digest(&self) -> &str {
        &self.prepared.retained.intent_digest
    }
}

pub(crate) struct BornManualRosterEnrolledSignerV2 {
    pub(super) retained: RetainedBornManualRosterEnrollmentV2,
    pub(super) journal: Arc<SignerConsentJournal>,
    pub(super) history: ReconciledAuthorityHistory,
    pub(super) witness: AuthenticatedBornManualRosterEnrollmentV2,
    pub(super) source: NativeAuthorityBinding,
    pub(super) peer: AuthenticatedPeer,
}
impl BornManualRosterEnrolledSignerV2 {
    pub(crate) fn record(&self) -> &BornManualRosterEnrollmentRecordV2 {
        &self.retained.record
    }
    pub(crate) fn check_current_publication(&self) -> Result<()> {
        self.source.check_current()?;
        self.peer.check_current()?;
        self.retained.check()?;
        require_retained_admission(&self.retained, &self.witness)?;
        self.journal.check_initial_born_owner(
            &self.retained.record.account_record.genesis,
            self.retained
                .record
                .account_record
                .terms
                .signer
                .writer_epoch,
        )?;
        check_history(&self.retained, &self.history, &self.witness)
    }
    pub(crate) fn require_host_owner(
        &self,
        peer: &AuthenticatedPeer,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<()> {
        owner.check_current()?;
        owner.native().binding().bounded_deadline()?;
        self.check_current_publication()?;
        peer.check_current()?;
        if self.source != owner.native().binding()
            || peer.native_origin != self.source
            || peer.grant_id != self.peer.grant_id
            || peer.scope != self.peer.scope
        {
            return Err(Error::Authentication);
        }
        peer.peer.same_live_process(&self.peer.peer)?;
        Ok(())
    }
    pub(crate) fn host_roster_enrollment_evidence(
        &self,
        request: &HostManualRosterPublicationRequestV2,
        peer: &AuthenticatedPeer,
        owner: &PendingAccountNativeAuthority,
        reviewed_digest: &str,
    ) -> Result<ManualRosterEnrollmentEvidenceV2> {
        self.require_host_owner(peer, owner)?;
        request
            .require_original(&self.retained.record.request()?)
            .map_err(|_| Error::ReviewMismatch)?;
        if request.attempt != actual_attempt(&self.witness)?
            || !is_hash(reviewed_digest)
            || peer.scope.manifest_digest != request.digest().map_err(|_| Error::InvalidData)?
        {
            return Err(Error::ReviewMismatch);
        }
        let e = self.witness.extension();
        let admission = self.witness.record();
        let snapshot = self.witness.snapshot();
        let session = self.witness.session();
        let audit = original(&self.retained.account)?
            .anchor()
            .audit_original_roster_preconstruction_witness_link(
                &self.history,
                &self.retained.record.extension()?,
            )?;
        let evidence = ManualRosterEnrollmentEvidenceV2 {
            version: 2,
            request: request.clone(),
            enrollment_ref: e.account_extension.enrollment_ref.clone(),
            signer_roster_record_digest: self.retained.record.reference()?,
            witness_roster_extension_digest: e.digest().map_err(|_| Error::InvalidData)?,
            witness_extension_digest: e
                .account_extension
                .digest()
                .map_err(|_| Error::InvalidData)?,
            witness_extension_sequence: e.account_extension.sequence,
            witness_extension_predecessor_digest: e.account_extension.predecessor_digest.clone(),
            admission: DurableManualRosterAdmissionV2 {
                version: 2,
                exact_request_digest: request.digest().map_err(|_| Error::InvalidData)?,
                signer_intent_digest: self.retained.intent_digest.clone(),
                witness_admission_digest: admission
                    .digest_for(e, self.witness.continuation())
                    .map_err(|_| Error::InvalidData)?,
                attempt_digest: admission.request.attempt_digest.clone(),
                attempt_sequence: admission.request.attempt_sequence,
                admitted_at_ms: admission.admitted_at_ms,
                admission_deadline_ms: admission.publication_expires_at_ms,
            },
            current: ManualCurrentState {
                writer_certificate_digest: session.writer_certificate_digest.clone(),
                writer_epoch: snapshot.writer_epoch,
                writer_session_digest: canonical(
                    "wholepact:born-manual-writer-session:v1",
                    session,
                )?,
                writer_session_expires_at_ms: session.expires_at_ms,
                witness_head_sequence: snapshot.head.sequence,
                witness_head_digest: snapshot.head.digest.clone(),
                complete_history_digest: self
                    .history
                    .history_digest()
                    .map_err(|_| Error::InvalidData)?,
                exclusion_checkpoint_digest: canonical(
                    "wholepact:born-manual-exclusion-checkpoint:v1",
                    audit.checkpoint(),
                )?,
                native_review_digest: reviewed_digest.into(),
            },
        };
        evidence.validate().map_err(|_| Error::InvalidData)?;
        self.require_host_owner(peer, owner)?;
        Ok(evidence)
    }
}
