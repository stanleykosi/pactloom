//! Fresh coordinated session/record staging from the actual paired source.
//! Historical rows select terms only; every candidate gets a NEW live nonce.
//! This private child never manufactures a NativeDecision or imports a receipt.
use super::*;
use crate::ipc::CoordinatedPairPeerV1;

pub(crate) struct CoordinatedPreconstructionSessionV1 {
    session: SignerConsentSession,
    peer: CoordinatedPairPeerV1,
    historical_enrollment: AccountEnrollmentRecord,
    historical_manifest: AcceptedManifestRecord,
    source_expires_at_ms: u64,
    receipt_progress: CoordinatedReceiptProgressV1,
}

// Private one-attempt state. No historical row or externally supplied record
// can manufacture evidence of the original successful Enrollment commit.
enum CoordinatedReceiptProgressV1 {
    Fresh,
    Enrollment(AccountEnrollmentRecord),
    Consumed,
}
impl CoordinatedReceiptProgressV1 {
    fn begin_enrollment(&mut self) -> Result<()> {
        if matches!(std::mem::replace(self, Self::Consumed), Self::Fresh) {
            Ok(())
        } else {
            Err(JournalError::Permission)
        }
    }
    fn begin_manifest(&mut self, expected: &AccountEnrollmentRecord) -> Result<AccountEnrollmentRecord> {
        match std::mem::replace(self, Self::Consumed) {
            Self::Enrollment(record) if &record == expected => Ok(record),
            _ => Err(JournalError::Permission),
        }
    }
}

/// Accepted identity/provenance only. This is not a live receipt, permission,
/// action, serializable record or cloneable capability. Only the successful
/// original Manifest commit below can mint it, after BOTH original approvals.
pub(crate) struct CoordinatedAcceptedProvenanceV1 {
    session: Arc<SessionInner>,
    generation: u64,
    enrollment: AccountEnrollmentRecord,
    manifest: AcceptedManifestRecord,
    peer: CoordinatedPairPeerV1,
    source_expires_at_ms: u64,
}
impl CoordinatedAcceptedProvenanceV1 {
    pub(in crate::consent_journal) fn require_lease(
        &self,
        lease: &ReadLease<'_>,
        enrollment: &AccountEnrollmentRecord,
        manifest: &AcceptedManifestRecord,
    ) -> Result<()> {
        // The record lease already holds this exact session read guard. Never
        // recursively acquire it while a revocation writer may be queued.
        require_accepted_identity(&self.session, self.generation, lease,
            enrollment, manifest, &self.enrollment, &self.manifest, self.source_expires_at_ms)?;
        self.session.coordinated_peer.as_ref()
            .ok_or(JournalError::Permission)?
            .require_same_grant(&self.peer).map_err(|_| JournalError::Permission)?;
        lease.check_current()
    }

    pub(in crate::consent_journal) fn require_session_metadata(&self, session: &SignerConsentSession) -> Result<()> {
        let lease = ReadLease {
            _guard: session.inner.read()?,
            principal: &session.inner.principal_id,
            session: &session.inner,
        };
        self.require_held_session(&lease)
    }
    pub(in crate::consent_journal) fn require_held_session(&self, lease: &ReadLease<'_>) -> Result<()> {
        self.require_lease(lease, &self.enrollment, &self.manifest)
    }

    pub(in crate::consent_journal) fn require_record_references(&self, enrollment: &str, manifest: &str) -> Result<()> {
        if enrollment != self.enrollment.reference() || manifest != self.manifest.reference() {
            return Err(JournalError::Permission);
        }
        Ok(())
    }

    pub(in crate::consent_journal) fn require_pair_facts(
        &self, source: &str, grant: &str, key: &str, channel: &str,
        generation: u64, session: &str, enrollment: &str, manifest: &str,
    ) -> Result<()> {
        require_accepted_pair_identity(
            (self.peer.source_identity(), self.peer.grant_id(), self.peer.key_digest(),
             self.peer.channel_digest(), self.peer.generation(), &self.session.session_id,
             self.enrollment.reference(), self.manifest.reference()),
            (source, grant, key, channel, generation, session, enrollment, manifest),
        )
    }
}

// A pure equality kernel, not an authority constructor. The expected side is
// always assembled by the nominal token from its retained original peer.
fn require_accepted_pair_identity(
    expected: (&str, &str, &str, &str, u64, &str, &str, &str),
    actual: (&str, &str, &str, &str, u64, &str, &str, &str),
) -> Result<()> {
    if actual != expected { return Err(JournalError::Permission); }
    Ok(())
}

// Pure identity/current-session restriction shared by the nominal token and
// maintained tests. It cannot construct a token or authorize any purpose.
fn require_accepted_identity(
    session: &Arc<SessionInner>, generation: u64, lease: &ReadLease<'_>,
    enrollment: &AccountEnrollmentRecord, manifest: &AcceptedManifestRecord,
    expected_enrollment: &AccountEnrollmentRecord, expected_manifest: &AcceptedManifestRecord,
    source_expires_at_ms: u64,
) -> Result<()> {
        lease.check_current()?;
        if !std::ptr::eq(lease.session, Arc::as_ptr(session))
            || lease._guard.generation != generation
            || enrollment != expected_enrollment
            || manifest != expected_manifest
            || enrollment.account_id() != session.account_id
            || enrollment.principal_id() != session.principal_id
            || manifest.terms.account_id != session.account_id
            || manifest.terms.principal_id != session.principal_id
            || manifest.enrollment_ref() != enrollment.reference()
        {
            return Err(JournalError::Permission);
        }
        let now = now_ms()?;
        if now >= source_expires_at_ms {
            return Err(JournalError::Expired);
        }
        for receipt in [enrollment.receipt(), manifest.receipt()] {
            if now < receipt.reviewed_at_ms() {
                return Err(JournalError::Expired);
            }
            // Accepted nonces remain immutable identity. This intentionally
            // neither renews nor consumes an expired generic receipt.
            if receipt.native_session_id != session.session_id
                || receipt.permission_generation != generation
                || receipt.writer_epoch != session.writer_epoch
                || receipt.trusted_launch_measurement != session.measurement
            {
                return Err(JournalError::Permission);
            }
        }
    Ok(())
}

fn require_live_receipt_pair(
    lease: &ReadLease<'_>, enrollment: &AccountEnrollmentRecord, manifest: &AcceptedManifestRecord,
) -> Result<()> {
    if manifest.enrollment_ref() != enrollment.reference() {
        return Err(JournalError::InvalidBinding);
    }
    lease.require_spending_decision(enrollment.receipt())?;
    lease.require_spending_decision(manifest.receipt())
}

pub(crate) struct PreparedCoordinatedEnrollmentV1 {
    pending: Pending<AccountEnrollmentRecord>,
    historical_enrollment_ref: String,
    historical_manifest_ref: String,
}
pub(crate) struct PreparedCoordinatedManifestV1 {
    pending: Pending<AcceptedManifestRecord>,
    enrollment: AccountEnrollmentRecord,
}
impl CoordinatedPreconstructionSessionV1 {
    // Internal nominal constructor: a DTO, socket path, PID or historical
    // transport record cannot provide this actual authenticated PairPeer.
    pub(crate) fn from_original_pair(
        binding: crate::account::birth::enrollment::roster_v2::durable_entry_v1::CoordinatedSourceReceiptBindingV1,
    ) -> Result<Self> {
        let (journal, historical, manifest, peer, source_expires_at_ms) = binding
            .into_session_parts()
            .map_err(|_| JournalError::Permission)?;
        peer.check_current().map_err(|_| JournalError::Permission)?;
        historical.validate()?;
        let proposal = manifest.proposal()?;
        if peer.scope().account_id != historical.account_id()
            || peer.scope().participant_id != historical.participant_id()
            || peer.scope().agreement_id != historical.agreement_id()
            || peer.scope().manifest_digest != proposal.manifest_digest()
            || manifest.enrollment_ref() != historical.reference()
            || !peer.scope().history_read
            || !peer.scope().preconstruction_export
            || peer.scope().authorization_export
        {
            return Err(JournalError::Permission);
        }
        let measurement = peer.common_image_measurement().to_owned();
        hash(&measurement)?;
        let session = SignerConsentSession {
            inner: Arc::new(SessionInner {
                journal,
                account_id: historical.account_id().into(),
                principal_id: format!("local-owner-uid-{}", unsafe { libc::geteuid() }),
                writer_epoch: historical.receipt().writer_epoch(),
                measurement,
                session_id: random_id()?,
                created: Instant::now(),
                issued_receipts: Mutex::new(std::collections::BTreeMap::new()),
                native_origin: None,
                native_peer: None,
                coordinated_peer: Some(peer.clone()),
                state: RwLock::new(SessionState {
                    current: true,
                    generation: 1,
                }),
            }),
        };
        let result = Self {
            session,
            peer,
            historical_enrollment: historical,
            historical_manifest: manifest,
            source_expires_at_ms,
            receipt_progress: CoordinatedReceiptProgressV1::Fresh,
        };
        result.check_current()?;
        Ok(result)
    }
    pub(crate) fn check_current(&self) -> Result<()> {
        self.peer
            .check_current()
            .map_err(|_| JournalError::Permission)?;
        let state = self.session.inner.read()?;
        let retained = self
            .session
            .inner
            .coordinated_peer
            .as_ref()
            .ok_or(JournalError::Permission)?;
        retained
            .require_same_grant(&self.peer)
            .map_err(|_| JournalError::Permission)?;
        drop(state);
        Ok(())
    }
    pub(crate) fn stage_enrollment(&self) -> Result<PreparedCoordinatedEnrollmentV1> {
        let historical = &self.historical_enrollment;
        let manifest = &self.historical_manifest;
        self.check_current()?;
        historical.validate()?;
        let proposal = manifest.proposal()?;
        if historical.account_id() != self.session.inner.account_id
            || historical.participant_id() != self.peer.scope().participant_id
            || historical.agreement_id() != self.peer.scope().agreement_id
            || proposal.manifest_digest() != self.peer.scope().manifest_digest
            || manifest.enrollment_ref() != historical.reference()
        {
            return Err(JournalError::InvalidBinding);
        }
        let mut terms = historical.terms.clone();
        terms.principal_id = self.session.inner.principal_id.clone();
        terms.transport = TransportIdentityBinding::LocalProcess {
            transport_identity_id: self.peer.grant_id().into(),
            channel_key_digest: self.peer.key_digest().into(),
            channel_binding_digest: self.peer.channel_digest().into(),
            uid: self.peer.actual_peer().uid(),
            pid: self.peer.actual_peer().pid(),
            process_instance: self.peer.actual_peer().instance().into(),
            signer_generation: self.peer.generation(),
            account_id: self.peer.scope().account_id.clone(),
            agreement_id: self.peer.scope().agreement_id.clone(),
            participant_id: self.peer.scope().participant_id.clone(),
            manifest_digest: self.peer.scope().manifest_digest.clone(),
        };
        terms.receipt = self.fresh_bounded_receipt()?;
        let record = AccountEnrollmentRecord::new(terms)?;
        self.check_current()?;
        Ok(PreparedCoordinatedEnrollmentV1 {
            pending: Pending::new(
                record.clone(),
                record.reference.clone(),
                &self.session.inner,
            ),
            historical_enrollment_ref: historical.reference().into(),
            historical_manifest_ref: manifest.reference().into(),
        })
    }
    pub(crate) fn stage_manifest(
        &self,
        current_enrollment: &AccountEnrollmentRecord,
    ) -> Result<PreparedCoordinatedManifestV1> {
        let proposal = self.historical_manifest.proposal()?;
        self.check_current()?;
        // The maintained validator requires this SAME session's nonce map;
        // replacing a historical receipt's visible fields cannot revive it.
        let state = self.session.inner.read()?;
        let lease = ReadLease {
            _guard: state,
            principal: &self.session.inner.principal_id,
            session: &self.session.inner,
        };
        lease.require_spending_decision(current_enrollment.receipt())?;
        drop(lease);
        let prepared = self
            .session
            .prepare_manifest(current_enrollment, &proposal)?;
        let mut terms = prepared.0.record.terms.clone();
        // Preserve the already issued nonce and timestamp; only restrict its
        // wall bound to the original paired channel, never renew either clock.
        let remaining = u64::try_from(
            self.peer
                .deadline()
                .saturating_duration_since(Instant::now())
                .as_millis(),
        )
        .map_err(|_| JournalError::Expired)?;
        terms.receipt.expires_at_ms = terms.receipt.expires_at_ms.min(
            now_ms()?
                .checked_add(remaining)
                .ok_or(JournalError::Expired)?,
        );
        terms.receipt.expires_at_ms = terms.receipt.expires_at_ms.min(self.source_expires_at_ms);
        let record = AcceptedManifestRecord::new(terms)?;
        let prepared = PreparedManifestAcceptance(Pending {
            review_digest: record.reference().into(),
            record,
            session: prepared.0.session,
            created: prepared.0.created,
        });
        self.check_current()?;
        Ok(PreparedCoordinatedManifestV1 {
            pending: prepared.0,
            enrollment: current_enrollment.clone(),
        })
    }
}
impl PreparedCoordinatedEnrollmentV1 {
    pub(crate) fn record(&self) -> &AccountEnrollmentRecord {
        &self.pending.record
    }
    pub(crate) fn historical_references(&self) -> (&str, &str) {
        (
            &self.historical_enrollment_ref,
            &self.historical_manifest_ref,
        )
    }
}
impl PreparedCoordinatedManifestV1 {
    pub(crate) fn record(&self) -> &AcceptedManifestRecord {
        &self.pending.record
    }
    pub(crate) fn enrollment(&self) -> &AccountEnrollmentRecord {
        &self.enrollment
    }
}

use crate::consent_journal::storage::CoordinatedReceiptActionV1;
use wholepact_financial_coordinator_origin::{SignerV3EnrollmentFinalV1, SignerV3ManifestFinalV1};
struct ApprovedCoordinatedEnrollmentV1 {
    approval: Approval<AccountEnrollmentRecord>,
    action: SignerV3EnrollmentFinalV1,
}
struct ApprovedCoordinatedManifestV1 {
    approval: Approval<AcceptedManifestRecord>,
    enrollment: AccountEnrollmentRecord,
    action: SignerV3ManifestFinalV1,
}
impl CoordinatedPreconstructionSessionV1 {
    fn fresh_bounded_receipt(&self) -> Result<NativeConsentReceipt> {
        self.check_current()?;
        let mut receipt = self.session.receipt()?;
        let remaining = u64::try_from(
            self.peer
                .deadline()
                .saturating_duration_since(Instant::now())
                .as_millis(),
        )
        .map_err(|_| JournalError::Expired)?;
        if remaining == 0 {
            return Err(JournalError::Expired);
        }
        receipt.expires_at_ms = receipt.expires_at_ms.min(
            now_ms()?
                .checked_add(remaining)
                .ok_or(JournalError::Expired)?,
        );
        receipt.expires_at_ms = receipt.expires_at_ms.min(self.source_expires_at_ms);
        receipt.validate()?;
        self.check_current()?;
        Ok(receipt)
    }
    pub(crate) fn require_current_receipts(
        &self,
        enrollment: &AccountEnrollmentRecord,
        manifest: &AcceptedManifestRecord,
    ) -> Result<()> {
        self.check_current()?;
        if manifest.enrollment_ref() != enrollment.reference() {
            return Err(JournalError::InvalidBinding);
        }
        let lease = ReadLease {
            _guard: self.session.inner.read()?,
            principal: &self.session.inner.principal_id,
            session: &self.session.inner,
        };
        require_live_receipt_pair(&lease, enrollment, manifest)?;
        drop(lease);
        self.check_current()
    }
    pub(crate) fn require_accepted_provenance(
        &self,
        accepted: &CoordinatedAcceptedProvenanceV1,
        enrollment: &AccountEnrollmentRecord,
        manifest: &AcceptedManifestRecord,
    ) -> Result<()> {
        self.check_current()?;
        let lease = ReadLease {
            _guard: self.session.inner.read()?,
            principal: &self.session.inner.principal_id,
            session: &self.session.inner,
        };
        accepted.require_lease(&lease, enrollment, manifest)?;
        drop(lease);
        self.check_current()
    }
    fn approve_enrollment(
        &self,
        value: PreparedCoordinatedEnrollmentV1,
        action: SignerV3EnrollmentFinalV1,
    ) -> Result<ApprovedCoordinatedEnrollmentV1> {
        self.check_current()?;
        action
            .check_current()
            .map_err(|_| JournalError::Permission)?;
        let f = action.facts();
        let record = &value.pending.record;
        let r = record.receipt();
        if !Arc::ptr_eq(&value.pending.session, &self.session.inner)
            || f.source_identity_digest != self.peer.source_identity()
            || f.pair_grant_id != self.peer.grant_id()
            || f.pair_key_digest != self.peer.key_digest()
            || f.pair_channel_digest != self.peer.channel_digest()
            || f.pair_generation != self.peer.generation()
            || f.record_reference != record.reference()
            || f.record_json
                != serde_json::to_string(record).map_err(|_| JournalError::InvalidBinding)?
            || f.coordinated_session_id != r.native_session_id()
            || f.receipt_nonce != r.nonce()
            || f.reviewed_at_ms != r.reviewed_at_ms()
            || f.expires_at_ms != r.expires_at_ms()
            || f.historical_enrollment_ref != value.historical_enrollment_ref
            || f.historical_manifest_ref != value.historical_manifest_ref
            || value.pending.created.elapsed() >= Duration::from_secs(120)
        {
            return Err(JournalError::Permission);
        }
        let pending = value.pending;
        Ok(ApprovedCoordinatedEnrollmentV1 {
            approval: Approval {
                record: pending.record,
                session: pending.session,
                created: pending.created,
            },
            action,
        })
    }
    fn approve_manifest(
        &self,
        value: PreparedCoordinatedManifestV1,
        action: SignerV3ManifestFinalV1,
    ) -> Result<ApprovedCoordinatedManifestV1> {
        self.check_current()?;
        action
            .check_current()
            .map_err(|_| JournalError::Permission)?;
        let f = action.facts();
        let record = &value.pending.record;
        let r = record.receipt();
        if !Arc::ptr_eq(&value.pending.session, &self.session.inner)
            || f.source_identity_digest != self.peer.source_identity()
            || f.pair_grant_id != self.peer.grant_id()
            || f.pair_key_digest != self.peer.key_digest()
            || f.pair_channel_digest != self.peer.channel_digest()
            || f.pair_generation != self.peer.generation()
            || f.record_reference != record.reference()
            || f.record_json
                != serde_json::to_string(record).map_err(|_| JournalError::InvalidBinding)?
            || f.coordinated_session_id != r.native_session_id()
            || f.receipt_nonce != r.nonce()
            || f.reviewed_at_ms != r.reviewed_at_ms()
            || f.expires_at_ms != r.expires_at_ms()
            || f.current_enrollment_ref != value.enrollment.reference()
            || value.pending.created.elapsed() >= Duration::from_secs(120)
        {
            return Err(JournalError::Permission);
        }
        let pending = value.pending;
        Ok(ApprovedCoordinatedManifestV1 {
            approval: Approval {
                record: pending.record,
                session: pending.session,
                created: pending.created,
            },
            enrollment: value.enrollment,
            action,
        })
    }
    pub(crate) fn commit_enrollment(
        &mut self,
        journal: &SignerConsentJournal,
        pin: PreparedDeliveryJournalRevisionV3,
        prepared: PreparedCoordinatedEnrollmentV1,
        action: SignerV3EnrollmentFinalV1,
    ) -> Result<(AccountEnrollmentRecord, Result<PreparedDeliveryJournalRevisionV3>)> {
        // Consume before any attempted effect. Failure/uncertainty cannot
        // restore a receipt approval or permit a second publication attempt.
        self.receipt_progress.begin_enrollment()?;
        let ApprovedCoordinatedEnrollmentV1 {
            approval: a,
            action,
        } = self.approve_enrollment(prepared, action)?;
        let a = &a;
        let result = journal.with_coordinated_receipt_effect_v1(
            pin,
            CoordinatedReceiptActionV1::Enrollment(&action),
            |tx| {
                let account = storage::read_account(tx)?;
                let lease = a.lease(&journal.binding(), &account, a.record.receipt())?;
                action
                    .check_current()
                    .map_err(|_| JournalError::Permission)?;
                lease.require_spending_decision(a.record.receipt())?;
                if lease.principal != a.record.principal_id()
                    || account.account_id != a.record.account_id()
                    || storage::read_enrollment(tx, a.record.reference())?.is_some()
                {
                    return Err(JournalError::Conflict);
                }
                let raw = encode(&a.record)?;
                Ok(move |tx: &rusqlite::Transaction<'_>| {
                // Hold the validated session lease throughout the already-entered SQL effect.
                let _lease = lease;
                tx.execute(
                    "INSERT INTO signer_enrollments VALUES(?1,?2,?3,?4,?5)",
                    rusqlite::params![
                        a.record.reference(),
                        a.record.account_id(),
                        a.record.agreement_id(),
                        a.record.participant_id(),
                        raw.as_str()
                    ],
                )?;
                storage::bounded(tx, journal.capacity_limits())?;
                Ok(a.record.clone())
                })
            },
        )?;
        let (record, pin) = result;
        let pin = pin.and_then(|pin| {
            action.finish_review().map_err(|_| JournalError::Permission)?;
            self.receipt_progress = CoordinatedReceiptProgressV1::Enrollment(record.clone());
            Ok(pin)
        });
        Ok((record, pin))
    }
    pub(crate) fn commit_manifest(
        &mut self,
        journal: &SignerConsentJournal,
        pin: PreparedDeliveryJournalRevisionV3,
        prepared: PreparedCoordinatedManifestV1,
        action: SignerV3ManifestFinalV1,
    ) -> Result<(AcceptedManifestRecord, Result<(PreparedDeliveryJournalRevisionV3, CoordinatedAcceptedProvenanceV1)>)> {
        let accepted_enrollment = self.receipt_progress.begin_manifest(&prepared.enrollment)?;
        let ApprovedCoordinatedManifestV1 {
            approval: a,
            enrollment: expected,
            action,
        } = self.approve_manifest(prepared, action)?;
        let a = &a;
        let result = journal.with_coordinated_receipt_effect_v1(pin, CoordinatedReceiptActionV1::Manifest(&action), |tx| {
            let account = storage::read_account(tx)?;
            let lease = a.lease(&journal.binding(), &account, a.record.receipt())?;
            action.check_current().map_err(|_| JournalError::Permission)?;
            let enrollment = storage::read_enrollment(tx, a.record.enrollment_ref())?.ok_or(JournalError::NotFound)?;
            let proposal = a.record.proposal()?;
            if enrollment != expected || lease.principal != enrollment.principal_id()
                || account.account_id != enrollment.account_id() || a.record.terms.account_id != enrollment.account_id()
                || a.record.terms.principal_id != enrollment.principal_id()
                || proposal.manifest().agreement.agreement_id != enrollment.agreement_id()
                || proposal.manifest().agreement.network_profile_id != enrollment.terms.network_profile_id
                || !proposal.manifest().participants.iter().any(|p| p.account_id == enrollment.account_id() && p.participant_id == enrollment.participant_id())
                || !storage::same_native_origin(enrollment.receipt(),a.record.receipt()) {
                return Err(JournalError::InvalidBinding);
            }
            enrollment.transport().validate_scope(enrollment.account_id(), enrollment.agreement_id(), enrollment.participant_id(),Some(proposal.manifest_digest()))?;
            lease.require_spending_decision(enrollment.receipt())?;
            lease.require_spending_decision(a.record.receipt())?;
            if storage::read_manifest(tx, a.record.reference())?.is_some() { return Err(JournalError::Conflict); }
            let exists: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM signer_accepted_manifests WHERE enrollment_ref=?1 AND proposal_id=?2)",rusqlite::params![a.record.enrollment_ref(),proposal.input().proposal_id],|r|r.get(0))?;
            if exists { return Err(JournalError::Conflict); }
            let raw = encode(&a.record)?;
            Ok(move |tx: &rusqlite::Transaction<'_>| {
            let _lease = lease;
            tx.execute("INSERT INTO signer_accepted_manifests VALUES(?1,?2,?3,?4,?5)",rusqlite::params![a.record.reference(),a.record.enrollment_ref(),proposal.input().proposal_id,a.record.proposal_digest(),raw.as_str()])?;
            storage::bounded(tx,journal.capacity_limits())?;
            Ok(a.record.clone())
            })
        })?;
        let (record, pin) = result;
        let pin = pin.and_then(|pin| {
            action.finish_review().map_err(|_| JournalError::Permission)?;
            // This NEW nominal handoff is issued only while BOTH unchanged
            // original120 receipt predicates still hold. A late failure keeps
            // the actual committed record above, but mints no provenance.
            self.require_current_receipts(&accepted_enrollment, &record)?;
            let generation = self.session.inner.read()?.generation;
            let accepted = CoordinatedAcceptedProvenanceV1 {
                session: Arc::clone(&self.session.inner),
                generation,
                enrollment: accepted_enrollment,
                manifest: record.clone(),
                peer: self.peer.clone(),
                source_expires_at_ms: self.source_expires_at_ms,
            };
            Ok((pin, accepted))
        });
        Ok((record, pin))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn synthetic_session() -> SignerConsentSession {
        SignerConsentSession {
            inner: Arc::new(SessionInner {
                journal: SignerJournalBinding(Arc::new(())),
                account_id: "test-account".into(),
                principal_id: "test-principal".into(),
                writer_epoch: 1,
                measurement: "11".repeat(32),
                session_id: random_id().unwrap(),
                created: Instant::now(),
                issued_receipts: Mutex::new(Default::default()),
                native_origin: None,
                native_peer: None,
                coordinated_peer: None,
                state: RwLock::new(SessionState {
                    current: true,
                    generation: 1,
                }),
            }),
        }
    }
    fn accepts(session: &SignerConsentSession, receipt: &NativeConsentReceipt) -> bool {
        let lease = ReadLease {
            _guard: session.inner.read().unwrap(),
            principal: &session.inner.principal_id,
            session: &session.inner,
        };
        lease.require_spending_decision(receipt).is_ok()
    }
    #[test]
    fn coordinated_fresh_receipt_rejects_historical_session() {
        let old = synthetic_session();
        let new = synthetic_session();
        let receipt = old.receipt().unwrap();
        assert!(accepts(&old, &receipt));
        assert!(!accepts(&new, &receipt));
    }
    #[test]
    fn coordinated_fresh_receipt_visible_session_relabel_cannot_mint_nonce() {
        let old = synthetic_session();
        let new = synthetic_session();
        let mut receipt = old.receipt().unwrap();
        receipt.native_session_id = new.inner.session_id.clone();
        assert!(!accepts(&new, &receipt));
    }
    #[test]
    fn coordinated_fresh_receipt_original_monotonic_window_cannot_renew() {
        let session = synthetic_session();
        let mut receipt = session.receipt().unwrap();
        *session
            .inner
            .issued_receipts
            .lock()
            .unwrap()
            .get_mut(&receipt.nonce)
            .unwrap() = Instant::now() - Duration::from_secs(121);
        receipt.reviewed_at_ms = now_ms().unwrap();
        receipt.expires_at_ms = receipt.reviewed_at_ms + 120_000;
        assert!(!accepts(&session, &receipt));
    }
}

fn pending_deadline<T>(pending: &Pending<T>, nonce: &str) -> Result<Instant> {
    let state = pending.session.read()?;
    let issued = pending
        .session
        .issued_receipts
        .lock()
        .map_err(|_| JournalError::Permission)?;
    let issued_at = *issued.get(nonce).ok_or(JournalError::Permission)?;
    let peer = pending
        .session
        .coordinated_peer
        .as_ref()
        .ok_or(JournalError::Permission)?;
    peer.check_current().map_err(|_| JournalError::Permission)?;
    let deadline = issued_at
        .checked_add(Duration::from_secs(120))
        .ok_or(JournalError::Expired)?
        .min(peer.deadline());
    if Instant::now() >= deadline {
        return Err(JournalError::Expired);
    }
    drop(state);
    Ok(deadline)
}
impl PreparedCoordinatedEnrollmentV1 {
    pub(crate) fn original_review_deadline(&self) -> Result<Instant> {
        pending_deadline(&self.pending, self.record().receipt().nonce())
    }
}
impl PreparedCoordinatedManifestV1 {
    pub(crate) fn original_review_deadline(&self) -> Result<Instant> {
        pending_deadline(&self.pending, self.record().receipt().nonce())
    }
}

impl CoordinatedPreconstructionSessionV1 {
    pub(crate) fn acquire_construction_records<'a>(&'a self, journal: &'a SignerConsentJournal,
        enrollment: &str, manifest: &str, accepted: &'a CoordinatedAcceptedProvenanceV1,
        action: CoordinatedConstructionActionV1<'a>,
    ) -> Result<CoordinatedPurposeRecordLease<'a>> {
        self.check_current()?;
        self.require_accepted_provenance(accepted, &accepted.enrollment, &accepted.manifest)?;
        journal.acquire_coordinated_preconstruction_records(enrollment,manifest,&self.session,accepted,action)
    }
}
impl CoordinatedPreconstructionSessionV1 {
    /// Observation of the SAME live nonce clocks, never receipt renewal.
    pub(crate) fn current_receipt_deadline(&self,enrollment:&AccountEnrollmentRecord,manifest:&AcceptedManifestRecord)->Result<Instant>{
        self.require_current_receipts(enrollment,manifest)?;
        let issued=self.session.inner.issued_receipts.lock().map_err(|_|JournalError::Permission)?;
        let a=issued.get(enrollment.receipt().nonce()).ok_or(JournalError::Permission)?.checked_add(Duration::from_secs(120)).ok_or(JournalError::Expired)?;
        let b=issued.get(manifest.receipt().nonce()).ok_or(JournalError::Permission)?.checked_add(Duration::from_secs(120)).ok_or(JournalError::Expired)?;
        Ok(a.min(b).min(self.peer.deadline()))
    }
}

#[cfg(test)]
#[path = "coordinated_preconstruction_v1/handoff_security_tests.rs"]
mod handoff_security_tests;
