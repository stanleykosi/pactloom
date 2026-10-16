//! Read-only complete continuity at the surviving signer. This freezes local
//! authority for one short inventory inspection; it never changes the signer writer.
use super::*;
use crate::authority_bridge::{
    disclosure::RetainedWitnessDisclosure,
    protocol::{AuthorizationDeliveryScope, RetainedWitnessPermit},
};
use rusqlite::Connection;
use std::sync::RwLockWriteGuard;
use wholepact_authority::{
    AuthenticatedWriterSession, AuthorityHead, ReconciledAuthorityHistory, ReservationPermit,
    ReserveAuthorization, WitnessDisclosureDescriptor, WriterSessionReceipt,
};

pub(crate) struct HostContinuityRecordLease<'a> {
    permission: authority::ReadLease<'a>,
    // Exclusive to prevent new originals while the complete exposure inventory
    // is consumed. try_write avoids waiting behind an existing retained lease.
    _fence: RwLockWriteGuard<'a, ()>,
}
impl HostContinuityRecordLease<'_> {
    pub(crate) fn check_current(&self) -> Result<()> {
        self.permission.check_current()
    }
    pub(crate) fn require_native_origin(
        &self,
        origin: &crate::native_ui::NativeAuthorityBinding,
    ) -> Result<()> {
        self.permission.require_native_origin(origin)
    }
}
impl SignerConsentJournal {
    pub(crate) fn acquire_host_recovery_continuity<'a>(
        &'a self,
        session: &'a SignerConsentSession,
        history: &ReconciledAuthorityHistory,
        active: &AuthenticatedWriterSession,
    ) -> Result<HostContinuityRecordLease<'a>> {
        let account = self.account_state()?;
        if account.recovery_required {
            return Err(JournalError::RecoveryRequired);
        }
        let permission = session.read_lease(&self.binding(), &account)?;
        let fence = self
            .authority_fence
            .try_write()
            .map_err(|_| JournalError::Permission)?;
        let c = self.connection.lock().map_err(|_| JournalError::Database)?;
        storage::check_account(&c, &account)?;
        storage::bounded(&c, self.capacity_limits())?;
        if active.snapshot() != history.snapshot()
            || active.disclosure() != history.disclosure()
            || active.history_digest()
                != history
                    .history_digest()
                    .map_err(|_| JournalError::InvalidBinding)?
            || active.snapshot().account_id != account.account_id
            || active.snapshot().writer_epoch != account.writer_epoch
            || active.observation_age() >= std::time::Duration::from_secs(30)
            || active.receipt().expires_at_ms <= now_ms()?
            || active.snapshot().active_writer_session.as_ref() != Some(active.receipt())
            || active.snapshot().writer_status != wholepact_authority::WriterStatus::Active
        {
            return Err(JournalError::InvalidBinding);
        }
        validate_live_continuity(&c, history)?;
        let held = HostContinuityRecordLease {
            permission,
            _fence: fence,
        };
        held.check_current()?;
        Ok(held)
    }
}
fn validate_live_continuity(c: &Connection, history: &ReconciledAuthorityHistory) -> Result<()> {
    offline_history::require_legacy_journal(c)?;
    let permits = history
        .permits()
        .map_err(|_| JournalError::OfflineHistoryUnsupported)?;
    validate_online_continuity(c, history, permits)
}
// Only the complete v2 caller may supply its explicitly checked online branch.
// This function never publishes a filtered history inventory.
fn validate_online_continuity(
    c: &Connection,
    history: &ReconciledAuthorityHistory,
    permits: &[ReservationPermit],
) -> Result<()> {
    if !validate_online_continuity_cells(c, history, permits)? {
        return Err(JournalError::RecoveryRequired);
    }
    Ok(())
}

// Read-only semantic kernel. Returning whether these cells include a pin is
// deliberately separate from ownership: ordinary continuity above still
// requires it, while the restrictive born path has its actual immutable source.
pub(super) fn validate_online_continuity_cells(
    c: &Connection,
    history: &ReconciledAuthorityHistory,
    permits: &[ReservationPermit],
) -> Result<bool> {
    let descriptor = history.disclosure();
    let mut pinned = false;
    let mut q = c.prepare("SELECT disclosure,head_sequence,head_digest,writer_epoch,payload FROM signer_writer_reconciliations")?;
    let rows = q.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, u64>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, u64>(3)?,
            r.get::<_, String>(4)?,
        ))
    })?;
    for row in rows {
        let (raw, sequence, head_digest, epoch, payload) = row?;
        let retained: WitnessDisclosureDescriptor = decode(raw)?;
        let (receipt, _native, _digest): (WriterSessionReceipt, NativeConsentReceipt, String) =
            decode(payload)?;
        if &retained != descriptor
            || receipt.disclosure != retained
            || receipt.writer_epoch != epoch
            || !history.contains_head(&AuthorityHead {
                sequence,
                digest: head_digest,
            })
            || !history.contains_head(&receipt.reconciled_head)
            || !history.contains_head(&receipt.acquired_head)
        {
            return Err(JournalError::Conflict);
        }
        pinned = true;
    }
    drop(q);
    let mut q = c.prepare(
        "SELECT authorization_id,original_consent_ref,request_payload FROM signer_bridge_requests",
    )?;
    let rows = q.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
        ))
    })?;
    for row in rows {
        let (authorization, original, raw) = row?;
        let (request, _delivery, disclosure): (
            ReserveAuthorization,
            AuthorizationDeliveryScope,
            Option<RetainedWitnessDisclosure>,
        ) = decode(raw)?;
        let permit = permits
            .iter()
            .find(|p| p.request.authorization_id == authorization)
            .ok_or(JournalError::RecoveryRequired)?;
        if permit.request != request
            || request.authorization_id != authorization
            || request.original_consent_ref != original
            || !history.contains_head(&request.expected_head)
        {
            return Err(JournalError::Conflict);
        }
        if let Some(disclosure) = disclosure {
            if &disclosure.descriptor != descriptor
                || disclosure.expected_head != request.expected_head
                || disclosure.original_consent_ref != request.original_consent_ref
            {
                return Err(JournalError::Conflict);
            }
            pinned = true;
        }
    }
    drop(q);
    let mut q =
        c.prepare("SELECT authorization_id,reference,payload FROM signer_original_consents")?;
    let rows = q.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
        ))
    })?;
    for row in rows {
        let (authorization, reference, raw) = row?;
        let original: OriginalSpendConsent = decode(raw)?;
        original.validate()?;
        if original.reference() != reference || original.terms().authorization_id != authorization {
            return Err(JournalError::Conflict);
        }
        let permit = permits
            .iter()
            .find(|p| p.request.authorization_id == authorization)
            .ok_or(JournalError::RecoveryRequired)?;
        let linked =
            storage::read_original(c, &authorization)?.ok_or(JournalError::RecoveryRequired)?;
        if linked.original_consent() != &original {
            return Err(JournalError::Conflict);
        }
        recovery_activation::validate_original_permit(&original, permit)?;
    }
    drop(q);
    let original_count: u64 =
        c.query_row("SELECT count(*) FROM signer_original_consents", [], |r| {
            r.get(0)
        })?;
    let release_count: u64 =
        c.query_row("SELECT count(*) FROM signer_release_intents", [], |r| {
            r.get(0)
        })?;
    if original_count != release_count {
        return Err(JournalError::Conflict);
    }
    let mut q=c.prepare("SELECT authorization_id,original_consent_ref,account_id,obligation_id,maximum_debit,payload FROM signer_remote_exposures")?;
    let rows = q.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, String>(4)?,
            r.get::<_, String>(5)?,
        ))
    })?;
    for row in rows {
        let (authorization, original, account, obligation, debit, raw) = row?;
        let permit: ReservationPermit = decode(raw)?;
        let request = &permit.request;
        if request.authorization_id != authorization
            || request.original_consent_ref != original
            || request.account_id != account
            || request.obligation_id != obligation
            || request.maximum_debit_zatoshis.to_string() != debit
            || !permits.contains(&permit)
        {
            return Err(JournalError::Conflict);
        }
        let mut inputs=c.prepare("SELECT account_id,nullifier FROM signer_remote_inputs WHERE authorization_id=?1 ORDER BY nullifier")?;
        let actual = inputs
            .query_map([&authorization], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let mut expected: Vec<_> = request
            .inputs
            .iter()
            .map(|i| (account.clone(), i.nullifier.clone()))
            .collect();
        expected.sort();
        if actual != expected {
            return Err(JournalError::Conflict);
        }
    }
    drop(q);
    let mut q = c.prepare("SELECT authorization_id,payload FROM signer_bridge_permits")?;
    let rows = q.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
    for row in rows {
        let (authorization, raw) = row?;
        let saved: RetainedWitnessPermit = decode(raw)?;
        if saved.descriptor().request.authorization_id != authorization
            || saved.witness_certificate_digest() != descriptor.pinned_server_certificate_digest
            || !permits.contains(saved.descriptor())
        {
            return Err(JournalError::Conflict);
        }
    }
    drop(q);
    let mut q = c.prepare("SELECT policy_key,version,payload FROM signer_sponsor_policy_events")?;
    let rows = q.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, u64>(1)?,
            r.get::<_, String>(2)?,
        ))
    })?;
    for row in rows {
        let (key, version, raw) = row?;
        let policy: NativeSponsorPolicyRecord = decode(raw)?;
        if policy.binding.policy_key != key
            || policy.binding.version != version
            || policy.witness.witness_id != descriptor.witness_id
            || policy.witness.policy_digest != descriptor.policy_digest
            || policy.witness.aggregate_budget_zatoshis
                != history.snapshot().aggregate_budget_zatoshis
        {
            return Err(JournalError::Conflict);
        }
    }
    drop(q);
    let mut q = c.prepare("SELECT authorization_id,payload FROM signer_automation_keyuse")?;
    let rows = q.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
    for row in rows {
        let (authorization, raw) = row?;
        let admission: wholepact_authority::AutomaticKeyUseAdmission = decode(raw)?;
        admission
            .matches_request(&admission.request)
            .map_err(|_| JournalError::InvalidBinding)?;
        if admission.reservation.request.authorization_id != authorization
            || admission.witness_id != descriptor.witness_id
            || admission.policy_digest != descriptor.policy_digest
            || !history.automatic_key_use_admissions().contains(&admission)
            || !history.contains_operation(&admission.request.operation_id)
            || !history.contains_head(&admission.committed_head)
            || !permits.contains(&admission.reservation)
        {
            return Err(JournalError::Conflict);
        }
    }
    drop(q);
    let mut q = c.prepare(
        "SELECT grant_id,revision,enrollment_ref,payload FROM signer_automation_grant_events",
    )?;
    let rows = q.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, u64>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
        ))
    })?;
    for row in rows {
        let (grant_id, revision, enrollment_ref, raw) = row?;
        let grant: NativeAutomationGrantRecord = decode(raw)?;
        grant.validate()?;
        if grant.binding.grant_id != grant_id
            || grant.binding.revision != revision
            || grant.enrollment_ref != enrollment_ref
            || grant.witness.witness_id != descriptor.witness_id
            || grant.witness.policy_digest != descriptor.policy_digest
            || grant.witness.aggregate_budget_zatoshis
                != history.snapshot().aggregate_budget_zatoshis
        {
            return Err(JournalError::Conflict);
        }
    }
    Ok(pinned)
}

/// Versioned complete audit hold. Construction still requires the real session,
/// native read grant, current authenticated writer and exclusive journal fence.
/// No saved DTO can construct this lease or authorize signing/publication.
pub(crate) struct HostContinuityRecordLeaseV2<'a> {
    held: HostContinuityRecordLease<'a>,
    journal: &'a SignerConsentJournal,
    account: SignerAccountState,
    history: crate::authority_bridge::host_recovery_ipc::v2::HostRecoveryHistoryV2,
}
impl HostContinuityRecordLeaseV2<'_> {
    pub(crate) fn history_v2(
        &self,
    ) -> &crate::authority_bridge::host_recovery_ipc::v2::HostRecoveryHistoryV2 {
        &self.history
    }
    pub(crate) fn require_native_origin(
        &self,
        origin: &crate::native_ui::NativeAuthorityBinding,
    ) -> Result<()> {
        self.held.require_native_origin(origin)
    }
    pub(crate) fn check_current(&self) -> Result<()> {
        self.held.check_current()?;
        let mut c = self
            .journal
            .connection
            .lock()
            .map_err(|_| JournalError::Database)?;
        let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)?;
        let current = writer_history::WriterLocalInventory::read(
            &tx,
            &self.account,
            self.journal.capacity_limits(),
        )?;
        if current.commitment() != self.history.complete_journal_digest {
            return Err(JournalError::Conflict);
        }
        self.held.check_current()?;
        tx.rollback()?;
        Ok(())
    }
}
impl SignerConsentJournal {
    pub(crate) fn acquire_host_recovery_continuity_v2<'a>(
        &'a self,
        session: &'a SignerConsentSession,
        history: &ReconciledAuthorityHistory,
        active: &AuthenticatedWriterSession,
    ) -> Result<HostContinuityRecordLeaseV2<'a>> {
        let account = self.account_state()?;
        if account.recovery_required {
            return Err(JournalError::RecoveryRequired);
        }
        let permission = session.read_lease(&self.binding(), &account)?;
        let fence = self
            .authority_fence
            .try_write()
            .map_err(|_| JournalError::Permission)?;
        let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
        let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)?;
        if active.snapshot() != history.snapshot()
            || active.disclosure() != history.disclosure()
            || active.history_digest()
                != history
                    .history_digest()
                    .map_err(|_| JournalError::InvalidBinding)?
            || active.snapshot().account_id != account.account_id
            || active.snapshot().writer_epoch != account.writer_epoch
            || active.observation_age() >= std::time::Duration::from_secs(30)
            || active.receipt().expires_at_ms <= now_ms()?
            || active.snapshot().active_writer_session.as_ref() != Some(active.receipt())
            || active.snapshot().writer_status != wholepact_authority::WriterStatus::Active
        {
            return Err(JournalError::InvalidBinding);
        }
        permission.check_current()?;
        let complete = read_complete_continuity(&tx, &account, self.capacity_limits(), history)?;
        permission.check_current()?;
        tx.rollback()?;
        drop(c);
        let held = HostContinuityRecordLeaseV2 {
            held: HostContinuityRecordLease {
                permission,
                _fence: fence,
            },
            journal: self,
            account,
            history: complete,
        };
        held.check_current()?;
        Ok(held)
    }
}
fn read_complete_continuity(
    c: &Connection,
    account: &SignerAccountState,
    limits: (u64, u64),
    history: &ReconciledAuthorityHistory,
) -> Result<crate::authority_bridge::host_recovery_ipc::v2::HostRecoveryHistoryV2> {
    // This financial-origin IPC schema cannot carry non-signing construction.
    // Refuse this projection without hiding the separate complete inventory.
    if history
        .manual_roster_construction_records_v2()
        .next()
        .is_some()
        || offline_reconciliation::common_context_history(history)?.is_some()
    {
        return Err(JournalError::ConstructionHistoryUnsupported);
    }
    read_financial_continuity_branch(c, account, limits, history)
}
// This partial branch is private and is only published inside an explicit
// complete v2 (construction denied) or v3 (construction preserved) envelope.
fn read_financial_continuity_branch(
    c: &Connection,
    account: &SignerAccountState,
    limits: (u64, u64),
    history: &ReconciledAuthorityHistory,
) -> Result<crate::authority_bridge::host_recovery_ipc::v2::HostRecoveryHistoryV2> {
    let local = writer_history::WriterLocalInventory::read(c, account, limits)?;
    local.require_all_online_originals_replayed(history)?;
    offline_receipts::validate_reconciled(c, &account.account_id, history)?;
    // Validate all authenticated enrollment bindings and every typed origin,
    // even though this audit path deliberately does not import any history.
    let _prepared = writer_history::PreparedWriterHistory::prepare(&local, history)?;
    let union = local.offline_history().reconcile_reservations(history)?;
    build_financial_continuity_branch(c, account, history, &local, &union)
}

/// Private branch renderer. Callers must validate the complete versioned source
/// before calling and retain it in their returned envelope. No native permission
/// or writer import is produced by this financial projection.
fn build_financial_continuity_branch(
    c: &Connection,
    account: &SignerAccountState,
    history: &ReconciledAuthorityHistory,
    local: &writer_history::WriterLocalInventory,
    union: &offline_reconciliation::OfflineReconciliationInventory<'_>,
) -> Result<crate::authority_bridge::host_recovery_ipc::v2::HostRecoveryHistoryV2> {
    use crate::authority_bridge::host_recovery_ipc::v2::*;
    union.require_retained_offline_coverage()?;
    let online: Vec<ReservationPermit> = union
        .witness_online_reservations()
        .iter()
        .map(|p| (*p).clone())
        .collect();
    validate_online_continuity(c, history, &online)?;
    let mut origins: Vec<HostRecoveryReservationOriginV2> = online
        .into_iter()
        .map(|permit| HostRecoveryReservationOriginV2::Online { permit })
        .collect();
    for origin in union.offline_origins() {
        let retained = origin.retained_history();
        let remote = match retained.and_then(|r| r.admission()) {
            None => None,
            Some(admission) => {
                let retained = retained.ok_or(JournalError::InvalidBinding)?;
                Some(RetainedOfflineRemoteV2 {
                    admission: admission.clone(),
                    policy: retained
                        .enrollment()
                        .ok_or(JournalError::InvalidBinding)?
                        .clone(),
                    provenance: retained
                        .provenance()
                        .ok_or(JournalError::InvalidBinding)?
                        .clone(),
                })
            }
        };
        let signature_knowledge = match origin.signature_knowledge() {
            OfflineSignatureKnowledge::HistoricalAdmissionSignatureUnknown => {
                OfflineSignatureKnowledgeV2::HistoricalAdmissionSignatureUnknown
            }
            OfflineSignatureKnowledge::OriginalConsentRetainedSignatureUnknown => {
                OfflineSignatureKnowledgeV2::OriginalConsentRetainedSignatureUnknown
            }
            OfflineSignatureKnowledge::LocalKeyUseStartedSignatureUnknown => {
                OfflineSignatureKnowledgeV2::LocalKeyUseStartedSignatureUnknown
            }
            OfflineSignatureKnowledge::ExactResultRetainedCurrentValidityUnknown => {
                OfflineSignatureKnowledgeV2::ExactResultRetainedCurrentValidityUnknown
            }
        };
        origins.push(HostRecoveryReservationOriginV2::Offline {
            origin: Box::new(HostRecoveryOfflineOriginV2 {
                replayed_admission: origin.replayed_admission().cloned(),
                retained_remote: remote,
                minimal_local: retained.and_then(|r| r.local_admission()).cloned(),
                original: retained.and_then(|r| r.original_consent()).cloned(),
                key_use: retained.and_then(|r| r.local_key_use()).cloned(),
                retained_result: retained.and_then(|r| r.retained_result()).cloned(),
                signature_knowledge,
            }),
        });
    }
    // Each origin was already structurally validated by the typed union.
    let mut keyed: Vec<(String, HostRecoveryReservationOriginV2)> = origins
        .into_iter()
        .map(|origin| {
            let key = origin
                .authorization_id()
                .map_err(|_| JournalError::InvalidBinding)?
                .to_owned();
            Ok((key, origin))
        })
        .collect::<Result<_>>()?;
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    let origins = keyed.into_iter().map(|(_, origin)| origin).collect();
    let account_use = account_use_recovery::reconcile_live(c, history)?;
    let complete = HostRecoveryHistoryV2 {
        schema_version: 2,
        pending_birth_commit: history.pending_birth_commit().cloned(),
        complete_journal_digest: local.commitment().to_owned(),
        origins,
        retained_enrollments: union.retained_enrollments().to_vec(),
        retained_reservation_intents: union.retained_reservation_intents().to_vec(),
        review_receipts: offline_receipts::continuity_metadata(c, &account.account_id)?,
        account_use: AccountUseHistoryV2 {
            genesis: account_use.genesis().cloned(),
            exclusion: account_use.exclusion().cloned(),
            witness_ack: account_use.acknowledgement().cloned(),
        },
    };
    complete
        .validate(
            &account.account_id,
            &history.disclosure().network_profile_id,
            history.disclosure(),
            &history.snapshot().head,
            account.writer_epoch,
        )
        .map_err(|_| JournalError::InvalidBinding)?;
    Ok(complete)
}

/// Versioned complete audit hold. Construction still requires the real session,
/// native read grant, current authenticated writer and exclusive journal fence.
/// No saved DTO can construct this lease or authorize signing/publication.
pub(crate) struct HostContinuityRecordLeaseV3<'a> {
    held: HostContinuityRecordLease<'a>,
    journal: &'a SignerConsentJournal,
    account: SignerAccountState,
    history: crate::authority_bridge::host_recovery_ipc::v3::HostRecoveryHistoryV3,
}
impl HostContinuityRecordLeaseV3<'_> {
    pub(crate) fn history_v3(
        &self,
    ) -> &crate::authority_bridge::host_recovery_ipc::v3::HostRecoveryHistoryV3 {
        &self.history
    }
    pub(crate) fn require_native_origin(
        &self,
        origin: &crate::native_ui::NativeAuthorityBinding,
    ) -> Result<()> {
        self.held.require_native_origin(origin)
    }
    pub(crate) fn check_current(&self) -> Result<()> {
        self.held.check_current()?;
        let mut c = self
            .journal
            .connection
            .lock()
            .map_err(|_| JournalError::Database)?;
        let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)?;
        let current = writer_history::WriterLocalInventory::read(
            &tx,
            &self.account,
            self.journal.capacity_limits(),
        )?;
        if current.commitment() != self.history.financial_origins_v2.complete_journal_digest {
            return Err(JournalError::Conflict);
        }
        self.held.check_current()?;
        tx.rollback()?;
        Ok(())
    }
}
impl SignerConsentJournal {
    pub(crate) fn acquire_host_recovery_continuity_v3<'a>(
        &'a self,
        session: &'a SignerConsentSession,
        history: &ReconciledAuthorityHistory,
        active: &AuthenticatedWriterSession,
    ) -> Result<HostContinuityRecordLeaseV3<'a>> {
        let account = self.account_state()?;
        if account.recovery_required {
            return Err(JournalError::RecoveryRequired);
        }
        let permission = session.read_lease(&self.binding(), &account)?;
        let fence = self
            .authority_fence
            .try_write()
            .map_err(|_| JournalError::Permission)?;
        let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
        let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)?;
        if active.snapshot() != history.snapshot()
            || active.disclosure() != history.disclosure()
            || active.history_digest()
                != history
                    .history_digest()
                    .map_err(|_| JournalError::InvalidBinding)?
            || active.snapshot().account_id != account.account_id
            || active.snapshot().writer_epoch != account.writer_epoch
            || active.observation_age() >= std::time::Duration::from_secs(30)
            || active.receipt().expires_at_ms <= now_ms()?
            || active.snapshot().active_writer_session.as_ref() != Some(active.receipt())
            || active.snapshot().writer_status != wholepact_authority::WriterStatus::Active
        {
            return Err(JournalError::InvalidBinding);
        }
        permission.check_current()?;
        let complete = read_complete_continuity_v3(&tx, &account, self.capacity_limits(), history)?;
        permission.check_current()?;
        tx.rollback()?;
        drop(c);
        let held = HostContinuityRecordLeaseV3 {
            held: HostContinuityRecordLease {
                permission,
                _fence: fence,
            },
            journal: self,
            account,
            history: complete,
        };
        held.check_current()?;
        Ok(held)
    }
}
fn read_complete_continuity_v3(
    c: &Connection,
    account: &SignerAccountState,
    limits: (u64, u64),
    history: &ReconciledAuthorityHistory,
) -> Result<crate::authority_bridge::host_recovery_ipc::v3::HostRecoveryHistoryV3> {
    let complete = crate::authority_bridge::host_recovery_ipc::v3::HostRecoveryHistoryV3 {
        schema_version: 3,
        financial_origins_v2: read_financial_continuity_branch(c, account, limits, history)?,
        construction: history
            .construction_history_v1()
            .map_err(|_| JournalError::InvalidBinding)?,
    };
    complete
        .validate(
            &account.account_id,
            &history.disclosure().network_profile_id,
            history.disclosure(),
            &history.snapshot().head,
            account.writer_epoch,
        )
        .map_err(|_| JournalError::InvalidBinding)?;
    Ok(complete)
}

/// Versioned complete audit hold. Construction still requires the real session,
/// native read grant, current authenticated writer and exclusive journal fence.
/// No saved DTO can construct this lease or authorize signing/publication.
pub(crate) struct HostContinuityRecordLeaseV4<'a> {
    held: HostContinuityRecordLease<'a>,
    journal: &'a SignerConsentJournal,
    account: SignerAccountState,
    history: crate::authority_bridge::host_recovery_ipc::v4::HostRecoveryHistoryV4,
}
impl HostContinuityRecordLeaseV4<'_> {
    pub(crate) fn history_v4(
        &self,
    ) -> &crate::authority_bridge::host_recovery_ipc::v4::HostRecoveryHistoryV4 {
        &self.history
    }
    pub(crate) fn require_native_origin(
        &self,
        origin: &crate::native_ui::NativeAuthorityBinding,
    ) -> Result<()> {
        self.held.require_native_origin(origin)
    }
    pub(crate) fn check_current(&self) -> Result<()> {
        self.held.check_current()?;
        let mut c = self
            .journal
            .connection
            .lock()
            .map_err(|_| JournalError::Database)?;
        let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)?;
        let current = writer_history::WriterLocalInventory::read(
            &tx,
            &self.account,
            self.journal.capacity_limits(),
        )?;
        if current.commitment() != self.history.financial_origins_v2.complete_journal_digest {
            return Err(JournalError::Conflict);
        }
        self.held.check_current()?;
        tx.rollback()?;
        Ok(())
    }
}
impl SignerConsentJournal {
    pub(crate) fn acquire_host_recovery_continuity_v4<'a>(
        &'a self,
        session: &'a SignerConsentSession,
        history: &ReconciledAuthorityHistory,
        active: &AuthenticatedWriterSession,
    ) -> Result<HostContinuityRecordLeaseV4<'a>> {
        let account = self.account_state()?;
        if account.recovery_required {
            return Err(JournalError::RecoveryRequired);
        }
        let permission = session.read_lease(&self.binding(), &account)?;
        let fence = self
            .authority_fence
            .try_write()
            .map_err(|_| JournalError::Permission)?;
        let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
        let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)?;
        if active.snapshot() != history.snapshot()
            || active.disclosure() != history.disclosure()
            || active.history_digest()
                != history
                    .history_digest()
                    .map_err(|_| JournalError::InvalidBinding)?
            || active.snapshot().account_id != account.account_id
            || active.snapshot().writer_epoch != account.writer_epoch
            || active.observation_age() >= std::time::Duration::from_secs(30)
            || active.receipt().expires_at_ms <= now_ms()?
            || active.snapshot().active_writer_session.as_ref() != Some(active.receipt())
            || active.snapshot().writer_status != wholepact_authority::WriterStatus::Active
        {
            return Err(JournalError::InvalidBinding);
        }
        permission.check_current()?;
        let complete = read_complete_continuity_v4(&tx, &account, self.capacity_limits(), history)?;
        permission.check_current()?;
        tx.rollback()?;
        drop(c);
        let held = HostContinuityRecordLeaseV4 {
            held: HostContinuityRecordLease {
                permission,
                _fence: fence,
            },
            journal: self,
            account,
            history: complete,
        };
        held.check_current()?;
        Ok(held)
    }
}
fn read_complete_continuity_v4(
    c: &Connection,
    account: &SignerAccountState,
    limits: (u64, u64),
    history: &ReconciledAuthorityHistory,
) -> Result<crate::authority_bridge::host_recovery_ipc::v4::HostRecoveryHistoryV4> {
    named_recipient_inventory::require_absent(c)?;
    storage::require_no_unimplemented_reentry(c)?;
    let complete = crate::authority_bridge::host_recovery_ipc::v4::HostRecoveryHistoryV4 {
        schema_version: 4,
        signer_common_context_audit: construction_audit_v3::read_all(c, &account.account_id)?,
        financial_origins_v2: read_financial_continuity_branch(c, account, limits, history)?,
        construction: history
            .construction_history_v2()
            .map_err(|_| JournalError::InvalidBinding)?,
    };
    complete
        .validate(
            &account.account_id,
            &history.disclosure().network_profile_id,
            history.disclosure(),
            &history.snapshot().head,
            account.writer_epoch,
        )
        .map_err(|_| JournalError::InvalidBinding)?;
    Ok(complete)
}

/// Exact complete V5 read in the caller's one SQLite snapshot. Ordinary writer
/// inventory/import constructors retain their legacy transport refusals.
/// Shared only with the sealed-source informational reader; this kernel cannot
/// create a native read owner, writer session or import capability.
pub(super) fn read_complete_continuity_v5(
    c: &Connection,
    account: &SignerAccountState,
    limits: (u64, u64),
    history: &ReconciledAuthorityHistory,
) -> Result<crate::authority_bridge::host_recovery_ipc::v5::HostRecoveryHistoryV5> {
    let source =
        writer_history::TransportContinuityLocalInventory::read(c, account, limits, history)?;
    source.validate_financial_origins(history)?;
    offline_receipts::validate_transport_reconciled(
        c,
        &account.account_id,
        history,
        source.construction(),
    )?;
    let union = source
        .local()
        .offline_history()
        .reconcile_transport_financial_branch(history, source.construction())?;
    let complete = crate::authority_bridge::host_recovery_ipc::v5::HostRecoveryHistoryV5 {
        schema_version: 5,
        financial_origins_v2: build_financial_continuity_branch(
            c,
            account,
            history,
            source.local(),
            &union,
        )?,
        construction: source.construction().clone(),
        signer_common_context_audit: source.audit().clone(),
    };
    complete
        .validate(
            &account.account_id,
            &history.disclosure().network_profile_id,
            history.disclosure(),
            &history.snapshot().head,
            account.writer_epoch,
        )
        .map_err(|_| JournalError::InvalidBinding)?;
    Ok(complete)
}

/// Informational V5 owner only. Current native read permission and local
/// exclusion remain held; a historical session/fenced key is never a writer
/// capability. No Serialize/Deserialize or import conversion exists.
pub(crate) struct HostContinuityRecordLeaseV5<'a> {
    _fence: RwLockWriteGuard<'a, ()>,
    journal: &'a SignerConsentJournal,
    account: SignerAccountState,
    observation: &'a crate::native_ui::NativeHostRecoveryObservationV5,
    history: crate::authority_bridge::host_recovery_ipc::v5::HostRecoveryHistoryV5,
}
impl HostContinuityRecordLeaseV5<'_> {
    pub(crate) fn history_v5(
        &self,
    ) -> &crate::authority_bridge::host_recovery_ipc::v5::HostRecoveryHistoryV5 {
        &self.history
    }
    pub(crate) fn require_native_origin(
        &self,
        origin: &crate::native_ui::NativeAuthorityBinding,
    ) -> Result<()> {
        self.observation
            .require_native_origin(origin)
            .map_err(|_| JournalError::Permission)?;
        Ok(())
    }
    pub(crate) fn check_current(&self) -> Result<()> {
        self.observation
            .check_current()
            .map_err(|_| JournalError::Permission)?;
        self.observation
            .require_journal(&self.journal.binding())
            .map_err(|_| JournalError::Permission)?;
        let mut c = self
            .journal
            .connection
            .lock()
            .map_err(|_| JournalError::Database)?;
        let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)?;
        let current = read_complete_continuity_v5(
            &tx,
            &self.account,
            self.journal.capacity_limits(),
            self.observation.history(),
        )?;
        if current != self.history {
            return Err(JournalError::Conflict);
        }
        self.observation
            .require_journal(&self.journal.binding())
            .map_err(|_| JournalError::Permission)?;
        self.observation
            .check_current()
            .map_err(|_| JournalError::Permission)?;
        tx.rollback()?;
        Ok(())
    }
}
impl SignerConsentJournal {
    pub(crate) fn acquire_host_recovery_continuity_v5<'a>(
        &'a self,
        observation: &'a crate::native_ui::NativeHostRecoveryObservationV5,
    ) -> Result<HostContinuityRecordLeaseV5<'a>> {
        observation
            .check_current()
            .map_err(|_| JournalError::Permission)?;
        observation
            .require_journal(&self.binding())
            .map_err(|_| JournalError::Permission)?;
        let account = self.account_state()?;
        let history = observation.history();
        // A recovery flag, paused writer or transport fence cannot be cleared
        // by this read. They do not manufacture permission and are preserved in
        // complete journal/replay provenance. The actual fresh informational
        // owner binds this exact local journal, account and historical epoch.
        if history.snapshot().account_id != account.account_id
            || history.snapshot().writer_epoch != account.writer_epoch
        {
            return Err(JournalError::InvalidBinding);
        }
        let fence = self
            .authority_fence
            .try_write()
            .map_err(|_| JournalError::Permission)?;
        let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
        let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)?;
        observation
            .check_current()
            .map_err(|_| JournalError::Permission)?;
        let complete = read_complete_continuity_v5(&tx, &account, self.capacity_limits(), history)?;
        observation
            .check_current()
            .map_err(|_| JournalError::Permission)?;
        observation
            .check_current()
            .map_err(|_| JournalError::Permission)?;
        tx.rollback()?;
        drop(c);
        let held = HostContinuityRecordLeaseV5 {
            _fence: fence,
            journal: self,
            account,
            observation,
            history: complete,
        };
        held.check_current()?;
        Ok(held)
    }
}

#[cfg(all(test, feature = "pending-birth-owner-signing", target_os = "linux"))]
#[path = "host_recovery_continuity_v5_tests.rs"]
mod v5_tests;
