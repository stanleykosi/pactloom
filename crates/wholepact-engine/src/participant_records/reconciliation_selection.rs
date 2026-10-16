//! Private record selection checks. An opaque client-selected identity never
//! discloses the retained archive or grants a record/account lease.
use super::*;
use crate::native_dispatch_requests::DispatchSource;
pub(crate) fn validate_selection(
    e: &Envelope,
    principal: &str,
    source: &DispatchSource,
    participant: &str,
    id: &str,
) -> Result<()> {
    for value in [participant, id] {
        validate_identifier(value)?;
        if matches!(value, "." | "..") {
            return Err(not_found());
        }
    }
    let r = e
        .participant_records
        .get(id)
        .filter(|r| r.owner_principal_id == principal)
        .ok_or_else(not_found)?;
    let archive = &r.record;
    if archive.record_id != id
        || r.candidate_id != source.original.candidate_id
        || archive.proposal.proposal_id != source.original.candidate_id
        || archive.proposal.artifact_digest.as_ref() != Some(&source.signed.signed_candidate_digest)
        || archive.own_authorization.participant_id != participant
        || archive.own_authorization.manifest_digest != source.original.manifest_digest
        || archive.transaction.transaction_id != source.txid
        || archive.transaction.transaction_bytes_digest != source.transaction_digest
    {
        return Err(not_found());
    }
    Ok(())
}
#[cfg(all(
    feature = "submission-handoff",
    feature = "signer-authority-bridge",
    target_os = "linux"
))]
pub(crate) struct SelectedRecordLease<'a> {
    lease: Box<dyn ParticipantRecordLease + 'a>,
    engine: Engine,
    access: Access,
    source: DispatchSource,
    immutable_identity: String,
    scope: ParticipantRecordScope,
    window: ObservationWindow,
}
#[cfg(all(
    feature = "submission-handoff",
    feature = "signer-authority-bridge",
    target_os = "linux"
))]
impl SelectedRecordLease<'_> {
    // This path deliberately performs no Engine/Store reads. The native record
    // lease checks only its held foreground fence and clock; bindings are values.
    pub(crate) fn check_commit_permission(&self) -> Result<()> {
        check_lease(&*self.lease, &self.scope, &self.window)
    }
    pub(crate) fn check_current(&self) -> Result<()> {
        self.check_commit_permission()?;
        require_mutable_records(&self.engine, &self.scope.agreement_id)?;
        let e = self.engine.load(&self.access, &self.scope.agreement_id)?;
        validate_selection(
            &e,
            &self.access.principal_id,
            &self.source,
            &self.scope.participant_id,
            &self.scope.record_id,
        )?;
        let r = owned_record(
            &e,
            &self.access,
            &self.scope.record_id,
            &self.scope.profile_id,
        )?;
        if immutable_identity(r)? != self.immutable_identity {
            return Err(corrupt_record());
        }
        Ok(())
    }
    pub(crate) fn validate_signer_history(
        &self,
        history: &wholepact_signer::authority_bridge::ipc::OriginalHistoryLease<'_>,
    ) -> Result<()> {
        // Check current Access, exact immutable row and record permission before
        // inspecting authenticated signer evidence, then bind it before settlement.
        self.check_current()?;
        history.check_current().map_err(|_| corrupt_record())?;
        let e = self.engine.load(&self.access, &self.scope.agreement_id)?;
        self.check_origin(
            &self.engine,
            &self.access,
            &e,
            &self.source,
            history.evidence(),
        )
    }
    pub(crate) fn check_origin(
        &self,
        engine: &Engine,
        access: &Access,
        e: &Envelope,
        source: &DispatchSource,
        original: &wholepact_signer::authority_bridge::protocol::OriginalAuthorizationView,
    ) -> Result<()> {
        self.check_current()?;
        if self.scope.store != engine.protected_record_store_binding()?
            || self.scope.principal_id != access.principal_id
            || self.scope.agreement_id != e.view.agreement.agreement_id
        {
            return Err(not_found());
        }
        validate_selection(
            e,
            &access.principal_id,
            source,
            &self.scope.participant_id,
            &self.scope.record_id,
        )?;
        let r = owned_record(e, access, &self.scope.record_id, &self.scope.profile_id)?;
        let own = &r.record.own_authorization;
        let terms = original.consent.terms();
        if self.scope.account_id != own.account_id
            || terms.principal_id != access.principal_id
            || terms.agreement_id != self.scope.agreement_id
            || terms.account_id != own.account_id
            || original.enrollment.participant_id() != self.scope.participant_id
            || terms.proposal_id != source.original.candidate_id
            || terms.artifact_digest != source.original.proved_artifact_digest
            || terms.manifest_digest != source.original.manifest_digest
            || own.authorization_record_ref != terms.authorization_id
            || own.consent_record_ref != original.consent.reference()
            || own.effects_commitment != terms.effects_digest
            || own.release_operation_id.as_deref() != Some(terms.authorization_id.as_str())
        {
            return Err(ApiError::new(
                "SETTLEMENT_RECORD_MISMATCH",
                "Selected original participant record does not match authenticated signer provenance",
            ));
        }
        Ok(())
    }
}
#[cfg(all(
    feature = "submission-handoff",
    feature = "signer-authority-bridge",
    target_os = "linux"
))]
pub(crate) fn acquire_selection<'a>(
    engine: &Engine,
    access: &Access,
    e: &Envelope,
    source: &DispatchSource,
    participant: &str,
    id: &str,
    runtime: &'a ParticipantRecordRuntime<'_>,
) -> Result<SelectedRecordLease<'a>> {
    require_mutable_records(engine, &e.view.agreement.agreement_id)?;
    validate_selection(e, &access.principal_id, source, participant, id)?;
    let r = owned_record(e, access, id, runtime.profile_id)?;
    let scope = make_scope(
        engine,
        access,
        &e.view.agreement.agreement_id,
        r,
        runtime,
        ParticipantRecordAction::ReadPrivate,
    );
    let lease = checked_lease(runtime, &scope)?;
    Ok(SelectedRecordLease {
        lease,
        engine: engine.clone(),
        access: access.clone(),
        source: source.clone(),
        immutable_identity: immutable_identity(r)?,
        scope,
        window: runtime.window.clone(),
    })
}

#[cfg(all(
    feature = "submission-handoff",
    feature = "signer-authority-bridge",
    target_os = "linux"
))]
fn immutable_identity(r: &StoredParticipantRecord) -> Result<String> {
    let own = &r.record.own_authorization;
    // Confidence, exposure and record revisions legitimately change during apply.
    // Bind only the original archive and provenance; never serialize this to a client.
    hash_domain(
        b"wholepact:resolution-selected-record:v1\0",
        &json!({
            "owner":r.owner_principal_id,"profile":r.profile_id,"candidate":r.candidate_id,
            "candidate_proposal_digest":r.candidate_proposal_digest,"retained_source":r.retained_source_id,
            "record_id":r.record.record_id,"proposal":r.record.proposal,"transaction":r.record.transaction,
            "participant":own.participant_id,"account":own.account_id,"proposal_digest":own.proposal_digest,
            "manifest":own.manifest_digest,"effects":own.effects_commitment,"consent":own.consent_record_ref,
            "authorization":own.authorization_record_ref,"release":own.release_operation_id
        }),
    )
}
