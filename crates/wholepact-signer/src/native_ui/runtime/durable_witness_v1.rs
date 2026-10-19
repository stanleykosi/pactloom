//! Source-bound financial witness workflow. All native/prepared/approved custody
//! is private to the runtime. Serialized requests and retained historical rows
//! never reconstruct permission or replace the actual current imported source.
use super::durable_review_v1::DurableWitnessImportedSourceV1;
use super::*;
use crate::native_ui::NativeDecision;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use wholepact_authority::durable_payment_v1::{
    DurableFixedCandidateBindingV1, DurablePaymentAdmissionTermsV1,
};
#[cfg(feature = "synthetic-born-joined-qualification")]
use wholepact_authority::transport::history_diagnostics_v1::{
    CheckedHistoryFailureV1, CheckedHistoryIoKindV1, CheckedHistoryMeasurementV1,
    CheckedHistoryStageV1,
};
use wholepact_authority::{
    AccountSnapshot, OwnerControl, OwnerControlRequest, ReconciledAuthorityHistory,
    WitnessDisclosureDescriptor, WriterSessionReceipt,
};

#[derive(Clone, Copy)]
enum CredentialRole {
    Owner,
    Writer,
}
fn require_workspace_source(
    workspace: &NativeWitnessWorkspace,
    source: &DurableWitnessImportedSourceV1,
    role: CredentialRole,
) -> Result<()> {
    require_workspace_source_inner(
        workspace,
        source,
        role,
        #[cfg(feature = "synthetic-born-joined-qualification")]
        None,
        #[cfg(feature = "synthetic-born-joined-qualification")]
        flow_diag_v1::DurableFlowStageV1::FixtureState,
    )
}
fn require_workspace_source_inner(
    workspace: &NativeWitnessWorkspace,
    source: &DurableWitnessImportedSourceV1,
    role: CredentialRole,
    #[cfg(feature = "synthetic-born-joined-qualification")] observer: Option<
        &flow_diag_v1::DurableFlowObserverV1,
    >,
    #[cfg(feature = "synthetic-born-joined-qualification")] stage: flow_diag_v1::DurableFlowStageV1,
) -> Result<()> {
    // This descriptor is data only. The complete source/journal/current-record
    // check follows it on EVERY callback and retains its own actual read fence.
    let disclosure = source.entry().original_witness_disclosure_data_v1()?;
    source.check_current_inner(
        #[cfg(feature = "synthetic-born-joined-qualification")]
        observer,
        #[cfg(feature = "synthetic-born-joined-qualification")]
        stage,
    )?;
    let signer = &source.entry().record().account_record.terms.signer;
    let certificate = match role {
        CredentialRole::Owner => &signer.owner_certificate_digest,
        CredentialRole::Writer => &signer.writer_certificate_digest,
    };
    workspace.require_durable_credential_v1(
        &source.entry().native_binding(),
        &disclosure,
        certificate,
    )
}
fn source_history(
    workspace: &NativeWitnessWorkspace,
    source: &DurableWitnessImportedSourceV1,
    role: CredentialRole,
    deadline: Instant,
) -> Result<ReconciledAuthorityHistory> {
    source_history_inner(
        workspace,
        source,
        role,
        deadline,
        #[cfg(feature = "synthetic-born-joined-qualification")]
        None,
        #[cfg(feature = "synthetic-born-joined-qualification")]
        None,
        #[cfg(feature = "synthetic-born-joined-qualification")]
        flow_diag_v1::DurableFlowStageV1::FixtureState,
    )
}
fn source_history_inner(
    workspace: &NativeWitnessWorkspace,
    source: &DurableWitnessImportedSourceV1,
    role: CredentialRole,
    deadline: Instant,
    #[cfg(feature = "synthetic-born-joined-qualification")] failure: Option<
        &mut Option<(CheckedHistoryFailureV1, Option<Error>)>,
    >,
    #[cfg(feature = "synthetic-born-joined-qualification")] observer: Option<
        &flow_diag_v1::DurableFlowObserverV1,
    >,
    #[cfg(feature = "synthetic-born-joined-qualification")] stage: flow_diag_v1::DurableFlowStageV1,
) -> Result<ReconciledAuthorityHistory> {
    durable_flow_observe_v1!(
        observer,
        stage,
        require_workspace_source_inner(
            workspace,
            source,
            role,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            observer,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            stage,
        )
    )?;
    #[cfg(feature = "synthetic-born-joined-qualification")]
    if let Some(failure) = failure {
        return workspace.durable_history_diagnosed_v1(
            deadline,
            || require_workspace_source(workspace, source, role),
            failure,
        );
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    {
        workspace.durable_history_flow_v1(
            deadline,
            || require_workspace_source_inner(workspace, source, role, observer, stage),
            observer,
            stage,
        )
    }
    #[cfg(not(feature = "synthetic-born-joined-qualification"))]
    {
        workspace.durable_history_v1(deadline, || {
            require_workspace_source(workspace, source, role)
        })
    }
}

fn canonical<T: serde::Serialize>(domain: &str, value: &T) -> Result<String> {
    wholepact_core::proposal::canonical_digest(domain, value).map_err(|_| Error::InvalidData)
}
fn now_ms() -> Result<u64> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::ReviewMismatch)?
            .as_millis(),
    )
    .map_err(|_| Error::ReviewMismatch)
}
fn fixed_binding(
    source: &DurableWitnessImportedSourceV1,
) -> Result<DurableFixedCandidateBindingV1> {
    serde_json::from_value(
        serde_json::to_value(source.fixed().verified().identity())
            .map_err(|_| Error::InvalidData)?,
    )
    .map_err(|_| Error::InvalidData)
}
fn terms(
    source: &DurableWitnessImportedSourceV1,
    from: u64,
    until: u64,
) -> Result<DurablePaymentAdmissionTermsV1> {
    source.check_current()?;
    let result = terms_from_current_policy_records(source, from, until)?;
    source.check_current()?;
    Ok(result)
}
// Read-only reconstruction only. This owns and drops its actual policy lease;
// the returned terms are inert data, never a successful current-source token.
fn terms_from_current_policy_records(
    source: &DurableWitnessImportedSourceV1,
    from: u64,
    until: u64,
) -> Result<DurablePaymentAdmissionTermsV1> {
    let entry = source.entry();
    let extension = entry.record().extension()?;
    let old = &extension.account_extension;
    let economics = source.fixed();
    let fixed = economics.verified();
    let lease = entry.journal().acquire_preconstruction_records(
        source.enrollment_ref(),
        source.manifest_ref(),
        source.session(),
    )?;
    lease.require_native_origin(&entry.native_binding())?;
    lease.require_current_durable_disclosure_receipts_v1()?;
    let recipient_policy_scope_digest =
        authority_bridge::durable_proposal_v1::validate_durable_payment_policy_v1(
            entry,
            lease.enrollment(),
            lease.manifest(),
            fixed,
            economics.input_actions(),
            economics.output_actions(),
        )
        .map_err(|_| Error::ReviewMismatch)?;
    let account = entry.account().account_id()?;
    let proposal = economics.proposal();
    let owner = proposal
        .manifest()
        .participants
        .iter()
        .find(|p| p.account_id == account)
        .ok_or(Error::ReviewMismatch)?;
    let inputs = economics
        .input_actions()
        .iter()
        .filter(|i| i.account_id == account)
        .map(|map| {
            let input = fixed
                .private_review_policy()
                .inputs
                .iter()
                .find(|i| i.action_index == map.action_index)
                .ok_or(Error::ReviewMismatch)?;
            Ok(wholepact_authority::InputReservation {
                input_id: map.input_id.clone(),
                nullifier: hex::encode(input.nullifier),
                action_index: map.action_index as u64,
                value_zatoshis: input.value_zatoshis,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let result = DurablePaymentAdmissionTermsV1 {
        version: 1,
        identity: old.terms.identity.clone(),
        original_policy_digest: old.terms.original_policy_digest.clone(),
        original_genesis_digest: entry
            .genesis()
            .digest()
            .map_err(|_| Error::ReviewMismatch)?,
        original_birth_commit_digest: old.terms.birth_commit_digest.clone(),
        original_roster_extension_digest: extension.digest().map_err(|_| Error::ReviewMismatch)?,
        original_enrollment_ref: old.enrollment_ref.clone(),
        writer_certificate_digest: old.terms.signer.writer_certificate_digest.clone(),
        fixed: fixed_binding(source)?,
        authorization_id: authority_bridge::durable_proposal_v1::manual_authorization_id(
            fixed.identity(),
            &account,
        )
        .map_err(|_| Error::ReviewMismatch)?,
        recipient_policy_scope_digest,
        concrete_recipient_scope_digest:
            wholepact_core::manual_construction::construction_recipient_scope_digest(proposal)
                .map_err(|_| Error::ReviewMismatch)?,
        inputs,
        maximum_debit_zatoshis: proposal
            .accounting()
            .participant_net_debits
            .get(&owner.participant_id)
            .ok_or(Error::ReviewMismatch)?
            .as_zatoshis(),
        fee_share_zatoshis: owner.fee_share.as_zatoshis(),
        transaction_fee_zatoshis: proposal.manifest().transaction_fee.as_zatoshis(),
        valid_from_ms: from,
        valid_until_ms: until,
    };
    result.validate().map_err(|_| Error::ReviewMismatch)?;
    source.check_data_current_under_fence()?;
    drop(lease);
    Ok(result)
}
fn admission_terms(request: &OwnerControlRequest) -> Result<&DurablePaymentAdmissionTermsV1> {
    match &request.control {
        OwnerControl::AdmitDurablePaymentV1 { record } => Ok(&record.terms),
        _ => Err(Error::ReviewMismatch),
    }
}
fn require_request(
    source: &DurableWitnessImportedSourceV1,
    request: &OwnerControlRequest,
) -> Result<()> {
    let old = admission_terms(request)?;
    if *old != terms(source, old.valid_from_ms, old.valid_until_ms)? {
        return Err(Error::ReviewMismatch);
    }
    Ok(())
}
// Fixed-order, fixed-terms kernel used only by the closed three-purpose callback
// below. No closure receives a lease, connection or capability; no permission
// or validation result escapes. Tests can exercise this exact sequence without
// constructing an imported source or pretending to issue native custody.
fn check_callback_terms_v1(
    expected: &DurablePaymentAdmissionTermsV1,
    early_custody: impl FnOnce() -> Result<()>,
    reconstruct: impl FnOnce() -> Result<DurablePaymentAdmissionTermsV1>,
    late_current: impl FnOnce() -> Result<()>,
    final_custody: impl FnOnce() -> Result<()>,
    #[cfg(feature = "synthetic-born-joined-qualification")] mut observation: Option<
        &mut QualificationDurableAdmissionObservationV1,
    >,
) -> Result<()> {
    #[cfg(feature = "synthetic-born-joined-qualification")]
    if let Some(value) = observation.as_deref_mut() {
        value.callback(DurableAdmissionCallbackStageV1::Custody, early_custody)?;
    } else {
        early_custody()?;
    }
    #[cfg(not(feature = "synthetic-born-joined-qualification"))]
    early_custody()?;
    let check_request = || {
        let actual = reconstruct()?;
        // This is a fresh actual acquisition and complete snapshot, not reuse
        // of the earlier policy lease. Another live handle can change epoch or
        // append history despite that handle's authority read fence.
        late_current()?;
        if &actual != expected {
            return Err(Error::ReviewMismatch);
        }
        final_custody()
    };
    #[cfg(feature = "synthetic-born-joined-qualification")]
    if let Some(value) = observation {
        return value.callback(
            DurableAdmissionCallbackStageV1::RequestValidation,
            check_request,
        );
    }
    check_request()
}
fn require_request_under_fence(
    source: &DurableWitnessImportedSourceV1,
    request: &OwnerControlRequest,
) -> Result<()> {
    source.check_data_current_under_fence()?;
    let old = admission_terms(request)?;
    let extension = source.entry().record().extension()?;
    if old.fixed != fixed_binding(source)?
        || old.original_enrollment_ref != extension.account_extension.enrollment_ref
        || old.original_roster_extension_digest
            != extension.digest().map_err(|_| Error::ReviewMismatch)?
    {
        return Err(Error::ReviewMismatch);
    }
    Ok(())
}
fn require_live(request: &OwnerControlRequest) -> Result<()> {
    let terms = admission_terms(request)?;
    let now = now_ms()?;
    if now < terms.valid_from_ms || now >= terms.valid_until_ms {
        return Err(Error::RecoveryRequired);
    }
    Ok(())
}
fn local_intent(
    source: &DurableWitnessImportedSourceV1,
) -> Result<Option<RetainedDurablePaymentAdmissionIntentV1>> {
    let id = authority_bridge::durable_proposal_v1::manual_authorization_id(
        source.fixed().verified().identity(),
        &source.entry().account().account_id()?,
    )
    .map_err(|_| Error::ReviewMismatch)?;
    source
        .entry()
        .journal()
        .durable_payment_admission_intent_v1(&id, source.session())
        .map_err(Into::into)
}
fn require_intent(
    source: &DurableWitnessImportedSourceV1,
    intent: &RetainedDurablePaymentAdmissionIntentV1,
) -> Result<()> {
    require_request(source, intent.request())?;
    let old = &source.entry().record().account_record.terms;
    if intent.owner_certificate_digest() != old.signer.owner_certificate_digest
        || intent.disclosure() != &source.entry().original_witness_disclosure()?
        || local_intent(source)?.as_ref() != Some(intent)
    {
        return Err(Error::RecoveryRequired);
    }
    Ok(())
}
fn committed_intent(
    source: &DurableWitnessImportedSourceV1,
    history: &ReconciledAuthorityHistory,
    admission: &str,
) -> Result<RetainedDurablePaymentAdmissionIntentV1> {
    let intent = local_intent(source)?.ok_or(Error::RecoveryRequired)?;
    require_intent(source, &intent)?;
    if intent.request().operation_id != admission
        || history
            .durable_payment_admission_v1(admission)
            .map_err(|_| Error::RecoveryRequired)?
            != Some(intent.request())
        || history.disclosure() != intent.disclosure()
        || history.account_policy().owner_certificate_digest != intent.owner_certificate_digest()
    {
        return Err(Error::RecoveryRequired);
    }
    history
        .durable_payment_online_permits_v1(admission)
        .map_err(|_| Error::RecoveryRequired)?;
    Ok(intent)
}

// Exact historical request equality must precede the unchanged committed check.
// This returns no reusable intent or source-validation token.
fn check_historical_admission_v1(
    retained: &OwnerControlRequest,
    witnessed: &OwnerControlRequest,
    committed: impl FnOnce() -> Result<()>,
) -> Result<()> {
    if witnessed != retained {
        return Err(Error::RecoveryRequired);
    }
    committed()
}

// Fixed preparation sequence only: the output is inert data for the private
// constructor, never permission to skip a later custody/currentness check.
fn prepare_review_custody_v1(
    early_source_data: impl FnOnce() -> Result<()>,
    original_disclosure: impl FnOnce() -> Result<WitnessDisclosureDescriptor>,
    credential: impl Fn(&WitnessDisclosureDescriptor) -> Result<()>,
    original_deadline: impl FnOnce() -> Result<Instant>,
    late_source_current: impl FnOnce() -> Result<()>,
) -> Result<(WitnessDisclosureDescriptor, Instant)> {
    early_source_data()?;
    let disclosure = original_disclosure()?;
    credential(&disclosure)?;
    // Save the original absolute bound BEFORE the expensive complete check.
    // Late work must consume this interval, never start a fresh one.
    let deadline = original_deadline()?;
    late_source_current()?;
    if Instant::now() >= deadline {
        return Err(Error::ReviewMismatch);
    }
    credential(&disclosure)?;
    Ok((disclosure, deadline))
}

struct ReviewCustody {
    source: Arc<DurableWitnessImportedSourceV1>,
    instance: Arc<()>,
    certificate: String,
    disclosure: WitnessDisclosureDescriptor,
    digest: String,
    display: Zeroizing<String>,
    deadline: Instant,
}
impl ReviewCustody {
    fn new(
        workspace: &NativeWitnessWorkspace,
        source: Arc<DurableWitnessImportedSourceV1>,
        certificate: &str,
        digest: String,
        display: String,
    ) -> Result<Self> {
        let (disclosure, deadline) = prepare_review_custody_v1(
            // Deny-only native/source/peer/privacy preflight. Despite its name,
            // this helper neither acquires nor asserts a held journal fence.
            || source.check_data_current_under_fence(),
            || source.entry().original_witness_disclosure_data_v1(),
            |disclosure| {
                workspace.require_durable_credential_v1(
                    &source.entry().native_binding(),
                    disclosure,
                    certificate,
                )
            },
            || {
                Ok(source
                    .deadline()?
                    .min(Instant::now() + Duration::from_secs(120)))
            },
            // Keep the imported source's complete check unchanged: fresh epoch
            // and records, its actual fence/full snapshot, BOTH fresh receipts,
            // and original source/peer/scopes/deadline. No lease is retained.
            || source.check_current(),
        )?;
        let display = Zeroizing::new(format!("{}\n\nCurrent local enrollment: {}\nCurrent accepted manifest: {}\nBoth original material-use scopes and the actual local peer remain required throughout this operation.", display, source.enrollment_ref(), source.manifest_ref()));
        Ok(Self {
            source,
            instance: workspace.durable_instance_v1(),
            certificate: certificate.into(),
            disclosure,
            digest,
            display,
            deadline,
        })
    }
    fn current(&self) -> Result<()> {
        self.source.check_current()?;
        if Instant::now() >= self.deadline {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    fn workspace(&self, workspace: &NativeWitnessWorkspace) -> Result<()> {
        self.current()?;
        workspace.require_durable_instance_v1(&self.instance)?;
        workspace.require_durable_credential_v1(
            &self.source.entry().native_binding(),
            &self.disclosure,
            &self.certificate,
        )
    }
    // Exactly the Admission, Acquire and Activate transport callbacks use this
    // closed read-only composition. Generic custody, native approval, retain
    // and already-under-fence reconciliation deliberately keep their old gates.
    fn callback_current_v1(
        &self,
        workspace: &NativeWitnessWorkspace,
        request: &OwnerControlRequest,
        #[cfg(feature = "synthetic-born-joined-qualification")] observation: Option<
            &mut QualificationDurableAdmissionObservationV1,
        >,
    ) -> Result<()> {
        let expected = admission_terms(request)?;
        check_callback_terms_v1(
            expected,
            || {
                // Deny-only source/peer/material/native preflight. The data
                // checker takes no journal lock and also runs before acquisition
                // inside check_current. No fence or permission is asserted here;
                // the mandatory late full gate below must complete before TLS.
                self.source.check_data_current_under_fence()?;
                if Instant::now() >= self.deadline {
                    return Err(Error::ReviewMismatch);
                }
                workspace.require_durable_instance_v1(&self.instance)?;
                workspace.require_durable_credential_v1(
                    &self.source.entry().native_binding(),
                    &self.disclosure,
                    &self.certificate,
                )
            },
            || {
                // Preserve the second early data gate at the former terms-entry
                // boundary. All policy/receipt/export/FVK checks remain, and the
                // policy lease is dropped inside this call before late_current.
                self.source.check_data_current_under_fence()?;
                terms_from_current_policy_records(
                    &self.source,
                    expected.valid_from_ms,
                    expected.valid_until_ms,
                )
            },
            || self.source.check_current(),
            || {
                if Instant::now() >= self.deadline {
                    return Err(Error::ReviewMismatch);
                }
                workspace.require_durable_instance_v1(&self.instance)?;
                workspace.require_durable_credential_v1(
                    &self.source.entry().native_binding(),
                    &self.disclosure,
                    &self.certificate,
                )
            },
            #[cfg(feature = "synthetic-born-joined-qualification")]
            observation,
        )
    }
    fn decision(
        &self,
        decision: &NativeDecision,
        authority: &NativeAuthority,
        workspace: &NativeWitnessWorkspace,
    ) -> Result<()> {
        self.workspace(workspace)?;
        authority.check_current()?;
        if decision.binding() != &self.source.entry().native_binding()
            || authority.binding() != self.source.entry().native_binding()
            || decision.reviewed_digest() != self.digest
            || decision.consumed_at() >= self.deadline
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    fn display(&self) -> Result<String> {
        self.current()?;
        Ok(self.display.to_string())
    }
}

pub(super) struct PreparedDurableWitnessAdmissionV1 {
    custody: ReviewCustody,
    request: OwnerControlRequest,
    prepared: PreparedDurablePaymentAdmissionIntentV1,
}
pub(super) struct ApprovedDurableWitnessAdmissionV1 {
    custody: ReviewCustody,
    request: OwnerControlRequest,
    approved: ApprovedDurablePaymentAdmissionIntentV1,
}
pub(super) struct DurableWitnessAdmissionDispatchV1 {
    custody: ReviewCustody,
    retained: RetainedDurablePaymentAdmissionIntentV1,
}
impl PreparedDurableWitnessAdmissionV1 {
    pub(super) fn prepare(
        owner: &NativeWitnessWorkspace,
        source: Arc<DurableWitnessImportedSourceV1>,
        valid_from_ms: u64,
        valid_until_ms: u64,
    ) -> Result<Self> {
        source.check_current()?;
        if local_intent(&source)?.is_some() {
            return Err(Error::RecoveryRequired);
        }
        let history = source_history(owner, &source, CredentialRole::Owner, source.deadline()?)?;
        let request = wholepact_authority::durable_payment_v1::prepare_durable_payment_request_v1(
            terms(&source, valid_from_ms, valid_until_ms)?,
            &history,
        )
        .map_err(|_| Error::RecoveryRequired)?;
        Self::from_exact(
            owner,
            source,
            request,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            &mut DurableAdmissionPreparationStageV1::ExactRequest,
        )
    }
    pub(super) fn prepare_exact_retry(
        owner: &NativeWitnessWorkspace,
        source: Arc<DurableWitnessImportedSourceV1>,
        retained: RetainedDurablePaymentAdmissionIntentV1,
        #[cfg(feature = "synthetic-born-joined-qualification")]
        stage: &mut DurableAdmissionPreparationStageV1,
    ) -> Result<Self> {
        require_intent(&source, &retained)?;
        let history = source_history(owner, &source, CredentialRole::Owner, source.deadline()?)?;
        // Committed is historical success ONLY. Never reapprove or resubmit it.
        if history
            .durable_payment_admission_v1(&retained.request().operation_id)
            .map_err(|_| Error::RecoveryRequired)?
            .is_some()
            || history.snapshot().head != retained.request().expected_head
            || history.snapshot().writer_epoch != retained.request().writer_epoch
        {
            return Err(Error::RecoveryRequired);
        }
        Self::from_exact(
            owner,
            source,
            retained.request().clone(),
            #[cfg(feature = "synthetic-born-joined-qualification")]
            stage,
        )
    }
    fn from_exact(
        owner: &NativeWitnessWorkspace,
        source: Arc<DurableWitnessImportedSourceV1>,
        request: OwnerControlRequest,
        #[cfg(feature = "synthetic-born-joined-qualification")]
        stage: &mut DurableAdmissionPreparationStageV1,
    ) -> Result<Self> {
        #[cfg(feature = "synthetic-born-joined-qualification")]
        {
            *stage = DurableAdmissionPreparationStageV1::ExactRequest;
        }
        require_request(&source, &request)?;
        #[cfg(feature = "synthetic-born-joined-qualification")]
        {
            *stage = DurableAdmissionPreparationStageV1::LiveInterval;
        }
        require_live(&request)?;
        let certificate = source
            .entry()
            .record()
            .account_record
            .terms
            .signer
            .owner_certificate_digest
            .clone();
        #[cfg(feature = "synthetic-born-joined-qualification")]
        {
            *stage = DurableAdmissionPreparationStageV1::LocalIntent;
        }
        let prepared = source
            .session()
            .prepare_durable_payment_admission_intent_v1(
                source.entry().journal(),
                request.clone(),
                source.entry().original_witness_disclosure()?,
                &certificate,
                source.enrollment_ref(),
                source.manifest_ref(),
            )?;
        #[cfg(feature = "synthetic-born-joined-qualification")]
        {
            *stage = DurableAdmissionPreparationStageV1::IntentDisplay;
        }
        let display = format!("Admit this ONE exact durable payment candidate\n\n{}\n\nDurable witness serving and reopen are expressly approved for ONLY this unchanged body and interval, independently of this short native/data-disclosure window. No per-admission revocation exists after commit: cancel acts before commit, and stopping a server does not erase the record. Account exclusion remains available. The witness receives only these minimal account/input/economics/candidate commitments, never keys, FVKs, PCZTs, notes, witnesses or memos. Original budgets and exposure remain. Once acquired, ONLY the same live client key/session may reconnect; key loss or expiry requires separate recovery, not replacement. Separate fresh signing approval is still required.",
            prepared.display()?);
        #[cfg(feature = "synthetic-born-joined-qualification")]
        {
            *stage = DurableAdmissionPreparationStageV1::ReviewCustody;
        }
        let custody = ReviewCustody::new(
            owner,
            source,
            &certificate,
            prepared.digest().into(),
            display,
        )?;
        Ok(Self {
            custody,
            request,
            prepared,
        })
    }
    pub(super) fn request(&self) -> &OwnerControlRequest {
        &self.request
    }
    pub(super) fn digest(&self) -> &str {
        &self.custody.digest
    }
    pub(super) fn display(&self) -> Result<String> {
        self.custody.display()
    }
    pub(super) fn approve(
        self,
        decision: NativeDecision,
        authority: &NativeAuthority,
        owner: &NativeWitnessWorkspace,
    ) -> Result<ApprovedDurableWitnessAdmissionV1> {
        self.custody.decision(&decision, authority, owner)?;
        require_request(&self.custody.source, &self.request)?;
        let decision = self.custody.source.session().native_decision(decision)?;
        let approved = self
            .custody
            .source
            .session()
            .approve_durable_payment_admission_intent_v1(self.prepared, decision)?;
        Ok(ApprovedDurableWitnessAdmissionV1 {
            custody: self.custody,
            request: self.request,
            approved,
        })
    }
}
impl ApprovedDurableWitnessAdmissionV1 {
    pub(super) fn retain(self) -> Result<DurableWitnessAdmissionDispatchV1> {
        self.retain_inner(
            #[cfg(feature = "synthetic-born-joined-qualification")]
            None,
        )
    }
    fn retain_inner(
        self,
        #[cfg(feature = "synthetic-born-joined-qualification")] mut first_error: Option<
            &mut Option<Error>,
        >,
    ) -> Result<DurableWitnessAdmissionDispatchV1> {
        self.custody.current()?;
        require_live(&self.request)?;
        let retained = self
            .custody
            .source
            .entry()
            .journal()
            .retain_durable_payment_admission_intent_v1(self.approved, || {
                if Instant::now() >= self.custody.deadline {
                    return Err(JournalError::Permission);
                }
                require_request_under_fence(&self.custody.source, &self.request).map_err(|_error| {
                    #[cfg(feature = "synthetic-born-joined-qualification")]
                    if let Some(first) = first_error.as_deref_mut() {
                        if first.is_none() {
                            *first = Some(_error);
                        }
                    }
                    JournalError::Permission
                })
            })?;
        if retained.request() != &self.request {
            return Err(Error::RecoveryRequired);
        }
        Ok(DurableWitnessAdmissionDispatchV1 {
            custody: self.custody,
            retained,
        })
    }
}
impl DurableWitnessAdmissionDispatchV1 {
    pub(super) fn submit(&self, owner: &NativeWitnessWorkspace) -> Result<AccountSnapshot> {
        self.submit_inner(
            owner,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            None,
        )
    }
    fn submit_inner(
        &self,
        owner: &NativeWitnessWorkspace,
        #[cfg(feature = "synthetic-born-joined-qualification")] mut observation: Option<
            &mut QualificationDurableAdmissionObservationV1,
        >,
    ) -> Result<AccountSnapshot> {
        #[cfg(feature = "synthetic-born-joined-qualification")]
        let started = admission_optional_clock(observation.is_some(), Instant::now);
        let preflight = (|| {
            #[cfg(feature = "synthetic-born-joined-qualification")]
            if let Some(value) = observation.as_deref_mut() {
                value.stage = DurableAdmissionDispatchStageV1::SubmitCustody;
            }
            self.custody.workspace(owner)?;
            #[cfg(feature = "synthetic-born-joined-qualification")]
            if let Some(value) = observation.as_deref_mut() {
                value.stage = DurableAdmissionDispatchStageV1::SubmitIntent;
            }
            require_intent(&self.custody.source, &self.retained)?;
            #[cfg(feature = "synthetic-born-joined-qualification")]
            if let Some(value) = observation.as_deref_mut() {
                value.stage = DurableAdmissionDispatchStageV1::SubmitInterval;
            }
            require_live(self.retained.request())
        })();
        #[cfg(feature = "synthetic-born-joined-qualification")]
        if let (Some(value), Some(started)) = (observation.as_deref_mut(), started) {
            value.measurement.submit_preflight_us = Some(admission_micros(
                started.elapsed(),
                &mut value.measurement.clamped,
            ));
        }
        preflight?;
        #[cfg(feature = "synthetic-born-joined-qualification")]
        if let Some(value) = observation {
            value.stage = DurableAdmissionDispatchStageV1::SubmitWorkspace;
            let mut failure = None;
            let result = owner.durable_admit_diagnosed_v1(
                self.retained.request(),
                self.custody.deadline,
                || {
                    self.custody.callback_current_v1(
                        owner,
                        self.retained.request(),
                        Some(&mut *value),
                    )
                },
                &mut failure,
            );
            if let Some((authority, callback, workspace_current)) = failure {
                value.stage = DurableAdmissionDispatchStageV1::AuthorityCall;
                let callback_stage = callback.as_ref().and_then(|_| {
                    if workspace_current {
                        Some(DurableAdmissionCallbackStageV1::WorkspaceCurrent)
                    } else {
                        value.callback_stage
                    }
                });
                value.call_failure = Some(DurableAdmissionCallFailureV1 {
                    authority,
                    callback,
                    callback_stage,
                });
            }
            return result;
        }
        owner.durable_admit_v1(self.retained.request(), self.custody.deadline, || {
            self.custody.callback_current_v1(
                owner,
                self.retained.request(),
                #[cfg(feature = "synthetic-born-joined-qualification")]
                None,
            )
        })
    }
}

pub(super) struct PreparedDurableWriterSessionV1 {
    #[cfg(feature = "synthetic-born-joined-qualification")]
    flow_observer: Option<flow_diag_v1::DurableFlowObserverV1>,
    custody: ReviewCustody,
    history: ReconciledAuthorityHistory,
    admission: OwnerControlRequest,
}
pub(super) struct ApprovedDurableWriterSessionV1(PreparedDurableWriterSessionV1);
impl PreparedDurableWriterSessionV1 {
    pub(super) fn prepare(
        workspace: &NativeWitnessWorkspace,
        source: Arc<DurableWitnessImportedSourceV1>,
        admission_operation_id: &str,
    ) -> Result<Self> {
        Self::prepare_inner(
            workspace,
            source,
            admission_operation_id,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            None,
        )
    }
    pub(super) fn prepare_inner(
        workspace: &NativeWitnessWorkspace,
        source: Arc<DurableWitnessImportedSourceV1>,
        admission_operation_id: &str,
        #[cfg(feature = "synthetic-born-joined-qualification")] observer: Option<
            &flow_diag_v1::DurableFlowObserverV1,
        >,
    ) -> Result<Self> {
        source.check_current_inner(
            #[cfg(feature = "synthetic-born-joined-qualification")]
            observer,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            flow_diag_v1::DurableFlowStageV1::AcquirePrepare,
        )?;
        let history = source_history_inner(
            workspace,
            &source,
            CredentialRole::Writer,
            source.deadline()?,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            None,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            observer,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            flow_diag_v1::DurableFlowStageV1::AcquirePrepare,
        )?;
        let intent = committed_intent(&source, &history, admission_operation_id)?;
        let admission = intent.request().clone();
        require_live(&admission)?;
        let OwnerControl::AdmitDurablePaymentV1 { record } = &admission.control else {
            return Err(Error::ReviewMismatch);
        };
        let acquire = record
            .acquire_operation_id(&admission)
            .map_err(|_| Error::ReviewMismatch)?;
        if history.contains_operation(&acquire)
            || history.snapshot().pending_writer_session.is_some()
            || history.snapshot().active_writer_session.is_some()
        {
            return Err(Error::RecoveryRequired);
        }
        let certificate = record.terms.writer_certificate_digest.clone();
        let digest = canonical(
            "wholepact:native-durable-payment-writer-acquire:v1",
            &(
                &admission,
                &acquire,
                history
                    .history_digest()
                    .map_err(|_| Error::ReviewMismatch)?,
                history.snapshot(),
                history.disclosure(),
                &certificate,
                source.enrollment_ref(),
                source.manifest_ref(),
            ),
        )?;
        let display = format!("Acquire the ONE admission-derived writer session\n\n{}\n\nThis uses the actually enrolled writer certificate and one in-memory client key. It cannot sign yet. Exact reconnect and retry keep this same client, original head and key. After session loss or expiry, no replacement is allowed. Every previous exposure stays retained.",
            serde_json::to_string_pretty(&(&admission,&acquire,history.snapshot())).map_err(|_| Error::InvalidData)?);
        let custody = ReviewCustody::new(workspace, source, &certificate, digest, display)?;
        Ok(Self {
            #[cfg(feature = "synthetic-born-joined-qualification")]
            flow_observer: observer.cloned(),
            custody,
            history,
            admission,
        })
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub(super) fn qualification_correlation_v1(&self) -> Result<(Instant, String)> {
        Ok((
            self.custody.deadline,
            self.history
                .history_digest()
                .map_err(|_| Error::ReviewMismatch)?,
        ))
    }
    pub(super) fn digest(&self) -> &str {
        &self.custody.digest
    }
    pub(super) fn display(&self) -> Result<String> {
        self.custody.display()
    }
    pub(super) fn approve(
        self,
        decision: NativeDecision,
        authority: &NativeAuthority,
        workspace: &NativeWitnessWorkspace,
    ) -> Result<ApprovedDurableWriterSessionV1> {
        self.custody.decision(&decision, authority, workspace)?;
        require_request(&self.custody.source, &self.admission)?;
        Ok(ApprovedDurableWriterSessionV1(self))
    }
}
impl ApprovedDurableWriterSessionV1 {
    pub(super) fn acquire(
        &self,
        workspace: &NativeWitnessWorkspace,
    ) -> Result<WriterSessionReceipt> {
        self.acquire_inner(
            workspace,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            None,
        )
    }
    pub(super) fn acquire_inner(
        &self,
        workspace: &NativeWitnessWorkspace,
        #[cfg(feature = "synthetic-born-joined-qualification")] observer: Option<
            &flow_diag_v1::DurableFlowObserverV1,
        >,
    ) -> Result<WriterSessionReceipt> {
        self.0.custody.workspace(workspace)?;
        require_live(&self.0.admission)?;
        // NEVER refresh history/head on retry: this exact captured pre-acquire
        // history belongs to the same actual client and its retained key.
        let check = || {
            self.0.custody.callback_current_v1(
                workspace,
                &self.0.admission,
                #[cfg(feature = "synthetic-born-joined-qualification")]
                None,
            )
        };
        #[cfg(feature = "synthetic-born-joined-qualification")]
        {
            workspace.durable_acquire_observed_v1(
                &self.0.history,
                &self.0.admission.operation_id,
                self.0.custody.deadline,
                check,
                observer,
            )
        }
        #[cfg(not(feature = "synthetic-born-joined-qualification"))]
        {
            workspace.durable_acquire_v1(
                &self.0.history,
                &self.0.admission.operation_id,
                self.0.custody.deadline,
                check,
            )
        }
    }
}

pub(super) struct PreparedDurableWriterActivationV1 {
    #[cfg(feature = "synthetic-born-joined-qualification")]
    flow_observer: Option<flow_diag_v1::DurableFlowObserverV1>,
    custody: ReviewCustody,
    history: ReconciledAuthorityHistory,
    admission: OwnerControlRequest,
    request: OwnerControlRequest,
}
pub(super) struct ApprovedDurableWriterActivationV1(PreparedDurableWriterActivationV1);
impl PreparedDurableWriterActivationV1 {
    pub(super) fn prepare(
        owner: &NativeWitnessWorkspace,
        source: Arc<DurableWitnessImportedSourceV1>,
        admission_operation_id: &str,
        receipt: WriterSessionReceipt,
    ) -> Result<Self> {
        Self::prepare_inner(
            owner,
            source,
            admission_operation_id,
            receipt,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            None,
        )
    }
    pub(super) fn prepare_inner(
        owner: &NativeWitnessWorkspace,
        source: Arc<DurableWitnessImportedSourceV1>,
        admission_operation_id: &str,
        receipt: WriterSessionReceipt,
        #[cfg(feature = "synthetic-born-joined-qualification")] observer: Option<
            &flow_diag_v1::DurableFlowObserverV1,
        >,
    ) -> Result<Self> {
        source.check_current_inner(
            #[cfg(feature = "synthetic-born-joined-qualification")]
            observer,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            flow_diag_v1::DurableFlowStageV1::ActivationPrepare,
        )?;
        let history = source_history_inner(
            owner,
            &source,
            CredentialRole::Owner,
            source.deadline()?,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            None,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            observer,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            flow_diag_v1::DurableFlowStageV1::ActivationPrepare,
        )?;
        let intent = committed_intent(&source, &history, admission_operation_id)?;
        let admission = intent.request().clone();
        require_live(&admission)?;
        if history.snapshot().pending_writer_session.as_ref() != Some(&receipt)
            || history.snapshot().head != receipt.acquired_head
            || receipt.disclosure != *history.disclosure()
            || receipt.writer_certificate_digest
                != admission_terms(&admission)?.writer_certificate_digest
        {
            return Err(Error::RecoveryRequired);
        }
        let request = OwnerControlRequest {
            operation_id: canonical(
                "wholepact:durable-payment-owner-activation-operation:v1",
                &(&admission, &receipt, history.snapshot()),
            )?,
            account_id: history.snapshot().account_id.clone(),
            network_profile_id: history.snapshot().network_profile_id.clone(),
            expected_head: history.snapshot().head.clone(),
            writer_epoch: history.snapshot().writer_epoch,
            control: OwnerControl::ActivateWriter {
                session_id: receipt.session_id.clone(),
            },
        };
        let certificate = history.account_policy().owner_certificate_digest.clone();
        let digest = canonical(
            "wholepact:native-durable-payment-writer-activation:v1",
            &(
                &request,
                &admission,
                &receipt,
                &certificate,
                history
                    .history_digest()
                    .map_err(|_| Error::ReviewMismatch)?,
                source.enrollment_ref(),
                source.manifest_ref(),
            ),
        )?;
        let display = format!("Original owner: activate this EXACT durable writer session\n\n{}\n\nThis uses the separately enrolled original owner's actual mTLS credential, not the writer key. It approves only this exact pending session/head under the unchanged admitted candidate and limits. No replacement session, signing, budget increase, settlement or refund is authorized.",
            serde_json::to_string_pretty(&(&request,&admission,&receipt)).map_err(|_| Error::InvalidData)?);
        let custody = ReviewCustody::new(owner, source, &certificate, digest, display)?;
        Ok(Self {
            #[cfg(feature = "synthetic-born-joined-qualification")]
            flow_observer: observer.cloned(),
            custody,
            history,
            admission,
            request,
        })
    }
    pub(super) fn digest(&self) -> &str {
        &self.custody.digest
    }
    pub(super) fn display(&self) -> Result<String> {
        self.custody.display()
    }
    pub(super) fn approve(
        self,
        decision: NativeDecision,
        authority: &NativeAuthority,
        owner: &NativeWitnessWorkspace,
    ) -> Result<ApprovedDurableWriterActivationV1> {
        self.custody.decision(&decision, authority, owner)?;
        require_request(&self.custody.source, &self.admission)?;
        Ok(ApprovedDurableWriterActivationV1(self))
    }
}
impl ApprovedDurableWriterActivationV1 {
    pub(super) fn activate(&self, owner: &NativeWitnessWorkspace) -> Result<AccountSnapshot> {
        self.activate_inner(
            owner,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            None,
        )
    }
    pub(super) fn activate_inner(
        &self,
        owner: &NativeWitnessWorkspace,
        #[cfg(feature = "synthetic-born-joined-qualification")] observer: Option<
            &flow_diag_v1::DurableFlowObserverV1,
        >,
    ) -> Result<AccountSnapshot> {
        self.0.custody.workspace(owner)?;
        require_live(&self.0.admission)?;
        let check = || {
            self.0.custody.callback_current_v1(
                owner,
                &self.0.admission,
                #[cfg(feature = "synthetic-born-joined-qualification")]
                None,
            )
        };
        #[cfg(feature = "synthetic-born-joined-qualification")]
        {
            owner.durable_activate_observed_v1(
                &self.0.history,
                &self.0.admission.operation_id,
                &self.0.request,
                self.0.custody.deadline,
                check,
                observer,
            )
        }
        #[cfg(not(feature = "synthetic-born-joined-qualification"))]
        {
            owner.durable_activate_v1(
                &self.0.history,
                &self.0.admission.operation_id,
                &self.0.request,
                self.0.custody.deadline,
                check,
            )
        }
    }
}

pub(super) struct PreparedDurableWriterReconciliationV1 {
    #[cfg(feature = "synthetic-born-joined-qualification")]
    flow_observer: Option<flow_diag_v1::DurableFlowObserverV1>,
    source: Arc<DurableWitnessImportedSourceV1>,
    admission: OwnerControlRequest,
    prepared: PreparedWriterReconciliation,
    deadline: Instant,
}
pub(super) struct ApprovedDurableWriterReconciliationV1 {
    source: Arc<DurableWitnessImportedSourceV1>,
    admission: OwnerControlRequest,
    approved: ApprovedWriterReconciliation,
    deadline: Instant,
    review_digest: String,
}
pub(super) enum DurableReconciliationOutcomeV1 {
    Committed { review_digest: String },
    Uncertain { review_digest: String },
}
impl PreparedDurableWriterReconciliationV1 {
    pub(super) fn prepare(
        workspace: &NativeWitnessWorkspace,
        source: Arc<DurableWitnessImportedSourceV1>,
        admission_operation_id: &str,
    ) -> Result<Self> {
        Self::prepare_inner(
            workspace,
            source,
            admission_operation_id,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            None,
        )
    }
    pub(super) fn prepare_inner(
        workspace: &NativeWitnessWorkspace,
        source: Arc<DurableWitnessImportedSourceV1>,
        admission_operation_id: &str,
        #[cfg(feature = "synthetic-born-joined-qualification")] observer: Option<
            &flow_diag_v1::DurableFlowObserverV1,
        >,
    ) -> Result<Self> {
        source.check_current_inner(
            #[cfg(feature = "synthetic-born-joined-qualification")]
            observer,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            flow_diag_v1::DurableFlowStageV1::ReconcilePrepare,
        )?;
        let deadline = source
            .deadline()?
            .min(Instant::now() + Duration::from_secs(120));
        let history = source_history_inner(
            workspace,
            &source,
            CredentialRole::Writer,
            deadline,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            None,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            observer,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            flow_diag_v1::DurableFlowStageV1::ReconcilePrepare,
        )?;
        let intent = committed_intent(&source, &history, admission_operation_id)?;
        workspace.require_durable_credential_v1(
            &source.entry().native_binding(),
            history.disclosure(),
            &admission_terms(intent.request())?.writer_certificate_digest,
        )?;
        #[cfg(feature = "synthetic-born-joined-qualification")]
        let active = workspace.durable_active_observed_v1(
            &history,
            admission_operation_id,
            deadline,
            || {
                source.check_current_inner(
                    observer,
                    flow_diag_v1::DurableFlowStageV1::ActiveVerification,
                )
            },
            observer,
        )?;
        #[cfg(not(feature = "synthetic-born-joined-qualification"))]
        let active =
            workspace.durable_active_v1(&history, admission_operation_id, deadline, || {
                source.check_current()
            })?;
        history
            .require_durable_payment_session_v1(admission_operation_id, &active)
            .map_err(|_| Error::RecoveryRequired)?;
        let prepared = source
            .session()
            .prepare_durable_payment_writer_reconciliation_v1(
                source.entry().journal(),
                history,
                active,
                &intent,
            )?;
        source.check_current_inner(
            #[cfg(feature = "synthetic-born-joined-qualification")]
            observer,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            flow_diag_v1::DurableFlowStageV1::ReconcilePrepare,
        )?;
        Ok(Self {
            #[cfg(feature = "synthetic-born-joined-qualification")]
            flow_observer: observer.cloned(),
            source,
            admission: intent.request().clone(),
            prepared,
            deadline,
        })
    }
    pub(super) fn digest(&self) -> &str {
        self.prepared.review_digest()
    }
    pub(super) fn display(&self) -> Result<String> {
        self.source.check_current()?;
        if Instant::now() >= self.deadline {
            return Err(Error::ReviewMismatch);
        }
        Ok(format!("{}\n\nCompletion intentionally invalidates the current local session, enrollment/manifest references and imported data permission. Before signing: wait for actual revocation to drain, obtain a fresh native enrollment/manifest and exact redisclosure, and import the unchanged candidate again. The original owner deadline stays fixed; no old references or receipts are rewritten.",self.prepared.display()?))
    }
    pub(super) fn approve(
        self,
        decision: NativeDecision,
    ) -> Result<ApprovedDurableWriterReconciliationV1> {
        self.source.check_current()?;
        if Instant::now() >= self.deadline
            || decision.binding() != &self.source.entry().native_binding()
            || decision.reviewed_digest() != self.prepared.review_digest()
        {
            return Err(Error::ReviewMismatch);
        }
        let review_digest = self.prepared.review_digest().into();
        let decision = self.source.session().native_decision(decision)?;
        let approved = self
            .source
            .session()
            .approve_writer_reconciliation(self.prepared, decision)?;
        Ok(ApprovedDurableWriterReconciliationV1 {
            source: self.source,
            admission: self.admission,
            approved,
            deadline: self.deadline,
            review_digest,
        })
    }
}
impl ApprovedDurableWriterReconciliationV1 {
    pub(super) fn reconcile(self) -> Result<DurableReconciliationOutcomeV1> {
        self.reconcile_inner(
            #[cfg(feature = "synthetic-born-joined-qualification")]
            None,
        )
    }
    fn reconcile_inner(
        self,
        #[cfg(feature = "synthetic-born-joined-qualification")] observer: Option<
            &flow_diag_v1::DurableFlowObserverV1,
        >,
    ) -> Result<DurableReconciliationOutcomeV1> {
        self.source.check_current()?;
        require_request(&self.source, &self.admission)?;
        if Instant::now() >= self.deadline {
            return Err(Error::ReviewMismatch);
        }
        let result = durable_flow_call_v1!(
            observer,
            flow_diag_v1::DurableFlowCallV1::Reconciliation,
            flow_diag_v1::DurableFlowStageV1::ReconcileCall,
            self.source
                .entry()
                .journal()
                .reconcile_writer_checked_v1(self.approved, || {
                    if Instant::now() >= self.deadline {
                        return Err(JournalError::Permission);
                    }
                    durable_flow_observe_v1!(
                        observer,
                        flow_diag_v1::DurableFlowStageV1::ReconcileCall,
                        require_request_under_fence(&self.source, &self.admission)
                    )
                    .map_err(|_| JournalError::Permission)
                })
        );
        // No post-invalidation current-source assertion. Committed/uncertain
        // outcomes are inert evidence, never continuation of the old import.
        // Even uncertainty drains local permission; it never resets remote state.
        finish_durable_reconciliation_v1(
            result,
            self.review_digest,
            || self.source.session().invalidate(),
            #[cfg(feature = "synthetic-born-joined-qualification")]
            observer,
        )
    }
}

// The actual reconciliation result mapping. An invalidation refusal or uncertain
// database result remains Ok(Uncertain), not a newly invented operational Err.
fn finish_durable_reconciliation_v1<T>(
    result: std::result::Result<T, JournalError>,
    review_digest: String,
    invalidate: impl FnOnce() -> std::result::Result<(), JournalError>,
    #[cfg(feature = "synthetic-born-joined-qualification")] observer: Option<
        &flow_diag_v1::DurableFlowObserverV1,
    >,
) -> Result<DurableReconciliationOutcomeV1> {
    match result {
        Ok(_) => {
            let invalidated = durable_flow_call_v1!(
                observer,
                flow_diag_v1::DurableFlowCallV1::SessionInvalidation,
                flow_diag_v1::DurableFlowStageV1::Invalidate,
                invalidate()
            );
            Ok(if invalidated.is_ok() {
                DurableReconciliationOutcomeV1::Committed {
                    review_digest: review_digest,
                }
            } else {
                DurableReconciliationOutcomeV1::Uncertain {
                    review_digest: review_digest,
                }
            })
        }
        Err(JournalError::Database) => {
            let _ = durable_flow_call_v1!(
                observer,
                flow_diag_v1::DurableFlowCallV1::SessionInvalidation,
                flow_diag_v1::DurableFlowStageV1::Invalidate,
                invalidate()
            );
            Ok(DurableReconciliationOutcomeV1::Uncertain {
                review_digest: review_digest,
            })
        }
        // Proven pre-commit refusal leaves the original source intact.
        Err(error) => Err(error.into()),
    }
}

/// Per-open owner state. Dropping it never deletes the immutable SQL intent or
/// any remote exposure. A new owner must resolve original authenticated history.
#[derive(Default)]
pub(super) struct DurableWitnessRuntimeV1 {
    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub(super) flow_observation: Option<flow_diag_v1::DurableFlowObserverV1>,
    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub(super) flow_import: Option<super::durable_review_v1::DurableFlowImportExpectationV1>,
    admission_id: Option<String>,
    admission_retry: Option<Arc<DurableWitnessAdmissionDispatchV1>>,
    session_retry: Option<Arc<ApprovedDurableWriterSessionV1>>,
    activation_retry: Option<Arc<ApprovedDurableWriterActivationV1>>,
    #[cfg(feature = "synthetic-born-joined-qualification")]
    qualification_completion: Option<(String, QualificationDurableWitnessCompletionV1)>,
    #[cfg(feature = "synthetic-born-joined-qualification")]
    qualification_preparation: QualificationDurablePreparationV1,
    #[cfg(feature = "synthetic-born-joined-qualification")]
    qualification_admission: QualificationDurableAdmissionV1,
    #[cfg(feature = "synthetic-born-joined-qualification")]
    qualification_session: QualificationSessionV1,
}
// Inert per-dispatch evidence only. A review digest is deliberately insufficient:
// the first Acquire and its genuine retry share the same approved review.
#[cfg(feature = "synthetic-born-joined-qualification")]
#[derive(Clone)]
pub(super) struct QualificationSessionAttemptV1 {
    serial: u64,
    digest: String,
    observer: flow_diag_v1::DurableFlowObserverV1,
}
#[cfg(feature = "synthetic-born-joined-qualification")]
#[derive(Default)]
struct QualificationSessionV1 {
    next: u64,
    active: Option<QualificationSessionAttemptV1>,
    dispatched: bool,
    accepted: Option<bool>,
    error: Option<Error>,
}
#[cfg(feature = "synthetic-born-joined-qualification")]
impl QualificationSessionV1 {
    fn begin(
        &mut self,
        observer: &flow_diag_v1::DurableFlowObserverV1,
        digest: &str,
    ) -> Option<u64> {
        self.active = None;
        self.dispatched = false;
        self.accepted = None;
        self.error = None;
        let serial = self.next.checked_add(1)?;
        self.next = serial;
        self.active = Some(QualificationSessionAttemptV1 {
            serial,
            digest: digest.into(),
            observer: observer.clone(),
        });
        Some(serial)
    }
    fn dispatch(
        &mut self,
        observer: Option<&flow_diag_v1::DurableFlowObserverV1>,
        digest: &str,
    ) -> Option<QualificationSessionAttemptV1> {
        let active = self.active.as_ref()?;
        if self.dispatched
            || active.digest != digest
            || !observer.is_some_and(|observer| active.observer.same_attempt(observer))
        {
            return None;
        }
        self.dispatched = true;
        Some(active.clone())
    }
    fn matches(&self, serial: u64, digest: &str) -> bool {
        self.active.as_ref().is_some_and(|active| {
            active.serial == serial
                && active.digest == digest
                && active.observer.same_attempt(&active.observer)
        })
    }
    fn accept(
        &mut self,
        attempt: Option<QualificationSessionAttemptV1>,
        observer: Option<&flow_diag_v1::DurableFlowObserverV1>,
        digest: &str,
        error: Option<Error>,
    ) {
        let Some(attempt) = attempt else {
            return;
        };
        if self.accepted.is_some()
            || !self.dispatched
            || !self.matches(attempt.serial, digest)
            || attempt.digest != digest
            || !observer.is_some_and(|observer| attempt.observer.same_attempt(observer))
            || !self
                .active
                .as_ref()
                .is_some_and(|active| active.observer.same_attempt(&attempt.observer))
        {
            return;
        }
        self.accepted = Some(error.is_none());
        self.error = error;
    }
    fn absent(&mut self) {
        self.active = None;
        self.dispatched = false;
        self.accepted = None;
        self.error = None;
    }
    fn take_error(&mut self, serial: u64, digest: &str) -> Option<Error> {
        if self.matches(serial, digest) && self.accepted == Some(false) {
            self.error.take()
        } else {
            None
        }
    }
}
/// Closed synthetic diagnostics. These names carry no request or private data.
#[cfg(feature = "synthetic-born-joined-qualification")]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DurableAdmissionPreparationStageV1 {
    FixtureState,
    Source,
    History,
    RetainedIntent,
    Terms,
    RequestBuilder,
    ExactRequest,
    LiveInterval,
    LocalIntent,
    IntentDisplay,
    ReviewCustody,
    ReviewDisplay,
    NativeStage,
    WorkerCompletion,
}
#[cfg(feature = "synthetic-born-joined-qualification")]
pub struct DurableAdmissionPreparationFailureV1 {
    stage: DurableAdmissionPreparationStageV1,
    error: Error,
    history: Option<DurableAdmissionHistoryFailureV1>,
}
#[cfg(feature = "synthetic-born-joined-qualification")]
impl DurableAdmissionPreparationFailureV1 {
    pub(super) fn new(stage: DurableAdmissionPreparationStageV1, error: Error) -> Self {
        Self {
            stage,
            error,
            history: None,
        }
    }
    pub fn stage(&self) -> DurableAdmissionPreparationStageV1 {
        self.stage
    }
    pub fn into_error(self) -> Error {
        self.error
    }
    pub fn take_history_failure(&mut self) -> Option<DurableAdmissionHistoryFailureV1> {
        self.history.take()
    }
}
/// Inert error evidence from one actual checked history read. It cannot start a
/// request, expose history, restore a source or alter the main refusal result.
#[cfg(feature = "synthetic-born-joined-qualification")]
pub struct DurableAdmissionHistoryFailureV1 {
    authority: CheckedHistoryFailureV1,
    callback: Option<Error>,
}
#[cfg(feature = "synthetic-born-joined-qualification")]
impl DurableAdmissionHistoryFailureV1 {
    pub fn stage(&self) -> CheckedHistoryStageV1 {
        self.authority.stage()
    }
    pub fn io_kind(&self) -> Option<CheckedHistoryIoKindV1> {
        self.authority.io_kind()
    }
    pub fn measurement(&self) -> &CheckedHistoryMeasurementV1 {
        self.authority.measurement()
    }
    pub fn into_errors(self) -> (wholepact_authority::AuthorityError, Option<Error>) {
        (self.authority.into_error(), self.callback)
    }
}
#[cfg(feature = "synthetic-born-joined-qualification")]
#[derive(Default)]
struct QualificationDurablePreparationV1 {
    sequence: u64,
    active: Option<u64>,
    native_stage: Option<u64>,
    failure: Option<(u64, DurableAdmissionPreparationFailureV1)>,
    failure_seen: bool,
}
#[cfg(feature = "synthetic-born-joined-qualification")]
impl QualificationDurablePreparationV1 {
    fn begin(&mut self) -> Option<u64> {
        self.failure = None;
        self.failure_seen = false;
        self.native_stage = None;
        self.active = self.sequence.checked_add(1);
        if let Some(next) = self.active {
            self.sequence = next;
        }
        self.active
    }
    fn record(
        &mut self,
        attempt: Option<u64>,
        stage: DurableAdmissionPreparationStageV1,
        error: Error,
    ) {
        self.record_with_history(attempt, stage, error, None);
    }
    fn record_with_history(
        &mut self,
        attempt: Option<u64>,
        stage: DurableAdmissionPreparationStageV1,
        error: Error,
        history: Option<DurableAdmissionHistoryFailureV1>,
    ) {
        if let Some(attempt) = attempt.filter(|id| Some(*id) == self.active) {
            if !self.failure_seen {
                self.failure_seen = true;
                self.failure = Some((
                    attempt,
                    DurableAdmissionPreparationFailureV1 {
                        stage,
                        error,
                        history,
                    },
                ));
            }
        }
    }
    fn take(&mut self, attempt: u64) -> Option<DurableAdmissionPreparationFailureV1> {
        if self.active == Some(attempt)
            && self.failure.as_ref().is_some_and(|(id, _)| *id == attempt)
        {
            self.failure.take().map(|(_, failure)| failure)
        } else {
            None
        }
    }
}
/// Finite, inert observations of one exact approval attempt. These never carry
/// native custody, extend its lifetime, or authorize another operation.
#[cfg(feature = "synthetic-born-joined-qualification")]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DurableAdmissionDispatchStageV1 {
    FixtureState,
    ReviewCorrelation,
    NativeApproval,
    IntentRetention,
    SubmitCustody,
    SubmitIntent,
    SubmitInterval,
    SubmitWorkspace,
    AuthorityCall,
    WorkerCompletion,
    CommittedCorrelation,
}
#[cfg(feature = "synthetic-born-joined-qualification")]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DurableAdmissionCompletionV1 {
    NotObserved,
    ReturnedOk,
    ReturnedErr,
    Missing,
    Invalidated,
    Disconnected,
}
#[cfg(feature = "synthetic-born-joined-qualification")]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DurableAdmissionRetentionV1 {
    NotObserved,
    Unconfirmed,
    Confirmed,
}
#[cfg(feature = "synthetic-born-joined-qualification")]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DurableAdmissionCallbackStageV1 {
    WorkspaceCurrent,
    Custody,
    RequestValidation,
}
#[cfg(feature = "synthetic-born-joined-qualification")]
#[derive(Default)]
pub struct DurableAdmissionDispatchMeasurementV1 {
    native_approval_us: Option<u32>,
    retention_us: Option<u32>,
    submit_preflight_us: Option<u32>,
    callback_custody_calls: Option<u32>,
    callback_custody_us: Option<u32>,
    callback_custody_max_us: Option<u32>,
    request_validation_calls: Option<u32>,
    request_validation_us: Option<u32>,
    request_validation_max_us: Option<u32>,
    clamped: bool,
    incomplete: bool,
}
#[cfg(feature = "synthetic-born-joined-qualification")]
impl DurableAdmissionDispatchMeasurementV1 {
    pub fn native_approval_us(&self) -> Option<u32> {
        self.native_approval_us
    }
    pub fn retention_us(&self) -> Option<u32> {
        self.retention_us
    }
    pub fn submit_preflight_us(&self) -> Option<u32> {
        self.submit_preflight_us
    }
    pub fn callback_custody_calls(&self) -> Option<u32> {
        self.callback_custody_calls
    }
    pub fn callback_custody_us(&self) -> Option<u32> {
        self.callback_custody_us
    }
    pub fn callback_custody_max_us(&self) -> Option<u32> {
        self.callback_custody_max_us
    }
    pub fn request_validation_calls(&self) -> Option<u32> {
        self.request_validation_calls
    }
    pub fn request_validation_us(&self) -> Option<u32> {
        self.request_validation_us
    }
    pub fn request_validation_max_us(&self) -> Option<u32> {
        self.request_validation_max_us
    }
    pub fn clamped(&self) -> bool {
        self.clamped
    }
    pub fn incomplete(&self) -> bool {
        self.incomplete
    }
}
#[cfg(feature = "synthetic-born-joined-qualification")]
pub struct DurableAdmissionCallFailureV1 {
    authority: CheckedHistoryFailureV1,
    callback: Option<Error>,
    callback_stage: Option<DurableAdmissionCallbackStageV1>,
}
#[cfg(feature = "synthetic-born-joined-qualification")]
impl DurableAdmissionCallFailureV1 {
    pub fn stage(&self) -> CheckedHistoryStageV1 {
        self.authority.stage()
    }
    pub fn io_kind(&self) -> Option<CheckedHistoryIoKindV1> {
        self.authority.io_kind()
    }
    pub fn measurement(&self) -> &CheckedHistoryMeasurementV1 {
        self.authority.measurement()
    }
    pub fn callback_stage(&self) -> Option<DurableAdmissionCallbackStageV1> {
        self.callback_stage
    }
    pub fn into_errors(self) -> (wholepact_authority::AuthorityError, Option<Error>) {
        (self.authority.into_error(), self.callback)
    }
}
#[cfg(feature = "synthetic-born-joined-qualification")]
pub struct DurableAdmissionDispatchFailureV1 {
    stage: DurableAdmissionDispatchStageV1,
    error: Error,
    original_error: Option<Error>,
    original_is_operational: bool,
    completion: DurableAdmissionCompletionV1,
    retention: DurableAdmissionRetentionV1,
    measurement: Option<DurableAdmissionDispatchMeasurementV1>,
    call_failure: Option<DurableAdmissionCallFailureV1>,
}
#[cfg(feature = "synthetic-born-joined-qualification")]
impl DurableAdmissionDispatchFailureV1 {
    pub fn stage(&self) -> DurableAdmissionDispatchStageV1 {
        self.stage
    }
    pub fn completion(&self) -> DurableAdmissionCompletionV1 {
        self.completion
    }
    pub fn retention(&self) -> DurableAdmissionRetentionV1 {
        self.retention
    }
    pub fn original_error(&self) -> Option<&Error> {
        self.original_error
            .as_ref()
            .or_else(|| self.original_is_operational.then_some(&self.error))
    }
    pub fn measurement(&self) -> Option<&DurableAdmissionDispatchMeasurementV1> {
        self.measurement.as_ref()
    }
    pub fn call_failure(&self) -> Option<&DurableAdmissionCallFailureV1> {
        self.call_failure.as_ref()
    }
    pub fn take_call_failure(&mut self) -> Option<DurableAdmissionCallFailureV1> {
        self.call_failure.take()
    }
    pub fn into_error(self) -> Error {
        self.error
    }
    pub(super) fn new(
        stage: DurableAdmissionDispatchStageV1,
        error: Error,
        original_is_operational: bool,
    ) -> Self {
        Self {
            stage,
            error,
            original_error: None,
            original_is_operational,
            completion: DurableAdmissionCompletionV1::NotObserved,
            retention: DurableAdmissionRetentionV1::NotObserved,
            measurement: None,
            call_failure: None,
        }
    }
}
#[cfg(feature = "synthetic-born-joined-qualification")]
fn admission_optional_clock(observed: bool, now: impl FnOnce() -> Instant) -> Option<Instant> {
    observed.then(now)
}
#[cfg(feature = "synthetic-born-joined-qualification")]
fn admission_micros(elapsed: Duration, clamped: &mut bool) -> u32 {
    const MAX: u128 = 600_000_000;
    *clamped |= elapsed.as_micros() > MAX;
    elapsed.as_micros().min(MAX) as u32
}
#[cfg(feature = "synthetic-born-joined-qualification")]
fn admission_callback_cost(
    calls: &mut Option<u32>,
    total: &mut Option<u32>,
    maximum: &mut Option<u32>,
    elapsed: Duration,
    clamped: &mut bool,
) {
    let count = u64::from(calls.unwrap_or(0)) + 1;
    *clamped |= count > 1_000_000;
    *calls = Some(count.min(1_000_000) as u32);
    let micros = admission_micros(elapsed, clamped);
    let sum = u64::from(total.unwrap_or(0)) + u64::from(micros);
    *clamped |= sum > 600_000_000;
    *total = Some(sum.min(600_000_000) as u32);
    *maximum = Some(maximum.unwrap_or(0).max(micros));
}
#[cfg(feature = "synthetic-born-joined-qualification")]
pub(super) struct QualificationDurableAdmissionObservationV1 {
    attempt: u64,
    digest: String,
    stage: DurableAdmissionDispatchStageV1,
    first_error: Option<Error>,
    completion: DurableAdmissionCompletionV1,
    retention: DurableAdmissionRetentionV1,
    measurement: DurableAdmissionDispatchMeasurementV1,
    call_failure: Option<DurableAdmissionCallFailureV1>,
    callback_stage: Option<DurableAdmissionCallbackStageV1>,
}
#[cfg(feature = "synthetic-born-joined-qualification")]
impl QualificationDurableAdmissionObservationV1 {
    fn new(attempt: u64, digest: String) -> Self {
        Self {
            attempt,
            digest,
            stage: DurableAdmissionDispatchStageV1::NativeApproval,
            first_error: None,
            completion: DurableAdmissionCompletionV1::NotObserved,
            retention: DurableAdmissionRetentionV1::NotObserved,
            measurement: Default::default(),
            call_failure: None,
            callback_stage: None,
        }
    }
    fn callback<T>(
        &mut self,
        stage: DurableAdmissionCallbackStageV1,
        call: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        self.callback_stage = Some(stage);
        let started = Instant::now();
        let result = call();
        let elapsed = started.elapsed();
        let m = &mut self.measurement;
        match stage {
            DurableAdmissionCallbackStageV1::Custody => admission_callback_cost(
                &mut m.callback_custody_calls,
                &mut m.callback_custody_us,
                &mut m.callback_custody_max_us,
                elapsed,
                &mut m.clamped,
            ),
            DurableAdmissionCallbackStageV1::RequestValidation => admission_callback_cost(
                &mut m.request_validation_calls,
                &mut m.request_validation_us,
                &mut m.request_validation_max_us,
                elapsed,
                &mut m.clamped,
            ),
            DurableAdmissionCallbackStageV1::WorkspaceCurrent => {}
        }
        result
    }
}
#[cfg(feature = "synthetic-born-joined-qualification")]
#[derive(Default)]
struct QualificationDurableAdmissionV1 {
    sequence: u64,
    active: Option<(u64, String)>,
    observation: Option<QualificationDurableAdmissionObservationV1>,
    native_approval_us: Option<u32>,
    native_clamped: bool,
    taken: bool,
}
#[cfg(feature = "synthetic-born-joined-qualification")]
impl QualificationDurableAdmissionV1 {
    fn reset(&mut self) {
        self.active = None;
        self.observation = None;
        self.native_approval_us = None;
        self.native_clamped = false;
        self.taken = false;
    }
    fn begin(&mut self, digest: String) -> Option<u64> {
        self.reset();
        let next = self.sequence.checked_add(1)?;
        self.sequence = next;
        self.active = Some((next, digest));
        Some(next)
    }
    fn worker(&self, digest: &str) -> Option<QualificationDurableAdmissionObservationV1> {
        self.active
            .as_ref()
            .filter(|(_, actual)| actual == digest && !self.taken)
            .map(|(attempt, digest)| {
                QualificationDurableAdmissionObservationV1::new(*attempt, digest.clone())
            })
    }
    fn record(
        &mut self,
        observation: Option<QualificationDurableAdmissionObservationV1>,
        completion: DurableAdmissionCompletionV1,
        dispatch_confirmed: bool,
        error: Option<Error>,
    ) {
        let Some(mut observation) = observation else {
            return;
        };
        if self.taken
            || self.observation.is_some()
            || !self.active.as_ref().is_some_and(|(attempt, digest)| {
                *attempt == observation.attempt && digest == &observation.digest
            })
        {
            return;
        }
        observation.completion = completion;
        observation.retention = if dispatch_confirmed {
            DurableAdmissionRetentionV1::Confirmed
        } else {
            DurableAdmissionRetentionV1::Unconfirmed
        };
        if observation.first_error.is_none() {
            observation.first_error = error;
        }
        observation.measurement.incomplete |= matches!(
            completion,
            DurableAdmissionCompletionV1::Missing
                | DurableAdmissionCompletionV1::Invalidated
                | DurableAdmissionCompletionV1::Disconnected
        );
        self.observation = Some(observation);
    }
    fn absent(&mut self, completion: DurableAdmissionCompletionV1) {
        let observation = self
            .active
            .as_ref()
            .and_then(|(_, digest)| self.worker(digest));
        let observation = observation.map(|mut value| {
            value.stage = DurableAdmissionDispatchStageV1::WorkerCompletion;
            value
        });
        self.record(observation, completion, false, None);
    }
    fn take(
        &mut self,
        attempt: u64,
        digest: &str,
    ) -> Option<QualificationDurableAdmissionObservationV1> {
        if self.taken
            || !self
                .active
                .as_ref()
                .is_some_and(|(id, actual)| *id == attempt && actual == digest)
        {
            return None;
        }
        self.taken = true;
        self.observation.take().map(|mut observation| {
            observation.measurement.native_approval_us = self.native_approval_us;
            observation.measurement.clamped |= self.native_clamped;
            observation
        })
    }
}
/// Data-only observation of an actual worker result. Production decisions never
/// consult it; neither the kind nor its exact review digest restores permission.
#[cfg(feature = "synthetic-born-joined-qualification")]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum QualificationDurableWitnessCompletionV1 {
    AdmissionCommitted,
    SessionAcquired,
    ActivationCommitted,
    ReconciliationCommitted,
    ReconciliationUncertain,
}
pub(super) enum DurableWitnessPreparedV1 {
    Admission(PreparedDurableWitnessAdmissionV1),
    Session(PreparedDurableWriterSessionV1),
    Activation(PreparedDurableWriterActivationV1),
    Reconciliation(PreparedDurableWriterReconciliationV1),
}
impl DurableWitnessRuntimeV1 {
    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub(super) fn record_qualification_native_stage_failure_v1(&mut self, error: Error) {
        let attempt = self.qualification_preparation.native_stage;
        self.qualification_preparation.record(
            attempt,
            DurableAdmissionPreparationStageV1::NativeStage,
            error,
        );
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    fn qualification_completion_v1(
        &self,
        expected_review_digest: &str,
    ) -> Option<QualificationDurableWitnessCompletionV1> {
        self.qualification_completion
            .as_ref()
            .filter(|(digest, _)| digest == expected_review_digest)
            .map(|(_, kind)| *kind)
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub(super) fn observe_admission_disconnected_v1(&mut self) {
        self.qualification_admission
            .absent(DurableAdmissionCompletionV1::Disconnected);
        self.qualification_session.absent();
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub(super) fn observe_admission_invalidated_v1(&mut self, outcome: DurableWitnessOutcomeV1) {
        self.qualification_session.absent();
        if let DurableWitnessOutcomeV1::Admission {
            dispatch,
            result,
            observation,
        } = outcome
        {
            self.qualification_admission.record(
                observation,
                DurableAdmissionCompletionV1::Invalidated,
                dispatch.is_some(),
                result.err(),
            );
        }
    }
    pub(super) fn discard_import_custody(&mut self) {
        self.admission_retry = None;
        self.session_retry = None;
        self.activation_retry = None;
        #[cfg(feature = "synthetic-born-joined-qualification")]
        self.qualification_session.absent();
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub(super) fn qualification_session_retained_v1(
        &self,
        digest: &str,
        deadline: Instant,
        history_digest: &str,
    ) -> Result<bool> {
        let Some(approved) = &self.session_retry else {
            return Ok(false);
        };
        Ok(self.activation_retry.is_none()
            && approved.0.custody.digest == digest
            && approved.0.custody.deadline == deadline
            && approved
                .0
                .history
                .history_digest()
                .map_err(|_| Error::ReviewMismatch)?
                == history_digest)
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub(super) fn qualification_session_absent_v1(&self) -> bool {
        self.session_retry.is_none() && self.activation_retry.is_none()
    }
}
impl DurableWitnessPreparedV1 {
    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub(super) fn flow_observer_v1(&self) -> Option<&flow_diag_v1::DurableFlowObserverV1> {
        match self {
            Self::Admission(_) => None,
            Self::Session(value) => value.flow_observer.as_ref(),
            Self::Activation(value) => value.flow_observer.as_ref(),
            Self::Reconciliation(value) => value.flow_observer.as_ref(),
        }
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub(super) fn flow_native_stage_v1(&self) -> flow_diag_v1::DurableFlowStageV1 {
        use flow_diag_v1::DurableFlowStageV1 as S;
        match self {
            Self::Admission(_) => S::FixtureState,
            Self::Session(_) => S::AcquireNative,
            Self::Activation(_) => S::ActivationNative,
            Self::Reconciliation(_) => S::ReconcileNative,
        }
    }
    pub(super) fn source_current(&self) -> bool {
        match self {
            Self::Admission(v) => v.custody.source.check_data_current_under_fence().is_ok(),
            Self::Session(v) => v.custody.source.check_data_current_under_fence().is_ok(),
            Self::Activation(v) => v.custody.source.check_data_current_under_fence().is_ok(),
            Self::Reconciliation(v) => v.source.check_data_current_under_fence().is_ok(),
        }
    }
    fn digest(&self) -> &str {
        match self {
            Self::Admission(v) => v.digest(),
            Self::Session(v) => v.digest(),
            Self::Activation(v) => v.digest(),
            Self::Reconciliation(v) => v.digest(),
        }
    }
    fn display(&self) -> Result<String> {
        match self {
            Self::Admission(v) => v.display(),
            Self::Session(v) => v.display(),
            Self::Activation(v) => v.display(),
            Self::Reconciliation(v) => v.display(),
        }
    }
}
pub(super) enum DurableWitnessOutcomeV1 {
    #[cfg(feature = "synthetic-born-joined-qualification")]
    ObservedPreparation {
        attempt: Option<u64>,
        stage: DurableAdmissionPreparationStageV1,
        history_failure: Option<DurableAdmissionHistoryFailureV1>,
        outcome: Box<DurableWitnessOutcomeV1>,
    },
    Prepared(Result<Box<DurableWitnessPreparedV1>>),
    HistoricalAdmission(Result<String>),
    Admission {
        dispatch: Option<Arc<DurableWitnessAdmissionDispatchV1>>,
        result: Result<AccountSnapshot>,
        #[cfg(feature = "synthetic-born-joined-qualification")]
        observation: Option<QualificationDurableAdmissionObservationV1>,
    },
    Session {
        approved: Arc<ApprovedDurableWriterSessionV1>,
        result: Result<WriterSessionReceipt>,
        #[cfg(feature = "synthetic-born-joined-qualification")]
        observation: Option<QualificationSessionAttemptV1>,
    },
    Activation {
        approved: Arc<ApprovedDurableWriterActivationV1>,
        result: Result<AccountSnapshot>,
    },
    Reconciled(Result<DurableReconciliationOutcomeV1>),
}
impl NativeRuntime {
    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub(super) fn begin_qualification_session_v1(
        &mut self,
        observer: &flow_diag_v1::DurableFlowObserverV1,
        digest: &str,
    ) -> Option<u64> {
        let open = self.open.as_mut()?;
        open.durable_witness.qualification_completion = None;
        open.durable_witness
            .qualification_session
            .begin(observer, digest)
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub(super) fn qualification_session_result_v1(
        &self,
        serial: u64,
        digest: &str,
    ) -> Option<bool> {
        let state = &self.open.as_ref()?.durable_witness.qualification_session;
        state
            .matches(serial, digest)
            .then_some(state.accepted)
            .flatten()
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub(super) fn take_qualification_session_error_v1(
        &mut self,
        serial: u64,
        digest: &str,
    ) -> Option<Error> {
        self.open
            .as_mut()?
            .durable_witness
            .qualification_session
            .take_error(serial, digest)
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub(super) fn reset_qualification_admission_dispatch_v1(&mut self) {
        if let Some(open) = self.open.as_mut() {
            open.durable_witness.qualification_admission.reset();
        }
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub(super) fn begin_qualification_admission_dispatch_v1(
        &mut self,
        digest: String,
    ) -> Option<u64> {
        self.open
            .as_mut()?
            .durable_witness
            .qualification_admission
            .begin(digest)
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub(super) fn qualification_admission_native_cost_v1(&mut self, elapsed: Duration) {
        if let Some(open) = self.open.as_mut() {
            let state = &mut open.durable_witness.qualification_admission;
            if state.active.is_some() {
                state.native_approval_us =
                    Some(admission_micros(elapsed, &mut state.native_clamped));
            }
        }
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub(super) fn qualification_admission_missing_v1(&mut self) {
        if let Some(open) = self.open.as_mut() {
            open.durable_witness
                .qualification_admission
                .absent(DurableAdmissionCompletionV1::Missing);
        }
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub(super) fn take_qualification_admission_dispatch_v1(
        &mut self,
        attempt: u64,
        digest: &str,
        mut failure: DurableAdmissionDispatchFailureV1,
    ) -> DurableAdmissionDispatchFailureV1 {
        if let Some(open) = self.open.as_mut() {
            let state = &mut open.durable_witness.qualification_admission;
            let eligible = !state.taken
                && state
                    .active
                    .as_ref()
                    .is_some_and(|(id, actual)| *id == attempt && actual == digest);
            if let Some(observation) = state.take(attempt, digest) {
                if observation.first_error.is_some() {
                    failure.stage = observation.stage;
                }
                failure.original_error = observation.first_error;
                failure.completion = observation.completion;
                failure.retention = observation.retention;
                failure.measurement = Some(observation.measurement);
                failure.call_failure = observation.call_failure;
            } else if eligible {
                failure.measurement = Some(DurableAdmissionDispatchMeasurementV1 {
                    native_approval_us: state.native_approval_us,
                    clamped: state.native_clamped,
                    incomplete: true,
                    ..Default::default()
                });
            }
        }
        failure
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub(super) fn qualification_durable_admission_attempt_v1(&self) -> Option<u64> {
        self.open
            .as_ref()?
            .durable_witness
            .qualification_preparation
            .active
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub(super) fn take_qualification_durable_admission_failure_v1(
        &mut self,
        attempt: u64,
    ) -> Option<DurableAdmissionPreparationFailureV1> {
        self.open
            .as_mut()?
            .durable_witness
            .qualification_preparation
            .take(attempt)
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    fn clear_qualification_durable_witness_completion_v1(&mut self) {
        if let Some(open) = self.open.as_mut() {
            open.durable_witness.qualification_completion = None;
        }
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub(super) fn qualification_durable_witness_completion_v1(
        &self,
        expected_review_digest: &str,
    ) -> Option<QualificationDurableWitnessCompletionV1> {
        self.open
            .as_ref()?
            .durable_witness
            .qualification_completion_v1(expected_review_digest)
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub(super) fn qualification_committed_durable_admission_v1(
        &self,
    ) -> Result<Option<OwnerControlRequest>> {
        let open = self.open.as_ref().ok_or(Error::Locked)?;
        let source = open.durable_witness_source_v1()?;
        let Some(id) = open.durable_witness.admission_id.as_deref() else {
            return Ok(None);
        };
        let retained = local_intent(&source)?.ok_or(Error::RecoveryRequired)?;
        require_intent(&source, &retained)?;
        if retained.request().operation_id != id {
            return Err(Error::ReviewMismatch);
        }
        Ok(Some(retained.request().clone()))
    }
    /// Native primary-click preparation only. An existing row is never replaced:
    /// inspect authenticated complete history, or freshly review the SAME body.
    pub(super) fn prepare_durable_admission_v1(&mut self, epoch: u64) -> Result<()> {
        #[cfg(feature = "synthetic-born-joined-qualification")]
        self.clear_qualification_durable_witness_completion_v1();
        #[cfg(feature = "synthetic-born-joined-qualification")]
        let attempt = self
            .open
            .as_mut()
            .and_then(|open| open.durable_witness.qualification_preparation.begin());
        let open = self.open.as_ref().ok_or(Error::Locked)?;
        let source = open.durable_witness_source_v1()?;
        let owner = open.owner_witness.clone().ok_or(Error::Locked)?;
        self.start_witness_job(epoch, move |cancelled| {
            #[cfg(feature = "synthetic-born-joined-qualification")]
            let mut stage = DurableAdmissionPreparationStageV1::Source;
            #[cfg(feature = "synthetic-born-joined-qualification")]
            let mut history_failure = None;
            let result = (|| {
                if cancelled.load(Ordering::Acquire) {
                    return Err(Error::Locked);
                }
                source.check_current()?;
                #[cfg(feature = "synthetic-born-joined-qualification")]
                {
                    stage = DurableAdmissionPreparationStageV1::History;
                }
                let history = source_history_inner(
                    &owner,
                    &source,
                    CredentialRole::Owner,
                    source.deadline()?,
                    #[cfg(feature = "synthetic-born-joined-qualification")]
                    Some(&mut history_failure),
                    #[cfg(feature = "synthetic-born-joined-qualification")]
                    None,
                    #[cfg(feature = "synthetic-born-joined-qualification")]
                    flow_diag_v1::DurableFlowStageV1::FixtureState,
                )?;
                #[cfg(feature = "synthetic-born-joined-qualification")]
                {
                    stage = DurableAdmissionPreparationStageV1::RetainedIntent;
                }
                if let Some(retained) = local_intent(&source)? {
                    // Early deny-only preflight, not intent or journal authority.
                    // Both branches below retain their own complete intent gate.
                    source.check_data_current_under_fence()?;
                    match history
                        .durable_payment_admission_v1(&retained.request().operation_id)
                        .map_err(|_| Error::RecoveryRequired)?
                    {
                        Some(exact) => {
                            check_historical_admission_v1(retained.request(), exact, || {
                                committed_intent(&source, &history, &exact.operation_id).map(|_| ())
                            })?;
                            return Ok(DurableWitnessOutcomeV1::HistoricalAdmission(Ok(exact
                                .operation_id
                                .clone())));
                        }
                        None => {
                            let prepared = PreparedDurableWitnessAdmissionV1::prepare_exact_retry(
                                &owner,
                                source,
                                retained,
                                #[cfg(feature = "synthetic-born-joined-qualification")]
                                &mut stage,
                            )?;
                            return Ok(DurableWitnessOutcomeV1::Prepared(Ok(Box::new(
                                DurableWitnessPreparedV1::Admission(prepared),
                            ))));
                        }
                    }
                }
                let old = &source.entry().record().account_record.terms;
                let from = old.issued_at_ms;
                let until = old
                    .scope
                    .expires_at_ms
                    .min(history.account_policy().policy_expires_at_ms);
                #[cfg(feature = "synthetic-born-joined-qualification")]
                {
                    stage = DurableAdmissionPreparationStageV1::Terms;
                }
                let admission_terms = terms(&source, from, until)?;
                #[cfg(feature = "synthetic-born-joined-qualification")]
                {
                    stage = DurableAdmissionPreparationStageV1::RequestBuilder;
                }
                let request =
                    wholepact_authority::durable_payment_v1::prepare_durable_payment_request_v1(
                        admission_terms,
                        &history,
                    )
                    .map_err(|_| Error::RecoveryRequired)?;
                let prepared = PreparedDurableWitnessAdmissionV1::from_exact(
                    &owner,
                    source,
                    request,
                    #[cfg(feature = "synthetic-born-joined-qualification")]
                    &mut stage,
                )?;
                Ok(DurableWitnessOutcomeV1::Prepared(Ok(Box::new(
                    DurableWitnessPreparedV1::Admission(prepared),
                ))))
            })();
            let outcome = result.unwrap_or_else(|e| DurableWitnessOutcomeV1::Prepared(Err(e)));
            #[cfg(feature = "synthetic-born-joined-qualification")]
            let outcome = DurableWitnessOutcomeV1::ObservedPreparation {
                attempt,
                stage,
                history_failure: history_failure.map(|(authority, callback)| {
                    DurableAdmissionHistoryFailureV1 {
                        authority,
                        callback,
                    }
                }),
                outcome: Box::new(outcome),
            };
            WitnessOutcome::DurablePaymentV1(outcome)
        })
    }
    fn start_flow_witness_job_v1(
        &mut self,
        epoch: u64,
        #[cfg(feature = "synthetic-born-joined-qualification")]
        purpose: flow_diag_v1::DurableFlowJobPurposeV1,
        #[cfg(feature = "synthetic-born-joined-qualification")]
        stage: flow_diag_v1::DurableFlowStageV1,
        #[cfg(feature = "synthetic-born-joined-qualification")] observer: Option<
            flow_diag_v1::DurableFlowObserverV1,
        >,
        work: impl FnOnce(Arc<AtomicBool>) -> WitnessOutcome + Send + 'static,
    ) -> Result<()> {
        let result = self.start_witness_job_inner(
            epoch,
            work,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            observer.clone().map(|observer| (observer, purpose, stage)),
        );
        durable_flow_observe_v1!(observer.as_ref(), stage, result)
    }
    pub(super) fn prepare_durable_session_v1(&mut self, epoch: u64) -> Result<()> {
        #[cfg(feature = "synthetic-born-joined-qualification")]
        self.clear_qualification_durable_witness_completion_v1();
        let open = self.open.as_ref().ok_or(Error::Locked)?;
        if open.durable_witness.session_retry.is_some() || open.writer_receipt.is_some() {
            return Err(Error::RecoveryRequired);
        }
        let source = open.durable_witness_source_v1()?;
        let witness = open.witness.clone().ok_or(Error::Locked)?;
        let id = open
            .durable_witness
            .admission_id
            .clone()
            .ok_or(Error::RecoveryRequired)?;
        #[cfg(feature = "synthetic-born-joined-qualification")]
        let observer = open.durable_witness.flow_observation.clone();
        self.start_flow_witness_job_v1(
            epoch,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            flow_diag_v1::DurableFlowJobPurposeV1::AcquirePrepare,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            flow_diag_v1::DurableFlowStageV1::AcquirePrepare,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            observer.clone(),
            move |cancelled| {
                WitnessOutcome::DurablePaymentV1(DurableWitnessOutcomeV1::Prepared((|| {
                    if cancelled.load(Ordering::Acquire) {
                        return Err(Error::Locked);
                    }
                    Ok(Box::new(DurableWitnessPreparedV1::Session(
                        PreparedDurableWriterSessionV1::prepare_inner(
                            &witness,
                            source,
                            &id,
                            #[cfg(feature = "synthetic-born-joined-qualification")]
                            observer.as_ref(),
                        )?,
                    )))
                })(
                )))
            },
        )
    }
    pub(super) fn prepare_durable_activation_v1(&mut self, epoch: u64) -> Result<()> {
        #[cfg(feature = "synthetic-born-joined-qualification")]
        self.clear_qualification_durable_witness_completion_v1();
        let open = self.open.as_ref().ok_or(Error::Locked)?;
        if open.durable_witness.activation_retry.is_some() {
            return Err(Error::RecoveryRequired);
        }
        let source = open.durable_witness_source_v1()?;
        let owner = open.owner_witness.clone().ok_or(Error::Locked)?;
        let id = open
            .durable_witness
            .admission_id
            .clone()
            .ok_or(Error::RecoveryRequired)?;
        let receipt = open.writer_receipt.clone().ok_or(Error::RecoveryRequired)?;
        #[cfg(feature = "synthetic-born-joined-qualification")]
        let observer = open.durable_witness.flow_observation.clone();
        self.start_flow_witness_job_v1(
            epoch,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            flow_diag_v1::DurableFlowJobPurposeV1::ActivationPrepare,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            flow_diag_v1::DurableFlowStageV1::ActivationPrepare,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            observer.clone(),
            move |cancelled| {
                WitnessOutcome::DurablePaymentV1(DurableWitnessOutcomeV1::Prepared((|| {
                    if cancelled.load(Ordering::Acquire) {
                        return Err(Error::Locked);
                    }
                    Ok(Box::new(DurableWitnessPreparedV1::Activation(
                        PreparedDurableWriterActivationV1::prepare_inner(
                            &owner,
                            source,
                            &id,
                            receipt,
                            #[cfg(feature = "synthetic-born-joined-qualification")]
                            observer.as_ref(),
                        )?,
                    )))
                })(
                )))
            },
        )
    }
    pub(super) fn prepare_durable_reconciliation_v1(&mut self, epoch: u64) -> Result<()> {
        #[cfg(feature = "synthetic-born-joined-qualification")]
        self.clear_qualification_durable_witness_completion_v1();
        let open = self.open.as_ref().ok_or(Error::Locked)?;
        let source = open.durable_witness_source_v1()?;
        let witness = open.witness.clone().ok_or(Error::Locked)?;
        let id = open
            .durable_witness
            .admission_id
            .clone()
            .ok_or(Error::RecoveryRequired)?;
        #[cfg(feature = "synthetic-born-joined-qualification")]
        let observer = open.durable_witness.flow_observation.clone();
        self.start_flow_witness_job_v1(
            epoch,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            flow_diag_v1::DurableFlowJobPurposeV1::ReconcilePrepare,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            flow_diag_v1::DurableFlowStageV1::ReconcilePrepare,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            observer.clone(),
            move |cancelled| {
                WitnessOutcome::DurablePaymentV1(DurableWitnessOutcomeV1::Prepared((|| {
                    if cancelled.load(Ordering::Acquire) {
                        return Err(Error::Locked);
                    }
                    Ok(Box::new(DurableWitnessPreparedV1::Reconciliation(
                        PreparedDurableWriterReconciliationV1::prepare_inner(
                            &witness,
                            source,
                            &id,
                            #[cfg(feature = "synthetic-born-joined-qualification")]
                            observer.as_ref(),
                        )?,
                    )))
                })(
                )))
            },
        )
    }
    pub(super) fn approve_durable_witness_v1(
        &mut self,
        prepared: DurableWitnessPreparedV1,
        decision: NativeDecision,
        epoch: u64,
    ) -> Result<()> {
        #[cfg(feature = "synthetic-born-joined-qualification")]
        self.clear_qualification_durable_witness_completion_v1();
        let open = self.open.as_ref().ok_or(Error::Locked)?;
        match prepared {
            DurableWitnessPreparedV1::Admission(value) => {
                let owner = open.owner_witness.clone().ok_or(Error::Locked)?;
                #[cfg(feature = "synthetic-born-joined-qualification")]
                let mut observation = open
                    .durable_witness
                    .qualification_admission
                    .worker(value.digest());
                let approved = value.approve(decision, &open.authority, &owner)?;
                self.start_witness_job(epoch, move |cancelled| {
                    let outcome = if cancelled.load(Ordering::Acquire) {
                        #[cfg(feature = "synthetic-born-joined-qualification")]
                        if let Some(value) = observation.as_mut() {
                            value.stage = DurableAdmissionDispatchStageV1::WorkerCompletion;
                        }
                        DurableWitnessOutcomeV1::Admission {
                            dispatch: None,
                            result: Err(Error::Locked),
                            #[cfg(feature = "synthetic-born-joined-qualification")]
                            observation,
                        }
                    } else {
                        #[cfg(feature = "synthetic-born-joined-qualification")]
                        let started = admission_optional_clock(observation.is_some(), Instant::now);
                        #[cfg(feature = "synthetic-born-joined-qualification")]
                        if let Some(value) = observation.as_mut() {
                            value.stage = DurableAdmissionDispatchStageV1::IntentRetention;
                        }
                        #[cfg(feature = "synthetic-born-joined-qualification")]
                        let retained = if let Some(value) = observation.as_mut() {
                            approved.retain_inner(Some(&mut value.first_error))
                        } else {
                            approved.retain()
                        };
                        #[cfg(not(feature = "synthetic-born-joined-qualification"))]
                        let retained = approved.retain();
                        #[cfg(feature = "synthetic-born-joined-qualification")]
                        if let (Some(value), Some(started)) = (observation.as_mut(), started) {
                            value.measurement.retention_us = Some(admission_micros(
                                started.elapsed(),
                                &mut value.measurement.clamped,
                            ));
                        }
                        match retained {
                            Ok(dispatch) => {
                                let dispatch = Arc::new(dispatch);
                                let result = dispatch.submit_inner(
                                    &owner,
                                    #[cfg(feature = "synthetic-born-joined-qualification")]
                                    observation.as_mut(),
                                );
                                DurableWitnessOutcomeV1::Admission {
                                    dispatch: Some(dispatch),
                                    result,
                                    #[cfg(feature = "synthetic-born-joined-qualification")]
                                    observation,
                                }
                            }
                            Err(error) => DurableWitnessOutcomeV1::Admission {
                                dispatch: None,
                                result: Err(error),
                                #[cfg(feature = "synthetic-born-joined-qualification")]
                                observation,
                            },
                        }
                    };
                    WitnessOutcome::DurablePaymentV1(outcome)
                })
            }
            DurableWitnessPreparedV1::Session(value) => {
                let witness = open.witness.clone().ok_or(Error::Locked)?;
                #[cfg(feature = "synthetic-born-joined-qualification")]
                let observer = value.flow_observer.clone();
                let approved = Arc::new(durable_flow_observe_v1!(
                    observer.as_ref(),
                    flow_diag_v1::DurableFlowStageV1::AcquireNative,
                    value.approve(decision, &open.authority, &witness)
                )?);
                #[cfg(feature = "synthetic-born-joined-qualification")]
                if let Some(observer) = &observer {
                    observer.lifecycle_point(
                        flow_diag_v1::DurableLifecyclePointV1::AcquireNativeApproval,
                    );
                }
                #[cfg(feature = "synthetic-born-joined-qualification")]
                let session_observation = self.open.as_mut().and_then(|open| {
                    open.durable_witness
                        .qualification_session
                        .dispatch(observer.as_ref(), &approved.0.custody.digest)
                });
                self.start_flow_witness_job_v1(
                    epoch,
                    #[cfg(feature = "synthetic-born-joined-qualification")]
                    flow_diag_v1::DurableFlowJobPurposeV1::Acquire,
                    #[cfg(feature = "synthetic-born-joined-qualification")]
                    flow_diag_v1::DurableFlowStageV1::AcquireCall,
                    #[cfg(feature = "synthetic-born-joined-qualification")]
                    observer.clone(),
                    move |cancelled| {
                        let result = if cancelled.load(Ordering::Acquire) {
                            Err(Error::Locked)
                        } else {
                            approved.acquire_inner(
                                &witness,
                                #[cfg(feature = "synthetic-born-joined-qualification")]
                                observer.as_ref(),
                            )
                        };
                        WitnessOutcome::DurablePaymentV1(DurableWitnessOutcomeV1::Session {
                            approved,
                            result,
                            #[cfg(feature = "synthetic-born-joined-qualification")]
                            observation: session_observation,
                        })
                    },
                )
            }
            DurableWitnessPreparedV1::Activation(value) => {
                let owner = open.owner_witness.clone().ok_or(Error::Locked)?;
                #[cfg(feature = "synthetic-born-joined-qualification")]
                let observer = value.flow_observer.clone();
                let approved = Arc::new(durable_flow_observe_v1!(
                    observer.as_ref(),
                    flow_diag_v1::DurableFlowStageV1::ActivationNative,
                    value.approve(decision, &open.authority, &owner)
                )?);
                self.start_flow_witness_job_v1(
                    epoch,
                    #[cfg(feature = "synthetic-born-joined-qualification")]
                    flow_diag_v1::DurableFlowJobPurposeV1::Activate,
                    #[cfg(feature = "synthetic-born-joined-qualification")]
                    flow_diag_v1::DurableFlowStageV1::ActivationCall,
                    #[cfg(feature = "synthetic-born-joined-qualification")]
                    observer.clone(),
                    move |cancelled| {
                        let result = if cancelled.load(Ordering::Acquire) {
                            Err(Error::Locked)
                        } else {
                            approved.activate_inner(
                                &owner,
                                #[cfg(feature = "synthetic-born-joined-qualification")]
                                observer.as_ref(),
                            )
                        };
                        WitnessOutcome::DurablePaymentV1(DurableWitnessOutcomeV1::Activation {
                            approved,
                            result,
                        })
                    },
                )
            }
            DurableWitnessPreparedV1::Reconciliation(value) => {
                #[cfg(feature = "synthetic-born-joined-qualification")]
                let observer = value.flow_observer.clone();
                let approved = durable_flow_observe_v1!(
                    observer.as_ref(),
                    flow_diag_v1::DurableFlowStageV1::ReconcileNative,
                    value.approve(decision)
                )?;
                self.start_flow_witness_job_v1(
                    epoch,
                    #[cfg(feature = "synthetic-born-joined-qualification")]
                    flow_diag_v1::DurableFlowJobPurposeV1::Reconcile,
                    #[cfg(feature = "synthetic-born-joined-qualification")]
                    flow_diag_v1::DurableFlowStageV1::ReconcileCall,
                    #[cfg(feature = "synthetic-born-joined-qualification")]
                    observer.clone(),
                    move |cancelled| {
                        WitnessOutcome::DurablePaymentV1(DurableWitnessOutcomeV1::Reconciled(
                            if cancelled.load(Ordering::Acquire) {
                                Err(Error::Locked)
                            } else {
                                approved.reconcile_inner(
                                    #[cfg(feature = "synthetic-born-joined-qualification")]
                                    observer.as_ref(),
                                )
                            },
                        ))
                    },
                )
            }
        }
    }
    pub(super) fn retry_durable_witness_v1(&mut self, kind: u8, epoch: u64) -> Result<()> {
        #[cfg(feature = "synthetic-born-joined-qualification")]
        self.clear_qualification_durable_witness_completion_v1();
        let open = self.open.as_ref().ok_or(Error::Locked)?;
        match kind {
            0 => {
                let dispatch = open
                    .durable_witness
                    .admission_retry
                    .clone()
                    .ok_or(Error::RecoveryRequired)?;
                let owner = open.owner_witness.clone().ok_or(Error::Locked)?;
                self.start_witness_job(epoch, move |cancelled| {
                    let result = if cancelled.load(Ordering::Acquire) {
                        Err(Error::Locked)
                    } else {
                        dispatch.submit(&owner)
                    };
                    WitnessOutcome::DurablePaymentV1(DurableWitnessOutcomeV1::Admission {
                        dispatch: Some(dispatch),
                        result,
                        #[cfg(feature = "synthetic-born-joined-qualification")]
                        observation: None,
                    })
                })
            }
            1 => {
                let approved = open
                    .durable_witness
                    .session_retry
                    .clone()
                    .ok_or(Error::RecoveryRequired)?;
                let witness = open.witness.clone().ok_or(Error::Locked)?;
                #[cfg(feature = "synthetic-born-joined-qualification")]
                let observer = open.durable_witness.flow_observation.clone();
                #[cfg(feature = "synthetic-born-joined-qualification")]
                let session_observation = self.open.as_mut().and_then(|open| {
                    open.durable_witness
                        .qualification_session
                        .dispatch(observer.as_ref(), &approved.0.custody.digest)
                });
                self.start_flow_witness_job_v1(
                    epoch,
                    #[cfg(feature = "synthetic-born-joined-qualification")]
                    flow_diag_v1::DurableFlowJobPurposeV1::Acquire,
                    #[cfg(feature = "synthetic-born-joined-qualification")]
                    flow_diag_v1::DurableFlowStageV1::AcquireCall,
                    #[cfg(feature = "synthetic-born-joined-qualification")]
                    observer.clone(),
                    move |cancelled| {
                        let result = if cancelled.load(Ordering::Acquire) {
                            Err(Error::Locked)
                        } else {
                            approved.acquire_inner(
                                &witness,
                                #[cfg(feature = "synthetic-born-joined-qualification")]
                                observer.as_ref(),
                            )
                        };
                        WitnessOutcome::DurablePaymentV1(DurableWitnessOutcomeV1::Session {
                            approved,
                            result,
                            #[cfg(feature = "synthetic-born-joined-qualification")]
                            observation: session_observation,
                        })
                    },
                )
            }
            2 => {
                let approved = open
                    .durable_witness
                    .activation_retry
                    .clone()
                    .ok_or(Error::RecoveryRequired)?;
                let owner = open.owner_witness.clone().ok_or(Error::Locked)?;
                self.start_witness_job(epoch, move |cancelled| {
                    let result = if cancelled.load(Ordering::Acquire) {
                        Err(Error::Locked)
                    } else {
                        approved.activate(&owner)
                    };
                    WitnessOutcome::DurablePaymentV1(DurableWitnessOutcomeV1::Activation {
                        approved,
                        result,
                    })
                })
            }
            _ => Err(Error::InvalidData),
        }
    }
}
#[cfg(feature = "synthetic-born-joined-qualification")]
fn qualification_completion_from_outcome_v1(
    outcome: &DurableWitnessOutcomeV1,
) -> Option<(String, QualificationDurableWitnessCompletionV1)> {
    use QualificationDurableWitnessCompletionV1 as C;
    match outcome {
        DurableWitnessOutcomeV1::Admission {
            dispatch: Some(dispatch),
            result: Ok(_),
            ..
        } => Some((dispatch.custody.digest.clone(), C::AdmissionCommitted)),
        DurableWitnessOutcomeV1::Session {
            approved,
            result: Ok(_),
            ..
        } => Some((approved.0.custody.digest.clone(), C::SessionAcquired)),
        DurableWitnessOutcomeV1::Activation {
            approved,
            result: Ok(_),
        } => Some((approved.0.custody.digest.clone(), C::ActivationCommitted)),
        DurableWitnessOutcomeV1::Reconciled(Ok(DurableReconciliationOutcomeV1::Committed {
            review_digest,
        })) => Some((review_digest.clone(), C::ReconciliationCommitted)),
        DurableWitnessOutcomeV1::Reconciled(Ok(DurableReconciliationOutcomeV1::Uncertain {
            review_digest,
        })) => Some((review_digest.clone(), C::ReconciliationUncertain)),
        _ => None,
    }
}
#[cfg(feature = "synthetic-born-joined-qualification")]
pub(super) fn observe_flow_worker_v1(
    job: &flow_diag_v1::DurableFlowJobObservationV1,
    stage: flow_diag_v1::DurableFlowStageV1,
    outcome: &WitnessOutcome,
) {
    if let WitnessOutcome::DurablePaymentV1(outcome) = outcome {
        match outcome {
            DurableWitnessOutcomeV1::Prepared(result) => job.returned(stage, result),
            DurableWitnessOutcomeV1::HistoricalAdmission(result) => job.returned(stage, result),
            DurableWitnessOutcomeV1::Reconciled(result) => job.returned(stage, result),
            DurableWitnessOutcomeV1::Session { result, .. } => job.returned(stage, result),
            DurableWitnessOutcomeV1::Activation { result, .. }
            | DurableWitnessOutcomeV1::Admission { result, .. } => job.returned(stage, result),
            DurableWitnessOutcomeV1::ObservedPreparation { .. } => {}
        }
    }
}
#[cfg(feature = "synthetic-born-joined-qualification")]
pub(super) fn observe_flow_receive_v1(
    job: &flow_diag_v1::DurableFlowJobObservationV1,
    stage: flow_diag_v1::DurableFlowStageV1,
    outcome: &WitnessOutcome,
) {
    if let WitnessOutcome::DurablePaymentV1(outcome) = outcome {
        match outcome {
            DurableWitnessOutcomeV1::Prepared(result) => job.received(stage, result),
            DurableWitnessOutcomeV1::HistoricalAdmission(result) => job.received(stage, result),
            DurableWitnessOutcomeV1::Reconciled(result) => job.received(stage, result),
            DurableWitnessOutcomeV1::Session { result, .. } => job.received(stage, result),
            DurableWitnessOutcomeV1::Activation { result, .. }
            | DurableWitnessOutcomeV1::Admission { result, .. } => job.received(stage, result),
            DurableWitnessOutcomeV1::ObservedPreparation { .. } => job.missing(),
        }
    } else {
        job.missing();
    }
}
fn durable_witness_display_result_v1(
    result: Result<String>,
    #[cfg(feature = "synthetic-born-joined-qualification")] observer: Option<
        &flow_diag_v1::DurableFlowObserverV1,
    >,
    #[cfg(feature = "synthetic-born-joined-qualification")] stage: flow_diag_v1::DurableFlowStageV1,
) -> Result<String> {
    durable_flow_observe_v1!(observer, stage, result)
}
pub(super) fn complete(
    open: &mut OpenAccount,
    outcome: DurableWitnessOutcomeV1,
) -> (&'static str, Option<(String, Result<String>, Operation)>) {
    complete_inner(
        open,
        outcome,
        #[cfg(feature = "synthetic-born-joined-qualification")]
        None,
    )
}
pub(super) fn complete_inner(
    open: &mut OpenAccount,
    outcome: DurableWitnessOutcomeV1,
    #[cfg(feature = "synthetic-born-joined-qualification")] observer: Option<
        &flow_diag_v1::DurableFlowObserverV1,
    >,
) -> (&'static str, Option<(String, Result<String>, Operation)>) {
    #[cfg(feature = "synthetic-born-joined-qualification")]
    if let DurableWitnessOutcomeV1::ObservedPreparation {
        attempt,
        stage,
        history_failure,
        outcome,
    } = outcome
    {
        // The original owned Error is retained only as inert synthetic evidence.
        // The existing production refusal remains no pending review.
        if let DurableWitnessOutcomeV1::Prepared(Err(error)) = *outcome {
            open.durable_witness.qualification_completion = None;
            open.durable_witness
                .qualification_preparation
                .record_with_history(attempt, stage, error, history_failure);
            return (
                "Durable witness history or source was rejected. No new body, session or approval was substituted.",
                None,
            );
        }
        let (message, prepared) = complete_inner(open, *outcome, observer);
        if let Some((digest, display, operation)) = prepared {
            if matches!(&operation, Operation::DurableWitnessV1(value)
                if matches!(value.as_ref(), DurableWitnessPreparedV1::Admission(_)))
            {
                match display {
                    Err(error) => {
                        open.durable_witness.qualification_preparation.record(
                            attempt,
                            DurableAdmissionPreparationStageV1::ReviewDisplay,
                            error,
                        );
                        return (message, None);
                    }
                    Ok(display) => {
                        if attempt.is_some()
                            && attempt == open.durable_witness.qualification_preparation.active
                        {
                            open.durable_witness.qualification_preparation.native_stage = attempt;
                        }
                        return (message, Some((digest, Ok(display), operation)));
                    }
                }
            }
            return (message, Some((digest, display, operation)));
        }
        return (message, None);
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    {
        // A failed/prepared/historical result clears prior success. Only actual
        // completion at this native owner records an exact review correlation.
        open.durable_witness.qualification_completion =
            qualification_completion_from_outcome_v1(&outcome);
    }
    match outcome {
        DurableWitnessOutcomeV1::Prepared(Ok(value)) => {
            let digest = value.digest().into();
            #[cfg(feature = "synthetic-born-joined-qualification")]
            let stage = value.flow_native_stage_v1();
            let display = durable_witness_display_result_v1(
                value.display(),
                #[cfg(feature = "synthetic-born-joined-qualification")]
                observer,
                #[cfg(feature = "synthetic-born-joined-qualification")]
                stage,
            );
            (
                "Review the exact source-bound durable witness operation.",
                Some((digest, display, Operation::DurableWitnessV1(value))),
            )
        }
        DurableWitnessOutcomeV1::HistoricalAdmission(Ok(id)) => {
            // Correlation only. Every later live constructor independently
            // rejoins current source, exact intent, complete history and limits.
            open.durable_witness.admission_id = Some(id);
            (
                "Exact retained admission is committed in authenticated complete history. This is historical evidence, not renewed approval or a replacement session.",
                None,
            )
        }
        DurableWitnessOutcomeV1::Admission {
            dispatch,
            result,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            observation,
        } => {
            let Some(dispatch) = dispatch else {
                #[cfg(feature = "synthetic-born-joined-qualification")]
                open.durable_witness.qualification_admission.record(
                    observation,
                    if result.is_ok() {
                        DurableAdmissionCompletionV1::ReturnedOk
                    } else {
                        DurableAdmissionCompletionV1::ReturnedErr
                    },
                    false,
                    result.err(),
                );
                return (
                    "No admission dispatch was confirmed. Inspect the original local intent before retrying; do not assume local retention or remote rollback, and never create a replacement body or ID.",
                    None,
                );
            };
            if result.is_ok() {
                open.durable_witness.admission_id = Some(dispatch.retained.request().operation_id.clone());
            }
            open.durable_witness.admission_retry = Some(dispatch);
            let message = if result.is_ok() {
                "Exact durable admission committed. Start or reopen only its narrow witness server, then separately review the admission-derived writer session."
            } else {
                "Admission outcome is uncertain or blocked. The exact immutable local intent is retained; inspect authenticated full history, never replace its body, head or ID."
            };
            #[cfg(feature = "synthetic-born-joined-qualification")]
            open.durable_witness.qualification_admission.record(
                observation,
                if result.is_ok() {
                    DurableAdmissionCompletionV1::ReturnedOk
                } else {
                    DurableAdmissionCompletionV1::ReturnedErr
                },
                true,
                result.err(),
            );
            (message, None)
        }
        DurableWitnessOutcomeV1::Session {
            approved,
            result,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            observation,
        } => {
            #[cfg(feature = "synthetic-born-joined-qualification")]
            let digest = approved.0.custody.digest.clone();
            open.durable_witness.session_retry = Some(approved);
            match result {
                Ok(receipt) => {
                    #[cfg(feature = "synthetic-born-joined-qualification")]
                    open.durable_witness.qualification_session.accept(
                        observation,
                        observer,
                        &digest,
                        None,
                    );
                    open.writer_receipt = Some(receipt);
                    (
                        "Exact durable writer session acquired. Separate original-owner activation is required.",
                        None,
                    )
                }
                Err(error) => {
                    // This is the original owned operational error, at its original
                    // discard point, after the unchanged production receive gate.
                    #[cfg(feature = "synthetic-born-joined-qualification")]
                    open.durable_witness.qualification_session.accept(
                        observation,
                        observer,
                        &digest,
                        Some(error),
                    );
                    #[cfg(not(feature = "synthetic-born-joined-qualification"))]
                    let _ = error;
                    (
                        "Writer acquisition is uncertain. Keep this same client/key and exact pre-acquire request; never prepare a replacement session.",
                        None,
                    )
                }
            }
        }
        DurableWitnessOutcomeV1::Activation { approved, result } => {
            open.durable_witness.activation_retry = Some(approved);
            let message = if result.is_ok() {
                "Exact durable writer session activated. Review complete local and witness reconciliation next."
            } else {
                "Activation is uncertain. Retain the same owner client and exact request; inspect history or retry only within its original window."
            };
            (message, None)
        }
        DurableWitnessOutcomeV1::Reconciled(result) => {
            if result.is_err() {
                return (
                    "Reconciliation was refused before commit. The original source and exposure remain unchanged; inspect the exact failure before a fresh review.",
                    None,
                );
            }
            let committed = matches!(result, Ok(DurableReconciliationOutcomeV1::Committed { .. }));
            // The worker already waited for actual session invalidation. Drop
            // stale references/import, but preserve the real writer client/key.
            open.session = None;
            open.enrollment = None;
            open.manifest = None;
            open.clear_durable_review_v1();
            open.writer_reconciled = committed;
            let message = if committed {
                "Complete durable history reconciled and old session revoked. Fresh native enrollment/manifest, exact redisclosure and a NEW import are required before signing; the original owner deadline did not change."
            } else {
                "Reconciliation is uncertain or failed. Old local permission is discarded; retain exact intent, client/session and exposure for recovery inspection. No replacement was created."
            };
            (message, None)
        }
        _ => (
            "Durable witness history or source was rejected. No new body, session or approval was substituted.",
            None,
        ),
    }
}

impl NativeRuntime {
    pub(super) fn durable_witness_ui_v1(
        &mut self,
        ui: &mut egui::Ui,
        focused: bool,
        epoch: u64,
    ) -> bool {
        let Some(open) = self.open.as_ref() else {
            return false;
        };
        if open.durable_born_entry.is_none() || self.pending.is_some() || open.witness_job.is_some()
        {
            return false;
        }
        let retries = [
            open.durable_witness.admission_retry.is_some(),
            open.durable_witness.session_retry.is_some(),
            open.durable_witness.activation_retry.is_some(),
        ];
        let mut action = None;
        egui::CollapsingHeader::new("Exact durable-payment witness admission").show(ui,|ui|{
            ui.label("Use the original enrolled owner and writer credentials and exact current imported proposal. The native review displays the exact immutable interval. No generic owner request, saved receipt or selected certificate grants permission.");
            for (id,label) in [
                (0,"Inspect exact retained admission or review this one immutable admission"),
                (1,"Review the admission-derived writer session"),
                (2,"Review original-owner activation of this exact session"),
                (3,"Review complete durable local/witness reconciliation"),
            ] {
                if ui.button(label).clicked_by(egui::PointerButton::Primary)&&focused{action=Some(id);}
            }
            for (kind,available) in retries.into_iter().enumerate(){
                if available&&ui.button(["Retry SAME retained admission within original approval","Retry SAME acquired-session request and client key","Retry SAME owner activation within original approval"][kind])
                    .clicked_by(egui::PointerButton::Primary)&&focused {action=Some(4+kind);}
            }
        });
        let Some(action) = action else {
            return false;
        };
        let result = match action {
            0 => self.prepare_durable_admission_v1(epoch),
            1 => self.prepare_durable_session_v1(epoch),
            2 => self.prepare_durable_activation_v1(epoch),
            3 => self.prepare_durable_reconciliation_v1(epoch),
            n => self.retry_durable_witness_v1((n - 4) as u8, epoch),
        };
        if result.is_err() {
            self.message="Exact durable operation could not start. Retain original intent/client/session and all exposure; no replacement or renewed deadline was created.";
        }
        true
    }
}

#[cfg(test)]
mod custody_tests {
    use super::*;
    // These are inert equality/order fixtures only. They are not a verified
    // candidate, native source, approved request or current privacy authority.
    fn callback_terms_data(purpose: &str) -> DurablePaymentAdmissionTermsV1 {
        DurablePaymentAdmissionTermsV1 {
            version: 1,
            identity: wholepact_core::manual_enrollment::ManualAccountIdentity {
                account_id: "11".repeat(32),
                full_viewing_key_digest: "12".repeat(32),
                network_profile_id: "data-only-network".into(),
                derivation_domain: "data-only-domain".into(),
            },
            original_policy_digest: "13".repeat(32),
            original_genesis_digest: "14".repeat(32),
            original_birth_commit_digest: "15".repeat(32),
            original_roster_extension_digest: "16".repeat(32),
            original_enrollment_ref: "17".repeat(32),
            writer_certificate_digest: "18".repeat(32),
            fixed: DurableFixedCandidateBindingV1 {
                schema_version: 1,
                network_profile_id: "data-only-network".into(),
                agreement_id: "data-only-agreement".into(),
                obligation_id: "data-only-obligation".into(),
                proposal_id: purpose.into(),
                revision: 1,
                expiry_height: 2,
                proposal_digest: "19".repeat(32),
                manifest_digest: "1a".repeat(32),
                unsigned_artifact_digest: "1b".repeat(32),
                proved_artifact_digest: "1c".repeat(32),
                effects_commitment: "1d".repeat(32),
                policy_digest: "1e".repeat(32),
                review_binding: "1f".repeat(32),
                action_mapping_digest: "20".repeat(32),
                anchor: "21".repeat(32),
                proposal_binding: "22".repeat(32),
            },
            authorization_id: "data-only-authorization".into(),
            recipient_policy_scope_digest: "23".repeat(32),
            concrete_recipient_scope_digest: "24".repeat(32),
            inputs: vec![wholepact_authority::InputReservation {
                input_id: "data-only-input".into(),
                nullifier: "25".repeat(32),
                action_index: 0,
                value_zatoshis: 50,
            }],
            maximum_debit_zatoshis: 40,
            fee_share_zatoshis: 2,
            transaction_fee_zatoshis: 4,
            valid_from_ms: 1,
            valid_until_ms: 2,
        }
    }
    fn preparation_descriptor() -> WitnessDisclosureDescriptor {
        WitnessDisclosureDescriptor {
            endpoint: "127.0.0.1:7443".into(),
            server_name: "inert.example".into(),
            witness_id: "inert-witness".into(),
            account_id: "inert-account".into(),
            network_profile_id: "inert-network".into(),
            policy_digest: "11".repeat(32),
            pinned_server_certificate_digest: "22".repeat(32),
        }
    }

    #[test]
    fn review_preparation_actual_kernel_orders_each_gate_once_and_reuses_descriptor() {
        let expected = preparation_descriptor();
        let deadline = Instant::now() + Duration::from_secs(60);
        let events = std::cell::RefCell::new(Vec::new());
        let seen_descriptor = std::cell::Cell::new(None);
        let result = prepare_review_custody_v1(
            || {
                events.borrow_mut().push(0);
                Ok(())
            },
            || {
                events.borrow_mut().push(1);
                Ok(expected.clone())
            },
            |actual| {
                assert!(actual == &expected);
                let pointer = actual as *const WitnessDisclosureDescriptor;
                if let Some(first) = seen_descriptor.get() {
                    assert!(std::ptr::eq(first, pointer));
                    events.borrow_mut().push(5);
                } else {
                    seen_descriptor.set(Some(pointer));
                    events.borrow_mut().push(2);
                }
                Ok(())
            },
            || {
                events.borrow_mut().push(3);
                Ok(deadline)
            },
            || {
                events.borrow_mut().push(4);
                Ok(())
            },
        );
        let (actual, saved_deadline) = result.unwrap();
        assert!(actual == expected);
        assert!(saved_deadline == deadline);
        assert!(*events.borrow() == [0, 1, 2, 3, 4, 5]);
    }

    #[test]
    fn review_preparation_actual_kernel_preserves_owned_errors_and_short_circuits() {
        for fail_at in 0..6 {
            let events = std::cell::RefCell::new(Vec::new());
            let credential_calls = std::cell::Cell::new(0);
            let step = |at| -> Result<()> {
                events.borrow_mut().push(at);
                if at == fail_at {
                    Err(Error::Io(std::io::Error::from_raw_os_error(1500 + at)))
                } else {
                    Ok(())
                }
            };
            let result = prepare_review_custody_v1(
                || step(0),
                || {
                    step(1)?;
                    Ok(preparation_descriptor())
                },
                |_| {
                    let at = if credential_calls.get() == 0 { 2 } else { 5 };
                    credential_calls.set(credential_calls.get() + 1);
                    step(at)
                },
                || {
                    step(3)?;
                    Ok(Instant::now() + Duration::from_secs(60))
                },
                || step(4),
            );
            assert!(
                matches!(result, Err(Error::Io(error)) if error.raw_os_error() == Some(1500 + fail_at))
            );
            assert!(*events.borrow() == (0..=fail_at).collect::<Vec<_>>());
        }
    }

    #[test]
    fn review_preparation_actual_kernel_never_renews_saved_deadline_after_late_work() {
        let original = Instant::now();
        let available_deadline = std::cell::Cell::new(original);
        let deadline_calls = std::cell::Cell::new(0);
        let credential_calls = std::cell::Cell::new(0);
        let late_calls = std::cell::Cell::new(0);
        let result = prepare_review_custody_v1(
            || Ok(()),
            || Ok(preparation_descriptor()),
            |_| {
                credential_calls.set(credential_calls.get() + 1);
                Ok(())
            },
            || {
                deadline_calls.set(deadline_calls.get() + 1);
                Ok(available_deadline.get())
            },
            || {
                assert!(deadline_calls.get() == 1);
                late_calls.set(late_calls.get() + 1);
                // Even if a later read could offer a new interval, this attempt
                // remains bound to its one saved deadline. No sleeps or issuer.
                available_deadline.set(Instant::now() + Duration::from_secs(120));
                Ok(())
            },
        );
        assert!(matches!(result, Err(Error::ReviewMismatch)));
        assert!(deadline_calls.get() == 1);
        assert!(late_calls.get() == 1);
        assert!(credential_calls.get() == 1);
        assert!(available_deadline.get() > original);
    }

    #[test]
    fn review_preparation_actual_kernel_rejects_final_credential_invalidation() {
        let late_completed = std::cell::Cell::new(false);
        let credential_calls = std::cell::Cell::new(0);
        let result = prepare_review_custody_v1(
            || Ok(()),
            || Ok(preparation_descriptor()),
            |_| {
                credential_calls.set(credential_calls.get() + 1);
                if late_completed.get() {
                    Err(Error::Authentication)
                } else {
                    Ok(())
                }
            },
            || Ok(Instant::now() + Duration::from_secs(60)),
            || {
                late_completed.set(true);
                Ok(())
            },
        );
        assert!(matches!(result, Err(Error::Authentication)));
        assert!(credential_calls.get() == 2);
    }

    fn historical_request_data() -> OwnerControlRequest {
        OwnerControlRequest {
            operation_id: "inert-historical-operation".into(),
            account_id: "inert-account".into(),
            network_profile_id: "inert-network".into(),
            expected_head: wholepact_authority::AuthorityHead {
                sequence: 1,
                digest: "33".repeat(32),
            },
            writer_epoch: 2,
            control: OwnerControl::AdmitDurablePaymentV1 {
                record: Box::new(
                    wholepact_authority::durable_payment_v1::DurablePaymentAdmissionRecordV1 {
                        terms: callback_terms_data("historical-admission"),
                        witness_native_review_digest: "44".repeat(32),
                    },
                ),
            },
        }
    }

    #[test]
    fn historical_preparation_actual_kernel_requires_late_committed_check() {
        let request = historical_request_data();
        for fails in [false, true] {
            let calls = std::cell::Cell::new(0);
            let result = check_historical_admission_v1(&request, &request, || {
                calls.set(calls.get() + 1);
                if fails {
                    Err(Error::Io(std::io::Error::from_raw_os_error(1600)))
                } else {
                    Ok(())
                }
            });
            assert!(calls.get() == 1);
            if fails {
                assert!(
                    matches!(result, Err(Error::Io(error)) if error.raw_os_error() == Some(1600))
                );
            } else {
                assert!(result.is_ok());
            }
        }
    }

    #[test]
    fn historical_preparation_actual_kernel_rejects_every_request_leaf_substitution() {
        fn leaf_paths(value: &serde_json::Value, prefix: &str, paths: &mut Vec<String>) {
            match value {
                serde_json::Value::Object(fields) => {
                    for (name, value) in fields {
                        leaf_paths(value, &format!("{prefix}/{name}"), paths);
                    }
                }
                serde_json::Value::Array(values) => {
                    for (index, value) in values.iter().enumerate() {
                        leaf_paths(value, &format!("{prefix}/{index}"), paths);
                    }
                }
                _ => paths.push(prefix.into()),
            }
        }
        let expected = historical_request_data();
        let encoded = serde_json::to_value(&expected).unwrap();
        let mut paths = Vec::new();
        leaf_paths(&encoded, "", &mut paths);
        // Check the actual path inventory, including the enum discriminant,
        // rather than relying on a guessed leaf count or a hand-picked subset.
        let mut inventory = [
            "/operation_id",
            "/account_id",
            "/network_profile_id",
            "/expected_head/sequence",
            "/expected_head/digest",
            "/writer_epoch",
            "/control/action",
            "/control/record/witness_native_review_digest",
        ]
        .map(str::to_owned)
        .to_vec();
        inventory.extend(
            [
                "version",
                "identity/account_id",
                "identity/full_viewing_key_digest",
                "identity/network_profile_id",
                "identity/derivation_domain",
                "original_policy_digest",
                "original_genesis_digest",
                "original_birth_commit_digest",
                "original_roster_extension_digest",
                "original_enrollment_ref",
                "writer_certificate_digest",
                "fixed/schema_version",
                "fixed/network_profile_id",
                "fixed/agreement_id",
                "fixed/obligation_id",
                "fixed/proposal_id",
                "fixed/revision",
                "fixed/expiry_height",
                "fixed/proposal_digest",
                "fixed/manifest_digest",
                "fixed/unsigned_artifact_digest",
                "fixed/proved_artifact_digest",
                "fixed/effects_commitment",
                "fixed/policy_digest",
                "fixed/review_binding",
                "fixed/action_mapping_digest",
                "fixed/anchor",
                "fixed/proposal_binding",
                "authorization_id",
                "recipient_policy_scope_digest",
                "concrete_recipient_scope_digest",
                "inputs/0/input_id",
                "inputs/0/nullifier",
                "inputs/0/action_index",
                "inputs/0/value_zatoshis",
                "maximum_debit_zatoshis",
                "fee_share_zatoshis",
                "transaction_fee_zatoshis",
                "valid_from_ms",
                "valid_until_ms",
            ]
            .into_iter()
            .map(|path| format!("/control/record/terms/{path}")),
        );
        inventory.sort();
        paths.sort();
        assert!(paths == inventory);
        for path in paths {
            let actual = if path == "/control/action" {
                let mut actual = expected.clone();
                actual.control = OwnerControl::RequireRecovery;
                actual
            } else {
                let mut changed = encoded.clone();
                match changed.pointer_mut(&path).unwrap() {
                    serde_json::Value::String(value) => value.push('x'),
                    serde_json::Value::Number(value) => {
                        *value = serde_json::Number::from(value.as_u64().unwrap() + 1);
                    }
                    _ => panic!("unexpected inert request field: {path}"),
                }
                serde_json::from_value(changed).unwrap()
            };
            for changed_retained in [false, true] {
                let (retained, witnessed) = if changed_retained {
                    (&actual, &expected)
                } else {
                    (&expected, &actual)
                };
                let result = check_historical_admission_v1(retained, witnessed, || {
                    panic!("changed complete request must not reach committed validation")
                });
                assert!(matches!(result, Err(Error::RecoveryRequired)), "{path}");
            }
        }
    }

    #[test]
    fn historical_preparation_actual_kernel_rejects_changed_input_inventory() {
        let mut expected = historical_request_data();
        let OwnerControl::AdmitDurablePaymentV1 { record } = &mut expected.control else {
            unreachable!();
        };
        let mut second = record.terms.inputs[0].clone();
        second.input_id.push('2');
        second.nullifier = "55".repeat(32);
        second.action_index += 1;
        record.terms.inputs.push(second);
        let original_inputs = record.terms.inputs.clone();
        let mut reordered = original_inputs.clone();
        reordered.reverse();
        for inputs in [
            Vec::new(),
            vec![original_inputs[0].clone()],
            vec![original_inputs[0].clone(); 2],
            reordered,
        ] {
            let mut actual = expected.clone();
            let OwnerControl::AdmitDurablePaymentV1 { record } = &mut actual.control else {
                unreachable!();
            };
            record.terms.inputs = inputs;
            assert!(matches!(
                check_historical_admission_v1(&expected, &actual, || {
                    panic!("changed input inventory must stop before committed validation")
                }),
                Err(Error::RecoveryRequired)
            ));
        }
    }

    #[test]
    fn durable_callback_terms_kernel_checks_once_in_order_for_three_purposes() {
        // The three concrete call sites are source-reviewed separately. These
        // exercise their shared production kernel, not native custody issuance.
        for purpose in ["admission", "acquire", "activate"] {
            let expected = callback_terms_data(purpose);
            let order = std::cell::RefCell::new(Vec::new());
            let result = check_callback_terms_v1(
                &expected,
                || {
                    order.borrow_mut().push(0);
                    Ok(())
                },
                || {
                    order.borrow_mut().push(1);
                    Ok(expected.clone())
                },
                || {
                    order.borrow_mut().push(2);
                    Ok(())
                },
                || {
                    order.borrow_mut().push(3);
                    Ok(())
                },
                #[cfg(feature = "synthetic-born-joined-qualification")]
                None,
            );
            assert!(result.is_ok());
            assert!(*order.borrow() == [0, 1, 2, 3]);
        }
    }
    #[test]
    fn durable_callback_terms_kernel_preserves_each_error_and_short_circuits() {
        for purpose in ["admission", "acquire", "activate"] {
            let expected = callback_terms_data(purpose);
            for fail_at in 0..4 {
                let order = std::cell::RefCell::new(Vec::new());
                let step = |at| -> Result<()> {
                    order.borrow_mut().push(at);
                    if at == fail_at {
                        Err(Error::Io(std::io::Error::from_raw_os_error(1200 + at)))
                    } else {
                        Ok(())
                    }
                };
                let result = check_callback_terms_v1(
                    &expected,
                    || step(0),
                    || {
                        step(1)?;
                        Ok(expected.clone())
                    },
                    || step(2),
                    || step(3),
                    #[cfg(feature = "synthetic-born-joined-qualification")]
                    None,
                );
                assert!(
                    matches!(result, Err(Error::Io(error)) if error.raw_os_error() == Some(1200 + fail_at))
                );
                assert!(*order.borrow() == (0..=fail_at).collect::<Vec<_>>());
            }
        }
    }
    #[test]
    fn durable_callback_terms_kernel_rejects_every_changed_field_after_late_check() {
        fn leaf_paths(value: &serde_json::Value, prefix: &str, paths: &mut Vec<String>) {
            match value {
                serde_json::Value::Object(fields) => {
                    for (name, value) in fields {
                        leaf_paths(value, &format!("{prefix}/{name}"), paths);
                    }
                }
                serde_json::Value::Array(values) => {
                    for (index, value) in values.iter().enumerate() {
                        leaf_paths(value, &format!("{prefix}/{index}"), paths);
                    }
                }
                _ => paths.push(prefix.into()),
            }
        }
        let expected = callback_terms_data("admission");
        let encoded = serde_json::to_value(&expected).unwrap();
        let mut paths = Vec::new();
        leaf_paths(&encoded, "", &mut paths);
        assert!(paths.len() == 40);
        for path in paths {
            let mut changed = encoded.clone();
            let leaf = changed.pointer_mut(&path).unwrap();
            match leaf {
                serde_json::Value::String(value) => value.push('x'),
                serde_json::Value::Number(value) => {
                    *value = serde_json::Number::from(value.as_u64().unwrap() + 1);
                }
                _ => panic!("unexpected data-only fixture field"),
            }
            let actual: DurablePaymentAdmissionTermsV1 = serde_json::from_value(changed).unwrap();
            let late_calls = std::cell::Cell::new(0);
            let result = check_callback_terms_v1(
                &expected,
                || Ok(()),
                || Ok(actual),
                || {
                    late_calls.set(late_calls.get() + 1);
                    Ok(())
                },
                || panic!("changed complete terms must not reach final custody"),
                #[cfg(feature = "synthetic-born-joined-qualification")]
                None,
            );
            assert!(matches!(result, Err(Error::ReviewMismatch)));
            assert!(late_calls.get() == 1);
        }
        for inputs in [Vec::new(), vec![expected.inputs[0].clone(); 2]] {
            let mut actual = expected.clone();
            actual.inputs = inputs;
            assert!(matches!(
                check_callback_terms_v1(
                    &expected,
                    || Ok(()),
                    || Ok(actual),
                    || Ok(()),
                    || panic!("changed input set must not reach final custody"),
                    #[cfg(feature = "synthetic-born-joined-qualification")]
                    None,
                ),
                Err(Error::ReviewMismatch)
            ));
        }
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    #[test]
    fn durable_callback_terms_kernel_observation_preserves_order_and_result() {
        for diagnosed in [false, true] {
            for fail_at in [None, Some(0), Some(1), Some(2), Some(3)] {
                let expected = callback_terms_data("admission");
                let mut observation =
                    QualificationDurableAdmissionObservationV1::new(1, "inert-review".into());
                let order = std::cell::RefCell::new(Vec::new());
                let step = |at| -> Result<()> {
                    order.borrow_mut().push(at);
                    if fail_at == Some(at) {
                        Err(Error::Io(std::io::Error::from_raw_os_error(1300 + at)))
                    } else {
                        Ok(())
                    }
                };
                let result = check_callback_terms_v1(
                    &expected,
                    || step(0),
                    || {
                        step(1)?;
                        Ok(expected.clone())
                    },
                    || step(2),
                    || step(3),
                    diagnosed.then_some(&mut observation),
                );
                match fail_at {
                    Some(at) => assert!(
                        matches!(result, Err(Error::Io(error)) if error.raw_os_error() == Some(1300 + at))
                    ),
                    None => assert!(result.is_ok()),
                }
                assert!(*order.borrow() == (0..=fail_at.unwrap_or(3)).collect::<Vec<_>>());
                assert!(observation.measurement.callback_custody_calls == diagnosed.then_some(1));
                assert!(
                    observation.measurement.request_validation_calls
                        == (diagnosed && fail_at != Some(0)).then_some(1)
                );
                if !diagnosed {
                    assert!(observation.measurement.callback_custody_us.is_none());
                    assert!(observation.measurement.request_validation_us.is_none());
                    assert!(observation.callback_stage.is_none());
                }
            }
        }
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    #[test]
    fn admission_dispatch_first_error_is_inert_and_original_result_stays_separate() {
        let mut state = QualificationDurableAdmissionV1::default();
        let attempt = state.begin("exact-review".into()).unwrap();
        let mut observation = state.worker("exact-review").unwrap();
        observation.stage = DurableAdmissionDispatchStageV1::IntentRetention;
        // This is the first original callback error before the existing mapped
        // journal refusal; no journal, source or native decision is constructed.
        observation.first_error = Some(Error::ReviewMismatch);
        state.record(
            Some(observation),
            DurableAdmissionCompletionV1::ReturnedErr,
            false,
            Some(Error::ConsentJournal(JournalError::Permission)),
        );
        let observation = state.take(attempt, "exact-review").unwrap();
        assert!(matches!(
            observation.first_error.as_ref(),
            Some(Error::ReviewMismatch)
        ));
        assert!(observation.retention == DurableAdmissionRetentionV1::Unconfirmed);
        let mut failure = DurableAdmissionDispatchFailureV1::new(
            DurableAdmissionDispatchStageV1::WorkerCompletion,
            Error::Uncertain,
            false,
        );
        failure.original_error = observation.first_error;
        assert!(matches!(
            failure.original_error(),
            Some(Error::ReviewMismatch)
        ));
        assert!(matches!(failure.into_error(), Error::Uncertain));
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    #[test]
    fn admission_dispatch_reset_stale_digest_take_once_and_overflow_are_closed() {
        let mut state = QualificationDurableAdmissionV1::default();
        let first = state.begin("old-review".into()).unwrap();
        let stale = state.worker("old-review").unwrap();
        let next = state.begin("new-review".into()).unwrap();
        assert!(state.worker("old-review").is_none());
        state.record(
            Some(stale),
            DurableAdmissionCompletionV1::ReturnedErr,
            false,
            Some(Error::Locked),
        );
        assert!(state.observation.is_none());
        assert!(state.take(first, "old-review").is_none());
        assert!(state.take(next, "wrong-review").is_none());
        let actual = state.worker("new-review");
        state.record(
            actual,
            DurableAdmissionCompletionV1::ReturnedErr,
            true,
            Some(Error::Authentication),
        );
        assert!(state.take(next, "new-review").is_some());
        assert!(state.take(next, "new-review").is_none());
        assert!(state.worker("new-review").is_none());
        state.sequence = u64::MAX;
        assert!(state.begin("overflow-review".into()).is_none());
        assert!(state.active.is_none());
        assert!(state.observation.is_none());
        assert!(state.worker("overflow-review").is_none());
        // The absence of optional collection is not an operational Result.
        let operational: Result<()> = Ok(());
        assert!(operational.is_ok());
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    #[test]
    fn admission_dispatch_missing_invalidated_and_disconnected_are_not_failures_or_rollback() {
        for completion in [
            DurableAdmissionCompletionV1::Missing,
            DurableAdmissionCompletionV1::Disconnected,
        ] {
            let mut state = QualificationDurableAdmissionV1::default();
            let attempt = state.begin("review".into()).unwrap();
            state.absent(completion);
            let observed = state.take(attempt, "review").unwrap();
            assert!(observed.completion == completion);
            assert!(observed.first_error.is_none());
            assert!(observed.retention == DurableAdmissionRetentionV1::Unconfirmed);
            assert!(observed.measurement.incomplete());
        }
        let mut runtime = DurableWitnessRuntimeV1::default();
        let attempt = runtime
            .qualification_admission
            .begin("review".into())
            .unwrap();
        let observation = runtime.qualification_admission.worker("review");
        runtime.observe_admission_invalidated_v1(DurableWitnessOutcomeV1::Admission {
            dispatch: None,
            result: Err(Error::Authentication),
            observation,
        });
        let observed = runtime
            .qualification_admission
            .take(attempt, "review")
            .unwrap();
        assert!(observed.completion == DurableAdmissionCompletionV1::Invalidated);
        assert!(observed.retention == DurableAdmissionRetentionV1::Unconfirmed);
        assert!(matches!(observed.first_error, Some(Error::Authentication)));
        assert!(runtime.admission_id.is_none());
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    #[test]
    fn admission_dispatch_none_clock_failed_span_null_and_caps_are_explicit() {
        assert!(admission_optional_clock(false, || panic!(
            "observer None must not sample a clock"
        ))
        .is_none());
        let mut observation = QualificationDurableAdmissionObservationV1::new(1, "review".into());
        assert!(observation.measurement.retention_us().is_none());
        assert!(observation.measurement.callback_custody_calls().is_none());
        let mut calls = 0;
        let result: Result<()> =
            observation.callback(DurableAdmissionCallbackStageV1::Custody, || {
                calls += 1;
                Err(Error::Locked)
            });
        assert!(matches!(result, Err(Error::Locked)));
        assert_eq!(calls, 1);
        assert_eq!(observation.measurement.callback_custody_calls(), Some(1));
        assert!(observation.measurement.callback_custody_us().is_some());
        assert!(observation.measurement.request_validation_calls().is_none());
        let m = &mut observation.measurement;
        m.request_validation_calls = Some(1_000_000);
        admission_callback_cost(
            &mut m.request_validation_calls,
            &mut m.request_validation_us,
            &mut m.request_validation_max_us,
            Duration::from_secs(601),
            &mut m.clamped,
        );
        assert_eq!(m.request_validation_calls(), Some(1_000_000));
        assert_eq!(m.request_validation_us(), Some(600_000_000));
        assert_eq!(m.request_validation_max_us(), Some(600_000_000));
        assert!(m.clamped());
        let mut zero_calls = None;
        let mut zero_total = None;
        let mut zero_max = None;
        admission_callback_cost(
            &mut zero_calls,
            &mut zero_total,
            &mut zero_max,
            Duration::ZERO,
            &mut false,
        );
        assert_eq!(
            (zero_calls, zero_total, zero_max),
            (Some(1), Some(0), Some(0))
        );
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    #[test]
    fn optional_history_diagnostic_does_not_change_original_preparation_error() {
        let mut failure = DurableAdmissionPreparationFailureV1::new(
            DurableAdmissionPreparationStageV1::History,
            Error::Uncertain,
        );
        assert!(failure.take_history_failure().is_none());
        assert!(failure.take_history_failure().is_none());
        assert!(failure.stage() == DurableAdmissionPreparationStageV1::History);
        assert!(matches!(failure.into_error(), Error::Uncertain));
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    #[test]
    fn admission_preparation_observer_preserves_first_error_and_exact_attempt() {
        use DurableAdmissionPreparationStageV1 as S;
        let mut observer = QualificationDurablePreparationV1::default();
        let first = observer.begin().unwrap();
        observer.record(
            Some(first),
            S::LocalIntent,
            Error::ConsentJournal(JournalError::Expired),
        );
        observer.record(Some(first), S::WorkerCompletion, Error::ReviewMismatch);
        assert!(observer.take(first + 1).is_none());
        let failure = observer.take(first).unwrap();
        assert!(failure.stage() == S::LocalIntent);
        assert!(matches!(
            failure.into_error(),
            Error::ConsentJournal(JournalError::Expired)
        ));
        observer.record(Some(first), S::NativeStage, Error::Locked);
        assert!(observer.take(first).is_none());
        let next = observer.begin().unwrap();
        assert_ne!(next, first);
        observer.record(Some(first), S::Source, Error::Authentication);
        assert!(observer.take(next).is_none());
        observer.record(Some(next), S::Terms, Error::ReviewMismatch);
        assert!(observer.take(next).unwrap().stage() == S::Terms);
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    #[test]
    fn admission_preparation_observer_reset_and_overflow_are_closed() {
        use DurableAdmissionPreparationStageV1 as S;
        let mut observer = QualificationDurablePreparationV1::default();
        let first = observer.begin().unwrap();
        observer.record(Some(first), S::History, Error::Uncertain);
        let next = observer.begin().unwrap();
        assert!(observer.take(first).is_none());
        assert!(observer.take(next).is_none());
        observer.sequence = u64::MAX;
        assert!(observer.begin().is_none());
        observer.record(None, S::Source, Error::Locked);
        observer.record(Some(next), S::Source, Error::Locked);
        assert!(observer.failure.is_none());
        assert!(observer.native_stage.is_none());
        assert!(observer.active.is_none());
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    #[test]
    fn completion_observer_does_not_turn_history_or_uncertainty_into_fresh_success() {
        use QualificationDurableWitnessCompletionV1 as C;
        // Inert outcome classification only. No source, native decision,
        // credential, retained intent, or journal commit is constructed here.
        assert!(qualification_completion_from_outcome_v1(
            &DurableWitnessOutcomeV1::HistoricalAdmission(Ok("historical-only".into()))
        )
        .is_none());
        assert!(
            qualification_completion_from_outcome_v1(&DurableWitnessOutcomeV1::Admission {
                dispatch: None,
                result: Err(Error::Uncertain),
                observation: None,
            })
            .is_none()
        );
        assert!(
            qualification_completion_from_outcome_v1(&DurableWitnessOutcomeV1::Reconciled(Err(
                Error::ReviewMismatch
            )))
            .is_none()
        );
        let observation = qualification_completion_from_outcome_v1(
            &DurableWitnessOutcomeV1::Reconciled(Ok(DurableReconciliationOutcomeV1::Uncertain {
                review_digest: "exact-inert-digest".into(),
            })),
        );
        let state = DurableWitnessRuntimeV1 {
            qualification_completion: observation,
            ..Default::default()
        };
        assert!(state.qualification_completion_v1("wrong-digest").is_none());
        assert!(
            state.qualification_completion_v1("exact-inert-digest")
                == Some(C::ReconciliationUncertain)
        );
        assert!(
            state.qualification_completion_v1("exact-inert-digest")
                != Some(C::ReconciliationCommitted)
        );
        assert!(DurableWitnessRuntimeV1::default()
            .qualification_completion_v1("exact-inert-digest")
            .is_none());
    }
    #[test]
    fn discarding_private_custody_keeps_only_inert_admission_correlation() {
        let mut state = DurableWitnessRuntimeV1::default();
        state.admission_id = Some("historical-operation-only".into());
        state.discard_import_custody();
        assert_eq!(
            state.admission_id.as_deref(),
            Some("historical-operation-only")
        );
        assert!(state.admission_retry.is_none());
        assert!(state.session_retry.is_none());
        assert!(state.activation_retry.is_none());
        state = DurableWitnessRuntimeV1::default();
        assert!(state.admission_id.is_none());
    }
}

#[cfg(all(test, feature = "synthetic-born-joined-qualification"))]
mod durable_flow_reconciliation_tests {
    use super::*;
    use flow_diag_v1::{
        DurableFlowCallOutcomeV1 as Call, DurableFlowCallV1 as Slot,
        DurableFlowCollectorV1 as Collector, DurableFlowErrorCodeV1 as Code,
        DurableFlowJobPurposeV1 as Purpose, DurableFlowOperationV1 as Operation,
        DurableFlowResultV1 as Observed, DurableFlowStageV1 as Stage,
    };
    use std::cell::Cell;
    #[test]
    fn actual_worker_hook_retains_ok_and_err_after_receiver_drop_without_ui_receipt() {
        for successful in [false, true] {
            let collector = Collector::default();
            let observer = collector.arm(Operation::WriterReconcile);
            let job = observer.job_start(Purpose::Reconcile, 11);
            observer.record_error(Stage::ReconcileCall, &JournalError::Database);
            observer.record_terminal(Stage::FixtureState, &Error::Locked);
            let mut failure =
                flow_diag_v1::DurableFlowFailureV1::new_pending(Error::Locked, observer.clone());
            let (send, receive) = std::sync::mpsc::sync_channel(1);
            drop(receive);
            let calls = Cell::new(0);
            let work = || {
                calls.set(calls.get() + 1);
                WitnessOutcome::DurablePaymentV1(DurableWitnessOutcomeV1::Reconciled(
                    if successful {
                        Ok(DurableReconciliationOutcomeV1::Uncertain {
                            review_digest: "inert-only".into(),
                        })
                    } else {
                        Err(Error::Authentication)
                    },
                ))
            };
            let original = work();
            observe_flow_worker_v1(&job, Stage::ReconcileCall, &original);
            let forwarded = send.send(original).err().unwrap().0;
            assert!(calls.get() == 1);
            match forwarded {
                WitnessOutcome::DurablePaymentV1(DurableWitnessOutcomeV1::Reconciled(result)) => {
                    assert!(result.is_ok() == successful)
                }
                _ => panic!("original worker outcome changed"),
            }
            observer.record_drain(&Ok::<(), Error>(()));
            failure.finalize_after_drain();
            let initial = failure.diagnostic().unwrap();
            assert!(initial.first_error().unwrap().code() == Code::JournalDatabase);
            assert!(initial.terminal_error().unwrap().code() == Code::SignerLocked);
            assert!(initial.completion().receive() == flow_diag_v1::DurableFlowReceiveV1::Pending);
            assert!(initial.completion().result() == Observed::NotObserved);
            assert!(
                initial.completion().presentation()
                    == flow_diag_v1::DurableFlowPresentationV1::NotObserved
            );
            let after = initial.after_drain().unwrap();
            assert!(
                after.worker_result()
                    == if successful {
                        Observed::ReturnedOk
                    } else {
                        Observed::ReturnedErr
                    }
            );
            assert!(after.worker_error().is_some() == !successful);
            assert!(matches!(failure.into_error(), Error::Locked));
        }
    }
    #[test]
    fn actual_reconciliation_database_error_stays_uncertain_with_separate_calls() {
        let collector = Collector::default();
        let observer = collector.arm(Operation::WriterReconcile);
        let job = observer.job_start(Purpose::Reconcile, 7);
        let calls = Cell::new(0);
        let original: std::result::Result<(), JournalError> = durable_flow_call_v1!(
            Some(&observer),
            Slot::Reconciliation,
            Stage::ReconcileCall,
            Err(JournalError::Database)
        );
        let result = finish_durable_reconciliation_v1(
            original,
            "inert-digest".into(),
            || {
                calls.set(calls.get() + 1);
                Ok(())
            },
            Some(&observer),
        );
        assert_eq!(calls.get(), 1);
        assert!(
            matches!(&result, Ok(DurableReconciliationOutcomeV1::Uncertain { review_digest }) if review_digest == "inert-digest")
        );
        job.received(Stage::ReconcileCall, &result);
        let report = observer.finish(Observed::ReturnedErr).unwrap();
        assert!(report.first_error().unwrap().code() == Code::JournalDatabase);
        assert!(report.call_outcomes().reconciliation() == Call::ReturnedErr);
        assert!(report.call_outcomes().session_invalidation() == Call::ReturnedOk);
        assert!(report.completion().result() == Observed::ReturnedOk);
    }
    #[test]
    fn actual_reconciliation_invalidation_error_stays_uncertain_without_postcheck() {
        for diagnosed in [false, true] {
            let collector = Collector::default();
            let observer = collector.arm(Operation::WriterReconcile);
            let calls = Cell::new(0);
            let original: std::result::Result<(), JournalError> = durable_flow_call_v1!(
                diagnosed.then_some(&observer),
                Slot::Reconciliation,
                Stage::ReconcileCall,
                Ok(())
            );
            let result = finish_durable_reconciliation_v1(
                original,
                "inert-digest".into(),
                || {
                    calls.set(calls.get() + 1);
                    Err(JournalError::Permission)
                },
                diagnosed.then_some(&observer),
            );
            assert_eq!(calls.get(), 1);
            assert!(matches!(
                result,
                Ok(DurableReconciliationOutcomeV1::Uncertain { .. })
            ));
            if diagnosed {
                let report = observer.finish(Observed::ReturnedErr).unwrap();
                assert!(report.first_error().unwrap().code() == Code::JournalPermission);
                assert!(report.first_error().unwrap().stage() == Stage::Invalidate);
                assert!(report.call_outcomes().reconciliation() == Call::ReturnedOk);
                assert!(report.call_outcomes().session_invalidation() == Call::ReturnedErr);
            }
        }
    }
    #[test]
    fn actual_reconciliation_precommit_refusal_does_not_invalidate() {
        let collector = Collector::default();
        let observer = collector.arm(Operation::WriterReconcile);
        let original: std::result::Result<(), JournalError> = durable_flow_call_v1!(
            Some(&observer),
            Slot::Reconciliation,
            Stage::ReconcileCall,
            Err(JournalError::Expired)
        );
        let result = finish_durable_reconciliation_v1(
            original,
            "inert-digest".into(),
            || panic!("precommit refusal must preserve source"),
            Some(&observer),
        );
        assert!(matches!(
            result,
            Err(Error::ConsentJournal(JournalError::Expired))
        ));
        let report = observer.finish(Observed::ReturnedErr).unwrap();
        assert!(report.first_error().unwrap().code() == Code::JournalExpired);
        assert!(report.call_outcomes().session_invalidation() == Call::NotObserved);
    }
    #[test]
    fn actual_witness_display_old_job_cannot_populate_new_attempt() {
        let collector = Collector::default();
        let old = collector.arm(Operation::WriterReconcile);
        let _job = old.job_start(Purpose::AcquirePrepare, 7);
        let current = collector.arm(Operation::WriterReconcile);
        let original = durable_witness_display_result_v1(
            Err(Error::Verification),
            Some(&old),
            Stage::AcquireNative,
        );
        assert!(matches!(original, Err(Error::Verification)));
        let report = current.finish(Observed::ReturnedErr).unwrap();
        assert!(report.first_error().is_none());
        assert!(report.incomplete());
    }
}

#[cfg(all(test, feature = "synthetic-born-joined-qualification"))]
mod acquire_reply_loss_session_tests {
    use super::*;
    use flow_diag_v1::{
        DurableFlowCollectorV1 as Collector, DurableFlowJobPurposeV1 as Purpose,
        DurableFlowOperationV1 as Flow, DurableFlowResultV1 as Observed,
        DurableFlowStageV1 as Stage,
    };

    #[derive(Debug)]
    struct OriginalError(u8);
    impl std::fmt::Display for OriginalError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "inert-test-{}", self.0)
        }
    }
    impl std::error::Error for OriginalError {}

    #[test]
    fn actual_session_error_is_owned_once_and_correlated_to_observed_job() {
        let collector = Collector::default();
        let observer = collector.arm(Flow::WriterReconcile);
        let mut state = QualificationSessionV1::default();
        let serial = state.begin(&observer, "same-review").unwrap();
        let attempt = state.dispatch(Some(&observer), "same-review").unwrap();
        assert!(state.dispatch(Some(&observer), "same-review").is_none());
        let job = observer.job_start(Purpose::Acquire, 1);
        let owned = Box::new(OriginalError(41));
        let original_address = (&*owned as *const OriginalError) as usize;
        let owned: Box<dyn std::error::Error + Send + Sync> = owned;
        let result: Result<()> = Err(Error::Io(std::io::Error::other(owned)));
        job.returned(Stage::AcquireCall, &result);
        job.received(Stage::AcquireCall, &result);
        state.accept(Some(attempt), Some(&observer), "same-review", result.err());
        assert!(state.accepted == Some(false));
        let error = state.take_error(serial, "same-review").unwrap();
        match error {
            Error::Io(error) => {
                let actual = error
                    .get_ref()
                    .unwrap()
                    .downcast_ref::<OriginalError>()
                    .unwrap();
                assert_eq!(actual as *const OriginalError as usize, original_address);
            }
            _ => panic!("actual owned error was replaced"),
        }
        assert!(state.take_error(serial, "same-review").is_none());
        let diagnostic = observer.finish(Observed::ReturnedErr).unwrap();
        assert!(diagnostic.completion().purpose() == Some(Purpose::Acquire));
        assert!(diagnostic.completion().result() == Observed::ReturnedErr);
        assert!(diagnostic.completion().receive() == flow_diag_v1::DurableFlowReceiveV1::Received);
    }

    #[test]
    fn session_error_wrong_digest_stale_attempt_and_wrong_observer_never_match() {
        let collector = Collector::default();
        let first = collector.arm(Flow::WriterReconcile);
        let mut state = QualificationSessionV1::default();
        let first_serial = state.begin(&first, "same-review").unwrap();
        let stale = state.dispatch(Some(&first), "same-review").unwrap();
        state.accept(
            Some(stale.clone()),
            Some(&first),
            "same-review",
            Some(Error::Authentication),
        );
        assert!(state.take_error(first_serial, "wrong-review").is_none());
        assert!(matches!(
            state.take_error(first_serial, "same-review"),
            Some(Error::Authentication)
        ));
        let retry = collector.arm(Flow::WriterReconcile);
        let serial = state.begin(&retry, "same-review").unwrap();
        assert_ne!(serial, first_serial);
        let current = state.dispatch(Some(&retry), "same-review").unwrap();
        state.accept(
            Some(stale),
            Some(&retry),
            "same-review",
            Some(Error::Uncertain),
        );
        assert!(state.accepted.is_none());
        assert!(state.take_error(serial, "same-review").is_none());
        state.accept(
            Some(current),
            Some(&first),
            "same-review",
            Some(Error::Uncertain),
        );
        assert!(state.accepted.is_none());
        assert!(state.take_error(serial, "same-review").is_none());
    }

    #[test]
    fn stale_and_duplicate_session_results_cannot_erase_or_replace_current_error() {
        let collector = Collector::default();
        let first = collector.arm(Flow::WriterReconcile);
        let mut state = QualificationSessionV1::default();
        let old_serial = state.begin(&first, "review").unwrap();
        let old = state.dispatch(Some(&first), "review").unwrap();
        let current = collector.arm(Flow::WriterReconcile);
        let serial = state.begin(&current, "review").unwrap();
        let payload = state.dispatch(Some(&current), "review").unwrap();
        state.accept(
            Some(payload.clone()),
            Some(&current),
            "review",
            Some(Error::Authentication),
        );
        state.accept(Some(old), Some(&current), "review", Some(Error::Uncertain));
        state.accept(Some(payload.clone()), Some(&current), "review", None);
        state.accept(Some(payload), Some(&current), "review", Some(Error::Locked));
        state.accept(None, None, "review", Some(Error::InvalidData));
        assert!(state.accepted == Some(false));
        assert!(state.take_error(old_serial, "review").is_none());
        assert!(state.take_error(serial, "wrong-review").is_none());
        assert!(matches!(
            state.take_error(serial, "review"),
            Some(Error::Authentication)
        ));
        assert!(state.take_error(serial, "review").is_none());
    }

    #[test]
    fn session_success_missing_disconnected_invalidated_and_overflow_are_not_errors() {
        for mode in 0..5 {
            let collector = Collector::default();
            let observer = collector.arm(Flow::WriterReconcile);
            let mut state = QualificationSessionV1::default();
            let serial = state.begin(&observer, "review").unwrap();
            let attempt = state.dispatch(Some(&observer), "review").unwrap();
            match mode {
                0 => state.accept(Some(attempt), Some(&observer), "review", None),
                1 => state.accept(None, Some(&observer), "review", Some(Error::Uncertain)),
                2 | 3 => {
                    let delayed = attempt.clone();
                    state.accept(
                        Some(attempt),
                        Some(&observer),
                        "review",
                        Some(Error::Uncertain),
                    );
                    state.absent();
                    state.accept(
                        Some(delayed),
                        Some(&observer),
                        "review",
                        Some(Error::Authentication),
                    );
                }
                _ => {
                    state.next = u64::MAX;
                    assert!(state.begin(&observer, "review").is_none());
                    state.accept(
                        Some(attempt),
                        Some(&observer),
                        "review",
                        Some(Error::Uncertain),
                    );
                }
            }
            assert!(state.take_error(serial, "review").is_none());
        }
    }

    #[test]
    fn session_evidence_none_and_reset_do_not_mutate_original_retry_slots() {
        let collector = Collector::default();
        let observer = collector.arm(Flow::WriterReconcile);
        let mut runtime = DurableWitnessRuntimeV1::default();
        let serial = runtime
            .qualification_session
            .begin(&observer, "review")
            .unwrap();
        let payload = runtime
            .qualification_session
            .dispatch(Some(&observer), "review");
        runtime.qualification_session.accept(
            payload,
            Some(&observer),
            "review",
            Some(Error::Uncertain),
        );
        assert!(runtime.session_retry.is_none() && runtime.activation_retry.is_none());
        assert!(
            runtime
                .qualification_session
                .take_error(serial, "review")
                .is_some()
        );
        runtime.qualification_session.begin(&observer, "review");
        assert!(runtime.session_retry.is_none() && runtime.activation_retry.is_none());
        assert!(runtime.qualification_session.error.is_none());
        // No Approved or receipt factory is used. The observer's type cannot
        // access either production slot, and unobserved collection is inert.
        runtime
            .qualification_session
            .accept(None, None, "review", Some(Error::Authentication));
        assert!(runtime.qualification_session.error.is_none());
    }
}
