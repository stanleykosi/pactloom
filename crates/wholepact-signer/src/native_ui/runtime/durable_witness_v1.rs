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
    CheckedHistoryFailureV1, CheckedHistoryIoKindV1, CheckedHistoryStageV1,
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
    source.check_current()?;
    let signer = &source.entry().record().account_record.terms.signer;
    let certificate = match role {
        CredentialRole::Owner => &signer.owner_certificate_digest,
        CredentialRole::Writer => &signer.writer_certificate_digest,
    };
    workspace.require_durable_credential_v1(
        &source.entry().native_binding(),
        &source.entry().original_witness_disclosure()?,
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
) -> Result<ReconciledAuthorityHistory> {
    require_workspace_source(workspace, source, role)?;
    #[cfg(feature = "synthetic-born-joined-qualification")]
    if let Some(failure) = failure {
        return workspace.durable_history_diagnosed_v1(
            deadline,
            || require_workspace_source(workspace, source, role),
            failure,
        );
    }
    workspace.durable_history_v1(deadline, || {
        require_workspace_source(workspace, source, role)
    })
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
    source.check_current()?;
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
        source.check_current()?;
        let disclosure = source.entry().original_witness_disclosure()?;
        workspace.require_durable_credential_v1(
            &source.entry().native_binding(),
            &disclosure,
            certificate,
        )?;
        let deadline = source
            .deadline()?
            .min(Instant::now() + Duration::from_secs(120));
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
                require_request_under_fence(&self.custody.source, &self.request)
                    .map_err(|_| JournalError::Permission)
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
        self.custody.workspace(owner)?;
        require_intent(&self.custody.source, &self.retained)?;
        require_live(self.retained.request())?;
        owner.durable_admit_v1(self.retained.request(), self.custody.deadline, || {
            self.custody.workspace(owner)?;
            require_request(&self.custody.source, self.retained.request())
        })
    }
}

pub(super) struct PreparedDurableWriterSessionV1 {
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
        source.check_current()?;
        let history = source_history(
            workspace,
            &source,
            CredentialRole::Writer,
            source.deadline()?,
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
            custody,
            history,
            admission,
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
        self.0.custody.workspace(workspace)?;
        require_live(&self.0.admission)?;
        // NEVER refresh history/head on retry: this exact captured pre-acquire
        // history belongs to the same actual client and its retained key.
        workspace.durable_acquire_v1(
            &self.0.history,
            &self.0.admission.operation_id,
            self.0.custody.deadline,
            || {
                self.0.custody.workspace(workspace)?;
                require_request(&self.0.custody.source, &self.0.admission)
            },
        )
    }
}

pub(super) struct PreparedDurableWriterActivationV1 {
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
        source.check_current()?;
        let history = source_history(owner, &source, CredentialRole::Owner, source.deadline()?)?;
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
        self.0.custody.workspace(owner)?;
        require_live(&self.0.admission)?;
        owner.durable_activate_v1(
            &self.0.history,
            &self.0.admission.operation_id,
            &self.0.request,
            self.0.custody.deadline,
            || {
                self.0.custody.workspace(owner)?;
                require_request(&self.0.custody.source, &self.0.admission)
            },
        )
    }
}

pub(super) struct PreparedDurableWriterReconciliationV1 {
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
        source.check_current()?;
        let deadline = source
            .deadline()?
            .min(Instant::now() + Duration::from_secs(120));
        let history = source_history(workspace, &source, CredentialRole::Writer, deadline)?;
        let intent = committed_intent(&source, &history, admission_operation_id)?;
        workspace.require_durable_credential_v1(
            &source.entry().native_binding(),
            history.disclosure(),
            &admission_terms(intent.request())?.writer_certificate_digest,
        )?;
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
        source.check_current()?;
        Ok(Self {
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
        self.source.check_current()?;
        require_request(&self.source, &self.admission)?;
        if Instant::now() >= self.deadline {
            return Err(Error::ReviewMismatch);
        }
        let result =
            self.source
                .entry()
                .journal()
                .reconcile_writer_checked_v1(self.approved, || {
                    if Instant::now() >= self.deadline {
                        return Err(JournalError::Permission);
                    }
                    require_request_under_fence(&self.source, &self.admission)
                        .map_err(|_| JournalError::Permission)
                });
        // No post-invalidation current-source assertion. Committed/uncertain
        // outcomes are inert evidence, never continuation of the old import.
        // Even uncertainty drains local permission; it never resets remote state.
        match result {
            Ok(_) => {
                let invalidated = self.source.session().invalidate();
                Ok(if invalidated.is_ok() {
                    DurableReconciliationOutcomeV1::Committed {
                        review_digest: self.review_digest,
                    }
                } else {
                    DurableReconciliationOutcomeV1::Uncertain {
                        review_digest: self.review_digest,
                    }
                })
            }
            Err(JournalError::Database) => {
                let _ = self.source.session().invalidate();
                Ok(DurableReconciliationOutcomeV1::Uncertain {
                    review_digest: self.review_digest,
                })
            }
            // Proven pre-commit refusal leaves the original source intact.
            Err(error) => Err(error.into()),
        }
    }
}

/// Per-open owner state. Dropping it never deletes the immutable SQL intent or
/// any remote exposure. A new owner must resolve original authenticated history.
#[derive(Default)]
pub(super) struct DurableWitnessRuntimeV1 {
    admission_id: Option<String>,
    admission_retry: Option<Arc<DurableWitnessAdmissionDispatchV1>>,
    session_retry: Option<Arc<ApprovedDurableWriterSessionV1>>,
    activation_retry: Option<Arc<ApprovedDurableWriterActivationV1>>,
    #[cfg(feature = "synthetic-born-joined-qualification")]
    qualification_completion: Option<(String, QualificationDurableWitnessCompletionV1)>,
    #[cfg(feature = "synthetic-born-joined-qualification")]
    qualification_preparation: QualificationDurablePreparationV1,
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
    pub(super) fn discard_import_custody(&mut self) {
        self.admission_retry = None;
        self.session_retry = None;
        self.activation_retry = None;
    }
}
impl DurableWitnessPreparedV1 {
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
    },
    Session {
        approved: Arc<ApprovedDurableWriterSessionV1>,
        result: Result<WriterSessionReceipt>,
    },
    Activation {
        approved: Arc<ApprovedDurableWriterActivationV1>,
        result: Result<AccountSnapshot>,
    },
    Reconciled(Result<DurableReconciliationOutcomeV1>),
}
impl NativeRuntime {
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
                )?;
                #[cfg(feature = "synthetic-born-joined-qualification")]
                {
                    stage = DurableAdmissionPreparationStageV1::RetainedIntent;
                }
                if let Some(retained) = local_intent(&source)? {
                    require_intent(&source, &retained)?;
                    match history
                        .durable_payment_admission_v1(&retained.request().operation_id)
                        .map_err(|_| Error::RecoveryRequired)?
                    {
                        Some(exact) if exact == retained.request() => {
                            committed_intent(&source, &history, &exact.operation_id)?;
                            return Ok(DurableWitnessOutcomeV1::HistoricalAdmission(Ok(exact
                                .operation_id
                                .clone())));
                        }
                        Some(_) => return Err(Error::RecoveryRequired),
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
        self.start_witness_job(epoch, move |cancelled| {
            WitnessOutcome::DurablePaymentV1(DurableWitnessOutcomeV1::Prepared((|| {
                if cancelled.load(Ordering::Acquire) {
                    return Err(Error::Locked);
                }
                Ok(Box::new(DurableWitnessPreparedV1::Session(
                    PreparedDurableWriterSessionV1::prepare(&witness, source, &id)?,
                )))
            })()))
        })
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
        self.start_witness_job(epoch, move |cancelled| {
            WitnessOutcome::DurablePaymentV1(DurableWitnessOutcomeV1::Prepared((|| {
                if cancelled.load(Ordering::Acquire) {
                    return Err(Error::Locked);
                }
                Ok(Box::new(DurableWitnessPreparedV1::Activation(
                    PreparedDurableWriterActivationV1::prepare(&owner, source, &id, receipt)?,
                )))
            })()))
        })
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
        self.start_witness_job(epoch, move |cancelled| {
            WitnessOutcome::DurablePaymentV1(DurableWitnessOutcomeV1::Prepared((|| {
                if cancelled.load(Ordering::Acquire) {
                    return Err(Error::Locked);
                }
                Ok(Box::new(DurableWitnessPreparedV1::Reconciliation(
                    PreparedDurableWriterReconciliationV1::prepare(&witness, source, &id)?,
                )))
            })()))
        })
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
                let approved = value.approve(decision, &open.authority, &owner)?;
                self.start_witness_job(epoch, move |cancelled| {
                    let outcome = if cancelled.load(Ordering::Acquire) {
                        DurableWitnessOutcomeV1::Admission {
                            dispatch: None,
                            result: Err(Error::Locked),
                        }
                    } else {
                        match approved.retain() {
                            Ok(dispatch) => {
                                let dispatch = Arc::new(dispatch);
                                let result = dispatch.submit(&owner);
                                DurableWitnessOutcomeV1::Admission {
                                    dispatch: Some(dispatch),
                                    result,
                                }
                            }
                            Err(error) => DurableWitnessOutcomeV1::Admission {
                                dispatch: None,
                                result: Err(error),
                            },
                        }
                    };
                    WitnessOutcome::DurablePaymentV1(outcome)
                })
            }
            DurableWitnessPreparedV1::Session(value) => {
                let witness = open.witness.clone().ok_or(Error::Locked)?;
                let approved = Arc::new(value.approve(decision, &open.authority, &witness)?);
                self.start_witness_job(epoch, move |cancelled| {
                    let result = if cancelled.load(Ordering::Acquire) {
                        Err(Error::Locked)
                    } else {
                        approved.acquire(&witness)
                    };
                    WitnessOutcome::DurablePaymentV1(DurableWitnessOutcomeV1::Session {
                        approved,
                        result,
                    })
                })
            }
            DurableWitnessPreparedV1::Activation(value) => {
                let owner = open.owner_witness.clone().ok_or(Error::Locked)?;
                let approved = Arc::new(value.approve(decision, &open.authority, &owner)?);
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
            DurableWitnessPreparedV1::Reconciliation(value) => {
                let approved = value.approve(decision)?;
                self.start_witness_job(epoch, move |cancelled| {
                    WitnessOutcome::DurablePaymentV1(DurableWitnessOutcomeV1::Reconciled(
                        if cancelled.load(Ordering::Acquire) {
                            Err(Error::Locked)
                        } else {
                            approved.reconcile()
                        },
                    ))
                })
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
                self.start_witness_job(epoch, move |cancelled| {
                    let result = if cancelled.load(Ordering::Acquire) {
                        Err(Error::Locked)
                    } else {
                        approved.acquire(&witness)
                    };
                    WitnessOutcome::DurablePaymentV1(DurableWitnessOutcomeV1::Session {
                        approved,
                        result,
                    })
                })
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
        } => Some((dispatch.custody.digest.clone(), C::AdmissionCommitted)),
        DurableWitnessOutcomeV1::Session {
            approved,
            result: Ok(_),
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
pub(super) fn complete(
    open: &mut OpenAccount,
    outcome: DurableWitnessOutcomeV1,
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
            return ("Durable witness history or source was rejected. No new body, session or approval was substituted.", None);
        }
        let (message, prepared) = complete(open, *outcome);
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
            let display = value.display();
            (
                "Review the exact source-bound durable witness operation.",
                Some((digest, display, Operation::DurableWitnessV1(value))),
            )
        }
        DurableWitnessOutcomeV1::HistoricalAdmission(Ok(id)) => {
            // Correlation only. Every later live constructor independently
            // rejoins current source, exact intent, complete history and limits.
            open.durable_witness.admission_id = Some(id);
            ("Exact retained admission is committed in authenticated complete history. This is historical evidence, not renewed approval or a replacement session.", None)
        }
        DurableWitnessOutcomeV1::Admission { dispatch, result } => {
            let Some(dispatch) = dispatch else {
                return ("No admission dispatch was confirmed. Inspect the original local intent before retrying; do not assume local retention or remote rollback, and never create a replacement body or ID.", None);
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
            (message, None)
        }
        DurableWitnessOutcomeV1::Session { approved, result } => {
            open.durable_witness.session_retry = Some(approved);
            match result {
                Ok(receipt) => {
                    open.writer_receipt = Some(receipt);
                    ("Exact durable writer session acquired. Separate original-owner activation is required.", None)
                }
                Err(_) => ("Writer acquisition is uncertain. Keep this same client/key and exact pre-acquire request; never prepare a replacement session.", None),
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
                return ("Reconciliation was refused before commit. The original source and exposure remain unchanged; inspect the exact failure before a fresh review.", None);
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
        _ => ("Durable witness history or source was rejected. No new body, session or approval was substituted.", None),
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
                result: Err(Error::Uncertain)
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
