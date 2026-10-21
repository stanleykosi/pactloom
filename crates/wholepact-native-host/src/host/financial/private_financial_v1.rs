//! Original private financial orchestration. Read/source permission, artifact
//! retention, actual signing and final dispatch are separate nominal purposes.
use super::Host;
use crate::host::durable_dispatcher_v2::OriginalFinancialOwnerV1;
use crate::terminal::historical::HistoricalApproval;
use crate::{Error, Result};
use wholepact_engine::durable_construction_v1::{
    DurableMaterialActionV1, LocalDurableMaterialConsentV1,
};
use wholepact_engine::{
    LocalPrivateDurableFinancialConsentV1, PrivateDurableFinancialInspectionV1,
    PrivateWorkspaceScopeV1,
};
use wholepact_proof_jobs::{CheckpointScope, LocalAction, LocalProofConsent};
use wholepact_signer::authority_bridge::durable_construction_v1::DurableConstructionScopeV1;

// Diagnostics are erased outside the explicit synthetic qualification build.
macro_rules! financial_record {
    ($kind:ident, $stage:ident, $state:ident, $error:expr) => {{
        #[cfg(all(
            test,
            feature = "synthetic-born-joined-qualification",
            feature = "durable-proposal"
        ))]
        crate::host::financial_diagnostics_v1::$kind(
            crate::host::financial_diagnostics_v1::FinancialStageV1::$stage,
            crate::host::financial_diagnostics_v1::FinancialCommitStateV1::$state,
            $error,
        );
    }};
}
macro_rules! financial_step {
    ($stage:ident, $state:ident) => {{
        #[cfg(all(
            test,
            feature = "synthetic-born-joined-qualification",
            feature = "durable-proposal"
        ))]
        crate::host::financial_diagnostics_v1::set_stage(
            crate::host::financial_diagnostics_v1::FinancialStageV1::$stage,
            crate::host::financial_diagnostics_v1::FinancialCommitStateV1::$state,
        );
    }};
}
fn same<T: serde::Serialize>(left: &T, right: &T) -> bool {
    serde_json::to_vec(left)
        .ok()
        .zip(serde_json::to_vec(right).ok())
        .is_some_and(|(left, right)| left == right)
}
fn original_source_clocks_current(bounds: Option<(u64, u64)>) -> bool {
    let Some((from, until)) = bounds else { return false; };
    let Ok(elapsed) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) else { return false; };
    let Ok(now) = u64::try_from(elapsed.as_millis()) else { return false; };
    original_source_clocks_at((from, until), now)
}
fn original_source_clocks_at((from, until): (u64, u64), now: u64) -> bool {
    from <= now && now < until
}
fn original_material_clocks_current(inspection: &PrivateDurableFinancialInspectionV1) -> Result<()> {
    if inspection.materials().len() != 2 { return Err(Error::Authentication); }
    let now = crate::now()?;
    if inspection.materials().iter().any(|m| now < m.scope().valid_from_unix_seconds || now >= m.scope().valid_until_unix_seconds) {
        return Err(Error::Permission);
    }
    Ok(())
}
fn original_materials_current(inspection: &PrivateDurableFinancialInspectionV1) -> Result<()> {
    if inspection.materials().len() != 2 {
        return Err(Error::Authentication);
    }
    let now = crate::now()?;
    for material in inspection.materials() {
        material
            .scope()
            .check_valid_at(now)
            .map_err(|_| Error::Permission)?;
    }
    Ok(())
}
/// No terminal or lazy review method. This exact read permission cannot export,
/// reserve, sign, extract, retain new results or dispatch. Engine pins separately
/// bind its pure mathematical verification to the actual original connection.
struct ClosedFinancialReadConsentV1<'a, 'host> {
    owner: &'a OriginalFinancialOwnerV1<'host>,
    inspection: &'a PrivateDurableFinancialInspectionV1,
    approval: &'a HistoricalApproval,
}
impl ClosedFinancialReadConsentV1<'_, '_> {
    fn check(&self) -> Result<()> {
        self.approval.check()?;
        self.owner.check_read_source()?;
        original_materials_current(self.inspection)?;
        if !same(
            self.owner.workspace_scope(),
            self.inspection.workspace_scope(),
        ) {
            return Err(Error::Authentication);
        }
        self.approval.check()
    }
}
fn financial_prompt_bounds(read: &ClosedFinancialReadConsentV1<'_, '_>, source: Option<(u64, u64)>) -> Result<Option<crate::terminal::OriginalPromptBoundsV1>> {
    if !crate::terminal::coordinated_restriction_required() { return Ok(None); }
    let materials = read.inspection.materials();
    if materials.len() != 2 { return Err(Error::Authentication); }
    let from = materials.iter().map(|m| m.scope().valid_from_unix_seconds).max().ok_or(Error::Authentication)?
        .checked_mul(1000).ok_or(Error::Permission)?;
    let until = materials.iter().map(|m| m.scope().valid_until_unix_seconds).min().ok_or(Error::Authentication)?
        .checked_mul(1000).ok_or(Error::Permission)?;
    let bounds = source.map_or((from, until), |(a, b)| (from.max(a), until.min(b)));
    Ok(Some(crate::terminal::OriginalPromptBoundsV1::new(read.approval.deadline(), bounds)?))
}
impl LocalPrivateDurableFinancialConsentV1 for ClosedFinancialReadConsentV1<'_, '_> {
    fn check_final_effect_restriction_v1(&self) -> bool {
        !crate::terminal::coordinated_restriction_required()
            || (original_material_clocks_current(self.inspection).is_ok() && self.approval.check().is_ok())
    }
    fn permits_source(&self, scope: &PrivateWorkspaceScopeV1) -> bool {
        same(scope, self.inspection.workspace_scope()) && self.check().is_ok()
    }
}
impl LocalProofConsent for ClosedFinancialReadConsentV1<'_, '_> {
    fn permits(&self, scope: &CheckpointScope, action: LocalAction) -> bool {
        scope == self.inspection.checkpoint_scope()
            && matches!(
                action,
                LocalAction::InspectStatus | LocalAction::ReadPrivateArtifact
            )
            && self.check().is_ok()
    }
}
impl LocalDurableMaterialConsentV1 for ClosedFinancialReadConsentV1<'_, '_> {
    fn permits(
        &self,
        scope: &DurableConstructionScopeV1,
        digest: &str,
        action: DurableMaterialActionV1,
    ) -> bool {
        matches!(action, DurableMaterialActionV1::ReadForExactConstruction)
            && self
                .inspection
                .materials()
                .iter()
                .any(|m| m.scope() == scope && m.material_digest() == digest)
            && self.check().is_ok()
    }
}

/// Holds all actual original source/proof pins and independent admissions until
/// the concrete chain orchestrator has persisted the attempt outcome.
struct ProductionDurableSubmissionAuthorityV1<'a, 'prepared, 'owner, 'source, 'host> {
    verified: &'a wholepact_engine::VerifiedPrivateDurableSubmissionV1<'prepared, 'owner, 'source>,
    access: &'a wholepact_engine::Access,
    read: &'a ClosedFinancialReadConsentV1<'a, 'host>,
    admissions: &'a [wholepact_authority::completed_dispatch_v1::AuthenticatedCompletedDispatchAdmissionV1;
            2],
    native: &'a crate::authority::durable_submission_v1::NativeDurableSubmissionConsentV1,
    retention: &'a crate::authority::retention::FrozenNativeFinancialRetentionConsentV1,
    used: bool,
}
struct ProductionDurableSubmissionPermitV1<'a, 'prepared, 'owner, 'source, 'host> {
    verified: &'a wholepact_engine::VerifiedPrivateDurableSubmissionV1<'prepared, 'owner, 'source>,
    access: &'a wholepact_engine::Access,
    read: &'a ClosedFinancialReadConsentV1<'a, 'host>,
    admissions: &'a [wholepact_authority::completed_dispatch_v1::AuthenticatedCompletedDispatchAdmissionV1;
            2],
    native: &'a crate::authority::durable_submission_v1::NativeDurableSubmissionConsentV1,
    retention: &'a crate::authority::retention::FrozenNativeFinancialRetentionConsentV1,
    send_until: u64,
    expected_attempt: u32,
    restriction: OriginalSubmissionRestrictionV1<'a>,
}
impl<'a, 'prepared, 'owner, 'source, 'host> wholepact_chain::SubmissionAuthority
    for ProductionDurableSubmissionAuthorityV1<'a, 'prepared, 'owner, 'source, 'host>
{
    type Permit = ProductionDurableSubmissionPermitV1<'a, 'prepared, 'owner, 'source, 'host>;
    fn authorize(
        &mut self,
        review: &wholepact_chain::SubmissionReview<'_>,
    ) -> std::result::Result<Self::Permit, wholepact_chain::ChainError> {
        use wholepact_chain::{ChainError, SubmissionPermit};
        if self.used {
            return Err(ChainError::SubmissionNotAuthorized);
        }
        let mut until = self
            .native
            .valid_until_unix_seconds()
            .min(self.retention.valid_until_unix_seconds().saturating_sub(1));
        for admission in self.admissions {
            until = until.min(
                crate::authority::durable_submission_v1::strict_ms_to_inclusive_seconds(
                    admission.admission().expires_at_ms,
                )
                .map_err(|_| ChainError::SubmissionNotAuthorized)?,
            );
        }
        for material in self.read.inspection.materials() {
            // Material APIs use strict wall-clock expiry too. Preserve its
            // original stored interval; never use a new relative lifetime.
            until = until.min(material.scope().valid_until_unix_seconds.saturating_sub(1));
        }
        // HistoricalApproval is monotonic-only. Snapshot its remaining bound
        // conservatively into the final token; it remains independently held.
        let remaining = self
            .read
            .approval
            .deadline()
            .checked_duration_since(std::time::Instant::now())
            .ok_or(ChainError::SubmissionNotAuthorized)?
            .as_secs();
        until = until.min(
            crate::now()
                .map_err(|_| ChainError::SubmissionNotAuthorized)?
                .checked_add(remaining)
                .and_then(|v| v.checked_sub(1))
                .ok_or(ChainError::SubmissionNotAuthorized)?,
        );
        let mut permit = ProductionDurableSubmissionPermitV1 {
            verified: self.verified,
            access: self.access,
            read: self.read,
            admissions: self.admissions,
            native: self.native,
            retention: self.retention,
            send_until: until,
            restriction: OriginalSubmissionRestrictionV1 {
                native: self.native, read_deadline: self.read.approval.deadline(), send_until: until,
            },
            expected_attempt: self
                .verified
                .expected_dispatch_chain_attempt_v1()
                .map_err(|_| ChainError::SubmissionNotAuthorized)?,
        };
        permit.check_current(review)?;
        self.used = true;
        Ok(permit)
    }
}
/// Borrows only the native restriction and immutable original clocks, never
/// the source owner or a full permission callback. It can only deny effects.
struct OriginalSubmissionRestrictionV1<'a> {
    native: &'a crate::authority::durable_submission_v1::NativeDurableSubmissionConsentV1,
    read_deadline: std::time::Instant,
    send_until: u64,
}
impl wholepact_chain::SubmissionEffectRestriction for OriginalSubmissionRestrictionV1<'_> {
    fn check_before_effect(&self) -> std::result::Result<(), wholepact_chain::ChainError> {
        let denied = || wholepact_chain::ChainError::SubmissionNotAuthorized;
        let now = crate::now().map_err(|_| denied())?;
        if std::time::Instant::now() >= self.read_deadline || now > self.send_until
            || now.saturating_mul(1000) < self.native.reviewed_at_ms()
        { return Err(denied()); }
        // Both native and frozen financial retention were issued by the same
        // self.authority Fence in dispatch_completed_private_financial_v1; the
        // retention's earlier expiry is already included in send_until.
        self.native.check_final_effect_restriction().map_err(|_| denied())
    }
}
impl wholepact_chain::SubmissionPermit for ProductionDurableSubmissionPermitV1<'_, '_, '_, '_, '_> {
    fn effect_restriction(&self) -> Option<&dyn wholepact_chain::SubmissionEffectRestriction> {
        if crate::terminal::coordinated_restriction_required() {
            Some(&self.restriction)
        } else { None }
    }
    fn valid_until_unix_seconds(&self) -> Option<u64> {
        Some(self.send_until)
    }
    fn expected_attempt_number(&self) -> Option<u32> {
        Some(self.expected_attempt)
    }
    fn check_current(
        &mut self,
        review: &wholepact_chain::SubmissionReview<'_>,
    ) -> std::result::Result<(), wholepact_chain::ChainError> {
        use wholepact_chain::ChainError;
        let denied = || ChainError::SubmissionNotAuthorized;
        // REQUIRED with missing/failed installation denies before a permit can
        // be issued; effect_restriction never falls back to None in that state.
        crate::terminal::check_original_coordinator_restriction().map_err(|_| denied())?;
        self.read.check().map_err(|_| denied())?;
        self.read
            .owner
            .check_effect_source()
            .map_err(|_| denied())?;
        self.verified
            .check_current_v1(self.access, self.read, self.read, self.read)
            .map_err(|_| denied())?;
        self.native.check(review)?;
        let c = self.native.context();
        if review.journal_identity
            != self
                .read
                .owner
                .submission_journal_identity()
                .map_err(|_| denied())?
            || review.now_unix_seconds > self.send_until
            || review.descriptor != self.verified.retained().descriptor()
            || c.delivery != *self.verified.delivery_plan()
            || c.owners != self.verified.completed_owners()
            || c.signed_result_request_digest != self.verified.retained().signed_request_digest()
            || c.signed_artifact_digest != self.verified.retained().signed_candidate_digest()
        {
            return Err(denied());
        }
        let mut accounts = std::collections::BTreeSet::new();
        for actual in self.admissions {
            actual.check_current().map_err(|_| denied())?;
            let a = actual.admission();
            let scope = &self
                .verified
                .continuation_record(&a.request.account_id)
                .ok_or_else(denied)?
                .terms
                .scope;
            if !accounts.insert(a.request.account_id.as_str())
                || a.request.context != *c
                || a.request.host_reviewed_at_ms != self.native.reviewed_at_ms()
                || a.request.writer_epoch != scope.original_writer_epoch
                || a.request.network_profile_id != scope.authorization.identity.network_profile_id
                || a.witness_id != scope.witness.witness_id
                || a.policy_digest != scope.witness.policy_digest
            {
                return Err(denied());
            }
        }
        if accounts.len() != 2
            || accounts != c.owners.iter().map(|o| o.account_id.as_str()).collect()
        {
            return Err(denied());
        }
        // The frozen gate has no terminal, and cannot mint a new permission here.
        if review.now_unix_seconds >= self.retention.valid_until_unix_seconds() {
            return Err(denied());
        }
        self.read.check().map_err(|_| denied())
    }
}

/// Effect authority is nominally separate from historical read permission. It
/// exists only under the final exact native dispatch decision; it cannot expose
/// a terminal or authorize proof creation/signing/extraction.
struct ClosedDispatchEffectConsentV1<'a, 'host> {
    read: &'a ClosedFinancialReadConsentV1<'a, 'host>,
    native: &'a crate::authority::durable_submission_v1::NativeDurableSubmissionConsentV1,
}
impl LocalPrivateDurableFinancialConsentV1 for ClosedDispatchEffectConsentV1<'_, '_> {
    fn check_final_effect_restriction_v1(&self) -> bool {
        !crate::terminal::coordinated_restriction_required()
            || (original_material_clocks_current(self.read.inspection).is_ok() && self.read.approval.check().is_ok() && self.native.check_final_effect_restriction().is_ok())
    }
    fn permits_source(&self, scope: &PrivateWorkspaceScopeV1) -> bool {
        same(scope, self.read.inspection.workspace_scope())
            && self.read.check().is_ok()
            && self.read.owner.check_effect_source().is_ok()
            && self.native.check_current().is_ok()
    }
}

/// A report is inert outcome data. Disclosure status never changes its effect.
pub(in crate::host) enum FinancialReportDisclosureV1 {
    NotRequested,
    Displayed,
    Refused(Error),
}
pub(in crate::host) struct OriginalDispatchOutcomeV1 {
    pub(in crate::host) report: wholepact_chain::SubmissionDispatchReport,
    pub(in crate::host) disclosure: FinancialReportDisclosureV1,
}
impl Host {
    /// Completed-only production composition. Both supplied histories are opaque
    /// authenticated original Witness reads, not parsed JSON grants. This method
    /// never signs or extracts; missing completed originals fail closed.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::host) async fn dispatch_completed_private_financial_v1<
        B: wholepact_chain::SubmissionBackend,
        C: wholepact_chain::SubmissionClock,
    >(
        &self,
        root: &std::path::Path,
        key: &str,
        histories: [&wholepact_signer::authority_bridge::financial_continuation_v1::AuthenticatedFinancialContinuationHistoryV1; 2],
        backend: &mut B,
        clock: &C,
    ) -> Result<wholepact_chain::SubmissionDispatchReport> {
        self.dispatch_completed_private_financial_kernel_v1(root, key, histories, backend, clock, false)
            .await.map(|outcome| outcome.report)
    }
    /// Explicit saved-byte dispatch plus a separately reviewed local report.
    /// Successful dispatch remains successful even when later disclosure denies.
    #[cfg(feature = "coordinated-financial-workflow-v1")]
    pub(in crate::host) async fn dispatch_and_display_completed_private_financial_v1<
        B: wholepact_chain::SubmissionBackend, C: wholepact_chain::SubmissionClock,
    >(
        &self, root: &std::path::Path, key: &str,
        histories: [&wholepact_signer::authority_bridge::financial_continuation_v1::AuthenticatedFinancialContinuationHistoryV1; 2],
        backend: &mut B, clock: &C,
    ) -> Result<OriginalDispatchOutcomeV1> {
        if !crate::terminal::coordinated_restriction_required() { return Err(Error::Permission); }
        self.dispatch_completed_private_financial_kernel_v1(root, key, histories, backend, clock, true).await
    }
    async fn dispatch_completed_private_financial_kernel_v1<
        B: wholepact_chain::SubmissionBackend, C: wholepact_chain::SubmissionClock,
    >(
        &self, root: &std::path::Path, key: &str,
        histories: [&wholepact_signer::authority_bridge::financial_continuation_v1::AuthenticatedFinancialContinuationHistoryV1; 2],
        backend: &mut B, clock: &C, display: bool,
    ) -> Result<OriginalDispatchOutcomeV1> {
        financial_step!(InputValidation, NotEstablished);
        let result = async {
        use wholepact_authority::completed_dispatch_v1::{
            AuthorizeCompletedDispatchV1, CompletedDispatchContextV1,
        };
        use wholepact_engine::signature_intake::LocalSignedRetention;
        use wholepact_protocol::authorization::retention::transaction::{
            LocalTransactionCheckpoint,
            submission_handoff::{
                LocalSubmissionDispatch, LocalSubmissionHandoff, SubmissionHandoffConsent,
                SubmissionHandoffScope,
            },
        };
        crate::id(key)?;
        let command_key =
            wholepact_core::proposal::canonical_digest("wholepact:host-financial-command:v1", &key)
                .map_err(|_| Error::Invalid)?;
        financial_step!(OriginalSource, NotEstablished);
        let owner = self
            .original_financial_owner_v1(root)
            .map_err(|error| { financial_record!(host, OriginalSource, NotEstablished, &error); financial_failure("ORIGINAL_SOURCE") })?;
        let inspection = owner.initial_inspection();
        financial_step!(ReadConsent, NotEstablished);
        let approval = self.terminal.approve_historical("Read and mathematically verify only the saved original financial union and completed transaction for this exact dispatch review. Missing or uncertain extraction must remain fenced; this read cannot repair, re-sign or extract.")?;
        let read = ClosedFinancialReadConsentV1 {
            owner: &owner,
            inspection,
            approval: &approval,
        };
        read.check()?;
        let financial = self.financial.as_ref().ok_or(Error::Locked)?;
        let access = self.access()?;
        financial_step!(SourcePreparation, NotEstablished);
        let mut prepared = owner
            .coordinator()
            .prepare_original_financial_v1(access, &read, &read, &read)
            .map_err(|error| { financial_record!(engine, SourcePreparation, NotEstablished, &error); financial_failure("FIXED_SOURCE_VERIFICATION") })?;
        financial_step!(RetentionContexts, NotEstablished);
            let contexts = prepared.financial_retention_contexts_v1(access, &read, &read, &read)
            .map_err(|error| { financial_record!(engine, RetentionContexts, NotEstablished, &error); financial_failure("RETENTION_CONTEXTS") })?;
        financial_step!(SignedRetentionApproval, NotEstablished);
            let retention = self.authority.financial_retention_consent_v1(&contexts)?;
            let prompt_bounds = if crate::terminal::coordinated_restriction_required() {
                financial_prompt_bounds(&read, Some(prepared.original_financial_clock_bounds_ms_v1()?))?
            } else { None };
            let retention = if let Some(bounds) = prompt_bounds { retention.bind_original_prompt_bounds(bounds)? } else { retention };
        let operation = histories[0]
            .continuation_record()
            .terms
            .scope
            .delivery
            .submission_operation_id
            .clone();
        financial_step!(CompletedVerification, NotEstablished);
        let verified = prepared
            .verify_completed_submission_v1(
                access,
                &operation,
                LocalSignedRetention {
                    journal: &financial.signed,
                    consent: &retention,
                },
                LocalTransactionCheckpoint {
                    journal: &financial.transactions,
                    consent: &retention,
                },
                &read,
                &read,
                &read,
            )
            .map_err(|error| { financial_record!(engine, CompletedVerification, NotEstablished, &error); financial_failure("COMPLETED_VERIFICATION") })?;
        financial_step!(Currentness, NotEstablished);
        let journal_identity = owner.submission_journal_identity()?;
        let backend_identity = backend.identity().clone();
        // This exact metadata comes from the sealed completed predecessor, never
        // a caller-constructed scope. Privacy review happens BEFORE final consent.
        if !SubmissionHandoffConsent::permits(
            &retention,
            &SubmissionHandoffScope {
                retained: verified.retained().retention_scope(),
                descriptor: verified.retained().descriptor(),
                backend: &backend_identity,
                destination_journal_identity: &journal_identity,
            },
        ) {
            return Err(Error::Permission);
        }
        financial_step!(RetentionFreeze, NotEstablished);
        let frozen = retention.freeze_for_dispatch()?;
        financial_step!(DispatchReview, NotEstablished);
        let descriptor = verified.retained().descriptor();
        let context = CompletedDispatchContextV1 {
            fixed: serde_json::from_value(serde_json::to_value(
                verified.retained().fixed_identity(),
            )?)?,
            delivery: verified.delivery_plan().clone(),
            owners: verified.completed_owners().to_vec(),
            signed_result_request_digest: verified.retained().signed_request_digest().into(),
            signed_artifact_digest: verified.retained().signed_candidate_digest().into(),
            transaction_checkpoint_id: verified.retained().checkpoint_id(),
            final_transaction_digest: descriptor.bytes_sha256.clone(),
            final_transaction_id: descriptor.transaction_id.clone(),
            transaction_expiry_height: descriptor.expiry_height,
            network: descriptor.network.clone(),
            consensus_branch_id: descriptor.consensus_branch_id,
            backend_disclosure_digest:
                crate::authority::durable_submission_v1::durable_backend_disclosure_digest_v1(
                    descriptor,
                    &journal_identity,
                    &backend_identity,
                    verified.delivery_plan(),
                )?,
            attempt: prepared.next_dispatch_attempt_v1().map_err(|error| { financial_record!(engine, AuditSummary, NotEstablished, &error); error })?,
        };
        verified.validate_completed_dispatch_context_v1(&context).map_err(|error| { financial_record!(engine, DispatchReview, NotEstablished, &error); error })?;
        // Last effect-authorizing human prompt. All effect gates below are closed;
        // an explicitly requested later report Read cannot authorize an effect.
        financial_step!(DispatchReview, NotEstablished);
        let native = self.authority.approve_exact_durable_submission_original_v1(
            verified.retained(),
            context,
            &journal_identity,
            &backend_identity,
            prompt_bounds.as_ref(),
        )?;
        drop(verified);
        let effect = ClosedDispatchEffectConsentV1 {
            read: &read,
            native: &native,
        };
        let mut requests = Vec::with_capacity(2);
        for account in &native.context().owners {
            let history = histories
                .iter()
                .find(|h| h.snapshot().account_id == account.account_id)
                .ok_or(Error::Authentication)?;
            let mut request = AuthorizeCompletedDispatchV1 {
                operation_id: String::new(),
                account_id: account.account_id.clone(),
                network_profile_id: history.snapshot().network_profile_id.clone(),
                writer_epoch: history.snapshot().writer_epoch,
                expected_head: history.snapshot().head.clone(),
                context: native.context().clone(),
                host_reviewed_at_ms: native.reviewed_at_ms(),
                requested_admission_lifetime_ms: 120_000,
            };
            request.operation_id = request
                .canonical_operation_id()
                .map_err(|_| Error::Authentication)?;
            request.validate().map_err(|_| Error::Authentication)?;
            requests.push(request);
        }
        let requests: [AuthorizeCompletedDispatchV1; 2] =
            requests.try_into().map_err(|_| Error::Invalid)?;
        {
            financial_step!(PairIntentRetention, OutcomeUncertain);
            let journal = self.submission.lock().map_err(|_| Error::Locked)?;
            prepared = prepared
                .retain_dispatch_intent_v1(
                    access,
                    &format!("dispatch-{command_key}-pair"),
                    requests,
                    histories,
                    &journal,
                    LocalSignedRetention {
                        journal: &financial.signed,
                        consent: &frozen,
                    },
                    LocalTransactionCheckpoint {
                        journal: &financial.transactions,
                        consent: &frozen,
                    },
                    &effect,
                    &read,
                    &read,
                )
                .map_err(|error| { financial_record!(engine, PairIntentRetention, OutcomeUncertain, &error); financial_failure("PAIR_INTENT") })?;
        }
        let mut admissions = Vec::with_capacity(2);
        for index in 0..2 {
            financial_step!(RetainedPairRead, OutcomeUncertain);
            let intent = prepared.retained_dispatch_intent_v1(
                native.context().attempt,
                access,
                &effect,
                &read,
                &read,
            ).map_err(|error| { financial_record!(engine, RetainedPairRead, OutcomeUncertain, &error); error })?;
            if index == 0 { financial_step!(AdmissionFirst, OutcomeUncertain); } else { financial_step!(AdmissionSecond, OutcomeUncertain); }
            let admission = owner.admit_completed_dispatch_v1(
                &intent, index, access, &effect, &read, &read, &native,
            )?;
            drop(intent);
            financial_step!(AdmissionReceiptRetention, OutcomeUncertain);
            prepared = prepared
                .retain_dispatch_admission_v1(
                    access,
                    &format!("dispatch-{command_key}-admission-{index}"),
                    &admission,
                    &effect,
                    &read,
                    &read,
                )
                .map_err(|error| { financial_record!(engine, AdmissionReceiptRetention, OutcomeUncertain, &error); financial_failure("ADMISSION_RETENTION") })?;
            admissions.push(admission);
        }
        let admissions: [_; 2] = admissions.try_into().map_err(|_| Error::Invalid)?;
        financial_step!(DispatchReverification, OutcomeUncertain);
        let verified = prepared
            .verify_completed_submission_v1(
                access,
                &operation,
                LocalSignedRetention {
                    journal: &financial.signed,
                    consent: &frozen,
                },
                LocalTransactionCheckpoint {
                    journal: &financial.transactions,
                    consent: &frozen,
                },
                &effect,
                &read,
                &read,
            )
            .map_err(|error| { financial_record!(engine, DispatchReverification, OutcomeUncertain, &error); financial_failure("COMPLETED_VERIFICATION") })?;
        let policy = wholepact_chain::SubmissionPolicy {
            minimum_expiry_margin_blocks: native.context().delivery.minimum_expiry_margin_blocks,
            ..Default::default()
        };
        // Fresh provider context is not a human prompt or authority renewal.
        financial_step!(BackendContext, OutcomeUncertain);
        let chain_context = backend.fresh_context().await.map_err(|error| { financial_record!(chain, BackendContext, OutcomeUncertain, &error); error })?;
        let mut journal = self.submission.lock().map_err(|_| Error::Locked)?;
        let mut authority = ProductionDurableSubmissionAuthorityV1 {
            verified: &verified,
            access,
            read: &read,
            admissions: &admissions,
            native: &native,
            retention: &frozen,
            used: false,
        };
        financial_step!(SavedTransactionHandoff, OutcomeUncertain);
        prepared
            .retain_original_submission_v1(
                access,
                &operation,
                LocalSignedRetention {
                    journal: &financial.signed,
                    consent: &frozen,
                },
                LocalSubmissionHandoff {
                    transactions: LocalTransactionCheckpoint {
                        journal: &financial.transactions,
                        consent: &frozen,
                    },
                    submission_journal: &mut journal,
                    authority: &mut authority,
                    backend: &backend_identity,
                    chain_context: &chain_context,
                    clock,
                    policy,
                    consent: &frozen,
                },
                &effect,
                &read,
                &read,
            )
            .map_err(|error| { financial_record!(engine, SavedTransactionHandoff, OutcomeUncertain, &error); financial_failure("SAVED_TRANSACTION_HANDOFF") })?;
        let mut authority = ProductionDurableSubmissionAuthorityV1 {
            verified: &verified,
            access,
            read: &read,
            admissions: &admissions,
            native: &native,
            retention: &frozen,
            used: false,
        };
        financial_step!(DispatchOutcome, OutcomeUncertain);
        let report = prepared
            .dispatch_original_submission_v1(
                access,
                &operation,
                LocalSignedRetention {
                    journal: &financial.signed,
                    consent: &frozen,
                },
                LocalSubmissionDispatch {
                    transactions: LocalTransactionCheckpoint {
                        journal: &financial.transactions,
                        consent: &frozen,
                    },
                    submission_journal: &mut journal,
                    authority: &mut authority,
                    backend,
                    clock,
                    policy,
                    consent: &frozen,
                },
                &effect,
                &read,
                &read,
            )
            .await
            .map_err(|error| { financial_record!(engine, DispatchOutcome, OutcomeUncertain, &error); financial_failure("DISPATCH_OUTCOME") })?;
        if !display {
            return Ok(OriginalDispatchOutcomeV1 { report, disclosure: FinancialReportDisclosureV1::NotRequested });
        }
        // Never hold submission/source-effect authority or its journal mutex
        // across the separate report-only human Read. Original verified source
        // custody is retained, but the completed dispatch decision is over.
        drop(authority);
        drop(journal);
        drop(effect);
        drop(native);
        drop(frozen);
        drop(read);
        drop(approval);
        #[cfg(feature = "coordinated-financial-workflow-v1")]
        let disclosure = (|| -> Result<()> {
            if !same(&report.descriptor, verified.retained().descriptor()) {
                return Err(Error::Authentication);
            }
            let source = original_result_material_bounds(
                inspection, prepared.original_financial_clock_bounds_ms_v1()?,
            )?;
            let prompt = crate::terminal::OriginalPromptBoundsV1::new(
                crate::terminal::original_coordinated_session_ceiling()?, source,
            )?;
            original_materials_current(inspection)?;
            let report_approval = self.terminal.approve_historical_original(
                "Read and locally display ONLY the actual durable report for the exact saved-byte dispatch that already returned. Refusing or losing this report Read cannot undo the attempted send or its recorded outcome. This does not assert payment inclusion or settlement and cannot authorize a retry, replacement, repair, new admission or another send.",
                Some(&prompt),
            )?;
            let report_read = ClosedFinancialReadConsentV1 { owner: &owner, inspection, approval: &report_approval };
            let bounds = prompt.narrow_deadline(report_approval.deadline());
            report_read.check()?;
            let output = self.terminal.historical_output()?;
            report_approval.effect(&mut || output.json_checked_original(
                &report, || report_read.check(), &report_approval, &bounds,
            ))?;
            report_read.check()
        })();
        #[cfg(not(feature = "coordinated-financial-workflow-v1"))]
        let disclosure: Result<()> = Err(Error::Permission);
        // Preserve actual dispatch outcome independently of later disclosure.
        // Even a partial output failure cannot become a no-effect or retry claim.
        Ok(OriginalDispatchOutcomeV1 { report, disclosure: match disclosure {
            Ok(()) => FinancialReportDisclosureV1::Displayed,
            Err(error) => FinancialReportDisclosureV1::Refused(error),
        } })

        }.await;
        #[cfg(all(
            test,
            feature = "synthetic-born-joined-qualification",
            feature = "durable-proposal"
        ))]
        if let Err(error) = &result {
            crate::host::financial_diagnostics_v1::host_current(error);
        }
        result
    }
}

/// An independently reviewed local financial step. It is neither a historical
/// read grant nor a final network-dispatch decision. Its private constructor is
/// the exact foreground Host command below; no remote effect uses this type.
struct ClosedFinancialPreparationConsentV1<'a, 'host> {
    read: &'a ClosedFinancialReadConsentV1<'a, 'host>,
    effect: &'a HistoricalApproval,
    original_bounds_ms: Option<(u64, u64)>,
}
impl LocalPrivateDurableFinancialConsentV1 for ClosedFinancialPreparationConsentV1<'_, '_> {
    fn check_final_effect_restriction_v1(&self) -> bool {
        !crate::terminal::coordinated_restriction_required()
            || (original_source_clocks_current(self.original_bounds_ms) && original_material_clocks_current(self.read.inspection).is_ok() && self.read.approval.check().is_ok() && self.effect.check().is_ok())
    }
    fn permits_source(&self, scope: &PrivateWorkspaceScopeV1) -> bool {
        same(scope, self.read.inspection.workspace_scope())
            && self.read.check().is_ok()
            && self.read.owner.check_effect_source().is_ok()
            && self.effect.check().is_ok()
    }
}
struct OriginalCompletionRetentionV1<'a, 'read, 'host> {
    native: &'a crate::authority::retention::NativeFinancialRetentionConsentV1,
    effect: &'a ClosedFinancialPreparationConsentV1<'read, 'host>,
}
impl wholepact_protocol::authorization::retention::SignedRetentionConsent for OriginalCompletionRetentionV1<'_, '_, '_> {
    fn permits(&self, scope: &wholepact_protocol::authorization::retention::SignedRetentionScope) -> bool {
        wholepact_protocol::authorization::retention::SignedRetentionConsent::permits(self.native, scope)
            && self.effect.check_final_effect_restriction_v1()
    }
}
impl wholepact_protocol::authorization::retention::transaction::TransactionRetentionConsent for OriginalCompletionRetentionV1<'_, '_, '_> {
    fn permits(&self, scope: &wholepact_protocol::authorization::retention::transaction::TransactionRetentionScope) -> bool {
        wholepact_protocol::authorization::retention::transaction::TransactionRetentionConsent::permits(self.native, scope)
            && self.effect.check_final_effect_restriction_v1()
    }
    fn check_final_effect_restriction(&self) -> bool {
        wholepact_protocol::authorization::retention::transaction::TransactionRetentionConsent::check_final_effect_restriction(self.native)
            && self.effect.check_final_effect_restriction_v1()
    }
}
struct OriginalIntakeRetentionV1<'a, 'setup, 'host> {
    native: &'a crate::authority::retention::FrozenNativeSignedIntakeConsentV1,
    setup: &'a ClosedFinancialIntakeSetupV1<'setup, 'host>,
}
impl wholepact_protocol::authorization::retention::SignedRetentionConsent for OriginalIntakeRetentionV1<'_, '_, '_> {
    fn permits(&self, scope: &wholepact_protocol::authorization::retention::SignedRetentionScope) -> bool {
        wholepact_protocol::authorization::retention::SignedRetentionConsent::permits(self.native, scope)
            && self.setup.check_final_effect_restriction_v1()
    }
}
impl Host {
    pub(in crate::host) fn bind_original_financial_continuations_v1(
        &self,
        root: &std::path::Path,
        key: &str,
        histories: [&wholepact_signer::authority_bridge::financial_continuation_v1::AuthenticatedFinancialContinuationHistoryV1; 2],
    ) -> Result<u64> {
        financial_step!(InputValidation, NotEstablished);
        let result = (|| -> Result<_> {
            crate::id(key)?;
            financial_step!(OriginalSource, NotEstablished);
            let owner = self.original_financial_owner_v1(root).map_err(|error| {
                financial_record!(host, OriginalSource, NotEstablished, &error);
                financial_failure("ORIGINAL_SOURCE")
            })?;
            let inspection = owner.initial_inspection();
            financial_step!(ReadConsent, NotEstablished);
            let approval = self.terminal.approve_historical("Read this exact original saved fixed proof and both original financial continuation records. No signing, repair or dispatch is permitted by this read.")?;
            let read = ClosedFinancialReadConsentV1 {
                owner: &owner,
                inspection,
                approval: &approval,
            };
            financial_step!(EffectConsent, NotEstablished);
            let prompt_source = if crate::terminal::coordinated_restriction_required() {
                Some((
                    histories.iter().map(|h| { let t = &h.continuation_record().terms; t.valid_from_ms.max(t.scope.authorization.valid_from_ms) }).max().ok_or(Error::Authentication)?,
                    histories.iter().map(|h| { let t = &h.continuation_record().terms; t.valid_until_ms.min(t.scope.authorization.valid_until_ms) }).min().ok_or(Error::Authentication)?,
                ))
            } else { None };
            let prompt_bounds = financial_prompt_bounds(&read, prompt_source)?;
            let approval = self.terminal.approve_historical_original(&format!("Record the two authenticated owner financial continuations against this exact original fixed proposal {} at revision {}, command {}. This local association does not sign, reserve, extract or dispatch, and does not extend any owner deadline.", inspection.fixed_identity().proposal_id, inspection.revision(), key), prompt_bounds.as_ref())?;
            let effect = ClosedFinancialPreparationConsentV1 {
                read: &read,
                effect: &approval,
                original_bounds_ms: if crate::terminal::coordinated_restriction_required() {
                    Some((
                        histories.iter().map(|h| { let t = &h.continuation_record().terms; t.valid_from_ms.max(t.scope.authorization.valid_from_ms) }).max().ok_or(Error::Authentication)?,
                        histories.iter().map(|h| { let t = &h.continuation_record().terms; t.valid_until_ms.min(t.scope.authorization.valid_until_ms) }).min().ok_or(Error::Authentication)?,
                    ))
                } else { None },
            };
            financial_step!(ContinuationBinding, OutcomeUncertain);
            owner
                .coordinator()
                .bind_financial_continuations_v1(
                    self.access()?,
                    key,
                    inspection.revision(),
                    histories,
                    &effect,
                    &read,
                    &read,
                )
                .map_err(|error| {
                    financial_record!(engine, ContinuationBinding, OutcomeUncertain, &error);
                    financial_failure("CONTINUATION_BIND")
                })
        })();
        #[cfg(all(
            test,
            feature = "synthetic-born-joined-qualification",
            feature = "durable-proposal"
        ))]
        if let Err(error) = &result {
            crate::host::financial_diagnostics_v1::host_current(error);
        }
        result
    }

    pub(in crate::host) fn intake_original_financial_result_v1(
        &self,
        root: &std::path::Path,
        key: &str,
        receiver: wholepact_signer::authority_bridge::financial_continuation_v1::PreparedFinancialResultReceiverV1,
        history: &wholepact_signer::authority_bridge::financial_continuation_v1::AuthenticatedFinancialContinuationHistoryV1,
    ) -> Result<u64> {
        self.intake_original_financial_result_kernel_v1(root, key, receiver, history)
    }

    #[cfg(feature = "coordinated-financial-workflow-v1")]
    pub(in crate::host) fn intake_original_coordinated_financial_result_v1(
        &self,
        root: &std::path::Path,
        key: &str,
        receiver: wholepact_signer::authority_bridge::financial_continuation_v1::PreparedCoordinatedFinancialResultReceiverV1,
        history: &wholepact_signer::authority_bridge::financial_continuation_v1::AuthenticatedFinancialContinuationHistoryV1,
    ) -> Result<u64> {
        if !crate::terminal::coordinated_restriction_required() { return Err(Error::Permission); }
        self.intake_original_financial_result_kernel_v1(root, key, receiver, history)
    }

    fn intake_original_financial_result_kernel_v1<R: OriginalFinancialResultReceiverV1>(
        &self,
        root: &std::path::Path,
        key: &str,
        receiver: R,
        history: &wholepact_signer::authority_bridge::financial_continuation_v1::AuthenticatedFinancialContinuationHistoryV1,
    ) -> Result<u64> {
        financial_step!(InputValidation, NotEstablished);
        let result = (|| -> Result<_> {
            use wholepact_engine::signature_intake::LocalSignedRetention;
            use wholepact_protocol::authorization::retention::SignedRetentionConsent;
            crate::id(key)?;
            financial_step!(OriginalSource, NotEstablished);
            let owner = self.original_financial_owner_v1(root).map_err(|error| {
                financial_record!(host, OriginalSource, NotEstablished, &error);
                financial_failure("ORIGINAL_SOURCE")
            })?;
            let inspection = owner.initial_inspection();
            financial_step!(ReadConsent, NotEstablished);
            let read_approval = self.terminal.approve_historical("Read the exact original financial fixed proof and existing intake lineage for protected signer-result verification. No missing result may be regenerated.")?;
            let read = ClosedFinancialReadConsentV1 {
                owner: &owner,
                inspection,
                approval: &read_approval,
            };
            financial_step!(EffectConsent, NotEstablished);
            let prompt_source = if crate::terminal::coordinated_restriction_required() {
                let t = &history.continuation_record().terms;
                Some((t.valid_from_ms.max(t.scope.authorization.valid_from_ms), t.valid_until_ms.min(t.scope.authorization.valid_until_ms)))
            } else { None };
            let prompt_bounds = financial_prompt_bounds(&read, prompt_source)?;
            let effect_approval = self.terminal.approve_historical_original(&format!("Verify and retain one actual authenticated original signer result for fixed proposal {}, revision {}, command {}. The installed protected receive route and original source provenance must match. This cannot invoke signing or extract a transaction.", inspection.fixed_identity().proposal_id, inspection.revision(), key), prompt_bounds.as_ref())?;
            let effect = ClosedFinancialPreparationConsentV1 {
                read: &read,
                effect: &effect_approval,
                original_bounds_ms: None,
            };
            let scope = inspection.checkpoint_scope();
            financial_step!(SignedRetentionApproval, NotEstablished);
            let retention = self.authority.retention_consent(
                &scope.principal_id,
                &scope.candidate_id,
                &scope.manifest_digest,
                inspection.proof_job_id(),
                scope.account_ids.iter().cloned().collect(),
            )?;
            let financial = self.financial.as_ref().ok_or(Error::Locked)?;
            financial_step!(SourcePreparation, NotEstablished);
            let prepared = owner
                .coordinator()
                .prepare_original_financial_v1(self.access()?, &effect, &read, &read)
                .map_err(|error| {
                    financial_record!(engine, SourcePreparation, NotEstablished, &error);
                    financial_failure("FIXED_SOURCE_VERIFICATION")
                })?;
            let effect = ClosedFinancialPreparationConsentV1 {
                original_bounds_ms: if crate::terminal::coordinated_restriction_required() {
                    Some(prepared.original_financial_clock_bounds_ms_v1()?)
                } else { None },
                ..effect
            };
            let prompt_bounds = financial_prompt_bounds(&read, effect.original_bounds_ms)?;
            let retention = if let Some(bounds) = prompt_bounds { retention.bind_original_prompt_bounds(bounds)? } else { retention };
            financial_step!(ResultPreview, NotEstablished);
            let expected_scope = prepared
                .financial_result_retention_scope_v1(
                    receiver.preview(),
                    self.access()?,
                    &effect,
                    &read,
                    &read,
                )
                .map_err(|error| {
                    financial_record!(engine, ResultPreview, NotEstablished, &error);
                    financial_failure("RESULT_PREFLIGHT")
                })?;
            financial_step!(SignedRetentionApproval, NotEstablished);
            if !SignedRetentionConsent::permits(&retention, &expected_scope) {
                return Err(Error::Permission);
            }
            let original_until = inspection
                .materials()
                .iter()
                .map(|m| m.scope().valid_until_unix_seconds)
                .chain(std::iter::once(
                    prepared
                        .original_financial_valid_until_ms_v1()
                        .map_err(|error| {
                            financial_record!(engine, Currentness, NotEstablished, &error);
                            error
                        })?
                        / 1000,
                ))
                .min()
                .ok_or(Error::Authentication)?;
            financial_step!(IntakeSetupApproval, NotEstablished);
            let setup_approval = self
                .terminal
                .approve_financial_intake_setup_original_v1(&expected_scope, original_until, prompt_bounds.as_ref())?;
            let setup = ClosedFinancialIntakeSetupV1 {
                owner: &owner,
                inspection,
                approval: &setup_approval,
                exact_scope: &expected_scope,
                original_bounds_ms: effect.original_bounds_ms,
            };
            financial_step!(RetentionFreeze, NotEstablished);
            let retention = retention.freeze_for_signed_intake()?;
            let restricted_retention = OriginalIntakeRetentionV1 { native: &retention, setup: &setup };
            drop(effect);
            drop(read);
            drop(effect_approval);
            drop(read_approval);
            #[cfg(feature = "coordinated-financial-workflow-v1")]
            let receiver = if crate::terminal::coordinated_restriction_required() {
                let source = original_result_material_bounds(
                    inspection, setup.original_bounds_ms.ok_or(Error::Permission)?,
                )?;
                receiver.bind_original_intake_restriction_v1(Box::new(OriginalResultIoRestrictionV1 {
                    bounds: setup_approval.original_restriction_bounds(source)?,
                })).map_err(|_| Error::Permission)?
            } else { receiver };
            // Only now may the independently approved Signer ReturnExact begin.
            // All later gates are closed; no Host human wait consumes its lease.
            financial_step!(ResultReceive, NotEstablished);
            let delivery = receiver.receive_host().map_err(|error| {
                financial_record!(bridge, ResultReceive, NotEstablished, &error);
                financial_failure("RESULT_RECEIVE")
            })?;
            financial_step!(AuthenticatedIntake, OutcomeUncertain);
            let revision = prepared
                .intake_original_signature_v1(
                    self.access()?,
                    key,
                    &delivery,
                    history,
                    LocalSignedRetention {
                        journal: &financial.signed,
                        consent: &restricted_retention,
                    },
                    &setup,
                    &setup,
                    &setup,
                )
                .map_err(|error| {
                    #[cfg(all(test,feature="synthetic-born-joined-qualification",feature="durable-proposal"))]
                    if let Some(detail)=delivery.last_failure_v1() {crate::host::financial_diagnostics_v1::signer_result(detail,crate::host::financial_diagnostics_v1::FinancialCommitStateV1::OutcomeUncertain);}
                    financial_record!(engine, AuthenticatedIntake, OutcomeUncertain, &error);
                    financial_failure("AUTHENTICATED_INTAKE")
                })?;
            financial_step!(ResultFinishAcknowledgement, IntakeCommitted);
            {
                #[cfg(all(test,feature="synthetic-born-joined-qualification",feature="durable-proposal"))]
                let result=delivery.finish_observed_v1().map_err(|observed| {
                    if let Some(detail)=observed.diagnostic {crate::host::financial_diagnostics_v1::signer_result(detail,crate::host::financial_diagnostics_v1::FinancialCommitStateV1::IntakeCommitted);}
                    observed.error
                });
                #[cfg(not(all(test,feature="synthetic-born-joined-qualification",feature="durable-proposal")))]
                let result=delivery.finish();
                result
            }.map_err(|error| {
                financial_record!(bridge, ResultFinishAcknowledgement, IntakeCommitted, &error);
                financial_failure("RESULT_FINISH_ACKNOWLEDGEMENT")
            })?;
            Ok(revision)
        })();
        #[cfg(all(
            test,
            feature = "synthetic-born-joined-qualification",
            feature = "durable-proposal"
        ))]
        if let Err(error) = &result {
            crate::host::financial_diagnostics_v1::host_current(error);
        }
        result
    }

    pub(in crate::host) fn complete_original_financial_transaction_v1(
        &self,
        root: &std::path::Path,
        key: &str,
    ) -> Result<
        wholepact_protocol::authorization::retention::transaction::TransactionCheckpointSummary,
    > {
        financial_step!(InputValidation, NotEstablished);
        let result = (|| -> Result<_> {
            use wholepact_engine::signature_intake::LocalSignedRetention;
            use wholepact_protocol::authorization::retention::transaction::LocalTransactionCheckpoint;
            crate::id(key)?;
            financial_step!(OriginalSource, NotEstablished);
            let owner = self.original_financial_owner_v1(root).map_err(|error| {
                financial_record!(host, OriginalSource, NotEstablished, &error);
                financial_failure("ORIGINAL_SOURCE")
            })?;
            let inspection = owner.initial_inspection();
            financial_step!(ReadConsent, NotEstablished);
            let approval = self.terminal.approve_historical("Read and verify the exact two retained financial signer results and original proof. Incomplete or uncertain result lineage remains fenced.")?;
            let read = ClosedFinancialReadConsentV1 {
                owner: &owner,
                inspection,
                approval: &approval,
            };
            financial_step!(EffectConsent, NotEstablished);
            let prompt_bounds = financial_prompt_bounds(&read, None)?;
            let approval = self.terminal.approve_historical_original(&format!("Combine only the two exact retained original signature subsets for proposal {}, revision {}, command {}, then create its single immutable completed transaction checkpoint. An existing extraction intent without a result is RecoveryRequired, never permission to re-extract. This performs no network submission.", inspection.fixed_identity().proposal_id, inspection.revision(), key), prompt_bounds.as_ref())?;
            let effect = ClosedFinancialPreparationConsentV1 {
                read: &read,
                effect: &approval,
                original_bounds_ms: None,
            };
            let financial = self.financial.as_ref().ok_or(Error::Locked)?;
            financial_step!(SourcePreparation, NotEstablished);
            let prepared = owner
                .coordinator()
                .prepare_original_financial_v1(self.access()?, &effect, &read, &read)
                .map_err(|error| {
                    financial_record!(engine, SourcePreparation, NotEstablished, &error);
                    financial_failure("FIXED_SOURCE_VERIFICATION")
                })?;
            let effect = ClosedFinancialPreparationConsentV1 {
                original_bounds_ms: if crate::terminal::coordinated_restriction_required() {
                    Some(prepared.original_financial_clock_bounds_ms_v1()?)
                } else { None },
                ..effect
            };
            financial_step!(RetentionContexts, NotEstablished);
            let contexts = prepared
                .financial_retention_contexts_v1(self.access()?, &effect, &read, &read)
                .map_err(|error| {
                    financial_record!(engine, RetentionContexts, NotEstablished, &error);
                    financial_failure("RETENTION_CONTEXTS")
                })?;
            financial_step!(SignedRetentionApproval, NotEstablished);
            let retention = self.authority.financial_retention_consent_v1(&contexts)?;
            let prompt_bounds = if crate::terminal::coordinated_restriction_required() {
                financial_prompt_bounds(&read, Some(prepared.original_financial_clock_bounds_ms_v1()?))?
            } else { None };
            let retention = if let Some(bounds) = prompt_bounds { retention.bind_original_prompt_bounds(bounds)? } else { retention };
            let restricted_retention = OriginalCompletionRetentionV1 { native: &retention, effect: &effect };
            financial_step!(UnionRetention, OutcomeUncertain);
            prepared
                .retain_original_union_v1(
                    self.access()?,
                    key,
                    LocalSignedRetention {
                        journal: &financial.signed,
                        consent: &restricted_retention,
                    },
                    &effect,
                    &read,
                    &read,
                )
                .map_err(|error| {
                    financial_record!(engine, UnionRetention, OutcomeUncertain, &error);
                    financial_failure("UNION_RETENTION")
                })?;
            // Reload only after our own successful append. The coordinator audits the
            // complete bounded lineage; no stale prepared pin is silently refreshed.
            financial_step!(SourcePreparation, NotEstablished);
            let prepared = owner
                .coordinator()
                .prepare_original_financial_v1(self.access()?, &effect, &read, &read)
                .map_err(|error| {
                    financial_record!(engine, SourcePreparation, NotEstablished, &error);
                    financial_failure("FIXED_SOURCE_VERIFICATION")
                })?;
            financial_step!(TransactionCheckpoint, OutcomeUncertain);
            prepared
                .checkpoint_original_transaction_v1(
                    self.access()?,
                    LocalSignedRetention {
                        journal: &financial.signed,
                        consent: &restricted_retention,
                    },
                    LocalTransactionCheckpoint {
                        journal: &financial.transactions,
                        consent: &restricted_retention,
                    },
                    &effect,
                    &read,
                    &read,
                )
                .map_err(|error| {
                    financial_record!(engine, TransactionCheckpoint, OutcomeUncertain, &error);
                    financial_failure("EXTRACTION_CHECKPOINT")
                })
        })();
        #[cfg(all(
            test,
            feature = "synthetic-born-joined-qualification",
            feature = "durable-proposal"
        ))]
        if let Err(error) = &result {
            crate::host::financial_diagnostics_v1::host_current(error);
        }
        result
    }
}

fn financial_failure(stage: &'static str) -> Error {
    Error::Receipt(format!(
        "FINANCIAL_{stage}: preserve original journals and reconcile exact retained operations; do not regenerate or infer non-delivery"
    ))
}

impl Host {
    pub(in crate::host) fn read_original_financial_history_v1(
        &self, root: &std::path::Path, account: &str, continuation_operation: &str,
    ) -> Result<wholepact_authority::durable_financial_continuation_v1::AuthenticatedFinancialContinuationHistoryV1>{
        financial_step!(InputValidation, NotEstablished);
        let result = (|| -> Result<_> {
            financial_step!(OriginalSource, NotEstablished);
            let owner = self.original_financial_owner_v1(root)?;
            financial_step!(ReadConsent, NotEstablished);
            let approval = self.terminal.approve_historical("Read the complete authenticated original financial Witness history through the planned dispatcher, including exact partial/uncertain dispatch outcomes. This read cannot append a request or recreate a live admission or old Host decision.")?;
            financial_step!(FinancialHistory, NotEstablished);
            owner.financial_history_v1(account, continuation_operation, &approval)
        })();
        #[cfg(all(
            test,
            feature = "synthetic-born-joined-qualification",
            feature = "durable-proposal"
        ))]
        if let Err(error) = &result {
            crate::host::financial_diagnostics_v1::host_current(error);
        }
        result
    }
}

/// Closed setup for exactly one pre-reviewed signature intake. It is not usable
/// by the union, extraction or dispatch compositions, and exposes no terminal.
struct ClosedFinancialIntakeSetupV1<'a, 'host> {
    owner: &'a OriginalFinancialOwnerV1<'host>,
    inspection: &'a PrivateDurableFinancialInspectionV1,
    approval: &'a crate::terminal::historical::FinancialIntakeSetupApprovalV1,
    exact_scope: &'a wholepact_protocol::authorization::retention::SignedRetentionScope,
    original_bounds_ms: Option<(u64, u64)>,
}
impl ClosedFinancialIntakeSetupV1<'_, '_> {
    fn check(&self) -> Result<()> {
        self.approval.require_scope(self.exact_scope)?;
        self.owner.check_effect_source()?;
        original_materials_current(self.inspection)?;
        if !same(
            self.owner.workspace_scope(),
            self.inspection.workspace_scope(),
        ) {
            return Err(Error::Authentication);
        }
        self.approval.check()
    }
}
impl LocalPrivateDurableFinancialConsentV1 for ClosedFinancialIntakeSetupV1<'_, '_> {
    fn check_final_effect_restriction_v1(&self) -> bool {
        !crate::terminal::coordinated_restriction_required()
            || (original_source_clocks_current(self.original_bounds_ms) && original_material_clocks_current(self.inspection).is_ok() && self.approval.check().is_ok())
    }
    fn permits_source(&self, scope: &PrivateWorkspaceScopeV1) -> bool {
        same(scope, self.inspection.workspace_scope()) && self.check().is_ok()
    }
}
impl LocalProofConsent for ClosedFinancialIntakeSetupV1<'_, '_> {
    fn permits(&self, scope: &CheckpointScope, action: LocalAction) -> bool {
        scope == self.inspection.checkpoint_scope()
            && matches!(
                action,
                LocalAction::InspectStatus | LocalAction::ReadPrivateArtifact
            )
            && self.check().is_ok()
    }
}
impl LocalDurableMaterialConsentV1 for ClosedFinancialIntakeSetupV1<'_, '_> {
    fn permits(
        &self,
        scope: &DurableConstructionScopeV1,
        digest: &str,
        action: DurableMaterialActionV1,
    ) -> bool {
        matches!(action, DurableMaterialActionV1::ReadForExactConstruction)
            && self
                .inspection
                .materials()
                .iter()
                .any(|m| m.scope() == scope && m.material_digest() == digest)
            && self.check().is_ok()
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub(in crate::host) struct CompletedPrivateFinancialSummaryV1 {
    pub checkpoint_id: String,
    pub transaction_digest: String,
    pub transaction_id: String,
    pub fixed_identity: serde_json::Value,
    pub frozen_export_history_digest: String,
    pub next_delegation_attempt: u32,
    pub latest_requests:
        Option<[wholepact_authority::completed_dispatch_v1::AuthorizeCompletedDispatchV1; 2]>,
    pub original_valid_until_ms: u64,
}
impl Host {
    /// Inert audit output from the same completed-only production verification.
    /// The operation claim is checked against both actual bound continuations.
    pub(in crate::host) fn verify_completed_private_financial_summary_v1(
        &self,
        root: &std::path::Path,
        operation: &str,
    ) -> Result<CompletedPrivateFinancialSummaryV1> {
        self.completed_private_financial_summary_kernel_v1(root, operation, false)
    }
    /// Concrete coordinated disclosure under the same genuine completed-only
    /// Read and original source owner; never accepts a detached summary DTO.
    #[cfg(feature = "coordinated-financial-workflow-v1")]
    pub(in crate::host) fn display_completed_private_financial_summary_v1(
        &self, root: &std::path::Path, operation: &str,
    ) -> Result<()> {
        if !crate::terminal::coordinated_restriction_required() { return Err(Error::Permission); }
        self.completed_private_financial_summary_kernel_v1(root, operation, true).map(|_| ())
    }
    fn completed_private_financial_summary_kernel_v1(
        &self, root: &std::path::Path, operation: &str, display: bool,
    ) -> Result<CompletedPrivateFinancialSummaryV1> {
        financial_step!(InputValidation, NotEstablished);
        let result = (|| -> Result<_> {
            use wholepact_engine::signature_intake::LocalSignedRetention;
            use wholepact_protocol::authorization::retention::transaction::LocalTransactionCheckpoint;
            financial_step!(OriginalSource, NotEstablished);
            let owner = self.original_financial_owner_v1(root)?;
            let inspection = owner.initial_inspection();
            financial_step!(ReadConsent, NotEstablished);
            let approval = self.terminal.approve_historical(if display {
                "Read, verify and locally display the exact completed original financial transaction and retained dispatch lineage as an inert audit summary. This cannot repair, extract, renew an admission or send a request."
            } else {
                "Read and verify the exact completed original financial transaction and retained dispatch lineage for an inert audit summary. This cannot repair, extract, renew an admission or send a request."
            })?;
            let read = ClosedFinancialReadConsentV1 {
                owner: &owner,
                inspection,
                approval: &approval,
            };
            let financial = self.financial.as_ref().ok_or(Error::Locked)?;
            financial_step!(SourcePreparation, NotEstablished);
            let prepared = owner
                .coordinator()
                .prepare_original_financial_v1(self.access()?, &read, &read, &read)
                .map_err(|error| {
                    financial_record!(engine, SourcePreparation, NotEstablished, &error);
                    error
                })?;
            financial_step!(RetentionContexts, NotEstablished);
            let contexts = prepared
                .financial_retention_contexts_v1(self.access()?, &read, &read, &read)
                .map_err(|error| {
                    financial_record!(engine, RetentionContexts, NotEstablished, &error);
                    financial_failure("RETENTION_CONTEXTS")
                })?;
            financial_step!(SignedRetentionApproval, NotEstablished);
            let retention = self.authority.financial_retention_consent_v1(&contexts)?;
            let prompt_bounds = if crate::terminal::coordinated_restriction_required() {
                financial_prompt_bounds(&read, Some(prepared.original_financial_clock_bounds_ms_v1()?))?
            } else { None };
            let retention = if let Some(bounds) = prompt_bounds { retention.bind_original_prompt_bounds(bounds)? } else { retention };
            financial_step!(CompletedVerification, NotEstablished);
            let verified = prepared
                .verify_completed_submission_v1(
                    self.access()?,
                    operation,
                    LocalSignedRetention {
                        journal: &financial.signed,
                        consent: &retention,
                    },
                    LocalTransactionCheckpoint {
                        journal: &financial.transactions,
                        consent: &retention,
                    },
                    &read,
                    &read,
                    &read,
                )
                .map_err(|error| {
                    financial_record!(engine, CompletedVerification, NotEstablished, &error);
                    error
                })?;
            financial_step!(AuditSummary, NotEstablished);
            let next = prepared.next_dispatch_attempt_v1().map_err(|error| {
                financial_record!(engine, AuditSummary, NotEstablished, &error);
                error
            })?;
            let latest_requests = if next > 1 {
                financial_step!(RetainedPairRead, NotEstablished);
                Some(
                    prepared
                        .retained_dispatch_intent_v1(next - 1, self.access()?, &read, &read, &read)
                        .map_err(|error| {
                            financial_record!(engine, RetainedPairRead, OutcomeUncertain, &error);
                            error
                        })?
                        .requests()
                        .clone(),
                )
            } else {
                None
            };
            read.check()?;
            let summary = CompletedPrivateFinancialSummaryV1 {
                checkpoint_id: verified.retained().checkpoint_id(),
                transaction_digest: verified.retained().descriptor().bytes_sha256.clone(),
                transaction_id: verified.retained().descriptor().transaction_id.clone(),
                fixed_identity: serde_json::to_value(verified.retained().fixed_identity())?,
                frozen_export_history_digest: inspection.frozen_export_history_digest.clone(),
                next_delegation_attempt: next,
                latest_requests,
                original_valid_until_ms: prepared.original_financial_valid_until_ms_v1().map_err(
                    |error| {
                        financial_record!(engine, Currentness, NotEstablished, &error);
                        error
                    },
                )?,
            };
            if display {
                let bounds = financial_prompt_bounds(
                    &read, Some(prepared.original_financial_clock_bounds_ms_v1()?),
                )?.ok_or(Error::Permission)?;
                let output = self.terminal.historical_output()?;
                read.check()?;
                approval.effect(&mut || output.json_checked_original(
                    &summary, || read.check(), &approval, &bounds,
                ))?;
                read.check()?;
            }
            Ok(summary)
        })();
        #[cfg(all(
            test,
            feature = "synthetic-born-joined-qualification",
            feature = "durable-proposal"
        ))]
        if let Err(error) = &result {
            crate::host::financial_diagnostics_v1::host_current(error);
        }
        result
    }
}

#[cfg(all(test, feature = "synthetic-born-joined-qualification"))]
impl Host {
    pub(in crate::host) fn require_stale_financial_dispatch_refused_v1(
        &self,
        root: &std::path::Path,
        claim: &wholepact_authority::completed_dispatch_v1::AuthorizeCompletedDispatchV1,
    ) -> Result<()> {
        financial_step!(InputValidation, NotEstablished);
        let result = (|| -> Result<_> {
            financial_step!(OriginalSource, NotEstablished);
            let owner = self.original_financial_owner_v1(root)?;
            let inspection = owner.initial_inspection();
            financial_step!(ReadConsent, NotEstablished);
            let approval = self.terminal.approve_historical("Verify the saved original dispatch pair and perform one never-funded qualification probe that is independently proven stale by current authenticated history. Require explicit StaleHead and unchanged history; any uncertain or unexpected outcome stops the test without sending transaction bytes.")?;
            let read = ClosedFinancialReadConsentV1 {
                owner: &owner,
                inspection,
                approval: &approval,
            };
            financial_step!(SourcePreparation, NotEstablished);
            let prepared = owner
                .coordinator()
                .prepare_original_financial_v1(self.access()?, &read, &read, &read)
                .map_err(|error| {
                    financial_record!(engine, SourcePreparation, NotEstablished, &error);
                    error
                })?;
            financial_step!(RetainedPairRead, OutcomeUncertain);
            let intent = prepared
                .retained_dispatch_intent_v1(
                    claim.context.attempt,
                    self.access()?,
                    &read,
                    &read,
                    &read,
                )
                .map_err(|error| {
                    financial_record!(engine, RetainedPairRead, OutcomeUncertain, &error);
                    error
                })?;
            let index = intent
                .requests()
                .iter()
                .position(|request| request == claim)
                .ok_or(Error::Authentication)?;
            financial_step!(StaleRefusal, OutcomeUncertain);
            owner.require_stale_dispatch_refused_v1(
                &intent,
                index,
                self.access()?,
                &read,
                &read,
                &read,
                &approval,
            )
        })();
        #[cfg(all(
            test,
            feature = "synthetic-born-joined-qualification",
            feature = "durable-proposal"
        ))]
        if let Err(error) = &result {
            crate::host::financial_diagnostics_v1::host_current(error);
        }
        result
    }
}

#[cfg(test)]
mod original_effect_clock_tests {
    #[test]
    fn retained_original_source_bounds_are_lower_inclusive_upper_exclusive() {
        assert!(!super::original_source_clocks_at((100, 200), 99));
        assert!(super::original_source_clocks_at((100, 200), 100));
        assert!(super::original_source_clocks_at((100, 200), 199));
        assert!(!super::original_source_clocks_at((100, 200), 200));
        assert!(!super::original_source_clocks_at((200, 100), 150));
    }
}

/// Cached original action/source clocks only. The installed original TTY and
/// shared observer are checked last, with no source or socket-lock re-entry.
#[cfg(feature = "coordinated-financial-workflow-v1")]
struct OriginalResultIoRestrictionV1 {
    bounds: crate::terminal::OriginalPromptBoundsV1,
}
#[cfg(feature = "coordinated-financial-workflow-v1")]
impl wholepact_signer::authority_bridge::financial_continuation_v1::FinancialResultRestrictionV1 for OriginalResultIoRestrictionV1 {
    fn check_before_io(&self) -> wholepact_signer::authority_bridge::Result<()> {
        self.bounds.check().and_then(|()| crate::terminal::check_original_coordinator_restriction())
            .map_err(|_| wholepact_signer::authority_bridge::BridgeError::Permission)
    }
}
#[cfg(feature = "coordinated-financial-workflow-v1")]
fn original_result_material_bounds(
    inspection: &PrivateDurableFinancialInspectionV1, source: (u64, u64),
) -> Result<(u64, u64)> {
    if inspection.materials().len() != 2 { return Err(Error::Authentication); }
    let from = inspection.materials().iter().map(|m| m.scope().valid_from_unix_seconds)
        .max().ok_or(Error::Authentication)?.checked_mul(1000).ok_or(Error::Permission)?;
    let until = inspection.materials().iter().map(|m| m.scope().valid_until_unix_seconds)
        .min().ok_or(Error::Authentication)?.checked_mul(1000).ok_or(Error::Permission)?;
    Ok((from.max(source.0), until.min(source.1)))
}
#[cfg(feature = "coordinated-financial-workflow-v1")]
impl Host {
    // Only the actual same-Host retained V3 wrapper calls this. The maintained
    // opening obtains its own initial inspection before opening private sources.
    pub(in crate::host::financial) fn prepare_retained_original_financial_preview_v3(
        &self,
        root: &std::path::Path,
        pending: wholepact_signer::authority_bridge::durable_delivery_admission_ipc_v3::PendingDurableDeliveryAdmissionV3,
        socket: &std::path::Path,
        request: &wholepact_signer::authority_bridge::financial_continuation_v1::FinancialResultRequestV1,
        history: &wholepact_signer::authority_bridge::financial_continuation_v1::AuthenticatedFinancialContinuationHistoryV1,
        original_host_material_delivery_ceiling: std::time::Instant,
        original: Box<dyn wholepact_signer::authority_bridge::financial_continuation_v1::FinancialResultRestrictionV1>,
    ) -> Result<wholepact_signer::authority_bridge::financial_continuation_v1::PreparedFinancialResultReceiverV1> {
        if !crate::terminal::coordinated_restriction_required() { return Err(Error::Permission); }
        let owner = self.original_financial_owner_v1(root)?;
        let inspection = owner.initial_inspection();
        let terms = &history.continuation_record().terms;
        let source = original_result_material_bounds(inspection, (
            terms.valid_from_ms.max(terms.scope.authorization.valid_from_ms),
            terms.valid_until_ms.min(terms.scope.authorization.valid_until_ms),
        ))?;
        if inspection.fixed_identity() != &request.fixed { return Err(Error::Authentication); }
        let prompt_bounds = crate::terminal::OriginalPromptBoundsV1::new(
            original_host_material_delivery_ceiling.min(crate::terminal::original_coordinated_session_ceiling()?), source,
        )?;
        // Static text discloses no saved DTO. The cached original inspection
        // material/source clocks still bound each prompt write/response read.
        let approval = self.terminal.approve_historical_original(
            "Read ONLY the exact protected original financial result-preview metadata from the SAME retained original Signer process for this original fixed source. Independently match its complete continuation and result commitments. No signature bytes, ReturnExact, retention, signing, extraction or dispatch is authorized by this Read.",
            Some(&prompt_bounds),
        )?;
        let read = ClosedFinancialReadConsentV1 { owner: &owner, inspection, approval: &approval };
        read.check()?;
        let preview_read = OriginalResultIoRestrictionV1 {
            bounds: prompt_bounds.narrow_deadline(approval.deadline()),
        };
        let receiver = pending.prepare_retained_financial_result_v1(
            socket, request, history, original_host_material_delivery_ceiling, original, &preview_read,
        ).map_err(|_| Error::Permission)?;
        read.check()?;
        // The fresh preview Read ends here. It is never carried as authority
        // into the separately reviewed intake or replaced with a new deadline.
        Ok(receiver)
    }
}

#[cfg(feature = "coordinated-financial-workflow-v1")]
impl Host {
    pub(in crate::host::financial) fn prepare_retained_original_coordinated_financial_preview_v1(
        &self,
        root: &std::path::Path,
        pending: wholepact_signer::authority_bridge::durable_review_ipc_v3::coordinated_v1::PendingCoordinatedDurableDeliveryAdmissionV1,
        socket: &std::path::Path,
        request: &wholepact_signer::authority_bridge::financial_continuation_v1::FinancialResultRequestV1,
        history: &wholepact_signer::authority_bridge::financial_continuation_v1::AuthenticatedFinancialContinuationHistoryV1,
        original_host_material_delivery_ceiling: std::time::Instant,
        original: Box<dyn wholepact_signer::authority_bridge::financial_continuation_v1::FinancialResultRestrictionV1>,
    ) -> Result<wholepact_signer::authority_bridge::financial_continuation_v1::PreparedCoordinatedFinancialResultReceiverV1> {
        if !crate::terminal::coordinated_restriction_required() { return Err(Error::Permission); }
        let owner = self.original_financial_owner_v1(root)?;
        let inspection = owner.initial_inspection();
        let terms = &history.continuation_record().terms;
        let source = original_result_material_bounds(inspection, (
            terms.valid_from_ms.max(terms.scope.authorization.valid_from_ms),
            terms.valid_until_ms.min(terms.scope.authorization.valid_until_ms),
        ))?;
        if inspection.fixed_identity() != &request.fixed { return Err(Error::Authentication); }
        let prompt_bounds = crate::terminal::OriginalPromptBoundsV1::new(
            original_host_material_delivery_ceiling.min(crate::terminal::original_coordinated_session_ceiling()?), source,
        )?;
        // Static text discloses no saved DTO. The cached original inspection
        // material/source clocks still bound each prompt write/response read.
        let approval = self.terminal.approve_historical_original(
            "Read ONLY the exact protected original financial result-preview metadata from the SAME retained original Signer process for this original fixed source. Independently match its complete continuation and result commitments. No signature bytes, ReturnExact, retention, signing, extraction or dispatch is authorized by this Read.",
            Some(&prompt_bounds),
        )?;
        let read = ClosedFinancialReadConsentV1 { owner: &owner, inspection, approval: &approval };
        read.check()?;
        let preview_read = OriginalResultIoRestrictionV1 {
            bounds: prompt_bounds.narrow_deadline(approval.deadline()),
        };
        let receiver = pending.prepare_retained_financial_result_v1(
            socket, request, history, original_host_material_delivery_ceiling, original, &preview_read,
        ).map_err(|_| Error::Permission)?;
        read.check()?;
        // The fresh preview Read ends here. It is never carried as authority
        // into the separately reviewed intake or replaced with a new deadline.
        Ok(receiver)
    }
}

/// Private concrete adapter only; callers cannot supply a transport or create
/// an authenticated lease from metadata. The actual original-origin variant
/// remains inside the Signer's sealed receiver and resulting lease.
trait OriginalFinancialResultReceiverV1: Sized {
    fn preview(&self) -> &wholepact_signer::authority_bridge::financial_continuation_v1::AuthenticatedFinancialResultPreviewV1;
    #[cfg(feature = "coordinated-financial-workflow-v1")]
    fn bind_original_intake_restriction_v1(self, restriction: Box<dyn wholepact_signer::authority_bridge::financial_continuation_v1::FinancialResultRestrictionV1>) -> wholepact_signer::authority_bridge::Result<Self>;
    fn receive_host(self) -> wholepact_signer::authority_bridge::Result<wholepact_signer::authority_bridge::financial_continuation_v1::AuthenticatedFinancialResultLeaseV1>;
}
impl OriginalFinancialResultReceiverV1 for wholepact_signer::authority_bridge::financial_continuation_v1::PreparedFinancialResultReceiverV1 {
    fn preview(&self) -> &wholepact_signer::authority_bridge::financial_continuation_v1::AuthenticatedFinancialResultPreviewV1 { self.preview() }
    #[cfg(feature = "coordinated-financial-workflow-v1")]
    fn bind_original_intake_restriction_v1(self, restriction: Box<dyn wholepact_signer::authority_bridge::financial_continuation_v1::FinancialResultRestrictionV1>) -> wholepact_signer::authority_bridge::Result<Self> { self.bind_original_intake_restriction_v1(restriction) }
    fn receive_host(self) -> wholepact_signer::authority_bridge::Result<wholepact_signer::authority_bridge::financial_continuation_v1::AuthenticatedFinancialResultLeaseV1> {
        #[cfg(all(test,feature="synthetic-born-joined-qualification",feature="durable-proposal"))]
        { self.receive_observed_v1().map_err(|observed| {
            if let Some(detail)=observed.diagnostic {crate::host::financial_diagnostics_v1::signer_result(detail,crate::host::financial_diagnostics_v1::FinancialCommitStateV1::NotEstablished);}
            observed.error
        }) }
        #[cfg(not(all(test,feature="synthetic-born-joined-qualification",feature="durable-proposal")))]
        { self.receive() }
    }
}
#[cfg(feature = "coordinated-financial-workflow-v1")]
impl OriginalFinancialResultReceiverV1 for wholepact_signer::authority_bridge::financial_continuation_v1::PreparedCoordinatedFinancialResultReceiverV1 {
    fn preview(&self) -> &wholepact_signer::authority_bridge::financial_continuation_v1::AuthenticatedFinancialResultPreviewV1 { self.preview() }
    fn bind_original_intake_restriction_v1(self, restriction: Box<dyn wholepact_signer::authority_bridge::financial_continuation_v1::FinancialResultRestrictionV1>) -> wholepact_signer::authority_bridge::Result<Self> { self.bind_original_intake_restriction_v1(restriction) }
    fn receive_host(self) -> wholepact_signer::authority_bridge::Result<wholepact_signer::authority_bridge::financial_continuation_v1::AuthenticatedFinancialResultLeaseV1> { self.receive() }
}
