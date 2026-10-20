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

fn same<T: serde::Serialize>(left: &T, right: &T) -> bool {
    serde_json::to_vec(left)
        .ok()
        .zip(serde_json::to_vec(right).ok())
        .is_some_and(|(left, right)| left == right)
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
impl LocalPrivateDurableFinancialConsentV1 for ClosedFinancialReadConsentV1<'_, '_> {
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
impl wholepact_chain::SubmissionPermit for ProductionDurableSubmissionPermitV1<'_, '_, '_, '_, '_> {
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
    fn permits_source(&self, scope: &PrivateWorkspaceScopeV1) -> bool {
        same(scope, self.read.inspection.workspace_scope())
            && self.read.check().is_ok()
            && self.read.owner.check_effect_source().is_ok()
            && self.native.check_current().is_ok()
    }
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
        let owner = self
            .original_financial_owner_v1(root)
            .map_err(|_| financial_failure("ORIGINAL_SOURCE"))?;
        let inspection = owner.initial_inspection();
        let approval = self.terminal.approve_historical("Read and mathematically verify only the saved original financial union and completed transaction for this exact dispatch review. Missing or uncertain extraction must remain fenced; this read cannot repair, re-sign or extract.")?;
        let read = ClosedFinancialReadConsentV1 {
            owner: &owner,
            inspection,
            approval: &approval,
        };
        read.check()?;
        let financial = self.financial.as_ref().ok_or(Error::Locked)?;
        let access = self.access()?;
        let mut prepared = owner
            .coordinator()
            .prepare_original_financial_v1(access, &read, &read, &read)
            .map_err(|_| financial_failure("FIXED_SOURCE_VERIFICATION"))?;
        let contexts = prepared.financial_retention_contexts_v1(access, &read, &read, &read)
            .map_err(|_| financial_failure("RETENTION_CONTEXTS"))?;
        let retention = self.authority.financial_retention_consent_v1(&contexts)?;
        let operation = histories[0]
            .continuation_record()
            .terms
            .scope
            .delivery
            .submission_operation_id
            .clone();
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
            .map_err(|_| financial_failure("COMPLETED_VERIFICATION"))?;
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
        let frozen = retention.freeze_for_dispatch()?;
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
            attempt: prepared.next_dispatch_attempt_v1()?,
        };
        verified.validate_completed_dispatch_context_v1(&context)?;
        // Last human prompt. Every gate below is closed and has no terminal.
        let native = self.authority.approve_exact_durable_submission_v1(
            verified.retained(),
            context,
            &journal_identity,
            &backend_identity,
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
                .map_err(|_| financial_failure("PAIR_INTENT"))?;
        }
        let mut admissions = Vec::with_capacity(2);
        for index in 0..2 {
            let intent = prepared.retained_dispatch_intent_v1(
                native.context().attempt,
                access,
                &effect,
                &read,
                &read,
            )?;
            let admission = owner.admit_completed_dispatch_v1(
                &intent, index, access, &effect, &read, &read, &native,
            )?;
            drop(intent);
            prepared = prepared
                .retain_dispatch_admission_v1(
                    access,
                    &format!("dispatch-{command_key}-admission-{index}"),
                    &admission,
                    &effect,
                    &read,
                    &read,
                )
                .map_err(|_| financial_failure("ADMISSION_RETENTION"))?;
            admissions.push(admission);
        }
        let admissions: [_; 2] = admissions.try_into().map_err(|_| Error::Invalid)?;
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
            .map_err(|_| financial_failure("COMPLETED_VERIFICATION"))?;
        let policy = wholepact_chain::SubmissionPolicy {
            minimum_expiry_margin_blocks: native.context().delivery.minimum_expiry_margin_blocks,
            ..Default::default()
        };
        // Fresh provider context is not a human prompt or authority renewal.
        let chain_context = backend.fresh_context().await?;
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
            .map_err(|_| financial_failure("SAVED_TRANSACTION_HANDOFF"))?;
        let mut authority = ProductionDurableSubmissionAuthorityV1 {
            verified: &verified,
            access,
            read: &read,
            admissions: &admissions,
            native: &native,
            retention: &frozen,
            used: false,
        };
        prepared
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
            .map_err(|_| financial_failure("DISPATCH_OUTCOME"))
    }
}

/// An independently reviewed local financial step. It is neither a historical
/// read grant nor a final network-dispatch decision. Its private constructor is
/// the exact foreground Host command below; no remote effect uses this type.
struct ClosedFinancialPreparationConsentV1<'a, 'host> {
    read: &'a ClosedFinancialReadConsentV1<'a, 'host>,
    effect: &'a HistoricalApproval,
}
impl LocalPrivateDurableFinancialConsentV1 for ClosedFinancialPreparationConsentV1<'_, '_> {
    fn permits_source(&self, scope: &PrivateWorkspaceScopeV1) -> bool {
        same(scope, self.read.inspection.workspace_scope())
            && self.read.check().is_ok()
            && self.read.owner.check_effect_source().is_ok()
            && self.effect.check().is_ok()
    }
}
impl Host {
    pub(in crate::host) fn bind_original_financial_continuations_v1(
        &self,
        root: &std::path::Path,
        key: &str,
        histories: [&wholepact_signer::authority_bridge::financial_continuation_v1::AuthenticatedFinancialContinuationHistoryV1; 2],
    ) -> Result<u64> {
        crate::id(key)?;
        let owner = self
            .original_financial_owner_v1(root)
            .map_err(|_| financial_failure("ORIGINAL_SOURCE"))?;
        let inspection = owner.initial_inspection();
        let approval = self.terminal.approve_historical("Read this exact original saved fixed proof and both original financial continuation records. No signing, repair or dispatch is permitted by this read.")?;
        let read = ClosedFinancialReadConsentV1 {
            owner: &owner,
            inspection,
            approval: &approval,
        };
        let approval = self.terminal.approve_historical(&format!("Record the two authenticated owner financial continuations against this exact original fixed proposal {} at revision {}, command {}. This local association does not sign, reserve, extract or dispatch, and does not extend any owner deadline.", inspection.fixed_identity().proposal_id, inspection.revision(), key))?;
        let effect = ClosedFinancialPreparationConsentV1 {
            read: &read,
            effect: &approval,
        };
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
            .map_err(|_| financial_failure("CONTINUATION_BIND"))
    }

    pub(in crate::host) fn intake_original_financial_result_v1(
        &self,
        root: &std::path::Path,
        key: &str,
        receiver: wholepact_signer::authority_bridge::financial_continuation_v1::PreparedFinancialResultReceiverV1,
        history: &wholepact_signer::authority_bridge::financial_continuation_v1::AuthenticatedFinancialContinuationHistoryV1,
    ) -> Result<u64> {
        use wholepact_engine::signature_intake::LocalSignedRetention;
        use wholepact_protocol::authorization::retention::SignedRetentionConsent;
        crate::id(key)?;
        let owner = self
            .original_financial_owner_v1(root)
            .map_err(|_| financial_failure("ORIGINAL_SOURCE"))?;
        let inspection = owner.initial_inspection();
        let read_approval = self.terminal.approve_historical("Read the exact original financial fixed proof and existing intake lineage for protected signer-result verification. No missing result may be regenerated.")?;
        let read = ClosedFinancialReadConsentV1 {
            owner: &owner,
            inspection,
            approval: &read_approval,
        };
        let effect_approval = self.terminal.approve_historical(&format!("Verify and retain one actual authenticated original signer result for fixed proposal {}, revision {}, command {}. The installed protected receive route and original source provenance must match. This cannot invoke signing or extract a transaction.", inspection.fixed_identity().proposal_id, inspection.revision(), key))?;
        let effect = ClosedFinancialPreparationConsentV1 {
            read: &read,
            effect: &effect_approval,
        };
        let scope = inspection.checkpoint_scope();
        let retention = self.authority.retention_consent(
            &scope.principal_id,
            &scope.candidate_id,
            &scope.manifest_digest,
            inspection.proof_job_id(),
            scope.account_ids.iter().cloned().collect(),
        )?;
        let financial = self.financial.as_ref().ok_or(Error::Locked)?;
        let prepared = owner
            .coordinator()
            .prepare_original_financial_v1(self.access()?, &effect, &read, &read)
            .map_err(|_| financial_failure("FIXED_SOURCE_VERIFICATION"))?;
        let expected_scope = prepared
            .financial_result_retention_scope_v1(
                receiver.preview(),
                self.access()?,
                &effect,
                &read,
                &read,
            )
            .map_err(|_| financial_failure("RESULT_PREFLIGHT"))?;
        if !SignedRetentionConsent::permits(&retention, &expected_scope) {
            return Err(Error::Permission);
        }
        let original_until = inspection
            .materials()
            .iter()
            .map(|m| m.scope().valid_until_unix_seconds)
            .chain(std::iter::once(
                prepared.original_financial_valid_until_ms_v1()? / 1000,
            ))
            .min()
            .ok_or(Error::Authentication)?;
        let setup_approval = self
            .terminal
            .approve_financial_intake_setup_v1(&expected_scope, original_until)?;
        let setup = ClosedFinancialIntakeSetupV1 {
            owner: &owner,
            inspection,
            approval: &setup_approval,
            exact_scope: &expected_scope,
        };
        let retention = retention.freeze_for_signed_intake()?;
        drop(effect);
        drop(read);
        drop(effect_approval);
        drop(read_approval);
        // Only now may the independently approved Signer ReturnExact begin.
        // All later gates are closed; no Host human wait consumes its lease.
        let delivery = receiver
            .receive()
            .map_err(|_| financial_failure("RESULT_RECEIVE"))?;
        let revision = prepared
            .intake_original_signature_v1(
                self.access()?,
                key,
                &delivery,
                history,
                LocalSignedRetention {
                    journal: &financial.signed,
                    consent: &retention,
                },
                &setup,
                &setup,
                &setup,
            )
            .map_err(|_| financial_failure("AUTHENTICATED_INTAKE"))?;
        delivery
            .finish()
            .map_err(|_| financial_failure("RESULT_FINISH_ACKNOWLEDGEMENT"))?;
        Ok(revision)
    }

    pub(in crate::host) fn complete_original_financial_transaction_v1(
        &self,
        root: &std::path::Path,
        key: &str,
    ) -> Result<
        wholepact_protocol::authorization::retention::transaction::TransactionCheckpointSummary,
    > {
        use wholepact_engine::signature_intake::LocalSignedRetention;
        use wholepact_protocol::authorization::retention::transaction::LocalTransactionCheckpoint;
        crate::id(key)?;
        let owner = self
            .original_financial_owner_v1(root)
            .map_err(|_| financial_failure("ORIGINAL_SOURCE"))?;
        let inspection = owner.initial_inspection();
        let approval = self.terminal.approve_historical("Read and verify the exact two retained financial signer results and original proof. Incomplete or uncertain result lineage remains fenced.")?;
        let read = ClosedFinancialReadConsentV1 {
            owner: &owner,
            inspection,
            approval: &approval,
        };
        let approval = self.terminal.approve_historical(&format!("Combine only the two exact retained original signature subsets for proposal {}, revision {}, command {}, then create its single immutable completed transaction checkpoint. An existing extraction intent without a result is RecoveryRequired, never permission to re-extract. This performs no network submission.", inspection.fixed_identity().proposal_id, inspection.revision(), key))?;
        let effect = ClosedFinancialPreparationConsentV1 {
            read: &read,
            effect: &approval,
        };
        let financial = self.financial.as_ref().ok_or(Error::Locked)?;
        let prepared = owner
            .coordinator()
            .prepare_original_financial_v1(self.access()?, &effect, &read, &read)
            .map_err(|_| financial_failure("FIXED_SOURCE_VERIFICATION"))?;
        let contexts = prepared.financial_retention_contexts_v1(
            self.access()?, &effect, &read, &read,
        ).map_err(|_| financial_failure("RETENTION_CONTEXTS"))?;
        let retention = self.authority.financial_retention_consent_v1(&contexts)?;
        prepared
            .retain_original_union_v1(
                self.access()?,
                key,
                LocalSignedRetention {
                    journal: &financial.signed,
                    consent: &retention,
                },
                &effect,
                &read,
                &read,
            )
            .map_err(|_| financial_failure("UNION_RETENTION"))?;
        // Reload only after our own successful append. The coordinator audits the
        // complete bounded lineage; no stale prepared pin is silently refreshed.
        let prepared = owner
            .coordinator()
            .prepare_original_financial_v1(self.access()?, &effect, &read, &read)
            .map_err(|_| financial_failure("FIXED_SOURCE_VERIFICATION"))?;
        prepared
            .checkpoint_original_transaction_v1(
                self.access()?,
                LocalSignedRetention {
                    journal: &financial.signed,
                    consent: &retention,
                },
                LocalTransactionCheckpoint {
                    journal: &financial.transactions,
                    consent: &retention,
                },
                &effect,
                &read,
                &read,
            )
            .map_err(|_| financial_failure("EXTRACTION_CHECKPOINT"))
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
        let owner = self.original_financial_owner_v1(root)?;
        let approval = self.terminal.approve_historical("Read the complete authenticated original financial Witness history through the planned dispatcher, including exact partial/uncertain dispatch outcomes. This read cannot append a request or recreate a live admission or old Host decision.")?;
        owner.financial_history_v1(account, continuation_operation, &approval)
    }
}

/// Closed setup for exactly one pre-reviewed signature intake. It is not usable
/// by the union, extraction or dispatch compositions, and exposes no terminal.
struct ClosedFinancialIntakeSetupV1<'a, 'host> {
    owner: &'a OriginalFinancialOwnerV1<'host>,
    inspection: &'a PrivateDurableFinancialInspectionV1,
    approval: &'a crate::terminal::historical::FinancialIntakeSetupApprovalV1,
    exact_scope: &'a wholepact_protocol::authorization::retention::SignedRetentionScope,
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
        use wholepact_engine::signature_intake::LocalSignedRetention;
        use wholepact_protocol::authorization::retention::transaction::LocalTransactionCheckpoint;
        let owner = self.original_financial_owner_v1(root)?;
        let inspection = owner.initial_inspection();
        let approval = self.terminal.approve_historical("Read and verify the exact completed original financial transaction and retained dispatch lineage for an inert audit summary. This cannot repair, extract, renew an admission or send a request.")?;
        let read = ClosedFinancialReadConsentV1 {
            owner: &owner,
            inspection,
            approval: &approval,
        };
        let financial = self.financial.as_ref().ok_or(Error::Locked)?;
        let prepared = owner.coordinator().prepare_original_financial_v1(
            self.access()?,
            &read,
            &read,
            &read,
        )?;
        let contexts = prepared.financial_retention_contexts_v1(
            self.access()?, &read, &read, &read,
        ).map_err(|_| financial_failure("RETENTION_CONTEXTS"))?;
        let retention = self.authority.financial_retention_consent_v1(&contexts)?;
        let verified = prepared.verify_completed_submission_v1(
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
        )?;
        let next = prepared.next_dispatch_attempt_v1()?;
        let latest_requests = if next > 1 {
            Some(
                prepared
                    .retained_dispatch_intent_v1(next - 1, self.access()?, &read, &read, &read)?
                    .requests()
                    .clone(),
            )
        } else {
            None
        };
        read.check()?;
        Ok(CompletedPrivateFinancialSummaryV1 {
            checkpoint_id: verified.retained().checkpoint_id(),
            transaction_digest: verified.retained().descriptor().bytes_sha256.clone(),
            transaction_id: verified.retained().descriptor().transaction_id.clone(),
            fixed_identity: serde_json::to_value(verified.retained().fixed_identity())?,
            frozen_export_history_digest: inspection.frozen_export_history_digest.clone(),
            next_delegation_attempt: next,
            latest_requests,
            original_valid_until_ms: prepared.original_financial_valid_until_ms_v1()?,
        })
    }
}

#[cfg(all(test, feature = "synthetic-born-joined-qualification"))]
impl Host {
    pub(in crate::host) fn require_stale_financial_dispatch_refused_v1(
        &self,
        root: &std::path::Path,
        claim: &wholepact_authority::completed_dispatch_v1::AuthorizeCompletedDispatchV1,
    ) -> Result<()> {
        let owner = self.original_financial_owner_v1(root)?;
        let inspection = owner.initial_inspection();
        let approval = self.terminal.approve_historical("Verify the saved original dispatch pair and perform one never-funded qualification probe that is independently proven stale by current authenticated history. Require explicit StaleHead and unchanged history; any uncertain or unexpected outcome stops the test without sending transaction bytes.")?;
        let read = ClosedFinancialReadConsentV1 {
            owner: &owner,
            inspection,
            approval: &approval,
        };
        let prepared = owner.coordinator().prepare_original_financial_v1(
            self.access()?,
            &read,
            &read,
            &read,
        )?;
        let intent = prepared.retained_dispatch_intent_v1(
            claim.context.attempt,
            self.access()?,
            &read,
            &read,
            &read,
        )?;
        let index = intent
            .requests()
            .iter()
            .position(|request| request == claim)
            .ok_or(Error::Authentication)?;
        owner.require_stale_dispatch_refused_v1(
            &intent,
            index,
            self.access()?,
            &read,
            &read,
            &read,
            &approval,
        )
    }
}
