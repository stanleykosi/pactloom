//! Nominal actual-original financial custody. This is not a conversion of B1
//! read/export permission. Opening inspects the exact original sources; every
//! subsequent effect must obtain its own current purpose-specific decision.
use super::*;
use wholepact_engine::{
    LocalPrivateDurableFinancialConsentV1, PrivateDurableFinancialCoordinatorV1,
};

struct InitialFinancialInspectionV1<'a> {
    host: &'a Host,
    files: &'a OriginalWorkspaceDispatcherFilesV4,
    target: &'a ManualCommittedTarget<'a>,
    approval: &'a HistoricalApproval,
}
impl LocalPrivateDurableFinancialConsentV1 for InitialFinancialInspectionV1<'_> {
    fn permits_source(&self, scope: &wholepact_engine::PrivateWorkspaceScopeV1) -> bool {
        scope_matches(scope, self.files)
            && self.approval.check().is_ok()
            && check_admission_originals(self.host, self.files, self.target).is_ok()
            && self.approval.check().is_ok()
    }
}
pub(in crate::host) struct OriginalFinancialOwnerV1<'host> {
    coordinator: PrivateDurableFinancialCoordinatorV1<'host>,
    target: ManualCommittedTarget<'host>,
    host: &'host Host,
    files: &'host OriginalWorkspaceDispatcherFilesV4,
    directory: Directory,
    // Captured from the actual immutable Host journal owner before any dispatch
    // guard is borrowed. Final submission also checks its actual review identity.
    submission_identity: String,
    initial_metadata: wholepact_engine::PrivateDurableFinancialInspectionV1,
}
impl Host {
    pub(in crate::host) fn original_financial_owner_v1<'host>(
        &'host self,
        root: &Path,
    ) -> Result<OriginalFinancialOwnerV1<'host>> {
        self.require_private_workspace_read_session_v1()?;
        let files = self
            .dispatcher_files
            .as_ref()
            .ok_or(Error::Authentication)?;
        files.check_inventory(&self.directory, &self.secrets)?;
        let p = &files.original.workspace.original.pending;
        let c = &files.original.workspace.original.committed;
        if root != p.association.workspace_root {
            return Err(Error::Authentication);
        }
        let inspection = self.terminal.approve_historical(&format!(
            "Inspect this exact original financial continuation and saved proof for agreement {}. Read only the immutable original sources, bounded export history, completed signature/transaction records and original expiry. This inspection cannot sign, extract, acquire authority or dispatch. Original workspace: {}.", p.association.agreement_id, root.display()))?;
        let target = ManualCommittedTarget::open_workspace_dispatcher_original_v4(
            &self.directory,
            &self.secrets,
            files,
        )?;
        check_admission_originals(self, files, &target)?;
        let directory = Directory::open(root)?;
        directory.inventory_of(&["private-coordination.sqlite"], &["profile.lock"])?;
        if directory.manual_target_identity_digest()? != c.workspace_directory_identity {
            return Err(Error::Authentication);
        }
        let source = self
            .engine
            .original_private_workspace_source_v1(self.access()?, &p.association.agreement_id)?;
        let proof = self
            .financial
            .as_ref()
            .ok_or(Error::Locked)?
            .original_workspace_proof_v1()?;
        let privacy = InitialFinancialInspectionV1 {
            host: self,
            files,
            target: &target,
            approval: &inspection,
        };
        let coordinator = PrivateDurableFinancialCoordinatorV1::open_original(
            source,
            self.access()?,
            &p.association.database_path,
            &DatabaseKey::from_bytes(p.database_key),
            c.original_database_origin,
            &p.association.retention_policy,
            &c.association_digest,
            proof,
            p.proof.original_proof_origin,
            &p.initialization_plan,
            &c.seed,
            &privacy,
        )?;
        if coordinator.origin_marker_digest()? != c.seed.marker_digest {
            return Err(Error::Authentication);
        }
        let initial_metadata =
            coordinator.inspect_original_financial_v1(self.access()?, &privacy)?;
        inspection.check()?;
        let submission_identity = self
            .submission
            .lock()
            .map_err(|_| Error::Locked)?
            .identity()
            .to_owned();
        if submission_identity != files.original.pending.submission_journal_identity {
            return Err(Error::Authentication);
        }
        Ok(OriginalFinancialOwnerV1 {
            coordinator,
            target,
            host: self,
            files,
            directory,
            submission_identity,
            initial_metadata,
        })
    }
}
impl<'host> OriginalFinancialOwnerV1<'host> {
    /// Inert exact metadata inspected under the completed opening decision.
    /// Later operations require a new closed read/effect decision and live pins.
    pub(in crate::host) fn initial_inspection(
        &self,
    ) -> &wholepact_engine::PrivateDurableFinancialInspectionV1 {
        &self.initial_metadata
    }
    pub(in crate::host) fn coordinator(&self) -> &PrivateDurableFinancialCoordinatorV1<'host> {
        &self.coordinator
    }
    pub(in crate::host) fn workspace_scope(&self) -> &wholepact_engine::PrivateWorkspaceScopeV1 {
        self.coordinator.workspace_scope()
    }
    pub(in crate::host) fn check_read_source(&self) -> Result<()> {
        require_closed_original_source_permission_v3(
            self.host,
            ClosedOriginalSourcePurposeV3::HistoricalRead,
        )?;
        self.check_source_identity()
    }
    pub(in crate::host) fn check_effect_source(&self) -> Result<()> {
        require_closed_original_source_permission_v3(
            self.host,
            ClosedOriginalSourcePurposeV3::ManualEffect,
        )?;
        self.check_source_identity()
    }
    fn check_source_identity(&self) -> Result<()> {
        self.target.check_current()?;
        self.files
            .original
            .workspace
            .check_combined_v4(&self.host.directory, &self.host.secrets)?;
        self.files
            .original
            .pending_file
            .check(&self.host.directory, MAX_PENDING)?;
        self.files
            .original
            .commit_file
            .check(&self.host.directory, MAX_COMMIT)?;
        if !self.files.original.pending_file.is_final()
            || !self.files.original.commit_file.is_final()
            || self.host.access()?.principal_id != self.files.original.pending.principal_id
            || self.host.dispatcher.is_none()
            || self.host.workspace_files.is_some()
            || self.submission_identity != self.files.original.pending.submission_journal_identity
            || self
                .host
                .financial
                .as_ref()
                .ok_or(Error::Locked)?
                .manual_original_primary_origin_digest(&self.host.directory, &self.host.secrets)?
                != self
                    .files
                    .original
                    .pending
                    .original_host
                    .financial_journal_origin_digest
        {
            return Err(Error::Authentication);
        }
        self.host.submission_identity.check_retained_owner_path()?;
        self.directory
            .inventory_of(&["private-coordination.sqlite"], &["profile.lock"])?;
        if self.directory.manual_target_identity_digest()?
            != self
                .files
                .original
                .workspace
                .original
                .committed
                .workspace_directory_identity
        {
            return Err(Error::Authentication);
        }
        self.host.directory.inventory_of(
            &[
                "coordination.sqlite",
                "inbox.sqlite",
                "outbox.sqlite",
                "submission.sqlite",
                "history.capsule.sqlite",
            ],
            &[
                "profile.lock",
                "profile.vault",
                "recovery.plan",
                "generation.manifest",
                "generation.commit",
                "generation.keys",
                "financial.attached",
                "financial.inventory",
                crate::files::PRIVATE_PENDING,
                crate::files::PRIVATE_COMMIT,
                self.files.original.pending_file.name(),
                self.files.original.commit_file.name(),
            ],
        )?;
        self.target.check_current()
    }
    pub(in crate::host) fn descriptor(&self) -> Result<DurableDeliveryDispatcherV2> {
        self.check_read_source()?;
        self.files.original.pending.descriptor()
    }
    pub(in crate::host) fn submission_journal_identity(&self) -> Result<String> {
        self.check_read_source()?;
        Ok(self.submission_identity.clone())
    }
}

impl OriginalFinancialOwnerV1<'_> {
    /// This is the ONLY new use of retained dispatcher TLS custody. The caller
    /// cannot obtain a client or key. A sealed durable intent and actual fresh
    /// Host decision must remain current across the real handshake and request.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::host) fn admit_completed_dispatch_v1(
        &self,
        intent: &wholepact_engine::RetainedPrivateDispatchIntentV1<'_, '_, '_>,
        index: usize,
        access: &wholepact_engine::Access,
        source: &dyn wholepact_engine::LocalPrivateDurableFinancialConsentV1,
        proof: &dyn wholepact_proof_jobs::LocalProofConsent,
        material: &dyn wholepact_engine::durable_construction_v1::LocalDurableMaterialConsentV1,
        native: &crate::authority::durable_submission_v1::NativeDurableSubmissionConsentV1,
    ) -> Result<wholepact_authority::completed_dispatch_v1::AuthenticatedCompletedDispatchAdmissionV1>
    {
        self.check_effect_source()?;
        native.check_current()?;
        intent.check_current_v1(access, source, proof, material)?;
        let request = intent.requests().get(index).ok_or(Error::Invalid)?;
        if &request.context != native.context()
            || request.host_reviewed_at_ms != native.reviewed_at_ms()
            || request.context.delivery.dispatcher != self.descriptor()?
            || request.context.delivery.submission_journal_identity
                != self.submission_journal_identity()?
        {
            return Err(Error::Authentication);
        }
        let selected = self
            .files
            .original
            .pending
            .destinations
            .iter()
            .position(|d| d.witness.account_id == request.account_id)
            .ok_or(Error::Authentication)?;
        let stored = self.host.dispatcher.as_ref().ok_or(Error::Authentication)?;
        let client = &stored.destinations[selected];
        let deadline = native.deadline()?;
        client.authorize_completed_dispatch_v1_checked_until(request, deadline, || {
            self.check_effect_source().map_err(|_| wholepact_authority::AuthorityError::Permission)?;
            native.check_current().map_err(|_| wholepact_authority::AuthorityError::Permission)?;
            intent.check_current_v1(access, source, proof, material).map_err(|_| wholepact_authority::AuthorityError::Permission)
        }).map_err(|error| {
            #[cfg(all(test, feature = "synthetic-born-joined-qualification"))]
            report_financial_authority_failure_v1(false, &error);
            let _ = error;
            Error::Receipt("DISPATCH_ADMISSION_UNKNOWN: preserve the exact retained pair requests and inspect the same original operations; no replacement or expiry renewal is authorized".into())
        })
    }
}

impl OriginalFinancialOwnerV1<'_> {
    /// Read-only authenticated reconciliation through the planned dispatcher.
    /// No mutation request, live admission, raw client or key escapes this method.
    pub(in crate::host) fn financial_history_v1(
        &self, account: &str, continuation_operation: &str,
        approval: &HistoricalApproval,
    ) -> Result<wholepact_authority::durable_financial_continuation_v1::AuthenticatedFinancialContinuationHistoryV1>{
        self.check_read_source()?;
        approval.check()?;
        let selected = self
            .files
            .original
            .pending
            .destinations
            .iter()
            .position(|d| d.witness.account_id == account)
            .ok_or(Error::Authentication)?;
        let stored = self.host.dispatcher.as_ref().ok_or(Error::Authentication)?;
        let client = &stored.destinations[selected];
        let history = client.financial_continuation_history_v1_checked_until(continuation_operation, approval.deadline(), || {
            self.check_read_source().map_err(|_| wholepact_authority::AuthorityError::Permission)?;
            approval.check().map_err(|_| wholepact_authority::AuthorityError::Permission)
        }).map_err(|error| {
            #[cfg(all(test, feature = "synthetic-born-joined-qualification"))]
            report_financial_authority_failure_v1(true, &error);
            let _ = error;
            Error::Receipt("FINANCIAL_HISTORY_RECONCILIATION: original outcome remains uncertain; preserve exact operations".into())
        })?;
        let record = history.continuation_record();
        if record.terms.scope.authorization.identity.account_id != account
            || record.terms.scope.delivery.dispatcher != self.descriptor()?
            || record.terms.scope.delivery.submission_journal_identity
                != self.submission_journal_identity()?
            || serde_json::to_value(&record.terms.scope.authorization.fixed)?
                != serde_json::to_value(self.initial_metadata.fixed_identity())?
        {
            return Err(Error::Authentication);
        }
        approval.check()?;
        self.check_read_source()?;
        Ok(history)
    }
}

#[cfg(all(test, feature = "synthetic-born-joined-qualification"))]
impl OriginalFinancialOwnerV1<'_> {
    /// Deny-only never-funded qualification. A current authenticated history
    /// must independently prove this exact original head stale before any write.
    pub(in crate::host) fn require_stale_dispatch_refused_v1(
        &self,
        intent: &wholepact_engine::RetainedPrivateDispatchIntentV1<'_, '_, '_>,
        index: usize,
        access: &wholepact_engine::Access,
        source: &dyn LocalPrivateDurableFinancialConsentV1,
        proof: &dyn wholepact_proof_jobs::LocalProofConsent,
        material: &dyn wholepact_engine::durable_construction_v1::LocalDurableMaterialConsentV1,
        approval: &HistoricalApproval,
    ) -> Result<()> {
        intent.check_current_v1(access, source, proof, material)?;
        let original = intent.requests().get(index).ok_or(Error::Invalid)?;
        let continuation = original
            .context
            .owners
            .iter()
            .find(|o| o.account_id == original.account_id)
            .ok_or(Error::Authentication)?
            .continuation_operation_id
            .clone();
        let before = self.financial_history_v1(&original.account_id, &continuation, approval)?;
        if before.snapshot().head == original.expected_head
            || before
                .completed_dispatch_outcome(original)
                .map_err(|_| Error::Authentication)?
                .is_none()
        {
            return Err(Error::Authentication);
        }
        let mut request = original.clone();
        request.context.attempt = request
            .context
            .attempt
            .checked_add(1)
            .ok_or(Error::Invalid)?;
        request.operation_id = request
            .canonical_operation_id()
            .map_err(|_| Error::Invalid)?;
        request.host_reviewed_at_ms = crate::now()?.checked_mul(1000).ok_or(Error::Invalid)?;
        request.validate().map_err(|_| Error::Invalid)?;
        if before
            .completed_dispatch_outcome(&request)
            .map_err(|_| Error::Authentication)?
            .is_some()
        {
            return Err(Error::Authentication);
        }
        let selected = self
            .files
            .original
            .pending
            .destinations
            .iter()
            .position(|d| d.witness.account_id == request.account_id)
            .ok_or(Error::Authentication)?;
        let stored = self.host.dispatcher.as_ref().ok_or(Error::Authentication)?;
        let client = &stored.destinations[selected];
        let outcome = client.authorize_completed_dispatch_v1_checked_until(
            &request,
            approval.deadline(),
            || {
                self.check_read_source()
                    .map_err(|_| wholepact_authority::AuthorityError::Permission)?;
                approval
                    .check()
                    .map_err(|_| wholepact_authority::AuthorityError::Permission)
            },
        );
        if !matches!(outcome, Err(wholepact_authority::AuthorityError::StaleHead)) {
            return Err(Error::Receipt("SYNTHETIC_STALE_PROBE_UNEXPECTED_OR_UNCERTAIN: preserve originals, no retry or send".into()));
        }
        let after = self.financial_history_v1(&original.account_id, &continuation, approval)?;
        if after.history_digest() != before.history_digest()
            || after.snapshot() != before.snapshot()
            || after
                .completed_dispatch_outcome(&request)
                .map_err(|_| Error::Authentication)?
                .is_some()
        {
            return Err(Error::Authentication);
        }
        intent.check_current_v1(access, source, proof, material)?;
        Ok(())
    }
}

// Qualification-only finite first-failure evidence. No payload, source path,
// request, certificate, receipt or key is formatted. Output cannot replace the
// actual owned failure or turn an uncertain response into verified absence.
#[cfg(all(test, feature = "synthetic-born-joined-qualification"))]
fn report_financial_authority_failure_v1(history: bool, error: &wholepact_authority::AuthorityError) {
    use std::io::Write;
    use wholepact_authority::AuthorityError as E;
    let outcome = match error {
        E::InvalidBinding => "AuthorityInvalidBinding",
        E::Permission => "AuthorityPermission",
        E::StaleHead => "AuthorityStaleHead",
        E::Conflict => "AuthorityConflict",
        E::Inactive => "AuthorityInactive",
        E::RecoveryRequired => "AuthorityRecoveryRequired",
        E::Expired => "AuthorityExpired",
        E::PolicyDenied => "AuthorityPolicyDenied",
        E::BudgetExceeded => "AuthorityBudgetExceeded",
        E::InputReserved => "AuthorityInputReserved",
        E::ObligationReserved => "AuthorityObligationReserved",
        E::Limit => "AuthorityLimit",
        E::Storage => "AuthorityStorage",
        E::CorruptHistory => "AuthorityCorruptHistory",
        E::PermanentStopUnavailable => "AuthorityPermanentStopUnavailable",
        E::OfflineHistoryUnsupported => "AuthorityOfflineHistoryUnsupported",
        E::ConstructionHistoryUnsupported => "AuthorityConstructionHistoryUnsupported",
        E::UnsupportedVersion => "AuthorityUnsupportedVersion",
        E::Authentication => "AuthorityAuthentication",
        E::Uncertain => "AuthorityUncertain",
        E::ResolutionUnavailable => "AuthorityResolutionUnavailable",
        E::SessionRequired => "AuthoritySessionRequired",
        E::SessionPending => "AuthoritySessionPending",
    };
    let boundary = if history { "DeliveryHistoricalRead" } else { "DeliveryNativeAdmission" };
    let _ = writeln!(std::io::stderr().lock(), "\n[JOINED_DIAGNOSTIC {boundary} {outcome}]");
}
