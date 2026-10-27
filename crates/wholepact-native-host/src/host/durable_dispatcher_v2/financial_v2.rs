//! Versioned durable result lifecycle custody. Original source/peer/file checks
//! are the existing V1 checks; only the separately versioned Engine owner differs.
//! Nominal actual-original financial custody. This is not a conversion of B1
//! read/export permission. Opening inspects the exact original sources; every
//! subsequent effect must obtain its own current purpose-specific decision.
use super::*;
use wholepact_engine::{
    LocalPrivateDurableFinancialConsentV1, PrivateDurableFinancialCoordinatorV2,
};

struct InitialFinancialInspectionV1<'a> {
    host: &'a Host,
    files: &'a OriginalWorkspaceDispatcherFilesV4,
    target: &'a ManualCommittedTarget<'a>,
    approval: &'a HistoricalApproval,
}
impl LocalPrivateDurableFinancialConsentV1 for InitialFinancialInspectionV1<'_> {
    fn check_final_effect_restriction_v1(&self) -> bool {
        !crate::terminal::coordinated_restriction_required() || self.approval.check().is_ok()
    }
    fn permits_source(&self, scope: &wholepact_engine::PrivateWorkspaceScopeV1) -> bool {
        scope_matches(scope, self.files)
            && self.approval.check().is_ok()
            && check_admission_originals(self.host, self.files, self.target).is_ok()
            && self.approval.check().is_ok()
    }
}
pub(in crate::host) struct OriginalFinancialOwnerV2<'host> {
    coordinator: PrivateDurableFinancialCoordinatorV2<'host>,
    target: ManualCommittedTarget<'host>,
    host: &'host Host,
    files: &'host OriginalWorkspaceDispatcherFilesV4,
    directory: Directory,
    // Captured from the actual immutable Host journal owner before any dispatch
    // guard is borrowed. Final submission also checks its actual review identity.
    submission_identity: String,
    initial_metadata: wholepact_engine::PrivateDurableFinancialInspectionV2,
}
impl Host {
    pub(in crate::host) fn original_financial_owner_v2<'host>(
        &'host self,
        root: &Path,
    ) -> Result<OriginalFinancialOwnerV2<'host>> {
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
        let coordinator = PrivateDurableFinancialCoordinatorV2::open_original(
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
            coordinator.inspect_original_financial_v2(self.access()?, &privacy)?;
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
        Ok(OriginalFinancialOwnerV2 {
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
impl<'host> OriginalFinancialOwnerV2<'host> {
    /// Inert exact metadata inspected under the completed opening decision.
    /// Later operations require a new closed read/effect decision and live pins.
    pub(in crate::host) fn initial_inspection(
        &self,
    ) -> &wholepact_engine::PrivateDurableFinancialInspectionV2 {
        &self.initial_metadata
    }
    pub(in crate::host) fn coordinator(&self) -> &PrivateDurableFinancialCoordinatorV2<'host> {
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

fn transport_material_bounds_current_v1(bounds: [(u64, u64); 2], now: u64) -> bool {
    bounds.into_iter().all(|(from, until)| from <= now && now < until)
}
impl OriginalFinancialOwnerV2<'_> {
    fn check_transport_material_clocks_v1(&self) -> Result<()> {
        let materials = self.initial_metadata.materials();
        if materials.len() != 2 { return Err(Error::Authentication); }
        let bounds = [0, 1].map(|index| {
            let scope = materials[index].scope();
            (scope.valid_from_unix_seconds, scope.valid_until_unix_seconds)
        });
        if transport_material_bounds_current_v1(bounds, crate::now()?) { Ok(()) }
        else { Err(Error::Permission) }
    }
    /// Read-only authenticated reconciliation through the planned dispatcher.
    /// No mutation request, live admission, raw client or key escapes this method.
    pub(in crate::host) fn financial_history_v2(
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
        let current = || {
            self.check_read_source().map_err(|_| wholepact_authority::AuthorityError::Permission)?;
            approval.check().map_err(|_| wholepact_authority::AuthorityError::Permission)
        };
        let result = if crate::terminal::coordinated_restriction_required() {
            // Historical reconciliation has its own fresh read grant. It must
            // not acquire a new material-use policy or revive signing authority.
            let fast = || approval.check()
                .map_err(|_| wholepact_authority::AuthorityError::Permission);
            client.financial_continuation_history_v1_restricted_checked_until(
                continuation_operation, approval.deadline(), current, &fast)
        } else {
            client.financial_continuation_history_v1_checked_until(
                continuation_operation, approval.deadline(), current)
        };
        let history = result.map_err(|error| {
            #[cfg(all(test,feature="synthetic-born-joined-qualification",feature="durable-proposal"))]
            crate::host::financial_diagnostics_v1::authority_current(&error);
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


impl OriginalFinancialOwnerV2<'_> {
    pub(in crate::host) fn original_host_generation_binding(&self) -> Result<ManualHostGenerationBinding> {
        self.check_read_source()?;
        original_host_binding(self.host, &self.target, &self.files.original.workspace)
    }
    pub(in crate::host) fn original_destinations(&self) -> Result<Vec<OriginalDispatcherDestinationV2>> {
        self.check_read_source()?;
        let result = self.files.original.pending.destinations.iter().map(|d| OriginalDispatcherDestinationV2 {
            witness: d.witness.clone(), original_terms: d.original_terms.clone(), original_audit: d.original_audit.clone(),
            original_signer_roster_record_digest: d.original_signer_roster_record_digest.clone(),
        }).collect();
        self.check_read_source()?;
        Ok(result)
    }
}
