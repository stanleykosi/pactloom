//! Explicit transition from a short native selection to one bounded retained
//! contribution. No HistoricalApproval or CommittedRosterImportTarget is made
//! longer-lived. The new owner has its own reviewed original invocation bound.
use super::{CommittedRosterImportTarget, FreshRosterPreliminaryWalletV2, Host};
use crate::terminal::{Terminal, historical::HistoricalApproval};
use crate::{Error, Result, recovery_generation::manual_target::ManualCommittedTarget};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use wholepact_core::{
    manual_roster_candidate_selection_v2::ManualRosterCandidateSelectionScopeV2,
    manual_roster_construction_v2::ManualRosterContributionRetentionRequestV2,
    manual_roster_inventory_v2::ManualRosterInventoryScopeV2,
};
use wholepact_engine::manual_enrollment::ManualEnrollmentTarget;
use wholepact_signer::authority_bridge::manual_roster_candidate_selection_v2::SignerRetainedRosterContributionV2;
use wholepact_store::manual_enrollment::ManualRosterCandidateLocalExclusionsV2;

/// Prelaunch approval of a bounded retention PROCESS, not actual input claims.
/// Only the subsequent independent signer-native review can approve exact facts.
/// Not Clone/Deserialize. Capturing this requires a real terminal decision now;
/// it cannot be reconstructed from an old historical receipt or scope JSON.
pub(in crate::host) struct RosterContributionRetentionAdmissionV2 {
    scope: ManualRosterCandidateSelectionScopeV2,
    operation_id: String,
    admission_deadline: Instant,
    completion_deadline: Instant,
}
impl RosterContributionRetentionAdmissionV2 {
    pub(in crate::host) fn review_before_launch(
        terminal: &Terminal,
        prior: &HistoricalApproval,
        scope: &ManualRosterCandidateSelectionScopeV2,
        operation_id: String,
        original_invocation_deadline: Instant,
    ) -> Result<Self> {
        scope.validate().map_err(|_| Error::Invalid)?;
        crate::id(&operation_id)?;
        let invocation = &scope.selection.invocation;
        if operation_id == invocation.operation_id {
            return Err(Error::Invalid);
        }
        let completion_deadline = original_invocation_deadline.min(deadline_from_original_wall(
            invocation.requested_at_ms,
            invocation.construction_expires_at_ms,
        )?);
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:host-roster-retention-process-review:v2",
            &(scope, &operation_id, invocation.construction_expires_at_ms),
        )
        .map_err(|_| Error::Invalid)?;
        let approval = terminal.approve_publication_reviewed(prior, &digest, &format!(
            "Retain the ONE maintained contribution selected for these exact input-free economics ONLY IF the installed signer separately approves its actual inputs, nullifiers, values, source context and same-account return before the original selection cutoff.\nScope: {}\nRetention operation: {}\nOriginal completion expiry (epoch milliseconds): {}\nActual inputs do not yet exist and are not approved by this terminal review. Once the native durable receipt is acknowledged, the actual fresh wallet controller and private contribution may remain alive while other owners are reviewed sequentially, through this original invocation expiry only. Later separately approved attachments may append to the authenticated registry, but the original exact attachment prefix and actual wallet identities must remain unchanged. No reopened wallet, renewed selection deadline, proof, signature or dispatch is approved. A separate full-candidate terminal review and fresh native witness Reserve/Consume are still mandatory. Private data already disclosed cannot be recalled.",
            serde_json::to_string_pretty(scope)?, operation_id, invocation.construction_expires_at_ms,
        ))?;
        let admission_deadline = approval.deadline().min(completion_deadline);
        approval.commit(
            &digest,
            || prior.check(),
            |_| {
                Ok(Self {
                    scope: scope.clone(),
                    operation_id,
                    admission_deadline,
                    completion_deadline,
                })
            },
        )
    }
    pub(in crate::host) fn check_selection(
        &self,
        scope: &ManualRosterCandidateSelectionScopeV2,
    ) -> Result<()> {
        if scope != &self.scope || Instant::now() >= self.admission_deadline {
            return Err(Error::Permission);
        }
        require_original_wall(&self.scope)?;
        Ok(())
    }
    #[cfg(test)]
    pub(in crate::host) fn synthetic_operation_id(&self) -> &str {
        &self.operation_id
    }
    pub(super) fn operation_id(&self) -> &str {
        &self.operation_id
    }
    pub(in crate::host) fn admission_deadline(&self) -> Instant {
        self.admission_deadline
    }
    pub(super) fn completion_deadline(&self) -> Instant {
        self.completion_deadline
    }
    fn require_receipt(&self, retained: &SignerRetainedRosterContributionV2) -> Result<()> {
        retained.check_retained().map_err(|_| Error::Permission)?;
        let request = retained.request().map_err(|_| Error::Permission)?;
        self.check_selection(&request.selection.scope)?;
        if request.operation_id != self.operation_id {
            return Err(Error::Authentication);
        }
        Ok(())
    }
}

/// Actual generation/capsule and Store owners captured while the original
/// historical/import gates are still live AND explicit retention was reviewed.
/// Later checks verify only this fixed local provenance and current permissions.
/// They do not pretend the old terminal/native approval is still in force.
pub(super) struct RetainedRosterLocalOwnersV2<'host> {
    host: &'host Host,
    committed: ManualCommittedTarget<'host>,
    engine: ManualEnrollmentTarget<'host>,
    inventory_scope: ManualRosterInventoryScopeV2,
    completion_deadline: Instant,
}
impl<'host> RetainedRosterLocalOwnersV2<'host> {
    pub(super) fn capture(
        host: &'host Host,
        target: &CommittedRosterImportTarget<'_, '_>,
        inventory_scope: &ManualRosterInventoryScopeV2,
        admission: &RosterContributionRetentionAdmissionV2,
    ) -> Result<Self> {
        admission.check_selection(&admission.scope)?;
        target.require_current(host, inventory_scope)?;
        if inventory_scope.inventory != admission.scope.selection.inventory
            || inventory_scope.provenance != admission.scope.provenance
        {
            return Err(Error::Authentication);
        }
        let committed = ManualCommittedTarget::open(&host.directory, &host.secrets)?;
        let engine = host
            .engine
            .manual_enrollment_target(host.access()?, &inventory_scope.inventory.enrollment)?;
        let result = Self {
            host,
            committed,
            engine,
            inventory_scope: inventory_scope.clone(),
            completion_deadline: admission.completion_deadline,
        };
        result.check_current(host)?;
        target.require_current(host, inventory_scope)?;
        admission.check_selection(&admission.scope)?;
        Ok(result)
    }
    fn check_current(&self, host: &Host) -> Result<()> {
        if !std::ptr::eq(host, self.host) || Instant::now() >= self.completion_deadline {
            return Err(Error::Permission);
        }
        let access = host.access()?;
        let terms = &self.inventory_scope.inventory.enrollment;
        host.directory.check()?;
        host.authority
            .check_financial_principal_fail_fast(&access.principal_id)?;
        if access.principal_id != terms.scope.principal_id
            || !host.config.as_ref().is_some_and(|config| {
                config.clients.iter().any(|client| {
                    client.client_id == access.principal_id
                        && client
                            .permissions
                            .contains(&wholepact_service::security::Permission::Read)
                        && client
                            .permissions
                            .contains(&wholepact_service::security::Permission::Coordinate)
                        && client
                            .permissions
                            .contains(&wholepact_service::security::Permission::Disclose)
                })
            })
        {
            return Err(Error::Permission);
        }
        self.committed.check_current()?;
        self.committed.coverage().require_complete()?;
        self.engine.check_current_fail_fast(access)?;
        let financial_origin = host
            .financial
            .as_ref()
            .ok_or(Error::Locked)?
            .manual_original_primary_origin_digest(&host.directory, &host.secrets)?;
        let binding = &terms.host;
        if binding.generation_id != self.committed.generation_id()
            || binding.inventory_digest != self.committed.inventory_digest()
            || binding.generation_plan_digest != self.committed.plan_digest()
            || binding.profile_id != self.committed.profile_id()
            || binding.canonical_root != self.committed.canonical_root()
            || binding.destination_identity_digest != self.committed.destination_identity_digest()
            || binding.store_destination_identity != self.engine.store_destination_identity()
            || binding.financial_journal_origin_digest != financial_origin
            || binding.inherited_identity_digest != self.committed.coverage().digest()?
            || binding.scope_predecessor_digest.is_some()
        {
            return Err(Error::Authentication);
        }
        Ok(())
    }
}

/// Private handoff releases the mutable fresh-wallet borrow, so its exact
/// controller can subsequently be moved into the retained owner. There is no
/// public factory, raw contribution escape or serialization route.
pub(in crate::host) struct RetainedRosterInputHandoffV2<'host> {
    native: SignerRetainedRosterContributionV2,
    local: RetainedRosterLocalOwnersV2<'host>,
}
impl<'host> RetainedRosterInputHandoffV2<'host> {
    pub(super) fn finish(
        native: SignerRetainedRosterContributionV2,
        local: RetainedRosterLocalOwnersV2<'host>,
        admission: RosterContributionRetentionAdmissionV2,
    ) -> Result<Self> {
        admission.require_receipt(&native)?;
        local.check_current(local.host)?;
        Ok(Self { native, local })
    }
    pub(in crate::host) fn attach_original_source(
        self,
        fresh: FreshRosterPreliminaryWalletV2,
        exclusions: ManualRosterCandidateLocalExclusionsV2<'host>,
    ) -> Result<RetainedRosterCandidateInputsV2<'host>> {
        let result = RetainedRosterCandidateInputsV2 {
            native: self.native,
            local: self.local,
            fresh,
            exclusions,
        };
        result.check_current(result.local.host)?;
        Ok(result)
    }
}

/// No lifetimes refer to old native clients, historical approvals or original
/// CommittedRosterImportTarget. The real wallet controller remains owned here,
/// so the lower protected selection's weak source-generation guard stays valid.
pub(in crate::host) struct RetainedRosterCandidateInputsV2<'host> {
    native: SignerRetainedRosterContributionV2,
    local: RetainedRosterLocalOwnersV2<'host>,
    fresh: FreshRosterPreliminaryWalletV2,
    exclusions: ManualRosterCandidateLocalExclusionsV2<'host>,
}
impl RetainedRosterCandidateInputsV2<'_> {
    /// Restriction for the new live common-context producer only. Historical
    /// uniform V1 records remain readable, but cannot enter this new invocation.
    pub(in crate::host) fn require_original_retention_scope_v2(&self, host: &Host) -> Result<()> {
        self.request(host)?
            .selection
            .scope
            .selection
            .require_original_retention_scope()
            .map_err(|_| Error::Permission)?;
        self.check_current(host)
    }
    pub(super) fn check_current(&self, host: &Host) -> Result<()> {
        self.local.check_current(host)?;
        self.native
            .check_retained()
            .map_err(|_| Error::Permission)?;
        let request = self.native.request().map_err(|_| Error::Permission)?;
        require_original_wall(&request.selection.scope)?;
        if request.selection.scope.selection.inventory != self.local.inventory_scope.inventory
            || request.selection.scope.provenance != self.local.inventory_scope.provenance
        {
            return Err(Error::Authentication);
        }
        self.fresh
            .check_current_attachment(host, &self.local.inventory_scope, true)?;
        let exclusions = host
            .engine
            .manual_roster_retained_current_exclusions_v2_fail_fast(
                host.access()?,
                request,
                &self.exclusions,
            )?;
        if exclusions.snapshot_digest()? != request.local_exclusion_digest
            || request
                .selected_inputs
                .iter()
                .any(|input| exclusions.excludes(&input.input_id, &input.nullifier))
        {
            return Err(Error::Permission);
        }
        self.local.engine.require_current_agreement_fail_fast(
            host.access()?,
            &request.selection.scope.selection.economic_intent.agreement,
        )?;
        self.native.check_retained().map_err(|_| Error::Permission)
    }
    pub(super) fn request(
        &self,
        host: &Host,
    ) -> Result<&ManualRosterContributionRetentionRequestV2> {
        self.check_current(host)?;
        self.native.request().map_err(|_| Error::Permission)
    }
    pub(super) fn original_completion_deadline(&self) -> Instant {
        self.local.completion_deadline
    }
    pub(super) fn require_external_destination(
        &self,
        host: &Host,
        path: &std::path::Path,
    ) -> Result<()> {
        self.check_current(host)?;
        host.directory.external_destination(path)?;
        let actual = self.fresh.wallet.manual_attachment_descriptor(
            &host.secrets.profile(),
            &self
                .local
                .inventory_scope
                .inventory
                .enrollment
                .identity
                .account_id,
        )?;
        if path.starts_with(&actual.canonical_directory) {
            return Err(Error::Permission);
        }
        Ok(())
    }
    pub(super) fn retention_evidence_digest(&self, host: &Host) -> Result<String> {
        self.check_current(host)?;
        self.native
            .evidence()
            .map_err(|_| Error::Permission)?
            .digest()
            .map_err(|_| Error::Invalid)
    }
}

/// Source-only owner retained alongside Engine's actual native completion and
/// wallet-observation guards through durable claim, randomness and checkpoint.
pub(super) struct RetainedRosterConstructionSourceV2<'host> {
    local: RetainedRosterLocalOwnersV2<'host>,
    fresh: FreshRosterPreliminaryWalletV2,
    exclusions: ManualRosterCandidateLocalExclusionsV2<'host>,
    retained: ManualRosterContributionRetentionRequestV2,
}
impl RetainedRosterConstructionSourceV2<'_> {
    pub(super) fn check_current(&self, host: &Host) -> Result<()> {
        self.local.check_current(host)?;
        require_original_wall(&self.retained.selection.scope)?;
        self.fresh
            .check_current_attachment(host, &self.local.inventory_scope, true)?;
        let exclusions = host
            .engine
            .manual_roster_retained_current_exclusions_v2_fail_fast(
                host.access()?,
                &self.retained,
                &self.exclusions,
            )?;
        if exclusions.snapshot_digest()? != self.retained.local_exclusion_digest
            || self
                .retained
                .selected_inputs
                .iter()
                .any(|i| exclusions.excludes(&i.input_id, &i.nullifier))
        {
            return Err(Error::Permission);
        }
        self.local.engine.require_current_agreement_fail_fast(
            host.access()?,
            &self
                .retained
                .selection
                .scope
                .selection
                .economic_intent
                .agreement,
        )?;
        Ok(())
    }
}
impl<'host> RetainedRosterCandidateInputsV2<'host> {
    pub(super) fn into_construction_parts(
        self,
        host: &Host,
    ) -> Result<(
        SignerRetainedRosterContributionV2,
        RetainedRosterConstructionSourceV2<'host>,
    )> {
        self.check_current(host)?;
        let retained = self
            .native
            .request()
            .map_err(|_| Error::Permission)?
            .clone();
        let source = RetainedRosterConstructionSourceV2 {
            local: self.local,
            fresh: self.fresh,
            exclusions: self.exclusions,
            retained,
        };
        source.check_current(host)?;
        Ok((self.native, source))
    }
}

use crate::authority::manual_roster_exact_input_observation_v1::{
    HostAdmittedRosterExactInputObservationV1, RosterExactInputCompletionV1,
};
use wholepact_wallet::wallet::protected_sync::{
    BackendIdentity, LocalWalletAccess, ProtectedWalletSync, WalletAccessPurpose,
    exact_input_observation::{
        ExactInputRestriction, ExactInputVerifierSnapshot, ExactObservationError,
        FreshExactInputObservation,
    },
};

impl RetainedRosterCandidateInputsV2<'_> {
    pub(super) fn native_retained(
        &self,
        host: &Host,
    ) -> Result<&SignerRetainedRosterContributionV2> {
        self.check_current(host)?;
        Ok(&self.native)
    }
}

/// Verifies only original import/file/registry and current Store/Host facts.
/// It deliberately cannot borrow sync, so neither proof consent nor a held
/// wallet guard can reenter a wallet database or acquire a new wallet lock.
pub(super) struct RetainedRosterSourceCheckV2<'a, 'host> {
    local: &'a RetainedRosterLocalOwnersV2<'host>,
    fresh: super::FreshRosterProvenanceV2<'a>,
    exclusions: &'a ManualRosterCandidateLocalExclusionsV2<'host>,
    retained: &'a ManualRosterContributionRetentionRequestV2,
    completion: &'a RosterExactInputCompletionV1,
}
impl RetainedRosterSourceCheckV2<'_, '_> {
    pub(super) fn check(&self, account: wholepact_wallet::wallet::AccountUuid) -> Result<()> {
        let host = self.local.host;
        self.local.check_current(host)?;
        self.completion.check()?;
        require_original_wall(&self.retained.selection.scope)?;
        self.fresh
            .check_current(host, &self.local.inventory_scope, account)?;
        let exclusions = host
            .engine
            .manual_roster_retained_current_exclusions_v2_fail_fast(
                host.access()?,
                self.retained,
                self.exclusions,
            )?;
        if exclusions.snapshot_digest()? != self.retained.local_exclusion_digest
            || self
                .retained
                .selected_inputs
                .iter()
                .any(|i| exclusions.excludes(&i.input_id, &i.nullifier))
        {
            return Err(Error::Permission);
        }
        self.local.engine.require_current_agreement_fail_fast(
            host.access()?,
            &self
                .retained
                .selection
                .scope
                .selection
                .economic_intent
                .agreement,
        )?;
        self.completion.check()
    }
    pub(super) fn check_original_account(&self) -> Result<()> {
        self.check(self.fresh.import.account_uuid())
    }
}
impl ExactInputRestriction for RetainedRosterSourceCheckV2<'_, '_> {
    fn check_current(
        &self,
        account: wholepact_wallet::wallet::AccountUuid,
    ) -> std::result::Result<(), ExactObservationError> {
        self.check(account)
            .map_err(|_| ExactObservationError::Permission)
    }
}
impl LocalWalletAccess for RetainedRosterSourceCheckV2<'_, '_> {
    fn permits(
        &self,
        account: wholepact_wallet::wallet::AccountUuid,
        provider: &BackendIdentity,
        purpose: WalletAccessPurpose,
    ) -> bool {
        let expected = &self.local.inventory_scope.inventory.provider;
        matches!(purpose, WalletAccessPurpose::SynchronizePublicBlocks)
            && provider.source_id == expected.source_id
            && provider.endpoint == expected.endpoint
            && provider.trust_profile == expected.trust_profile
            && self.check(account).is_ok()
    }
}

pub(in crate::host) struct RefreshedRosterSourceV2<'host> {
    source: RetainedRosterConstructionSourceV2<'host>,
    completion: RosterExactInputCompletionV1,
}
impl<'host> RefreshedRosterSourceV2<'host> {
    pub(super) fn split(
        &mut self,
    ) -> (
        &mut ProtectedWalletSync,
        RetainedRosterSourceCheckV2<'_, 'host>,
    ) {
        let (sync, fresh) = self.source.fresh.exact_input_parts();
        (
            sync,
            RetainedRosterSourceCheckV2 {
                local: &self.source.local,
                fresh,
                exclusions: &self.source.exclusions,
                retained: &self.source.retained,
                completion: &self.completion,
            },
        )
    }
}
impl<'host> RetainedRosterCandidateInputsV2<'host> {
    pub(super) async fn refresh_exact_inputs(
        self,
        host: &Host,
        admission: HostAdmittedRosterExactInputObservationV1,
    ) -> Result<(
        SignerRetainedRosterContributionV2,
        RefreshedRosterSourceV2<'host>,
        FreshExactInputObservation,
        ExactInputVerifierSnapshot,
    )> {
        self.check_current(host)?;
        let (admitted, completion) = admission.into_parts()?;
        if admitted
            .request()
            .map_err(|_| Error::Permission)?
            .plan
            .retained
            != *self.native.request().map_err(|_| Error::Permission)?
        {
            return Err(Error::Authentication);
        }
        let (mut native, source) = self.into_construction_parts(host)?;
        let mut source = RefreshedRosterSourceV2 { source, completion };
        let fresh = {
            let (sync, check) = source.split();
            check.check_original_account()?;
            native
                .observe_exact_inputs(sync, admitted, &check)
                .await
                .map_err(Error::from)?
        };
        let snapshot = native
            .exact_verifier_snapshot(&fresh)
            .map_err(|_| Error::Permission)?;
        Ok((native, source, fresh, snapshot))
    }
}

fn require_original_wall(scope: &ManualRosterCandidateSelectionScopeV2) -> Result<()> {
    let invocation = &scope.selection.invocation;
    require_window(
        now_ms()?,
        invocation.requested_at_ms,
        invocation.construction_expires_at_ms,
    )
}
fn require_window(now: u64, start: u64, end: u64) -> Result<()> {
    if start == 0 || now < start || now >= end {
        return Err(Error::Permission);
    }
    Ok(())
}
fn deadline_from_original_wall(start: u64, end: u64) -> Result<Instant> {
    let captured = Instant::now();
    let now = now_ms()?;
    require_window(now, start, end)?;
    captured
        .checked_add(Duration::from_millis(
            end.checked_sub(now).ok_or(Error::Invalid)?,
        ))
        .ok_or(Error::Invalid)
}
pub(super) fn now_ms() -> Result<u64> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Permission)?
            .as_millis(),
    )
    .map_err(|_| Error::Invalid)
}
// Common-context transition preserves the actual original local source while
// moving its native owner into exactly one new read. No archived record factory.
pub(in crate::host) struct PendingHostCommonContextReadV1<'client, 'host> {
    native: wholepact_signer::authority_bridge::manual_roster_candidate_selection_v2::PendingSignerCommonContextReadV1<'client>,
    source: RetainedRosterConstructionSourceV2<'host>,
    admission: crate::authority::manual_roster_common_context_read_v1::RosterCommonContextReadAdmissionV1,
}
impl<'host> RetainedRosterCandidateInputsV2<'host> {
    pub(in crate::host) fn begin_common_context_read<'client>(
        self,
        host: &Host,
        client: &'client wholepact_signer_origin::NativeManualClient,
        admission: crate::authority::manual_roster_common_context_read_v1::RosterCommonContextReadAdmissionV1,
        attempt_digest: &str,
        attempt_sequence: u64,
    ) -> Result<PendingHostCommonContextReadV1<'client, 'host>> {
        self.check_current(host)?;
        let request = admission.request(
            client
                .current_caller_binding_digest()
                .map_err(|_| Error::Permission)?,
            {
                let now = now_ms()?;
                #[cfg(all(test, feature = "synthetic-born-joined-qualification"))]
                crate::host::synthetic_roster_timing_v1::event("ObservedReadRequest", true, false);
                now
            },
        );
        #[cfg(all(test, feature = "synthetic-born-joined-qualification"))]
        crate::host::synthetic_roster_timing_v1::event("ObservedReadRequest", false, request.is_err());
        let request = request?;
        let original_deadline = self.original_completion_deadline();
        if request.plan.retained != *self.request(host)? {
            return Err(Error::Authentication);
        }
        let (native, source) = self.into_construction_parts(host)?;
        let pending = native
            .begin_common_context_read_before(
                client,
                &request,
                attempt_digest,
                attempt_sequence,
                admission.deadline(),
                original_deadline,
            )
            .map_err(|_| Error::Permission)?;
        Ok(PendingHostCommonContextReadV1 {
            native: pending,
            source,
            admission,
        })
    }
}
impl<'host> PendingHostCommonContextReadV1<'_, 'host> {
    pub(in crate::host) fn finish(
        self,
        host: &Host,
    ) -> Result<ReadyHostCommonContextReadV1<'host>> {
        self.source.check_current(host)?;
        let (native, read) = self.native.finish().map_err(|_| Error::Permission)?;
        #[cfg(all(test, feature = "synthetic-born-joined-qualification"))]
        crate::host::synthetic_roster_timing_v1::event("ObservedReadAdmitted", true, false);
        let read = self.admission.finish(read);
        #[cfg(all(test, feature = "synthetic-born-joined-qualification"))]
        crate::host::synthetic_roster_timing_v1::event("ObservedReadAdmitted", false, read.is_err());
        let read = read?;
        let (read, completion) = read.into_parts()?;
        self.source.check_current(host)?;
        Ok(ReadyHostCommonContextReadV1 {
            native,
            source: RefreshedRosterSourceV2 {
                source: self.source,
                completion,
            },
            read,
        })
    }
}
pub(in crate::host) struct ReadyHostCommonContextReadV1<'host> {
    native: wholepact_signer::authority_bridge::manual_roster_candidate_selection_v2::SignerRetainedCommonContextContributionV3,
    source: RefreshedRosterSourceV2<'host>,
    read: wholepact_signer_origin::AdmittedRosterCommonContextReadV1,
}
pub(in crate::host) type ObservedHostCommonContextV3<'host> = (
    wholepact_signer::authority_bridge::manual_roster_candidate_selection_v2::SignerRetainedCommonContextContributionV3,
    RefreshedRosterSourceV2<'host>,
    wholepact_wallet::wallet::protected_sync::exact_input_observation::FreshCommonContextObservation,
    wholepact_wallet::wallet::protected_sync::exact_input_observation::CommonContextVerifierSnapshot,
);
impl<'host> ReadyHostCommonContextReadV1<'host> {
    pub(in crate::host) async fn observe(
        self,
        host: &Host,
    ) -> Result<ObservedHostCommonContextV3<'host>> {
        let Self {
            mut native,
            mut source,
            read,
        } = self;
        source.source.check_current(host)?;
        let observation = {
            let (sync, check) = source.split();
            check.check_original_account()?;
            native
                .observe_common_context(sync, read, &check)
                .await
                .map_err(Error::from)?
        };
        let snapshot = native
            .common_context_verifier_snapshot(&observation)
            .map_err(|_| Error::Permission)?;
        source.source.check_current(host)?;
        observation.check_current().map_err(Error::from)?;
        Ok((native, source, observation, snapshot))
    }
}

/// Separate foreground authorization is completed before the one maintained
/// observation. This owner cannot authorize a witness grant or construction.
pub(in crate::host) struct AuthorizedHostCommonContextReadV1<'host> {
    ready: ReadyHostCommonContextReadV1<'host>,
    authorization: wholepact_signer_origin::NativeCommonContextHandoffAuthorizationV1,
}
impl<'host> ReadyHostCommonContextReadV1<'host> {
    /// Derive inert request material from this actual admitted read. No caller
    /// may supply a replacement read digest or caller identity.
    pub(in crate::host) fn handoff_request(
        &self,
        client: &wholepact_signer_origin::NativeManualClient,
        operation_id: String,
    ) -> Result<wholepact_signer_origin::common_context_handoff_v1::RosterCommonContextHandoffAuthorizationRequestV1>{
        self.read
            .check_completion()
            .map_err(|_| Error::Permission)?;
        let request = wholepact_signer_origin::common_context_handoff_v1::RosterCommonContextHandoffAuthorizationRequestV1 {
            version: 1,
            operation_id,
            original_read_admission_digest: self.read.evidence().digest().map_err(|_| Error::Authentication)?,
            current_caller_binding_digest: client.current_caller_binding_digest().map_err(|_| Error::Permission)?,
        };
        request.validate().map_err(|_| Error::Invalid)?;
        Ok(request)
    }
    pub(in crate::host) fn authorize_handoff_before(
        self,
        client: &wholepact_signer_origin::NativeManualClient,
        request: &wholepact_signer_origin::common_context_handoff_v1::RosterCommonContextHandoffAuthorizationRequestV1,
        deadline: std::time::Instant,
    ) -> Result<AuthorizedHostCommonContextReadV1<'host>> {
        let authorization = client
            .begin_roster_common_context_handoff_authorization_before(&self.read, request, deadline)
            .map_err(|_| Error::Permission)?
            .finish()
            .map_err(|_| Error::Permission)?;
        Ok(AuthorizedHostCommonContextReadV1 {
            ready: self,
            authorization,
        })
    }
}
/// One actual read, exact installed-peer authorization and erased old pairing.
/// All participants must be collected into the private roster barrier before
/// any grant request can be obtained from these owners.
pub(in crate::host) struct ObservedHandoffCommonContextV1<'host> {
    pub(super) observed: ObservedHostCommonContextV3<'host>,
    pub(super) authorization: wholepact_signer::authority_bridge::manual_roster_candidate_selection_v2::SignerObservedCommonContextHandoffV1,
    pub(super) reentry: Option<wholepact_signer_origin::CommonContextReentrySourceV1>,
}
impl<'host> AuthorizedHostCommonContextReadV1<'host> {
    pub(in crate::host) async fn observe(
        self,
        host: &Host,
        client: wholepact_signer_origin::NativeManualClient,
    ) -> Result<ObservedHandoffCommonContextV1<'host>> {
        let observed = self.ready.observe(host).await?;
        let authorization = wholepact_signer::authority_bridge::manual_roster_candidate_selection_v2::SignerObservedCommonContextHandoffV1::from_observed_read(self.authorization, &observed.2)
            .map_err(|_| Error::Authentication)?;
        let reentry = client
            .into_common_context_reentry_source(observed.2.native_read())
            .map_err(|_| Error::Permission)?;
        observed.2.check_current()?;
        Ok(ObservedHandoffCommonContextV1 {
            observed,
            authorization,
            reentry: Some(reentry),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retention_never_restarts_or_renews_original_wall_window() {
        assert!(require_window(10, 10, 20).is_ok());
        assert!(require_window(19, 10, 20).is_ok());
        for (now, start, end) in [(9, 10, 20), (20, 10, 20), (10, 0, 20), (10, 20, 10)] {
            assert!(require_window(now, start, end).is_err());
        }
    }
}
