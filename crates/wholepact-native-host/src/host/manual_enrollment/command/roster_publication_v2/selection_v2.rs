//! Optional separately reviewed post-inventory input selection in the SAME
//! installed signer process. All prompts and approvals finish before launch.
//! No parsed data, viewing lease or selected input becomes construction consent.
use super::*;
use crate::{
    authority::manual_roster_candidate_selection_v2::RosterCandidateSelectionAdmissionV2,
    host::financial::manual_roster_inventory_setup_v2::{
        FreshRosterPreliminaryWalletV2, RetainedRosterCandidateInputsV2,
        RosterContributionRetentionAdmissionV2,
    },
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use wholepact_core::{
    born_policy_origin_v2::BornRecipientPolicyOriginV2,
    manual_candidate_selection::{
        ManualCandidateEconomicIntent, ManualCandidateInvocation, ManualCandidateSelectionScope,
    },
    manual_inventory::MAX_PRELIMINARY_DISCLOSURE_MS,
    manual_roster_candidate_selection_v2::{
        ManualRosterCandidateSelectionRequestV2, ManualRosterCandidateSelectionScopeV2,
    },
    manual_roster_inventory_v2::{ManualRosterInventoryScopeV2, OriginalHostRosterAuditV3},
};
use wholepact_signer::authority_bridge::manual_roster_candidate_selection_v2::SignerRosterCandidateSelectionLeaseV2;

/// Input-free user choices only. Enrollment, wallet/provider inventory, V3/V4
/// provenance, caller binding and native approvals come from actual owners.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectionInput {
    operation_id: String,
    original_policy_origin: BornRecipientPolicyOriginV2,
    economic_intent: ManualCandidateEconomicIntent,
    invocation: ManualCandidateInvocation,
}

pub(super) struct PreparedSelection {
    inventory_scope: ManualRosterInventoryScopeV2,
    scope: ManualRosterCandidateSelectionScopeV2,
    operation_id: String,
    admission: RosterCandidateSelectionAdmissionV2,
    pair_approval: PublicationApproval,
    request_approval: PublicationApproval,
    review_digest: String,
    audit_review_digest: String,
    invocation_deadline: Instant,
    retention: Option<RosterContributionRetentionAdmissionV2>,
}

pub(super) fn prepare(
    host: &Host,
    audit: &PreparedRosterPublication<'_>,
    inventory: &ManualRosterInventoryScopeV2,
    retain: bool,
) -> Result<PreparedSelection> {
    require_prepared_inventory(host, audit, inventory)?;
    let selected: SelectionInput = host.read_manual_private(
        "Exact private input-free candidate selection JSON file: ",
        "reviewing exact candidate economics, complete original V2 policy-origin evidence and one fixed invocation; the file contains no selected inputs or authority",
    )?;
    id(&selected.operation_id)?;
    if selected.operation_id == selected.invocation.operation_id {
        return Err(Error::Invalid);
    }
    let scope = ManualRosterCandidateSelectionScopeV2 {
        version: 2,
        selection: ManualCandidateSelectionScope {
            version: 1,
            // The actual earlier prepared scope is wrapped without accepting
            // enrollment, attachment or roster substitution from this file.
            inventory: inventory.inventory.clone(),
            original_policy_origin: selected.original_policy_origin,
            economic_intent: selected.economic_intent,
            invocation: selected.invocation,
            purpose: "prepare_one_private_contribution".into(),
        },
        provenance: inventory.provenance.clone(),
    };
    require_exact_wrapper(&scope, inventory)?;
    // Capture the original wall-clock budget once, before further approvals.
    // Time spent reviewing, launching, publishing and scanning consumes it.
    let captured = Instant::now();
    let now = now_ms()?;
    let invocation = &scope.selection.invocation;
    let remaining = remaining_invocation_ms(
        now,
        invocation.requested_at_ms,
        invocation.construction_expires_at_ms,
    )?;
    let invocation_deadline = captured
        .checked_add(Duration::from_millis(remaining))
        .ok_or(Error::Invalid)?;
    require_prepared_inventory(host, audit, inventory)?;
    let admission = RosterCandidateSelectionAdmissionV2::review(
        &host.terminal,
        &audit.original.source.history_review,
        &scope,
    )?;
    let review_digest =
        selection_review_digest(&scope, &selected.operation_id, &audit.review_digest)?;
    let pair_approval = host.terminal.approve_publication_reviewed(
        &audit.original.source.history_review,
        &review_digest,
        &format!(
            "After the exact reviewed audit and preliminary wallet import/scan, send one DISTINCT candidate-selection pairing to the SAME actual installed signer process.\nSelection operation: {}\nExact selection scope commitment: {}\nAudit review commitment: {}\nThe preliminary viewing lease must be dropped first. Its grant and purpose do not authorize selection. The new signer-native review independently checks the original V2 policy, retained continuation and exact economics. All terminal prompts end before signer launch; no process reload, new deadline or construction grant follows.",
            selected.operation_id,
            scope.pairing_digest().map_err(|_| Error::Invalid)?,
            audit.review_digest,
        ),
    )?;
    let request_approval = host.terminal.approve_publication_reviewed(
        &audit.original.source.history_review,
        &review_digest,
        &format!(
            "After that separate same-process pairing, send ONE candidate-selection request for this complete input-free scope:\n{}\nSelection operation: {}\nThe caller binding comes only from the actual new native grant. Start is the send-time clock; disclosure ends at the earlier of 30,000 milliseconds later and the ORIGINAL invocation ceiling. All earlier Host, native and process deadlines still apply. The original signer-intent commitment comes only from the exact committed audit owner.\nThe installed signer separately reviews FVK disclosure and one local selection. Before selection the Host reads current conservative exclusions from the actual Store under the actual lower lease, then rechecks every chosen input/nullifier. Only the exact already-scanned fresh wallet is used; selection cannot refresh the provider. The private result display may reveal this account's actual input identifiers, nullifiers, values and authenticated same-account return. Those displayed fields cannot be recalled. This is incomplete single-provider/local evidence, not independently established unspentness, complete history, a full candidate, reserved funds, construction, proof, signature or dispatch. Stay in the signer window through bounded selection and guarded display; no further terminal prompts occur.",
            serde_json::to_string_pretty(&scope)?,
            selected.operation_id,
        ),
    )?;
    let retention = if retain {
        let operation_id = host
            .terminal
            .ask("Exact distinct native retention operation ID: ")?;
        if operation_id.as_str() == selected.operation_id {
            return Err(Error::Invalid);
        }
        Some(
            RosterContributionRetentionAdmissionV2::review_before_launch(
                &host.terminal,
                &audit.original.source.history_review,
                &scope,
                operation_id.to_string(),
                invocation_deadline,
            )?,
        )
    } else {
        None
    };
    let result = PreparedSelection {
        inventory_scope: inventory.clone(),
        scope,
        operation_id: selected.operation_id,
        admission,
        pair_approval,
        request_approval,
        review_digest,
        audit_review_digest: audit.review_digest.clone(),
        invocation_deadline,
        retention,
    };
    result.check_before(audit)?;
    Ok(result)
}

fn require_exact_wrapper(
    scope: &ManualRosterCandidateSelectionScopeV2,
    inventory: &ManualRosterInventoryScopeV2,
) -> Result<()> {
    scope.validate().map_err(|_| Error::Invalid)?;
    inventory.validate().map_err(|_| Error::Invalid)?;
    if scope.selection.inventory != inventory.inventory || scope.provenance != inventory.provenance
    {
        return Err(Error::Authentication);
    }
    Ok(())
}

fn require_prepared_inventory(
    host: &Host,
    audit: &PreparedRosterPublication<'_>,
    inventory: &ManualRosterInventoryScopeV2,
) -> Result<()> {
    audit.check_before()?;
    inventory.validate().map_err(|_| Error::Invalid)?;
    let ManualRosterPublicationAttemptV2::ContinuationV2 {
        continuation_digest,
        attempt_sequence,
    } = &audit.request.attempt
    else {
        return Err(Error::Permission);
    };
    let original = audit.prior_digest.as_ref().ok_or(Error::Permission)?;
    let s = &inventory.inventory;
    let p = &inventory.provenance;
    if !std::ptr::eq(host, audit.original.source.host)
        || audit.purpose != RosterAuditPurpose::ExistingOriginalContinuationV4
        || s.enrollment != audit.request.enrollment.terms
        || s.enrollment != *audit.original.source.engine.terms()
        || s.enrollment_ref != audit.extension.account_extension.enrollment_ref
        || s.witness_extension_digest
            != audit
                .extension
                .account_extension
                .digest()
                .map_err(|_| Error::Invalid)?
        || s.attempt.continuation_digest != *continuation_digest
        || s.attempt.attempt_sequence != *attempt_sequence
        || p.original_host_audit
            != (OriginalHostRosterAuditV3::AdditionalPublicationV3 {
                audit_digest: original.clone(),
            })
        || p.roster != audit.extension.roster
        || p.signer_roster_record_digest != audit.extension.signer_roster_record_digest
        || p.witness_roster_extension_digest
            != audit.extension.digest().map_err(|_| Error::Invalid)?
    {
        return Err(Error::Authentication);
    }
    audit.check_before()
}

fn selection_review_digest(
    scope: &ManualRosterCandidateSelectionScopeV2,
    operation: &str,
    audit_review: &str,
) -> Result<String> {
    wholepact_core::proposal::canonical_digest(
        "wholepact:native-host-roster-candidate-selection-review:v2",
        &(
            scope,
            operation,
            audit_review,
            MAX_PRELIMINARY_DISCLOSURE_MS,
            "actual-new-native-grant-send-clock-and-original-invocation-only",
        ),
    )
    .map_err(|_| Error::Invalid)
}
fn now_ms() -> Result<u64> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Permission)?
            .as_millis(),
    )
    .map_err(|_| Error::Invalid)
}
fn remaining_invocation_ms(now: u64, start: u64, end: u64) -> Result<u64> {
    if start == 0 || now < start || now >= end {
        return Err(Error::Permission);
    }
    end.checked_sub(now).ok_or(Error::Invalid)
}
fn disclosure_expiry(now: u64, start: u64, original_end: u64) -> Result<u64> {
    remaining_invocation_ms(now, start, original_end)?;
    Ok(now
        .checked_add(MAX_PRELIMINARY_DISCLOSURE_MS)
        .ok_or(Error::Invalid)?
        .min(original_end))
}
fn check_clock(scope: &ManualRosterCandidateSelectionScopeV2, deadline: Instant) -> Result<u64> {
    if Instant::now() >= deadline {
        return Err(Error::Permission);
    }
    let now = now_ms()?;
    let i = &scope.selection.invocation;
    remaining_invocation_ms(now, i.requested_at_ms, i.construction_expires_at_ms)?;
    Ok(now)
}

impl PreparedSelection {
    pub(super) fn deadline(&self) -> Instant {
        self.invocation_deadline
            .min(self.admission.deadline())
            .min(self.pair_approval.deadline())
            .min(self.request_approval.deadline())
            .min(
                self.retention
                    .as_ref()
                    .map_or(self.invocation_deadline, |r| r.admission_deadline()),
            )
    }
    pub(super) fn check_before(&self, audit: &PreparedRosterPublication<'_>) -> Result<()> {
        require_prepared_inventory(audit.original.source.host, audit, &self.inventory_scope)?;
        require_exact_wrapper(&self.scope, &self.inventory_scope)?;
        if self.audit_review_digest != audit.review_digest
            || self.review_digest
                != selection_review_digest(
                    &self.scope,
                    &self.operation_id,
                    &self.audit_review_digest,
                )?
        {
            return Err(Error::Authentication);
        }
        self.admission.require_scope(&self.scope)?;
        if let Some(retention) = &self.retention {
            retention.check_selection(&self.scope)?;
        }
        self.pair_approval.check()?;
        self.request_approval.check()?;
        check_clock(&self.scope, self.deadline())?;
        Ok(())
    }

    pub(super) fn run<'host>(
        self,
        host: &'host Host,
        client: NativeManualClient,
        audit: &CommittedRosterAudit<'_>,
        mut fresh: FreshRosterPreliminaryWalletV2,
        target: &CommittedRosterImportTarget<'_, '_>,
    ) -> Result<Option<RetainedRosterCandidateInputsV2<'host>>> {
        let deadline = self.deadline().min(audit.deadline);
        let Self {
            inventory_scope,
            scope,
            operation_id,
            admission,
            pair_approval,
            request_approval,
            review_digest,
            audit_review_digest,
            invocation_deadline: _,
            retention,
        } = self;
        require_exact_wrapper(&scope, &inventory_scope)?;
        if audit_review_digest != audit.review_digest
            || review_digest
                != selection_review_digest(&scope, &operation_id, &audit_review_digest)?
        {
            return Err(Error::Authentication);
        }
        audit.check_current()?;
        target.require_current(host, &inventory_scope)?;
        fresh.check_current(host, &inventory_scope, target)?;
        admission.require_scope(&scope)?;
        request_approval.check()?;
        check_clock(&scope, deadline)?;
        // The parent dropped the preliminary read/lease before handing over
        // this exact client. The lower pairing rejects any occupied lease slot.
        let pending = pair_approval.commit(
            &review_digest,
            || {
                audit.check_current()?;
                admission.require_scope(&scope)?;
                check_clock(&scope, deadline)?;
                fresh.check_current(host, &inventory_scope, target)
            },
            |_| {
                client
                    .begin_roster_candidate_selection_pair_before(
                        "wholepact-native-roster-candidate-selection-v2",
                        &scope,
                        deadline,
                    )
                    .map_err(|_| Error::Permission)
            },
        )?;
        let client = pending.finish().map_err(|_| Error::Permission)?;
        let pending = request_approval.commit(
            &review_digest,
            || {
                audit.check_current()?;
                admission.require_scope(&scope)?;
                check_clock(&scope, deadline)?;
                fresh.check_current(host, &inventory_scope, target)
            },
            |_| {
                // Derive both fields inside the approved send action, after
                // actual separate pairing; saved JSON never supplies either.
                let current_caller_binding_digest = client
                    .current_caller_binding_digest()
                    .map_err(|_| Error::Permission)?;
                let requested_at_ms = check_clock(&scope, deadline)?;
                let invocation = &scope.selection.invocation;
                let request = ManualRosterCandidateSelectionRequestV2 {
                    version: 2,
                    operation_id,
                    scope: scope.clone(),
                    current_caller_binding_digest,
                    requested_at_ms,
                    disclosure_expires_at_ms: disclosure_expiry(
                        requested_at_ms,
                        invocation.requested_at_ms,
                        invocation.construction_expires_at_ms,
                    )?,
                };
                request.validate().map_err(|_| Error::Invalid)?;
                client
                    .begin_roster_candidate_selection_before(
                        &request,
                        &audit.original_signer_intent_digest,
                        deadline,
                    )
                    .map_err(|_| Error::Permission)
            },
        )?;
        let lower = pending.finish().map_err(|_| Error::Permission)?;
        audit.check_current()?;
        lower.check_current().map_err(|_| Error::Permission)?;
        admission.require_scope(&scope)?;
        fresh.check_current(host, &inventory_scope, target)?;
        check_clock(&scope, deadline)?;
        // This query requires the real lower owner, before moving it into the
        // maintained signer bridge. The snapshot borrows the actual Store,
        // never JSON, a boolean, an empty-default list or the earlier inventory.
        let local_exclusions = host
            .engine
            .manual_roster_candidate_local_exclusions_v2(host.access()?, &lower)?;
        let lease = SignerRosterCandidateSelectionLeaseV2::from_native_lease(lower)
            .map_err(|_| Error::Permission)?;
        audit.check_current()?;
        lease.check_current().map_err(|_| Error::Permission)?;
        admission.require_scope(&scope)?;
        fresh.check_current(host, &inventory_scope, target)?;
        check_clock(&scope, deadline)?;
        let selected = host.select_manual_roster_candidate_inputs_v2(
            &mut fresh,
            admission,
            &lease,
            target,
            &local_exclusions,
        )?;
        audit.check_current()?;
        selected.display_current_evidence(&lease)?;
        if let Some(retention) = retention {
            let retained = selected.retain_for_sequential_collection(host, lease, retention)?;
            // The selection/native borrow ended. Move the SAME live controller
            // and actual Store snapshot, never reopen/reconstruct a fresh one.
            return Ok(Some(
                retained.attach_original_source(fresh, local_exclusions)?,
            ));
        }
        drop(selected);
        audit.check_current()?;
        lease.check_current().map_err(|_| Error::Permission)?;
        fresh.check_current(host, &inventory_scope, target)?;
        check_clock(&scope, deadline)?;
        lease.finish().map_err(|_| Error::Permission)?;
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selection_disclosure_is_clipped_to_original_invocation_without_renewal() {
        assert_eq!(disclosure_expiry(100, 100, 120_100).unwrap(), 30_100);
        assert_eq!(disclosure_expiry(119_900, 100, 120_100).unwrap(), 120_100);
        assert_eq!(remaining_invocation_ms(119_900, 100, 120_100).unwrap(), 200);
        assert!(disclosure_expiry(120_100, 100, 120_100).is_err());
        assert!(disclosure_expiry(99, 100, 120_100).is_err());
    }
    #[test]
    fn invalid_or_overflowing_selection_clocks_fail_closed() {
        assert!(remaining_invocation_ms(1, 0, 2).is_err());
        assert!(remaining_invocation_ms(10, 20, 30).is_err());
        assert!(remaining_invocation_ms(30, 20, 30).is_err());
        assert!(remaining_invocation_ms(20, 20, 19).is_err());
        assert!(disclosure_expiry(u64::MAX - 1, 1, u64::MAX).is_err());
    }
}
