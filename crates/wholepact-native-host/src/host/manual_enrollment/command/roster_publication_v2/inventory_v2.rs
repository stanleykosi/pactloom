//! Explicit post-audit viewing composition. Configuration is inert; the exact
//! fresh attachment, native review and same-process lower lease are independent
//! owners. Optional selection is separately reviewed and paired after inventory.
//! Neither phase creates construction or financial authority.
use super::*;
use crate::{
    authority::manual_roster_inventory_v2::RosterInventoryAdmissionV2,
    financial_inventory::{
        AttachmentOpenMode,
        manual::{FreshRosterFinancialProfileV2, PreparedAttachment, binding_for_profile},
    },
    host::financial::manual_roster_inventory_setup_v2::FreshRosterPreliminaryWalletV2,
};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use wholepact_core::manual_roster_inventory_v2::{
    ManualRosterInventoryRequestV2, ManualRosterInventoryScopeV2,
    ManualRosterPreparationProvenanceV2, OriginalHostRosterAuditV3,
};
use wholepact_core::{
    born_recipient_policy_v2::BornConstructionRecipientPolicyV2,
    manual_construction::{
        ManualConstructionAttempt, PreconstructionBirthday, PreconstructionProvider,
    },
    manual_inventory::{MAX_PRELIMINARY_DISCLOSURE_MS, ManualPreliminaryInventoryScope},
};
use wholepact_signer::authority_bridge::manual_roster_inventory_v2::SignerRosterInventoryLeaseV2;

/// User selection only. No account, generation, attachment, current caller,
/// original intent, lease, receipt or approval field is accepted from JSON.
#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct InventorySelection {
    operation_id: String,
    original_recipient_policy: BornConstructionRecipientPolicyV2,
    operator_name: String,
    retention_policy: String,
    provider: PreconstructionProvider,
    birthday: PreconstructionBirthday,
    minimum_confirmations: u32,
    maximum_blocks: u32,
    anchor_height: u32,
}

pub(super) struct PreparedInventory {
    fresh: FreshRosterFinancialProfileV2,
    scope: ManualRosterInventoryScopeV2,
    operation_id: String,
    admission: RosterInventoryAdmissionV2,
    pair_approval: PublicationApproval,
    request_approval: PublicationApproval,
    review_digest: String,
    audit_review_digest: String,
    selection: Option<super::selection_v2::PreparedSelection>,
}

pub(super) fn prepare(
    host: &Host,
    audit: &PreparedRosterPublication<'_>,
    selection_mode: Option<super::selection_v2::SelectionMode>,
) -> Result<PreparedInventory> {
    let retain = selection_mode.is_some_and(super::selection_v2::SelectionMode::retains_inputs);
    audit.check_before()?;
    if audit.purpose != RosterAuditPurpose::ExistingOriginalContinuationV4 {
        return Err(Error::Permission);
    }
    let original_digest = audit.prior_digest.clone().ok_or(Error::Permission)?;
    let ManualRosterPublicationAttemptV2::ContinuationV2 {
        continuation_digest,
        attempt_sequence,
    } = &audit.request.attempt
    else {
        return Err(Error::Permission);
    };
    let selected: InventorySelection = host.read_manual_private(
        "Exact private preliminary-inventory selection JSON file: ",
        "reviewing the full original V2 recipient policy, named provider, birthday and bounded scan selection; these fields grant no authority",
    )?;
    id(&selected.operation_id)?;
    selected
        .original_recipient_policy
        .require_enrollment(&audit.request.enrollment.terms)
        .map_err(|_| Error::Invalid)?;
    // Validate the maintained provider adapter before any attachment creation;
    // this performs no connection. The exact scope is validated again below.
    ChainAdapter::testnet(
        &selected.provider.source_id,
        &selected.provider.endpoint,
        NetworkPolicy::default(),
    )?;
    let path = host.path("NEW private encrypted preliminary wallet directory (absolute; no reopen or pending retry): ")?;
    let password = host
        .terminal
        .secret("New preliminary wallet passphrase (12–1024 bytes): ")?;
    let repeat = host
        .terminal
        .secret("Repeat preliminary wallet passphrase: ")?;
    if password.len() < 12 || password.len() > 1024 || *password != *repeat {
        return Err(Error::Authentication);
    }
    drop(repeat);
    let attachment_operation = wholepact_core::proposal::canonical_digest(
        "wholepact:native-host-roster-inventory-fresh-attachment:v2",
        &(&audit.review_digest, &audit.request, &selected, &path),
    )
    .map_err(|_| Error::Invalid)?;
    let primary = host.financial.as_ref().ok_or(Error::Locked)?;
    let attachment = PreparedAttachment::prepare(
        &host.directory,
        &host.secrets,
        primary,
        &attachment_operation,
        &audit.request.enrollment.terms.identity.account_id,
        &path,
        AttachmentOpenMode::Create,
    )?;
    let attachment_approval = host.terminal.approve_publication_reviewed(&audit.original.source.history_review,
        attachment.review_digest(),
        &format!("{}\nThis explicit command creates a NEW encrypted preliminary wallet before signer launch. Its pending/committed attachment is durable even if later validation, audit or disclosure fails. Reopened or pending wallets cannot enter this fresh-only flow. No account genesis is performed.\nExact private inventory selection: {}",
            attachment.detail(), serde_json::to_string_pretty(&selected)?),
    )?;
    audit.original.source.check_current()?;
    let fresh = if retain {
        // Dedicated original-create no-wait wallet for the separately admitted
        // exact-read route. Ordinary inventory keeps its existing lock policy.
        attachment.open_fresh_roster_exact_input_v1(attachment_approval, password.as_bytes())?
    } else {
        attachment.open_fresh_roster_v2(attachment_approval, password.as_bytes())?
    };
    drop(password);
    audit.original.source.check_current()?;
    let binding = binding_for_profile(
        &host.directory,
        &host.secrets,
        primary,
        fresh.profile(),
        &audit.request.enrollment.terms.identity.account_id,
    )?;
    let scope = ManualPreliminaryInventoryScope {
        version: 1,
        enrollment: audit.request.enrollment.terms.clone(),
        enrollment_ref: audit.extension.account_extension.enrollment_ref.clone(),
        witness_extension_digest: audit
            .extension
            .account_extension
            .digest()
            .map_err(|_| Error::Invalid)?,
        attempt: ManualConstructionAttempt {
            version: 2,
            continuation_digest: continuation_digest.clone(),
            attempt_sequence: *attempt_sequence,
        },
        original_recipient_policy: selected.original_recipient_policy,
        operator_name: selected.operator_name,
        operator_destination: audit.original.source.committed.canonical_root().into(),
        wallet_destination: format!("{}/wallet.sqlite", binding.selected.canonical_directory),
        attachment: binding,
        purpose: "preliminary_inventory_only".into(),
        retention_policy: selected.retention_policy,
        provider: selected.provider,
        birthday: selected.birthday,
        minimum_confirmations: selected.minimum_confirmations,
        maximum_blocks: selected.maximum_blocks,
        anchor_height: selected.anchor_height,
    };
    let scope = ManualRosterInventoryScopeV2 {
        version: 2,
        inventory: scope,
        provenance: ManualRosterPreparationProvenanceV2 {
            version: 2,
            original_host_audit: OriginalHostRosterAuditV3::AdditionalPublicationV3 {
                audit_digest: original_digest,
            },
            roster: audit.extension.roster.clone(),
            signer_roster_record_digest: audit.extension.signer_roster_record_digest.clone(),
            witness_roster_extension_digest: audit
                .extension
                .digest()
                .map_err(|_| Error::Invalid)?,
        },
    };
    scope.validate().map_err(|_| Error::Invalid)?;
    let admission = RosterInventoryAdmissionV2::review(
        &host.terminal,
        &audit.original.source.history_review,
        &scope,
    )?;
    // The future caller binding and clock value do not exist before actual
    // pairing. Review fixes this deterministic derivation and its original
    // deadlines, rather than accepting caller-supplied authority placeholders.
    let review_digest =
        inventory_review_digest(&scope, &selected.operation_id, &audit.review_digest)?;
    let pair_approval = host.terminal.approve_publication_reviewed(&audit.original.source.history_review, &review_digest, &format!(
        "After the exact reviewed audit commits, send one DISTINCT preliminary-inventory pairing in the SAME actual installed signer process.\nInventory operation: {}\nScope commitment: {}\nAudit review commitment: {}\nNo prior pairing is reinterpreted. The signer must independently authenticate its original V2 policy and retained continuation. All terminal prompts end before launch.",
        selected.operation_id, scope.pairing_digest().map_err(|_| Error::Invalid)?, audit.review_digest,
    ))?;
    let request_approval = host.terminal.approve_publication_reviewed(&audit.original.source.history_review, &review_digest, &format!(
        "After that same-process pairing, send ONE preliminary viewing request for this exact scope.\nOperation: {}\nFull private scope: {}\nThe request's caller binding is derived only from the actual new native grant. Its start is the actual send-time clock and its requested disclosure expiry is exactly 30,000 milliseconds later, never beyond the original policy; all original native and Host deadlines may shorten it. The expected original signer-intent commitment comes only from the checked continuation lease before audit consumption.\nThe installed signer separately approves disclosing this account's FVK to this Host and encrypted wallet. The named provider receives the bounded public-block request. Local known-balance output is incomplete, single-provider and not consensus, unspentness, empty-account, contribution-selection or spending evidence. Disclosed keys and admitted wallet writes cannot be recalled. Stay in the signer window through automatic import, scan and guarded display; no further terminal prompts occur.",
        selected.operation_id, serde_json::to_string_pretty(&scope)?,
    ))?;
    let selection = if let Some(mode) = selection_mode {
        Some(super::selection_v2::prepare(host, audit, &scope, mode)?)
    } else {
        None
    };
    let prepared = PreparedInventory {
        fresh,
        scope,
        operation_id: selected.operation_id,
        admission,
        pair_approval,
        request_approval,
        review_digest,
        audit_review_digest: audit.review_digest.clone(),
        selection,
    };
    prepared.check_before(audit)?;
    Ok(prepared)
}

fn inventory_review_digest(
    scope: &ManualRosterInventoryScopeV2,
    operation: &str,
    audit_review: &str,
) -> Result<String> {
    wholepact_core::proposal::canonical_digest(
        "wholepact:native-host-roster-preliminary-disclosure-review:v2",
        &(
            scope,
            operation,
            audit_review,
            MAX_PRELIMINARY_DISCLOSURE_MS,
            "actual-new-native-grant-and-send-time-only",
        ),
    )
    .map_err(|_| Error::Invalid)
}
fn check_fresh(
    host: &Host,
    fresh: &FreshRosterFinancialProfileV2,
    scope: &ManualRosterInventoryScopeV2,
) -> Result<()> {
    scope.validate().map_err(|_| Error::Invalid)?;
    if binding_for_profile(
        &host.directory,
        &host.secrets,
        host.financial.as_ref().ok_or(Error::Locked)?,
        fresh.profile(),
        &scope.inventory.enrollment.identity.account_id,
    )? != scope.inventory.attachment
    {
        return Err(Error::Authentication);
    }
    Ok(())
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
fn disclosure_expiry(start: u64, original_expiry: u64) -> Result<u64> {
    let end = start
        .checked_add(MAX_PRELIMINARY_DISCLOSURE_MS)
        .ok_or(Error::Invalid)?;
    if start == 0 || end > original_expiry {
        return Err(Error::Permission);
    }
    Ok(end)
}
impl PreparedInventory {
    #[cfg(test)]
    pub(super) fn synthetic_retention_operation_id(&self) -> Option<&str> {
        self.selection
            .as_ref()
            .and_then(|s| s.synthetic_retention_operation_id())
    }

    #[cfg(test)]
    pub(super) fn synthetic_exact_request_parts(&self) -> (&ManualRosterInventoryScopeV2, &str) {
        (&self.scope, &self.operation_id)
    }
    #[cfg(test)]
    pub(super) fn synthetic_selection_parts(&self) -> Option<(&wholepact_core::manual_roster_candidate_selection_v2::ManualRosterCandidateSelectionScopeV2, &str)>{
        self.selection
            .as_ref()
            .map(|s| s.synthetic_exact_request_parts())
    }

    pub(super) fn deadline(&self) -> Instant {
        self.admission
            .deadline()
            .min(self.pair_approval.deadline())
            .min(self.request_approval.deadline())
            .min(
                self.selection
                    .as_ref()
                    .map_or(self.admission.deadline(), |s| s.deadline()),
            )
    }
    pub(super) fn check_before(&self, audit: &PreparedRosterPublication<'_>) -> Result<()> {
        audit.check_before()?;
        self.admission.require_scope(&self.scope)?;
        self.pair_approval.check()?;
        self.request_approval.check()?;
        if let Some(selection) = &self.selection {
            selection.check_before(audit)?;
        }
        check_fresh(audit.original.source.host, &self.fresh, &self.scope)
    }
    pub(super) fn run<'host>(
        self,
        host: &'host Host,
        client: NativeManualClient,
        audit: &CommittedRosterAudit<'_>,
    ) -> Result<Option<crate::host::financial::manual_roster_inventory_setup_v2::RetainedRosterCandidateInputsV2<'host>>>{
        let deadline = self.deadline().min(audit.deadline);
        let Self {
            fresh,
            scope,
            operation_id,
            admission,
            pair_approval,
            request_approval,
            review_digest,
            audit_review_digest,
            selection,
        } = self;
        // The retained post-audit owner is the exact operation reviewed before
        // creation. A different valid audit cannot authorize this attachment.
        if audit_review_digest != audit.review_digest
            || review_digest
                != inventory_review_digest(&scope, &operation_id, &audit_review_digest)?
        {
            return Err(Error::Authentication);
        }
        let import_target = audit.borrow_import_target(host, &scope)?;
        import_target.require_current(host, &scope)?;
        audit.check_current()?;
        admission.require_scope(&scope)?;
        check_fresh(host, &fresh, &scope)?;
        request_approval.check()?;
        // Audit's actual lower lease has been consumed and its lease slot freed.
        // Consume that exact client; no provider reload or process relaunch.
        let pending = pair_approval.commit(
            &review_digest,
            || {
                audit.check_current()?;
                admission.require_scope(&scope)?;
                check_fresh(host, &fresh, &scope)
            },
            |_| {
                client
                    .begin_roster_inventory_pair_before(
                        "wholepact-native-roster-preliminary-inventory-v2",
                        &scope,
                        deadline,
                    )
                    .map_err(|_| Error::Permission)
            },
        )?;
        let client = pending.finish().map_err(|_| Error::Permission)?;
        audit.check_current()?;
        admission.require_scope(&scope)?;
        check_fresh(host, &fresh, &scope)?;
        let current_caller_binding_digest = client
            .current_caller_binding_digest()
            .map_err(|_| Error::Permission)?;
        let requested_at_ms = now_ms()?;
        let request = ManualRosterInventoryRequestV2 {
            version: 2,
            operation_id,
            scope: scope.clone(),
            current_caller_binding_digest,
            requested_at_ms,
            disclosure_expires_at_ms: disclosure_expiry(
                requested_at_ms,
                scope.inventory.enrollment.scope.expires_at_ms,
            )?,
        };
        request.validate().map_err(|_| Error::Invalid)?;
        let pending = request_approval.commit(
            &review_digest,
            || {
                audit.check_current()?;
                admission.require_scope(&scope)?;
                check_fresh(host, &fresh, &scope)
            },
            |_| {
                client
                    .begin_roster_inventory_before(
                        &request,
                        &audit.original_signer_intent_digest,
                        deadline,
                    )
                    .map_err(|_| Error::Permission)
            },
        )?;
        let lower = pending.finish().map_err(|_| Error::Permission)?;
        let lease = SignerRosterInventoryLeaseV2::from_native_lease(lower)
            .map_err(|_| Error::Permission)?;
        audit.check_current()?;
        lease.check_current().map_err(|_| Error::Permission)?;
        admission.require_scope(&scope)?;
        check_fresh(host, &fresh, &scope)?;
        let mut wallet = FreshRosterPreliminaryWalletV2::import(
            host,
            fresh,
            &admission,
            &lease,
            &import_target,
        )?;
        audit.check_current()?;
        lease.check_current().map_err(|_| Error::Permission)?;
        wallet.check_current(host, &scope, &import_target)?;
        let read =
            host.scan_manual_roster_inventory_v2(&mut wallet, admission, &lease, &import_target)?;
        audit.check_current()?;
        lease.check_current().map_err(|_| Error::Permission)?;
        // The read owner itself retains/checks the wallet and import binding.
        // No unguarded metadata DTO escapes. The private read owner checks its
        // native gate and actual observation inside the fixed bounded display.
        read.display_known_balances()?;
        drop(read);
        audit.check_current()?;
        lease.check_current().map_err(|_| Error::Permission)?;
        wallet.check_current(host, &scope, &import_target)?;
        // End the distinct preliminary native slot before a separately reviewed
        // candidate request. A prior viewing lease cannot authorize selection.
        lease.finish().map_err(|_| Error::Permission)?;
        if let Some(selection) = selection {
            return selection.run(host, client, audit, wallet, &import_target);
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn disclosure_request_never_extends_original_policy_or_accepts_zero_clock() {
        assert_eq!(disclosure_expiry(1, 30_001).unwrap(), 30_001);
        assert!(disclosure_expiry(1, 30_000).is_err());
        assert!(disclosure_expiry(0, 30_000).is_err());
        assert!(disclosure_expiry(u64::MAX, u64::MAX).is_err());
    }
}
