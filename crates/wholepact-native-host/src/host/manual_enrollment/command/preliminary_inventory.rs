//! Explicit post-audit viewing composition. Configuration is inert; the exact
//! fresh attachment, native review and same-process lower lease are independent
//! owners. Nothing in this module selects contribution inputs or creates funds.
use super::*;
use crate::{
    authority::manual_inventory::PreliminaryInventoryAdmission,
    financial_inventory::{
        AttachmentOpenMode,
        manual::{FreshFinancialProfile, PreparedAttachment, binding_for_profile},
    },
    host::financial::manual_inventory_setup::FreshPreliminaryWallet,
};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use wholepact_core::{
    born_recipient_policy_v2::BornConstructionRecipientPolicyV2,
    manual_construction::{
        ManualConstructionAttempt, PreconstructionBirthday, PreconstructionProvider,
    },
    manual_inventory::{
        MAX_PRELIMINARY_DISCLOSURE_MS, ManualPreliminaryInventoryRequest,
        ManualPreliminaryInventoryScope,
    },
};
use wholepact_signer::authority_bridge::manual_inventory::SignerPreliminaryInventoryLease;

/// User selection only. No account, generation, attachment, current caller,
/// original intent, lease, receipt or approval field is accepted from JSON.
#[derive(Deserialize, Serialize)]
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
    fresh: FreshFinancialProfile,
    scope: ManualPreliminaryInventoryScope,
    operation_id: String,
    admission: PreliminaryInventoryAdmission,
    pair_approval: PublicationApproval,
    request_approval: PublicationApproval,
    review_digest: String,
    audit_review_digest: String,
}

pub(super) fn prepare(
    host: &Host,
    audit: &PreparedManualContinuation<'_>,
    envelope: &ManualEnrollmentSessionContinuationOwnerSignature,
) -> Result<PreparedInventory> {
    audit.source.check_current()?;
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
        "wholepact:native-host-manual-inventory-fresh-attachment:v1",
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
    let attachment_approval = host.terminal.approve_publication(
        attachment.review_digest(),
        &format!("{}\nThis explicit command creates a NEW encrypted preliminary wallet before signer launch. Its pending/committed attachment is durable even if later validation, audit or disclosure fails. Reopened or pending wallets cannot enter this fresh-only flow. No account genesis is performed.\nExact private inventory selection: {}",
            attachment.detail(), serde_json::to_string_pretty(&selected)?),
    )?;
    audit.source.check_current()?;
    let fresh = attachment.open_fresh(attachment_approval, password.as_bytes())?;
    drop(password);
    audit.source.check_current()?;
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
        enrollment_ref: audit.source.enrollment_ref.clone(),
        witness_extension_digest: audit.source.extension_digest.clone(),
        attempt: ManualConstructionAttempt {
            version: 2,
            continuation_digest: audit.request.continuation_digest.clone(),
            attempt_sequence: envelope.continuation.sequence,
        },
        original_recipient_policy: selected.original_recipient_policy,
        operator_name: selected.operator_name,
        operator_destination: audit.source.committed.canonical_root().into(),
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
    scope.validate().map_err(|_| Error::Invalid)?;
    let admission = PreliminaryInventoryAdmission::review(&host.terminal, &scope)?;
    // The future caller binding and clock value do not exist before actual
    // pairing. Review fixes this deterministic derivation and its original
    // deadlines, rather than accepting caller-supplied authority placeholders.
    let review_digest =
        inventory_review_digest(&scope, &selected.operation_id, &audit.review_digest)?;
    let pair_approval = host.terminal.approve_publication(&review_digest, &format!(
        "After the exact reviewed audit commits, send one DISTINCT preliminary-inventory pairing in the SAME actual installed signer process.\nInventory operation: {}\nScope commitment: {}\nAudit review commitment: {}\nNo prior pairing is reinterpreted. The signer must independently authenticate its original V2 policy and retained continuation. All terminal prompts end before launch.",
        selected.operation_id, scope.pairing_digest().map_err(|_| Error::Invalid)?, audit.review_digest,
    ))?;
    let request_approval = host.terminal.approve_publication(&review_digest, &format!(
        "After that same-process pairing, send ONE preliminary viewing request for this exact scope.\nOperation: {}\nFull private scope: {}\nThe request's caller binding is derived only from the actual new native grant. Its start is the actual send-time clock and its requested disclosure expiry is exactly 30,000 milliseconds later, never beyond the original policy; all original native and Host deadlines may shorten it. The expected original signer-intent commitment comes only from the checked continuation lease before audit consumption.\nThe installed signer separately approves disclosing this account's FVK to this Host and encrypted wallet. The named provider receives the bounded public-block request. Local known-balance output is incomplete, single-provider and not consensus, unspentness, empty-account, contribution-selection or spending evidence. Disclosed keys and admitted wallet writes cannot be recalled. Stay in the signer window through automatic import, scan and guarded display; no further terminal prompts occur.",
        selected.operation_id, serde_json::to_string_pretty(&scope)?,
    ))?;
    let prepared = PreparedInventory {
        fresh,
        scope,
        operation_id: selected.operation_id,
        admission,
        pair_approval,
        request_approval,
        review_digest,
        audit_review_digest: audit.review_digest.clone(),
    };
    prepared.check_before(&audit.source)?;
    Ok(prepared)
}

fn inventory_review_digest(
    scope: &ManualPreliminaryInventoryScope,
    operation: &str,
    audit_review: &str,
) -> Result<String> {
    wholepact_core::proposal::canonical_digest(
        "wholepact:native-host-manual-preliminary-disclosure-review:v1",
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
    fresh: &FreshFinancialProfile,
    scope: &ManualPreliminaryInventoryScope,
) -> Result<()> {
    scope.validate().map_err(|_| Error::Invalid)?;
    if binding_for_profile(
        &host.directory,
        &host.secrets,
        host.financial.as_ref().ok_or(Error::Locked)?,
        fresh.profile(),
        &scope.enrollment.identity.account_id,
    )? != scope.attachment
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
    pub(super) fn deadline(&self) -> Instant {
        self.admission
            .deadline()
            .min(self.pair_approval.deadline())
            .min(self.request_approval.deadline())
    }
    pub(super) fn check_before(&self, source: &ContinuationOwners<'_>) -> Result<()> {
        source.check_current()?;
        self.admission.require_scope(&self.scope)?;
        self.pair_approval.check()?;
        self.request_approval.check()?;
        check_fresh(source.host, &self.fresh, &self.scope)
    }
    pub(super) fn run(
        self,
        host: &Host,
        client: NativeManualClient,
        audit: &CommittedManualAudit<'_>,
    ) -> Result<()> {
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
        } = self;
        // The retained post-audit owner is the exact operation reviewed before
        // creation. A different valid audit cannot authorize this attachment.
        if audit_review_digest != audit.review_digest
            || scope.enrollment != audit.request.enrollment.terms
            || scope.attempt.continuation_digest != audit.request.continuation_digest
            || scope.enrollment_ref != audit.source.enrollment_ref
            || scope.witness_extension_digest != audit.source.extension_digest
            || review_digest
                != inventory_review_digest(&scope, &operation_id, &audit_review_digest)?
        {
            return Err(Error::Authentication);
        }
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
                    .begin_preliminary_inventory_pair_before(
                        "wholepact-native-preliminary-inventory",
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
        let request = ManualPreliminaryInventoryRequest {
            version: 1,
            operation_id,
            scope: scope.clone(),
            current_caller_binding_digest,
            requested_at_ms,
            disclosure_expires_at_ms: disclosure_expiry(
                requested_at_ms,
                scope.enrollment.scope.expires_at_ms,
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
                    .begin_preliminary_inventory_before(
                        &request,
                        &audit.original_signer_intent_digest,
                        deadline,
                    )
                    .map_err(|_| Error::Permission)
            },
        )?;
        let lower = pending.finish().map_err(|_| Error::Permission)?;
        let lease = SignerPreliminaryInventoryLease::from_native_lease(lower)
            .map_err(|_| Error::Permission)?;
        audit.check_current()?;
        lease.check_current().map_err(|_| Error::Permission)?;
        admission.require_scope(&scope)?;
        check_fresh(host, &fresh, &scope)?;
        let import_target = audit.borrow_import_target(host, &scope)?;
        let mut wallet =
            FreshPreliminaryWallet::import(host, fresh, &admission, &lease, &import_target)?;
        audit.check_current()?;
        lease.check_current().map_err(|_| Error::Permission)?;
        wallet.check_current(host, &scope)?;
        let read = host.scan_manual_preliminary_inventory(&mut wallet, admission, &lease)?;
        audit.check_current()?;
        lease.check_current().map_err(|_| Error::Permission)?;
        wallet.check_current(host, &scope)?;
        // No unguarded metadata DTO escapes. The private read owner checks its
        // native gate and actual observation inside the fixed bounded display.
        read.display_known_balances(&host.terminal)?;
        audit.check_current()?;
        lease.check_current().map_err(|_| Error::Permission)?;
        wallet.check_current(host, &scope)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inventory_window_is_exactly_thirty_seconds_and_never_renews_original_expiry() {
        assert_eq!(disclosure_expiry(10_000, 40_000).unwrap(), 40_000);
        assert_eq!(disclosure_expiry(10_000, 90_000).unwrap(), 40_000);
        assert!(disclosure_expiry(10_001, 40_000).is_err());
        assert!(disclosure_expiry(0, 90_000).is_err());
        assert!(disclosure_expiry(u64::MAX - 1, u64::MAX).is_err());
    }
    // Structurally complete private synthetic DATA only. No native approval,
    // socket, account genesis, viewing owner or lease can be made from this.
    fn selection_json() -> serde_json::Value {
        serde_json::json!({
            "operation_id":"synthetic-inventory", "operator_name":"synthetic operator",
            "retention_policy":"local encrypted fixture", "minimum_confirmations":1,
            "maximum_blocks":1,"anchor_height":2,
            "provider":{"source_id":"synthetic","endpoint":"https://synthetic.invalid","trust_profile":"single_tls_provider_report_not_consensus"},
            "birthday":{"prior_height":1,"prior_block_hash":"a".repeat(64),"sapling_tree":"","orchard_tree":"","ironwood_tree":""},
            "original_recipient_policy":{
                "version":2,"account_id":"b".repeat(64),"network_profile_id":"synthetic",
                "agreement_id":"agreement","obligation_id":"obligation","participant_id":"participant",
                "recipients":[],"charges":[],"own_return_rule":"authenticated_same_account",
                "original_limits":{"aggregate_budget_zatoshis":1,"per_operation_limit_zatoshis":1,
                    "maximum_fee_share_zatoshis":0,"maximum_transaction_fee_zatoshis":0,
                    "maximum_permit_lifetime_ms":1,"policy_expires_at_ms":1}
            }
        })
    }
    #[test]
    fn selection_cannot_supply_attachment_caller_origin_or_authority() {
        assert!(serde_json::from_value::<InventorySelection>(selection_json()).is_ok());
        for field in [
            "attachment",
            "current_caller_binding_digest",
            "original_signer_intent_digest",
            "audit_receipt",
            "approved",
            "wallet_destination",
            "enrollment",
            "reopen",
        ] {
            let mut value = selection_json();
            value[field] = serde_json::json!("untrusted");
            assert!(
                serde_json::from_value::<InventorySelection>(value).is_err(),
                "{field}"
            );
        }
    }
    #[test]
    fn selection_requires_full_original_v2_policy_descriptor() {
        let mut missing = selection_json();
        missing
            .as_object_mut()
            .unwrap()
            .remove("original_recipient_policy");
        assert!(serde_json::from_value::<InventorySelection>(missing).is_err());
        let mut digest_only = selection_json();
        digest_only["original_recipient_policy"] = serde_json::json!("c".repeat(64));
        assert!(serde_json::from_value::<InventorySelection>(digest_only).is_err());
    }
}
