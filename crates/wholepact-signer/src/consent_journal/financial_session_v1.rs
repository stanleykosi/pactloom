//! New source-bound financial decision, not an old SignerConsentSession revival.
//! The original enrollment and manifest remain unchanged; only the explicit
//! financial consent carries this genuine fresh SignExact decision provenance.
use super::*;
#[cfg(feature = "coordinated-financial-workflow-v1")]
#[path = "financial_session_v1/coordinated_sign_v1.rs"]
mod coordinated_sign_v1;
#[cfg(feature = "coordinated-financial-workflow-v1")]
pub(crate) use coordinated_sign_v1::{PreparedCoordinatedFinancialSpendV1, PresentedCoordinatedFinancialSpendV1, ApprovedCoordinatedFinancialSpendConsentV1};
use crate::native_ui::financial_authority_v1::{FinancialReadLeaseV1, FinancialSignActionV1};
use crate::{
    account::DedicatedAccount,
    manifest::{AcceptedManifest, ReviewInputs},
};
use sha2::{Digest, Sha256};
use wholepact_authority::{AuthorityHead, OwnerControl, WitnessDisclosureDescriptor};
use wholepact_protocol::durable_proposal_v1::VerifiedFixedProposal;

fn inert_terms(terms: &SpendConsentTerms) -> Result<serde_json::Value> {
    let mut value = serde_json::to_value(terms).map_err(|_| JournalError::InvalidBinding)?;
    value
        .as_object_mut()
        .ok_or(JournalError::InvalidBinding)?
        .remove("receipt");
    Ok(value)
}
fn receipt(read: &FinancialReadLeaseV1, epoch: u64) -> NativeConsentReceipt {
    NativeConsentReceipt {
        native_session_id: read.session_digest().into(),
        trusted_launch_measurement: read.measurement().into(),
        permission_generation: read.permission_generation(),
        writer_epoch: epoch,
        nonce: read.nonce().into(),
        reviewed_at_ms: read.reviewed_at_unix_ms(),
        expires_at_ms: read.expires_at_unix_ms(),
    }
}
// A closed purpose guard, not a caller-provided callback or provenance DTO.
// The coordinated branch is added only with its actual nominal Read consumer.
enum FinancialSpendPreparationGuardV1<'a> {
    Native(&'a FinancialReadLeaseV1),
    #[cfg(feature = "coordinated-financial-workflow-v1")]
    Coordinated(&'a wholepact_financial_coordinator_origin::SignerSignReadFinalV1, &'a orchard::keys::FullViewingKey),
}
impl FinancialSpendPreparationGuardV1<'_> {
    fn check(&self, source: &FinancialSourceBindingV1) -> Result<()> {
        match self {
            Self::Native(read) => read.check_source(source.identity_digest()),
            #[cfg(feature = "coordinated-financial-workflow-v1")]
            Self::Coordinated(read, _) => {
                if read.presentation().facts.original.activation.facts.original.source_identity_digest != source.identity_digest() {
                    return Err(JournalError::Permission);
                }
                read.check_current().map_err(Into::into)
            }
        }.map_err(|_| JournalError::Permission)
    }
    fn authenticated_fvk(&self, account: &DedicatedAccount) -> Result<orchard::keys::FullViewingKey> {
        match self {
            Self::Native(_) => account.fvk().map_err(|_| JournalError::InvalidBinding),
            // This is the actual retained WalletObserve ticket's FVK, not a
            // policy label. Reconciliation below checks private LocalSelection
            // and the original enrollment digest before retaining any terms.
            #[cfg(feature = "coordinated-financial-workflow-v1")]
            Self::Coordinated(_, fvk) => Ok((**fvk).clone()),
        }
    }
    fn principal_id<'a>(&'a self, enrolled: &'a str) -> &'a str {
        match self {
            Self::Native(read) => read.principal_id(),
            #[cfg(feature = "coordinated-financial-workflow-v1")]
            Self::Coordinated(..) => enrolled,
        }
    }
    fn receipt(&self, writer_epoch: u64) -> NativeConsentReceipt {
        match self {
            Self::Native(read) => receipt(read, writer_epoch),
            #[cfg(feature = "coordinated-financial-workflow-v1")]
            Self::Coordinated(read, _) => {
                let p = read.presentation();
                NativeConsentReceipt {
                    native_session_id: p.actor.session_challenge.clone(),
                    trusted_launch_measurement: p.actor.common_image_measurement.clone(),
                    permission_generation: 1, writer_epoch, nonce: p.challenge.clone(),
                    reviewed_at_ms: p.facts.reviewed_at_ms, expires_at_ms: p.facts.expires_at_ms,
                }
            }
        }
    }
}
/// Full mathematically verified data before the final decision. Its temporary
/// receipt records read provenance only and is never retained as a spend record.
pub(crate) struct PreparedFinancialSpendV1 {
    binding: SignerJournalBinding,
    source_identity: String,
    account: SignerAccountState,
    retained: RetainedFinancialContinuationIntentV1,
    terms: SpendConsentTerms,
    head: AuthorityHead,
    disclosure: WitnessDisclosureDescriptor,
    digest: String,
    fixed: Arc<VerifiedFixedProposal>,
    inputs: ReviewInputs,
}
impl FinancialConsentJournalV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_financial_spend_v1(
        &self,
        source: &FinancialSourceBindingV1,
        read: &FinancialReadLeaseV1,
        account: &DedicatedAccount,
        fixed: Arc<VerifiedFixedProposal>,
        inputs: ReviewInputs,
        history:&wholepact_authority::durable_financial_continuation_v1::AuthenticatedFinancialContinuationHistoryV1,
    ) -> Result<PreparedFinancialSpendV1> {
        read.check_source(source.identity_digest())
            .map_err(|_| JournalError::Permission)?;
        let prepared = self.prepare_financial_spend_data_v1(
            source,
            account,
            fixed,
            inputs,
            history,
            &FinancialSpendPreparationGuardV1::Native(read),
        )?;
        read.check_source(source.identity_digest())
            .map_err(|_| JournalError::Permission)?;
        Ok(prepared)
    }

    // Private data-only mathematical kernel. The only callers are the two
    // concrete original-role adapters, which retain their genuine Read through
    // this call. A provenance tuple is inert and cannot issue a spend approval.
    #[allow(clippy::too_many_arguments)]
    fn prepare_financial_spend_data_v1(
        &self,
        source: &FinancialSourceBindingV1,
        account: &DedicatedAccount,
        fixed: Arc<VerifiedFixedProposal>,
        inputs: ReviewInputs,
        history: &wholepact_authority::durable_financial_continuation_v1::AuthenticatedFinancialContinuationHistoryV1,
        guard: &FinancialSpendPreparationGuardV1<'_>,
    ) -> Result<PreparedFinancialSpendV1> {
        guard.check(source)?;
        let (enrollment, manifest, retained, state) = {
            let _fence = self.journal.authority_fence.read().map_err(|_| JournalError::Permission)?;
            guard.check(source)?;
            let mut c = self
                .journal
                .connection
                .lock()
                .map_err(|_| JournalError::Database)?;
            guard.check(source)?;
            if !c.is_autocommit() { return Err(JournalError::Conflict); }
            source.require(&self.journal, &c)?;
            guard.check(source)?;
            source.require_pin(&c)?;
            guard.check(source)?;
            let tx = c.transaction_with_behavior(TransactionBehavior::Deferred)?;
            guard.check(source)?;
            validate(&tx, &self.genesis)?;
            guard.check(source)?;
            let retained = intent::read(&tx)?;
            guard.check(source)?;
            let t = retained.terms()?;
            let enrollment = read_enrollment(&tx, &t.original_recipient_enrollment_ref)?
                .ok_or(JournalError::NotFound)?;
            guard.check(source)?;
            let manifest = read_manifest(&tx, &t.original_recipient_manifest_ref)?
                .ok_or(JournalError::NotFound)?;
            guard.check(source)?;
            let state = read_account(&tx)?;
            guard.check(source)?;
            #[cfg(feature = "coordinated-financial-workflow-v1")]
            if matches!(guard, FinancialSpendPreparationGuardV1::Coordinated(..)) {
                for table in ["signer_original_consents", "signer_bridge_requests", "signer_bridge_permits", "signer_bridge_keyuse", "signer_bridge_results"] {
                    guard.check(source)?;
                    let exists: bool = tx.query_row(&format!("SELECT EXISTS(SELECT 1 FROM {table})"), [], |row| row.get(0))?;
                    if exists { return Err(JournalError::Conflict); }
                }
            }
            if original_rows_digest(&tx)? != source.original_rows_digest {
                return Err(JournalError::Conflict);
            }
            source.require(&self.journal, &tx)?;
            guard.check(source)?;
            source.require_pin(&tx)?;
            guard.check(source)?;
            tx.commit()?;
            guard.check(source)?;
            source.require_pin(&c)?;
            guard.check(source)?;
            (enrollment, manifest, retained, state)
        };
        guard.check(source)?;
        let principal_id = guard.principal_id(enrollment.principal_id());
        if history.continuation_request() != retained.request() {
            return Err(JournalError::InvalidBinding);
        }
        let head = history.snapshot().head.clone();
        let disclosure = history.disclosure().clone();
        let continuation = retained.terms()?;
        let a = &continuation.scope.authorization;
        continuation
            .require_live(now_ms()?)
            .map_err(|_| JournalError::Expired)?;
        let fvk = guard.authenticated_fvk(account)?;
        let account_id = account
            .account_id()
            .map_err(|_| JournalError::InvalidBinding)?;
        let proposal = manifest.proposal()?;
        if account.recovery_required()
            || account_id != a.identity.account_id
            || account_id != enrollment.account_id()
            || enrollment.principal_id() != principal_id
            || state.account_id != account_id
            || state.writer_epoch != continuation.scope.original_writer_epoch
            || disclosure != continuation.scope.witness
            || hex::encode(Sha256::digest(fvk.to_bytes())) != enrollment.account_fvk_digest()
            || serde_json::to_value(fixed.identity()).map_err(|_| JournalError::InvalidBinding)?
                != serde_json::to_value(&a.fixed).map_err(|_| JournalError::InvalidBinding)?
            || proposal.proposal_digest() != fixed.identity().proposal_digest
            || proposal.manifest_digest() != fixed.identity().manifest_digest
        {
            return Err(JournalError::InvalidBinding);
        }
        fixed
            .verify_action_mappings(&inputs.input_actions, &inputs.output_actions)
            .map_err(|_| JournalError::InvalidBinding)?;
        if wholepact_protocol::review_manifest::policy_fingerprint(&inputs.policy)
            != fixed.identity().policy_digest
        {
            return Err(JournalError::InvalidBinding);
        }
        crate::manifest::reconcile(
            &AcceptedManifest {
                proposal: proposal.clone(),
            },
            &inputs,
            &account_id,
            &fvk,
        )
        .map_err(|_| JournalError::InvalidBinding)?;
        let owner = inputs
            .policy
            .participants
            .iter()
            .position(|p| p.account_id == account_id)
            .ok_or(JournalError::InvalidBinding)?;
        let verified = fixed.economic_review();
        let mut bindings = Vec::new();
        for mapping in inputs
            .input_actions
            .iter()
            .filter(|m| m.account_id == account_id)
        {
            let input = inputs
                .policy
                .inputs
                .iter()
                .find(|i| i.action_index == mapping.action_index && i.participant_index == owner)
                .ok_or(JournalError::InvalidBinding)?;
            bindings.push(ConsentInputBinding {
                input_id: mapping.input_id.clone(),
                action_index: input
                    .action_index
                    .try_into()
                    .map_err(|_| JournalError::InvalidBinding)?,
                nullifier: hex::encode(input.nullifier),
                value_zatoshis: input.value_zatoshis,
            });
        }
        bindings.sort_by(|a, b| a.input_id.cmp(&b.input_id));
        if bindings.len() != a.inputs.len()
            || bindings.iter().zip(&a.inputs).any(|(b, i)| {
                b.input_id != i.input_id
                    || b.action_index != i.action_index
                    || b.nullifier != i.nullifier
                    || b.value_zatoshis != i.value_zatoshis
            })
            || verified.net_debits_zatoshis()[owner] != a.maximum_debit_zatoshis
            || inputs.policy.participants[owner].fee_share_zatoshis != a.fee_share_zatoshis
            || verified.fee_zatoshis() != a.transaction_fee_zatoshis
        {
            return Err(JournalError::InvalidBinding);
        }
        let selection = &inputs.own_selection.context;
        let read_receipt = guard.receipt(state.writer_epoch);
        let terms = SpendConsentTerms {
            durable_born_policy_v1: None,
            automation: None,
            sponsor_policy: None,
            sponsor_owner_attestation_digest: None,
            authorization_id: a.authorization_id.clone(),
            enrollment_ref: enrollment.reference().into(),
            accepted_manifest_ref: manifest.reference().into(),
            account_id: account_id.clone(),
            principal_id: principal_id.into(),
            agreement_id: proposal.manifest().agreement.agreement_id.clone(),
            obligation_id: proposal.manifest().agreement.obligation_id.clone(),
            proposal_id: proposal.input().proposal_id.clone(),
            proposal_digest: proposal.proposal_digest().into(),
            manifest_digest: proposal.manifest_digest().into(),
            effects_digest: verified.shielded_sighash().into(),
            artifact_digest: fixed.identity().proved_artifact_digest.clone(),
            review_binding: verified.review_binding().into(),
            transport: enrollment.transport().clone(),
            input_bindings: bindings,
            maximum_debit_zatoshis: a.maximum_debit_zatoshis,
            fee_share_zatoshis: a.fee_share_zatoshis,
            transaction_fee_zatoshis: a.transaction_fee_zatoshis,
            aggregate_budget_limit_zatoshis: enrollment.budget_limit_zatoshis(),
            transaction_expiry_height: inputs.policy.expiry_height,
            wallet_key_use_policy: inputs.own_selection.key_use_policy.clone(),
            wallet_snapshot: WalletSnapshotBinding {
                tip_height: selection.tip_height,
                tip_hash: hex::encode(selection.tip_hash),
                anchor_height: selection.anchor_height,
                anchor_hash: hex::encode(selection.anchor_hash),
                anchor_root: hex::encode(selection.anchor_root),
            },
            receipt: read_receipt,
        };
        if terms.wallet_key_use_policy.is_none() {
            return Err(JournalError::Permission);
        }
        let digest = digest(
            "wholepact:financial-sign-exact-and-dispatch:v1",
            &(
                source.identity_digest(),
                retained.history_digest()?,
                inert_terms(&terms)?,
                &head,
                &disclosure,
                &continuation.scope.delivery,
            ),
        )?;
        guard.check(source)?;
        // Recheck the exact metadata revision after the pure mathematical work;
        // do not reopen semantic rows without the live purpose guard.
        {
            let c = self.journal.connection.lock().map_err(|_| JournalError::Database)?;
            guard.check(source)?;
            source.require(&self.journal, &c)?;
            if !c.is_autocommit() || source.revision != revision(&c)? {
                return Err(JournalError::Conflict);
            }
        }
        guard.check(source)?;
        Ok(PreparedFinancialSpendV1 {
            binding: self.journal.binding(),
            source_identity: source.identity_digest().into(),
            account: state,
            retained,
            terms,
            head,
            disclosure,
            digest,
            fixed,
            inputs,
        })
    }
}
impl PreparedFinancialSpendV1 {
    pub(crate) fn reviewed_digest(&self) -> &str {
        &self.digest
    }
    pub(crate) fn display(&self) -> Result<String> {
        project_spend_display(
            &self.terms, &self.disclosure, &self.head,
            || Ok(&self.retained.terms()?.scope.delivery), &self.digest,
        )
    }
    pub(crate) fn approve(
        self,
        action: FinancialSignActionV1,
    ) -> Result<ApprovedFinancialSpendConsentV1> {
        action
            .check_source(&self.source_identity)
            .map_err(|_| JournalError::Permission)?;
        if action.terms_digest() != self.digest || action.principal_id() != self.terms.principal_id
        {
            return Err(JournalError::Permission);
        }
        let mut terms = self.terms;
        terms.receipt = NativeConsentReceipt {
            native_session_id: action.session_digest().into(),
            trusted_launch_measurement: action.measurement().into(),
            permission_generation: action.permission_generation(),
            writer_epoch: self.account.writer_epoch,
            nonce: action.nonce().into(),
            reviewed_at_ms: action.reviewed_at_unix_ms(),
            expires_at_ms: action.expires_at_unix_ms(),
        };
        let OwnerControl::AdmitFinancialContinuationV1 { record } =
            &self.retained.request().control
        else {
            return Err(JournalError::InvalidBinding);
        };
        let binding = FinancialSpendBindingV1 {
            coordinated_origin_v1: None,
            continuation_operation_id: self.retained.request().operation_id.clone(),
            continuation_request_digest: record
                .request_digest(self.retained.request())
                .map_err(|_| JournalError::InvalidBinding)?,
            continuation_history_digest: self.retained.history_digest()?,
            source_identity_digest: self.source_identity.clone(),
            terms_digest: self
                .retained
                .terms()?
                .intent_terms_digest()
                .map_err(|_| JournalError::InvalidBinding)?,
            signing_terms_digest: self.digest,
            reviewed_head: self.head.clone(),
            disclosure: self.disclosure.clone(),
            action_review_digest: action.native_review_digest().into(),
            native_session_digest: action.session_digest().into(),
            principal_id: action.principal_id().into(),
            measurement: action.measurement().into(),
            permission_generation: action.permission_generation(),
            nonce: action.nonce().into(),
        };
        let record = OriginalSpendConsent::new_financial_v1(terms, binding)?;
        Ok(ApprovedFinancialSpendConsentV1 {
            record,
            journal: self.binding,
            account: self.account,
            action: Arc::new(action),
            fixed: self.fixed,
            inputs: self.inputs,
            head: self.head,
            disclosure: self.disclosure,
        })
    }
}
pub(crate) struct ApprovedFinancialSpendConsentV1 {
    record: OriginalSpendConsent,
    journal: SignerJournalBinding,
    account: SignerAccountState,
    action: Arc<FinancialSignActionV1>,
    fixed: Arc<VerifiedFixedProposal>,
    inputs: ReviewInputs,
    head: AuthorityHead,
    disclosure: WitnessDisclosureDescriptor,
}
pub(crate) struct FinancialPermissionLeaseV1<'a> {
    action: &'a FinancialSignActionV1,
    _publication: crate::native_ui::NativePublicationLease<'a>,
}
impl FinancialPermissionLeaseV1<'_> {
    pub(crate) fn check_current(&self) -> Result<()> {
        self.action
            .check_current()
            .map_err(|_| JournalError::Permission)
    }
}
impl ApprovedFinancialSpendConsentV1 {
    pub(crate) fn publication_lease(&self) -> Result<crate::native_ui::NativePublicationLease<'_>> {
        self.action
            .publication_lease()
            .map_err(|_| JournalError::Permission)
    }
    pub(crate) fn record(&self) -> &OriginalSpendConsent {
        &self.record
    }
    pub(crate) fn fixed(&self) -> &VerifiedFixedProposal {
        &self.fixed
    }
    pub(crate) fn inputs(&self) -> &ReviewInputs {
        &self.inputs
    }
    pub(crate) fn reviewed_head(&self) -> &AuthorityHead {
        &self.head
    }
    pub(crate) fn disclosure(&self) -> &WitnessDisclosureDescriptor {
        &self.disclosure
    }
    pub(crate) fn check_current(&self) -> Result<()> {
        self.action
            .check_current()
            .map_err(|_| JournalError::Permission)
    }
    pub(crate) fn lease_for_journal(
        &self,
        journal: &SignerJournalBinding,
        account: &SignerAccountState,
    ) -> Result<FinancialPermissionLeaseV1<'_>> {
        self.check_current()?;
        if *journal != self.journal
            || account.account_id != self.account.account_id
            || account.writer_epoch != self.account.writer_epoch
            || account.recovery_required
        {
            return Err(JournalError::Permission);
        }
        Ok(FinancialPermissionLeaseV1 {
            action: &self.action,
            _publication: self
                .action
                .publication_lease()
                .map_err(|_| JournalError::Permission)?,
        })
    }
}
impl FinancialConsentJournalV1 {
    /// Inert original audience binding from the unchanged V3 recipient intent.
    /// This does not turn the expired recipient decision into a current grant.
    pub(crate) fn original_financial_host_instance_v1(
        &self,
        source: &FinancialSourceBindingV1,
    ) -> Result<String> {
        self.check_financial_source_binding_v1(source)?;
        let mut connection = self
            .journal
            .connection
            .lock()
            .map_err(|_| JournalError::Database)?;
        source.require(&self.journal, &connection)?;
        source.require_pin(&connection)?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        validate(&tx, &self.genesis)?;
        let retained = intent::read(&tx)?;
        let original = authority::durable_delivery_admission_intent_v3::read(
            &tx,
            &retained.terms()?.scope.authorization.authorization_id,
        )?
        .ok_or(JournalError::NotFound)?;
        let instance = original
            .recipient_intent()
            .authorized_host_process_instance
            .clone();
        hash(&instance)?;
        source.require(&self.journal, &tx)?;
        source.require_pin(&tx)?;
        tx.commit()?;
        source.require_pin(&connection)?;
        Ok(instance)
    }
}

// Pure complete Sign display; lazy delivery preserves the original error order.
pub(crate) fn project_spend_display<'a>(
    terms: &SpendConsentTerms,
    disclosure: &WitnessDisclosureDescriptor,
    head: &AuthorityHead,
    delivery: impl FnOnce() -> Result<&'a wholepact_authority::durable_delivery_scope_v2::DurableDeliveryPlanV2>,
    digest: &str,
) -> Result<String> {
    Ok(format!(
        "SIGN THIS EXACT ORIGINAL PAYMENT AND ITS BOUNDED FUTURE DISPATCH\n{}\nWitness reservation disclosure: {}\nExpected original head: {}\nProspective immutable delivery policy: {}\nBoth accounts' signatures are required. Once completed, only the first retained verified transaction may be dispatched by the named dedicated dispatcher, before the original expiry, following a fresh Host confirmation. This does not renew signing permission or authorize replacement inputs, another signature, replacement transaction, or exposure clearance.\nExact review: {}",
        serde_json::to_string_pretty(&inert_terms(terms)?)
        .map_err(|_| JournalError::InvalidBinding)?,
        serde_json::to_string(disclosure).map_err(|_| JournalError::InvalidBinding)?,
        serde_json::to_string(head).map_err(|_| JournalError::InvalidBinding)?,
        serde_json::to_string(delivery()?)
        .map_err(|_| JournalError::InvalidBinding)?,
        digest
    ))
}

// Test-only access to pure data projections; no authority constructors.
#[cfg(all(test, feature = "coordinated-financial-workflow-v1", feature = "durable-proposal", feature = "pending-birth-owner-signing", feature = "native-ui", target_os = "linux"))]
pub(crate) use coordinated_sign_v1::project_sign_exact_facts;
