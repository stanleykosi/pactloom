//! Conservative planning for a separate shielded residual transfer and account
//! retirement. This module never signs, sweeps, invents refund destinations, or
//! claims that retirement revokes previously disclosed viewing authority.
pub mod transfer;

use crate::agreement::{validate_address_text, validate_timestamp};
use crate::error::validate_id;
use crate::proposal::{canonical_digest, validate_sha256};
use crate::records::{
    ExactTransactionReference, ObservationPolicy, ObservationWindow, SourcedChainObservation,
};
use crate::{
    outstanding_exposure, Amount, AuthorizationExposure, ChainStatus, CoreError, ErrorCode, Result,
    RevisionExposure,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

pub const VIEWING_KEY_EXPOSURE_STATEMENT: &str = "Retirement stops routine Wholepact reuse. A previously disclosed viewing key remains usable by its recipient and can reveal later activity in this account. Changing a password, deleting records, or retiring the account cannot revoke that knowledge. Necessary authorization, recovery and observation history must be retained.";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExposureHistoryState {
    Missing,
    RestoredOrUnknown,
    Reconciled {
        writer_authority_ref: String,
        journal_checkpoint_digest: String,
        reconciliation_evidence_ref: String,
    },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResidualFundOrigin {
    UnselectedFunds,
    LeftoverChange,
    Unknown,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResidualInput {
    pub input_id: String,
    pub amount: Amount,
    pub origin: ResidualFundOrigin,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountRecoveryView {
    pub account_id: String,
    pub network_profile_id: String,
    pub observed_at: String,
    pub history: ExposureHistoryState,
    pub revisions: Vec<RevisionExposure>,
    pub local_reservation_input_ids: Vec<String>,
    /// Complete, currently unspent set from the trusted account scanner. An
    /// empty set with Missing/RestoredOrUnknown history does not imply safety.
    pub residual_inputs: Vec<ResidualInput>,
    pub viewing_key_disclosure_refs: Vec<String>,
}
impl fmt::Debug for AccountRecoveryView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AccountRecoveryView { private_contents: [REDACTED] }")
    }
}
impl AccountRecoveryView {
    fn validate(&self, account_id: &str, network: &str, window: &ObservationWindow) -> Result<()> {
        window.validate()?;
        validate_id(&self.account_id, "recovery account")?;
        validate_id(&self.network_profile_id, "recovery network")?;
        validate_timestamp(&self.observed_at)?;
        if self.account_id != account_id || self.network_profile_id != network {
            return Err(CoreError::new(
                ErrorCode::RevisionConflict,
                "account recovery source returned a different account or network",
            ));
        }
        if !window.contains(&self.observed_at) {
            return Err(CoreError::new(
                ErrorCode::StaleChain,
                "account recovery view is stale or from the future",
            ));
        }
        if self.revisions.len() > 4096
            || self.residual_inputs.len() > 256
            || self.local_reservation_input_ids.len() > 256
            || self.viewing_key_disclosure_refs.len() > 256
        {
            return Err(CoreError::new(
                ErrorCode::ResourceLimit,
                "account recovery view exceeds bounded history/input limits",
            ));
        }
        if let ExposureHistoryState::Reconciled {
            writer_authority_ref,
            journal_checkpoint_digest,
            reconciliation_evidence_ref,
        } = &self.history
        {
            validate_id(writer_authority_ref, "writer authority reference")?;
            validate_sha256(journal_checkpoint_digest)?;
            validate_id(
                reconciliation_evidence_ref,
                "exposure reconciliation evidence",
            )?;
        }
        let mut inputs = BTreeSet::new();
        for input in &self.residual_inputs {
            validate_id(&input.input_id, "residual input")?;
            if input.amount == Amount::ZERO || !inputs.insert(&input.input_id) {
                return Err(CoreError::new(
                    ErrorCode::InvalidTerms,
                    "residual inputs must be positive and unique",
                ));
            }
        }
        for (ids, label) in [
            (&self.local_reservation_input_ids, "reservation input"),
            (
                &self.viewing_key_disclosure_refs,
                "viewing-key disclosure reference",
            ),
        ] {
            let mut seen = BTreeSet::new();
            for id in ids {
                validate_id(id, label)?;
                if !seen.insert(id) {
                    return Err(CoreError::new(
                        ErrorCode::DuplicateIdentifier,
                        "duplicate account recovery reference",
                    ));
                }
            }
        }
        for revision in &self.revisions {
            validate_id(&revision.obligation_id, "historical obligation")?;
            if revision.input_ids.is_empty() || revision.input_ids.len() > 256 {
                return Err(CoreError::new(
                    ErrorCode::MissingEvidence,
                    "each retained revision needs its bounded exact input set",
                ));
            }
            let mut seen = BTreeSet::new();
            for id in &revision.input_ids {
                validate_id(id, "historical input")?;
                if !seen.insert(id) {
                    return Err(CoreError::new(
                        ErrorCode::DuplicateIdentifier,
                        "duplicate input in historical authorization",
                    ));
                }
            }
            if revision.exposure == AuthorizationExposure::Consumed
                && revision.input_ids.iter().any(|id| inputs.contains(id))
            {
                return Err(CoreError::new(
                    ErrorCode::RecoveryRequired,
                    "a consumed authorization conflicts with the claimed unspent input view",
                ));
            }
        }
        outstanding_exposure(&self.revisions)?;
        Amount::checked_sum(self.residual_inputs.iter().map(|input| input.amount))?;
        Ok(())
    }
    fn require_reclaimable(&self) -> Result<()> {
        if !matches!(self.history, ExposureHistoryState::Reconciled { .. }) {
            return Err(CoreError::new(ErrorCode::RecoveryRequired, "reclaim requires complete current writer and authorization-history reconciliation; seed recovery and an empty list are insufficient"));
        }
        if self
            .revisions
            .iter()
            .any(|r| r.exposure.may_still_execute())
            || !self.local_reservation_input_ids.is_empty()
        {
            return Err(CoreError::new(ErrorCode::OutstandingExposure, "reclaim is blocked by live/local authorization or reservations; a separate intentional-conflict protocol is not supported here"));
        }
        if self
            .residual_inputs
            .iter()
            .any(|input| input.origin == ResidualFundOrigin::Unknown)
        {
            return Err(CoreError::new(
                ErrorCode::MissingEvidence,
                "unknown fund classification requires account reconciliation",
            ));
        }
        Ok(())
    }
    pub fn known_residual_balance(&self) -> Result<Amount> {
        Ok(Amount::checked_sum(
            self.residual_inputs.iter().map(|input| input.amount),
        )?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReclaimDestinationRequest {
    /// Explicit user-selected destination, never derived from original senders.
    pub address: String,
    pub user_controlled_account_ref: String,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShieldedReceiverPool {
    /// Explicit pool identity, not a claim that native retirement is qualified.
    Ironwood,
    Orchard,
    Sapling,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserControlledShieldedDestination {
    pub address: String,
    pub user_controlled_account_ref: String,
    pub network_profile_id: String,
    pub pool: ShieldedReceiverPool,
    pub ownership_source_ref: String,
    pub ownership_evidence_digest: String,
}
impl fmt::Debug for UserControlledShieldedDestination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UserControlledShieldedDestination { private_contents: [REDACTED] }")
    }
}
impl UserControlledShieldedDestination {
    fn validate_for(
        &self,
        request: &ReclaimDestinationRequest,
        network: &str,
        source_account: &str,
    ) -> Result<()> {
        validate_address_text(&self.address)?;
        validate_id(&self.user_controlled_account_ref, "destination account")?;
        validate_id(&self.ownership_source_ref, "destination ownership source")?;
        validate_sha256(&self.ownership_evidence_digest)?;
        if self.address != request.address
            || self.user_controlled_account_ref != request.user_controlled_account_ref
            || self.network_profile_id != network
            || self.user_controlled_account_ref == source_account
        {
            return Err(CoreError::new(ErrorCode::MissingEvidence, "reclaim needs the explicit independently checked user-controlled shielded destination on the same network and outside the retiring account"));
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReclaimFeeQuote {
    pub quote_ref: String,
    pub fee: Amount,
    pub input_set_digest: String,
    pub destination_digest: String,
    pub expires_at: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReclaimRequest {
    pub plan_id: String,
    pub account_id: String,
    pub network_profile_id: String,
    pub destination: ReclaimDestinationRequest,
    pub maximum_fee: Amount,
    pub maximum_net_debit: Amount,
}
/// Trusted account/chain/ownership adapter. History reconciliation includes all
/// retained alternatives, durable released intents, current writer continuity,
/// and qualified conflict/expiry evidence. This is not implemented by accepting
/// an app's serialized ExposureHistoryState or prefix-matching an address.
pub trait AccountRecoverySource {
    fn read_recovery_view(&mut self, account_id: &str) -> Result<AccountRecoveryView>;
    fn verify_destination(
        &mut self,
        request: &ReclaimDestinationRequest,
        network: &str,
    ) -> Result<UserControlledShieldedDestination>;
    fn quote_residual_transfer(
        &mut self,
        view: &AccountRecoveryView,
        destination: &UserControlledShieldedDestination,
    ) -> Result<ReclaimFeeQuote>;
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct AccountRetirementPlan {
    request: ReclaimRequest,
    snapshot: AccountRecoveryView,
    destination: UserControlledShieldedDestination,
    fee_quote: ReclaimFeeQuote,
    transfer_amount: Amount,
    maximum_net_debit: Amount,
    plan_digest: String,
    viewing_key_exposure: String,
}
impl fmt::Debug for AccountRetirementPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AccountRetirementPlan { private_contents: [REDACTED] }")
    }
}
impl AccountRetirementPlan {
    /// Plans a transfer of all known residual inputs less the explicit source
    /// fee quote. This is an unsigned proposal and creates no spending authority.
    pub fn prepare(
        source: &mut impl AccountRecoverySource,
        request: ReclaimRequest,
        window: &ObservationWindow,
    ) -> Result<Self> {
        for id in [
            &request.plan_id,
            &request.account_id,
            &request.network_profile_id,
            &request.destination.user_controlled_account_ref,
        ] {
            validate_id(id, "reclaim request identity")?;
        }
        validate_address_text(&request.destination.address)?;
        let snapshot = source.read_recovery_view(&request.account_id)?;
        snapshot.validate(&request.account_id, &request.network_profile_id, window)?;
        snapshot.require_reclaimable()?;
        let balance = snapshot.known_residual_balance()?;
        if balance == Amount::ZERO {
            return Err(CoreError::new(ErrorCode::InvalidTerms, "no residual transfer is needed; use empty-account retirement after exposure reconciliation"));
        }
        if balance > request.maximum_net_debit {
            return Err(CoreError::new(
                ErrorCode::DebitCapExceeded,
                "residual transfer would exceed the user's complete debit cap",
            ));
        }
        let destination =
            source.verify_destination(&request.destination, &request.network_profile_id)?;
        destination.validate_for(
            &request.destination,
            &request.network_profile_id,
            &request.account_id,
        )?;
        let fee_quote = source.quote_residual_transfer(&snapshot, &destination)?;
        validate_id(&fee_quote.quote_ref, "reclaim fee quote")?;
        validate_timestamp(&fee_quote.expires_at)?;
        if fee_quote.expires_at <= window.now
            || fee_quote.input_set_digest != reclaim_input_digest(&snapshot.residual_inputs)?
            || fee_quote.destination_digest != reclaim_destination_digest(&destination)?
        {
            return Err(CoreError::new(
                ErrorCode::MissingEvidence,
                "reclaim fee quote is expired or for different exact inputs/destination",
            ));
        }
        if fee_quote.fee > request.maximum_fee {
            return Err(CoreError::new(
                ErrorCode::FeeCapExceeded,
                "reclaim fee exceeds the separately reviewed fee cap",
            ));
        }
        if fee_quote.fee >= balance {
            return Err(CoreError::new(
                ErrorCode::InvalidAmount,
                "residual balance does not cover a positive transfer after fees",
            ));
        }
        let transfer_amount = balance.checked_sub(fee_quote.fee)?;
        let plan_digest = canonical_digest(
            "wholepact:retirement-plan:v1",
            &(
                &request,
                &snapshot,
                &destination,
                &fee_quote,
                transfer_amount,
                balance,
                VIEWING_KEY_EXPOSURE_STATEMENT,
            ),
        )?;
        Ok(Self {
            request,
            snapshot,
            destination,
            fee_quote,
            transfer_amount,
            maximum_net_debit: balance,
            plan_digest,
            viewing_key_exposure: VIEWING_KEY_EXPOSURE_STATEMENT.into(),
        })
    }
    pub fn digest(&self) -> &str {
        &self.plan_digest
    }
    pub fn request(&self) -> &ReclaimRequest {
        &self.request
    }
    pub fn destination(&self) -> &UserControlledShieldedDestination {
        &self.destination
    }
    pub fn inputs(&self) -> &[ResidualInput] {
        &self.snapshot.residual_inputs
    }
    pub fn transfer_amount(&self) -> Amount {
        self.transfer_amount
    }
    pub fn fee(&self) -> Amount {
        self.fee_quote.fee
    }
    pub fn maximum_net_debit(&self) -> Amount {
        self.maximum_net_debit
    }
    pub fn viewing_key_exposure(&self) -> &str {
        &self.viewing_key_exposure
    }
    /// Freshness/history and exact review are checked again before handing an
    /// unsigned request to the separate external signer/authorization workflow.
    pub fn review_for_separate_authorization(
        &self,
        source: &mut impl AccountRecoverySource,
        review: &mut impl ReclaimReviewSource,
        window: &ObservationWindow,
    ) -> Result<ReviewedReclaimPlan> {
        let current = source.read_recovery_view(&self.request.account_id)?;
        current.validate(
            &self.request.account_id,
            &self.request.network_profile_id,
            window,
        )?;
        current.require_reclaimable()?;
        // Time can advance without changing economic facts or authority history.
        let mut snapshot = self.snapshot.clone();
        snapshot.observed_at = current.observed_at.clone();
        if current != snapshot || self.fee_quote.expires_at <= window.now {
            return Err(CoreError::new(ErrorCode::RevisionConflict, "account, exposure or fee quote changed; prepare and review a new exact reclaim plan"));
        }
        let destination = source
            .verify_destination(&self.request.destination, &self.request.network_profile_id)?;
        destination.validate_for(
            &self.request.destination,
            &self.request.network_profile_id,
            &self.request.account_id,
        )?;
        if destination != self.destination {
            return Err(CoreError::new(
                ErrorCode::RevisionConflict,
                "destination ownership evidence changed since review",
            ));
        }
        match review.review_reclaim(self)? {
            ReclaimReviewDecision::Rejected => Err(CoreError::new(
                ErrorCode::UserRejected,
                "residual transfer review was rejected",
            )),
            ReclaimReviewDecision::Accepted {
                plan_digest,
                review_record_ref,
            } => {
                validate_id(&review_record_ref, "reclaim review reference")?;
                if plan_digest != self.plan_digest {
                    return Err(CoreError::new(
                        ErrorCode::RevisionConflict,
                        "review accepted a different reclaim plan",
                    ));
                }
                Ok(ReviewedReclaimPlan {
                    plan: self.clone(),
                    review_record_ref,
                })
            }
        }
    }
}
pub fn reclaim_input_digest(inputs: &[ResidualInput]) -> Result<String> {
    canonical_digest("wholepact:reclaim-inputs:v1", &inputs)
}
pub fn reclaim_destination_digest(
    destination: &UserControlledShieldedDestination,
) -> Result<String> {
    canonical_digest("wholepact:reclaim-destination:v1", destination)
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReclaimReviewDecision {
    Rejected,
    Accepted {
        plan_digest: String,
        review_record_ref: String,
    },
}
pub trait ReclaimReviewSource {
    fn review_reclaim(&mut self, plan: &AccountRetirementPlan) -> Result<ReclaimReviewDecision>;
}
/// There is deliberately no `sign` or `execute` method and no boolean approval
/// field which a client can promote to spending authority.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct ReviewedReclaimPlan {
    plan: AccountRetirementPlan,
    review_record_ref: String,
}
impl fmt::Debug for ReviewedReclaimPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReviewedReclaimPlan { separate_transfer_authorization: REQUIRED }")
    }
}
impl ReviewedReclaimPlan {
    pub fn plan(&self) -> &AccountRetirementPlan {
        &self.plan
    }
    pub fn review_record_ref(&self) -> &str {
        &self.review_record_ref
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReclaimSettlementEvidence {
    pub plan_digest: String,
    pub authorization_record_ref: String,
    pub release_operation_id: String,
    pub input_set_digest: String,
    pub destination: UserControlledShieldedDestination,
    pub amount: Amount,
    pub fee: Amount,
    pub chain: SourcedChainObservation,
}
impl fmt::Debug for ReclaimSettlementEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReclaimSettlementEvidence { private_contents: [REDACTED] }")
    }
}
/// Independently verifies the separately authorized exact transaction against
/// its protected signer/release journal and maintained transaction decoder, and
/// observes the recipient output and canonical inclusion. Not a signing API.
pub trait ReclaimSettlementSource {
    fn observe_separately_authorized_reclaim(
        &mut self,
        plan: &ReviewedReclaimPlan,
    ) -> Result<ReclaimSettlementEvidence>;
}
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct RetiredAccountRecord {
    account_id: String,
    network_profile_id: String,
    retired_at: String,
    reclaim_transaction: Option<ExactTransactionReference>,
    retained_history_checkpoint: String,
    viewing_key_disclosure_refs: Vec<String>,
    viewing_key_exposure: String,
}
impl fmt::Debug for RetiredAccountRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "RetiredAccountRecord { private_contents: [REDACTED], routine_reuse: DISABLED }",
        )
    }
}
impl RetiredAccountRecord {
    pub fn account_id(&self) -> &str {
        &self.account_id
    }
    pub fn viewing_key_exposure(&self) -> &str {
        &self.viewing_key_exposure
    }
    /// Product policy is immutable; retirement cannot be undone to make the
    /// previously disclosed account eligible for unrelated routine reuse.
    pub fn routine_reuse_allowed(&self) -> bool {
        false
    }
    pub fn reclaim_transaction(&self) -> Option<&ExactTransactionReference> {
        self.reclaim_transaction.as_ref()
    }
    pub fn retire_empty_account(
        source: &mut impl AccountRecoverySource,
        account_id: &str,
        network: &str,
        window: &ObservationWindow,
    ) -> Result<Self> {
        let snapshot = source.read_recovery_view(account_id)?;
        snapshot.validate(account_id, network, window)?;
        snapshot.require_reclaimable()?;
        Self::from_empty_view(snapshot, window, None)
    }
    pub fn after_reclaim(
        source: &mut impl AccountRecoverySource,
        settlement: &mut impl ReclaimSettlementSource,
        reviewed: &ReviewedReclaimPlan,
        chain_policy: &ObservationPolicy,
        required_confirmations: u32,
        window: &ObservationWindow,
    ) -> Result<Self> {
        window.validate()?;
        chain_policy.validate()?;
        if required_confirmations == 0 || required_confirmations > 10_000 {
            return Err(CoreError::new(
                ErrorCode::InvalidTerms,
                "retirement requires a nonzero explicit confirmation policy",
            ));
        }
        let evidence = settlement.observe_separately_authorized_reclaim(reviewed)?;
        let plan = &reviewed.plan;
        for id in [
            &evidence.authorization_record_ref,
            &evidence.release_operation_id,
        ] {
            validate_id(id, "separate reclaim authorization provenance")?;
        }
        if evidence.plan_digest != plan.plan_digest
            || evidence.input_set_digest != reclaim_input_digest(plan.inputs())?
            || evidence.destination != plan.destination
            || evidence.amount != plan.transfer_amount
            || evidence.fee != plan.fee()
            || evidence.chain.transaction.network_profile_id != plan.request.network_profile_id
        {
            return Err(CoreError::new(
                ErrorCode::RevisionConflict,
                "settled reclaim differs from the separately reviewed exact effects",
            ));
        }
        evidence
            .chain
            .validate_for(&evidence.chain.transaction, chain_policy)?;
        let observation = &evidence.chain.observation;
        if !window.contains(&observation.observed_at)
            || !matches!(
                observation.status,
                ChainStatus::Included | ChainStatus::ConfirmationPolicyMet
            )
            || observation.confirmations < required_confirmations
        {
            return Err(CoreError::new(ErrorCode::StaleChain, "reclaim is not currently included under the retirement confirmation policy; keep observing"));
        }
        let snapshot = source.read_recovery_view(&plan.request.account_id)?;
        snapshot.validate(
            &plan.request.account_id,
            &plan.request.network_profile_id,
            window,
        )?;
        snapshot.require_reclaimable()?;
        Self::from_empty_view(snapshot, window, Some(evidence.chain.transaction))
    }
    fn from_empty_view(
        snapshot: AccountRecoveryView,
        window: &ObservationWindow,
        transaction: Option<ExactTransactionReference>,
    ) -> Result<Self> {
        if snapshot.known_residual_balance()? != Amount::ZERO {
            return Err(CoreError::new(ErrorCode::OutstandingExposure, "residual funds remain; retirement completion needs another separately reviewed recovery step"));
        }
        let ExposureHistoryState::Reconciled {
            journal_checkpoint_digest,
            ..
        } = snapshot.history
        else {
            return Err(CoreError::new(
                ErrorCode::RecoveryRequired,
                "retirement cannot discard unknown authorization history",
            ));
        };
        Ok(Self {
            account_id: snapshot.account_id,
            network_profile_id: snapshot.network_profile_id,
            retired_at: window.now.clone(),
            reclaim_transaction: transaction,
            retained_history_checkpoint: journal_checkpoint_digest,
            viewing_key_disclosure_refs: snapshot.viewing_key_disclosure_refs,
            viewing_key_exposure: VIEWING_KEY_EXPOSURE_STATEMENT.into(),
        })
    }
    /// A reorg reopens recovery/observation work; it never permits routine reuse.
    pub fn reconcile_after_reorganization(&self) -> RetirementRecoveryRequired {
        RetirementRecoveryRequired { account: self.clone(), reason: "Reconcile the original and reclaim transactions and every retained authorization; no automatic replacement or routine account reuse is permitted.".into() }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RetirementRecoveryRequired {
    pub account: RetiredAccountRecord,
    pub reason: String,
}
