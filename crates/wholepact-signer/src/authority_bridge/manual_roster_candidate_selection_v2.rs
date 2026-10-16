//! Maintained viewing-key consumer for the genuine separately reviewed candidate-selection lease.
//!
//! This wrapper owns the installed-peer lease, including its original wall and
//! monotonic deadlines. It does not accept a wire response, account identifier,
//! viewing-key byte array, approval flag or caller-defined permission callback.
//! Host scan consent, exact wallet destination and provider checks remain separate.
//! Every access below checks the live lease. Viewing data already copied or
//! imported into a wallet cannot be recalled when the native owner revokes it.
use super::{BridgeError, Result};
use orchard::keys::FullViewingKey;
use sha2::{Digest, Sha256};
use wholepact_core::manual_roster_candidate_selection_v2::ManualRosterCandidateSelectionRequestV2;
use wholepact_signer_origin::{
    ManualRosterCandidateSelectionLeaseV2,
    manual_roster_candidate_selection_v2::ManualRosterCandidateSelectionEvidenceV2,
};
use wholepact_wallet::wallet::{AccountUuid, protected_sync::ProtectedWalletSync};
use zeroize::Zeroizing;

/// Candidate-selection viewing owner. No Clone, Debug, Serialize or Deserialize and
/// no conversion into construction admission or key-use authority. Actual local
/// selection still needs the separate Host gate; it is never full-proposal consent.
/// Dropping it also drops the real lower lease and its current-channel slot.
///
/// Orchard's maintained FullViewingKey does not implement Zeroize. Temporary
/// raw encodings and the lower retained bytes are zeroized, but this type makes
/// no secure-memory or revocation-of-already-disclosed-data claim.
pub struct SignerRosterCandidateSelectionLeaseV2<'client> {
    native: ManualRosterCandidateSelectionLeaseV2<'client>,
    fvk: FullViewingKey,
    selection_attempted: std::sync::atomic::AtomicBool,
    selected_facts_digest: std::sync::Mutex<Option<String>>,
}
impl<'client> SignerRosterCandidateSelectionLeaseV2<'client> {
    /// Consume this viewing owner and complete the exact native channel before
    /// any separate purpose is paired. Imported data cannot be recalled.
    pub fn finish(self) -> Result<()> {
        self.native.finish().map_err(Into::into)
    }

    /// Consume only the real installed-peer result of the candidate-selection native
    /// disclosure. This does not renew any deadline or create scan permission.
    pub fn from_native_lease(
        native: ManualRosterCandidateSelectionLeaseV2<'client>,
    ) -> Result<Self> {
        native.check_current()?;
        native.evidence().validate()?;
        let expected = &native
            .binding()
            .scope
            .selection
            .inventory
            .enrollment
            .identity
            .full_viewing_key_digest;
        let fvk = decode_inventory_fvk(native.full_viewing_key_bytes()?, expected)?;
        native.check_current()?;
        Ok(Self {
            native,
            fvk,
            selection_attempted: std::sync::atomic::AtomicBool::new(false),
            selected_facts_digest: std::sync::Mutex::new(None),
        })
    }

    pub fn requested_debit_zatoshis(&self) -> Result<u64> {
        self.check_current()?;
        self.native
            .binding()
            .scope
            .requested_debit_zatoshis()
            .map_err(|_| BridgeError::Binding)
    }

    /// Exactly ONE maintained local selection attempt. Failure consumes it too.
    /// No note-reference prefilter is supplied here: the Host MUST check every
    /// actual selected input/nullifier against its conservative exclusions and
    /// drop conflicts before retaining evidence. Empty prefilter is NOT evidence
    /// of empty exclusions. This never reserves funds or authorizes construction.
    pub fn select_contribution(
        &self,
        wallet: &mut ProtectedWalletSync,
        access: &impl wholepact_wallet::wallet::protected_sync::LocalWalletAccess,
    ) -> Result<wholepact_wallet::wallet::protected_sync::ProtectedContribution> {
        consume_selection_attempt(&self.selection_attempted)?;
        self.check_current()?;
        self.verify_wallet_account(wallet)?;
        let request = self.request()?;
        let scope = &request.scope.selection.inventory;
        let status = wallet.status().map_err(|_| BridgeError::Verification)?;
        if status.minimum_confirmations != scope.minimum_confirmations
            || status.source.source_id != scope.provider.source_id
            || status.source.endpoint != scope.provider.endpoint
            || status.source.trust_profile != scope.provider.trust_profile
        {
            return Err(BridgeError::Binding);
        }
        let debit = request
            .scope
            .requested_debit_zatoshis()
            .map_err(|_| BridgeError::Binding)?;
        let selected = wallet
            .select_contribution(
                access,
                &self.fvk,
                &scope.enrollment.identity.account_id,
                debit,
                &[],
            )
            .map_err(|_| BridgeError::Verification)?;
        self.check_current()?;
        selected
            .check_current()
            .map_err(|_| BridgeError::Permission)?;
        let actual = selected.selection();
        if actual.account_id() != scope.enrollment.identity.account_id
            || actual.requested_debit_zatoshis() != debit
            || actual.context().anchor_height != scope.anchor_height
            || actual.fvk().to_bytes() != self.fvk.to_bytes()
            || self.fvk.scope_for_address(&actual.change_address())
                != Some(orchard::keys::Scope::Internal)
        {
            return Err(BridgeError::Binding);
        }
        self.check_current()?;
        *self
            .selected_facts_digest
            .lock()
            .map_err(|_| BridgeError::Permission)? =
            Some(facts_digest(&selected_facts(&selected)?)?);
        Ok(selected)
    }

    /// Checks the actual installed process, exact evidence challenge, original
    /// native/request deadlines and revocation state. Failure is not renewable.
    pub fn check_current(&self) -> Result<()> {
        self.native.check_current().map_err(Into::into)
    }

    /// Exact reviewed request from the held native channel, not a caller claim.
    pub fn request(&self) -> Result<&ManualRosterCandidateSelectionRequestV2> {
        self.check_current()?;
        Ok(self.native.binding())
    }

    /// Audit material only. Copying it cannot recreate this viewing owner.
    pub fn evidence(&self) -> Result<&ManualRosterCandidateSelectionEvidenceV2> {
        self.check_current()?;
        Ok(self.native.evidence())
    }

    pub fn provider_enrollment_reference(&self) -> Result<&str> {
        self.check_current()?;
        Ok(self.native.provider_enrollment_reference())
    }

    /// Borrow the maintained FVK for the exactly approved wallet import. The
    /// caller must still use its concrete original destination/disclosure owner.
    /// A cloned FVK is private data, never a replacement for this current lease.
    pub fn fvk(&self) -> Result<&FullViewingKey> {
        self.check_current()?;
        Ok(&self.fvk)
    }

    /// Read the actual dedicated wallet's maintained account and compare its
    /// Orchard FVK before returning that wallet's UUID. No caller UUID or bytes
    /// enter this check. The Host must keep using this same protected wallet and
    /// independently enforce its held exact destination and provider binding.
    /// This is an identity check only; it does not authorize a scan or selection.
    pub fn verify_wallet_account(&self, wallet: &ProtectedWalletSync) -> Result<AccountUuid> {
        self.check_current()?;
        wallet
            .verify_account_fvk(&self.fvk)
            .map_err(|_| BridgeError::Verification)?;
        let account = wallet.account_uuid();
        self.check_current()?;
        Ok(account)
    }
}

fn consume_selection_attempt(attempted: &std::sync::atomic::AtomicBool) -> Result<()> {
    use std::sync::atomic::Ordering;
    attempted
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map(|_| ())
        .map_err(|_| BridgeError::Permission)
}

/// Pure maintained-library validation, deliberately private. Returning a parsed
/// key here cannot construct a native lease or the public wrapper.
fn decode_inventory_fvk(raw: &[u8; 96], expected_digest: &str) -> Result<FullViewingKey> {
    let fvk = FullViewingKey::from_bytes(raw).ok_or(BridgeError::Verification)?;
    let canonical = Zeroizing::new(fvk.to_bytes());
    if canonical.as_slice() != raw
        || hex::encode(Sha256::digest(canonical.as_slice())) != expected_digest
    {
        return Err(BridgeError::Binding);
    }
    Ok(fvk)
}

use wholepact_core::manual_construction::{ManualConstructionInput, ManualSelectionContext};
use wholepact_core::manual_roster_construction_v2::ManualRosterContributionRetentionRequestV2;
use wholepact_signer_origin::manual_roster_construction_v2::ManualRosterContributionRetentionEvidenceV2;
use wholepact_signer_origin::{
    PendingManualRosterContributionRetentionV2, RetainedManualRosterContributionV2,
};
use wholepact_wallet::wallet::protected_sync::ProtectedContribution;
use wholepact_wallet::wallet::protected_sync::exact_input_observation::{
    ExactInputVerifierSnapshot, FreshExactInputObservation, HeldExactRosterObservation,
    RetainedExactWalletMaterial,
};

impl<'client> SignerRosterCandidateSelectionLeaseV2<'client> {
    /// Consume this exact live selection gate and its actual returned maintained
    /// contribution before closing the native phase. Caller data is limited to
    /// the operation identity, checked local exclusion commitment and a SHORTER
    /// original admission deadline; private input/change facts are derived here.
    pub fn begin_retention(
        self,
        selected: ProtectedContribution,
        operation_id: String,
        local_exclusion_digest: String,
        requested_at_ms: u64,
        admission_expires_at_ms: u64,
        original_completion_deadline: std::time::Instant,
    ) -> Result<PendingSignerRosterContributionRetentionV2<'client>> {
        self.check_current()?;
        selected
            .check_current()
            .map_err(|_| BridgeError::Permission)?;
        let facts = selected_facts(&selected)?;
        if self
            .selected_facts_digest
            .lock()
            .map_err(|_| BridgeError::Permission)?
            .as_deref()
            != Some(facts_digest(&facts)?.as_str())
        {
            return Err(BridgeError::Binding);
        }
        let (selected_inputs, selection_context, change_address, change_value_zatoshis) = facts;
        let request = ManualRosterContributionRetentionRequestV2 {
            version: 2,
            operation_id,
            selection: self.native.binding().clone(),
            selection_evidence_digest: self.native.evidence().digest()?,
            selected_inputs,
            selection_context,
            local_exclusion_digest,
            change_address,
            change_value_zatoshis,
            requested_at_ms,
            admission_expires_at_ms,
        };
        request.validate().map_err(|_| BridgeError::Binding)?;
        let pending = self
            .native
            .begin_retention(request, original_completion_deadline)?;
        Ok(PendingSignerRosterContributionRetentionV2 { pending, selected })
    }
}
pub struct PendingSignerRosterContributionRetentionV2<'client> {
    pending: PendingManualRosterContributionRetentionV2<'client>,
    selected: ProtectedContribution,
}
impl PendingSignerRosterContributionRetentionV2<'_> {
    pub fn finish(self) -> Result<SignerRetainedRosterContributionV2> {
        let native = self.pending.finish()?;
        self.selected
            .check_current()
            .map_err(|_| BridgeError::Permission)?;
        let result = SignerRetainedRosterContributionV2 {
            native,
            selected: RetainedExactWalletMaterial::from_current(self.selected)
                .map_err(|_| BridgeError::Permission)?,
        };
        result.check_retained()?;
        Ok(result)
    }
}
/// Sequential non-signing private-data owner. Actual wallet material and the
/// original source-generation/freshness guard remain owned here; DTOs cannot
/// recreate this object. NO current GUI lease is retained or claimed.
pub struct SignerRetainedRosterContributionV2 {
    native: RetainedManualRosterContributionV2,
    selected: RetainedExactWalletMaterial,
}
impl SignerRetainedRosterContributionV2 {
    pub fn check_retained(&self) -> Result<()> {
        self.native.check_retained()?;
        // Original process lineage and immutable facts remain historical after
        // provider TTL expiry. This grants no fresh wallet or constructor read.
        self.selected
            .check_retained_lineage()
            .map_err(|_| BridgeError::Permission)?;
        let facts = retained_selection_facts(self.selected.selection())?;
        let r = self.native.request()?;
        if facts.0 != r.selected_inputs
            || facts.1 != r.selection_context
            || facts.2 != r.change_address
            || facts.3 != r.change_value_zatoshis
        {
            return Err(BridgeError::Binding);
        }
        Ok(())
    }
    pub fn request(&self) -> Result<&ManualRosterContributionRetentionRequestV2> {
        self.check_retained()?;
        self.native.request().map_err(Into::into)
    }
    pub fn evidence(&self) -> Result<&ManualRosterContributionRetentionEvidenceV2> {
        self.check_retained()?;
        Ok(self.native.evidence())
    }
    pub fn durable_receipt_digest(&self) -> &str {
        self.native.durable_receipt_digest()
    }
    pub fn provider_enrollment_reference(&self) -> &str {
        self.native.provider_enrollment_reference()
    }
    // Deliberately no into_current_contribution until an actual fresh exact
    // full-proposal witness-consumed construction owner is supplied.
}
impl SignerRetainedRosterContributionV2 {
    pub fn check_held(&self, held: &HeldExactRosterObservation<'_>) -> Result<()> {
        self.check_retained()?;
        held.check_all_current()
            .map_err(|_| BridgeError::Permission)?;
        held.matches_material(&self.selected)
            .map_err(|_| BridgeError::Binding)
    }
    pub fn begin_exact_input_observation_before<'client>(
        &'client self,
        client: &'client wholepact_signer_origin::NativeManualClient,
        request: &wholepact_core::manual_roster_exact_input_observation_v1::ManualRosterExactInputObservationRequestV1,
        expected_current_attempt_digest: &str,
        expected_current_attempt_sequence: u64,
        deadline: std::time::Instant,
        original_host_deadline: std::time::Instant,
    ) -> Result<wholepact_signer_origin::PendingRosterExactInputObservationV1<'client>> {
        self.check_retained()?;
        if request.plan.retained != *self.native.request()?
            || request.plan.retained_evidence_digest != self.native.evidence().digest()?
            || request.original_durable_receipt_digest != self.native.durable_receipt_digest()
        {
            return Err(BridgeError::Binding);
        }
        client
            .begin_roster_exact_input_observation_before(
                request,
                &self.native,
                expected_current_attempt_digest,
                expected_current_attempt_sequence,
                deadline,
                original_host_deadline,
            )
            .map_err(Into::into)
    }
    pub async fn observe_exact_inputs(
        &mut self,
        wallet: &mut ProtectedWalletSync,
        admitted: wholepact_signer_origin::AdmittedRosterExactInputObservationV1,
        access: &impl wholepact_wallet::wallet::protected_sync::LocalWalletAccess,
    ) -> std::result::Result<
        FreshExactInputObservation,
        wholepact_wallet::wallet::protected_sync::exact_input_observation::ExactObservationError,
    > {
        use wholepact_wallet::wallet::protected_sync::exact_input_observation::ExactObservationError as E;
        self.check_retained().map_err(|_| E::Permission)?;
        let request = admitted.request().map_err(|_| E::Permission)?;
        if request.plan.retained != *self.native.request().map_err(|_| E::Permission)?
            || request.plan.retained_evidence_digest
                != self.native.evidence().digest().map_err(|_| E::Binding)?
            || request.original_durable_receipt_digest != self.native.durable_receipt_digest()
        {
            return Err(E::Binding);
        }
        let fresh = wallet
            .observe_retained_exact_inputs(&mut self.selected, admitted, access)
            .await?;
        self.check_retained().map_err(|_| E::Permission)?;
        fresh.check_current()?;
        Ok(fresh)
    }
    pub fn exact_verifier_snapshot(
        &self,
        fresh: &FreshExactInputObservation,
    ) -> Result<ExactInputVerifierSnapshot> {
        self.check_retained()?;
        fresh
            .prepare_verifier(&self.selected)
            .map_err(|_| BridgeError::Permission)
    }
}

type SelectedFacts = (
    Vec<ManualConstructionInput>,
    ManualSelectionContext,
    String,
    u64,
);
fn selected_facts(selected: &ProtectedContribution) -> Result<SelectedFacts> {
    selected
        .check_current()
        .map_err(|_| BridgeError::Permission)?;
    retained_selection_facts(selected.selection())
}
fn retained_selection_facts(
    actual: &wholepact_wallet::wallet::WalletContribution,
) -> Result<SelectedFacts> {
    let evidence = actual.evidence();
    let c = actual.context();
    let mut inputs: Vec<_> = evidence
        .inputs()
        .iter()
        .map(|i| ManualConstructionInput {
            input_id: i.input_id().into(),
            nullifier: hex::encode(i.nullifier()),
            value_zatoshis: i.value_zatoshis(),
        })
        .collect();
    inputs.sort_by(|a, b| a.input_id.cmp(&b.input_id));
    Ok((
        inputs,
        ManualSelectionContext {
            tip_height: c.tip_height,
            tip_hash_protocol: hex::encode(c.tip_hash_protocol),
            anchor_height: c.anchor_height,
            anchor_hash_protocol: hex::encode(c.anchor_hash_protocol),
            anchor_root: hex::encode(c.anchor_root),
        },
        wholepact_protocol::review::encode_testnet_receiver(&actual.change_address()),
        actual
            .selected_zatoshis()
            .checked_sub(actual.requested_debit_zatoshis())
            .ok_or(BridgeError::Binding)?,
    ))
}
fn facts_digest(facts: &SelectedFacts) -> Result<String> {
    wholepact_core::proposal::canonical_digest("wholepact:actual-roster-selection-facts:v2", facts)
        .map_err(|_| BridgeError::Binding)
}

use wholepact_signer_origin::AdmittedManualRosterConstructionContributionV2;
impl SignerRetainedRosterContributionV2 {
    /// Both original owned wallet selection and actual newly native/witness
    /// consumed full-proposal owner are consumed together. A plan/evidence DTO
    /// cannot substitute for either. Call only after durable whole-roster claim.
    pub fn into_construction(
        self,
        admitted: AdmittedManualRosterConstructionContributionV2,
        held: &HeldExactRosterObservation<'_>,
    ) -> Result<SignerConsumedRosterConstructionV2> {
        self.check_held(held)?;
        admitted.check_completion()?;
        let request = admitted.request()?;
        if request.plan.retained != *self.native.request()?
            || request.plan.retained_evidence_digest != self.native.evidence().digest()?
            || admitted.evidence().retained_signer_intent_digest
                != self.native.evidence().retained_signer_intent_digest
            || admitted.evidence().current_attempt_sequence
                <= self
                    .native
                    .request()?
                    .selection
                    .scope
                    .selection
                    .inventory
                    .attempt
                    .attempt_sequence
        {
            return Err(BridgeError::Binding);
        }
        let value = SignerConsumedRosterConstructionV2 {
            retained: self,
            admitted,
        };
        value.check_current(held)?;
        Ok(value)
    }
}
/// Both one-use sources remain alive through the Engine's exact claim and
/// constructor conjunction, with their original independent deadlines/guards.
pub struct SignerConsumedRosterConstructionV2 {
    retained: SignerRetainedRosterContributionV2,
    admitted: AdmittedManualRosterConstructionContributionV2,
}
impl SignerConsumedRosterConstructionV2 {
    pub fn check_current(&self, held: &HeldExactRosterObservation<'_>) -> Result<()> {
        self.retained.check_held(held)?;
        self.admitted.check_completion().map_err(Into::into)
    }
    pub fn plan(
        &self,
        held: &HeldExactRosterObservation<'_>,
    ) -> Result<&wholepact_core::manual_roster_construction_v2::ManualRosterConstructionPlanV2>
    {
        self.check_current(held)?;
        Ok(&self.admitted.request()?.plan)
    }
    pub fn evidence(&self)->&wholepact_signer_origin::manual_roster_construction_v2::ManualRosterConstructionContributionEvidenceV2{
        self.admitted.evidence()
    }
    /// Only the actual held maintained roster can extract original private
    /// construction material; generic selection/freshness APIs are unchanged.
    pub fn into_exact_parts(
        self,
        held: &HeldExactRosterObservation<'_>,
    ) -> Result<(
        wholepact_protocol::construction::OwnedContribution,
        wholepact_protocol::construction::ConstructionContext,
        SignerRosterConstructionCompletionGuardV2,
    )> {
        self.check_current(held)?;
        let (contribution, context) = self
            .retained
            .selected
            .into_construction(held)
            .map_err(|_| BridgeError::Permission)?;
        Ok((
            contribution,
            context,
            SignerRosterConstructionCompletionGuardV2 {
                retention: self.retained.native,
                admitted: self.admitted,
            },
        ))
    }
}

/// One-use completion guard retained by the concrete Engine around randomized
/// construction and checkpoint persistence. It does not recreate source data.
pub struct SignerRosterConstructionCompletionGuardV2 {
    retention: RetainedManualRosterContributionV2,
    admitted: AdmittedManualRosterConstructionContributionV2,
}
impl SignerRosterConstructionCompletionGuardV2 {
    pub fn check_current(&self) -> Result<()> {
        self.retention.check_retained()?;
        self.admitted.check_completion().map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use orchard::keys::SpendingKey;
    #[test]
    fn selection_attempt_stays_consumed_after_error_or_expiry() {
        let attempted = std::sync::atomic::AtomicBool::new(false);
        assert!(consume_selection_attempt(&attempted).is_ok());
        // The attempt was consumed before native checks or any wallet call.
        assert!(consume_selection_attempt(&attempted).is_err());
        assert!(consume_selection_attempt(&attempted).is_err());
    }
    #[test]
    fn maintained_change_must_belong_to_the_authenticated_internal_account() {
        let fvk = FullViewingKey::from_bytes(&fixture(21)).unwrap();
        let other = FullViewingKey::from_bytes(&fixture(22)).unwrap();
        assert_eq!(
            fvk.scope_for_address(&fvk.address_at(0u32, orchard::keys::Scope::Internal)),
            Some(orchard::keys::Scope::Internal)
        );
        assert_eq!(
            fvk.scope_for_address(&other.address_at(0u32, orchard::keys::Scope::Internal)),
            None
        );
        assert_ne!(
            fvk.scope_for_address(&fvk.address_at(0u32, orchard::keys::Scope::External)),
            Some(orchard::keys::Scope::Internal)
        );
    }

    // Public synthetic never-funded fixture. These tests construct no native
    // owner, lower lease, wallet-access permission or wrapper instance.
    fn fixture(byte: u8) -> Zeroizing<[u8; 96]> {
        let spending =
            SpendingKey::from_zip32_seed(&[byte; 64], 1, 0u32.try_into().unwrap()).unwrap();
        Zeroizing::new(FullViewingKey::from(&spending).to_bytes())
    }

    #[test]
    fn maintained_inventory_key_matches_exact_authenticated_digest() {
        let raw = fixture(11);
        let expected = hex::encode(Sha256::digest(raw.as_slice()));
        let decoded = decode_inventory_fvk(&raw, &expected).unwrap();
        assert!(decoded.to_bytes() == *raw);
        let other = fixture(12);
        let wrong = hex::encode(Sha256::digest(other.as_slice()));
        assert!(matches!(
            decode_inventory_fvk(&raw, &wrong),
            Err(BridgeError::Binding)
        ));
    }

    #[test]
    fn matching_hash_does_not_make_invalid_orchard_bytes_a_viewing_key() {
        let invalid = Zeroizing::new([0xffu8; 96]);
        let expected = hex::encode(Sha256::digest(invalid.as_slice()));
        assert!(matches!(
            decode_inventory_fvk(&invalid, &expected),
            Err(BridgeError::Verification)
        ));
    }

    #[test]
    fn noncanonical_or_missing_digest_is_rejected_without_owner_factory() {
        let raw = fixture(13);
        let expected = hex::encode(Sha256::digest(raw.as_slice()));
        for invalid in [String::new(), "0".repeat(63), expected.to_uppercase()] {
            assert!(decode_inventory_fvk(&raw, &invalid).is_err());
        }
    }
}

#[path = "manual_roster_common_context_v3.rs"]
mod common_context_v3;
pub use common_context_v3::{
    PendingSignerCommonContextReadV1, PendingSignerCommonContextReentryV1,
    SignerConsumedRosterConstructionV3,
    SignerObservedCommonContextHandoffV1,
    SignerRetainedCommonContextContributionV3, SignerRosterConstructionCompletionGuardV3,
};
