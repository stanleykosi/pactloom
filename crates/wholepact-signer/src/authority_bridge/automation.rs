//! Foreground native bounded automation. The Store remains the local exposure
//! mirror; the independent witness serializes grants, reservations and final
//! key-use admission. A verified request is neither disclosure nor key-use consent.
use super::{BridgeError, Result};
use crate::{
    consent_journal::{NativeAutomationGrantRecord, PreparedSpendConsent},
    ipc::AuthenticatedPeer,
    manifest::ReviewInputs,
    native_ui::AuthenticatedPairing,
};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use wholepact_authority::{AuthenticatedWriterSession, AuthorityHead};
use wholepact_core::{
    Amount,
    automation::{
        AutomationEvidence, AutomationEvidenceKind, AutomationRequest, evaluate_automation_request,
    },
};
use wholepact_wallet::wallet::protected_sync::key_use::WalletKeyUseTicket;

pub(crate) const AUTOMATION_VERIFIER_ID: &str = "native-exact-automation-v1";
pub(crate) const AUTOMATION_SIGNER_ID: &str = "native-retained-automation-v1";

/// No DTO, deserialization, public constructor or success-flag conversion. Its
/// issuer checks real artifact verification, selected wallet inputs, kernel peer
/// provenance and an opaque fully reconciled authenticated witness session.
pub struct VerifiedAutomaticRequest {
    request: AutomationRequest,
    original_consent_reference: String,
    grant_binding: wholepact_authority::AutomationGrantBinding,
    grant_reference: String,
    account_policy_id: String,
    peer: AuthenticatedPeer,
    head: AuthorityHead,
    created: Instant,
    issued_at_ms: u64,
}
impl VerifiedAutomaticRequest {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn verify(
        grant: &NativeAutomationGrantRecord,
        prepared: &PreparedSpendConsent,
        pairing: &AuthenticatedPairing,
        bytes: &[u8],
        inputs: &ReviewInputs,
        ticket: &WalletKeyUseTicket,
        witness: &AuthenticatedWriterSession,
    ) -> Result<Self> {
        pairing
            .check_current()
            .map_err(|_| BridgeError::Permission)?;
        let original = prepared.record();
        let t = original.terms();
        let now = now_ms()?;
        let policy = t
            .wallet_key_use_policy
            .as_ref()
            .ok_or(BridgeError::Permission)?;
        ticket.validate_policy(policy)?;
        let selected = ticket.evidence();
        let snapshot = witness.snapshot();
        if grant.terms.verifier_id != AUTOMATION_VERIFIER_ID
            || grant.terms.signer_id != AUTOMATION_SIGNER_ID
            || grant.terms.application_id != pairing.binding().identity_id()
            || pairing.binding() != &t.transport
            || pairing.account_id() != t.account_id
            || pairing.agreement_id() != t.agreement_id
            || grant.enrollment_ref != t.enrollment_ref
            || selected.account_id() != t.account_id
            || snapshot.account_id != t.account_id
            || snapshot.writer_epoch != t.receipt.writer_epoch()
            || snapshot.network_profile_id != grant.terms.network_profile
            || snapshot.witness_id != grant.witness.witness_id
            || snapshot.policy_digest != grant.witness.policy_digest
            || witness.receipt().expires_at_ms <= now
            || hex::encode(Sha256::digest(bytes)) != t.artifact_digest
            || selected.context().tip_height != t.wallet_snapshot.tip_height
            || hex::encode(selected.context().tip_hash_protocol) != t.wallet_snapshot.tip_hash
            || hex::encode(selected.context().anchor_root) != t.wallet_snapshot.anchor_root
            || selected.inputs().len() != t.input_bindings.len()
        {
            return Err(BridgeError::Binding);
        }
        for i in &t.input_bindings {
            if !selected.inputs().iter().any(|s| {
                s.input_id() == i.input_id
                    && hex::encode(s.nullifier()) == i.nullifier
                    && s.value_zatoshis() == i.value_zatoshis
            }) {
                return Err(BridgeError::Binding);
            }
        }
        let reviewed = wholepact_protocol::review::verify_review(bytes, &inputs.policy)
            .map_err(|_| BridgeError::Verification)?;
        let owner = inputs
            .policy
            .participants
            .iter()
            .position(|p| {
                p.account_id == t.account_id && p.fvk.to_bytes() == selected.fvk().to_bytes()
            })
            .ok_or(BridgeError::Binding)?;
        if reviewed.review_binding() != t.review_binding
            || reviewed.shielded_sighash() != t.effects_digest
            || reviewed.net_debits_zatoshis().get(owner) != Some(&t.maximum_debit_zatoshis)
            || reviewed.fee_zatoshis() != t.transaction_fee_zatoshis
            || inputs.policy.participants[owner].fee_share_zatoshis != t.fee_share_zatoshis
        {
            return Err(BridgeError::Binding);
        }
        wholepact_protocol::proving::verify_proved_candidate(
            bytes,
            &inputs.policy,
            &t.review_binding,
            wholepact_protocol::proving::ProvingLimits { maximum_actions: 8 },
        )
        .map_err(|_| BridgeError::Verification)?;
        let mut recipients: Vec<_> = inputs
            .policy
            .outputs
            .iter()
            .filter(|o| {
                matches!(
                    o.purpose,
                    wholepact_protocol::review::OutputPurpose::Recipient
                )
            })
            .map(|o| receiver_fingerprint(&o.receiver.to_raw_address_bytes()))
            .collect();
        recipients.sort();
        recipients.dedup();
        let chain_observed = ticket
            .observation()
            .observed_at_unix_seconds()
            .checked_mul(1000)
            .ok_or(BridgeError::Binding)?;
        let witness_observed = witness.observed_at_ms();
        let witness_age_ms: u64 = witness
            .observation_age()
            .as_millis()
            .try_into()
            .map_err(|_| BridgeError::Permission)?;
        let mut expires = t
            .receipt
            .expires_at_ms()
            .min(grant.terms.expires_at_ms)
            .min(witness.receipt().expires_at_ms)
            .min(
                t.receipt
                    .reviewed_at_ms()
                    .checked_add(grant.terms.maximum_authorization_lifetime_ms)
                    .ok_or(BridgeError::Binding)?,
            );
        // The sealed continuation expires before ANY required observation can
        // age out, including the direct native path without a Store callback.
        for requirement in &grant.terms.evidence {
            let observed = match requirement.kind {
                AutomationEvidenceKind::CurrentChain => chain_observed,
                AutomationEvidenceKind::ExposureContinuity => {
                    // Snapshot acquisition and proof verification consume the
                    // original opaque observation's age; never re-date it here.
                    expires = expires.min(fresh_observation_deadline(
                        witness_observed,
                        witness_age_ms,
                        now,
                        requirement.maximum_age_ms,
                    )?);
                    witness_observed
                }
                _ => now,
            };
            expires = expires.min(
                observed
                    .checked_add(requirement.maximum_age_ms)
                    .ok_or(BridgeError::Binding)?,
            );
        }
        let evidence = grant
            .terms
            .evidence
            .iter()
            .map(|requirement| {
                if requirement.verifier_id != AUTOMATION_VERIFIER_ID {
                    return Err(BridgeError::Binding);
                }
                let (commitment, observed) = match requirement.kind {
                    AutomationEvidenceKind::AccountControl => {
                        (digest(&(pairing.binding(), &t.enrollment_ref))?, now)
                    }
                    AutomationEvidenceKind::RecipientInstructions => (digest(&recipients)?, now),
                    AutomationEvidenceKind::ExactEffects => (
                        digest(&(&t.artifact_digest, &t.effects_digest, &t.review_binding))?,
                        now,
                    ),
                    AutomationEvidenceKind::CurrentChain => {
                        (digest(&(&t.wallet_snapshot, policy))?, chain_observed)
                    }
                    AutomationEvidenceKind::ExposureContinuity => (
                        digest(&(witness.history_digest(), snapshot))?,
                        witness_observed,
                    ),
                    AutomationEvidenceKind::PrivateMatch => {
                        let sponsor = t.sponsor_policy.as_ref().ok_or(BridgeError::Permission)?;
                        let attestation = t
                            .sponsor_owner_attestation_digest
                            .as_ref()
                            .ok_or(BridgeError::Permission)?;
                        (digest(&(sponsor, attestation, &t.manifest_digest))?, now)
                    }
                };
                Ok(AutomationEvidence {
                    kind: requirement.kind,
                    verifier_id: AUTOMATION_VERIFIER_ID.into(),
                    evidence_digest: commitment,
                    manifest_digest: t.manifest_digest.clone(),
                    effects_digest: t.effects_digest.clone(),
                    observed_at_ms: observed,
                    expires_at_ms: expires,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let request = AutomationRequest {
            authorization_id: t.authorization_id.clone(),
            application_id: pairing.binding().identity_id().into(),
            account_id: t.account_id.clone(),
            writer_epoch: t.receipt.writer_epoch(),
            agreement_id: t.agreement_id.clone(),
            obligation_id: t.obligation_id.clone(),
            proposal_id: t.proposal_id.clone(),
            network_profile: snapshot.network_profile_id.clone(),
            manifest_digest: t.manifest_digest.clone(),
            effects_digest: t.effects_digest.clone(),
            artifact_digest: t.artifact_digest.clone(),
            input_ids: t
                .input_bindings
                .iter()
                .map(|i| i.input_id.clone())
                .collect(),
            recipient_fingerprints: recipients,
            maximum_debit: Amount::from_zatoshis(t.maximum_debit_zatoshis)
                .map_err(|_| BridgeError::Binding)?,
            fee: Amount::from_zatoshis(t.fee_share_zatoshis).map_err(|_| BridgeError::Binding)?,
            current_height: t.wallet_snapshot.tip_height,
            transaction_expiry_height: t.transaction_expiry_height,
            authorization_expires_at_ms: expires,
            evidence,
        };
        evaluate_automation_request(&grant.policy, &grant.terms, &request, now)
            .map_err(|_| BridgeError::Permission)?;
        Ok(Self {
            request,
            original_consent_reference: original.reference().into(),
            grant_binding: grant.binding.clone(),
            grant_reference: grant.reference()?,
            account_policy_id: grant.policy.policy_id.clone(),
            peer: pairing.current_peer(),
            head: snapshot.head.clone(),
            created: Instant::now(),
            issued_at_ms: now,
        })
    }
    pub(crate) fn request(&self) -> &AutomationRequest {
        &self.request
    }
    pub(crate) fn original_consent_reference(&self) -> &str {
        &self.original_consent_reference
    }
    pub(crate) fn witness_head(&self) -> &AuthorityHead {
        &self.head
    }
    pub(crate) fn check_current(&self) -> Result<()> {
        self.peer
            .check_current()
            .map_err(|_| BridgeError::Permission)?;
        self.peer
            .native_origin
            .check_current()
            .map_err(|_| BridgeError::Permission)?;
        let now = now_ms()?;
        if now < self.issued_at_ms
            || now >= self.request.authorization_expires_at_ms
            || self.created.elapsed()
                >= Duration::from_millis(
                    self.request.authorization_expires_at_ms - self.issued_at_ms,
                )
        {
            return Err(BridgeError::Permission);
        }
        Ok(())
    }
}
/// Fingerprints canonical decoded Ironwood testnet receiver bytes, never a
/// human address label. This domain is also used by native grant preparation.
pub(crate) fn receiver_fingerprint(receiver: &[u8; 43]) -> String {
    let mut hash = Sha256::new();
    hash.update(b"wholepact:automation:ironwood-testnet-receiver:v1\0");
    hash.update(receiver);
    hex::encode(hash.finalize())
}
fn digest(value: &impl serde::Serialize) -> Result<String> {
    wholepact_core::proposal::canonical_digest("wholepact:native-automation-evidence:v1", value)
        .map_err(|_| BridgeError::Binding)
}
fn fresh_observation_deadline(
    observed: u64,
    monotonic_age: u64,
    now: u64,
    maximum_age: u64,
) -> Result<u64> {
    if observed > now || monotonic_age >= maximum_age || now - observed >= maximum_age {
        return Err(BridgeError::Permission);
    }
    let absolute = observed
        .checked_add(maximum_age)
        .ok_or(BridgeError::Binding)?;
    let monotonic = now
        .checked_add(maximum_age - monotonic_age)
        .ok_or(BridgeError::Binding)?;
    Ok(absolute.min(monotonic))
}
fn now_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| BridgeError::Permission)?
        .as_millis()
        .try_into()
        .map_err(|_| BridgeError::Permission)
}

use crate::consent_journal::{
    ApprovedAutomaticSpendConsent, SignerConsentJournal, SignerConsentSession,
};
use wholepact_store::automation::{
    AutomaticAuthorizationOutcome, AutomaticAuthorizer, AutomationError, AutomationGrantAction,
    AutomationGrantStatus, AutomationLease, AutomationReview, AutomationTrustSource,
    PreparedAutomaticAuthorization,
};

/// Adapter for an existing coordinator Store, never a new native exposure DB.
/// Current owner consent is read from the signer journal. The mirror cannot
/// confer key-use permission: the authorizer still obtains live witness admission.
pub struct NativeAutomationTrustSource<'a> {
    journal: &'a SignerConsentJournal,
    session: &'a SignerConsentSession,
    grant: &'a NativeAutomationGrantRecord,
    verified: Option<&'a VerifiedAutomaticRequest>,
    reference: String,
}
impl<'a> NativeAutomationTrustSource<'a> {
    pub fn new(
        journal: &'a SignerConsentJournal,
        session: &'a SignerConsentSession,
        grant: &'a NativeAutomationGrantRecord,
        verified: Option<&'a VerifiedAutomaticRequest>,
    ) -> Result<Self> {
        if journal
            .automation_grant(&grant.binding.grant_id, session)?
            .as_ref()
            != Some(grant)
        {
            return Err(BridgeError::Permission);
        }
        if let Some(verified) = verified {
            verified.check_current()?;
        }
        Ok(Self {
            journal,
            session,
            grant,
            verified,
            reference: grant.reference()?,
        })
    }
}
pub struct NativeAutomationLease<'a> {
    grant: &'a NativeAutomationGrantRecord,
    verified: Option<&'a VerifiedAutomaticRequest>,
    reference: String,
    review: AutomationReview,
}
impl AutomationLease for NativeAutomationLease<'_> {
    fn check_current(
        &self,
        review: &AutomationReview,
        now: u64,
    ) -> wholepact_store::automation::Result<()> {
        if review != &self.review
            || now < self.grant.policy.valid_from_ms
            || now >= self.grant.policy.expires_at_ms
        {
            return Err(AutomationError::Denied);
        }
        match review {
            AutomationReview::ConfigureAccount { policy, .. } if policy == &self.grant.policy => {}
            AutomationReview::CreateGrant { terms, account }
                if terms == &self.grant.terms && account.policy == self.grant.policy => {}
            AutomationReview::ChangeGrant { grant, action } if grant.terms == self.grant.terms => {
                let expected = match action {
                    AutomationGrantAction::Activate => {
                        wholepact_authority::AutomationGrantStatus::Active
                    }
                    AutomationGrantAction::Pause => {
                        wholepact_authority::AutomationGrantStatus::Paused
                    }
                    AutomationGrantAction::Revoke => {
                        wholepact_authority::AutomationGrantStatus::Revoked
                    }
                    AutomationGrantAction::ObserveExpiry => {
                        if now < self.grant.terms.expires_at_ms {
                            return Err(AutomationError::Denied);
                        }
                        return Ok(());
                    }
                };
                if self.grant.status != expected {
                    return Err(AutomationError::Denied);
                }
            }
            AutomationReview::Authorize {
                account,
                grant,
                request,
            } => {
                let verified = self.verified.ok_or(AutomationError::Unavailable)?;
                verified
                    .check_current()
                    .map_err(|_| AutomationError::Denied)?;
                if account.policy != self.grant.policy
                    || grant.terms != self.grant.terms
                    || grant.status != AutomationGrantStatus::Active
                    || self.grant.status != wholepact_authority::AutomationGrantStatus::Active
                    || grant.current_activation_consent_reference.as_deref()
                        != Some(&self.reference)
                    || request.as_ref() != verified.request()
                {
                    return Err(AutomationError::Denied);
                }
                evaluate_automation_request(&self.grant.policy, &self.grant.terms, request, now)?;
            }
            _ => return Err(AutomationError::Denied),
        }
        Ok(())
    }
    fn consent_reference(&self) -> &str {
        &self.reference
    }
}
impl<'a> AutomationTrustSource for NativeAutomationTrustSource<'a> {
    type Lease = NativeAutomationLease<'a>;
    fn verifier_id(&self) -> &str {
        AUTOMATION_VERIFIER_ID
    }
    fn now_ms(&self) -> wholepact_store::automation::Result<u64> {
        now_ms().map_err(|_| AutomationError::ClockInvalid)
    }
    fn acquire(
        &self,
        review: &AutomationReview,
    ) -> wholepact_store::automation::Result<Self::Lease> {
        if self
            .journal
            .automation_grant(&self.grant.binding.grant_id, self.session)
            .map_err(|_| AutomationError::Unavailable)?
            .as_ref()
            != Some(self.grant)
        {
            return Err(AutomationError::Denied);
        }
        let lease = NativeAutomationLease {
            grant: self.grant,
            verified: self.verified,
            reference: self.reference.clone(),
            review: review.clone(),
        };
        lease.check_current(review, self.now_ms()?)?;
        Ok(lease)
    }
}

/// Exactly one callback owns the sealed continuation and separately approved
/// disclosure. Any error after Store precommit remains Unknown. The adapter never
/// retries admission or signing and never returns or dispatches signature bytes.
pub struct NativeAutomaticAuthorizer<'a> {
    journal: &'a SignerConsentJournal,
    session: &'a SignerConsentSession,
    account: &'a crate::account::DedicatedAccount,
    verified: &'a VerifiedAutomaticRequest,
    approval: Option<ApprovedAutomaticSpendConsent>,
    disclosure: Option<super::disclosure::ApprovedWitnessDisclosure>,
    bytes: &'a [u8],
    inputs: &'a ReviewInputs,
    wallet: &'a mut wholepact_wallet::wallet::protected_sync::ProtectedWalletSync,
    ticket: &'a WalletKeyUseTicket,
    witness: &'a wholepact_authority::AuthorityClient,
    commit: Option<super::AuthorizationCommit>,
}
impl<'a> NativeAutomaticAuthorizer<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        journal: &'a SignerConsentJournal,
        session: &'a SignerConsentSession,
        account: &'a crate::account::DedicatedAccount,
        verified: &'a VerifiedAutomaticRequest,
        approval: ApprovedAutomaticSpendConsent,
        disclosure: super::disclosure::ApprovedWitnessDisclosure,
        bytes: &'a [u8],
        inputs: &'a ReviewInputs,
        wallet: &'a mut wholepact_wallet::wallet::protected_sync::ProtectedWalletSync,
        ticket: &'a WalletKeyUseTicket,
        witness: &'a wholepact_authority::AuthorityClient,
    ) -> Result<Self> {
        verified.check_current()?;
        let t = approval.record().terms();
        let automation = t.automation.as_ref().ok_or(BridgeError::Permission)?;
        if automation.grant != verified.grant_binding
            || t.authorization_id != verified.request.authorization_id
            || t.artifact_digest != verified.request.artifact_digest
            || automation.request_digest
                != wholepact_core::proposal::canonical_digest(
                    "wholepact:verified-automatic-request:v1",
                    verified.request(),
                )
                .map_err(|_| BridgeError::Binding)?
        {
            return Err(BridgeError::Binding);
        }
        Ok(Self {
            journal,
            session,
            account,
            verified,
            approval: Some(approval),
            disclosure: Some(disclosure),
            bytes,
            inputs,
            wallet,
            ticket,
            witness,
            commit: None,
        })
    }
    pub fn retained_commit(&self) -> Option<&super::AuthorizationCommit> {
        self.commit.as_ref()
    }
}
impl AutomaticAuthorizer for NativeAutomaticAuthorizer<'_> {
    fn signer_id(&self) -> &str {
        AUTOMATION_SIGNER_ID
    }
    fn authorize_exact(
        &mut self,
        prepared: PreparedAutomaticAuthorization<'_>,
    ) -> wholepact_store::automation::Result<AutomaticAuthorizationOutcome> {
        prepared.check_current()?;
        self.verified
            .check_current()
            .map_err(|_| AutomationError::Denied)?;
        if &prepared.record().request != self.verified.request()
            || prepared.record().grant_id != self.verified.grant_binding.grant_id
            || prepared.record().account_policy_id != self.verified.account_policy_id
            || prepared.record().active_consent_reference != self.verified.grant_reference
        {
            return Err(AutomationError::Denied);
        }
        // Take before attempting external work. This object itself cannot sign
        // twice, even if a caller bypasses Store's already-once callback guard.
        let approval = self
            .approval
            .take()
            .ok_or(AutomationError::AuthorizationUncertain)?;
        let disclosure = self
            .disclosure
            .take()
            .ok_or(AutomationError::AuthorizationUncertain)?;
        let result = (|| {
            let pending = super::prepare_automatic_authorization(
                self.journal,
                self.session,
                self.account,
                approval,
                self.bytes,
                self.verified.head.clone(),
                super::protocol::AuthorizationDeliveryScope {
                    candidate_id: self.verified.request.proposal_id.clone(),
                },
                disclosure,
            )?;
            let reserved = pending.reserve(self.witness)?;
            let check = || {
                prepared
                    .check_current()
                    .map_err(|_| BridgeError::Permission)?;
                self.verified.check_current()
            };
            reserved.authorize_with_wallet_checked(self.wallet, self.ticket, self.inputs, &check)
        })();
        match result {
            Ok(commit) => {
                self.commit = Some(commit);
                Ok(AutomaticAuthorizationOutcome::RetainedLocally)
            }
            Err(_) => Err(AutomationError::AuthorizationUncertain),
        }
    }
}

/// Read-only restart/replay inspection. Never reconstructs a continuation and
/// never invokes a signer. None means no retained result; exposure stays unknown.
/// Export/redelivery remains the existing separately approved delivery flow.
pub fn retained_automatic_commit(
    journal: &SignerConsentJournal,
    session: &SignerConsentSession,
    authorization_id: &str,
) -> Result<Option<super::AuthorizationCommit>> {
    let lease = journal.acquire_original_authorization(authorization_id, session)?;
    if lease
        .evidence()
        .original_consent()
        .terms()
        .automation
        .is_none()
    {
        return Err(BridgeError::Binding);
    }
    match journal.bridge_result(&lease) {
        Ok(result) => Ok(Some(super::AuthorizationCommit::from(&result))),
        Err(BridgeError::Missing) => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn witness_observation_age_is_not_redated_and_clock_rollback_cannot_extend_it() {
        assert_eq!(
            fresh_observation_deadline(10_000, 1_000, 11_000, 2_000).unwrap(),
            12_000
        );
        assert!(fresh_observation_deadline(10_000, 2_000, 11_000, 2_000).is_err());
        assert!(fresh_observation_deadline(10_000, 1_000, 12_000, 2_000).is_err());
        assert!(fresh_observation_deadline(10_000, 0, 9_999, 2_000).is_err());
        assert_eq!(
            fresh_observation_deadline(10_000, 1_500, 10_500, 2_000).unwrap(),
            11_000
        );
    }
    #[test]
    fn receiver_fingerprint_is_canonical_network_qualified_and_exact() {
        let receiver = [7; 43];
        let a = receiver_fingerprint(&receiver);
        assert_eq!(a.len(), 64);
        assert_eq!(a, receiver_fingerprint(&receiver));
        let mut changed = receiver;
        changed[42] ^= 1;
        assert_ne!(a, receiver_fingerprint(&changed));
        assert_ne!(a, hex::encode(Sha256::digest(receiver)));
    }
}
