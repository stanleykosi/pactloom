//! Manual authorization of one retained, fully proved two-owner proposal.
//!
//! Durability belongs to the immutable proposal, not to permission. A reopened
//! proposal must obtain a new current native review, current protected-wallet
//! ticket and the existing independent witness reservation. No retained DTO can
//! reconstruct the native continuation. Once an original release is committed,
//! this adapter never creates a second attempt: only the exact already-retained
//! result may be delivered through the existing recipient-authenticated IPC.
use super::{
    disclosure::ApprovedWitnessDisclosure, protocol::AuthorizationDeliveryScope,
    AuthorizationCommit, BridgeError, Result,
};
#[cfg(feature = "synthetic-born-joined-qualification")]
use super::durable_flow_diagnostics_v1::DurableFlowObserverV1;
use crate::{
    account::DedicatedAccount,
    consent_journal::{
        AcceptedManifestRecord, AccountEnrollmentRecord, ApprovedSpendConsent,
        NativeConsentDecision, OriginalSpendConsent, PreparedSpendConsent, SignerConsentJournal,
        SignerConsentSession, SpendConsentTerms,
    },
    manifest::ReviewInputs,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use wholepact_authority::{AuthorityClient, AuthorityHead};
use wholepact_protocol::{
    durable_proposal_v1::{FixedProposalIdentityV1, VerifiedFixedProposal},
    review_manifest::{policy_fingerprint, verify_manifest_policy},
};
use wholepact_wallet::wallet::protected_sync::{key_use::WalletKeyUseTicket, ProtectedWalletSync};

mod stable_returns_v2;

/// Read-only original V2 preimage validation for the separate financial
/// admission review. This does not create consent, disclosure or key use.
#[cfg(all(
    feature = "pending-birth-owner-signing",
    feature = "native-ui",
    target_os = "linux"
))]
pub(crate) fn validate_durable_payment_policy_v1(
    entry: &crate::account::birth::enrollment::roster_v2::durable_entry_v1::FreshDurableBornEntryV1,
    enrollment: &AccountEnrollmentRecord,
    manifest: &AcceptedManifestRecord,
    fixed: &VerifiedFixedProposal,
    inputs: &[wholepact_protocol::construction::InputActionMapping],
    outputs: &[wholepact_protocol::construction::OutputActionMapping],
) -> Result<String> {
    entry
        .check_original_source_current()
        .map_err(|_| BridgeError::Permission)?;
    let original = entry
        .original_recipient_policy_export_v2()
        .map_err(|_| BridgeError::Binding)?;
    let binding =
        crate::consent_journal::DurableBornPolicyBindingV1::from_original_stable_source_v2(
            entry.record(),
            enrollment,
            manifest,
            fixed.identity(),
            &original,
        )?;
    stable_returns_v2::verify_stable_returns_v2(
        fixed,
        inputs,
        outputs,
        &entry.account().fvk().map_err(|_| BridgeError::Binding)?,
        &entry
            .account()
            .account_id()
            .map_err(|_| BridgeError::Binding)?,
        &binding.stable_return_requirements_v2(manifest)?,
    )?;
    // The export is validated original history. Its private preimage never
    // leaves this signer; only its committed policy digest goes to the witness.
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct OriginalPolicy {
        version: u16,
        anchor: wholepact_core::born_policy_origin_v2::BornRecipientPolicyOriginV2,
        original_birth_commit: wholepact_authority::pending_birth::PendingBirthCommitRecord,
    }
    let exact: OriginalPolicy =
        serde_json::from_value(serde_json::to_value(&original).map_err(|_| BridgeError::Binding)?)
            .map_err(|_| BridgeError::Binding)?;
    if exact.version != 2
        || exact.original_birth_commit.request.native_birth_digest != exact.anchor.birth_digest
    {
        return Err(BridgeError::Binding);
    }
    exact
        .anchor
        .recipient_policy
        .digest()
        .map_err(|_| BridgeError::Binding)
}

/// Reloads the exact protected proposal record and its independently retained
/// full policy. A caller must not hold a database lock across this callback or
/// across key use. Returning a digest, parsed descriptor or verification flag is
/// deliberately insufficient. The immutable proposal must have been constructed
/// through the maintained protocol verifier. An owned verified snapshot may be
/// reused after exact retained-record and genuine current permission checks; no
/// callback can manufacture native permission or revive a former approval.
///
/// This callback also runs while the original authorization owns the journal
/// read fence. It MUST NOT acquire journal authority/session fences recursively:
/// a queued revocation writer can otherwise deadlock a recursive read. Concrete
/// native sources check only immutable data and the actual native/vault source;
/// the specialized key-use path separately validates the exact held lease.
pub type FixedProposalSource = Arc<dyn Fn() -> Result<Arc<VerifiedFixedProposal>> + Send + Sync>;

/// A displayable fresh review, not permission. Neither this type nor its approved
/// successor is serializable, cloneable, or constructible from saved evidence.
pub struct PreparedDurableProposalReview {
    source: FixedProposalSource,
    proposal: Arc<VerifiedFixedProposal>,
    inputs: ReviewInputs,
    prepared: PreparedSpendConsent,
}

/// One immediate genuine native decision for the exact fixed proposal. Dropping
/// it abandons permission, not durable proposal data or previously held exposure.
///
/// Saved data cannot restore this continuation:
/// ```compile_fail
/// use wholepact_signer::authority_bridge::durable_proposal_v1::ApprovedDurableProposalAction;
/// let action: ApprovedDurableProposalAction = serde_json::from_str("{}").unwrap();
/// ```
pub struct ApprovedDurableProposalAction {
    source: FixedProposalSource,
    proposal: Arc<VerifiedFixedProposal>,
    inputs: ReviewInputs,
    approval: ApprovedSpendConsent,
    original: OriginalSpendConsent,
}

/// A stable correlation identifier only, never an authorization capability.
/// It intentionally excludes wall-clock time, wallet tip and attempt counters.
pub fn manual_authorization_id(
    identity: &FixedProposalIdentityV1,
    account_id: &str,
) -> Result<String> {
    crate::review::validate_label(account_id).map_err(|_| BridgeError::Binding)?;
    if identity.schema_version != 1
        || identity.proposal_binding.len() != 64
        || !identity
            .proposal_binding
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(BridgeError::Binding);
    }
    let mut hash = Sha256::new();
    hash.update(b"wholepact:durable-manual-proposal-authorization:v1\0");
    for value in [identity.proposal_binding.as_str(), account_id] {
        hash.update((value.len() as u64).to_le_bytes());
        hash.update(value.as_bytes());
    }
    Ok(format!("durable-v1-{}", hex::encode(hash.finalize())))
}

/// Prepare only from a freshly reloaded verified proposal and genuine current
/// signer-owned wallet selection. The accepted enrollment/manifest must belong
/// to the current native session; old native receipts are never renewed here.
/// Human waiting happens before this call, or discards and repeats this review.
#[allow(clippy::too_many_arguments)]
pub fn prepare_manual_review(
    source: FixedProposalSource,
    journal: &SignerConsentJournal,
    session: &SignerConsentSession,
    enrollment: &AccountEnrollmentRecord,
    manifest: &AcceptedManifestRecord,
    account: &DedicatedAccount,
    inputs: ReviewInputs,
) -> Result<PreparedDurableProposalReview> {
    let proposal = source()?;
    validate_review_inputs(&proposal, manifest, &inputs)?;
    let account_id = account.account_id().map_err(|_| BridgeError::Binding)?;
    let authorization_id = manual_authorization_id(proposal.identity(), &account_id)?;
    require_unreleased(
        journal,
        session,
        proposal.identity(),
        &authorization_id,
        &account_id,
    )?;
    // This is the existing genuine review constructor. It independently binds
    // the actual signer FVK, accepted manifest, current local selection, exact
    // economics and the current native session. It grants no key-use permission.
    let prepared = session.prepare_spend(
        enrollment,
        manifest,
        account,
        proposal.private_proved_pczt_bytes(),
        &inputs,
        &authorization_id,
    )?;
    validate_original_binding(&proposal, prepared.record(), &account_id)?;
    Ok(PreparedDurableProposalReview {
        source,
        proposal,
        inputs,
        prepared,
    })
}

impl PreparedDurableProposalReview {
    /// Bind original witness policy only through the actual freshly opened
    /// source, before witness disclosure and the native spending decision. The
    /// fresh enrollment/manifest and their same-native-origin checks remain
    /// independent of historical policy association.
    #[cfg(all(
        feature = "pending-birth-owner-signing",
        feature = "native-ui",
        target_os = "linux"
    ))]
    pub(crate) fn with_durable_born_policy_v1(
        mut self,
        entry: &crate::account::birth::enrollment::roster_v2::durable_entry_v1::FreshDurableBornEntryV1,
        enrollment: &AccountEnrollmentRecord,
        manifest: &AcceptedManifestRecord,
    ) -> Result<Self> {
        entry.check_current().map_err(|_| BridgeError::Permission)?;
        // This runtime profile requires a genuine original V2 birth preimage.
        // Failure does not fall back to interpreting an allowlisted policy hash
        // as a concrete output digest or trusting a caller-supplied descriptor.
        let original_policy = entry
            .original_recipient_policy_export_v2()
            .map_err(|_| BridgeError::Binding)?;
        let binding =
            crate::consent_journal::DurableBornPolicyBindingV1::from_original_stable_source_v2(
                entry.record(),
                enrollment,
                manifest,
                self.proposal.identity(),
                &original_policy,
            )?;
        stable_returns_v2::verify_stable_returns_v2(
            &self.proposal,
            &self.inputs.input_actions,
            &self.inputs.output_actions,
            &entry.account().fvk().map_err(|_| BridgeError::Binding)?,
            &entry
                .account()
                .account_id()
                .map_err(|_| BridgeError::Binding)?,
            &binding.stable_return_requirements_v2(manifest)?,
        )?;
        self.prepared = self
            .prepared
            .with_durable_born_policy_v1(binding, enrollment, manifest)?;
        let account_id = entry
            .account()
            .account_id()
            .map_err(|_| BridgeError::Binding)?;
        validate_original_binding(&self.proposal, self.prepared.record(), &account_id)?;
        check_reload(&self.source, &self.proposal)?;
        entry.check_current().map_err(|_| BridgeError::Permission)?;
        Ok(self)
    }

    /// Borrowed for the existing native spending display and separate exact
    /// witness-disclosure review. No extraction of approval is provided.
    pub fn prepared_spend(&self) -> &PreparedSpendConsent {
        &self.prepared
    }

    pub fn identity(&self) -> &FixedProposalIdentityV1 {
        self.proposal.identity()
    }
}

impl PreparedDurableProposalReview {
    /// Only the existing native decision issuer can provide this opaque input.
    /// A JSON success flag, terminal acknowledgement or durable data is not one.
    pub fn approve(
        self,
        session: &SignerConsentSession,
        decision: NativeConsentDecision,
    ) -> Result<ApprovedDurableProposalAction> {
        check_reload(&self.source, &self.proposal)?;
        let original = self.prepared.record().clone();
        let approval = session.approve_spend(self.prepared, decision)?;
        Ok(ApprovedDurableProposalAction {
            source: self.source,
            proposal: self.proposal,
            inputs: self.inputs,
            approval,
            original,
        })
    }
}

impl ApprovedDurableProposalAction {
    /// Commit exact release intent and conservative exposure before contacting
    /// the independently authenticated witness, then use the existing held
    /// wallet/native key-use fence. An error after release requires recovery,
    /// never a new authorization ID, new candidate, or reservation refund.
    ///
    /// Only a non-sensitive receipt is returned. The established native IPC
    /// exports the already-retained detached assigned signatures to the exact
    /// approved recipient; a different recipient needs its separate decision.
    #[allow(clippy::too_many_arguments)]
    pub fn authorize(
        self,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        account: &DedicatedAccount,
        expected_head: AuthorityHead,
        disclosure: ApprovedWitnessDisclosure,
        client: &AuthorityClient,
        wallet: &mut ProtectedWalletSync,
        ticket: &WalletKeyUseTicket,
    ) -> Result<AuthorizationCommit> {
        // The generic route cannot consume a release for a born account that
        // its downstream key accessor deliberately refuses.
        account
            .require_generic_spending_source()
            .map_err(|_| BridgeError::Permission)?;
        let account_id = account.account_id().map_err(|_| BridgeError::Binding)?;
        validate_original_binding(&self.proposal, &self.original, &account_id)?;
        require_unreleased(
            journal,
            session,
            self.proposal.identity(),
            &self.original.terms().authorization_id,
            &account_id,
        )?;
        check_ticket(&self.original, ticket)?;
        if ticket.evidence().fvk().to_bytes()
            != account.fvk().map_err(|_| BridgeError::Binding)?.to_bytes()
        {
            return Err(BridgeError::Binding);
        }
        disclosure.check(&self.original, Some(client))?;
        if disclosure.record().expected_head != expected_head {
            return Err(BridgeError::Binding);
        }
        let check = || check_reload(&self.source, &self.proposal);
        check()?;
        // record_original_consent_release atomically rejects another live
        // authorization for the obligation or any reserved input, including a
        // different ID. The preflight above does not replace that safety fence.
        let pending = super::prepare_authorization(
            journal,
            session,
            account,
            self.approval,
            self.proposal.private_proved_pczt_bytes(),
            expected_head,
            AuthorizationDeliveryScope {
                candidate_id: self.proposal.identity().proposal_id.clone(),
            },
            disclosure,
        )?;
        check()?;
        let reserved = pending.reserve(client)?;
        reserved.authorize_with_wallet_checked(wallet, ticket, &self.inputs, &check)
    }

    /// Purpose-specific genuine fresh born entry. Historical origin only pins
    /// the original namespace; current native consent, wallet transaction and
    /// independently reconciled writer/permit remain mandatory. No born flag is
    /// cleared and generic key access remains denied.
    #[cfg(all(
        feature = "pending-birth-owner-signing",
        feature = "native-ui",
        target_os = "linux"
    ))]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn authorize_from_durable_born_v1(
        self,
        entry: &crate::account::birth::enrollment::roster_v2::durable_entry_v1::FreshDurableBornEntryV1,
        session: &SignerConsentSession,
        expected_head: AuthorityHead,
        disclosure: ApprovedWitnessDisclosure,
        client: &AuthorityClient,
        wallet: &mut ProtectedWalletSync,
        ticket: &WalletKeyUseTicket,
    ) -> Result<AuthorizationCommit> {
        self.authorize_from_durable_born_v1_inner(
            entry,
            session,
            expected_head,
            disclosure,
            client,
            wallet,
            ticket,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            None,
        )
    }
    #[cfg(all(feature = "synthetic-born-joined-qualification", target_os = "linux"))]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn authorize_from_durable_born_v1_diagnosed(
        self,
        entry: &crate::account::birth::enrollment::roster_v2::durable_entry_v1::FreshDurableBornEntryV1,
        session: &SignerConsentSession,
        expected_head: AuthorityHead,
        disclosure: ApprovedWitnessDisclosure,
        client: &AuthorityClient,
        wallet: &mut ProtectedWalletSync,
        ticket: &WalletKeyUseTicket,
        observer: Option<&DurableFlowObserverV1>,
    ) -> Result<AuthorizationCommit> {
        self.authorize_from_durable_born_v1_inner(
            entry,
            session,
            expected_head,
            disclosure,
            client,
            wallet,
            ticket,
            observer,
        )
    }
    #[cfg(all(
        feature = "pending-birth-owner-signing",
        feature = "native-ui",
        target_os = "linux"
    ))]
    #[allow(clippy::too_many_arguments)]
    fn authorize_from_durable_born_v1_inner(
        self,
        entry: &crate::account::birth::enrollment::roster_v2::durable_entry_v1::FreshDurableBornEntryV1,
        session: &SignerConsentSession,
        expected_head: AuthorityHead,
        disclosure: ApprovedWitnessDisclosure,
        client: &AuthorityClient,
        wallet: &mut ProtectedWalletSync,
        ticket: &WalletKeyUseTicket,
        #[cfg(feature = "synthetic-born-joined-qualification")] observer: Option<
            &DurableFlowObserverV1,
        >,
    ) -> Result<AuthorizationCommit> {
        flow_observe!(observer, AuthorizationSource, entry.check_current())
            .map_err(|_| BridgeError::Permission)?;
        let journal = entry.journal().as_ref();
        let account = entry.account();
        flow_observe!(
            observer,
            AuthorizationSource,
            entry.require_account_identity(account)
        )
        .map_err(|_| BridgeError::Permission)?;
        flow_observe!(
            observer,
            AuthorizationSource,
            entry.require_journal_identity(journal)
        )
        .map_err(|_| BridgeError::Permission)?;
        if client.disclosure_descriptor()
            != flow_observe!(
                observer,
                AuthorizationSource,
                entry.original_witness_disclosure()
            )
            .map_err(|_| BridgeError::Binding)?
        {
            return flow_observe!(observer, AuthorizationSource, Err(BridgeError::Binding));
        }
        let account_id = flow_observe!(observer, AuthorizationSource, account.account_id())
            .map_err(|_| BridgeError::Binding)?;
        flow_observe!(
            observer,
            AuthorizationSource,
            validate_original_binding(&self.proposal, &self.original, &account_id)
        )?;
        let binding = flow_observe!(
            observer,
            AuthorizationSource,
            self.original
                .terms()
                .durable_born_policy_v1
                .as_ref()
                .ok_or(BridgeError::Permission)
        )?;
        let enrollment = flow_observe!(
            observer,
            AuthorizationSource,
            flow_observe!(
                observer,
                AuthorizationSource,
                journal.enrollment(&self.original.terms().enrollment_ref, session)
            )?
            .ok_or(BridgeError::Missing)
        )?;
        let manifest = flow_observe!(
            observer,
            AuthorizationSource,
            flow_observe!(
                observer,
                AuthorizationSource,
                journal.accepted_manifest(&self.original.terms().accepted_manifest_ref, session)
            )?
            .ok_or(BridgeError::Missing)
        )?;
        // Cache only an exact historical projection of the actual immutable
        // source, not permission. Repeated checks below revalidate that source
        // under the already-held original lease without reacquiring its fence.
        let original_policy = if binding.uses_stable_recipient_policy_v2() {
            Some(
                flow_observe!(
                    observer,
                    AuthorizationSource,
                    entry.original_recipient_policy_export_v2()
                )
                .map_err(|_| BridgeError::Binding)?,
            )
        } else {
            None
        };
        let actual_fvk = flow_observe!(observer, AuthorizationSource, account.fvk())
            .map_err(|_| BridgeError::Binding)?;
        let validate_policy = || {
            if let Some(original_policy) = &original_policy {
                flow_observe!(
                    observer,
                    AuthorizationSource,
                    binding.validate_stable_original_source_v2(
                        entry.record(),
                        entry.genesis(),
                        original_policy,
                    )
                )?;
                flow_observe!(
                    observer,
                    AuthorizationSource,
                    stable_returns_v2::verify_stable_returns_v2(
                        &self.proposal,
                        &self.inputs.input_actions,
                        &self.inputs.output_actions,
                        &actual_fvk,
                        &account_id,
                        &flow_observe!(
                            observer,
                            AuthorizationSource,
                            binding.stable_return_requirements_v2(&manifest)
                        )?,
                    )
                )
            } else {
                // Only an explicitly exact historical profile can reach this
                // validator; it rejects stable-policy records, never downgrades.
                flow_observe!(
                    observer,
                    AuthorizationSource,
                    binding.validate_original_source(entry.record(), entry.genesis())
                )?;
                Ok(())
            }
        };
        flow_observe!(observer, AuthorizationSource, validate_policy())?;
        flow_observe!(
            observer,
            AuthorizationSource,
            binding.validate_consent(self.original.terms(), &enrollment, &manifest)
        )?;
        flow_observe!(
            observer,
            AuthorizationSource,
            binding.require_fixed_identity(self.proposal.identity())
        )?;
        flow_observe!(
            observer,
            AuthorizationSource,
            binding.require_current_time(flow_observe!(
                observer,
                AuthorizationSource,
                current_time_ms()
            )?)
        )?;
        flow_observe!(
            observer,
            AuthorizationSource,
            require_unreleased_inner(
                journal,
                session,
                self.proposal.identity(),
                &self.original.terms().authorization_id,
                &account_id,
                #[cfg(feature = "synthetic-born-joined-qualification")]
                observer,
            )
        )?;
        flow_observe!(
            observer,
            AuthorizationSource,
            check_ticket_inner(
                &self.original,
                ticket,
                #[cfg(feature = "synthetic-born-joined-qualification")]
                observer,
            )
        )?;
        if ticket.evidence().fvk().to_bytes()
            != flow_observe!(observer, AuthorizationSource, account.fvk())
                .map_err(|_| BridgeError::Binding)?
                .to_bytes()
        {
            return flow_observe!(observer, AuthorizationSource, Err(BridgeError::Binding));
        }
        flow_observe!(
            observer,
            AuthorizationSource,
            disclosure.check(&self.original, Some(client))
        )?;
        if disclosure.record().expected_head != expected_head {
            return flow_observe!(observer, AuthorizationSource, Err(BridgeError::Binding));
        }
        // Once prepare_authorization returns, its original lease already owns
        // the journal read fence. This callback must never recursively acquire
        // that fence behind a queued revocation writer. Full journal + origin
        // checks below reuse the actual held lease instead.
        let check = || {
            flow_observe!(
                observer,
                AuthorizationSource,
                entry.check_original_source_current()
            )
            .map_err(|_| BridgeError::Permission)?;
            flow_observe!(observer, AuthorizationSource, validate_policy())?;
            flow_observe!(
                observer,
                AuthorizationSource,
                binding.validate_consent(self.original.terms(), &enrollment, &manifest)
            )?;
            flow_observe!(
                observer,
                AuthorizationSource,
                binding.require_fixed_identity(self.proposal.identity())
            )?;
            flow_observe!(
                observer,
                AuthorizationSource,
                binding.require_current_time(flow_observe!(
                    observer,
                    AuthorizationSource,
                    current_time_ms()
                )?)
            )?;
            flow_observe!(
                observer,
                AuthorizationSource,
                check_reload(&self.source, &self.proposal)
            )
        };
        flow_observe!(observer, AuthorizationSource, check())?;
        let pending = super::prepare_authorization_from_durable_born_v1_inner(
            entry,
            session,
            self.approval,
            self.proposal.private_proved_pczt_bytes(),
            expected_head,
            AuthorizationDeliveryScope {
                candidate_id: self.proposal.identity().proposal_id.clone(),
            },
            disclosure,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            observer,
        )?;
        flow_observe!(observer, AuthorizationSource, check())?;
        flow_observe!(
            observer,
            AuthorizationSource,
            entry.require_authorization_identity(account, journal, &pending.lease)
        )
        .map_err(|_| BridgeError::Permission)?;
        let reserved = pending.reserve_inner(
            client,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            observer,
        )?;
        reserved.authorize_with_wallet_from_durable_born_v1_inner(
            wallet,
            ticket,
            &self.inputs,
            &check,
            entry,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            observer,
        )
    }
}

#[cfg(all(
    feature = "pending-birth-owner-signing",
    feature = "native-ui",
    target_os = "linux"
))]
fn current_time_ms() -> Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| BridgeError::Permission)?
        .as_millis()
        .try_into()
        .map_err(|_| BridgeError::Permission)
}

/// Read only the receipt for an already persisted exact result. This does not
/// restore a signing continuation or export signatures. A committed original
/// without its exact retained result is recovery-required, even before key use.
pub fn retained_manual_commit(
    source: &FixedProposalSource,
    journal: &SignerConsentJournal,
    session: &SignerConsentSession,
    account: &DedicatedAccount,
) -> Result<Option<AuthorizationCommit>> {
    retained_manual_commit_inner(
        source,
        journal,
        session,
        account,
        #[cfg(feature = "synthetic-born-joined-qualification")]
        None,
    )
}
#[cfg(feature = "synthetic-born-joined-qualification")]
pub(crate) fn retained_manual_commit_diagnosed(
    source: &FixedProposalSource,
    journal: &SignerConsentJournal,
    session: &SignerConsentSession,
    account: &DedicatedAccount,
    observer: Option<&DurableFlowObserverV1>,
) -> Result<Option<AuthorizationCommit>> {
    retained_manual_commit_inner(source, journal, session, account, observer)
}
fn retained_manual_commit_inner(
    source: &FixedProposalSource,
    journal: &SignerConsentJournal,
    session: &SignerConsentSession,
    account: &DedicatedAccount,
    #[cfg(feature = "synthetic-born-joined-qualification")] observer: Option<
        &DurableFlowObserverV1,
    >,
) -> Result<Option<AuthorizationCommit>> {
    let proposal = flow_observe!(observer, RetainedLookup, source())?;
    let account_id = flow_observe!(observer, RetainedLookup, account.account_id())
        .map_err(|_| BridgeError::Binding)?;
    let authorization_id = flow_observe!(
        observer,
        RetainedLookup,
        manual_authorization_id(proposal.identity(), &account_id)
    )?;
    let Some(original) = flow_observe!(
        observer,
        RetainedLookup,
        journal.original_authorization(&authorization_id, session)
    )?
    else {
        return Ok(None);
    };
    flow_observe!(
        observer,
        RetainedLookup,
        validate_original_binding(&proposal, original.original_consent(), &account_id)
    )?;
    let lease = flow_observe!(
        observer,
        RetainedLookup,
        journal.acquire_original_authorization(&authorization_id, session)
    )?;
    let result = retained_lookup_result(
        journal.bridge_result(&lease),
        #[cfg(feature = "synthetic-born-joined-qualification")]
        observer,
    )?;
    flow_observe!(observer, RetainedLookup, check_reload(source, &proposal))?;
    Ok(Some(AuthorizationCommit::from(&result)))
}

fn retained_lookup_result<T>(
    original: Result<T>,
    #[cfg(feature = "synthetic-born-joined-qualification")] observer: Option<
        &DurableFlowObserverV1,
    >,
) -> Result<T> {
    flow_observe!(observer, RetainedLookup, original).map_err(recovery_if_incomplete)
}

fn recovery_if_incomplete(error: BridgeError) -> BridgeError {
    match error {
        BridgeError::Missing | BridgeError::Uncertain => BridgeError::RecoveryRequired,
        other => other,
    }
}

fn require_unreleased(
    journal: &SignerConsentJournal,
    session: &SignerConsentSession,
    identity: &FixedProposalIdentityV1,
    authorization_id: &str,
    account_id: &str,
) -> Result<()> {
    require_unreleased_inner(
        journal,
        session,
        identity,
        authorization_id,
        account_id,
        #[cfg(feature = "synthetic-born-joined-qualification")]
        None,
    )
}
fn require_unreleased_inner(
    journal: &SignerConsentJournal,
    session: &SignerConsentSession,
    identity: &FixedProposalIdentityV1,
    authorization_id: &str,
    account_id: &str,
    #[cfg(feature = "synthetic-born-joined-qualification")] observer: Option<
        &DurableFlowObserverV1,
    >,
) -> Result<()> {
    if let Some(original) = flow_observe!(
        observer,
        AuthorizationSource,
        journal.original_authorization(authorization_id, session)
    )? {
        let t = original.original_consent().terms();
        if t.account_id != account_id
            || t.proposal_id != identity.proposal_id
            || t.proposal_digest != identity.proposal_digest
            || t.artifact_digest != identity.proved_artifact_digest
            || t.manifest_digest != identity.manifest_digest
        {
            return Err(BridgeError::Conflict);
        }
        return Err(BridgeError::RecoveryRequired);
    }
    Ok(())
}

fn check_reload(source: &FixedProposalSource, original: &VerifiedFixedProposal) -> Result<()> {
    let current = source()?;
    if current.identity() != original.identity()
        || current.private_proved_pczt_bytes() != original.private_proved_pczt_bytes()
        || policy_fingerprint(current.private_review_policy())
            != policy_fingerprint(original.private_review_policy())
    {
        return Err(BridgeError::Conflict);
    }
    Ok(())
}

fn validate_review_inputs(
    fixed: &VerifiedFixedProposal,
    manifest: &AcceptedManifestRecord,
    inputs: &ReviewInputs,
) -> Result<()> {
    let identity = fixed.identity();
    let proposal = wholepact_core::Proposal::validate(manifest.proposal_input().clone())
        .map_err(|_| BridgeError::Binding)?;
    if proposal.input().proposal_id != identity.proposal_id
        || proposal.proposal_digest() != identity.proposal_digest
        || proposal.manifest_digest() != identity.manifest_digest
        || inputs.policy.participants.len() != 2
        || policy_fingerprint(&inputs.policy) != identity.policy_digest
        || hex::encode(inputs.policy.anchor) != identity.anchor
        || inputs.own_selection.key_use_policy.is_none()
    {
        return Err(BridgeError::Binding);
    }
    verify_manifest_policy(
        &proposal,
        &inputs.policy,
        &inputs.input_actions,
        &inputs.output_actions,
    )
    .map_err(|_| BridgeError::Verification)?;
    fixed
        .verify_action_mappings(&inputs.input_actions, &inputs.output_actions)
        .map_err(|_| BridgeError::Binding)?;
    Ok(())
}

fn validate_original_binding(
    fixed: &VerifiedFixedProposal,
    original: &OriginalSpendConsent,
    account_id: &str,
) -> Result<()> {
    let identity = fixed.identity();
    let t = original.terms();
    validate_terms_binding(identity, t, account_id)?;
    let policy = fixed.private_review_policy();
    let owner = policy
        .participants
        .iter()
        .position(|p| p.account_id == account_id)
        .ok_or(BridgeError::Binding)?;
    let own_inputs: Vec<_> = policy
        .inputs
        .iter()
        .filter(|input| input.participant_index == owner)
        .collect();
    if fixed.economic_review().net_debits_zatoshis().get(owner) != Some(&t.maximum_debit_zatoshis)
        || t.transaction_fee_zatoshis != policy.exact_fee_zatoshis
        || t.fee_share_zatoshis != policy.participants[owner].fee_share_zatoshis
        || own_inputs.len() != t.input_bindings.len()
        || own_inputs.iter().any(|input| {
            !t.input_bindings.iter().any(|bound| {
                bound.action_index == input.action_index as u64
                    && bound.nullifier == hex::encode(input.nullifier)
                    && bound.value_zatoshis == input.value_zatoshis
            })
        })
    {
        return Err(BridgeError::Binding);
    }
    Ok(())
}

fn validate_terms_binding(
    identity: &FixedProposalIdentityV1,
    t: &SpendConsentTerms,
    account_id: &str,
) -> Result<()> {
    if t.automation.is_some()
        || t.sponsor_policy.is_some()
        || t.sponsor_owner_attestation_digest.is_some()
        || t.account_id != account_id
        || t.authorization_id != manual_authorization_id(identity, account_id)?
        || t.agreement_id != identity.agreement_id
        || t.obligation_id != identity.obligation_id
        || t.proposal_id != identity.proposal_id
        || t.proposal_digest != identity.proposal_digest
        || t.manifest_digest != identity.manifest_digest
        || t.artifact_digest != identity.proved_artifact_digest
        || t.effects_digest != identity.effects_commitment
        || t.review_binding != identity.review_binding
        || t.wallet_snapshot.anchor_root != identity.anchor
        || t.transaction_expiry_height != identity.expiry_height
        || t.wallet_key_use_policy.is_none()
    {
        return Err(BridgeError::Binding);
    }
    Ok(())
}

fn check_ticket(original: &OriginalSpendConsent, ticket: &WalletKeyUseTicket) -> Result<()> {
    check_ticket_inner(
        original,
        ticket,
        #[cfg(feature = "synthetic-born-joined-qualification")]
        None,
    )
}
fn check_ticket_inner(
    original: &OriginalSpendConsent,
    ticket: &WalletKeyUseTicket,
    #[cfg(feature = "synthetic-born-joined-qualification")] observer: Option<
        &DurableFlowObserverV1,
    >,
) -> Result<()> {
    let t = original.terms();
    let policy = flow_observe!(
        observer,
        WalletGuard,
        t.wallet_key_use_policy
            .as_ref()
            .ok_or(BridgeError::Permission)
    )?;
    flow_observe!(observer, WalletGuard, ticket.validate_policy(policy))?;
    let evidence = ticket.evidence();
    let context = evidence.context();
    if evidence.account_id() != t.account_id
        || context.tip_height != t.wallet_snapshot.tip_height
        || hex::encode(context.tip_hash_protocol) != t.wallet_snapshot.tip_hash
        || context.anchor_height != t.wallet_snapshot.anchor_height
        || hex::encode(context.anchor_hash_protocol) != t.wallet_snapshot.anchor_hash
        || hex::encode(context.anchor_root) != t.wallet_snapshot.anchor_root
        || evidence.inputs().len() != t.input_bindings.len()
        || t.input_bindings.iter().any(|input| {
            !evidence.inputs().iter().any(|selected| {
                selected.input_id() == input.input_id
                    && hex::encode(selected.nullifier()) == input.nullifier
                    && selected.value_zatoshis() == input.value_zatoshis
            })
        })
    {
        return flow_observe!(observer, WalletGuard, Err(BridgeError::Binding));
    }
    Ok(())
}

#[cfg(test)]
#[path = "durable_proposal_v1_tests.rs"]
mod tests;

#[cfg(all(test, feature = "synthetic-born-joined-qualification"))]
mod diagnostic_mapping_tests {
    use super::*;
    use super::super::durable_flow_diagnostics_v1::{
        DurableFlowCollectorV1, DurableFlowErrorCodeV1, DurableFlowOperationV1,
        DurableFlowResultV1, DurableFlowStageV1,
    };
    #[test]
    fn durable_flow_retained_lookup_preserves_original_before_recovery_mapping() {
        for missing in [false, true] {
            let collector = DurableFlowCollectorV1::default();
            let observer = collector.arm(DurableFlowOperationV1::RetainedRetry);
            let original = if missing {
                BridgeError::Missing
            } else {
                BridgeError::Uncertain
            };
            let result: Result<()> = retained_lookup_result(Err(original), Some(&observer));
            assert!(matches!(result, Err(BridgeError::RecoveryRequired)));
            let diagnostic = observer.finish(DurableFlowResultV1::ReturnedErr).unwrap();
            let first = diagnostic.first_error().unwrap();
            assert!(first.stage() == DurableFlowStageV1::RetainedLookup);
            assert!(
                first.code()
                    == if missing {
                        DurableFlowErrorCodeV1::BridgeMissing
                    } else {
                        DurableFlowErrorCodeV1::BridgeUncertain
                    }
            );
        }
        let ordinary: Result<()> = retained_lookup_result(Err(BridgeError::Missing), None);
        assert!(matches!(ordinary, Err(BridgeError::RecoveryRequired)));
    }
    #[test]
    fn durable_flow_retained_lookup_does_not_reconstruct_other_errors() {
        let collector = DurableFlowCollectorV1::default();
        let observer = collector.arm(DurableFlowOperationV1::RetainedRetry);
        let original = BridgeError::Journal(crate::consent_journal::JournalError::Database);
        let result: Result<()> = retained_lookup_result(Err(original), Some(&observer));
        assert!(matches!(
            result,
            Err(BridgeError::Journal(
                crate::consent_journal::JournalError::Database
            ))
        ));
        assert!(
            observer
                .finish(DurableFlowResultV1::ReturnedErr)
                .unwrap()
                .first_error()
                .unwrap()
                .code()
                == DurableFlowErrorCodeV1::BridgeJournal
        );
    }
}
