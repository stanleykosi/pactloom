//! Explicit ephemeral native trust decision. No runtime entry or issuer adapter
//! exists until owner-authenticated offline setup is implemented. Public signature
//! evidence alone cannot manufacture this private decision.
use super::*;
use wholepact_offline_bridge::{
    NamedVerifierExpectedContext, NamedVerifierSignatureEvidence, SelectedOfflineEffectsReport,
    inspect_named_verifier_package,
};

pub(super) struct PreparedNamedVerifierReview<'a> {
    vault: &'a AccountVault,
    own: SelectedOfflineEffectsReport,
    account_id: String,
    source: NativeAuthorityBinding,
    evidence: NamedVerifierSignatureEvidence,
    review: ExactNativeReview,
}
pub(super) struct ApprovedNamedVerifierReview<'a> {
    vault: &'a AccountVault,
    own: SelectedOfflineEffectsReport,
    account_id: String,
    source: NativeAuthorityBinding,
    evidence: NamedVerifierSignatureEvidence,
    decided: Instant,
}
impl<'a> PreparedNamedVerifierReview<'a> {
    /// `selected_key` must come from the explicit local key-selection control,
    /// never a key/name field read from the incoming attestation.
    pub(super) fn prepare(
        vault: &'a AccountVault,
        authority: &NativeAuthority,
        own_policy: &wholepact_protocol::own_effects::OwnEffectsPolicy,
        package: &[u8],
        selected_key: [u8; 32],
        expected: &NamedVerifierExpectedContext<'_>,
        focus_epoch: u64,
    ) -> Result<Self> {
        authority.check_current()?;
        let account_id = vault.account_id()?;
        if vault.account().recovery_required()
            || account_id != expected.own_account_id
            || own_policy.account_id != account_id
            || own_policy.own_fvk.to_bytes() != vault.account().fvk()?.to_bytes()
        {
            return Err(Error::ReviewMismatch);
        }
        let inspected =
            inspect_named_verifier_package(package, own_policy, &selected_key, expected)
                .map_err(|_| Error::Verification)?;
        let package_digest = inspected.package_digest().to_owned();
        let (own, evidence) = inspected.into_evidence();
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-named-verifier-selection:v1",
            &(
                &package_digest,
                evidence.statement_digest(),
                evidence.verifier_key_digest(),
                own.inspection().artifact_digest(),
                own.inspection().policy_digest(),
                authority.principal_id(),
                authority.measurement(),
            ),
        )
        .map_err(|_| Error::InvalidData)?;
        let display = format!(
            "OPTIONAL NAMED-VERIFIER TRUST DECISION\nVerifier key SHA-256: {}\nExact signed assertion: {}\nExact reviewed artifact: {}\n\nYou explicitly trust this verifier's complete indexed input ownership, return allocation and contribution/fee assertions. A dishonest verifier can misstate peers and hide an own-controlled input under a peer label. Your selected-own checks cannot establish complete own-input coverage. Its signature authenticates its assertion, not its truth or spending permission. This is not independent multi-owner verification.\n\nIndependently checked selected-own debit: {} zatoshis; own return: {} zatoshis.\nVerifier-attested: full indexed ownership/return allocation and retained-manifest economics, with claimed original proof verification.\nUnknown: current chain, current unspentness, freshness after restart, revocation, external clones and complete account exposure.\nOriginal asserted validity: {}..{} ms; transaction expiry: {}. Local clock does not establish current validity.\n\nThis decision grants no credential, setup, reservation, signature, export, submission or settlement authority. No attested mode is selected by default.\nExact native review: {}",
            evidence.verifier_key_digest(),
            evidence.statement_digest(),
            own.inspection().artifact_digest(),
            own.inspection().selected_net_debit_zatoshis(),
            own.inspection().own_return_zatoshis(),
            evidence.statement().validity_not_before_ms,
            evidence.statement().validity_expires_ms,
            evidence.statement().transaction_expiry_height,
            digest
        );
        let review = ExactNativeReview::stage(authority, &digest, display, focus_epoch)?;
        Ok(Self {
            vault,
            own,
            account_id,
            source: authority.binding(),
            evidence,
            review,
        })
    }
    fn check(&self) -> Result<()> {
        self.source.check_current()?;
        if self.vault.account().recovery_required() || self.vault.account_id()? != self.account_id {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    pub(super) fn display(&self) -> &str {
        self.review.display()
    }
    pub(super) fn continue_from_native_click(&mut self, focused: bool, epoch: u64) -> Result<()> {
        self.check()?;
        self.review.continue_from_native_click(focused, epoch)
    }
    pub(super) fn confirm_from_native_click(
        self,
        focused: bool,
        epoch: u64,
        phrase: &str,
    ) -> Result<ApprovedNamedVerifierReview<'a>> {
        self.check()?;
        let decision = self.review.consume_native_click(focused, epoch, phrase)?;
        if decision.binding() != &self.source {
            return Err(Error::ReviewMismatch);
        }
        Ok(ApprovedNamedVerifierReview {
            vault: self.vault,
            own: self.own,
            account_id: self.account_id,
            source: self.source,
            evidence: self.evidence,
            decided: Instant::now(),
        })
    }
}
impl ApprovedNamedVerifierReview<'_> {
    pub(super) fn check_current(&self) -> Result<()> {
        self.source.check_current()?;
        if self.decided.elapsed() >= REVIEW_LIFETIME
            || self.vault.account().recovery_required()
            || self.vault.account_id()? != self.account_id
            || self.evidence.statement().recipient_artifact_digest
                != self.own.inspection().artifact_digest()
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
}
