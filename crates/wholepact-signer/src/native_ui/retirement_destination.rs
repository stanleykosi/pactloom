//! Native-only destination ownership approval for local evidence inspection.
//! The issuer uses the actual unlocked account and one-shot native decision;
//! no caller-supplied FVK, verified flag or deserialized approval exists.
#![allow(dead_code)] // Retains the separately staged preconstruction adapter.
use super::retirement_recipient::RetirementEvidenceRecipient;
use super::{NativeAuthority, NativeAuthorityBinding, NativeDecision};
use crate::{Error, Result, account::AccountVault};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
use wholepact_core::retirement::{ShieldedReceiverPool, UserControlledShieldedDestination};
use wholepact_protocol::{construction::PROFILE_ID, review::decode_testnet_receiver};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryDestinationRequest {
    pub operation_id: String,
    pub destination_account_id: String,
    pub address: String,
    pub network_profile_id: String,
    pub source_account_id: String,
    pub source_fvk_digest: String,
    /// Local-panel label, or the exact authenticated grant ID on the staged
    /// peer route. This string alone never confers recipient or ownership authority.
    pub local_recipient: String,
}
impl RecoveryDestinationRequest {
    pub(super) fn validate(&self) -> Result<()> {
        for id in [
            &self.operation_id,
            &self.destination_account_id,
            &self.source_account_id,
            &self.local_recipient,
        ] {
            if id.is_empty()
                || id.len() > 128
                || !id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
            {
                return Err(Error::InvalidData);
            }
        }
        wholepact_core::proposal::validate_sha256(&self.source_fvk_digest)
            .map_err(|_| Error::InvalidData)?;
        if self.network_profile_id != PROFILE_ID
            || self.destination_account_id == self.source_account_id
        {
            return Err(Error::ReviewMismatch);
        }
        decode_testnet_receiver(&self.address).map_err(|_| Error::ReviewMismatch)?;
        Ok(())
    }
}
pub(super) struct PreparedRecoveryDestination<'a> {
    vault: &'a AccountVault,
    request: RecoveryDestinationRequest,
    source: NativeAuthorityBinding,
    recipient: Option<RetirementEvidenceRecipient>,
    retirement_source: Option<super::retirement_source::RetirementSourceDeliveryBinding>,
    destination_fvk_digest: String,
    digest: String,
    started: Instant,
}
/// A local native authorization to attest this exact destination ownership fact.
/// It is not an IPC credential, permission to share an FVK, or spending approval.
pub(super) struct ApprovedRecoveryDestination<'a>(PreparedRecoveryDestination<'a>);
impl<'a> PreparedRecoveryDestination<'a> {
    pub(super) fn prepare(
        vault: &'a AccountVault,
        authority: &NativeAuthority,
        request: RecoveryDestinationRequest,
    ) -> Result<Self> {
        Self::prepare_with_recipient(vault, authority, request, None, None)
    }
    /// The already-approved dedicated source owner carries the actual recipient
    /// grant. A local-only source decision cannot be promoted into disclosure.
    pub(super) fn prepare_for_retirement_recipient(
        vault: &'a AccountVault,
        authority: &NativeAuthority,
        request: RecoveryDestinationRequest,
        source: &super::retirement_source::RetirementSourceRead,
        source_vault: &AccountVault,
    ) -> Result<Self> {
        source.check_destination(source_vault, &request)?;
        let recipient = source.recipient().ok_or(Error::Authentication)?.clone();
        Self::prepare_with_recipient(
            vault,
            authority,
            request,
            Some(recipient),
            Some(source.delivery_binding()?),
        )
    }
    fn prepare_with_recipient(
        vault: &'a AccountVault,
        authority: &NativeAuthority,
        request: RecoveryDestinationRequest,
        recipient: Option<RetirementEvidenceRecipient>,
        retirement_source: Option<super::retirement_source::RetirementSourceDeliveryBinding>,
    ) -> Result<Self> {
        authority.check_current()?;
        request.validate()?;
        if let Some(recipient) = &recipient {
            recipient.check_request(&request)?;
            retirement_source
                .as_ref()
                .ok_or(Error::Authentication)?
                .check_current()?;
        } else if retirement_source.is_some() {
            return Err(Error::Authentication);
        }
        if vault.account().recovery_required()
            || vault.account_id()? != request.destination_account_id
        {
            return Err(Error::ReviewMismatch);
        }
        let fvk = vault.account().fvk()?;
        let receiver =
            decode_testnet_receiver(&request.address).map_err(|_| Error::ReviewMismatch)?;
        let destination_fvk_digest = hex::encode(Sha256::digest(fvk.to_bytes()));
        if fvk.scope_for_address(&receiver).is_none()
            || destination_fvk_digest == request.source_fvk_digest
        {
            return Err(Error::ReviewMismatch);
        }
        let preparation_nonce = recipient
            .as_ref()
            .map(|_| crate::vault::random::<32>())
            .transpose()?;
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-recovery-destination-review:v2",
            &(
                &request,
                &destination_fvk_digest,
                authority.principal_id(),
                authority.measurement(),
                recipient.as_ref().map(|r| r.digest()),
                retirement_source.as_ref().map(|s| s.digest()),
                preparation_nonce,
            ),
        )
        .map_err(|_| Error::InvalidData)?;
        Ok(Self {
            vault,
            request,
            source: authority.binding(),
            recipient,
            retirement_source,
            destination_fvk_digest,
            digest,
            started: Instant::now(),
        })
    }
    pub(super) fn digest(&self) -> &str {
        &self.digest
    }
    pub(super) fn display(&self) -> String {
        format!(
            "Approve only this destination ownership fact for the local recipient {}.\nDestination account: {}\nExact shielded address: {}\nNetwork: {}\nSource account claim: {}\nOperation: {}\nThis checks the actual unlocked destination account. Source ownership and complete balances require separate evidence. No viewing key is exported, no transfer is signed, and no funds move. This does not revoke previously disclosed viewing authority.\nExact native review: {}",
            self.request.local_recipient,
            self.request.destination_account_id,
            self.request.address,
            self.request.network_profile_id,
            self.request.source_account_id,
            self.request.operation_id,
            self.digest
        ) + &self
            .recipient
            .as_ref()
            .map_or_else(String::new, |r| r.display())
            + &self
                .retirement_source
                .as_ref()
                .map_or_else(String::new, |s| {
                    format!("\nOriginal exact source review: {}", s.digest())
                })
    }
    pub(super) fn check_current(&self) -> Result<()> {
        self.source.check_current()?;
        if let Some(recipient) = &self.recipient {
            recipient.check_current()?;
        }
        if let Some(source) = &self.retirement_source {
            source.check_current()?;
        }
        if self.started.elapsed() >= Duration::from_secs(120)
            || self.vault.account().recovery_required()
            || self.vault.account_id()? != self.request.destination_account_id
            || hex::encode(Sha256::digest(self.vault.account().fvk()?.to_bytes()))
                != self.destination_fvk_digest
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    pub(super) fn approve(
        self,
        decision: NativeDecision,
        authority: &NativeAuthority,
    ) -> Result<ApprovedRecoveryDestination<'a>> {
        self.check_current()?;
        authority.check_current()?;
        if decision.binding() != &self.source
            || authority.binding() != self.source
            || decision.reviewed_digest() != self.digest
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(ApprovedRecoveryDestination(self))
    }
}
impl ApprovedRecoveryDestination<'_> {
    pub(super) fn deadline(&self) -> Instant {
        let deadline = self.0.started + Duration::from_secs(120);
        self.0
            .source
            .deadline()
            .map_or(deadline, |native| deadline.min(native))
    }
    /// A retained native delivery owner uses this while both actual vault
    /// borrows and original approvals remain live. It never accepts wire approval.
    pub(super) fn evidence_for_retirement_delivery(
        &self,
        source: &super::retirement_source::RetirementSourceRead,
        vault: &AccountVault,
        recipient: &RetirementEvidenceRecipient,
    ) -> Result<UserControlledShieldedDestination> {
        self.0
            .recipient
            .as_ref()
            .ok_or(Error::Authentication)?
            .require_same(recipient)?;
        let evidence = self.retirement_evidence(source, vault)?;
        self.0
            .recipient
            .as_ref()
            .ok_or(Error::Authentication)?
            .require_same(recipient)?;
        Ok(evidence)
    }
    /// The native decision authenticates only the destination. Before adapting
    /// that fact into core recovery evidence, independently recheck the genuine
    /// live source account lease. This does not extend that lease's spending or
    /// disclosure permission; the caller still needs dedicated retirement scope.
    pub(super) fn evidence_for_source(
        &self,
        source: &crate::authority_bridge::preconstruction_ipc::SignerPreconstructionLease<'_>,
    ) -> Result<UserControlledShieldedDestination> {
        if self.0.recipient.is_some() {
            return Err(Error::Authentication);
        }
        source.check_current().map_err(|_| Error::ReviewMismatch)?;
        self.0.check_current()?;
        self.verify_source_binding(
            source.account_id(),
            &source
                .scope()
                .proposal
                .manifest
                .agreement
                .network_profile_id,
            &hex::encode(Sha256::digest(source.fvk().to_bytes())),
        )?;
        let evidence = self.local_evidence()?;
        source.check_current().map_err(|_| Error::ReviewMismatch)?;
        self.0.check_current()?;
        Ok(evidence)
    }
    /// Dedicated signer-local retirement identity scope; no preconstruction or
    /// spending scope is reused by this route.
    pub(super) fn evidence_for_retirement_source(
        &self,
        source: &super::retirement_source::RetirementSourceRead,
        vault: &AccountVault,
    ) -> Result<UserControlledShieldedDestination> {
        source.check_recipient(None)?;
        if self.0.recipient.is_some() {
            return Err(Error::Authentication);
        }
        self.retirement_evidence(source, vault)
    }
    /// One-shot, evidence-only release for the exact current authenticated peer.
    /// No transport is activated here; returned data is informational, never a
    /// deserializable ownership lease or financial authorization.
    pub(super) fn release_for_retirement_peer(
        self,
        source: super::retirement_source::RetirementSourceRead,
        vault: &AccountVault,
        peer: &crate::ipc::AuthenticatedPeer,
    ) -> Result<UserControlledShieldedDestination> {
        let recipient = RetirementEvidenceRecipient::from_peer(peer.clone())?;
        self.release_for_recipient(source, vault, &recipient)
    }
    pub(super) fn release_for_recipient(
        self,
        source: super::retirement_source::RetirementSourceRead,
        vault: &AccountVault,
        recipient: &RetirementEvidenceRecipient,
    ) -> Result<UserControlledShieldedDestination> {
        self.evidence_for_retirement_delivery(&source, vault, recipient)
    }
    fn retirement_evidence(
        &self,
        source: &super::retirement_source::RetirementSourceRead,
        vault: &AccountVault,
    ) -> Result<UserControlledShieldedDestination> {
        source.check_destination(vault, &self.0.request)?;
        source.check_recipient(self.0.recipient.as_ref())?;
        if let Some(original) = &self.0.retirement_source {
            original.require_source(source)?;
        }
        self.0.check_current()?;
        let evidence = self.local_evidence()?;
        source.check_destination(vault, &self.0.request)?;
        source.check_recipient(self.0.recipient.as_ref())?;
        if let Some(original) = &self.0.retirement_source {
            original.require_source(source)?;
        }
        self.0.check_current()?;
        Ok(evidence)
    }
    fn verify_source_binding(&self, account: &str, network: &str, digest: &str) -> Result<()> {
        if account != self.0.request.source_account_id
            || network != self.0.request.network_profile_id
            || digest != self.0.request.source_fvk_digest
            || digest == self.0.destination_fvk_digest
            || account == self.0.request.destination_account_id
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    fn local_evidence(&self) -> Result<UserControlledShieldedDestination> {
        self.0.check_current()?;
        Ok(UserControlledShieldedDestination {
            address: self.0.request.address.clone(),
            user_controlled_account_ref: self.0.request.destination_account_id.clone(),
            network_profile_id: self.0.request.network_profile_id.clone(),
            pool: ShieldedReceiverPool::Ironwood,
            ownership_source_ref: self.0.request.operation_id.clone(),
            ownership_evidence_digest: self.0.digest.clone(),
        })
    }
}

#[cfg(all(test, feature = "synthetic-qualification"))]
mod tests {
    use super::*;
    use crate::{
        account::PendingAccount,
        native_ui::authority::{recovery_test_authority, recovery_test_decision},
    };
    use orchard::keys::{FullViewingKey, Scope, SpendingKey};
    fn vault(path: &std::path::Path) -> AccountVault {
        let pending = PendingAccount::fixed_never_funded_qualification(0).unwrap();
        let words = pending.recovery_words().unwrap();
        AccountVault::create(
            path,
            pending.verify_backup(&words).unwrap(),
            b"synthetic-retirement-passphrase",
        )
        .unwrap()
    }
    fn request(vault: &AccountVault) -> RecoveryDestinationRequest {
        RecoveryDestinationRequest {
            operation_id: "synthetic-destination-check".into(),
            destination_account_id: vault.account_id().unwrap(),
            address: wholepact_protocol::review::encode_testnet_receiver(
                &vault
                    .account()
                    .fvk()
                    .unwrap()
                    .address_at(3u32, Scope::External),
            ),
            network_profile_id: PROFILE_ID.into(),
            source_account_id: "independently-verified-source-needed".into(),
            source_fvk_digest: "11".repeat(32),
            local_recipient: "synthetic-local-host".into(),
        }
    }
    #[test]
    fn retirement_destination_checks_actual_account_and_exact_native_decision() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(&dir.path().join("account"));
        let authority = recovery_test_authority();
        let prepared =
            PreparedRecoveryDestination::prepare(&vault, &authority, request(&vault)).unwrap();
        let decision = recovery_test_decision(&authority, prepared.digest());
        let approved = prepared.approve(decision, &authority).unwrap();
        assert_eq!(
            approved.local_evidence().unwrap().address,
            request(&vault).address
        );
        assert!(
            approved
                .verify_source_binding("different-source", PROFILE_ID, &"11".repeat(32))
                .is_err()
        );
        assert!(
            approved
                .verify_source_binding(
                    &request(&vault).source_account_id,
                    "wrong-network",
                    &"11".repeat(32)
                )
                .is_err()
        );
        assert!(
            approved
                .verify_source_binding(
                    &request(&vault).source_account_id,
                    PROFILE_ID,
                    &"44".repeat(32)
                )
                .is_err()
        );
        authority.invalidate();
        assert!(approved.local_evidence().is_err());
    }
    #[test]
    fn retirement_destination_rejects_substitution_alias_wrong_window_and_digest() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(&dir.path().join("account"));
        let authority = recovery_test_authority();
        let mut wrong = request(&vault);
        wrong.destination_account_id = "wrong-destination-account".into();
        assert!(PreparedRecoveryDestination::prepare(&vault, &authority, wrong).is_err());
        let mut wrong = request(&vault);
        wrong.source_fvk_digest =
            hex::encode(Sha256::digest(vault.account().fvk().unwrap().to_bytes()));
        assert!(PreparedRecoveryDestination::prepare(&vault, &authority, wrong).is_err());
        let mut wrong = request(&vault);
        wrong.network_profile_id = "wrong-network".into();
        assert!(PreparedRecoveryDestination::prepare(&vault, &authority, wrong).is_err());
        let other = FullViewingKey::from(&SpendingKey::from_bytes([72; 32]).unwrap());
        let mut wrong = request(&vault);
        wrong.address = wholepact_protocol::review::encode_testnet_receiver(
            &other.address_at(0u32, Scope::External),
        );
        assert!(PreparedRecoveryDestination::prepare(&vault, &authority, wrong).is_err());
        let prepared =
            PreparedRecoveryDestination::prepare(&vault, &authority, request(&vault)).unwrap();
        let other_window = recovery_test_authority();
        let decision = recovery_test_decision(&other_window, prepared.digest());
        assert!(prepared.approve(decision, &authority).is_err());
        let prepared =
            PreparedRecoveryDestination::prepare(&vault, &authority, request(&vault)).unwrap();
        let decision = recovery_test_decision(&authority, &"33".repeat(32));
        assert!(prepared.approve(decision, &authority).is_err());
    }
}
