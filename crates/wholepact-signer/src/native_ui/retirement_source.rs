//! Purpose-specific signer-local identity inspection. No viewing-key export,
//! signing, wallet access, history completeness or retirement completion permit.
use super::retirement_destination::RecoveryDestinationRequest;
use super::retirement_recipient::RetirementEvidenceRecipient;
use super::{NativeAuthority, NativeAuthorityBinding, NativeDecision};
use crate::{Error, Result, account::AccountVault};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

pub(super) struct PreparedRetirementSource {
    source: NativeAuthorityBinding,
    recipient: Option<RetirementEvidenceRecipient>,
    request_digest: String,
    digest: String,
    account_id: String,
    request_display: String,
    fvk_digest: String,
    started: Instant,
}
/// Only a consumed exact native decision constructs this purpose-specific owner.
/// Deliberately no FVK getter or conversion to any financial/wallet authority.
pub(super) struct RetirementSourceRead(PreparedRetirementSource);
/// Original source review identity and deadline retained by the destination.
/// No deserialization or constructor from a claimed review digest exists.
pub(super) struct RetirementSourceDeliveryBinding {
    native: NativeAuthorityBinding,
    digest: String,
    started: Instant,
}
impl RetirementSourceDeliveryBinding {
    pub(super) fn digest(&self) -> &str {
        &self.digest
    }
    pub(super) fn check_current(&self) -> Result<()> {
        self.native.check_current()?;
        if self.started.elapsed() >= Duration::from_secs(120) {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    pub(super) fn require_source(&self, source: &RetirementSourceRead) -> Result<()> {
        self.check_current()?;
        source.check_liveness()?;
        if self.native != source.0.source
            || self.digest != source.0.digest
            || self.started != source.0.started
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
}
impl PreparedRetirementSource {
    pub(super) fn prepare(
        vault: &AccountVault,
        native: &NativeAuthority,
        request: &RecoveryDestinationRequest,
    ) -> Result<Self> {
        Self::prepare_with_recipient(vault, native, request, None)
    }
    /// Unconnected evidence-only adapter. A pairing grant requests access;
    /// this separate exact source decision is still required.
    #[allow(dead_code)]
    pub(super) fn prepare_for_peer(
        vault: &AccountVault,
        native: &NativeAuthority,
        request: &RecoveryDestinationRequest,
        peer: crate::ipc::AuthenticatedPeer,
    ) -> Result<Self> {
        let recipient = RetirementEvidenceRecipient::from_peer(peer)?;
        Self::prepare_with_recipient(vault, native, request, Some(recipient))
    }
    pub(super) fn prepare_with_recipient(
        vault: &AccountVault,
        native: &NativeAuthority,
        request: &RecoveryDestinationRequest,
        recipient: Option<RetirementEvidenceRecipient>,
    ) -> Result<Self> {
        native.check_current()?;
        request.validate()?;
        if let Some(recipient) = &recipient {
            recipient.check_source(native, request)?;
        }
        let started = Instant::now();
        if vault.account().recovery_required() {
            return Err(Error::RecoveryRequired);
        }
        let account_id = vault.account_id()?;
        let fvk_digest = hex::encode(Sha256::digest(vault.account().fvk()?.to_bytes()));
        if request.source_account_id != account_id || request.source_fvk_digest != fvk_digest {
            return Err(Error::ReviewMismatch);
        }
        let request_digest = request_digest(request)?;
        // A peer disclosure decision belongs to this exact preparation. Repeating
        // the same request/grant cannot refresh an older decision or source lease.
        let preparation_nonce = recipient
            .as_ref()
            .map(|_| crate::vault::random::<32>())
            .transpose()?;
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-retirement-source-read:v2",
            &(
                &request_digest,
                &account_id,
                &fvk_digest,
                native.principal_id(),
                native.measurement(),
                recipient.as_ref().map(|r| r.digest()),
                preparation_nonce,
            ),
        )
        .map_err(|_| Error::InvalidData)?;
        Ok(Self {
            source: native.binding(),
            recipient,
            request_digest,
            digest,
            account_id,
            request_display: format!(
                "Operation: {}\nLocal recipient: {}\nDestination account: {}\nExact destination address: {}\nNetwork: {}",
                request.operation_id,
                request.local_recipient,
                request.destination_account_id,
                request.address,
                request.network_profile_id
            ),
            fvk_digest,
            started,
        })
    }
    pub(super) fn digest(&self) -> &str {
        &self.digest
    }
    pub(super) fn display(&self) -> String {
        format!(
            "Review source identity for local retirement evidence only.\nActual unlocked source account: {}\n{}\nExact destination request commitment: {}\nThis permission reads local identity only. No viewing key is exported, no wallet or witness is queried, no transfer is signed, and no exclusion is recorded. Earliest activity, full account components, pending/full transactions, canonical unspentness and all authorization/reservation exposure remain unknown. Zero local balances elsewhere cannot complete retirement. Prior viewing-key disclosure cannot be revoked.\nExact native review: {}",
            self.account_id, self.request_display, self.request_digest, self.digest
        ) + &self
            .recipient
            .as_ref()
            .map_or_else(String::new, |r| r.display())
    }
    pub(super) fn check_current(&self, vault: &AccountVault) -> Result<()> {
        self.source.check_current()?;
        if let Some(recipient) = &self.recipient {
            recipient.check_current()?;
        }
        if self.started.elapsed() >= Duration::from_secs(120)
            || vault.account().recovery_required()
            || vault.account_id()? != self.account_id
            || hex::encode(Sha256::digest(vault.account().fvk()?.to_bytes())) != self.fvk_digest
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    pub(super) fn approve(
        self,
        vault: &AccountVault,
        native: &NativeAuthority,
        decision: NativeDecision,
    ) -> Result<RetirementSourceRead> {
        self.check_current(vault)?;
        native.check_current()?;
        if decision.binding() != &self.source
            || native.binding() != self.source
            || decision.reviewed_digest() != self.digest
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(RetirementSourceRead(self))
    }
}
impl RetirementSourceRead {
    pub(super) fn review_digest(&self) -> &str {
        &self.0.digest
    }
    /// Restrictions on the original preparation; no call starts a fresh lease.
    pub(super) fn deadline(&self) -> Instant {
        let mut deadline = self.0.started + Duration::from_secs(120);
        if let Some(native) = self.0.source.deadline() {
            deadline = deadline.min(native);
        }
        if let Some(recipient) = &self.0.recipient {
            deadline = deadline.min(recipient.deadline());
        }
        deadline
    }
    pub(super) fn delivery_binding(&self) -> Result<RetirementSourceDeliveryBinding> {
        self.check_liveness()?;
        self.recipient().ok_or(Error::Authentication)?;
        Ok(RetirementSourceDeliveryBinding {
            native: self.0.source.clone(),
            digest: self.0.digest.clone(),
            started: self.0.started,
        })
    }
    pub(super) fn check_liveness(&self) -> Result<()> {
        self.0.source.check_current()?;
        if let Some(recipient) = &self.0.recipient {
            recipient.check_current()?;
        }
        if self.0.started.elapsed() >= Duration::from_secs(120) {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    pub(super) fn recipient(&self) -> Option<&RetirementEvidenceRecipient> {
        self.0.recipient.as_ref()
    }
    pub(super) fn check_recipient(
        &self,
        recipient: Option<&RetirementEvidenceRecipient>,
    ) -> Result<()> {
        self.check_liveness()?;
        match (self.recipient(), recipient) {
            (None, None) => Ok(()),
            (Some(source), Some(destination)) => source.require_same(destination),
            _ => Err(Error::Authentication),
        }
    }
    pub(super) fn check_destination(
        &self,
        vault: &AccountVault,
        request: &RecoveryDestinationRequest,
    ) -> Result<()> {
        self.0.check_current(vault)?;
        if request_digest(request)? != self.0.request_digest {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
}
fn request_digest(request: &RecoveryDestinationRequest) -> Result<String> {
    wholepact_core::proposal::canonical_digest(
        "wholepact:retirement-source-exact-destination:v1",
        request,
    )
    .map_err(|_| Error::InvalidData)
}

#[cfg(all(test, feature = "synthetic-qualification"))]
mod tests {
    use super::super::retirement_destination::PreparedRecoveryDestination;
    use super::*;
    use crate::{
        account::PendingAccount,
        native_ui::authority::{recovery_test_authority, recovery_test_decision},
    };
    fn vault(path: &std::path::Path, index: u8) -> AccountVault {
        let pending = PendingAccount::fixed_never_funded_qualification(index).unwrap();
        let words = pending.recovery_words().unwrap();
        AccountVault::create(
            path,
            pending.verify_backup(&words).unwrap(),
            b"synthetic-retirement-owner",
        )
        .unwrap()
    }
    fn request(source: &AccountVault, destination: &AccountVault) -> RecoveryDestinationRequest {
        RecoveryDestinationRequest {
            operation_id: "synthetic-local-evidence".into(),
            destination_account_id: destination.account_id().unwrap(),
            address: wholepact_protocol::review::encode_testnet_receiver(
                &destination
                    .account()
                    .fvk()
                    .unwrap()
                    .address_at(0u32, orchard::keys::Scope::External),
            ),
            network_profile_id: wholepact_protocol::construction::PROFILE_ID.into(),
            source_account_id: source.account_id().unwrap(),
            source_fvk_digest: hex::encode(Sha256::digest(
                source.account().fvk().unwrap().to_bytes(),
            )),
            local_recipient: "native-retirement-evidence-panel".into(),
        }
    }
    #[test]
    fn retirement_identity_and_destination_require_two_exact_native_decisions() {
        let dir = tempfile::tempdir().unwrap();
        let source = vault(&dir.path().join("source"), 0);
        let destination = vault(&dir.path().join("destination"), 1);
        let native = recovery_test_authority();
        let request = request(&source, &destination);
        let prepared = PreparedRetirementSource::prepare(&source, &native, &request).unwrap();
        assert!(prepared.display().contains(&request.address));
        let decision = recovery_test_decision(&native, prepared.digest());
        let owner = prepared.approve(&source, &native, decision).unwrap();
        let prepared =
            PreparedRecoveryDestination::prepare(&destination, &native, request.clone()).unwrap();
        let decision = recovery_test_decision(&native, prepared.digest());
        let approved = prepared.approve(decision, &native).unwrap();
        assert_eq!(
            approved
                .evidence_for_retirement_source(&owner, &source)
                .unwrap()
                .address,
            request.address
        );
        assert!(
            approved
                .evidence_for_retirement_source(&owner, &destination)
                .is_err()
        );
        native.invalidate();
        assert!(
            approved
                .evidence_for_retirement_source(&owner, &source)
                .is_err()
        );
    }
    #[test]
    fn retirement_source_rejects_changed_request_and_wrong_native_window() {
        let dir = tempfile::tempdir().unwrap();
        let source = vault(&dir.path().join("source"), 0);
        let destination = vault(&dir.path().join("destination"), 1);
        let native = recovery_test_authority();
        let request = request(&source, &destination);
        let prepared = PreparedRetirementSource::prepare(&source, &native, &request).unwrap();
        let wrong = recovery_test_authority();
        let decision = recovery_test_decision(&wrong, prepared.digest());
        assert!(prepared.approve(&source, &native, decision).is_err());
        let prepared = PreparedRetirementSource::prepare(&source, &native, &request).unwrap();
        let decision = recovery_test_decision(&native, prepared.digest());
        let owner = prepared.approve(&source, &native, decision).unwrap();
        for field in 0..4 {
            let mut changed = request.clone();
            match field {
                0 => changed.operation_id.push('x'),
                1 => changed.local_recipient.push('x'),
                2 => changed.address.push('x'),
                _ => changed.source_fvk_digest = "22".repeat(32),
            }
            assert!(owner.check_destination(&source, &changed).is_err());
        }
    }
    #[test]
    fn destination_reprepare_cannot_refresh_retirement_source_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let source = vault(&dir.path().join("source"), 0);
        let destination = vault(&dir.path().join("destination"), 1);
        let native = recovery_test_authority();
        let request = request(&source, &destination);
        let prepared = PreparedRetirementSource::prepare(&source, &native, &request).unwrap();
        let decision = recovery_test_decision(&native, prepared.digest());
        let mut owner = prepared.approve(&source, &native, decision).unwrap();
        owner.0.started = Instant::now() - Duration::from_secs(121);
        let prepared =
            PreparedRecoveryDestination::prepare(&destination, &native, request).unwrap();
        let decision = recovery_test_decision(&native, prepared.digest());
        let approved = prepared.approve(decision, &native).unwrap();
        assert!(
            approved
                .evidence_for_retirement_source(&owner, &source)
                .is_err()
        );
    }
}
