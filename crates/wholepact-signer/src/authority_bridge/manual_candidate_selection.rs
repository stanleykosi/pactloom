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
use wholepact_core::manual_candidate_selection::ManualCandidateSelectionRequest;
use wholepact_signer_origin::{
    ManualCandidateSelectionLease, manual_candidate_selection::ManualCandidateSelectionEvidence,
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
pub struct SignerCandidateSelectionLease<'client> {
    native: ManualCandidateSelectionLease<'client>,
    fvk: FullViewingKey,
    selection_attempted: std::sync::atomic::AtomicBool,
}
impl<'client> SignerCandidateSelectionLease<'client> {
    /// Consume only the real installed-peer result of the candidate-selection native
    /// disclosure. This does not renew any deadline or create scan permission.
    pub fn from_native_lease(native: ManualCandidateSelectionLease<'client>) -> Result<Self> {
        native.check_current()?;
        native.evidence().validate()?;
        let expected = &native
            .binding()
            .scope
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
        let scope = &request.scope.inventory;
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
        Ok(selected)
    }

    /// Checks the actual installed process, exact evidence challenge, original
    /// native/request deadlines and revocation state. Failure is not renewable.
    pub fn check_current(&self) -> Result<()> {
        self.native.check_current().map_err(Into::into)
    }

    /// Exact reviewed request from the held native channel, not a caller claim.
    pub fn request(&self) -> Result<&ManualCandidateSelectionRequest> {
        self.check_current()?;
        Ok(self.native.binding())
    }

    /// Audit material only. Copying it cannot recreate this viewing owner.
    pub fn evidence(&self) -> Result<&ManualCandidateSelectionEvidence> {
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
