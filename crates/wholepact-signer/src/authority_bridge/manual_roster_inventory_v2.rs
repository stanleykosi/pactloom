//! Maintained viewing-key consumer for the genuine candidate-free native lease.
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
use wholepact_core::manual_roster_inventory_v2::ManualRosterInventoryRequestV2;
use wholepact_signer_origin::{
    ManualRosterInventoryLeaseV2, manual_roster_inventory_v2::ManualRosterInventoryEvidenceV2,
};
use wholepact_wallet::wallet::{AccountUuid, protected_sync::ProtectedWalletSync};
use zeroize::Zeroizing;

/// Candidate-free viewing owner. No Clone, Debug, Serialize or Deserialize and
/// no conversion into a contribution, construction admission or key-use owner.
/// Dropping it also drops the real lower lease and its current-channel slot.
///
/// Orchard's maintained FullViewingKey does not implement Zeroize. Temporary
/// raw encodings and the lower retained bytes are zeroized, but this type makes
/// no secure-memory or revocation-of-already-disclosed-data claim.
pub struct SignerRosterInventoryLeaseV2<'client> {
    native: ManualRosterInventoryLeaseV2<'client>,
    fvk: FullViewingKey,
}
impl<'client> SignerRosterInventoryLeaseV2<'client> {
    /// Consume this viewing owner and complete the exact native channel before
    /// any separate purpose is paired. Imported data cannot be recalled.
    pub fn finish(self) -> Result<()> {
        self.native.finish().map_err(Into::into)
    }

    /// Consume only the real installed-peer result of the preliminary native
    /// disclosure. This does not renew any deadline or create scan permission.
    pub fn from_native_lease(native: ManualRosterInventoryLeaseV2<'client>) -> Result<Self> {
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
        Ok(Self { native, fvk })
    }

    /// Checks the actual installed process, exact evidence challenge, original
    /// native/request deadlines and revocation state. Failure is not renewable.
    pub fn check_current(&self) -> Result<()> {
        let result = self.native.check_current();
        #[cfg(feature = "synthetic-born-joined-qualification")]
        if let Err(error) = &result {
            eprintln!(
                "\n[JOINED_DIAGNOSTIC InventoryLeaseOrigin {}]",
                native_lease_error_kind(error)
            );
        }
        result.map_err(Into::into)
    }

    /// Exact reviewed request from the held native channel, not a caller claim.
    pub fn request(&self) -> Result<&ManualRosterInventoryRequestV2> {
        self.check_current()?;
        Ok(self.native.binding())
    }

    /// Audit material only. Copying it cannot recreate this viewing owner.
    pub fn evidence(&self) -> Result<&ManualRosterInventoryEvidenceV2> {
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

/// Synthetic-only closed projection before the existing bridge conversion.
/// In particular, never format an OS error, path, or message payload.
#[cfg(feature = "synthetic-born-joined-qualification")]
pub(super) fn native_lease_error_kind(error: &wholepact_signer_origin::Error) -> &'static str {
    use wholepact_signer_origin::Error as E;
    match error {
        E::PermanentStopUnavailable => "OriginPermanentStopUnavailable",
        E::RetirementEvidenceUnavailable => "OriginRetirementEvidenceUnavailable",
        E::SignerOriginUnavailable => "OriginSignerOriginUnavailable",
        E::PeerLifetimeUnavailable => "OriginPeerLifetimeUnavailable",
        E::Authentication => "OriginAuthentication",
        E::Binding => "OriginBinding",
        E::Conflict => "OriginConflict",
        E::Permission => "OriginPermission",
        E::InvalidData => "OriginInvalidData",
        E::Locked => "OriginLocked",
        E::Crypto => "OriginCrypto",
        E::Ipc => "OriginIpc",
        E::Limit => "OriginLimit",
        E::Io(error) => match error.kind() {
            std::io::ErrorKind::TimedOut => "OriginIoTimedOut",
            std::io::ErrorKind::WouldBlock => "OriginIoWouldBlock",
            std::io::ErrorKind::UnexpectedEof => "OriginIoUnexpectedEof",
            std::io::ErrorKind::BrokenPipe => "OriginIoBrokenPipe",
            std::io::ErrorKind::ConnectionReset => "OriginIoConnectionReset",
            std::io::ErrorKind::ConnectionAborted => "OriginIoConnectionAborted",
            std::io::ErrorKind::NotConnected => "OriginIoNotConnected",
            std::io::ErrorKind::Interrupted => "OriginIoInterrupted",
            std::io::ErrorKind::PermissionDenied => "OriginIoPermissionDenied",
            _ => "OriginIoOther",
        },
    }
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

    #[cfg(feature = "synthetic-born-joined-qualification")]
    #[test]
    fn native_lease_error_projection_never_formats_private_payloads() {
        use wholepact_signer_origin::Error as E;
        assert_eq!(native_lease_error_kind(&E::Permission), "OriginPermission");
        assert_eq!(native_lease_error_kind(&E::Binding), "OriginBinding");
        for (kind, expected) in [
            (std::io::ErrorKind::TimedOut, "OriginIoTimedOut"),
            (std::io::ErrorKind::WouldBlock, "OriginIoWouldBlock"),
            (std::io::ErrorKind::Other, "OriginIoOther"),
        ] {
            let error = E::Io(std::io::Error::new(kind, "private payload must not escape"));
            assert_eq!(native_lease_error_kind(&error), expected);
        }
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
