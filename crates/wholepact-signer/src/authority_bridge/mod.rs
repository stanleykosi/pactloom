//! Signer-owned exact witness reservation → durable key-use fence → retained
//! authorization/outbox. The coordinator never opens or unlocks this journal.
//! An authenticated witness is required for each exact authorization; neither
//! local history nor deserialized evidence can manufacture a permit or approval.
//! Real enrollment/deployment remains separate from this source implementation.
#[cfg(all(
    feature = "authority-signing",
    feature = "native-ui",
    target_os = "linux"
))]
pub mod automation;
#[cfg(target_os = "linux")]
pub mod born_dispatch_ipc;
#[cfg(target_os = "linux")]
pub mod born_history_ipc;
#[cfg(target_os = "linux")]
pub(crate) mod born_ipc_io;
pub mod disclosure;
#[cfg(target_os = "linux")]
pub mod dispatch_ipc;
#[cfg(all(feature = "durable-proposal", target_os = "linux"))]
pub mod durable_construction_v1;
#[cfg(feature = "durable-proposal")]
pub mod durable_proposal_v1;
#[cfg(target_os = "linux")]
pub mod host_publication_ipc;
#[cfg(target_os = "linux")]
pub mod host_recovery_ipc;
#[cfg(target_os = "linux")]
pub mod ipc;
#[cfg(all(target_os = "linux", feature = "manual-inventory-client"))]
pub mod manual_candidate_selection;
#[cfg(all(target_os = "linux", feature = "manual-inventory-client"))]
pub mod manual_inventory;
#[cfg(target_os = "linux")]
pub mod preconstruction_ipc;
pub mod protocol;
#[cfg(target_os = "linux")]
pub mod provider;
pub mod retired_history;
#[cfg(target_os = "linux")]
pub mod settlement_ipc;
#[cfg(feature = "authority-signing")]
mod signing;
#[cfg(all(
    feature = "durable-proposal",
    feature = "pending-birth-owner-signing",
    feature = "native-ui",
    target_os = "linux"
))]
pub(crate) use signing::DurableBornKeyUseFenceV1;

use crate::{
    account::DedicatedAccount,
    consent_journal::{
        ApprovedSpendConsent, OriginalAuthorizationLease, SignerConsentJournal,
        SignerConsentSession,
    },
};
use protocol::{
    AuthorizationDeliveryScope, RetainedAuthorizationRequest, RetainedAuthorizationResult,
};
use sha2::{Digest, Sha256};
use wholepact_authority::{AuthenticatedPermit, AuthorityClient, AuthorityHead};

pub type Result<T> = std::result::Result<T, BridgeError>;
#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
    #[error("signer bridge exact original account, artifact or permit binding does not match")]
    Binding,
    #[error("immutable signer bridge operation conflicts with its retained original")]
    Conflict,
    #[error("required original signer bridge history is missing")]
    Missing,
    #[error(
        "authorization is uncertain; preserve its original operation and exposure, never sign or select again"
    )]
    Uncertain,
    #[error("signer bridge resource limit reached")]
    Limit,
    #[error("signer bridge current permission is unavailable")]
    Permission,
    #[error("signer requires authoritative history reconciliation")]
    RecoveryRequired,
    #[error(
        "complete-origin host recovery v2 is unavailable until native review, journal continuity, publication and archive consumers are coherently integrated and qualified"
    )]
    CompleteOriginRecoveryUnavailable,
    #[error("signer bridge cryptographic revalidation failed")]
    Verification,
    #[error("authenticated signer-origin client association is unavailable")]
    SignerOriginUnavailable,
    #[error("signer journal refused the operation")]
    Journal(#[from] crate::consent_journal::JournalError),
    #[error("independent authority refused or could not reconcile the exact operation")]
    Authority(#[from] wholepact_authority::AuthorityError),
    #[cfg(feature = "authority-signing")]
    #[error("current signer-owned wallet evidence refused key use")]
    Wallet(#[from] wholepact_wallet::wallet::protected_sync::key_use::WalletKeyUseError),
    #[error(
        "authenticated signer IPC failed; private history or authorization may not be assumed current"
    )]
    Ipc,
}

/// One-shot process-local continuation from the actual consumed native approval.
/// No deserialization, cloning or constructor from retained evidence exists.
pub struct PendingWitnessAuthorization<'a> {
    journal: &'a SignerConsentJournal,
    account: &'a DedicatedAccount,
    lease: OriginalAuthorizationLease<'a>,
    request: RetainedAuthorizationRequest,
    disclosure: disclosure::ApprovedWitnessDisclosure,
}
/// Holds the original native decision and the authenticated exact witness permit.
/// A retained descriptor alone cannot construct this key-use continuation.
pub struct ReservedAuthorization<'a> {
    pending: PendingWitnessAuthorization<'a>,
    permit: AuthenticatedPermit,
    automatic_admission: Option<wholepact_authority::AuthenticatedAutomaticKeyUseAdmission>,
}

/// Consume a genuine native spending decision, precommit conservative original
/// release evidence and persist the exact artifact/request before contacting the
/// witness. A crash after original commit can only leave extra exposure.
#[allow(clippy::too_many_arguments)]
pub fn prepare_authorization<'a>(
    journal: &'a SignerConsentJournal,
    session: &'a SignerConsentSession,
    account: &'a DedicatedAccount,
    approval: ApprovedSpendConsent,
    bytes: &[u8],
    expected_head: AuthorityHead,
    delivery: AuthorizationDeliveryScope,
    disclosure: disclosure::ApprovedWitnessDisclosure,
) -> Result<PendingWitnessAuthorization<'a>> {
    if account.recovery_required() {
        return Err(BridgeError::RecoveryRequired);
    }
    let original = journal.record_original_consent_release(approval)?;
    let lease = journal.acquire_original_authorization(
        &original.original_consent().terms().authorization_id,
        session,
    )?;
    lease.require_current_spending_decision()?;
    if lease.evidence() != &original
        || account.account_id().map_err(|_| BridgeError::Binding)?
            != original.enrollment().account_id()
        || hex::encode(Sha256::digest(
            account.fvk().map_err(|_| BridgeError::Binding)?.to_bytes(),
        )) != original.enrollment().account_fvk_digest()
    {
        return Err(BridgeError::Binding);
    }
    disclosure.check(original.original_consent(), None)?;
    disclosure.require_origin(&lease)?;
    let mut request =
        RetainedAuthorizationRequest::from_original(&original, bytes, expected_head, delivery)?;
    request.disclosure = Some(disclosure.record().clone());
    request.validate_original(&original)?;
    journal.bridge_retain_request(&lease, &request)?;
    Ok(PendingWitnessAuthorization {
        journal,
        account,
        lease,
        request,
        disclosure,
    })
}
impl<'a> PendingWitnessAuthorization<'a> {
    pub fn reservation(&self) -> &wholepact_authority::ReserveAuthorization {
        self.request.reservation()
    }
    pub fn reserve(self, client: &AuthorityClient) -> Result<ReservedAuthorization<'a>> {
        self.lease.require_current_authorization()?;
        self.disclosure
            .check(self.lease.evidence().original_consent(), Some(client))?;
        self.disclosure.require_origin(&self.lease)?;
        // The stored descriptor is used verbatim. Never refresh its expected head,
        // operation ID, expiry or inputs after timeout/lost response.
        let permit = client.reserve(self.request.reservation.clone())?;
        permit.matches_request(&self.request.reservation)?;
        self.journal.bridge_retain_permit(&self.lease, &permit)?;
        self.lease.require_current_authorization()?;
        // This is the witness serialization point for grant pause/revoke. Only
        // the exact admitted operation may drain a subsequent control change.
        // A lost admission response is permanently uncertain, never reminted.
        let automatic_admission = if let Some(automation) = &self.request.reservation.automation {
            let r = &self.request.reservation;
            let admission_request = wholepact_authority::AuthorizeAutomaticKeyUse {
                operation_id: format!(
                    "auto-keyuse-{}",
                    hex::encode(Sha256::digest(r.operation_id.as_bytes()))
                ),
                account_id: r.account_id.clone(),
                network_profile_id: r.network_profile_id.clone(),
                writer_epoch: r.writer_epoch,
                expected_head: permit.descriptor().committed_head.clone(),
                reservation_operation_id: r.operation_id.clone(),
                reservation_request_digest: r.request_digest()?,
                automation: automation.clone(),
                reviewed_at_ms: r.reviewed_at_ms,
                admission_expires_at_ms: r.permit_expires_at_ms,
            };
            let admission = client.authorize_automatic_key_use(admission_request.clone())?;
            admission.matches_request(&admission_request)?;
            Some(admission)
        } else {
            None
        };
        Ok(ReservedAuthorization {
            pending: self,
            permit,
            automatic_admission,
        })
    }
}

/// Grant-derived exact continuation, deliberately separate from a native
/// spending click. Disclosure is still its own exact native decision.
#[cfg(all(
    feature = "authority-signing",
    feature = "native-ui",
    target_os = "linux"
))]
#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_automatic_authorization<'a>(
    journal: &'a SignerConsentJournal,
    session: &'a SignerConsentSession,
    account: &'a DedicatedAccount,
    approval: crate::consent_journal::ApprovedAutomaticSpendConsent,
    bytes: &[u8],
    expected_head: AuthorityHead,
    delivery: AuthorizationDeliveryScope,
    disclosure: disclosure::ApprovedWitnessDisclosure,
) -> Result<PendingWitnessAuthorization<'a>> {
    if account.recovery_required() {
        return Err(BridgeError::RecoveryRequired);
    }
    let (original, continuation) = journal.record_automatic_consent_release(approval)?;
    let lease = journal.original_automatic_authorization_lease(
        &original.original_consent().terms().authorization_id,
        session,
        &continuation,
    )?;
    lease.require_current_authorization()?;
    if lease.evidence() != &original
        || account.account_id().map_err(|_| BridgeError::Binding)?
            != original.enrollment().account_id()
        || hex::encode(Sha256::digest(
            account.fvk().map_err(|_| BridgeError::Binding)?.to_bytes(),
        )) != original.enrollment().account_fvk_digest()
    {
        return Err(BridgeError::Binding);
    }
    disclosure.check(original.original_consent(), None)?;
    disclosure.require_origin(&lease)?;
    let mut request =
        RetainedAuthorizationRequest::from_original(&original, bytes, expected_head, delivery)?;
    request.disclosure = Some(disclosure.record().clone());
    request.validate_original(&original)?;
    journal.bridge_retain_request(&lease, &request)?;
    Ok(PendingWitnessAuthorization {
        journal,
        account,
        lease,
        request,
        disclosure,
    })
}

/// Reconcile only the exact persisted witness request. Success retains the permit
/// but deliberately does not reconstruct a signing continuation after interruption.
/// It cannot use an adjusted head or fresh operation to evade an uncertain one.
pub fn retry_original_reservation(
    journal: &SignerConsentJournal,
    session: &SignerConsentSession,
    authorization_id: &str,
    client: &AuthorityClient,
) -> Result<protocol::RetainedWitnessPermit> {
    let lease = journal.acquire_original_authorization(authorization_id, session)?;
    let request = journal.bridge_request(&lease)?;
    let disclosure = request.disclosure.as_ref().ok_or(BridgeError::Permission)?;
    disclosure.validate_original(lease.evidence().original_consent())?;
    if disclosure.descriptor != client.disclosure_descriptor() {
        return Err(BridgeError::Binding);
    }
    let permit = client.reserve(request.reservation.clone())?;
    journal.bridge_retain_permit(&lease, &permit)
}

/// Non-sensitive receipt only; signatures and raw PCZT stay in protected storage.
#[derive(Clone, PartialEq, Eq, serde::Serialize)]
pub struct AuthorizationCommit {
    pub authorization_id: String,
    pub original_consent_ref: String,
    pub result_digest: String,
    pub outbox_digest: String,
    pub exposure_remains_uncertain: bool,
}
impl From<&RetainedAuthorizationResult> for AuthorizationCommit {
    fn from(r: &RetainedAuthorizationResult) -> Self {
        Self {
            authorization_id: r.authorization_id.clone(),
            original_consent_ref: r.original_consent_ref.clone(),
            result_digest: r.result_digest.clone(),
            outbox_digest: r.outbox_digest.clone(),
            exposure_remains_uncertain: true,
        }
    }
}

#[cfg(target_os = "linux")]
pub mod proved_disclosure_ipc;

#[cfg(target_os = "linux")]
pub mod automation_ipc;

#[cfg(target_os = "linux")]
impl From<wholepact_signer_origin::Error> for BridgeError {
    fn from(error: wholepact_signer_origin::Error) -> Self {
        use wholepact_signer_origin::Error as Origin;
        match error {
            Origin::SignerOriginUnavailable | Origin::PeerLifetimeUnavailable => {
                Self::SignerOriginUnavailable
            }
            Origin::Binding | Origin::InvalidData => Self::Binding,
            Origin::Conflict => Self::Conflict,
            Origin::Limit => Self::Limit,
            Origin::Permission | Origin::Authentication | Origin::Locked => Self::Permission,
            _ => Self::Ipc,
        }
    }
}

#[cfg(all(target_os = "linux", feature = "manual-inventory-client"))]
pub mod manual_roster_candidate_selection_v2;
#[cfg(all(target_os = "linux", feature = "manual-inventory-client"))]
pub mod manual_roster_inventory_v2;

#[cfg(target_os = "linux")]
pub mod account_inspection_ipc;
