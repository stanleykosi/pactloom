//! Signer-owned exact witness reservation → durable key-use fence → retained
//! authorization/outbox. The coordinator never opens or unlocks this journal.
//! An authenticated witness is required for each exact authorization; neither
//! local history nor deserialized evidence can manufacture a permit or approval.
//! Real enrollment/deployment remains separate from this source implementation.
// With diagnostics disabled these expand to the exact original expression.
macro_rules! flow_observe {
    ($observer:expr, $stage:ident, $expression:expr) => {{
        #[cfg(all(
            feature = "synthetic-born-joined-qualification",
            feature = "durable-proposal"
        ))]
        {
            $crate::authority_bridge::durable_flow_diagnostics_v1::observe_result(
                $observer,
                $crate::authority_bridge::durable_flow_diagnostics_v1::DurableFlowStageV1::$stage,
                $expression,
            )
        }
        #[cfg(not(all(
            feature = "synthetic-born-joined-qualification",
            feature = "durable-proposal"
        )))]
        {
            $expression
        }
    }};
}
#[cfg(feature = "authority-signing")]
macro_rules! flow_observe_at {
    ($observer:expr, $stage:expr, $expression:expr) => {{
        #[cfg(all(
            feature = "synthetic-born-joined-qualification",
            feature = "durable-proposal"
        ))]
        {
            $crate::authority_bridge::durable_flow_diagnostics_v1::observe_result(
                $observer,
                $stage,
                $expression,
            )
        }
        #[cfg(not(all(
            feature = "synthetic-born-joined-qualification",
            feature = "durable-proposal"
        )))]
        {
            $expression
        }
    }};
}
macro_rules! flow_call {
    ($observer:expr, $slot:ident, $stage:ident, $expression:expr) => {{
        #[cfg(all(
            feature = "synthetic-born-joined-qualification",
            feature = "durable-proposal"
        ))]
        {
            $crate::authority_bridge::durable_flow_diagnostics_v1::observe_call(
                $observer,
                $crate::authority_bridge::durable_flow_diagnostics_v1::DurableFlowCallV1::$slot,
                $crate::authority_bridge::durable_flow_diagnostics_v1::DurableFlowStageV1::$stage,
                || $expression,
            )
        }
        #[cfg(not(all(
            feature = "synthetic-born-joined-qualification",
            feature = "durable-proposal"
        )))]
        {
            $expression
        }
    }};
}
#[cfg(all(
    feature = "synthetic-born-joined-qualification",
    feature = "durable-proposal"
))]
pub(crate) mod durable_flow_diagnostics_v1;
#[cfg(all(
    feature = "synthetic-born-joined-qualification",
    feature = "durable-proposal"
))]
use durable_flow_diagnostics_v1::DurableFlowObserverV1;

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
#[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing", feature = "native-ui", target_os = "linux"))]
pub mod financial_continuation_v1;
pub mod disclosure;
#[cfg(target_os = "linux")]
pub mod dispatch_ipc;
#[cfg(all(feature = "durable-proposal", target_os = "linux"))]
pub mod durable_construction_v1;
#[cfg(feature = "durable-proposal")]
pub mod durable_proposal_v1;
#[cfg(all(feature = "durable-proposal", target_os = "linux"))]
pub mod durable_review_ipc_v1;
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
use protocol::{AuthorizationDeliveryScope, RetainedAuthorizationRequest, RetainedAuthorizationResult};
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
    // The public journal method refuses explicit durable-born policy terms.
    // Only the purpose-specific actual-source entry below may release those.
    let original = journal.record_original_consent_release(approval)?;
    complete_preparation(
        journal,
        session,
        account,
        original,
        bytes,
        expected_head,
        delivery,
        disclosure,
        #[cfg(all(
            feature = "synthetic-born-joined-qualification",
            feature = "durable-proposal"
        ))]
        None,
    )
}

#[cfg(all(
    feature = "durable-proposal",
    feature = "pending-birth-owner-signing",
    feature = "native-ui",
    target_os = "linux"
))]
#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_authorization_from_durable_born_v1<'a>(
    entry: &'a crate::account::birth::enrollment::roster_v2::durable_entry_v1::FreshDurableBornEntryV1,
    session: &'a SignerConsentSession,
    approval: ApprovedSpendConsent,
    bytes: &[u8],
    expected_head: AuthorityHead,
    delivery: AuthorizationDeliveryScope,
    disclosure: disclosure::ApprovedWitnessDisclosure,
) -> Result<PendingWitnessAuthorization<'a>> {
    prepare_authorization_from_durable_born_v1_inner(
        entry,
        session,
        approval,
        bytes,
        expected_head,
        delivery,
        disclosure,
        #[cfg(all(
            feature = "synthetic-born-joined-qualification",
            feature = "durable-proposal"
        ))]
        None,
    )
}
#[cfg(all(
    feature = "durable-proposal",
    feature = "pending-birth-owner-signing",
    feature = "native-ui",
    target_os = "linux"
))]
#[allow(clippy::too_many_arguments)]
fn prepare_authorization_from_durable_born_v1_inner<'a>(
    entry: &'a crate::account::birth::enrollment::roster_v2::durable_entry_v1::FreshDurableBornEntryV1,
    session: &'a SignerConsentSession,
    approval: ApprovedSpendConsent,
    bytes: &[u8],
    expected_head: AuthorityHead,
    delivery: AuthorizationDeliveryScope,
    disclosure: disclosure::ApprovedWitnessDisclosure,
    #[cfg(all(
        feature = "synthetic-born-joined-qualification",
        feature = "durable-proposal"
    ))]
    observer: Option<&DurableFlowObserverV1>,
) -> Result<PendingWitnessAuthorization<'a>> {
    flow_observe!(observer, AuthorizationSource, entry.check_current())
        .map_err(|_| BridgeError::Permission)?;
    let journal = entry.journal().as_ref();
    let account = entry.account();
    if account.recovery_required() {
        return flow_observe!(
            observer,
            AuthorizationSource,
            Err(BridgeError::RecoveryRequired)
        );
    }
    let original = flow_call!(
        observer,
        Release,
        Release,
        journal.record_durable_born_consent_release_v1(approval, entry)
    )?;
    let pending = complete_preparation(
        journal,
        session,
        account,
        original,
        bytes,
        expected_head,
        delivery,
        disclosure,
        #[cfg(all(
            feature = "synthetic-born-joined-qualification",
            feature = "durable-proposal"
        ))]
        observer,
    )?;
    flow_observe!(
        observer,
        AuthorizationSource,
        entry.require_authorization_identity(account, journal, &pending.lease)
    )
    .map_err(|_| BridgeError::Permission)?;
    Ok(pending)
}

#[allow(clippy::too_many_arguments)]
fn complete_preparation<'a>(
    journal: &'a SignerConsentJournal,
    session: &'a SignerConsentSession,
    account: &'a DedicatedAccount,
    original: crate::consent_journal::OriginalAuthorizationEvidence,
    bytes: &[u8],
    expected_head: AuthorityHead,
    delivery: AuthorizationDeliveryScope,
    disclosure: disclosure::ApprovedWitnessDisclosure,
    #[cfg(all(
        feature = "synthetic-born-joined-qualification",
        feature = "durable-proposal"
    ))]
    observer: Option<&DurableFlowObserverV1>,
) -> Result<PendingWitnessAuthorization<'a>> {
    let lease = flow_observe!(
        observer,
        RequestRetain,
        journal.acquire_original_authorization(
            &original.original_consent().terms().authorization_id,
            session,
        )
    )?;
    flow_observe!(
        observer,
        RequestRetain,
        lease.require_current_spending_decision()
    )?;
    if lease.evidence() != &original
        || flow_observe!(observer, RequestRetain, account.account_id())
            .map_err(|_| BridgeError::Binding)?
            != original.enrollment().account_id()
        || hex::encode(Sha256::digest(
            flow_observe!(observer, RequestRetain, account.fvk())
                .map_err(|_| BridgeError::Binding)?
                .to_bytes(),
        )) != original.enrollment().account_fvk_digest()
    {
        return flow_observe!(observer, RequestRetain, Err(BridgeError::Binding));
    }
    flow_observe!(
        observer,
        RequestRetain,
        disclosure.check(original.original_consent(), None)
    )?;
    flow_observe!(observer, RequestRetain, disclosure.require_origin(&lease))?;
    let mut request = flow_observe!(
        observer,
        RequestRetain,
        RetainedAuthorizationRequest::from_original(&original, bytes, expected_head, delivery)
    )?;
    request.disclosure = Some(disclosure.record().clone());
    flow_observe!(
        observer,
        RequestRetain,
        request.validate_original(&original)
    )?;
    flow_call!(
        observer,
        RequestRetention,
        RequestRetain,
        journal.bridge_retain_request(&lease, &request)
    )?;
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
        self.reserve_inner(
            client,
            #[cfg(all(
                feature = "synthetic-born-joined-qualification",
                feature = "durable-proposal"
            ))]
            None,
        )
    }
    fn reserve_inner(
        self,
        client: &AuthorityClient,
        #[cfg(all(
            feature = "synthetic-born-joined-qualification",
            feature = "durable-proposal"
        ))]
        observer: Option<&DurableFlowObserverV1>,
    ) -> Result<ReservedAuthorization<'a>> {
        flow_observe!(
            observer,
            Reserve,
            self.lease.require_current_authorization()
        )?;
        flow_observe!(
            observer,
            Reserve,
            self.disclosure
                .check(self.lease.evidence().original_consent(), Some(client))
        )?;
        flow_observe!(
            observer,
            Reserve,
            self.disclosure.require_origin(&self.lease)
        )?;
        // The stored descriptor is used verbatim. Never refresh its expected head,
        // operation ID, expiry or inputs after timeout/lost response.
        let permit = flow_call!(observer, Reservation, Reserve, {
            #[cfg(all(
                feature = "synthetic-born-joined-qualification",
                feature = "durable-proposal"
            ))]
            {
                if let Some(observer) = observer {
                    observer.observe_transport(
                        durable_flow_diagnostics_v1::DurableFlowTransportPurposeV1::Reserve,
                        durable_flow_diagnostics_v1::DurableFlowStageV1::Reserve,
                        None,
                        client.reserve_diagnosed(self.request.reservation.clone()),
                    )
                } else {
                    client.reserve(self.request.reservation.clone())
                }
            }
            #[cfg(not(all(
                feature = "synthetic-born-joined-qualification",
                feature = "durable-proposal"
            )))]
            {
                client.reserve(self.request.reservation.clone())
            }
        })?;
        flow_observe!(
            observer,
            Reserve,
            permit.matches_request(&self.request.reservation)
        )?;
        flow_call!(
            observer,
            PermitRetention,
            PermitRetain,
            self.journal.bridge_retain_permit(&self.lease, &permit)
        )?;
        flow_observe!(
            observer,
            PermitRetain,
            self.lease.require_current_authorization()
        )?;
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

#[cfg(all(feature = "durable-proposal", target_os = "linux"))]
pub mod durable_delivery_admission_ipc_v2;

#[cfg(all(
    feature = "durable-proposal",
    feature = "pending-birth-owner-signing",
    feature = "native-ui",
    target_os = "linux"
))]
#[path = "durable_proposal_v1/stable_returns_v2.rs"]
mod durable_delivery_stable_returns_v2;
#[cfg(all(
    feature = "durable-proposal",
    feature = "pending-birth-owner-signing",
    feature = "native-ui",
    target_os = "linux"
))]
pub(crate) fn validate_durable_delivery_policy_v2(
    entry: &crate::account::birth::enrollment::roster_v2::durable_entry_v1::FreshDurableDeliveryEntryV2,
    enrollment: &crate::consent_journal::AccountEnrollmentRecord,
    manifest: &crate::consent_journal::AcceptedManifestRecord,
    fixed: &wholepact_protocol::durable_proposal_v1::VerifiedFixedProposal,
    inputs: &[wholepact_protocol::construction::InputActionMapping],
    outputs: &[wholepact_protocol::construction::OutputActionMapping],
) -> Result<String> {
    entry
        .check_original_source_current()
        .map_err(|_| BridgeError::Permission)?;
    let original = entry
        .original_recipient_policy_export_v2()
        .map_err(|_| BridgeError::Binding)?;
    validate_prepared_delivery_policy_v3(
        entry.record(), &original, entry.account(), enrollment, manifest, fixed, inputs, outputs,
    )
}
/// Pure policy validation shared by independently checked original-source
/// owners. This function issues no source, native or transport permission.
#[cfg(all(
    feature = "durable-proposal",
    feature = "pending-birth-owner-signing",
    feature = "native-ui",
    target_os = "linux"
))]
#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_prepared_delivery_policy_v3(
    record: &crate::account::birth::enrollment::roster_v2::BornManualRosterEnrollmentRecordV2,
    original: &crate::account::birth::recipient_policy_v2::OriginalRecipientPolicyExportV2,
    account: &DedicatedAccount,
    enrollment: &crate::consent_journal::AccountEnrollmentRecord,
    manifest: &crate::consent_journal::AcceptedManifestRecord,
    fixed: &wholepact_protocol::durable_proposal_v1::VerifiedFixedProposal,
    inputs: &[wholepact_protocol::construction::InputActionMapping],
    outputs: &[wholepact_protocol::construction::OutputActionMapping],
) -> Result<String> {
    let binding =
        crate::consent_journal::DurableBornPolicyBindingV1::from_original_stable_source_v2(
            record,
            enrollment,
            manifest,
            fixed.identity(),
            original,
        )?;
    durable_delivery_stable_returns_v2::verify_stable_returns_v2(
        fixed,
        inputs,
        outputs,
        &account.fvk().map_err(|_| BridgeError::Binding)?,
        &account.account_id().map_err(|_| BridgeError::Binding)?,
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

#[cfg(all(feature = "durable-proposal", target_os = "linux"))]
pub mod durable_review_ipc_v3;
#[cfg(all(feature = "durable-proposal", target_os = "linux"))]
pub mod durable_delivery_admission_ipc_v3;
