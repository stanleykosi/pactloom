//! Actual native owner surface with one bounded private worker. Proposals come
//! only from the concrete namespace backend. No GUI DTO supplies native approval,
//! canonical directory identity, retained original enrollment or a storage key.
#[path = "window/durable_payment_v1.rs"]
mod durable_payment_v1;
#[path = "window/durable_delivery_admission_v2.rs"]
mod durable_delivery_admission_v2;
#[path = "window/financial_continuation_v1.rs"]
mod financial_continuation_v1;
#[cfg(feature = "synthetic-qualification")]
#[path = "window/ephemeral_fixture_v1.rs"]
pub(super) mod ephemeral_fixture_v1;
#[cfg(feature = "synthetic-qualification")]
#[path = "window/synthetic_plan_diagnostics_v1.rs"]
mod synthetic_plan_diagnostics_v1;
use super::lifecycle::{NativeOwner, ReviewClock};
use super::NativeWorkerLease;
#[cfg(feature = "born-offline-witness-owner")]
use crate::born_offline_artifacts_owner_v1::{
    commit_born_offline_artifacts_v1, prepare_born_offline_artifacts_v1,
    BornOfflineArtifactsProposalV1,
};
use crate::born_offline_enrollment_owner_v1::{
    commit_born_offline_enrollment_v1, prepare_born_offline_enrollment_v1,
    BornOfflineEnrollmentProposalV1,
};
use crate::born_offline_enrollment_signature_v1::{
    verify_born_offline_enrollment_v1_owner_signature, BornOfflineEnrollmentOwnerSignatureV1,
};
use crate::construction_transport_handoff_v1::{
    SignedConstructionTransportPreauthorizationV1, MAX_CONSTRUCTION_TRANSPORT_COMPONENT_BYTES,
};
use crate::construction_transport_owner_v1::{
    commit_construction_transport_grant_v1, prepare_construction_transport_grant_v1,
    ConstructionTransportGrantProposalV1,
};
use crate::manual_enrollment_owner::{
    commit_manual_enrollment_extension, prepare_manual_enrollment_extension,
    ManualEnrollmentExtensionProposal,
};
use crate::manual_enrollment_signature::{
    verify_manual_enrollment_extension_owner_signature, ManualEnrollmentExtensionOwnerSignature,
};
use crate::manual_roster_construction_owner_v2::{
    commit_manual_roster_construction_v2, prepare_manual_roster_construction_v2,
    ManualRosterConstructionProposalV2,
};
use crate::manual_roster_construction_owner_v3::{
    commit_manual_roster_construction_v3, prepare_manual_roster_construction_v3,
    ManualRosterConstructionProposalV3,
};
use crate::manual_roster_construction_signature_v2::{
    verify_manual_roster_construction_owner_signature_v2, ManualRosterConstructionOwnerSignatureV2,
};
use crate::manual_roster_construction_signature_v3::{
    verify_manual_roster_construction_owner_signature_v3, ManualRosterConstructionOwnerSignatureV3,
};
use crate::manual_roster_continuation_owner_v2::{
    commit_manual_roster_continuation_v2, prepare_manual_roster_continuation_v2,
    ManualRosterContinuationProposalV2,
};
use crate::manual_roster_continuation_signature_v2::{
    verify_manual_roster_continuation_owner_signature_v2, ManualRosterContinuationOwnerSignatureV2,
};
use crate::manual_roster_owner_v2::{
    commit_manual_roster_extension_v2, prepare_manual_roster_extension_v2,
    ManualRosterExtensionProposalV2,
};
use crate::manual_roster_signature_v2::{
    verify_manual_roster_enrollment_owner_signature_v2, ManualRosterEnrollmentOwnerSignatureV2,
};
use crate::manual_session_continuation_owner::{
    commit_manual_session_continuation, prepare_manual_session_continuation,
    ManualSessionContinuationProposal,
};
use crate::manual_session_continuation_signature::{
    verify_manual_enrollment_session_continuation_owner_signature,
    ManualEnrollmentSessionContinuationOwnerSignature,
};
use crate::pending_birth_signature::{verify_pending_birth_owner_signature, PendingBirthOwnerSignature};
use crate::permanent_exclusion_owner::{
    commit_permanent_exclusion_v1, prepare_permanent_exclusion_v1, PermanentExclusionProposalV1,
};
use crate::permanent_exclusion_signature::{
    verify_permanent_exclusion_owner_signature_v1, PermanentExclusionOwnerSignatureV1,
};
use crate::witness_locator::{
    install_namespace, open_namespace_recovery_evidence, prepare_namespace_backup,
    prepare_namespace_enrollment, prepare_namespace_recovery_disclosure, prepare_namespace_setup,
    write_namespace_backup, NamespaceBackupInput, NamespaceBackupProposal,
    NamespaceEnrollmentProposal, NamespaceOpenInput, NamespaceRecoveryInput,
    NamespaceRecoveryProposal, NamespaceSetupInput, NamespaceSetupProposal,
};
use crate::{AuthorityError, Result};
pub(crate) use durable_payment_v1::NativeDurablePaymentAdmissionDecisionV1;
pub(crate) use durable_delivery_admission_v2::NativeDurableDeliveryAdmissionDecisionV2;
pub(crate) use financial_continuation_v1::NativeFinancialContinuationDecisionV1;
use eframe::egui::{self, Color32, RichText};
use std::{
    io::Write,
    sync::mpsc::{self, Receiver, SyncSender, TryRecvError},
    thread::JoinHandle,
    time::Duration,
};
use zeroize::{Zeroize, Zeroizing};

// These areas coexist on one CentralPanel Ui after a completed operation.
// Stable distinct IDs keep receipt scrolling from overwriting form scrolling.
const COMPLETED_RECEIPT_SCROLL_ID: &str = "witness-completed-operation-receipt";
const OPERATION_SELECTION_SCROLL_ID: &str = "witness-operation-selection";
const MAX_CERTIFICATE_BYTES: usize = 16 * 1024;
const MAX_REVIEW_BYTES: usize = 512 * 1024;
const MAX_HISTORICAL_DISPLAY_BYTES: usize = 2 * 1024 * 1024;
const TRUST_NOTICE: &str = "Pre-release native source; attended runtime qualification is pending. This window relies on a trusted owner process, OS and compositor. The existing owner certificate authenticates key possession only. It does not prove signer native focus, newly generated keys, fresh account provenance or independent administration. Namespace setup is permanent local configuration; missing installed state cannot be reset here.";

/// Only the focused final primary-click branch constructs this value. Its
/// private fields cannot be supplied by a sibling, caller, JSON or test fixture.
pub(super) struct FinalPrimaryClick {
    review_digest: String,
    clock: ReviewClock,
}
impl FinalPrimaryClick {
    pub(super) fn into_parts(self) -> (String, ReviewClock) {
        (self.review_digest, self.clock)
    }
}
/// Nonclone/nonserializable setup decision with a concrete backend-owned proposal.
/// Moved once to a private worker; the native revocation owner stays in the GUI.
pub(crate) struct NativeSetupDecision {
    proposal: NamespaceSetupProposal,
    lease: NativeWorkerLease,
}
impl NativeSetupDecision {
    pub(crate) fn into_parts(self) -> (NamespaceSetupProposal, NativeWorkerLease) {
        (self.proposal, self.lease)
    }
}
/// This type cannot be constructed from a request, signature or receipt. Only
/// this file's genuine native primary-click branch supplies it to reserve_birth.
pub(crate) struct NativeEnrollmentDecision {
    proposal: NamespaceEnrollmentProposal,
    lease: NativeWorkerLease,
}
impl NativeEnrollmentDecision {
    pub(crate) fn into_parts(self) -> (NamespaceEnrollmentProposal, NativeWorkerLease) {
        (self.proposal, self.lease)
    }
}

/// Only the final focused primary-click branch couples this opaque backend
/// proposal to one native decision. No caller or deserialized value can mint it.
pub(crate) struct NativeNamespaceBackupDecision {
    proposal: NamespaceBackupProposal,
    lease: NativeWorkerLease,
}
impl NativeNamespaceBackupDecision {
    pub(crate) fn into_parts(self) -> (NamespaceBackupProposal, NativeWorkerLease) {
        (self.proposal, self.lease)
    }
}
/// Historical disclosure retains its revocable OPEN lease. It cannot grant
/// publication, namespace installation, enrollment or financial authority.
pub(crate) struct NativeNamespaceRecoveryDisclosureDecision {
    proposal: NamespaceRecoveryProposal,
    lease: NativeWorkerLease,
}
impl NativeNamespaceRecoveryDisclosureDecision {
    pub(crate) fn into_parts(self) -> (NamespaceRecoveryProposal, NativeWorkerLease) {
        (self.proposal, self.lease)
    }
}

/// No sibling, DTO or verified signature can manufacture this decision. The
/// sole construction is the focused final primary-click branch below.
pub(crate) struct NativeBornOfflineEnrollmentDecisionV1 {
    proposal: BornOfflineEnrollmentProposalV1,
    lease: NativeWorkerLease,
}
impl NativeBornOfflineEnrollmentDecisionV1 {
    pub(crate) fn into_parts(self) -> (BornOfflineEnrollmentProposalV1, NativeWorkerLease) {
        (self.proposal, self.lease)
    }
}

/// Only this window's focused final primary click creates persistent-import consent.
#[cfg(feature = "born-offline-witness-owner")]
pub(crate) struct NativeBornOfflineArtifactsDecisionV1 {
    proposal: BornOfflineArtifactsProposalV1,
    lease: NativeWorkerLease,
}
#[cfg(feature = "born-offline-witness-owner")]
impl NativeBornOfflineArtifactsDecisionV1 {
    pub(crate) fn into_parts(self) -> (BornOfflineArtifactsProposalV1, NativeWorkerLease) {
        (self.proposal, self.lease)
    }
}

/// One exact local extension commit from a genuine focused native final click.
/// This is neither a remote writer lease nor a financial action capability.
pub(crate) struct NativeManualEnrollmentExtensionDecision {
    proposal: ManualEnrollmentExtensionProposal,
    lease: NativeWorkerLease,
}
impl NativeManualEnrollmentExtensionDecision {
    pub(crate) fn into_parts(self) -> (ManualEnrollmentExtensionProposal, NativeWorkerLease) {
        (self.proposal, self.lease)
    }
}

/// One exact local continuation commit from a genuine focused native final click.
/// This is neither a remote writer lease nor a financial action capability.
pub(crate) struct NativeManualSessionContinuationDecision {
    proposal: ManualSessionContinuationProposal,
    lease: NativeWorkerLease,
}
impl NativeManualSessionContinuationDecision {
    pub(crate) fn into_parts(self) -> (ManualSessionContinuationProposal, NativeWorkerLease) {
        (self.proposal, self.lease)
    }
}

/// One exact local extension commit from a genuine focused native final click.
/// This is neither a remote writer lease nor a financial action capability.
pub(crate) struct NativeManualRosterExtensionDecisionV2 {
    proposal: ManualRosterExtensionProposalV2,
    lease: NativeWorkerLease,
}
impl NativeManualRosterExtensionDecisionV2 {
    pub(crate) fn into_parts(self) -> (ManualRosterExtensionProposalV2, NativeWorkerLease) {
        (self.proposal, self.lease)
    }
}

/// One exact local continuation commit from a genuine focused native final click.
/// This is neither a remote writer lease nor a financial action capability.
pub(crate) struct NativeManualRosterContinuationDecisionV2 {
    proposal: ManualRosterContinuationProposalV2,
    lease: NativeWorkerLease,
}
impl NativeManualRosterContinuationDecisionV2 {
    pub(crate) fn into_parts(self) -> (ManualRosterContinuationProposalV2, NativeWorkerLease) {
        (self.proposal, self.lease)
    }
}

/// Only the focused final-click branch below can issue this one inert grant.
/// Neither a valid signature nor caller JSON can create the native decision.
pub(crate) struct NativeConstructionTransportGrantDecisionV1 {
    proposal: ConstructionTransportGrantProposalV1,
    lease: NativeWorkerLease,
}
impl NativeConstructionTransportGrantDecisionV1 {
    pub(crate) fn into_parts(self) -> (ConstructionTransportGrantProposalV1, NativeWorkerLease) {
        (self.proposal, self.lease)
    }
}

pub(crate) struct NativeManualRosterConstructionDecisionV3 {
    proposal: ManualRosterConstructionProposalV3,
    lease: NativeWorkerLease,
}
impl NativeManualRosterConstructionDecisionV3 {
    pub(crate) fn into_parts(self) -> (ManualRosterConstructionProposalV3, NativeWorkerLease) {
        (self.proposal, self.lease)
    }
}

pub(crate) struct NativeManualRosterConstructionDecisionV2 {
    proposal: ManualRosterConstructionProposalV2,
    lease: NativeWorkerLease,
}
impl NativeManualRosterConstructionDecisionV2 {
    pub(crate) fn into_parts(self) -> (ManualRosterConstructionProposalV2, NativeWorkerLease) {
        (self.proposal, self.lease)
    }
}

/// One exact restrictive publication from the final focused native click.
pub(crate) struct NativePermanentExclusionDecisionV1 {
    proposal: PermanentExclusionProposalV1,
    lease: NativeWorkerLease,
}
impl NativePermanentExclusionDecisionV1 {
    pub(crate) fn into_parts(self) -> (PermanentExclusionProposalV1, NativeWorkerLease) {
        (self.proposal, self.lease)
    }
}

#[derive(Default)]
struct NativeInputs {
    durable_payment_v1: durable_payment_v1::InputsV1,
    durable_delivery_admission_v2: durable_delivery_admission_v2::InputsV2,
    financial_continuation_v1: financial_continuation_v1::InputsV1,
    #[cfg(feature = "synthetic-qualification")]
    synthetic_installation: Option<
        std::sync::Arc<
            wholepact_storage_security::witness_namespace_fs::EphemeralWitnessInstallation,
        >,
    >,
    endpoint: String,
    server_name: String,
    witness_id: String,
    pinned_server_certificate_digest: String,
    network_profile_id: String,
    storage_key_file: String,
    expected_account_id: String,
    owner_certificate_hex: Zeroizing<String>,
    signed_request_json: Zeroizing<String>,
    signed_manual_extension_json: Zeroizing<String>,
    signed_born_offline_enrollment_json: Zeroizing<String>,
    #[cfg(feature = "born-offline-witness-owner")]
    born_transport_key_file: String,
    #[cfg(feature = "born-offline-witness-owner")]
    born_signer_public_key_hex: String,
    signed_permanent_exclusion_json: Zeroizing<String>,
    signed_manual_roster_extension_json: Zeroizing<String>,
    signed_manual_continuation_json: Zeroizing<String>,
    signed_manual_roster_continuation_json: Zeroizing<String>,
    signed_manual_roster_construction_json: Zeroizing<String>,
    signed_manual_roster_construction_v3_json: Zeroizing<String>,
    signed_construction_transport_preauthorization_json: Zeroizing<String>,
    destination_directory: String,
    destination_key_file: String,
    package_directory: String,
    archive_key_file: String,
    expected_namespace_digest: String,
}
impl NativeInputs {
    fn independently_selected_owner_pin(&self) -> Result<String> {
        if self.owner_certificate_hex.is_empty()
            || self.owner_certificate_hex.len() > 2 * MAX_CERTIFICATE_BYTES
        {
            return Err(AuthorityError::Limit);
        }
        let der = Zeroizing::new(
            hex::decode(self.owner_certificate_hex.as_str())
                .map_err(|_| AuthorityError::InvalidBinding)?,
        );
        if der.is_empty() || der.len() > MAX_CERTIFICATE_BYTES {
            return Err(AuthorityError::InvalidBinding);
        }
        let certificate = rustls::pki_types::CertificateDer::from(der.as_slice());
        // Valid DER shape only; not PKI path, certificate time or revocation.
        webpki::EndEntityCert::try_from(&certificate)
            .map_err(|_| AuthorityError::InvalidBinding)?;
        Ok(crate::transport::certificate_digest(&certificate))
    }
    fn common_input(&self) -> Result<NamespaceSetupInput> {
        self.check_lengths()?;
        Ok(NamespaceSetupInput {
            #[cfg(feature = "synthetic-qualification")]
            synthetic_installation: self.synthetic_installation.clone(),
            endpoint: self.endpoint.clone(),
            server_name: self.server_name.clone(),
            witness_id: self.witness_id.clone(),
            pinned_server_certificate_digest: self.pinned_server_certificate_digest.clone(),
            owner_certificate_digest: self.independently_selected_owner_pin()?,
            network_profile_id: self.network_profile_id.clone(),
            storage_key_file: self.storage_key_file.clone(),
        })
    }
    fn setup_input(&self) -> Result<NamespaceSetupInput> {
        // A fresh fixed installation gets a backend-generated public witness ID.
        // An existing standalone origin must never be adopted as empty history.
        if !self.witness_id.is_empty() {
            return Err(AuthorityError::Conflict);
        }
        self.common_input()
    }
    fn enrollment_input(&self) -> Result<NamespaceOpenInput> {
        let s = self.common_input()?;
        crate::id(&s.witness_id)?;
        crate::hash(&self.expected_account_id)?;
        Ok(NamespaceOpenInput {
            #[cfg(feature = "synthetic-qualification")]
            synthetic_installation: s.synthetic_installation,
            endpoint: s.endpoint,
            server_name: s.server_name,
            witness_id: s.witness_id,
            pinned_server_certificate_digest: s.pinned_server_certificate_digest,
            owner_certificate_digest: s.owner_certificate_digest,
            network_profile_id: s.network_profile_id,
            storage_key_file: s.storage_key_file,
            expected_account_id: self.expected_account_id.clone(),
        })
    }
    fn backup_input(&self) -> Result<NamespaceBackupInput> {
        let namespace = self.common_input()?;
        crate::id(&namespace.witness_id)?;
        Ok(NamespaceBackupInput {
            namespace,
            destination_directory: self.destination_directory.clone(),
            destination_key_file: self.destination_key_file.clone(),
        })
    }
    fn recovery_input(&self) -> Result<NamespaceRecoveryInput> {
        self.check_lengths()?;
        let expected_namespace_digest = if self.expected_namespace_digest.is_empty() {
            None
        } else {
            crate::hash(&self.expected_namespace_digest)?;
            Some(self.expected_namespace_digest.clone())
        };
        Ok(NamespaceRecoveryInput {
            package_directory: self.package_directory.clone(),
            archive_key_file: self.archive_key_file.clone(),
            expected_namespace_digest,
        })
    }
    fn check_lengths(&self) -> Result<()> {
        for (v, max) in [
            (&self.endpoint, 256),
            (&self.server_name, 253),
            (&self.witness_id, 128),
            (&self.pinned_server_certificate_digest, 64),
            (&self.network_profile_id, 128),
            (&self.storage_key_file, 4096),
            (&self.expected_account_id, 64),
            (&self.destination_directory, 4096),
            (&self.destination_key_file, 4096),
            (&self.package_directory, 4096),
            (&self.archive_key_file, 4096),
            (&self.expected_namespace_digest, 64),
        ] {
            if v.len() > max {
                return Err(AuthorityError::Limit);
            }
        }
        Ok(())
    }
    fn discard_raw(&mut self) {
        self.durable_payment_v1.discard();
        self.durable_delivery_admission_v2.discard();
        self.financial_continuation_v1.discard();
        self.owner_certificate_hex.zeroize();
        self.signed_request_json.zeroize();
        self.signed_manual_extension_json.zeroize();
        self.signed_born_offline_enrollment_json.zeroize();
        #[cfg(feature = "born-offline-witness-owner")]
        {
            self.born_transport_key_file.zeroize();
            self.born_signer_public_key_hex.zeroize();
        }
        self.signed_permanent_exclusion_json.zeroize();
        self.signed_manual_roster_extension_json.zeroize();
        self.signed_manual_continuation_json.zeroize();
        self.signed_manual_roster_continuation_json.zeroize();
        self.signed_manual_roster_construction_json.zeroize();
        self.signed_manual_roster_construction_v3_json.zeroize();
        self.signed_construction_transport_preauthorization_json
            .zeroize();
        self.destination_directory.zeroize();
        self.destination_key_file.zeroize();
        self.package_directory.zeroize();
        self.archive_key_file.zeroize();
        self.expected_namespace_digest.zeroize();
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Reading,
    Confirming,
}
enum Proposal {
    DurablePaymentV1(Box<durable_payment_v1::PreparedNativeV1>),
    DurableDeliveryV2(Box<durable_delivery_admission_v2::PreparedNativeV2>),
    FinancialContinuationV1(Box<financial_continuation_v1::PreparedNativeV1>),
    Setup(Box<NamespaceSetupProposal>),
    Enrollment(Box<NamespaceEnrollmentProposal>),
    ManualExtension(Box<ManualEnrollmentExtensionProposal>),
    BornOfflineEnrollmentV1(Box<BornOfflineEnrollmentProposalV1>),
    #[cfg(feature = "born-offline-witness-owner")]
    BornOfflineArtifactsV1(Box<BornOfflineArtifactsProposalV1>),
    PermanentExclusionV1(Box<PermanentExclusionProposalV1>),
    ManualRosterExtensionV2(Box<ManualRosterExtensionProposalV2>),
    ManualContinuation(Box<ManualSessionContinuationProposal>),
    ManualRosterContinuationV2(Box<ManualRosterContinuationProposalV2>),
    ManualRosterConstructionV2(Box<ManualRosterConstructionProposalV2>),
    ManualRosterConstructionV3(Box<ManualRosterConstructionProposalV3>),
    ConstructionTransportGrantV1(Box<ConstructionTransportGrantProposalV1>),
    Backup(Box<NamespaceBackupProposal>),
    RecoveryDisclosure(Box<NamespaceRecoveryProposal>),
}
struct Prepared {
    proposal: Proposal,
    display: Zeroizing<String>,
    digest: String,
    first_commit_deadline_ms: Option<u64>,
}
impl Prepared {
    // These backend methods execute only on the worker. No blocking filesystem
    // rechecks occur on the GUI thread while a review or finalization is pending.
    fn setup(proposal: NamespaceSetupProposal) -> Result<Self> {
        proposal.check_current()?;
        let digest = proposal.review_digest()?;
        let display = proposal.display()?;
        Self::new(Proposal::Setup(Box::new(proposal)), display, digest, None)
    }
    fn enrollment(proposal: NamespaceEnrollmentProposal) -> Result<Self> {
        proposal.check_current()?;
        let digest = proposal.review_digest()?;
        let display = proposal.display()?;
        let deadline = proposal.first_commit_deadline_ms();
        Self::new(
            Proposal::Enrollment(Box::new(proposal)),
            display,
            digest,
            deadline,
        )
    }
    fn permanent_exclusion_v1(proposal: PermanentExclusionProposalV1) -> Result<Self> {
        proposal.check_current()?;
        let digest = proposal.review_digest()?;
        let display = proposal.display()?;
        Self::new(
            Proposal::PermanentExclusionV1(Box::new(proposal)),
            display,
            digest,
            None,
        )
    }
    fn born_offline_enrollment_v1(proposal: BornOfflineEnrollmentProposalV1) -> Result<Self> {
        proposal.check_current()?;
        let digest = proposal.review_digest()?;
        let display = proposal.display()?;
        let deadline = proposal.first_commit_deadline_ms();
        Self::new(
            Proposal::BornOfflineEnrollmentV1(Box::new(proposal)),
            display,
            digest,
            deadline,
        )
    }
    #[cfg(feature = "born-offline-witness-owner")]
    fn born_offline_artifacts_v1(proposal: BornOfflineArtifactsProposalV1) -> Result<Self> {
        proposal.check_current()?;
        let digest = proposal.review_digest()?;
        let display = proposal.display()?;
        let deadline = proposal.first_commit_deadline_ms();
        Self::new(
            Proposal::BornOfflineArtifactsV1(Box::new(proposal)),
            display,
            digest,
            deadline,
        )
    }
    fn manual_extension(proposal: ManualEnrollmentExtensionProposal) -> Result<Self> {
        proposal.check_current()?;
        let digest = proposal.review_digest()?;
        let display = proposal.display()?;
        let deadline = proposal.first_commit_deadline_ms();
        Self::new(
            Proposal::ManualExtension(Box::new(proposal)),
            display,
            digest,
            deadline,
        )
    }
    fn manual_continuation(proposal: ManualSessionContinuationProposal) -> Result<Self> {
        proposal.check_current()?;
        let digest = proposal.review_digest()?;
        let display = proposal.display()?;
        let deadline = proposal.first_commit_deadline_ms();
        Self::new(
            Proposal::ManualContinuation(Box::new(proposal)),
            display,
            digest,
            deadline,
        )
    }
    fn manual_roster_extension_v2(proposal: ManualRosterExtensionProposalV2) -> Result<Self> {
        proposal.check_current()?;
        let digest = proposal.review_digest()?;
        let display = proposal.display()?;
        let deadline = proposal.first_commit_deadline_ms();
        Self::new(
            Proposal::ManualRosterExtensionV2(Box::new(proposal)),
            display,
            digest,
            deadline,
        )
    }
    fn manual_roster_continuation_v2(proposal: ManualRosterContinuationProposalV2) -> Result<Self> {
        proposal.check_current()?;
        let digest = proposal.review_digest()?;
        let display = proposal.display()?;
        let deadline = proposal.first_commit_deadline_ms();
        Self::new(
            Proposal::ManualRosterContinuationV2(Box::new(proposal)),
            display,
            digest,
            deadline,
        )
    }
    fn construction_transport_grant_v1(
        proposal: ConstructionTransportGrantProposalV1,
    ) -> Result<Self> {
        proposal.check_current()?;
        let digest = proposal.review_digest()?;
        let display = proposal.display()?;
        let deadline = proposal.first_commit_deadline_ms();
        Self::new(
            Proposal::ConstructionTransportGrantV1(Box::new(proposal)),
            display,
            digest,
            deadline,
        )
    }
    fn manual_roster_construction_v3(proposal: ManualRosterConstructionProposalV3) -> Result<Self> {
        proposal.check_current()?;
        let digest = proposal.review_digest()?;
        let display = proposal.display()?;
        let deadline = proposal.first_commit_deadline_ms();
        Self::new(
            Proposal::ManualRosterConstructionV3(Box::new(proposal)),
            display,
            digest,
            deadline,
        )
    }
    fn manual_roster_construction_v2(proposal: ManualRosterConstructionProposalV2) -> Result<Self> {
        proposal.check_current()?;
        let digest = proposal.review_digest()?;
        let display = proposal.display()?;
        let deadline = proposal.first_commit_deadline_ms();
        Self::new(
            Proposal::ManualRosterConstructionV2(Box::new(proposal)),
            display,
            digest,
            deadline,
        )
    }
    fn backup(proposal: NamespaceBackupProposal) -> Result<Self> {
        proposal.check_current()?;
        let digest = proposal.review_digest()?;
        let display = proposal.display()?;
        Self::new(Proposal::Backup(Box::new(proposal)), display, digest, None)
    }
    fn recovery(proposal: NamespaceRecoveryProposal) -> Result<Self> {
        proposal.check_current()?;
        let digest = proposal.review_digest()?;
        let display = proposal.display()?;
        Self::new(
            Proposal::RecoveryDisclosure(Box::new(proposal)),
            display,
            digest,
            None,
        )
    }
    fn new(
        proposal: Proposal,
        display: String,
        digest: String,
        deadline: Option<u64>,
    ) -> Result<Self> {
        crate::hash(&digest)?;
        let display = Zeroizing::new(inert_text(&format!(
            "{display}\n\nExact owner review digest: {digest}\n\n{TRUST_NOTICE}"
        )));
        if display.len() > MAX_REVIEW_BYTES {
            return Err(AuthorityError::Limit);
        }
        Ok(Self {
            proposal,
            display,
            digest,
            first_commit_deadline_ms: deadline,
        })
    }
}
struct PendingReview {
    prepared: Prepared,
    owner: NativeOwner,
    clock: ReviewClock,
    epoch: u64,
    phase: Phase,
}
impl PendingReview {
    fn current(&self, focused: bool, epoch: u64) -> Result<()> {
        if !focused || self.epoch != epoch || !self.owner.is_open() {
            return Err(AuthorityError::Permission);
        }
        self.clock.check()
    }
    fn phrase(&self) -> String {
        format!("AUTHORIZE {}", &self.prepared.digest[..12])
    }
}

// Finite variants only. No backend accepts an arbitrary caller-supplied closure.
enum Work {
    DurablePaymentV1(durable_payment_v1::WorkV1),
    DurableDeliveryV2(durable_delivery_admission_v2::WorkV2),
    FinancialContinuationV1(financial_continuation_v1::WorkV1),
    PrepareSetup(NamespaceSetupInput),
    PrepareEnrollment {
        input: NamespaceOpenInput,
        envelope: Zeroizing<String>,
    },
    PreparePermanentExclusionV1 {
        input: NamespaceOpenInput,
        envelope: Zeroizing<String>,
    },
    ExcludePermanentlyV1 {
        decision: Box<NativePermanentExclusionDecisionV1>,
        clock: ReviewClock,
    },
    PrepareBornOfflineEnrollmentV1 {
        input: NamespaceOpenInput,
        envelope: Zeroizing<String>,
    },
    EnrollBornOfflineV1 {
        decision: Box<NativeBornOfflineEnrollmentDecisionV1>,
        clock: ReviewClock,
    },
    #[cfg(feature = "born-offline-witness-owner")]
    PrepareBornOfflineArtifactsV1 {
        input: NamespaceOpenInput,
        key_file: String,
        signer_hex: String,
    },
    #[cfg(feature = "born-offline-witness-owner")]
    InstallBornOfflineArtifactsV1 {
        decision: Box<NativeBornOfflineArtifactsDecisionV1>,
        clock: ReviewClock,
    },
    PrepareManualExtension {
        input: NamespaceOpenInput,
        envelope: Zeroizing<String>,
    },
    ExtendManual {
        decision: Box<NativeManualEnrollmentExtensionDecision>,
        clock: ReviewClock,
    },
    PrepareManualContinuation {
        input: NamespaceOpenInput,
        envelope: Zeroizing<String>,
    },
    ContinueManual {
        decision: Box<NativeManualSessionContinuationDecision>,
        clock: ReviewClock,
    },
    PrepareManualRosterExtensionV2 {
        input: NamespaceOpenInput,
        envelope: Zeroizing<String>,
    },
    ExtendManualRosterV2 {
        decision: Box<NativeManualRosterExtensionDecisionV2>,
        clock: ReviewClock,
    },
    PrepareManualRosterContinuationV2 {
        input: NamespaceOpenInput,
        envelope: Zeroizing<String>,
    },
    ContinueManualRosterV2 {
        decision: Box<NativeManualRosterContinuationDecisionV2>,
        clock: ReviewClock,
    },
    PrepareConstructionTransportGrantV1 {
        input: NamespaceOpenInput,
        envelope: Zeroizing<String>,
    },
    GrantConstructionTransportV1 {
        decision: Box<NativeConstructionTransportGrantDecisionV1>,
        clock: ReviewClock,
    },
    PrepareManualRosterConstructionV3 {
        input: NamespaceOpenInput,
        envelope: Zeroizing<String>,
    },
    ApproveManualRosterConstructionV3 {
        decision: Box<NativeManualRosterConstructionDecisionV3>,
        clock: ReviewClock,
    },
    PrepareManualRosterConstructionV2 {
        input: NamespaceOpenInput,
        envelope: Zeroizing<String>,
    },
    ApproveManualRosterConstructionV2 {
        decision: Box<NativeManualRosterConstructionDecisionV2>,
        clock: ReviewClock,
    },
    Install(Box<NativeSetupDecision>),
    Enroll(Box<NativeEnrollmentDecision>),
    PrepareBackup(NamespaceBackupInput),
    PrepareRecovery(NamespaceRecoveryInput),
    Backup {
        decision: Box<NativeNamespaceBackupDecision>,
        clock: ReviewClock,
    },
    Discard(Box<Prepared>),
}
enum WorkResult {
    FinancialContinuationAdmittedV1 { display: Zeroizing<String>, clock: ReviewClock },
    DurableDeliveryAdmittedV2 {
        display: Zeroizing<String>,
        clock: ReviewClock,
    },
    DurablePaymentAdmittedV1 {
        display: Zeroizing<String>,
        clock: ReviewClock,
    },
    PermanentlyExcludedV1 {
        display: Zeroizing<String>,
        clock: ReviewClock,
    },
    Prepared(Prepared),
    DiscardPrepared(Prepared),
    Discarded,
    Installed {
        witness_id: String,
        namespace_digest: String,
        canonical_root: String,
    },
    Enrolled,
    ManualContinued {
        display: Zeroizing<String>,
        clock: ReviewClock,
    },
    ConstructionApproved {
        display: Zeroizing<String>,
        clock: ReviewClock,
    },
    #[cfg(feature = "born-offline-witness-owner")]
    BornOfflineArtifactsInstalledV1 {
        display: Zeroizing<String>,
        clock: ReviewClock,
    },
    BornOfflineEnrolledV1 {
        display: Zeroizing<String>,
        clock: ReviewClock,
    },
    ManualExtended {
        display: Zeroizing<String>,
        clock: ReviewClock,
    },
    BackupWritten {
        display: Zeroizing<String>,
        clock: ReviewClock,
    },
}
struct WorkerJob {
    owner: NativeOwner,
    epoch: u64,
    receiver: Receiver<Result<WorkResult>>,
    thread: Option<JoinHandle<()>>,
    received: Option<Result<WorkResult>>,
    cleanup: bool,
    #[cfg(feature = "synthetic-qualification")]
    admission_observer:
        Option<crate::transport::admission_diagnostics_v1::AdmissionWitnessObserverV1>,
}
impl WorkerJob {
    fn poll(&mut self) -> Option<Result<WorkResult>> {
        if self.received.is_none() {
            match self.receiver.try_recv() {
                Ok(value) => {
                    #[cfg(feature = "synthetic-qualification")]
                    if let Some(observer) = &self.admission_observer {
                        observer.completion(crate::transport::admission_diagnostics_v1::AdmissionWitnessCompletionV1::Received);
                    }
                    self.received = Some(value);
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => {
                    #[cfg(feature = "synthetic-qualification")]
                    if let Some(observer) = &self.admission_observer {
                        observer.completion(crate::transport::admission_diagnostics_v1::AdmissionWitnessCompletionV1::Disconnected);
                    }
                    self.received = Some(Err(AuthorityError::Uncertain))
                }
            }
        }
        if self
            .thread
            .as_ref()
            .is_some_and(|thread| thread.is_finished())
        {
            // Never join a running worker from the GUI. No mutable/durable work
            // follows its send. Joining a finished thread only observes panic.
            let panicked = self.thread.take().expect("checked present").join().is_err();
            // The worker may finish between our first empty receive and this
            // join. Re-read once after join so a successfully queued result is
            // not misreported as uncertain.
            if self.received.is_none() {
                let received = self.receiver.try_recv();
                #[cfg(feature = "synthetic-qualification")]
                if let Some(observer) = &self.admission_observer {
                    observer.completion(if received.is_ok() {
                        crate::transport::admission_diagnostics_v1::AdmissionWitnessCompletionV1::Received
                    } else {
                        crate::transport::admission_diagnostics_v1::AdmissionWitnessCompletionV1::Disconnected
                    });
                }
                self.received = Some(received.unwrap_or(Err(AuthorityError::Uncertain)));
            }
            if panicked {
                #[cfg(feature = "synthetic-qualification")]
                if let Some(observer) = &self.admission_observer {
                    observer.completion(crate::transport::admission_diagnostics_v1::AdmissionWitnessCompletionV1::Panicked);
                }
                // A queued snapshot-bearing proposal still needs off-GUI
                // disposal even when the finishing preparation worker panicked.
                return Some(match self.received.take() {
                    Some(Ok(WorkResult::Prepared(prepared))) => {
                        Ok(WorkResult::DiscardPrepared(prepared))
                    }
                    _ => Err(AuthorityError::Uncertain),
                });
            }
            return self.received.take();
        }
        None
    }
}
fn launch_work(
    work: Work,
    owner: NativeOwner,
    epoch: u64,
    ctx: &egui::Context,
) -> Result<WorkerJob> {
    launch_private_work(work, owner, epoch, Some(ctx.clone()))
}
fn launch_private_work(
    work: Work,
    owner: NativeOwner,
    epoch: u64,
    ctx: Option<egui::Context>,
) -> Result<WorkerJob> {
    let cleanup = matches!(&work, Work::Discard(_));
    #[cfg(feature = "synthetic-qualification")]
    let admission_observer = match &work {
        Work::DurableDeliveryV2(durable_delivery_admission_v2::WorkV2::Admit {
            observer, ..
        }) => observer.clone(),
        Work::DurablePaymentV1(durable_payment_v1::WorkV1::Admit { observer, .. }) => {
            observer.clone()
        }
        _ => None,
    };
    // Spawn before transferring any heavyweight proposal. If spawning fails,
    // revoke first, then safely dispose locally: an exceptional synchronous
    // fallback, never a forgotten/leaked secret-bearing value or new authority.
    let (work_sender, work_receiver) = mpsc::sync_channel::<Work>(1);
    let (send, receiver) = mpsc::sync_channel(1);
    let thread = std::thread::Builder::new()
        .name("witness-owner-operation".into())
        .spawn(move || {
            let Ok(work) = work_receiver.recv() else {
                return;
            };
            #[cfg(feature = "synthetic-qualification")]
            let diagnostic_boundary = match &work {
                Work::PrepareManualRosterConstructionV3 { .. } => Some(
                    synthetic_plan_diagnostics_v1::Boundary::WitnessPlanWorkerPrepare,
                ),
                Work::ApproveManualRosterConstructionV3 { .. } => Some(
                    synthetic_plan_diagnostics_v1::Boundary::WitnessPlanWorkerApprove,
                ),
                _ => None,
            };
            #[cfg(feature = "synthetic-qualification")]
            if let Some(boundary) = diagnostic_boundary {
                synthetic_plan_diagnostics_v1::begin(boundary);
            }
            let result = match work {
                Work::Discard(prepared) => {
                    drop(prepared);
                    Ok(WorkResult::Discarded)
                }
                Work::PrepareSetup(input) => {
                    #[cfg(feature = "synthetic-qualification")]
                    let synthetic_owned = input.synthetic_installation.is_some();
                    let proposal = prepare_namespace_setup(input);
                    #[cfg(feature = "synthetic-qualification")]
                    if synthetic_owned {
                        if let Err(error) = &proposal {
                            eprintln!("synthetic witness setup prepare namespace: {error:?}");
                        }
                    }
                    let prepared = proposal.and_then(Prepared::setup);
                    #[cfg(feature = "synthetic-qualification")]
                    if synthetic_owned {
                        if let Err(error) = &prepared {
                            eprintln!("synthetic witness setup prepared current/display: {error:?}");
                        }
                    }
                    prepared.map(WorkResult::Prepared)
                },
                Work::PrepareEnrollment { input, envelope } => (|| {
                    let body: PendingBirthOwnerSignature = serde_json::from_str(&envelope)
                        .map_err(|_| AuthorityError::InvalidBinding)?;
                    let verified = verify_pending_birth_owner_signature(
                        &body,
                        &input.owner_certificate_digest,
                    )?;
                    Prepared::enrollment(prepare_namespace_enrollment(input, verified)?)
                        .map(WorkResult::Prepared)
                })(),
                Work::PrepareBornOfflineEnrollmentV1 { input, envelope } => (|| {
                    let body = parse_born_offline_enrollment_envelope_v1(&envelope)?;
                    let verified = verify_born_offline_enrollment_v1_owner_signature(&body, &input.owner_certificate_digest)?;
                    Prepared::born_offline_enrollment_v1(prepare_born_offline_enrollment_v1(input, verified)?).map(WorkResult::Prepared)
                })(),
                Work::EnrollBornOfflineV1 { decision, clock } => {
                    commit_born_offline_enrollment_v1(*decision)
                        .and_then(|audit| private_display(&serde_json::json!({
                            "kind": "immutable_born_offline_enrollment_v1",
                            "enrollment_digest": audit.enrollment_digest,
                            "offline_policy_digest": audit.offline_policy_digest,
                            "enrollment_ref": audit.enrollment_ref,
                            "committed_head": audit.committed_head,
                            "original_record": audit.original_record,
                            "financial_execution_available": false,
                        })).map_err(|_| AuthorityError::Uncertain))
                        .map(|display| WorkResult::BornOfflineEnrolledV1 { display, clock })
                }
                #[cfg(feature = "born-offline-witness-owner")]
                Work::PrepareBornOfflineArtifactsV1 {input,key_file,signer_hex} => prepare_born_offline_artifacts_v1(input,key_file,signer_hex).and_then(Prepared::born_offline_artifacts_v1).map(WorkResult::Prepared),
                #[cfg(feature = "born-offline-witness-owner")]
                Work::InstallBornOfflineArtifactsV1 {decision,clock} => commit_born_offline_artifacts_v1(*decision)
                    .and_then(|audit|private_display(&serde_json::json!({"kind":"immutable_born_offline_artifact_import_v1","original_record":audit.original_record,"committed_head":audit.committed_head,"financial_execution_available":false})).map_err(|_|AuthorityError::Uncertain))
                    .map(|display|WorkResult::BornOfflineArtifactsInstalledV1{display,clock}),
                Work::PrepareManualExtension { input, envelope } => (|| {
                    let body = parse_manual_extension_envelope(&envelope)?;
                    let verified = verify_manual_enrollment_extension_owner_signature(
                        &body,
                        &input.owner_certificate_digest,
                    )?;
                    Prepared::manual_extension(prepare_manual_enrollment_extension(
                        input, verified,
                    )?)
                    .map(WorkResult::Prepared)
                })(),
                Work::ExtendManual { decision, clock } => {
                    commit_manual_enrollment_extension(*decision)
                        .and_then(|audit| {
                            private_display(&serde_json::json!({
                                "kind": "immutable_manual_enrollment_extension",
                                "extension_digest": audit.extension_digest,
                                "enrollment_ref": audit.enrollment_ref,
                                "committed_head": audit.committed_head,
                            }))
                        })
                        .map(|display| WorkResult::ManualExtended { display, clock })
                }
                Work::PrepareManualContinuation { input, envelope } => (|| {
                    let body = parse_manual_continuation_envelope(&envelope)?;
                    let verified = verify_manual_enrollment_session_continuation_owner_signature(
                        &body,
                        &input.owner_certificate_digest,
                    )?;
                    Prepared::manual_continuation(prepare_manual_session_continuation(
                        input, verified,
                    )?)
                    .map(WorkResult::Prepared)
                })(),
                Work::ContinueManual { decision, clock } => {
                    commit_manual_session_continuation(*decision)
                        .and_then(|audit| {
                            private_display(&serde_json::json!({
                                "kind": "immutable_manual_session_continuation",
                                "attempt_digest": audit.attempt_digest,
                                "committed_head": audit.committed_head,
                            }))
                        })
                        .map(|display| WorkResult::ManualContinued { display, clock })
                }
                Work::PreparePermanentExclusionV1 { input, envelope } => (|| {
                    let body = parse_permanent_exclusion_envelope_v1(&envelope)?;
                    let verified = verify_permanent_exclusion_owner_signature_v1(&body, &input.owner_certificate_digest)?;
                    Prepared::permanent_exclusion_v1(prepare_permanent_exclusion_v1(input, verified)?).map(WorkResult::Prepared)
                })(),
                Work::ExcludePermanentlyV1 { decision, clock } => {
                    commit_permanent_exclusion_v1(*decision)
                        .and_then(|receipt| private_display(&serde_json::json!({
                            "kind": "immutable_permanent_account_exclusion_v1", "receipt": receipt,
                            "notice": "Routine reuse is permanently denied here. Pending exposure remains. No funds recovered, empty account or Host propagation is claimed."
                        })))
                        .map(|display| WorkResult::PermanentlyExcludedV1 { display, clock })
                }
                Work::DurablePaymentV1(work) => durable_payment_v1::execute(work),
                Work::DurableDeliveryV2(work) => durable_delivery_admission_v2::execute(work),
                Work::FinancialContinuationV1(work) => financial_continuation_v1::execute(work),
                Work::PrepareManualRosterExtensionV2 { input, envelope } => (|| {
                    let body = parse_manual_roster_extension_envelope_v2(&envelope)?;
                    let verified = verify_manual_roster_enrollment_owner_signature_v2(
                        &body,
                        &input.owner_certificate_digest,
                    )?;
                    Prepared::manual_roster_extension_v2(prepare_manual_roster_extension_v2(
                        input, verified,
                    )?)
                    .map(WorkResult::Prepared)
                })(),
                Work::ExtendManualRosterV2 { decision, clock } => {
                    commit_manual_roster_extension_v2(*decision)
                        .and_then(|audit| {
                            private_display(&serde_json::json!({
                                "kind": "immutable_manual_roster_enrollment_extension_v2",
                                "extension_digest": audit.extension_digest,
                                "enrollment_ref": audit.enrollment_ref,
                                "committed_head": audit.committed_head,
                            }))
                        })
                        .map(|display| WorkResult::ManualExtended { display, clock })
                }
                Work::PrepareManualRosterContinuationV2 { input, envelope } => (|| {
                    let body = parse_manual_roster_continuation_envelope_v2(&envelope)?;
                    let verified = verify_manual_roster_continuation_owner_signature_v2(
                        &body,
                        &input.owner_certificate_digest,
                    )?;
                    Prepared::manual_roster_continuation_v2(prepare_manual_roster_continuation_v2(
                        input, verified,
                    )?)
                    .map(WorkResult::Prepared)
                })(),
                Work::ContinueManualRosterV2 { decision, clock } => {
                    commit_manual_roster_continuation_v2(*decision)
                        .and_then(|audit| {
                            private_display(&serde_json::json!({
                                "kind": "immutable_manual_roster_session_continuation_v2",
                                "attempt_digest": audit.attempt_digest,
                                "committed_head": audit.committed_head,
                            }))
                        })
                        .map(|display| WorkResult::ManualContinued { display, clock })
                }
                Work::PrepareConstructionTransportGrantV1 { input, envelope } => (|| {
                    let authorization = parse_construction_transport_preauthorization_v1(&envelope)?;
                    Prepared::construction_transport_grant_v1(
                        prepare_construction_transport_grant_v1(input, authorization)?,
                    ).map(WorkResult::Prepared)
                })(),
                Work::GrantConstructionTransportV1 { decision, clock } => {
                    commit_construction_transport_grant_v1(*decision)
                        .and_then(|pending| private_display(&serde_json::json!({
                            "kind": "inert_pending_construction_transport_grant_v1",
                            "notice": "No active credential or financial authority. This exact post-append head is required by the one fresh native key claim.",
                            "pending_grant": pending,
                        })))
                        .map(|display| WorkResult::ConstructionApproved { display, clock })
                }
                Work::PrepareManualRosterConstructionV3 { input, envelope } => (|| {
                    let body = parse_manual_roster_construction_envelope_v3(&envelope)?;
                    let verified = verify_manual_roster_construction_owner_signature_v3(
                        &body,
                        &input.owner_certificate_digest,
                    )?;
                    Prepared::manual_roster_construction_v3(prepare_manual_roster_construction_v3(
                        input, verified,
                    )?)
                    .map(WorkResult::Prepared)
                })(),
                Work::ApproveManualRosterConstructionV3 { decision, clock } => {
                    commit_manual_roster_construction_v3(*decision)
                        .and_then(|audit| {
                            private_display(&serde_json::json!({
                                "kind": "immutable_manual_roster_construction_approval_v2",
                                "approval_digest": audit.approval_digest,
                                "committed_head": audit.committed_head,
                            }))
                        })
                        .map(|display| WorkResult::ConstructionApproved { display, clock })
                }
                Work::PrepareManualRosterConstructionV2 { input, envelope } => (|| {
                    let body = parse_manual_roster_construction_envelope_v2(&envelope)?;
                    let verified = verify_manual_roster_construction_owner_signature_v2(
                        &body,
                        &input.owner_certificate_digest,
                    )?;
                    Prepared::manual_roster_construction_v2(prepare_manual_roster_construction_v2(
                        input, verified,
                    )?)
                    .map(WorkResult::Prepared)
                })(),
                Work::ApproveManualRosterConstructionV2 { decision, clock } => {
                    commit_manual_roster_construction_v2(*decision)
                        .and_then(|audit| {
                            private_display(&serde_json::json!({
                                "kind": "immutable_manual_roster_construction_approval_v2",
                                "approval_digest": audit.approval_digest,
                                "committed_head": audit.committed_head,
                            }))
                        })
                        .map(|display| WorkResult::ConstructionApproved { display, clock })
                }
                Work::Install(decision) => {
                    install_namespace(*decision).map(|audit| WorkResult::Installed {
                        witness_id: audit.witness_id,
                        namespace_digest: audit.namespace_digest,
                        canonical_root: audit.canonical_root,
                    })
                }
                Work::Enroll(decision) => crate::pending_birth_owner::commit_native(*decision)
                    .map(|_| WorkResult::Enrolled),
                Work::PrepareBackup(input) => prepare_namespace_backup(input)
                    .and_then(Prepared::backup)
                    .map(WorkResult::Prepared),
                Work::PrepareRecovery(input) => prepare_namespace_recovery_disclosure(input)
                    .and_then(Prepared::recovery)
                    .map(WorkResult::Prepared),
                Work::Backup { decision, clock } => write_namespace_backup(*decision)
                    .and_then(|receipt| private_display(&receipt))
                    .map(|display| WorkResult::BackupWritten { display, clock }),
            };
            #[cfg(feature = "synthetic-qualification")]
            if let Some(boundary) = diagnostic_boundary {
                synthetic_plan_diagnostics_v1::result(boundary, &result);
            }
            let _ = send.send(result);
            if let Some(ctx) = ctx {
                ctx.request_repaint();
            }
        });
    let thread = match thread {
        Ok(thread) => thread,
        Err(_) => {
            owner.revoke();
            drop(work);
            return Err(AuthorityError::Inactive);
        }
    };
    if let Err(error) = work_sender.try_send(work) {
        owner.revoke();
        match error {
            mpsc::TrySendError::Full(work) | mpsc::TrySendError::Disconnected(work) => drop(work),
        }
        return Err(AuthorityError::Inactive);
    }
    Ok(WorkerJob {
        owner,
        epoch,
        receiver,
        thread: Some(thread),
        received: None,
        cleanup,
        #[cfg(feature = "synthetic-qualification")]
        admission_observer,
    })
}

// Finite read commands only. No arbitrary SQL, callback, writable journal or
// deserialization into a live owner is available from the historical UI.
enum HistoricalRequest {
    Summary,
    Inventory {
        first: u32,
        limit: u32,
    },
    AccountSummary {
        intent_digest: String,
    },
    AccountHistory {
        intent_digest: String,
        first_sequence: u64,
        limit: u32,
    },
}
impl HistoricalRequest {
    fn validate(&self) -> Result<()> {
        match self {
            Self::Summary => Ok(()),
            Self::Inventory { limit, .. } if *limit > 0 && *limit <= 16 => Ok(()),
            Self::AccountSummary { intent_digest } => crate::hash(intent_digest),
            Self::AccountHistory {
                intent_digest,
                first_sequence,
                limit,
            } if *first_sequence > 0 && *limit > 0 && *limit <= 32 => crate::hash(intent_digest),
            _ => Err(AuthorityError::InvalidBinding),
        }
    }
}
enum HistoricalOutput {
    Opened,
    Page {
        label: &'static str,
        display: Zeroizing<String>,
    },
}
struct HistoricalInputs {
    first_record: u32,
    record_limit: u32,
    intent_digest: Zeroizing<String>,
    first_sequence: u64,
    event_limit: u32,
}
impl Default for HistoricalInputs {
    fn default() -> Self {
        Self {
            first_record: 0,
            record_limit: 8,
            intent_digest: Zeroizing::new(String::new()),
            first_sequence: 1,
            event_limit: 8,
        }
    }
}
struct HistoricalWorker {
    owner: NativeOwner,
    clock: ReviewClock,
    epoch: u64,
    commands: Option<SyncSender<HistoricalRequest>>,
    receiver: Receiver<Result<HistoricalOutput>>,
    thread: Option<JoinHandle<()>>,
    opened: bool,
    busy: bool,
    terminal: bool,
}
impl HistoricalWorker {
    fn current(&self, focused: bool, epoch: u64) -> Result<()> {
        if !focused || self.epoch != epoch || !self.owner.is_open() || self.commands.is_none() {
            return Err(AuthorityError::Permission);
        }
        self.clock.check()
    }
    fn stop(&mut self) {
        self.owner.revoke();
        self.commands.take();
        self.opened = false;
        self.busy = false;
    }
    fn request(&mut self, request: HistoricalRequest, focused: bool, epoch: u64) -> Result<()> {
        self.current(focused, epoch)?;
        if !self.opened || self.busy {
            return Err(AuthorityError::Inactive);
        }
        request.validate()?;
        self.commands
            .as_ref()
            .ok_or(AuthorityError::Permission)?
            .try_send(request)
            .map_err(|_| AuthorityError::Inactive)?;
        self.busy = true;
        Ok(())
    }
    fn poll(&mut self) -> Option<Result<HistoricalOutput>> {
        if self.terminal {
            return None;
        }
        match self.receiver.try_recv() {
            Ok(output) => Some(output),
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => {
                self.terminal = true;
                self.commands
                    .as_ref()
                    .map(|_| Err(AuthorityError::Uncertain))
            }
        }
    }
    fn finished(&self) -> bool {
        self.thread
            .as_ref()
            .is_some_and(|thread| thread.is_finished())
    }
    fn join_finished(&mut self) -> Result<()> {
        if !self.finished() {
            return Err(AuthorityError::Inactive);
        }
        self.thread
            .take()
            .expect("checked finished")
            .join()
            .map_err(|_| AuthorityError::Uncertain)
    }
}
impl Drop for HistoricalWorker {
    fn drop(&mut self) {
        self.stop();
    }
}
fn launch_historical_work(
    decision: NativeNamespaceRecoveryDisclosureDecision,
    owner: NativeOwner,
    clock: ReviewClock,
    epoch: u64,
    ctx: &egui::Context,
) -> Result<HistoricalWorker> {
    let (decision_sender, decision_receiver) =
        mpsc::sync_channel::<NativeNamespaceRecoveryDisclosureDecision>(1);
    let (commands, requests) = mpsc::sync_channel::<HistoricalRequest>(1);
    let (send, receiver) = mpsc::sync_channel::<Result<HistoricalOutput>>(1);
    let ctx = ctx.clone();
    let thread = std::thread::Builder::new()
        .name("witness-owner-history".into())
        .spawn(move || {
            let Ok(decision) = decision_receiver.recv() else {
                return;
            };
            // The reader is constructed, used and dropped on this worker only.
            // Opening authenticates the selected package; it reveals no summary.
            let evidence = match open_namespace_recovery_evidence(decision) {
                Ok(evidence) => evidence,
                Err(error) => {
                    let _ = send.send(Err(error));
                    ctx.request_repaint();
                    return;
                }
            };
            if send.send(Ok(HistoricalOutput::Opened)).is_err() {
                return;
            }
            ctx.request_repaint();
            while let Ok(request) = requests.recv() {
                let output = request.validate().and_then(|()| match request {
                    HistoricalRequest::Summary => evidence
                        .summary()
                        .and_then(|value| private_display(&value))
                        .map(|display| HistoricalOutput::Page {
                            label: "Historical namespace summary",
                            display,
                        }),
                    HistoricalRequest::Inventory { first, limit } => evidence
                        .inventory(first, limit)
                        .and_then(|value| private_display(&value))
                        .map(|display| HistoricalOutput::Page {
                            label: "Historical inventory page",
                            display,
                        }),
                    HistoricalRequest::AccountSummary { intent_digest } => evidence
                        .account_summary(&intent_digest)
                        .and_then(|value| private_display(&value))
                        .map(|display| HistoricalOutput::Page {
                            label: "Historical account summary",
                            display,
                        }),
                    HistoricalRequest::AccountHistory {
                        intent_digest,
                        first_sequence,
                        limit,
                    } => evidence
                        .account_history(&intent_digest, first_sequence, limit)
                        .and_then(|value| private_display(&value))
                        .map(|display| HistoricalOutput::Page {
                            label: "Historical account event page",
                            display,
                        }),
                });
                let failed = output.is_err();
                if send.send(output).is_err() {
                    return;
                }
                ctx.request_repaint();
                if failed {
                    return;
                }
            }
            // Closing the command channel cancels idle work. In-flight backend
            // accessors check the retained revocable lease before and after I/O.
        });
    let thread = match thread {
        Ok(thread) => thread,
        Err(_) => {
            owner.revoke();
            drop(decision);
            return Err(AuthorityError::Inactive);
        }
    };
    if let Err(error) = decision_sender.try_send(decision) {
        owner.revoke();
        match error {
            mpsc::TrySendError::Full(decision) | mpsc::TrySendError::Disconnected(decision) => {
                drop(decision)
            }
        }
        return Err(AuthorityError::Inactive);
    }
    Ok(HistoricalWorker {
        owner,
        clock,
        epoch,
        commands: Some(commands),
        receiver,
        thread: Some(thread),
        opened: false,
        busy: true,
        terminal: false,
    })
}

struct PrivateDisplayBuffer(Zeroizing<Vec<u8>>);
impl Write for PrivateDisplayBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self
            .0
            .len()
            .checked_add(bytes.len())
            .is_none_or(|length| length > MAX_HISTORICAL_DISPLAY_BYTES)
        {
            return Err(std::io::Error::other("private display limit"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn private_display(value: &impl serde::Serialize) -> Result<Zeroizing<String>> {
    let mut buffer = PrivateDisplayBuffer(Zeroizing::new(Vec::new()));
    serde_json::to_writer_pretty(&mut buffer, value).map_err(|_| AuthorityError::Limit)?;
    let raw = Zeroizing::new(
        String::from_utf8(std::mem::take(&mut *buffer.0))
            .map_err(|_| AuthorityError::CorruptHistory)?,
    );
    let mut safe = Zeroizing::new(String::new());
    for character in raw.chars() {
        if character == '\n' || character == ' ' || character.is_ascii_graphic() {
            if safe.len() == MAX_HISTORICAL_DISPLAY_BYTES {
                return Err(AuthorityError::Limit);
            }
            safe.push(character);
        } else {
            for escaped in character.escape_default() {
                if safe.len() == MAX_HISTORICAL_DISPLAY_BYTES {
                    return Err(AuthorityError::Limit);
                }
                safe.push(escaped);
            }
        }
    }
    Ok(safe)
}

pub(super) struct Window {
    input: NativeInputs,
    pending: Option<PendingReview>,
    job: Option<WorkerJob>,
    historical: Option<HistoricalWorker>,
    historical_input: HistoricalInputs,
    historical_display: Option<(&'static str, Zeroizing<String>)>,
    last_archive_receipt: Option<(ReviewClock, Zeroizing<String>)>,
    confirmation: Zeroizing<String>,
    understood: bool,
    focus_epoch: u64,
    focused_last: bool,
    close_when_idle: bool,
    disposal_failed: bool,
    last_installation_audit: Option<Zeroizing<String>>,
    #[cfg(feature = "synthetic-qualification")]
    admission_observer:
        Option<crate::transport::admission_diagnostics_v1::AdmissionWitnessObserverV1>,
    message: &'static str,
}
impl Window {
    pub(super) fn new() -> Self {
        Self {
            input: NativeInputs::default(),
            pending: None,
            job: None,
            historical: None,
            historical_input: HistoricalInputs::default(),
            historical_display: None,
            last_archive_receipt: None,
            confirmation: Zeroizing::new(String::new()),
            understood: false,
            focus_epoch: 0,
            focused_last: false,
            close_when_idle: false,
            disposal_failed: false,
            last_installation_audit: None,
            #[cfg(feature = "synthetic-qualification")]
            admission_observer: None,
            message: "Choose the existing owner public certificate and exact witness identity independently. The namespace root is fixed by the OS installation; request data cannot select another root.",
        }
    }
    fn discard(&mut self) {
        if let Some(pending) = &self.pending {
            pending.owner.revoke();
        }
        let pending = self.pending.take();
        if let Some(job) = &self.job {
            job.owner.revoke();
        }
        if let Some(historical) = &mut self.historical {
            historical.stop();
        }
        self.historical_display.take();
        self.historical_input = HistoricalInputs::default();
        self.last_archive_receipt.take();
        self.focus_epoch = self.focus_epoch.saturating_add(1);
        self.confirmation.zeroize();
        self.input.discard_raw();
        self.understood = false;
        if let Some(PendingReview {
            prepared, owner, ..
        }) = pending
        {
            self.discard_prepared(prepared, owner);
        }
    }
    fn discard_prepared(&mut self, mut prepared: Prepared, owner: NativeOwner) {
        // First make the GUI-held admission and displayed private data unusable.
        // The snapshot-bearing opaque proposal is dropped only by Work::Discard.
        owner.revoke();
        prepared.display.zeroize();
        self.confirmation.zeroize();
        self.understood = false;
        self.input.discard_raw();
        self.historical_display.take();
        self.historical_input = HistoricalInputs::default();
        self.last_archive_receipt.take();
        if self.job.is_some() || self.historical.is_some() {
            // Broken private state is not permission to overlap workers. Keep
            // authority revoked and fail closed with safe synchronous disposal.
            self.disposal_failed = true;
            if let Some(job) = &self.job {
                job.owner.revoke();
            }
            if let Some(historical) = &mut self.historical {
                historical.stop();
            }
            drop(prepared);
            self.message = "Private cleanup encountered an inconsistent worker state. The review was revoked and disposed locally; close this window before starting another operation.";
            return;
        }
        match launch_private_work(
            Work::Discard(Box::new(prepared)),
            owner,
            self.focus_epoch,
            None,
        ) {
            Ok(job) => self.job = Some(job),
            Err(_) => {
                self.disposal_failed = true;
                self.message = "The private cleanup worker could not start. The review was revoked and disposed locally; cleanup may have blocked this window. Close it before starting another operation.";
            }
        }
    }
    fn can_select(&self) -> bool {
        self.pending.is_none()
            && self.job.is_none()
            && self.historical.is_none()
            && !self.disposal_failed
            && !self.close_when_idle
    }
    fn poll_job(&mut self, ctx: &egui::Context, focused: bool) {
        let Some(result) = self.job.as_mut().and_then(WorkerJob::poll) else {
            return;
        };
        let job = self.job.take().expect("polled existing job");
        match result {
            Ok(WorkResult::Prepared(prepared)) => {
                if focused
                    && job.epoch == self.focus_epoch
                    && job.owner.is_open()
                    && !self.close_when_idle
                {
                    match ReviewClock::start(prepared.first_commit_deadline_ms) {
                        Ok(clock) => {
                            self.pending = Some(PendingReview {
                                prepared,
                                owner: job.owner,
                                clock,
                                epoch: self.focus_epoch,
                                phase: Phase::Reading,
                            });
                            self.message = "Review the exact backend-authenticated namespace, operation, existing state and consequences below.";
                        }
                        Err(_) => {
                            self.message = "The original request expired during preparation. Its private snapshots are being discarded; no native decision was issued.";
                            self.discard_prepared(prepared, job.owner);
                        }
                    }
                } else {
                    self.message = "The interrupted preparation is being discarded on the private worker. Reopen the exact original request only after cleanup finishes.";
                    self.discard_prepared(prepared, job.owner);
                }
            }
            Ok(WorkResult::DiscardPrepared(prepared)) => {
                self.message = "Preparation did not finish normally. Its review is revoked and its private snapshots are being discarded.";
                self.discard_prepared(prepared, job.owner);
            }
            Ok(WorkResult::Discarded) => {
                self.message =
                    "Private snapshot cleanup finished. No previous native decision remains.";
            }
            Ok(WorkResult::Installed {
                witness_id,
                namespace_digest,
                canonical_root,
            }) => {
                self.last_installation_audit = Some(Zeroizing::new(inert_text(&format!(
                    "Installed witness ID: {witness_id}\nNamespace digest: {namespace_digest}\nCanonical root: {canonical_root}"
                ))));
                // Trusted completed local setup, never untrusted request data.
                self.input.witness_id = witness_id;
                self.message = "The exact immutable namespace installation completed. Its generated witness ID is filled below for a separately approved enrollment. Keep protected installation/registry and backup continuity together; missing state is not fresh setup.";
            }
            Ok(WorkResult::Enrolled) => {
                self.message = "The exact original witness enrollment and authenticated completion record agree. This is witness enrollment only; signer acknowledgement and active-vault publication remain separate gates.";
            }
            Ok(WorkResult::PermanentlyExcludedV1 { display, clock }) => {
                if focused
                    && job.epoch == self.focus_epoch
                    && !job.owner.revoke_requested()
                    && !self.close_when_idle
                    && clock.check().is_ok()
                {
                    self.last_archive_receipt = Some((clock, display));
                }
                self.message = "Exact original permanent restriction recorded. Pending exposure, released authorizations and lifetime charges remain. Host propagation requires its own durable acknowledgment; no funds recovery or empty-account completion is claimed.";
            }
            Ok(WorkResult::BornOfflineEnrolledV1 { display, clock }) => {
                if focused
                    && job.epoch == self.focus_epoch
                    && !job.owner.revoke_requested()
                    && !self.close_when_idle
                    && clock.check().is_ok()
                {
                    self.last_archive_receipt = Some((clock, display));
                }
                self.message = "The exact bounded born offline enrollment was recorded. Its original session, policy, charges and history remain. Older manual-only routes reject this offline-bearing history. Enrollment alone cannot execute; separate native protected artifact import and a dedicated configured born runtime are required. No payment or new credential was authorized. Preserve the original signed request for exact recovery.";
            }
            #[cfg(feature = "born-offline-witness-owner")]
            Ok(WorkResult::BornOfflineArtifactsInstalledV1 { display, clock }) => {
                if focused
                    && job.epoch == self.focus_epoch
                    && !job.owner.revoke_requested()
                    && !self.close_when_idle
                    && clock.check().is_ok()
                {
                    self.last_archive_receipt = Some((clock, display));
                }
                self.message = "The exact existing transport key and private mailboxes were retained in the original encrypted journal. This persistent import does not authorize a signature or payment. Preserve the complete namespace archive; uncertain outcomes must be inspected, never reset or replaced.";
            }
            Ok(WorkResult::FinancialContinuationAdmittedV1 { display, clock }) => {
                if focused && job.epoch == self.focus_epoch && !job.owner.revoke_requested()
                    && !self.close_when_idle && clock.check().is_ok() {
                    self.last_archive_receipt = Some((clock, display));
                }
                self.message = "Exact financial continuation retained. Original expiry and attempt limits remain. Fresh signing is still required; completed signatures permit only the separately bounded immutable-transaction dispatcher. No payment was sent by this operation.";
            }
            Ok(WorkResult::DurableDeliveryAdmittedV2 { display, clock }) => {
                if durable_payment_v1::retain_receipt_v1(
                    focused,
                    || job.epoch == self.focus_epoch,
                    || !job.owner.revoke_requested(),
                    || !self.close_when_idle,
                    || clock.check().is_ok(),
                    #[cfg(feature = "synthetic-qualification")]
                    job.admission_observer.as_ref(),
                ) {
                    self.last_archive_receipt = Some((clock, display));
                }
                self.message = "The exact prospective delivery scope is committed after original owner mTLS. This listener is closed. Historical reading is available, but Acquire, Activate, Reserve, signing, extraction and dispatch remain unsupported. An uncertain outcome requires exact history, not another request.";
            }
            Ok(WorkResult::DurablePaymentAdmittedV1 { display, clock }) => {
                if durable_payment_v1::retain_receipt_v1(
                    focused,
                    || job.epoch == self.focus_epoch,
                    || !job.owner.revoke_requested(),
                    || !self.close_when_idle,
                    || clock.check().is_ok(),
                    #[cfg(feature = "synthetic-qualification")]
                    job.admission_observer.as_ref(),
                ) {
                    self.last_archive_receipt = Some((clock, display));
                }
                self.message = "The exact durable financial admission was committed after original owner mTLS. This listener is closed. Closing this window does not revoke the approved interval. Reopen only the same original namespace and immutable record for bounded financial serving. No reserve, signature, release or dispatch occurred here.";
            }
            Ok(WorkResult::ManualExtended { display, clock }) => {
                if focused
                    && job.epoch == self.focus_epoch
                    && !job.owner.revoke_requested()
                    && !self.close_when_idle
                    && clock.check().is_ok()
                {
                    self.last_archive_receipt = Some((clock, display));
                }
                self.message = "The exact immutable manual-enrollment extension was recorded. Original policy, lifetime charges and exclusions remain unchanged. This window did not acquire a writer session, sign a payment or grant a financial action. Preserve the exact request for restart verification.";
            }
            Ok(WorkResult::ManualContinued { display, clock }) => {
                if focused
                    && job.epoch == self.focus_epoch
                    && !job.owner.revoke_requested()
                    && !self.close_when_idle
                    && clock.check().is_ok()
                {
                    self.last_archive_receipt = Some((clock, display));
                }
                self.message = "The exact successor attempt was recorded. Its previous bootstrap session is fenced. Original writer epoch, lifetime charges, policy, exclusions and all history remain. Reopen only this exact selected attempt; financial actions remain separate and denied.";
            }
            Ok(WorkResult::ConstructionApproved { display, clock }) => {
                if focused
                    && job.epoch == self.focus_epoch
                    && !job.owner.revoke_requested()
                    && !self.close_when_idle
                    && clock.check().is_ok()
                {
                    self.last_archive_receipt = Some((clock, display));
                }
                self.message = "The exact non-signing construction plan approval was recorded. Fresh signer-native full-proposal review and current Reserve/Consume remain required. Every admitted reservation retains conservative lifetime exposure; cancellation and expiry do not refund it. No proof, signature, financial release or dispatch was authorized.";
            }
            Ok(WorkResult::BackupWritten { display, clock }) => {
                if focused
                    && job.epoch == self.focus_epoch
                    && !job.owner.revoke_requested()
                    && !self.close_when_idle
                    && clock.check().is_ok()
                {
                    self.last_archive_receipt = Some((clock, display));
                }
                self.message = "The exact encrypted namespace archive was written and verified as permanently historical evidence. It grants no live namespace, signer or financial authority. Keep its independently selected archive key safe; key loss prevents recovery.";
            }
            Err(_) if job.cleanup => {
                self.disposal_failed = true;
                self.message = "The private cleanup worker did not finish normally. No native decision remains. Preserve existing files and close this window before starting another operation.";
            }
            Err(_) if job.owner.publication_started() => {
                self.message = "Finalization may be incomplete. Preserve all output and installed state. Verify the exact original operation before any retry; do not overwrite or initialize a replacement namespace, account target or archive package.";
            }
            Err(_) => {
                self.message = "Preparation or native admission failed or was canceled before publication. No new native approval remains."
            }
        }
        if self.close_when_idle && self.job.is_none() && self.historical.is_none() {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
    }
    fn stop_historical(&mut self) {
        if let Some(historical) = &mut self.historical {
            historical.stop();
        }
        self.historical_display.take();
        self.historical_input = HistoricalInputs::default();
    }
    fn poll_historical(&mut self, ctx: &egui::Context, focused: bool) {
        if self.historical.as_ref().is_some_and(|historical| {
            historical.commands.is_some()
                && (historical.current(focused, self.focus_epoch).is_err() || self.close_when_idle)
        }) {
            self.stop_historical();
            self.message = "The original historical review expired or was revoked. Private views were cleared; a new review needs another exact native decision.";
        }
        let output = self.historical.as_mut().and_then(HistoricalWorker::poll);
        let current = self.historical.as_ref().is_some_and(|historical| {
            historical.current(focused, self.focus_epoch).is_ok() && !self.close_when_idle
        });
        match output {
            Some(Ok(HistoricalOutput::Opened)) if current => {
                let historical = self.historical.as_mut().expect("current historical worker");
                historical.opened = true;
                historical.busy = false;
                self.message = "The historical archive is authenticated for this short, revocable review. Choose each summary or bounded page explicitly below. No private account data has been displayed yet.";
            }
            Some(Ok(HistoricalOutput::Page { label, display })) if current => {
                self.historical
                    .as_mut()
                    .expect("current historical worker")
                    .busy = false;
                self.historical_display = Some((label, display));
                self.message = "Historical evidence only. This page cannot establish current freshness, live ownership, writer admission or permission to spend.";
            }
            Some(Err(_)) if current => {
                self.stop_historical();
                self.message = "Historical verification or the requested bounded page failed. The private review is closed. Preserve the package; a new review requires a fresh native decision.";
            }
            // Delayed responses after blur, cancel or expiry are dropped without
            // rendering or retaining their private contents.
            _ => {}
        }
        if self
            .historical
            .as_ref()
            .is_some_and(HistoricalWorker::finished)
        {
            let mut historical = self.historical.take().expect("finished historical worker");
            let unexpected = historical.commands.is_some();
            let joined = historical.join_finished();
            historical.stop();
            self.historical_display.take();
            self.historical_input = HistoricalInputs::default();
            if unexpected || joined.is_err() {
                self.message = "The historical reader closed. Its private views were cleared; start a new exact native review before reading again.";
            }
        }
        if self.close_when_idle && self.job.is_none() && self.historical.is_none() {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
    }
    fn draw(&mut self, ui: &mut egui::Ui) {
        let (focused, lost_in_batch, closing, escape) = ui.ctx().input(|input| {
            (
                input.focused && input.viewport().focused == Some(true),
                input
                    .events
                    .iter()
                    .any(|event| matches!(event, egui::Event::WindowFocused(false))),
                input.viewport().close_requested(),
                input.key_pressed(egui::Key::Escape),
            )
        });
        let interrupted = focus_interrupted(self.focused_last, focused, lost_in_batch);
        self.focused_last = focused;
        ui.ctx().request_repaint_after(Duration::from_millis(100));
        if interrupted || !focused || closing || escape {
            self.discard();
            if closing && (self.job.is_some() || self.historical.is_some()) {
                self.close_when_idle = true;
                ui.ctx()
                    .send_viewport_cmd(egui::ViewportCommand::CancelClose);
            }
            self.poll_job(ui.ctx(), false);
            self.poll_historical(ui.ctx(), false);
            egui::CentralPanel::default().show(ui, |ui| {
                ui.heading("Independent witness owner");
                ui.label("Private details are hidden. Pending review input was discarded.");
                if self.job.as_ref().is_some_and(|job| job.owner.publication_in_flight()) {
                    ui.label("One exact publication had already been admitted. Its result is still pending; cancellation cannot be claimed. The window will close after the worker finishes if you requested Close.");
                } else if self.job.is_some() {
                    ui.label("Cancellation was requested. Waiting for the private worker to stop; no new review can begin meanwhile.");
                } else if self.historical.is_some() {
                    ui.label("The historical disclosure lease was revoked and its private views cleared. Waiting for the worker to close its encrypted read snapshots.");
                }
            });
            return;
        }
        self.poll_job(ui.ctx(), focused);
        self.poll_historical(ui.ctx(), focused);
        if self
            .last_archive_receipt
            .as_ref()
            .is_some_and(|(clock, _)| clock.check().is_err())
        {
            self.last_archive_receipt.take();
        }
        if self
            .pending
            .as_ref()
            .is_some_and(|p| p.current(focused, self.focus_epoch).is_err())
        {
            self.discard();
            self.message = "The native review expired or was invalidated. Reopen the exact original operation.";
            // Do not rearm in the same input frame.
            return;
        }
        egui::CentralPanel::default().show(ui, |ui| {
            ui.heading("Independent witness owner");
            ui.label(RichText::new("PRE-RELEASE · NATIVE RUNTIME QUALIFICATION PENDING").color(Color32::YELLOW));
            ui.label(TRUST_NOTICE);
            ui.separator(); ui.label(self.message); ui.separator();
            if let Some(audit) = &self.last_installation_audit { ui.label(RichText::new(audit.as_str()).monospace()); }
            if let Some((_, receipt)) = &self.last_archive_receipt {
                ui.label("Exact completed operation receipt");
                egui::ScrollArea::vertical().id_salt(COMPLETED_RECEIPT_SCROLL_ID).max_height(160.0).show(ui, |ui| {
                    ui.label(RichText::new(receipt.as_str()).monospace());
                });
            }
            if let Some(job) = &self.job {
                ui.label(if job.cleanup {
                    "Discarding revoked private proposal snapshots on the worker. Another operation must wait for cleanup to finish."
                } else if job.owner.publication_in_flight() {
                    "Finalizing the one exact admitted operation. The GUI remains responsive; later cancellation cannot erase a possible commit."
                } else if job.owner.revoke_requested() {
                    "Cancellation requested. Waiting for the worker before another operation can begin."
                } else { "Preparing or checking the exact operation on the private worker." });
                if ui.button("Cancel pending work").clicked_by(egui::PointerButton::Primary) { self.discard(); }
            } else if self.historical.is_some() { self.historical_ui(ui, focused); }
            else if self.pending.is_some() { self.review_ui(ui, focused); }
            else if self.disposal_failed {
                ui.label("Private cleanup could not run normally. No new operation is allowed in this window; close it before trying again.");
            }
            else if self.can_select() { self.selection_ui(ui, focused); }
        });
    }
    // Same concrete preparation entered only by a focused primary-pointer
    // branch. Public buttons retain their activation guard; the synthetic-only
    // fixture has a distinct finite control, never an opaque decision factory.
    fn prepare_manual_roster_construction_v3_from_primary(&mut self, ctx: &egui::Context) {
        let launched = (|| {
            let input = self.input.enrollment_input()?;
            if self
                .input
                .signed_manual_roster_construction_v3_json
                .is_empty()
                || self.input.signed_manual_roster_construction_v3_json.len()
                    > crate::MAX_FRAME_BYTES
            {
                return Err(AuthorityError::Limit);
            }
            let envelope = Zeroizing::new(std::mem::take(
                &mut *self.input.signed_manual_roster_construction_v3_json,
            ));
            launch_work(
                Work::PrepareManualRosterConstructionV3 { input, envelope },
                NativeOwner::entered_window(),
                self.focus_epoch,
                ctx,
            )
        })();
        #[cfg(feature = "synthetic-qualification")]
        synthetic_plan_diagnostics_v1::result(
            synthetic_plan_diagnostics_v1::Boundary::WitnessPlanLaunch,
            &launched,
        );
        self.accept_launch(launched);
    }
    fn prepare_construction_transport_grant_v1_from_primary(&mut self, ctx: &egui::Context) {
        let launched = (|| {
            let input = self.input.enrollment_input()?;
            if self
                .input
                .signed_construction_transport_preauthorization_json
                .is_empty()
                || self
                    .input
                    .signed_construction_transport_preauthorization_json
                    .len()
                    > MAX_CONSTRUCTION_TRANSPORT_COMPONENT_BYTES
            {
                return Err(AuthorityError::Limit);
            }
            let envelope = Zeroizing::new(std::mem::take(
                &mut *self
                    .input
                    .signed_construction_transport_preauthorization_json,
            ));
            launch_work(
                Work::PrepareConstructionTransportGrantV1 { input, envelope },
                NativeOwner::entered_window(),
                self.focus_epoch,
                ctx,
            )
        })();
        self.accept_launch(launched);
    }
    fn selection_ui(&mut self, ui: &mut egui::Ui, focused: bool) {
        egui::ScrollArea::vertical().id_salt(OPERATION_SELECTION_SCROLL_ID).show(ui, |ui| {
            ui.label("One namespace per OS-user installation. The root is derived from the authenticated OS account, ignoring HOME/XDG overrides. There is no alternate-root or reset input. New setup requires a blank witness ID and displays a backend-generated public identity before approval; importing an old standalone origin is unsupported.");
            field(ui, "Exact witness endpoint (IP:port)", &mut self.input.endpoint, 256);
            field(ui, "Exact TLS server name", &mut self.input.server_name, 253);
            field(ui, "Existing witness ID for enrollment; leave blank for NEW namespace setup", &mut self.input.witness_id, 128);
            field(ui, "Pinned witness server certificate digest", &mut self.input.pinned_server_certificate_digest, 64);
            field(ui, "Network profile", &mut self.input.network_profile_id, 128);
            field(ui, "Existing private 32-byte namespace storage-key FILE path", &mut self.input.storage_key_file, 4096);
            ui.label("The key file is read only by the private worker. Do not paste its contents. No key is generated or saved by this window.");
            ui.label("Independently chosen EXISTING OWNER PUBLIC certificate, DER as hex. Never paste a private key or seed.");
            ui.add(egui::TextEdit::multiline(&mut *self.input.owner_certificate_hex).desired_rows(3).char_limit(2 * MAX_CERTIFICATE_BYTES));
            if ui.button("Prepare exact permanent namespace setup review").clicked_by(egui::PointerButton::Primary) && focused {
                let result = self.input.setup_input().and_then(|input| launch_work(Work::PrepareSetup(input), NativeOwner::entered_window(), self.focus_epoch, ui.ctx()));
                self.accept_launch(result);
                return;
            }
            ui.separator();
            field(ui, "Expected account identity (independently chosen)", &mut self.input.expected_account_id, 64);
            ui.label("Exact signed pending-birth request envelope JSON (untrusted input)");
            ui.add(egui::TextEdit::multiline(&mut *self.input.signed_request_json).desired_rows(6).char_limit(crate::MAX_FRAME_BYTES));
            if ui.button("Open installed namespace and prepare exact enrollment / retry review")
                .clicked_by(egui::PointerButton::Primary) && focused {
                let result = (|| {
                    let input = self.input.enrollment_input()?;
                    if self.input.signed_request_json.is_empty() || self.input.signed_request_json.len() > crate::MAX_FRAME_BYTES {
                        return Err(AuthorityError::Limit);
                    }
                    let envelope = Zeroizing::new(std::mem::take(&mut *self.input.signed_request_json));
                    launch_work(Work::PrepareEnrollment { input, envelope }, NativeOwner::entered_window(), self.focus_epoch, ui.ctx())
                })();
                self.accept_launch(result);
                return;
            }
            ui.separator();
            ui.heading("Exact manual-enrollment extension");
            ui.label("Use the existing installed namespace and original account selected above. This distinct signed request adds only its exact reviewed manual enrollment reference under the original policy limits. It cannot replace policy, reset lifetime charges, revive retired accounts or restore automation. Writer bootstrap is separate.");
            ui.add(egui::TextEdit::multiline(&mut *self.input.signed_manual_extension_json).desired_rows(6).char_limit(crate::MAX_FRAME_BYTES));
            if ui.add_enabled(focused, egui::Button::new("Authenticate exact signed manual extension for review"))
                .clicked_by(egui::PointerButton::Primary) {
                let launched = (|| {
                    let input = self.input.enrollment_input()?;
                    if self.input.signed_manual_extension_json.is_empty()
                        || self.input.signed_manual_extension_json.len() > crate::MAX_FRAME_BYTES {
                        return Err(AuthorityError::Limit);
                    }
                    let envelope = Zeroizing::new(std::mem::take(&mut *self.input.signed_manual_extension_json));
                    launch_work(Work::PrepareManualExtension { input, envelope }, NativeOwner::entered_window(), self.focus_epoch, ui.ctx())
                })();
                self.accept_launch(launched);
                return;
            }
            ui.separator();
            ui.heading("Exact born offline enrollment");
            ui.label("This operation records one independently signed offline policy for the already-active original writer session. Enrollment alone cannot execute; separate native protected artifact import and a dedicated configured born runtime are required. Committing it makes older manual-only routes reject the resulting offline-bearing history. No new session, key, budget or mailbox is created. Review those consequences before proceeding; there is no renewal or undo action here.");
            ui.add(egui::TextEdit::multiline(&mut *self.input.signed_born_offline_enrollment_json).desired_rows(6).char_limit(crate::MAX_FRAME_BYTES));
            if ui.add_enabled(focused, egui::Button::new("Authenticate exact born offline enrollment for review"))
                .clicked_by(egui::PointerButton::Primary) {
                let launched = (|| {
                    let input = self.input.enrollment_input()?;
                    if self.input.signed_born_offline_enrollment_json.is_empty()
                        || self.input.signed_born_offline_enrollment_json.len() > crate::MAX_FRAME_BYTES { return Err(AuthorityError::Limit); }
                    let envelope = Zeroizing::new(std::mem::take(&mut *self.input.signed_born_offline_enrollment_json));
                    launch_work(Work::PrepareBornOfflineEnrollmentV1 { input, envelope }, NativeOwner::entered_window(), self.focus_epoch, ui.ctx())
                })();
                self.accept_launch(launched);
                return;
            }
            ui.separator();
            #[cfg(feature = "born-offline-witness-owner")]
            {
                ui.heading("Persistent born offline transport import");
                ui.label("Import only the existing protected witness HPKE key already pinned by the retained enrollment. This creates persistent local key and mailbox state inside the original encrypted journal. No new keys, namespace, budgets or mailbox files are created. Review and approve this separate persistent-access step only if intended; no signature or payment is authorized.");
                field(ui,"Existing protected witness HPKE key FILE path (never paste its contents)",&mut self.input.born_transport_key_file,4096);
                field(ui,"Original enrolled offline signer PUBLIC key (64 hex characters)",&mut self.input.born_signer_public_key_hex,64);
                if ui.add_enabled(focused,egui::Button::new("Review exact persistent transport import")).clicked_by(egui::PointerButton::Primary) {
                    let launched=(|| {
                        let input=self.input.enrollment_input()?;
                        if self.input.born_transport_key_file.len()>4096 || self.input.born_signer_public_key_hex.len()!=64 { return Err(AuthorityError::Limit); }
                        let key_file=std::mem::take(&mut self.input.born_transport_key_file);
                        let signer_hex=std::mem::take(&mut self.input.born_signer_public_key_hex);
                        launch_work(Work::PrepareBornOfflineArtifactsV1{input,key_file,signer_hex},NativeOwner::entered_window(),self.focus_epoch,ui.ctx())
                    })();
                    self.accept_launch(launched);
                    return;
                }
                ui.separator();
            }
            #[cfg(not(feature = "born-offline-witness-owner"))]
            ui.label("Born offline persistent transport import is unavailable in this build profile.");
            ui.heading("Exact attempted-session continuation");
            ui.label("Use the original installed namespace and exact retained enrollment. This signed continuation binds the full prior head, original immutable admission deadline and one public nonce. After the prior publication drains, it fences only the old bootstrap session and approves one successor attempt. Every original record and key stays retained; no financial authority is granted.");
            ui.add(egui::TextEdit::multiline(&mut *self.input.signed_manual_continuation_json).desired_rows(6).char_limit(crate::MAX_FRAME_BYTES));
            if ui.add_enabled(focused, egui::Button::new("Authenticate exact signed session continuation for review"))
                .clicked_by(egui::PointerButton::Primary) {
                let launched = (|| {
                    let input = self.input.enrollment_input()?;
                    if self.input.signed_manual_continuation_json.is_empty()
                        || self.input.signed_manual_continuation_json.len() > crate::MAX_FRAME_BYTES {
                        return Err(AuthorityError::Limit);
                    }
                    let envelope = Zeroizing::new(std::mem::take(&mut *self.input.signed_manual_continuation_json));
                    launch_work(Work::PrepareManualContinuation { input, envelope }, NativeOwner::entered_window(), self.focus_epoch, ui.ctx())
                })();
                self.accept_launch(launched);
                return;
            }
            ui.separator();
            ui.heading("Permanent stop of routine account reuse");
            ui.label("Unavailable pending attended installed-provider, native decision and kernel lifecycle qualification.");
            ui.label("Select the original installed namespace and existing owner certificate above. Authenticate the exact signer-retained tombstone. This closes future routine use without canceling any released authorization or reducing pending exposure. It cannot recover funds, prove an empty account or revoke a disclosed viewing key. Missing Host acknowledgments remain pending.");
            ui.add(egui::TextEdit::multiline(&mut *self.input.signed_permanent_exclusion_json).desired_rows(6).char_limit(crate::MAX_FRAME_BYTES));
            if ui.add_enabled(focused && crate::permanent_exclusion_owner::ACTIVATION_QUALIFIED_V1, egui::Button::new("Authenticate exact permanent exclusion for review")).clicked_by(egui::PointerButton::Primary) {
                let launched = (|| {
                    let input = self.input.enrollment_input()?;
                    if self.input.signed_permanent_exclusion_json.is_empty() || self.input.signed_permanent_exclusion_json.len() > crate::MAX_FRAME_BYTES { return Err(AuthorityError::Limit); }
                    let envelope = Zeroizing::new(std::mem::take(&mut *self.input.signed_permanent_exclusion_json));
                    launch_work(Work::PreparePermanentExclusionV1 { input, envelope }, NativeOwner::entered_window(), self.focus_epoch, ui.ctx())
                })();
                self.accept_launch(launched);
                return;
            }
            ui.separator();
            if durable_payment_v1::input_ui(self, ui, focused) { return; }
            if durable_delivery_admission_v2::input_ui(self, ui, focused) { return; }
            if financial_continuation_v1::input_ui(self, ui, focused) { return; }
            ui.heading("Exact V2 Host roster addition");
            ui.label("Use the existing installed namespace and original account selected above. This distinct V2 signed request binds the exact Host predecessor and ordered roster, the exact added born account and its immutable first enrollment under its original policy. The Host roster predecessor is separate from the account extension predecessor. It cannot replace policy, reset lifetime charges, revive retired accounts or restore automation. Writer bootstrap is separate.");
            ui.add(egui::TextEdit::multiline(&mut *self.input.signed_manual_roster_extension_json).desired_rows(6).char_limit(crate::MAX_FRAME_BYTES));
            if ui.add_enabled(focused, egui::Button::new("Authenticate signed V2 Host roster extension for review"))
                .clicked_by(egui::PointerButton::Primary) {
                let launched = (|| {
                    let input = self.input.enrollment_input()?;
                    if self.input.signed_manual_roster_extension_json.is_empty()
                        || self.input.signed_manual_roster_extension_json.len() > crate::MAX_FRAME_BYTES {
                        return Err(AuthorityError::Limit);
                    }
                    let envelope = Zeroizing::new(std::mem::take(&mut *self.input.signed_manual_roster_extension_json));
                    launch_work(Work::PrepareManualRosterExtensionV2 { input, envelope }, NativeOwner::entered_window(), self.focus_epoch, ui.ctx())
                })();
                self.accept_launch(launched);
                return;
            }
            ui.separator();
            ui.heading("Exact V2 Host roster session continuation");
            ui.label("Use the original installed namespace and exact retained enrollment. This signed continuation binds the full prior head, original immutable admission deadline and one public nonce. After the prior publication drains, it fences only the old bootstrap session and approves one successor attempt. Every original record and key stays retained; no financial authority is granted.");
            ui.add(egui::TextEdit::multiline(&mut *self.input.signed_manual_roster_continuation_json).desired_rows(6).char_limit(crate::MAX_FRAME_BYTES));
            if ui.add_enabled(focused, egui::Button::new("Authenticate signed V2 Host roster continuation for review"))
                .clicked_by(egui::PointerButton::Primary) {
                let launched = (|| {
                    let input = self.input.enrollment_input()?;
                    if self.input.signed_manual_roster_continuation_json.is_empty()
                        || self.input.signed_manual_roster_continuation_json.len() > crate::MAX_FRAME_BYTES {
                        return Err(AuthorityError::Limit);
                    }
                    let envelope = Zeroizing::new(std::mem::take(&mut *self.input.signed_manual_roster_continuation_json));
                    launch_work(Work::PrepareManualRosterContinuationV2 { input, envelope }, NativeOwner::entered_window(), self.focus_epoch, ui.ctx())
                })();
                self.accept_launch(launched);
                return;
            }
            ui.separator();
            ui.heading("Exact V2 non-signing construction plan");
            ui.label("Use the original installed account namespace. Independently review the full final proposal, actual selected inputs and return, complete participant retention commitments and original immutable deadline. This enables only exact non-signing Reserve/Consume after a separate fresh signer-native review. Reservations permanently retain conservative exposure here; consumption, expiry and cancellation never reset budget or refund it. No signing, proving or dispatch is approved.");
            ui.add(egui::TextEdit::multiline(&mut *self.input.signed_manual_roster_construction_json).desired_rows(6).char_limit(crate::MAX_FRAME_BYTES));
            if ui.add_enabled(focused, egui::Button::new("Authenticate signed V2 non-signing construction plan for review"))
                .clicked_by(egui::PointerButton::Primary) {
                let launched = (|| {
                    let input = self.input.enrollment_input()?;
                    if self.input.signed_manual_roster_construction_json.is_empty()
                        || self.input.signed_manual_roster_construction_json.len() > crate::MAX_FRAME_BYTES {
                        return Err(AuthorityError::Limit);
                    }
                    let envelope = Zeroizing::new(std::mem::take(&mut *self.input.signed_manual_roster_construction_json));
                    launch_work(Work::PrepareManualRosterConstructionV2 { input, envelope }, NativeOwner::entered_window(), self.focus_epoch, ui.ctx())
                })();
                self.accept_launch(launched);
                return;
            }
            ui.separator();
            ui.heading("Exact V3 non-signing construction plan");
            ui.label("SOURCE-STAGED, NOT ACTIVATED. Use the original installed account namespace. Original tips are historical; current usability remains unverified. The common target is maximum ORIGINAL tip plus one and the original anchor, expiry, inputs and minimum deadline stay unchanged. Exactly one additional-read wave and one final lock wave are permitted; no restart-to-build. Independently review the full final proposal, actual selected inputs and return, complete participant retention commitments and original immutable deadline. This enables only exact non-signing Reserve/Consume after a separate fresh signer-native review. Reservations permanently retain conservative exposure here; consumption, expiry and cancellation never reset budget or refund it. No signing, proving or dispatch is approved.");
            ui.add(egui::TextEdit::multiline(&mut *self.input.signed_manual_roster_construction_v3_json).desired_rows(6).char_limit(crate::MAX_FRAME_BYTES));
            if ui.add_enabled(focused && crate::COMMON_CONTEXT_V3_ACTIVATION_QUALIFIED, egui::Button::new("Authenticate signed V3 non-signing construction plan for review"))
                .clicked_by(egui::PointerButton::Primary) {
                self.prepare_manual_roster_construction_v3_from_primary(ui.ctx());
                return;
            }
            ui.separator();
            ui.heading("One-use construction transport handoff");
            ui.label("SOURCE-STAGED, NOT ACTIVATED. Review only after the original Host holds ALL real additional-read observations. This new signed admission grants nothing by itself. Your decision records one inert pending grant. A later fresh native original-owner decision must sign its exact committed post-grant head and fresh exporter. Its atomic claim permanently fences the old general transport key. Original session, attempt, account, read, proposal, expiry and accounting remain unchanged. Any intervening event or lost/uncertain attempt is terminal; no renewal or retry-to-authority.");
            ui.add(egui::TextEdit::multiline(&mut *self.input.signed_construction_transport_preauthorization_json)
                .desired_rows(6).char_limit(MAX_CONSTRUCTION_TRANSPORT_COMPONENT_BYTES));
            if ui.add_enabled(focused && crate::COMMON_CONTEXT_V3_ACTIVATION_QUALIFIED,
                egui::Button::new("Authenticate original-owner handoff admission for exact review"))
                .clicked_by(egui::PointerButton::Primary) {
                self.prepare_construction_transport_grant_v1_from_primary(ui.ctx());
                return;
            }
            ui.separator();
            ui.heading("Encrypted namespace backup");
            ui.label("Use the independently chosen installed namespace identity above. The exact review binds all retained locator, account-history and exclusion evidence to a new private package. No live namespace is restored or reactivated.");
            field(ui, "New private archive PACKAGE DIRECTORY (must not exist)", &mut self.input.destination_directory, 4096);
            field(ui, "Existing independent 32-byte archive-key FILE path", &mut self.input.destination_key_file, 4096);
            ui.label("Do not paste key contents. Keep the archive key separately; losing it makes this encrypted backup unreadable. Output is local only and will not be uploaded.");
            if ui.button("Prepare exact encrypted namespace backup review")
                .clicked_by(egui::PointerButton::Primary) && focused {
                let result = self.input.backup_input().and_then(|input|
                    launch_work(Work::PrepareBackup(input), NativeOwner::entered_window(), self.focus_epoch, ui.ctx()));
                self.accept_launch(result);
                return;
            }
            ui.separator();
            ui.heading("Private historical archive review");
            ui.label("Select a complete archive package and its key file. Preparation displays selected paths and disclosure categories only. Private metadata, inventory and account pages require a separate final native disclosure decision, followed by an explicit request for each page. This does not inspect or repair the fixed live namespace.");
            field(ui, "Existing historical archive PACKAGE DIRECTORY", &mut self.input.package_directory, 4096);
            field(ui, "Existing archive-key FILE path", &mut self.input.archive_key_file, 4096);
            field(ui, "Expected original namespace digest (optional exact match)", &mut self.input.expected_namespace_digest, 64);
            if ui.button("Prepare exact historical disclosure review")
                .clicked_by(egui::PointerButton::Primary) && focused {
                let result = self.input.recovery_input().and_then(|input|
                    launch_work(Work::PrepareRecovery(input), NativeOwner::entered_window(), self.focus_epoch, ui.ctx()));
                self.accept_launch(result);
            }
        });
    }
    fn historical_ui(&mut self, ui: &mut egui::Ui, focused: bool) {
        ui.heading("Revocable historical evidence");
        ui.label("Every returned value is historical data. Integrity does not establish freshness or grant writer, enrollment, signing, restoration or spending authority. Blur, Cancel, Close and the original review expiry clear this view. Reading another page never extends the review lifetime.");
        if ui
            .button("Close private history and clear views")
            .clicked_by(egui::PointerButton::Primary)
        {
            self.discard();
            self.message = "Historical disclosure was revoked. Waiting for the private reader to close before another operation.";
            return;
        }
        let historical = self.historical.as_ref().expect("selected historical UI");
        if historical.current(focused, self.focus_epoch).is_err() {
            ui.label("The disclosure lease is closed. Waiting for worker cleanup.");
            return;
        }
        if historical.busy {
            ui.spinner();
            ui.label(if historical.opened {
                "Reading the one requested bounded page."
            } else {
                "Authenticating the exact approved archive. No page was requested yet."
            });
        }
        let ready = historical.opened && !historical.busy;
        let mut request = None;
        ui.add_enabled_ui(ready, |ui| {
            if ui.button("Read historical namespace summary")
                .clicked_by(egui::PointerButton::Primary) {
                request = Some(HistoricalRequest::Summary);
            }
            ui.horizontal(|ui| {
                ui.label("Inventory first record (zero-based)");
                ui.add(egui::DragValue::new(&mut self.historical_input.first_record).range(0..=u32::MAX));
                ui.label("Maximum records");
                ui.add(egui::DragValue::new(&mut self.historical_input.record_limit).range(1..=16));
            });
            ui.label("Inventory pages retain original preparation/completion and permanent exclusion records. Use the returned next cursor to choose another page.");
            if ui.button("Read this bounded inventory page")
                .clicked_by(egui::PointerButton::Primary) && request.is_none() {
                request = Some(HistoricalRequest::Inventory {
                    first: self.historical_input.first_record, limit: self.historical_input.record_limit,
                });
            }
            field(ui, "Exact original intent digest from authenticated inventory", &mut self.historical_input.intent_digest, 64);
            if ui.button("Read this historical account summary")
                .clicked_by(egui::PointerButton::Primary) && request.is_none() {
                request = Some(HistoricalRequest::AccountSummary {
                    intent_digest: self.historical_input.intent_digest.to_string(),
                });
            }
            ui.horizontal(|ui| {
                ui.label("Account first event sequence");
                ui.add(egui::DragValue::new(&mut self.historical_input.first_sequence).range(1..=u64::MAX));
                ui.label("Maximum events");
                ui.add(egui::DragValue::new(&mut self.historical_input.event_limit).range(1..=32));
            });
            if ui.button("Read this bounded account-history page")
                .clicked_by(egui::PointerButton::Primary) && request.is_none() {
                request = Some(HistoricalRequest::AccountHistory {
                    intent_digest: self.historical_input.intent_digest.to_string(),
                    first_sequence: self.historical_input.first_sequence,
                    limit: self.historical_input.event_limit,
                });
            }
        });
        if let Some(request) = request {
            match self
                .historical
                .as_mut()
                .expect("selected historical UI")
                .request(request, focused, self.focus_epoch)
            {
                Ok(()) => {
                    self.historical_display.take();
                    self.message = "Reading the one explicitly selected historical page.";
                }
                Err(_) => {
                    self.message = "The requested historical cursor, digest or limits were rejected. No new page was requested."
                }
            }
        }
        if let Some((label, display)) = &self.historical_display {
            ui.separator();
            ui.label(*label);
            egui::ScrollArea::vertical()
                .max_height(360.0)
                .show(ui, |ui| {
                    // Plain escaped text only, never executable links or HTML.
                    ui.label(RichText::new(display.as_str()).monospace());
                });
        }
    }
    fn accept_launch(&mut self, result: Result<WorkerJob>) {
        self.input.discard_raw();
        self.confirmation.zeroize();
        self.understood = false;
        self.last_archive_receipt.take();
        match result {
            Ok(job) => self.job = Some(job),
            Err(_) => {
                self.message = "The selected independent inputs or worker launch were rejected. No review was retained."
            }
        }
    }
    fn review_ui(&mut self, ui: &mut egui::Ui, focused: bool) {
        let pending = self.pending.as_ref().expect("checked private state");
        let phase = pending.phase;
        let phrase = pending.phrase();
        egui::ScrollArea::vertical()
            .max_height(430.0)
            .show(ui, |ui| {
                // Complete backend-authenticated proposal: no HTML/links, omitted
                // signed values or floating-point monetary formatting.
                ui.label(RichText::new(pending.prepared.display.as_str()).monospace());
            });
        if ui
            .button("Cancel / change independent selection")
            .clicked_by(egui::PointerButton::Primary)
        {
            self.discard();
            self.message = "The previous exact review was discarded.";
            return;
        }
        if phase == Phase::Reading {
            if ui
                .button("Continue to exact native confirmation")
                .clicked_by(egui::PointerButton::Primary)
                && focused
            {
                if let Some(pending) = self.pending.as_mut() {
                    if pending.current(focused, self.focus_epoch).is_ok() {
                        pending.phase = Phase::Confirming;
                    } else {
                        self.discard();
                    }
                }
            }
            return;
        }
        ui.checkbox(&mut self.understood, "I reviewed this complete exact operation and its permanent consequences. I understand the existing owner signature does not attest fresh signer keys or native signer focus.");
        ui.label(format!(
            "Type {phrase}, then use the primary pointer button."
        ));
        ui.add(egui::TextEdit::singleline(&mut *self.confirmation).char_limit(40));
        let ready = self.understood && *self.confirmation == phrase && focused;
        if ui
            .add_enabled(
                ready,
                egui::Button::new("Authorize this exact one-time owner operation"),
            )
            .clicked_by(egui::PointerButton::Primary)
            && ready
        {
            let Some(pending) = self.pending.take() else {
                return;
            };
            if pending.current(focused, self.focus_epoch).is_err()
                || pending.phase != Phase::Confirming
            {
                self.pending = Some(pending);
                self.discard();
                return;
            }
            let PendingReview {
                prepared,
                owner,
                clock,
                ..
            } = pending;
            // This preserves the original review start/deadline; it carries no
            // authority and is never a renewed clock after disclosure or reads.
            let historical_clock = clock.clone();
            // Sole production FinalPrimaryClick construction. Keyboard activation,
            // flags, callbacks and deserialized approval claims cannot reach it.
            let click = FinalPrimaryClick {
                review_digest: prepared.digest.clone(),
                clock,
            };
            let lease = match owner.accept_final_click(click) {
                Ok(lease) => lease,
                Err(_) => {
                    self.discard();
                    self.discard_prepared(prepared, owner);
                    return;
                }
            };
            // These are the only production decision constructions, each coupled
            // to its backend-owned exact proposal. The GUI retains NativeOwner.
            let work = match prepared.proposal {
                Proposal::FinancialContinuationV1(prepared) => {
                    let financial_continuation_v1::PreparedNativeV1 { proposal, tls, listener } = *prepared;
                    Work::FinancialContinuationV1(financial_continuation_v1::WorkV1::Admit {
                        decision: NativeFinancialContinuationDecisionV1 { proposal, lease },
                        tls, listener, clock: historical_clock,
                    })
                }
                Proposal::DurableDeliveryV2(prepared) => {
                    let durable_delivery_admission_v2::PreparedNativeV2 {
                        proposal,
                        tls,
                        listener,
                    } = *prepared;
                    Work::DurableDeliveryV2(durable_delivery_admission_v2::WorkV2::Admit {
                        decision: NativeDurableDeliveryAdmissionDecisionV2 { proposal, lease },
                        tls,
                        listener,
                        clock: historical_clock,
                        #[cfg(feature = "synthetic-qualification")]
                        observer: self.admission_observer.clone(),
                    })
                }
                Proposal::DurablePaymentV1(prepared) => {
                    let durable_payment_v1::PreparedNativeV1 {
                        proposal,
                        tls,
                        listener,
                    } = *prepared;
                    Work::DurablePaymentV1(durable_payment_v1::WorkV1::Admit {
                        decision: NativeDurablePaymentAdmissionDecisionV1 { proposal, lease },
                        tls,
                        listener,
                        clock: historical_clock,
                        #[cfg(feature = "synthetic-qualification")]
                        observer: self.admission_observer.clone(),
                    })
                }
                Proposal::Setup(proposal) => Work::Install(Box::new(NativeSetupDecision {
                    proposal: *proposal,
                    lease,
                })),
                Proposal::Enrollment(proposal) => {
                    Work::Enroll(Box::new(NativeEnrollmentDecision {
                        proposal: *proposal,
                        lease,
                    }))
                }
                Proposal::PermanentExclusionV1(proposal) => Work::ExcludePermanentlyV1 {
                    decision: Box::new(NativePermanentExclusionDecisionV1 {
                        proposal: *proposal,
                        lease,
                    }),
                    clock: historical_clock,
                },
                Proposal::BornOfflineEnrollmentV1(proposal) => Work::EnrollBornOfflineV1 {
                    decision: Box::new(NativeBornOfflineEnrollmentDecisionV1 {
                        proposal: *proposal,
                        lease,
                    }),
                    clock: historical_clock,
                },
                #[cfg(feature = "born-offline-witness-owner")]
                Proposal::BornOfflineArtifactsV1(proposal) => Work::InstallBornOfflineArtifactsV1 {
                    decision: Box::new(NativeBornOfflineArtifactsDecisionV1 {
                        proposal: *proposal,
                        lease,
                    }),
                    clock: historical_clock,
                },
                Proposal::ManualExtension(proposal) => Work::ExtendManual {
                    decision: Box::new(NativeManualEnrollmentExtensionDecision {
                        proposal: *proposal,
                        lease,
                    }),
                    clock: historical_clock,
                },
                Proposal::ManualContinuation(proposal) => Work::ContinueManual {
                    decision: Box::new(NativeManualSessionContinuationDecision {
                        proposal: *proposal,
                        lease,
                    }),
                    clock: historical_clock,
                },
                Proposal::ManualRosterExtensionV2(proposal) => Work::ExtendManualRosterV2 {
                    decision: Box::new(NativeManualRosterExtensionDecisionV2 {
                        proposal: *proposal,
                        lease,
                    }),
                    clock: historical_clock,
                },
                Proposal::ManualRosterContinuationV2(proposal) => Work::ContinueManualRosterV2 {
                    decision: Box::new(NativeManualRosterContinuationDecisionV2 {
                        proposal: *proposal,
                        lease,
                    }),
                    clock: historical_clock,
                },
                Proposal::ConstructionTransportGrantV1(proposal) => {
                    Work::GrantConstructionTransportV1 {
                        decision: Box::new(NativeConstructionTransportGrantDecisionV1 {
                            proposal: *proposal,
                            lease,
                        }),
                        clock: historical_clock,
                    }
                }
                Proposal::ManualRosterConstructionV3(proposal) => {
                    Work::ApproveManualRosterConstructionV3 {
                        decision: Box::new(NativeManualRosterConstructionDecisionV3 {
                            proposal: *proposal,
                            lease,
                        }),
                        clock: historical_clock,
                    }
                }
                Proposal::ManualRosterConstructionV2(proposal) => {
                    Work::ApproveManualRosterConstructionV2 {
                        decision: Box::new(NativeManualRosterConstructionDecisionV2 {
                            proposal: *proposal,
                            lease,
                        }),
                        clock: historical_clock,
                    }
                }
                Proposal::Backup(proposal) => Work::Backup {
                    decision: Box::new(NativeNamespaceBackupDecision {
                        proposal: *proposal,
                        lease,
                    }),
                    clock: historical_clock,
                },
                Proposal::RecoveryDisclosure(proposal) => {
                    let decision = NativeNamespaceRecoveryDisclosureDecision {
                        proposal: *proposal,
                        lease,
                    };
                    let launched = launch_historical_work(
                        decision,
                        owner,
                        historical_clock,
                        self.focus_epoch,
                        ui.ctx(),
                    );
                    self.input.discard_raw();
                    self.confirmation.zeroize();
                    self.understood = false;
                    self.last_archive_receipt.take();
                    self.historical_display.take();
                    self.historical_input = HistoricalInputs::default();
                    match launched {
                        Ok(historical) => self.historical = Some(historical),
                        Err(_) => {
                            self.message = "The private historical worker could not start. No disclosure review remains."
                        }
                    }
                    return;
                }
            };
            let launched = launch_work(work, owner, self.focus_epoch, ui.ctx());
            self.accept_launch(launched);
        }
    }
}
impl Drop for Window {
    fn drop(&mut self) {
        self.discard();
    }
}
impl eframe::App for Window {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.draw(ui);
    }
}
fn focus_interrupted(previous: bool, current: bool, lost_in_batch: bool) -> bool {
    lost_in_batch || (previous && !current)
}
fn field(ui: &mut egui::Ui, label: &str, value: &mut String, maximum: usize) {
    ui.label(label);
    ui.add(egui::TextEdit::singleline(value).char_limit(maximum));
}
fn inert_text(value: &str) -> String {
    let mut safe = String::with_capacity(value.len());
    for c in value.chars() {
        if c == '\n' || c == ' ' || c.is_ascii_graphic() {
            safe.push(c);
        } else {
            safe.extend(c.escape_default());
        }
    }
    safe
}
pub(super) fn configure_style(ctx: &egui::Context) {
    let mut style = (*ctx.global_style()).clone();
    style.visuals = egui::Visuals::dark();
    style.visuals.override_text_color = Some(Color32::from_rgb(228, 236, 239));
    style.spacing.item_spacing = egui::vec2(10.0, 9.0);
    style.spacing.button_padding = egui::vec2(14.0, 10.0);
    ctx.set_global_style(style);
}

fn parse_permanent_exclusion_envelope_v1(
    bytes: &str,
) -> Result<PermanentExclusionOwnerSignatureV1> {
    if bytes.is_empty() || bytes.len() > crate::MAX_FRAME_BYTES {
        return Err(AuthorityError::Limit);
    }
    serde_json::from_str(bytes).map_err(|_| AuthorityError::InvalidBinding)
}

fn parse_born_offline_enrollment_envelope_v1(
    bytes: &str,
) -> Result<BornOfflineEnrollmentOwnerSignatureV1> {
    if bytes.is_empty() || bytes.len() > crate::MAX_FRAME_BYTES {
        return Err(AuthorityError::Limit);
    }
    serde_json::from_str(bytes).map_err(|_| AuthorityError::InvalidBinding)
}

fn parse_manual_extension_envelope(bytes: &str) -> Result<ManualEnrollmentExtensionOwnerSignature> {
    if bytes.is_empty() || bytes.len() > crate::MAX_FRAME_BYTES {
        return Err(AuthorityError::Limit);
    }
    serde_json::from_str(bytes).map_err(|_| AuthorityError::InvalidBinding)
}

fn parse_manual_continuation_envelope(
    bytes: &str,
) -> Result<ManualEnrollmentSessionContinuationOwnerSignature> {
    if bytes.is_empty() || bytes.len() > crate::MAX_FRAME_BYTES {
        return Err(AuthorityError::Limit);
    }
    serde_json::from_str(bytes).map_err(|_| AuthorityError::InvalidBinding)
}

fn parse_manual_roster_extension_envelope_v2(
    bytes: &str,
) -> Result<ManualRosterEnrollmentOwnerSignatureV2> {
    if bytes.is_empty() || bytes.len() > crate::MAX_FRAME_BYTES {
        return Err(AuthorityError::Limit);
    }
    serde_json::from_str(bytes).map_err(|_| AuthorityError::InvalidBinding)
}

fn parse_manual_roster_continuation_envelope_v2(
    bytes: &str,
) -> Result<ManualRosterContinuationOwnerSignatureV2> {
    if bytes.is_empty() || bytes.len() > crate::MAX_FRAME_BYTES {
        return Err(AuthorityError::Limit);
    }
    serde_json::from_str(bytes).map_err(|_| AuthorityError::InvalidBinding)
}

fn parse_construction_transport_preauthorization_v1(
    bytes: &str,
) -> Result<SignedConstructionTransportPreauthorizationV1> {
    if bytes.is_empty() || bytes.len() > MAX_CONSTRUCTION_TRANSPORT_COMPONENT_BYTES {
        return Err(AuthorityError::Limit);
    }
    let authorization: SignedConstructionTransportPreauthorizationV1 =
        serde_json::from_str(bytes).map_err(|_| AuthorityError::InvalidBinding)?;
    authorization.authorization.validate()?;
    Ok(authorization)
}

fn parse_manual_roster_construction_envelope_v3(
    bytes: &str,
) -> Result<ManualRosterConstructionOwnerSignatureV3> {
    if bytes.is_empty() || bytes.len() > crate::MAX_FRAME_BYTES {
        return Err(AuthorityError::Limit);
    }
    serde_json::from_str(bytes).map_err(|_| AuthorityError::InvalidBinding)
}

fn parse_manual_roster_construction_envelope_v2(
    bytes: &str,
) -> Result<ManualRosterConstructionOwnerSignatureV2> {
    if bytes.is_empty() || bytes.len() > crate::MAX_FRAME_BYTES {
        return Err(AuthorityError::Limit);
    }
    serde_json::from_str(bytes).map_err(|_| AuthorityError::InvalidBinding)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn born_offline_parser_is_bounded_inert_and_cancel_discards_private_input() {
        // The parser yields inert signature data, never a native decision. This
        // test does not create a focused click, original namespace or key use.
        let _: fn(&str) -> Result<BornOfflineEnrollmentOwnerSignatureV1> =
            parse_born_offline_enrollment_envelope_v1;
        for body in [
            "",
            "{}",
            r#"{"approved":true}"#,
            r#"{"native_decision":true}"#,
        ] {
            assert!(parse_born_offline_enrollment_envelope_v1(body).is_err());
        }
        assert!(
            parse_born_offline_enrollment_envelope_v1(&"x".repeat(crate::MAX_FRAME_BYTES + 1))
                .is_err()
        );
        let (birth, _, _, ledger) = crate::manual_enrollment::tests::bootstrap_events();
        let envelope = BornOfflineEnrollmentOwnerSignatureV1 {
            version: 1,
            enrollment: crate::born_offline_enrollment_v1::tests::record(&ledger, &birth)
                .enrollment,
            scheme: "ecdsa-p256-sha256-asn1-v1".into(),
            owner_certificate_der: vec![0],
            signature: vec![0],
        };
        let serialized = serde_json::to_string(&envelope).unwrap();
        let parsed = parse_born_offline_enrollment_envelope_v1(&serialized).unwrap();
        assert!(
            verify_born_offline_enrollment_v1_owner_signature(
                &parsed,
                &birth.request.policy.owner_certificate_digest
            )
            .is_err()
        );
        let mut with_flag = serde_json::to_value(&envelope).unwrap();
        with_flag["approved"] = serde_json::json!(true);
        assert!(
            parse_born_offline_enrollment_envelope_v1(&serde_json::to_string(&with_flag).unwrap())
                .is_err()
        );
        let mut window = Window::new();
        *window.input.signed_born_offline_enrollment_json = serialized;
        window.discard();
        assert!(window.input.signed_born_offline_enrollment_json.is_empty());
        assert!(window.pending.is_none());
        assert!(window.job.is_none());
    }

    #[test]
    fn handoff_parser_never_accepts_native_or_host_completion_flags() {
        for body in [
            "{}",
            r#"{"approved":true}"#,
            r#"{"all_observations_complete":true}"#,
            r#"{"native_decision":true}"#,
        ] {
            assert!(parse_construction_transport_preauthorization_v1(body).is_err());
        }
        let mut input = NativeInputs::default();
        *input.signed_construction_transport_preauthorization_json =
            "synthetic-private-admission".into();
        input.discard_raw();
        assert!(
            input
                .signed_construction_transport_preauthorization_json
                .is_empty()
        );
    }
    #[test]
    fn construction_owner_parser_rejects_approval_flags_and_discards_raw_input() {
        for body in ["{}", r#"{"approved":true}"#, r#"{"native_decision":true}"#] {
            assert!(parse_manual_roster_construction_envelope_v2(body).is_err());
        }
        assert!(
            parse_manual_roster_construction_envelope_v2(&"x".repeat(crate::MAX_FRAME_BYTES + 1))
                .is_err()
        );
        let mut input = NativeInputs::default();
        *input.signed_manual_roster_construction_json = "synthetic inert construction".into();
        input.discard_raw();
        assert!(input.signed_manual_roster_construction_json.is_empty());
    }

    #[test]
    fn roster_v2_parsers_are_bounded_inert_and_discard_private_inputs() {
        for body in ["{}", "{\"approved\":true}", "{\"native_decision\":true}"] {
            assert!(parse_manual_roster_extension_envelope_v2(body).is_err());
            assert!(parse_manual_roster_continuation_envelope_v2(body).is_err());
        }
        assert!(
            parse_manual_roster_extension_envelope_v2(&"x".repeat(crate::MAX_FRAME_BYTES + 1))
                .is_err()
        );
        assert!(
            parse_manual_roster_continuation_envelope_v2(&"x".repeat(crate::MAX_FRAME_BYTES + 1))
                .is_err()
        );
        let _: fn(&str) -> Result<ManualRosterEnrollmentOwnerSignatureV2> =
            parse_manual_roster_extension_envelope_v2;
        let _: fn(&str) -> Result<ManualRosterContinuationOwnerSignatureV2> =
            parse_manual_roster_continuation_envelope_v2;
        let mut input = NativeInputs::default();
        *input.signed_manual_roster_extension_json = "synthetic inert V2 extension".into();
        *input.signed_manual_roster_continuation_json = "synthetic inert V2 continuation".into();
        input.discard_raw();
        assert!(input.signed_manual_roster_extension_json.is_empty());
        assert!(input.signed_manual_roster_continuation_json.is_empty());
    }

    #[test]
    fn manual_extension_route_rejects_flags_wrong_format_and_oversized_input() {
        for bytes in [
            "{}",
            r#"{"approved":true}"#,
            r#"{"request":{},"signature":"00"}"#,
        ] {
            assert!(parse_manual_extension_envelope(bytes).is_err());
        }
        assert!(parse_manual_extension_envelope(&"x".repeat(crate::MAX_FRAME_BYTES + 1)).is_err());
    }
    #[test]
    fn manual_extension_parser_cannot_create_a_native_decision() {
        // The data parser does not return a native capability even for a future
        // well-formed envelope. Neither input flags nor a detached signature can
        // manufacture the private final-click value required by this window.
        let _: fn(&str) -> Result<ManualEnrollmentExtensionOwnerSignature> =
            parse_manual_extension_envelope;
        let mut input = NativeInputs::default();
        *input.signed_manual_extension_json = "private exact intent".into();
        input.discard_raw();
        assert!(input.signed_manual_extension_json.is_empty());
    }
    #[test]
    fn manual_continuation_route_rejects_flags_wrong_format_and_oversized_input() {
        for bytes in [
            "{}",
            r#"{"approved":true}"#,
            r#"{"request":{},"signature":"00"}"#,
        ] {
            assert!(parse_manual_continuation_envelope(bytes).is_err());
        }
        assert!(
            parse_manual_continuation_envelope(&"x".repeat(crate::MAX_FRAME_BYTES + 1)).is_err()
        );
    }
    #[test]
    fn manual_continuation_parser_cannot_create_a_native_decision() {
        // The data parser does not return a native capability even for a future
        // well-formed envelope. Neither input flags nor a detached signature can
        // manufacture the private final-click value required by this window.
        let _: fn(&str) -> Result<ManualEnrollmentSessionContinuationOwnerSignature> =
            parse_manual_continuation_envelope;
        let mut input = NativeInputs::default();
        *input.signed_manual_continuation_json = "private exact intent".into();
        input.discard_raw();
        assert!(input.signed_manual_continuation_json.is_empty());
    }
    #[test]
    fn batched_blur_refocus_still_invalidates() {
        assert!(focus_interrupted(true, true, true));
        assert!(focus_interrupted(false, true, true));
        assert!(focus_interrupted(true, false, false));
        assert!(!focus_interrupted(true, true, false));
    }
    #[test]
    fn cancel_clears_sensitive_input_without_creating_a_decision() {
        let mut window = Window::new();
        *window.input.owner_certificate_hex = "synthetic-public-certificate".into();
        *window.input.signed_request_json = "synthetic-request".into();
        *window.input.signed_manual_extension_json = "synthetic-extension".into();
        *window.input.signed_manual_continuation_json = "synthetic-continuation".into();
        *window.input.signed_manual_roster_extension_json = "synthetic-roster-extension".into();
        *window.input.signed_manual_roster_continuation_json =
            "synthetic-roster-continuation".into();
        *window.confirmation = "AUTHORIZE synthetic".into();
        window.understood = true;
        window.discard();
        assert!(window.pending.is_none());
        assert!(window.job.is_none());
        assert!(window.input.owner_certificate_hex.is_empty());
        assert!(window.input.signed_request_json.is_empty());
        assert!(window.input.signed_manual_extension_json.is_empty());
        assert!(window.input.signed_manual_continuation_json.is_empty());
        assert!(window.input.signed_manual_roster_extension_json.is_empty());
        assert!(
            window
                .input
                .signed_manual_roster_continuation_json
                .is_empty()
        );
        assert!(window.confirmation.is_empty());
        assert!(!window.understood);
    }
    #[test]
    fn malformed_independent_certificate_never_produces_setup_input() {
        let mut input = NativeInputs::default();
        assert!(input.setup_input().is_err());
        *input.owner_certificate_hex = "00".into();
        assert!(input.setup_input().is_err());
        *input.owner_certificate_hex = "g0".into();
        assert!(input.setup_input().is_err());
    }
    #[test]
    fn setup_refuses_an_existing_origin_before_certificate_or_storage_access() {
        let input = NativeInputs {
            witness_id: "existing-standalone-witness".into(),
            ..NativeInputs::default()
        };
        assert!(matches!(input.setup_input(), Err(AuthorityError::Conflict)));
    }
    #[test]
    fn native_input_lengths_are_bounded_before_worker_handoff() {
        let mut input = NativeInputs {
            storage_key_file: "a".repeat(4097),
            ..NativeInputs::default()
        };
        assert!(input.check_lengths().is_err());
        input.storage_key_file.clear();
        input.expected_account_id = "a".repeat(65);
        assert!(input.check_lengths().is_err());
    }
    #[test]
    fn historical_inputs_are_independent_and_bounded_without_opening_files() {
        let mut input = NativeInputs {
            package_directory: "/synthetic/no-files-opened/archive".into(),
            archive_key_file: "/synthetic/no-files-opened/key".into(),
            ..NativeInputs::default()
        };
        let recovery = input.recovery_input().unwrap();
        assert!(recovery.expected_namespace_digest.is_none());
        input.expected_namespace_digest = "g".repeat(64);
        assert!(input.recovery_input().is_err());
        input.expected_namespace_digest = "a".repeat(64);
        assert!(input.recovery_input().is_ok());
        input.archive_key_file = "a".repeat(4097);
        assert!(input.recovery_input().is_err());
    }
    #[test]
    fn historical_page_requests_cannot_exceed_finite_bounds() {
        assert!(
            HistoricalRequest::Inventory {
                first: 0,
                limit: 16
            }
            .validate()
            .is_ok()
        );
        for limit in [0, 17, u32::MAX] {
            assert!(
                HistoricalRequest::Inventory { first: 0, limit }
                    .validate()
                    .is_err()
            );
        }
        let digest = "a".repeat(64);
        assert!(
            HistoricalRequest::AccountHistory {
                intent_digest: digest.clone(),
                first_sequence: 1,
                limit: 32,
            }
            .validate()
            .is_ok()
        );
        assert!(
            HistoricalRequest::AccountHistory {
                intent_digest: digest,
                first_sequence: 0,
                limit: 32,
            }
            .validate()
            .is_err()
        );
        assert!(
            HistoricalRequest::AccountSummary {
                intent_digest: "untrusted".into()
            }
            .validate()
            .is_err()
        );
    }
    #[test]
    fn private_display_is_bounded_and_escapes_untrusted_controls() {
        let display =
            private_display(&serde_json::json!({"history": "text\u{202e}\u{1b}\t"})).unwrap();
        assert!(!display.contains('\u{202e}'));
        assert!(!display.contains('\u{1b}'));
        assert!(!display.contains('\t'));
        assert!(private_display(&"x".repeat(MAX_HISTORICAL_DISPLAY_BYTES + 1)).is_err());
    }
    #[test]
    fn cancellation_discards_delayed_historical_text_and_closes_read_channel() {
        // State/queue model only: no real archive, native decision or reader.
        let (commands, _requests) = mpsc::sync_channel(1);
        let (send, receiver) = mpsc::sync_channel(1);
        let mut window = Window::new();
        window.historical = Some(HistoricalWorker {
            owner: NativeOwner::entered_window(),
            clock: ReviewClock::start(None).unwrap(),
            epoch: window.focus_epoch,
            commands: Some(commands),
            receiver,
            thread: None,
            opened: true,
            busy: true,
            terminal: false,
        });
        window.historical_display =
            Some(("old view", Zeroizing::new("synthetic private page".into())));
        *window.historical_input.intent_digest = "a".repeat(64);
        window.input.package_directory = "/synthetic/private-path".into();
        assert!(
            send.send(Ok(HistoricalOutput::Page {
                label: "delayed view",
                display: Zeroizing::new("synthetic delayed private page".into()),
            }))
            .is_ok()
        );
        window.discard();
        window.poll_historical(&egui::Context::default(), true);
        assert!(window.historical_display.is_none());
        assert!(window.historical_input.intent_digest.is_empty());
        assert!(window.input.package_directory.is_empty());
        let historical = window.historical.as_mut().unwrap();
        assert!(historical.commands.is_none());
        assert!(!historical.owner.is_open());
        assert!(
            historical
                .request(HistoricalRequest::Summary, true, window.focus_epoch)
                .is_err()
        );
    }
    #[test]
    fn a_blocked_worker_does_not_block_gui_revocation_or_accept_another_job() {
        let (release, wait) = mpsc::sync_channel::<()>(1);
        let (send, receiver) = mpsc::sync_channel(1);
        let thread = std::thread::spawn(move || {
            wait.recv().unwrap();
            assert!(send.send(Err(AuthorityError::Permission)).is_ok());
        });
        let mut job = WorkerJob {
            owner: NativeOwner::entered_window(),
            epoch: 1,
            receiver,
            thread: Some(thread),
            received: None,
            cleanup: false,
            #[cfg(feature = "synthetic-qualification")]
            admission_observer: None,
        };
        assert!(job.poll().is_none());
        job.owner.revoke();
        assert!(!job.owner.is_open());
        assert!(job.poll().is_none());
        release.send(()).unwrap();
        let start = std::time::Instant::now();
        loop {
            if let Some(outcome) = job.poll() {
                assert!(matches!(outcome, Err(AuthorityError::Permission)));
                break;
            }
            assert!(start.elapsed() < Duration::from_secs(5));
            std::thread::yield_now();
        }
        // No proposal, genuine click, worker capability or publication is minted.
    }
    #[test]
    fn display_escapes_controls_and_bidi() {
        assert_eq!(inert_text("100\nabc"), "100\nabc");
        let safe = inert_text("amount\u{202e}0001\t\u{1b}");
        assert!(!safe.contains('\u{202e}'));
        assert!(!safe.contains('\t'));
        assert!(!safe.contains('\u{1b}'));
    }
    #[test]
    fn finite_cleanup_job_blocks_selection_until_the_worker_has_finished() {
        // Queue/lifetime model only: no opaque proposal, key, native decision,
        // real archive or cleanup filesystem operation is constructed here.
        let (release, wait) = mpsc::sync_channel::<()>(1);
        let (send, receiver) = mpsc::sync_channel(1);
        let thread = std::thread::spawn(move || {
            wait.recv().unwrap();
            assert!(send.send(Ok(WorkResult::Discarded)).is_ok());
        });
        let mut window = Window::new();
        let owner = NativeOwner::entered_window();
        owner.revoke();
        window.job = Some(WorkerJob {
            owner,
            epoch: window.focus_epoch,
            receiver,
            thread: Some(thread),
            received: None,
            cleanup: true,
            #[cfg(feature = "synthetic-qualification")]
            admission_observer: None,
        });
        assert!(!window.can_select());
        window.discard();
        assert!(!window.can_select());
        assert!(!window.job.as_ref().unwrap().owner.is_open());
        release.send(()).unwrap();
        let context = egui::Context::default();
        let started = std::time::Instant::now();
        while window.job.is_some() {
            window.poll_job(&context, true);
            assert!(started.elapsed() < Duration::from_secs(5));
            std::thread::yield_now();
        }
        assert!(window.can_select());
        window.disposal_failed = true;
        assert!(!window.can_select());
    }
}

#[cfg(all(test, feature = "born-offline-witness-owner"))]
mod born_artifact_input_tests {
    use super::*;
    #[test]
    fn discard_clears_persistent_import_inputs_without_creating_a_decision() {
        let mut inputs = NativeInputs {
            born_transport_key_file: "/synthetic/never-read.key".into(),
            born_signer_public_key_hex: "7".repeat(64),
            ..NativeInputs::default()
        };
        inputs.discard_raw();
        assert!(inputs.born_transport_key_file.is_empty());
        assert!(inputs.born_signer_public_key_hex.is_empty());
    }
}
