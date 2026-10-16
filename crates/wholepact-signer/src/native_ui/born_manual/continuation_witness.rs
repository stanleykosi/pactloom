//! V2 admission keeps the exact continuation/request across uncertain retries.
use super::super::{
    NativeAuthorityBinding, NativeDecision, PendingAccountNativeAuthority,
    witness_workspace::NativeWitnessWorkspace,
};
use crate::{
    Error, Result,
    account::birth::enrollment::{PreparedBornManualPublication, attempts::RetainedContinuation},
};
use std::sync::Arc;
use wholepact_authority::manual_session_continuation::BornManualEnrollmentAdmissionRequestV2;
use zeroize::Zeroizing;
/// Frozen complete-history request prepared BEFORE any remote durable admission.
pub(super) struct PreparedContinuedAdmission {
    retained: RetainedContinuation,
    workspace: Arc<NativeWitnessWorkspace>,
    peer: crate::ipc::AuthenticatedPeer,
    history: wholepact_authority::ReconciledAuthorityHistory,
    request: BornManualEnrollmentAdmissionRequestV2,
    source: NativeAuthorityBinding,
    digest: String,
    display: Zeroizing<String>,
}
pub(super) struct ApprovedContinuedAdmission(PreparedContinuedAdmission);
impl PreparedContinuedAdmission {
    pub(super) fn prepare(
        retained: RetainedContinuation,
        workspace: Arc<NativeWitnessWorkspace>,
        pairing: &crate::native_ui::AuthenticatedPairing,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<Self> {
        retained.check(owner)?;
        workspace.check_current()?;
        pairing.check_current()?;
        if workspace.disclosure() != retained.retained.disclosure()?
            || pairing.native_origin() != &owner.native().binding()
        {
            return Err(Error::ReviewMismatch);
        }
        let history = workspace
            .client()
            .reconcile_history_checked(|| {
                owner
                    .check_current()
                    .map_err(|_| wholepact_authority::AuthorityError::Permission)
            })
            .map_err(|_| Error::Uncertain)?;
        let active = workspace
            .client()
            .verify_active_session(&history)
            .map_err(|_| Error::Authentication)?;
        let extension = retained.retained.record().extension()?;
        if history
            .manual_enrollment_extension(&extension.enrollment_ref)
            .map_err(|_| Error::ReviewMismatch)?
            != Some(&extension)
        {
            return Err(Error::ReviewMismatch);
        }
        let request = BornManualEnrollmentAdmissionRequestV2 {
            version: 2,
            operation_id: retained
                .proposal
                .continuation
                .admission_operation_id(&extension)
                .map_err(|_| Error::InvalidData)?,
            account_id: history.snapshot().account_id.clone(),
            network_profile_id: history.snapshot().network_profile_id.clone(),
            extension_digest: extension.digest().map_err(|_| Error::InvalidData)?,
            enrollment_ref: retained.retained.record().reference()?,
            writer_epoch: history.snapshot().writer_epoch,
            expected_head: history.snapshot().head.clone(),
            session_id: active.receipt().session_id.clone(),
            attempt_digest: retained
                .proposal
                .continuation
                .digest_for(&extension)
                .map_err(|_| Error::InvalidData)?,
            attempt_sequence: retained.proposal.continuation.sequence,
        };
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-born-manual-witness-admission:v2",
            &(
                &request,
                &extension,
                pairing.binding(),
                owner.native().principal_id(),
                owner.native().measurement(),
            ),
        )
        .map_err(|_| Error::InvalidData)?;
        let display = Zeroizing::new(format!(
            "ADMIT ONE EXACT LOCAL MANUAL JOURNAL PUBLICATION AT THE ORIGINAL WITNESS\n\n{}\n\n{}\n\nThis appends the exact publication admission to independent witness history. It grants no transaction signing or financial permission. The request/head/session and operation below are frozen before first send. Only this same in-process request may retry after uncertainty; process loss/expiry does not authorize a new request. A later separate native review still controls local journal publication.\nExact review: {}",
            serde_json::to_string_pretty(&request).map_err(|_| Error::InvalidData)?,
            serde_json::to_string_pretty(&extension).map_err(|_| Error::InvalidData)?,
            digest
        ));
        Ok(Self {
            retained,
            workspace,
            peer: pairing.current_peer(),
            history,
            request,
            source: owner.native().binding(),
            digest,
            display,
        })
    }
    pub(super) fn digest(&self) -> &str {
        &self.digest
    }
    pub(super) fn display(&self) -> Result<String> {
        self.source.check_current()?;
        self.peer.check_current()?;
        Ok(self.display.to_string())
    }
    pub(super) fn approve(
        self,
        decision: NativeDecision,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<ApprovedContinuedAdmission> {
        self.retained.check(owner)?;
        self.source.check_current()?;
        self.peer.check_current()?;
        if self.source != owner.native().binding()
            || decision.binding() != &self.source
            || decision.reviewed_digest() != self.digest
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(ApprovedContinuedAdmission(self))
    }
}
impl ApprovedContinuedAdmission {
    pub(super) fn attempt(
        &self,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<PreparedBornManualPublication> {
        let p = &self.0;
        p.retained.check(owner)?;
        p.source.check_current()?;
        p.peer.check_current()?;
        p.workspace.check_current()?;
        if p.source != owner.native().binding() {
            return Err(Error::ReviewMismatch);
        }
        let extension = p.retained.retained.record().extension()?;
        let proof = p
            .workspace
            .client()
            .admit_born_manual_enrollment_v2(
                &p.history,
                &extension,
                &p.retained.proposal.continuation,
                &p.request,
            )
            .map_err(|_| Error::Uncertain)?;
        // Durable admission changes the head. Refresh COMPLETE history rather
        // than combining pre-admission history with the post-admission proof.
        let history = p
            .workspace
            .client()
            .reconcile_history_checked(|| {
                owner
                    .check_current()
                    .map_err(|_| wholepact_authority::AuthorityError::Permission)
            })
            .map_err(|_| Error::Uncertain)?;
        if history.snapshot() != proof.snapshot() {
            return Err(Error::ReviewMismatch);
        }
        let retained = p.retained.retained.reopen_exact(owner)?;
        let pairing =
            crate::native_ui::AuthenticatedPairing::from_authenticated_request(p.peer.clone())?;
        retained.prepare_publication_v2(history, proof, &pairing, owner)
    }
}
