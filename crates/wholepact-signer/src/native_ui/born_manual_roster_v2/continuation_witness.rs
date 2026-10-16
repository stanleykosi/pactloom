//! STAGED, UNCOMPILED. Roster V2 admission freezes the exact continuation,
//! complete V2 Host publication request and witness mutation for uncertain retry.
use super::super::{
    NativeAuthorityBinding, NativeDecision, PendingAccountNativeAuthority,
    witness_workspace::NativeWitnessWorkspace,
};
use super::witness::require_publication_pairing;
use crate::{
    Error, Result,
    account::birth::enrollment::roster_v2::{
        continuation::{self, RetainedContinuation},
        publication::PreparedBornManualRosterPublicationV2,
    },
};
use std::sync::Arc;
use wholepact_authority::manual_roster_witness_v2::BornManualRosterAdmissionRequestV2;
use wholepact_signer_origin::manual_roster_v2::{
    HostManualRosterPublicationRequestV2, ManualRosterPublicationAttemptV2,
};
use zeroize::Zeroizing;

pub(super) struct PreparedContinuedAdmission {
    retained: RetainedContinuation,
    workspace: Arc<NativeWitnessWorkspace>,
    peer: crate::ipc::AuthenticatedPeer,
    history: wholepact_authority::ReconciledAuthorityHistory,
    request: BornManualRosterAdmissionRequestV2,
    publication_request: HostManualRosterPublicationRequestV2,
    source: NativeAuthorityBinding,
    digest: String,
    display: Zeroizing<String>,
}
pub(super) struct ApprovedContinuedAdmission(PreparedContinuedAdmission);

fn require_acquired_continuation(
    retained: &RetainedContinuation,
    owner: &PendingAccountNativeAuthority,
) -> Result<()> {
    retained.check(owner)?;
    continuation::require_attempted_source(&retained.retained, owner)?;
    let own = continuation::load(&retained.retained)?
        .into_iter()
        .find(|entry| entry.proposal == retained.proposal)
        .ok_or(Error::RecoveryRequired)?;
    // The actual continuation owner must have retained its verified signature
    // and irreversible, independently reviewed acquire marker before this send.
    if own.signature.is_none() || own.acquire.is_none() {
        return Err(Error::RecoveryRequired);
    }
    Ok(())
}
impl PreparedContinuedAdmission {
    pub(super) fn prepare(
        retained: RetainedContinuation,
        workspace: Arc<NativeWitnessWorkspace>,
        publication_request: HostManualRosterPublicationRequestV2,
        pairing: &crate::native_ui::AuthenticatedPairing,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<Self> {
        require_publication_pairing(&retained.retained, &publication_request, pairing, owner)?;
        require_acquired_continuation(&retained, owner)?;
        workspace.check_native_source(&owner.native().binding())?;
        let extension = retained.retained.record().extension()?;
        let continuation = &retained.proposal.continuation;
        let attempt_digest = continuation
            .digest_for(&extension)
            .map_err(|_| Error::InvalidData)?;
        let expected_attempt = ManualRosterPublicationAttemptV2::ContinuationV2 {
            continuation_digest: attempt_digest.clone(),
            attempt_sequence: continuation.sequence(),
        };
        if workspace.disclosure() != retained.retained.disclosure()?
            || workspace.writer_certificate_digest()
                != retained
                    .retained
                    .record()
                    .account_record
                    .terms
                    .signer
                    .writer_certificate_digest
            || publication_request.attempt != expected_attempt
        {
            return Err(Error::ReviewMismatch);
        }
        let history = workspace
            .client()
            .reconcile_history_checked(|| {
                require_publication_pairing(
                    &retained.retained,
                    &publication_request,
                    pairing,
                    owner,
                )
                .and_then(|()| workspace.check_native_source(&owner.native().binding()))
                .map_err(|_| wholepact_authority::AuthorityError::Permission)
            })
            .map_err(|_| Error::Uncertain)?;
        let active = workspace
            .client()
            .verify_active_session(&history)
            .map_err(|_| Error::Authentication)?;
        let observed = history
            .latest_manual_roster_attempt_v2(&extension.account_extension.enrollment_ref)
            .map_err(|_| Error::ReviewMismatch)?;
        if history
            .manual_roster_enrollment_extension(&extension.account_extension.enrollment_ref)
            .map_err(|_| Error::ReviewMismatch)?
            != Some(&extension)
            || observed.continuation.as_ref() != Some(continuation)
            || observed.sequence != continuation.sequence()
            || observed.attempt_digest != attempt_digest
            || observed.admission.is_some()
        {
            return Err(Error::ReviewMismatch);
        }
        let request = BornManualRosterAdmissionRequestV2 {
            version: 2,
            operation_id: continuation
                .admission_operation_id(&extension)
                .map_err(|_| Error::InvalidData)?,
            account_id: history.snapshot().account_id.clone(),
            network_profile_id: history.snapshot().network_profile_id.clone(),
            extension_digest: extension.digest().map_err(|_| Error::InvalidData)?,
            enrollment_ref: extension.account_extension.enrollment_ref.clone(),
            writer_epoch: history.snapshot().writer_epoch,
            expected_head: history.snapshot().head.clone(),
            session_id: active.receipt().session_id.clone(),
            attempt_digest,
            attempt_sequence: continuation.sequence(),
        };
        request
            .validate_for(&extension, Some(continuation))
            .map_err(|_| Error::ReviewMismatch)?;
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-born-manual-roster-continued-witness-admission:v2",
            &(
                &request,
                &publication_request,
                &extension,
                continuation,
                history.history_digest().map_err(|_| Error::InvalidData)?,
                pairing.binding(),
                owner.native().principal_id(),
                owner.native().measurement(),
            ),
        )
        .map_err(|_| Error::InvalidData)?;
        let display = Zeroizing::new(format!(
            "ADMIT ONE EXACT ROSTER V2 CONTINUED LOCAL JOURNAL PUBLICATION\n\nHost publication request:\n{}\n\nFrozen witness admission:\n{}\n\nOriginal roster extension:\n{}\n\nExact retained continuation:\n{}\n\nThis appends one exact publication admission at the immutable original witness, preserving the original account, policy, budget and exposure. It grants no financial permission. The full V2 Host request, roster extension, continuation, witness head, session and operation are frozen before first send. Only this same in-process request may retry after uncertainty; no original deadline is renewed. Host roster ancestry is separate from this account's witness-attempt sequence. A later separate native review controls local journal publication.\nExact review: {}",
            serde_json::to_string_pretty(&publication_request).map_err(|_| Error::InvalidData)?,
            serde_json::to_string_pretty(&request).map_err(|_| Error::InvalidData)?,
            serde_json::to_string_pretty(&extension).map_err(|_| Error::InvalidData)?,
            serde_json::to_string_pretty(continuation).map_err(|_| Error::InvalidData)?,
            digest
        ));
        require_publication_pairing(&retained.retained, &publication_request, pairing, owner)?;
        Ok(Self {
            retained,
            workspace,
            peer: pairing.current_peer(),
            history,
            request,
            publication_request,
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
        self.workspace.check_native_source(&self.source)?;
        Ok(self.display.to_string())
    }
    fn check(&self, owner: &PendingAccountNativeAuthority) -> Result<()> {
        self.source.check_current()?;
        self.peer.check_current()?;
        self.workspace.check_native_source(&self.source)?;
        if self.source != owner.native().binding() {
            return Err(Error::ReviewMismatch);
        }
        let pairing =
            crate::native_ui::AuthenticatedPairing::from_authenticated_request(self.peer.clone())?;
        require_publication_pairing(
            &self.retained.retained,
            &self.publication_request,
            &pairing,
            owner,
        )?;
        require_acquired_continuation(&self.retained, owner)?;
        self.request
            .validate_for(
                &self.retained.retained.record().extension()?,
                Some(&self.retained.proposal.continuation),
            )
            .map_err(|_| Error::ReviewMismatch)
    }
    pub(super) fn approve(
        self,
        decision: NativeDecision,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<ApprovedContinuedAdmission> {
        self.check(owner)?;
        if decision.binding() != &self.source || decision.reviewed_digest() != self.digest {
            return Err(Error::ReviewMismatch);
        }
        Ok(ApprovedContinuedAdmission(self))
    }
}
impl ApprovedContinuedAdmission {
    pub(super) fn attempt(
        &self,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<PreparedBornManualRosterPublicationV2> {
        let p = &self.0;
        p.check(owner)?;
        let extension = p.retained.retained.record().extension()?;
        let proof = p
            .workspace
            .client()
            .admit_born_manual_roster_enrollment_v2(
                &p.history,
                &extension,
                Some(&p.retained.proposal.continuation),
                &p.request,
            )
            .map_err(|_| Error::Uncertain)?;
        // Refresh the full authenticated history after the durable mutation;
        // never combine a post-admission proof with a pre-admission snapshot.
        let history = p
            .workspace
            .client()
            .reconcile_history_checked(|| {
                p.check(owner)
                    .map_err(|_| wholepact_authority::AuthorityError::Permission)
            })
            .map_err(|_| Error::Uncertain)?;
        p.check(owner)?;
        proof.check_current().map_err(|_| Error::ReviewMismatch)?;
        if history.snapshot() != proof.snapshot() {
            return Err(Error::ReviewMismatch);
        }
        let retained = p.retained.retained.reopen_exact(owner)?;
        let pairing =
            crate::native_ui::AuthenticatedPairing::from_authenticated_request(p.peer.clone())?;
        PreparedBornManualRosterPublicationV2::prepare(
            retained,
            history,
            proof,
            p.publication_request.clone(),
            &pairing,
            owner,
        )
    }
}
