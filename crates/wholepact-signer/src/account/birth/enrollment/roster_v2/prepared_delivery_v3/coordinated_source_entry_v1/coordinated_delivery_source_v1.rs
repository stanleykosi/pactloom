//! Same-source preparation custody. Ordinary requests select, never open/read.
use super::coordinated_redisclosure_v1::CoordinatedRedisclosedSourceV1;
use super::*;
use crate::authority_bridge::durable_review_ipc_v3::coordinated_v1::CoordinatedPrepareClosedRecipientRequestV1;
use crate::ipc::CoordinatedPairPeerV1;

pub(crate) struct CoordinatedPreparingDeliverySourceV1 {
    pub(super) source: CoordinatedRedisclosedSourceV1,
    pub(super) preparation: CoordinatedPrepareClosedRecipientRequestV1,
    pub(super) preparation_digest: String,
    pub(super) original_material_deadline: Instant,
}
impl CoordinatedRedisclosedSourceV1 {
    pub(crate) fn next_event(&self) -> Result<Option<crate::ipc::CoordinatedLocalEventV1>> {
        self.check_current()?;
        self.ready.next_event()
    }
    pub(crate) fn begin_preparation(
        self,
        peer: &CoordinatedPairPeerV1,
        preparation: CoordinatedPrepareClosedRecipientRequestV1,
    ) -> Result<CoordinatedPreparingDeliverySourceV1> {
        // Freeze material clocks before subsequent configuration/display work.
        let captured = Instant::now();
        let wall = wall_ms()?;
        self.check_current()?;
        self.ready.peer.require_same_grant(peer)?;
        preparation.validate().map_err(|_| Error::ReviewMismatch)?;
        let current = preparation
            .request
            .current_disclosure
            .as_ref()
            .ok_or(Error::ReviewMismatch)?;
        let link = self.outbox.redisclosure().ok_or(Error::ReviewMismatch)?;
        let proposal = self.ready.manifest.proposal()?;
        if preparation.coordinated_provider_reference != peer.coordinated_provider_reference()
            || preparation.signer_process_instance != peer.signer_process_instance()
            || preparation.request.enrollment_ref != self.ready.enrollment.reference()
            || preparation.request.accepted_manifest_ref != self.ready.manifest.reference()
            || preparation.request.own_disclosure.operation_id != link.original_operation_id
            || preparation.request.own_disclosure.expected_request_digest
                != link.original_request_digest
            || current.operation_id != self.outbox.request().operation_id
            || current.expected_request_digest != self.outbox.request_digest()
            || preparation.fixed.proposal_digest != proposal.proposal_digest()
            || preparation.fixed.manifest_digest != proposal.manifest_digest()
            || self.outbox.request().scope.proposal != *proposal.input()
            || !self
                .outbox
                .request()
                .scope
                .permits_local_reviewer_account(self.ready.enrollment.account_id())
                .map_err(|_| Error::ReviewMismatch)?
        {
            return Err(Error::ReviewMismatch);
        }
        let own = preparation
            .material_scopes
            .iter()
            .find(|v| v.account_id == self.ready.enrollment.account_id())
            .ok_or(Error::ReviewMismatch)?;
        // Redisclosure changes only current recipient grant fields. The fixed
        // payload retains the actual original contribution scope commitment.
        // The exact original scope digest is re-read/checked under PrepareRead.
        if own.valid_from_unix_seconds != self.outbox.request().scope.valid_from_unix_seconds
            || own.valid_until_unix_seconds != self.outbox.request().scope.valid_until_unix_seconds
        {
            return Err(Error::ReviewMismatch);
        }
        let ceiling = preparation
            .material_scopes
            .iter()
            .map(|v| v.valid_until_unix_seconds.saturating_mul(1000))
            .min()
            .ok_or(Error::ReviewMismatch)?;
        if preparation
            .material_scopes
            .iter()
            .any(|v| wall < v.valid_from_unix_seconds.saturating_mul(1000))
            || ceiling <= wall
        {
            return Err(Error::Locked);
        }
        let original_material_deadline = captured
            .checked_add(Duration::from_millis(ceiling - wall))
            .ok_or(Error::Locked)?
            .min(self.ready.pairing.source.original_source_deadline)
            .min(peer.deadline())
            .min(
                self.ready
                    .session
                    .current_receipt_deadline(&self.ready.enrollment, &self.ready.manifest)?,
            );
        let preparation_digest = preparation.digest().map_err(|_| Error::ReviewMismatch)?;
        Ok(CoordinatedPreparingDeliverySourceV1 {
            source: self,
            preparation,
            preparation_digest,
            original_material_deadline,
        })
    }
}
impl CoordinatedPreparingDeliverySourceV1 {
    pub(crate) fn check_current(&self) -> Result<()> {
        self.source.check_current()?;
        if Instant::now() >= self.original_material_deadline {
            return Err(Error::Locked);
        }
        Ok(())
    }
    pub(crate) fn preparation(&self) -> &CoordinatedPrepareClosedRecipientRequestV1 {
        &self.preparation
    }
    pub(crate) fn preparation_digest(&self) -> &str {
        &self.preparation_digest
    }
    pub(crate) fn original_material_deadline(&self) -> Instant {
        self.original_material_deadline
    }
    pub(crate) fn original_source_deadline(&self) -> Instant {
        self.source.ready.pairing.source.original_source_deadline
    }
    pub(crate) fn original_channel_deadline(&self) -> Instant {
        self.source.ready.peer.deadline()
    }
    pub(crate) fn source_identity(&self) -> &str {
        &self
            .source
            .ready
            .pairing
            .source
            .opened
            .source_identity_digest
    }
    pub(crate) fn entry_digest(&self) -> &str {
        &self
            .source
            .ready
            .pairing
            .source
            .opened
            .entry_presentation_digest
    }
    pub(crate) fn source_wall_expiry(&self) -> u64 {
        self.source.ready.pairing.source.facts.source_expires_at_ms
    }
    pub(crate) fn peer(&self) -> &CoordinatedPairPeerV1 {
        &self.source.ready.peer
    }
    pub(crate) fn enrollment(&self) -> &crate::consent_journal::AccountEnrollmentRecord {
        &self.source.ready.enrollment
    }
    pub(crate) fn manifest(&self) -> &crate::consent_journal::AcceptedManifestRecord {
        &self.source.ready.manifest
    }
    pub(crate) fn outbox(
        &self,
    ) -> &crate::authority_bridge::durable_construction_v1::DurableConstructionOutboxV1 {
        &self.source.outbox
    }
    pub(crate) fn disclosure(&self) -> Result<wholepact_authority::WitnessDisclosureDescriptor> {
        serde_json::from_str(
            &self
                .source
                .ready
                .pairing
                .source
                .facts
                .witness_disclosure_json,
        )
        .map_err(|_| Error::InvalidData)
    }
    pub(crate) fn owner_certificate_digest(&self) -> &str {
        &self
            .source
            .ready
            .pairing
            .source
            .facts
            .owner_certificate_digest
    }
}

use crate::authority_bridge::durable_construction_v1::DurableConstructionOutboxV1;
use crate::consent_journal::CoordinatedConstructionActionV1;
use wholepact_financial_coordinator_origin::{
    SignerV3PrepareReadFinalV1, SignerV3PrepareReadPresentationV1, SignerV3PreparedLifetimeV1,
};
pub(crate) struct CoordinatedReadOpenedSourceV1 {
    staged: CoordinatedPreparingDeliverySourceV1,
    original: DurableConstructionOutboxV1,
    read: SignerV3PrepareReadPresentationV1,
}
pub(crate) struct CoordinatedPreparedDeliverySourceV1 {
    pub(super) staged: CoordinatedPreparingDeliverySourceV1,
    pub(super) original: DurableConstructionOutboxV1,
    pub(super) read: SignerV3PrepareReadPresentationV1,
    pub(super) lifetime: std::sync::Arc<SignerV3PreparedLifetimeV1>,
}
impl CoordinatedPreparingDeliverySourceV1 {
    pub(crate) fn read(
        self,
        action: &SignerV3PrepareReadFinalV1,
    ) -> Result<CoordinatedReadOpenedSourceV1> {
        self.check_current()?;
        action.check_current()?;
        let f = action.facts();
        if f.preparation_digest != self.preparation_digest
            || f.preparation_json
                != serde_json::to_string(&self.preparation).map_err(|_| Error::InvalidData)?
            || f.source_identity_digest != self.source_identity()
            || f.entry_presentation_digest != self.entry_digest()
            || f.current_outbox_reference != self.outbox().reference()
            || f.current_request_digest != self.outbox().request_digest()
            || f.current_enrollment_ref != self.enrollment().reference()
            || f.current_manifest_ref != self.manifest().reference()
            || f.pair_grant_id != self.peer().grant_id()
            || f.pair_key_digest != self.peer().key_digest()
            || f.pair_channel_digest != self.peer().channel_digest()
            || f.pair_generation != self.peer().generation()
            || f.coordinated_session_id != self.enrollment().receipt().native_session_id()
        {
            return Err(Error::ReviewMismatch);
        }
        let source = &self.source.ready.pairing.source;
        source.retained.check()?;
        action.check_current()?;
        let pin = source.revision.as_ref().ok_or(Error::Unavailable)?;
        source
            .journal
            .check_coordinated_v3_prepare_revision(pin, action)?;
        let lease = self.source.ready.session.acquire_construction_records(
            &source.journal,
            self.enrollment().reference(),
            self.manifest().reference(),
            &CoordinatedConstructionActionV1::Prepare(action),
        )?;
        let (original, fresh) = source.journal.read_coordinated_delivery_outboxes_v1(
            &self.preparation,
            &lease,
            action,
        )?;
        if fresh != self.source.outbox
            || original.request().enrollment_ref != source.enrollment.reference()
            || original.request().accepted_manifest_ref != source.manifest.reference()
            || lease.enrollment() != self.enrollment()
            || lease.manifest() != self.manifest()
        {
            return Err(Error::ReviewMismatch);
        }
        crate::native_ui::durable_construction_v1::validate_original(fresh.request(), &lease)
            .map_err(|_| Error::ReviewMismatch)?;
        original
            .request()
            .material
            .verify_owner(&source.retained.account.account().fvk()?)
            .map_err(|_| Error::ReviewMismatch)?;
        action.check_current()?;
        let own = self
            .preparation
            .material_scopes
            .iter()
            .find(|v| v.account_id == self.enrollment().account_id())
            .ok_or(Error::ReviewMismatch)?;
        if own.original_scope_digest
            != original
                .request()
                .scope
                .digest()
                .map_err(|_| Error::ReviewMismatch)?
        {
            return Err(Error::ReviewMismatch);
        }
        lease.require_current_durable_disclosure_receipts_v1()?;
        drop(lease);
        source
            .journal
            .check_coordinated_v3_prepare_revision(pin, action)?;
        action.check_current()?;
        let read = action.presentation().clone();
        Ok(CoordinatedReadOpenedSourceV1 {
            staged: self,
            original,
            read,
        })
    }
}
impl CoordinatedReadOpenedSourceV1 {
    pub(crate) fn seal_read(
        self,
        lifetime: std::sync::Arc<SignerV3PreparedLifetimeV1>,
    ) -> Result<CoordinatedPreparedDeliverySourceV1> {
        lifetime.check_current()?;
        if lifetime.read_presentation_digest() != self.read.presentation_digest
            || lifetime.source_identity_digest() != self.staged.source_identity()
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(CoordinatedPreparedDeliverySourceV1 {
            staged: self.staged,
            original: self.original,
            read: self.read,
            lifetime,
        })
    }
}
impl CoordinatedPreparedDeliverySourceV1 {
    /// Restriction/cache only. Every new private journal/owner read needs its
    /// own exact nominal action; the prepared lifetime grants none of them.
    pub(crate) fn check_current(&self) -> Result<()> {
        self.lifetime.check_current()?;
        self.staged.check_current()
    }
    pub(crate) fn read_presentation_digest(&self) -> &str {
        &self.read.presentation_digest
    }
    pub(crate) fn source_identity(&self) -> &str {
        self.staged.source_identity()
    }
    pub(crate) fn manifest(&self) -> &crate::consent_journal::AcceptedManifestRecord {
        self.staged.manifest()
    }
    pub(crate) fn enrollment(&self) -> &crate::consent_journal::AccountEnrollmentRecord {
        self.staged.enrollment()
    }
    pub(crate) fn original_outbox(&self) -> &DurableConstructionOutboxV1 {
        &self.original
    }
    pub(crate) fn original_material_deadline(&self) -> Instant {
        self.staged.original_material_deadline
    }
    pub(crate) fn original_source_deadline(&self) -> Instant {
        self.staged.original_source_deadline()
    }
    pub(crate) fn original_channel_deadline(&self) -> Instant {
        self.staged.original_channel_deadline()
    }
    pub(crate) fn peer(&self) -> &CoordinatedPairPeerV1 {
        self.staged.peer()
    }
    pub(crate) fn preparation(&self) -> &CoordinatedPrepareClosedRecipientRequestV1 {
        &self.staged.preparation
    }
}
impl CoordinatedPreparingDeliverySourceV1 {
    pub(crate) fn next_event(&self) -> Result<Option<crate::ipc::CoordinatedLocalEventV1>> {
        self.check_current()?;
        self.source.next_event()
    }
}
impl CoordinatedPreparedDeliverySourceV1 {
    pub(crate) fn next_event(&self) -> Result<Option<crate::ipc::CoordinatedLocalEventV1>> {
        self.check_current()?;
        self.staged.next_event()
    }
}
