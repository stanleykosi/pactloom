//! Same-source preparation custody. Ordinary requests select, never open/read.
use super::coordinated_redisclosure_v1::CoordinatedRedisclosedSourceV1;
use super::*;
use crate::authority_bridge::durable_review_ipc_v3::coordinated_v1::CoordinatedPrepareClosedRecipientRequestV1;
use crate::ipc::CoordinatedPairPeerV1;

pub(crate) struct CoordinatedPreparingDeliverySourceV1 {
    pub(super) source: CoordinatedRedisclosedSourceV1,
    pub(super) preparation: CoordinatedPrepareClosedRecipientRequestV1,
    pub(super) preparation_digest: String,
    material_selection: CoordinatedOriginalMaterialSelectionV1,
}
/// Non-authoritative, non-Clone selection. No journal/read/effect API accepts it.
/// Absolute material/source/channel ceilings are frozen once, never refreshed.
struct CoordinatedOriginalMaterialSelectionV1 {
    deadline: Instant,
    valid_from_ms: u64,
    expires_at_ms: u64,
}
impl CoordinatedOriginalMaterialSelectionV1 {
    fn capture(captured: Instant, wall: u64, valid_from_ms: u64, expires_at_ms: u64,
        source: Instant, channel: Instant) -> Result<Self> {
        if wall < valid_from_ms || wall >= expires_at_ms { return Err(Error::Locked); }
        let deadline = captured.checked_add(Duration::from_millis(expires_at_ms - wall))
            .ok_or(Error::Locked)?.min(source).min(channel);
        let value = Self { deadline, valid_from_ms, expires_at_ms };
        value.check_current(captured, wall)?;
        Ok(value)
    }
    fn check_current(&self, now: Instant, wall: u64) -> Result<()> {
        if now >= self.deadline || wall < self.valid_from_ms || wall >= self.expires_at_ms {
            return Err(Error::Locked);
        }
        Ok(())
    }
}
/// A new custody owner, not an extension of an old receipt/material token.
/// Only seal_read can build it after an actual read and consumed Prepare Final.
struct CoordinatedPreparedMaterialCustodyV1 {
    staged: CoordinatedPreparingDeliverySourceV1,
    lifetime: std::sync::Arc<SignerV3PreparedLifetimeV1>,
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
        // This is immutable selection metadata, NOT a private-read capability.
        // Accepted receipt provenance does not revive its old 120s permission.
        // A different nominal custody owner is minted only after PrepareRead.
        let material_selection = CoordinatedOriginalMaterialSelectionV1::capture(
            captured, wall,
            preparation.material_scopes.iter()
                .map(|v| v.valid_from_unix_seconds.saturating_mul(1000))
                .max().ok_or(Error::ReviewMismatch)?,
            ceiling,
            self.ready.pairing.source.original_source_deadline,
            peer.deadline(),
        )?;
        let preparation_digest = preparation.digest().map_err(|_| Error::ReviewMismatch)?;
        Ok(CoordinatedPreparingDeliverySourceV1 {
            source: self,
            preparation,
            preparation_digest,
            material_selection,
        })
    }
}
impl CoordinatedPreparingDeliverySourceV1 {
    pub(crate) fn check_current(&self) -> Result<()> {
        self.source.check_current()?;
        self.material_selection.check_current(Instant::now(), wall_ms()?)
    }
    pub(crate) fn preparation(&self) -> &CoordinatedPrepareClosedRecipientRequestV1 {
        &self.preparation
    }
    pub(crate) fn preparation_digest(&self) -> &str {
        &self.preparation_digest
    }
    pub(crate) fn original_material_deadline(&self) -> Instant {
        self.material_selection.deadline
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
    original_service_deadline: Instant,
}
pub(crate) struct CoordinatedPreparedDeliverySourceV1 {
    custody: CoordinatedPreparedMaterialCustodyV1,
    pub(super) original: DurableConstructionOutboxV1,
    pub(super) read: SignerV3PrepareReadPresentationV1,
}
impl CoordinatedPreparingDeliverySourceV1 {
    pub(crate) fn read(
        self,
        action: &SignerV3PrepareReadFinalV1,
    ) -> Result<CoordinatedReadOpenedSourceV1> {
        self.check_current()?;
        action.check_current()?;
        let f = action.facts();
        if action.original_source_deadline() != self.original_source_deadline()
            || action.original_channel_deadline() != self.original_channel_deadline()
            || action.original_material_deadline() != self.original_material_deadline()
            || f.preparation_digest != self.preparation_digest
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
            &self.source.ready.accepted,
            CoordinatedConstructionActionV1::Prepare(action),
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
        crate::native_ui::durable_construction_v1::validate_coordinated_original(fresh.request(), &lease)
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
        lease.require_prepare(action)?;
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
            original_service_deadline: action.original_service_deadline(),
        })
    }
}
impl CoordinatedReadOpenedSourceV1 {
    pub(crate) fn seal_read(
        self,
        lifetime: std::sync::Arc<SignerV3PreparedLifetimeV1>,
    ) -> Result<CoordinatedPreparedDeliverySourceV1> {
        lifetime.check_current()?;
        self.staged.check_current()?;
        if lifetime.read_presentation_digest() != self.read.presentation_digest
            || lifetime.source_identity_digest() != self.staged.source_identity()
            || lifetime.original_material_deadline() != self.staged.original_material_deadline()
            || lifetime.original_source_deadline() != self.staged.original_source_deadline()
            || lifetime.original_channel_deadline() != self.staged.original_channel_deadline()
            || lifetime.original_service_deadline() != self.original_service_deadline
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(CoordinatedPreparedDeliverySourceV1 {
            custody: CoordinatedPreparedMaterialCustodyV1 { staged: self.staged, lifetime },
            original: self.original,
            read: self.read,
        })
    }
}
impl CoordinatedPreparedDeliverySourceV1 {
    /// Restriction/cache only. Every new private journal/owner read needs its
    /// own exact nominal action; the prepared lifetime grants none of them.
    pub(crate) fn check_current(&self) -> Result<()> {
        self.custody.lifetime.check_current()?;
        self.custody.staged.check_current()
    }
    pub(crate) fn read_presentation_digest(&self) -> &str {
        &self.read.presentation_digest
    }
    pub(crate) fn source_identity(&self) -> &str {
        self.custody.staged.source_identity()
    }
    pub(crate) fn manifest(&self) -> &crate::consent_journal::AcceptedManifestRecord {
        self.custody.staged.manifest()
    }
    pub(crate) fn enrollment(&self) -> &crate::consent_journal::AccountEnrollmentRecord {
        self.custody.staged.enrollment()
    }
    pub(crate) fn original_outbox(&self) -> &DurableConstructionOutboxV1 {
        &self.original
    }
    pub(crate) fn original_material_deadline(&self) -> Instant {
        self.custody.staged.original_material_deadline()
    }
    pub(crate) fn original_source_deadline(&self) -> Instant {
        self.custody.staged.original_source_deadline()
    }
    pub(crate) fn original_channel_deadline(&self) -> Instant {
        self.custody.staged.original_channel_deadline()
    }
    pub(crate) fn original_service_deadline(&self) -> Instant {
        self.custody.lifetime.original_service_deadline()
    }
    pub(crate) fn peer(&self) -> &CoordinatedPairPeerV1 {
        self.custody.staged.peer()
    }
    pub(crate) fn preparation(&self) -> &CoordinatedPrepareClosedRecipientRequestV1 {
        &self.custody.staged.preparation
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
        self.custody.staged.next_event()
    }
}

#[path = "coordinated_delivery_source_v1/coordinated_admission_v1.rs"]
mod coordinated_admission_v1;
pub(crate) use coordinated_admission_v1::CoordinatedPreparedPurposeBindingV1;

#[path = "coordinated_delivery_source_v1/coordinated_financial_selection_v1.rs"]
mod coordinated_financial_selection_v1;

#[cfg(test)]
mod material_selection_handoff_tests {
    use super::*;

    #[test]
    fn accepted_selection_preserves_absolute_material_not_old_receipt_window() {
        let start = Instant::now();
        let selected = CoordinatedOriginalMaterialSelectionV1::capture(
            start, 1_000, 500, 601_000,
            start + Duration::from_secs(800), start + Duration::from_secs(900),
        ).unwrap();
        assert_eq!(selected.deadline, start + Duration::from_secs(600));
        // This tests selection metadata only, not permission to read/effect.
        assert!(selected.check_current(start + Duration::from_secs(121), 122_000).is_ok());
        assert!(selected.check_current(start + Duration::from_secs(599), 600_000).is_ok());
        assert!(selected.check_current(start + Duration::from_secs(600), 601_000).is_err());
    }

    #[test]
    fn material_selection_intersects_original_source_and_channel() {
        let start = Instant::now();
        for (source, channel, expected) in [(200, 300, 200), (300, 200, 200), (900, 900, 600)] {
            let selected = CoordinatedOriginalMaterialSelectionV1::capture(
                start, 1_000, 500, 601_000,
                start + Duration::from_secs(source), start + Duration::from_secs(channel),
            ).unwrap();
            assert_eq!(selected.deadline, start + Duration::from_secs(expected));
            assert!(selected.check_current(selected.deadline, 1_000 + expected * 1000).is_err());
        }
    }

    #[test]
    fn material_selection_does_not_refresh_on_later_observation() {
        let start = Instant::now();
        let selected = CoordinatedOriginalMaterialSelectionV1::capture(
            start, 1_000, 500, 601_000,
            start + Duration::from_secs(500), start + Duration::from_secs(900),
        ).unwrap();
        let original = selected.deadline;
        for elapsed in [0, 1, 119, 120, 121, 499] {
            selected.check_current(start + Duration::from_secs(elapsed), 1_000 + elapsed * 1000).unwrap();
            assert_eq!(selected.deadline, original);
        }
        assert!(selected.check_current(start + Duration::from_secs(500), 501_000).is_err());
        assert_eq!(selected.deadline, original);
    }

    #[test]
    fn material_selection_rejects_wall_rollback_and_absolute_expiry() {
        let start = Instant::now();
        let selected = CoordinatedOriginalMaterialSelectionV1::capture(
            start, 1_000, 900, 601_000,
            start + Duration::from_secs(800), start + Duration::from_secs(900),
        ).unwrap();
        assert!(selected.check_current(start, 899).is_err());
        assert!(selected.check_current(start, 601_000).is_err());
        assert!(selected.check_current(start, u64::MAX).is_err());
    }

    #[test]
    fn material_selection_refuses_expired_or_unstarted_originals() {
        let start = Instant::now();
        let later = start + Duration::from_secs(300);
        for (wall, from, until, source, channel) in [
            (1_000, 1_001, 3_000, later, later),
            (1_000, 500, 1_000, later, later),
            (1_000, 500, 999, later, later),
            (1_000, 500, 3_000, start, later),
            (1_000, 500, 3_000, later, start),
        ] {
            assert!(CoordinatedOriginalMaterialSelectionV1::capture(
                start, wall, from, until, source, channel,
            ).is_err());
        }
    }
}
