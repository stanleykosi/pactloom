//! Exact continuation of an already charged, consumed V3 construction. Public
//! values are historical data, never completion, native approval or key use.
use crate::{
    manual_roster_construction_v3::*,
    manual_roster_extension_v2::ManualRosterEnrollmentExtensionV2,
    manual_roster_witness_v2::ManualRosterSessionContinuationV2,
    offline::ReserveOfflineAuthorization, *,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BornOfflineConstructionLinkV1 {
    pub version: u16,
    pub reservation_operation_id: String,
    pub reservation_digest: String,
    pub consume_operation_id: String,
    pub consume_digest: String,
    pub plan_digest: String,
    pub common_context_digest: String,
    pub invocation_digest: String,
    /// Authenticated by the native signer's actual Host checkpoint intake.
    pub checkpoint_origin_digest: String,
}
impl BornOfflineConstructionLinkV1 {
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(AuthorityError::UnsupportedVersion);
        }
        id(&self.reservation_operation_id)?;
        id(&self.consume_operation_id)?;
        if self.reservation_operation_id == self.consume_operation_id {
            return Err(AuthorityError::InvalidBinding);
        }
        for h in [
            &self.reservation_digest,
            &self.consume_digest,
            &self.plan_digest,
            &self.common_context_digest,
            &self.invocation_digest,
            &self.checkpoint_origin_digest,
        ] {
            hash(h)?;
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:born-offline-construction-link:v1", self)
    }
    pub fn validate_origin(&self, o: &BornOfflineConstructionOriginV1) -> Result<()> {
        self.validate()?;
        o.validate()?;
        let r = &o.reservation;
        let c = &o.consumed;
        let p = &r.request.construction.plan;
        if self.reservation_operation_id != r.request.construction.operation_id
            || self.reservation_digest != r.digest_for(&o.extension, &o.continuation)?
            || self.consume_operation_id != c.request.operation_id
            || self.consume_digest != c.digest_for(r, &o.extension, &o.continuation)?
            || self.plan_digest != p.digest().map_err(|_| AuthorityError::InvalidBinding)?
            || self.common_context_digest != p.common_context_digest
            || self.invocation_digest != r.request.invocation_digest()?
        {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
    /// Immutable own-input bijection. Actual action positions remain checked by
    /// the maintained PCZT signer; no action index is invented by construction.
    pub fn validate_for(
        &self,
        o: &BornOfflineConstructionOriginV1,
        request: &ReserveOfflineAuthorization,
    ) -> Result<()> {
        self.validate_origin(o)?;
        request.validate()?;
        let r = &o.reservation;
        let p = &r.request.construction.plan;
        let proposal = p.validate().map_err(|_| AuthorityError::InvalidBinding)?;
        let t = &request.intent.terms;
        let e = p.enrollment();
        let common = &p.common_context;
        let allocation = proposal
            .manifest()
            .participants
            .iter()
            .find(|a| {
                a.account_id == e.identity.account_id && a.participant_id == e.scope.participant_id
            })
            .ok_or(AuthorityError::InvalidBinding)?;
        let expected: BTreeMap<_, _> = p
            .selected_inputs()
            .iter()
            .map(|i| {
                (
                    i.input_id.as_str(),
                    (i.nullifier.as_str(), i.value_zatoshis),
                )
            })
            .collect();
        let actual: BTreeMap<_, _> = t
            .inputs
            .iter()
            .map(|i| {
                (
                    i.input_id.as_str(),
                    (i.nullifier.as_str(), i.value_zatoshis),
                )
            })
            .collect();
        if expected.len() != p.selected_inputs().len()
            || actual.len() != t.inputs.len()
            || actual != expected
            || t.account_id != e.identity.account_id
            || t.network_profile_id != e.identity.network_profile_id
            || t.enrollment_ref != o.extension.account_extension.enrollment_ref
            || t.agreement_id != e.scope.agreement_id
            || t.obligation_id != e.scope.obligation_id
            || t.proposal_id != proposal.input().proposal_id
            || t.proposal_revision != common.candidate_revision
            || t.proposal_digest != proposal.proposal_digest()
            || t.manifest_digest != proposal.manifest_digest()
            || t.maximum_debit_zatoshis != r.reserved_debit_zatoshis
            || t.fee_share_zatoshis != allocation.fee_share.as_zatoshis()
            || t.transaction_fee_zatoshis != proposal.manifest().transaction_fee.as_zatoshis()
            || t.transaction_expiry_height != common.expiry_height
            || t.consensus_branch_id != common.consensus_branch_id
            || t.snapshot.tip_height != common.reference_tip_height
            || t.snapshot.tip_hash != common.reference_tip_hash_protocol
            || t.snapshot.anchor_height != common.anchor_height
            || t.snapshot.anchor_hash != common.anchor_hash_protocol
            || t.snapshot.anchor_root != common.anchor_root
            || request.writer_epoch != r.request.writer_epoch
            || request.requested_at_ms < o.consumed.consumed_at_ms
            || request.admission_expires_at_ms > r.construction_expires_at_ms
            || request.admission_expires_at_ms > r.session.expires_at_ms
            || request.expected_head.sequence < o.consumed.snapshot.head.sequence
        {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BornOfflineConstructionOriginV1 {
    pub extension: ManualRosterEnrollmentExtensionV2,
    pub continuation: ManualRosterSessionContinuationV2,
    pub reservation: ManualRosterConstructionReservationRecordV3,
    pub consumed: ManualRosterConstructionConsumedRecordV3,
    /// Original purpose family is retained, not projected into a direct writer.
    pub transport_credential_id: Option<String>,
}
impl BornOfflineConstructionOriginV1 {
    pub fn validate(&self) -> Result<()> {
        self.reservation
            .validate_for(&self.extension, &self.continuation)?;
        self.consumed
            .validate_for(&self.reservation, &self.extension, &self.continuation)?;
        if let Some(id) = &self.transport_credential_id {
            hash(id)?;
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:born-offline-construction-origin:v1", self)
    }
}
impl policy::Ledger {
    pub(crate) fn born_offline_construction_origin_v1(
        &self,
        link: &BornOfflineConstructionLinkV1,
    ) -> Result<BornOfflineConstructionOriginV1> {
        link.validate()?;
        let original = self.born_offline_construction_origin_by_operations_v1(
            &link.reservation_operation_id,
            &link.consume_operation_id,
        )?;
        link.validate_origin(&original)?;
        Ok(original)
    }
    pub(crate) fn born_offline_construction_origin_by_operations_v1(
        &self,
        reservation_operation_id: &str,
        consume_operation_id: &str,
    ) -> Result<BornOfflineConstructionOriginV1> {
        id(reservation_operation_id)?;
        id(consume_operation_id)?;
        let reserve = &self
            .operations
            .get(reservation_operation_id)
            .ok_or(AuthorityError::Permission)?
            .2;
        let consume = &self
            .operations
            .get(consume_operation_id)
            .ok_or(AuthorityError::Permission)?
            .2;
        let (r, c, transport) = match (reserve, consume) {
            (
                MutationResult::ManualRosterConstructionReservedV3(r),
                MutationResult::ManualRosterConstructionConsumedV3(c),
            ) => (r.as_ref(), c.as_ref(), None),
            (
                MutationResult::ConstructionTransportReservedV1(r),
                MutationResult::ConstructionTransportConsumedV1(c),
            ) if r.credential_id == c.credential_id => {
                (&r.original, &c.original, Some(r.credential_id.clone()))
            }
            _ => return Err(AuthorityError::InvalidBinding),
        };
        let e = self
            .manual_roster_extension()?
            .ok_or(AuthorityError::Permission)?
            .extension
            .clone();
        let mut continuation = None;
        for (m, _, _) in self.operations.values() {
            if let AuthorityMutation::OwnerControl(OwnerControlRequest {
                control: OwnerControl::ContinueManualRosterSessionV2 { record },
                ..
            }) = m
            {
                if record.continuation.digest_for(&e)? == r.request.attempt_digest
                    && continuation.replace(record.continuation.clone()).is_some()
                {
                    return Err(AuthorityError::CorruptHistory);
                }
            }
        }
        let o = BornOfflineConstructionOriginV1 {
            extension: e,
            continuation: continuation.ok_or(AuthorityError::Permission)?,
            reservation: r.clone(),
            consumed: c.clone(),
            transport_credential_id: transport,
        };
        o.validate()?;
        Ok(o)
    }
}
impl ReconciledAuthorityHistory {
    /// Full authenticated replay membership, never a portable construction owner.
    pub fn born_offline_construction_origin_v1(
        &self,
        link: &BornOfflineConstructionLinkV1,
    ) -> Result<BornOfflineConstructionOriginV1> {
        link.validate()?;
        let (r, c, transport) = match (
            self.manual_roster_construction_records_v3
                .get(&link.reservation_operation_id),
            self.manual_roster_construction_records_v3
                .get(&link.consume_operation_id),
        ) {
            (
                Some(ManualRosterConstructionHistoryRecordV3::Reservation { record: r }),
                Some(ManualRosterConstructionHistoryRecordV3::Consumed { record: c }),
            ) => ((**r).clone(), (**c).clone(), None),
            (None, None) => {
                let h = &self.construction_transport_history;
                let mut rs = h.reservations.iter().filter(|r| {
                    r.original.request.construction.operation_id == link.reservation_operation_id
                });
                let mut cs = h
                    .consumptions
                    .iter()
                    .filter(|c| c.original.request.operation_id == link.consume_operation_id);
                let r = rs.next().ok_or(AuthorityError::Permission)?;
                let c = cs.next().ok_or(AuthorityError::Permission)?;
                if rs.next().is_some() || cs.next().is_some() || r.credential_id != c.credential_id
                {
                    return Err(AuthorityError::CorruptHistory);
                }
                (
                    r.original.clone(),
                    c.original.clone(),
                    Some(r.credential_id.clone()),
                )
            }
            _ => return Err(AuthorityError::InvalidBinding),
        };
        let e = self
            .manual_roster_enrollment_extension(
                &r.request
                    .construction
                    .plan
                    .retained
                    .selection
                    .scope
                    .selection
                    .inventory
                    .enrollment_ref,
            )?
            .ok_or(AuthorityError::Permission)?
            .clone();
        let continuation = self
            .manual_roster_session_continuation_v2(&r.request.attempt_digest)?
            .ok_or(AuthorityError::Permission)?
            .clone();
        let o = BornOfflineConstructionOriginV1 {
            extension: e,
            continuation,
            reservation: r,
            consumed: c,
            transport_credential_id: transport,
        };
        link.validate_origin(&o)?;
        if !self.contains_head(&o.reservation.snapshot.head)
            || !self.contains_head(&o.consumed.snapshot.head)
        {
            return Err(AuthorityError::CorruptHistory);
        }
        Ok(o)
    }
}
