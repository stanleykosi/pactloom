//! Borrowed common accounting facts, never a wire format or authority token.
//!
//! Keep each origin's original canonical request/result intact. Future origins
//! must be added exhaustively here AND to authenticated complete-history and
//! original-consent consumers before they may issue reservations.
use crate::{InputReservation, MutationResult};

pub(crate) struct ReservationView<'a> {
    pub request_digest: &'a str,
    pub operation_id: &'a str,
    pub account_id: &'a str,
    pub network_profile_id: &'a str,
    pub obligation_id: &'a str,
    pub proposal_id: &'a str,
    pub effects_digest: &'a str,
    pub transaction_expiry_height: u32,
    pub maximum_debit_zatoshis: u64,
    pub inputs: &'a [InputReservation],
}
impl<'a> ReservationView<'a> {
    pub(crate) fn from_result(result: &'a MutationResult) -> Option<Self> {
        match result {
            MutationResult::OfflineReserved(p) => Some(Self {
                request_digest: &p.request_digest,
                operation_id: &p.request.operation_id,
                account_id: &p.request.intent.terms.account_id,
                network_profile_id: &p.request.intent.terms.network_profile_id,
                obligation_id: &p.request.intent.terms.obligation_id,
                proposal_id: &p.request.intent.terms.proposal_id,
                effects_digest: &p.request.intent.terms.effects_digest,
                transaction_expiry_height: p.request.intent.terms.transaction_expiry_height,
                maximum_debit_zatoshis: p.request.intent.terms.maximum_debit_zatoshis,
                inputs: &p.request.intent.terms.inputs,
            }),
            MutationResult::Reserved(p) => Some(Self {
                request_digest: &p.request_digest,
                operation_id: &p.request.operation_id,
                account_id: &p.request.account_id,
                network_profile_id: &p.request.network_profile_id,
                obligation_id: &p.request.obligation_id,
                proposal_id: &p.request.proposal_id,
                effects_digest: &p.request.effects_digest,
                transaction_expiry_height: p.request.transaction_expiry_height,
                maximum_debit_zatoshis: p.request.maximum_debit_zatoshis,
                inputs: &p.request.inputs,
            }),
            MutationResult::ConstructionTransportClaimedV1(_)
            | MutationResult::ConstructionTransportReservedV1(_)
            | MutationResult::ConstructionTransportConsumedV1(_)
            | MutationResult::ManualRosterConstructionReservedV3(_)
            | MutationResult::ManualRosterConstructionConsumedV3(_)
            | MutationResult::ManualRosterConstructionReservedV2(_)
            | MutationResult::ManualRosterConstructionConsumedV2(_)
            | MutationResult::ManualRosterEnrollmentAdmittedV2(_)
            | MutationResult::ManualEnrollmentAdmittedV2(_)
            | MutationResult::ManualEnrollmentAdmitted(_)
            | MutationResult::AutomaticKeyUseAdmitted(_)
            | MutationResult::Controlled(_)
            | MutationResult::WriterPending(_)
            | MutationResult::ProgressRecorded(_)
            | MutationResult::DispatchAdmitted(_)
            | MutationResult::ResolutionRecorded(_)
            | MutationResult::ResolutionsReopened(_) => None,
        }
    }
}

#[cfg(test)]
#[path = "reservation_view_tests.rs"]
mod tests;
