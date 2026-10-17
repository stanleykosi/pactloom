//! Exact post-return dispatch origin for a native-born construction continuation.
//! A fresh dispatch window never renews signing authority, the original session,
//! construction deadline or any earlier uncertainty. Chain observations remain
//! the explicitly disclosed Host provider's claims, not witness certification.
use crate::{born_offline_admission_v1::BornOfflineAuthorizationAdmissionV1, *};
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BornOfflineDispatchRequestV1 {
    pub version: u16,
    /// Inert common exact-transaction fields only. reservation_request_digest
    /// is the OUTER born request digest, never a legacy reservation permit.
    pub dispatch: AuthorizeDispatch,
    pub original_admission_digest: String,
    pub construction_link_digest: String,
    pub current_input_observation_digest: String,
    pub observed_at_ms: u64,
    pub observation_expires_at_ms: u64,
    pub native_review_digest: String,
}
impl BornOfflineDispatchRequestV1 {
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(AuthorityError::UnsupportedVersion);
        }
        self.dispatch.validate()?;
        for h in [
            &self.original_admission_digest,
            &self.construction_link_digest,
            &self.current_input_observation_digest,
            &self.native_review_digest,
        ] {
            hash(h)?;
        }
        if self.observed_at_ms == 0
            || self.observation_expires_at_ms <= self.observed_at_ms
            || self.observation_expires_at_ms - self.observed_at_ms > 60_000
            || self.dispatch.reviewed_at_ms < self.observed_at_ms
            || self.dispatch.admission_expires_at_ms > self.observation_expires_at_ms
        {
            return Err(AuthorityError::InvalidBinding);
        }
        encode(self)?;
        Ok(())
    }
    pub fn request_digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:born-offline-exact-dispatch:v1", self)
    }
    pub fn validate_original(&self, original: &BornOfflineAuthorizationAdmissionV1) -> Result<()> {
        self.validate()?;
        original.matches_request(&original.request)?;
        let r = &self.dispatch;
        let old = &original.request.reservation;
        if r.reservation_operation_id != old.operation_id
            || r.reservation_request_digest != original.request.request_digest()?
            || self.original_admission_digest != original.admission_digest()?
            || self.construction_link_digest != original.request.construction_link.digest()?
            || r.account_id != old.intent.terms.account_id
            || r.network_profile_id != old.intent.terms.network_profile_id
            || r.transaction_expiry_height != old.intent.terms.transaction_expiry_height
            || r.writer_epoch != old.writer_epoch
            || r.expected_head.sequence < original.reserved.committed_head.sequence
            || self.observed_at_ms < original.reserved.reserved_at_ms
        {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BornOfflineDispatchAdmissionV1 {
    pub version: u16,
    pub request: BornOfflineDispatchRequestV1,
    pub request_digest: String,
    pub original: BornOfflineAuthorizationAdmissionV1,
    pub committed_head: AuthorityHead,
    pub admitted_at_ms: u64,
    pub original_writer_session: WriterSessionReceipt,
}
impl BornOfflineDispatchAdmissionV1 {
    pub fn matches_request(&self, request: &BornOfflineDispatchRequestV1) -> Result<()> {
        request.validate_original(&self.original)?;
        let d = &request.dispatch;
        if self.version != 1
            || self.request != *request
            || self.request_digest != request.request_digest()?
            || self.committed_head.sequence
                != d.expected_head
                    .sequence
                    .checked_add(1)
                    .ok_or(AuthorityError::Limit)?
            || self.admitted_at_ms < d.reviewed_at_ms
            || self.admitted_at_ms >= d.admission_expires_at_ms
            || self.original_writer_session.session_id != self.original.reserved.writer_session_id
            || self.original_writer_session.writer_epoch != d.writer_epoch
            || d.admission_expires_at_ms > self.original_writer_session.expires_at_ms
            || self.original_writer_session.disclosure.witness_id
                != self.original.reserved.witness_id
            || self.original_writer_session.disclosure.policy_digest
                != self.original.reserved.witness_policy_digest
            || self.original_writer_session.disclosure.account_id != d.account_id
            || self.original_writer_session.disclosure.network_profile_id != d.network_profile_id
        {
            return Err(AuthorityError::InvalidBinding);
        }
        hash(&self.committed_head.digest)?;
        hash(&self.original_writer_session.session_id)?;
        self.original_writer_session.disclosure.validate()?;
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.matches_request(&self.request)?;
        digest("wholepact:born-offline-dispatch-admission:v1", self)
    }
}

impl policy::Ledger {
    /// This checks present authority even on exact retry. A serialized historical
    /// result can be read after expiry but cannot remint an execution wrapper.
    pub(crate) fn validate_born_dispatch_current_v1(
        &self,
        request: &BornOfflineDispatchRequestV1,
        peer: &str,
        now: u64,
    ) -> Result<&BornOfflineAuthorizationAdmissionV1> {
        request.validate()?;
        let enrollment = self.require_born_offline_original_session_v1(now)?;
        let session = &enrollment.original_writer_session;
        let d = &request.dispatch;
        if peer != enrollment.born_transport_certificate_v1()
            || d.writer_epoch != session.writer_epoch
            || d.admission_expires_at_ms > session.expires_at_ms
            || d.admission_expires_at_ms > enrollment.policy.expires_at_ms
            || now < d.reviewed_at_ms
            || now >= d.admission_expires_at_ms
        {
            return Err(AuthorityError::Expired);
        }
        let Some((
            AuthorityMutation::ReserveBornOfflineV1(record),
            original_peer,
            MutationResult::BornOfflineReservedV1(original),
        )) = self.operations.get(&d.reservation_operation_id)
        else {
            return Err(AuthorityError::Permission);
        };
        if original_peer != peer
            || record.request != original.request
            || original.request.enrollment_digest != enrollment.digest()?
        {
            return Err(AuthorityError::Permission);
        }
        request.validate_original(original)?;
        let construction =
            self.born_offline_construction_origin_v1(&original.request.construction_link)?;
        original
            .request
            .construction_link
            .validate_for(&construction, &original.request.reservation)?;
        if construction.reservation.session != *session || !self.resolutions.is_empty() {
            return Err(AuthorityError::Conflict);
        }
        // The original construction remains the sole accounting bucket. No
        // dispatch route releases or recreates its obligation/input claims.
        if !self
            .obligations
            .contains(&original.request.reservation.intent.terms.obligation_id)
            || original
                .request
                .reservation
                .intent
                .terms
                .inputs
                .iter()
                .any(|i| {
                    !self.input_ids.contains(&i.input_id) || !self.nullifiers.contains(&i.nullifier)
                })
        {
            return Err(AuthorityError::CorruptHistory);
        }
        for (mutation, _, _) in self.operations.values() {
            if let AuthorityMutation::AuthorizeBornOfflineDispatchV1(old) = mutation {
                if old.dispatch.reservation_operation_id == d.reservation_operation_id
                    && (old.dispatch.final_transaction_digest != d.final_transaction_digest
                        || old.dispatch.final_transaction_id != d.final_transaction_id
                        || old.dispatch.transaction_expiry_height != d.transaction_expiry_height
                        || old.dispatch.backend_disclosure_digest != d.backend_disclosure_digest
                        || old.original_admission_digest != request.original_admission_digest
                        || old.construction_link_digest != request.construction_link_digest)
                {
                    return Err(AuthorityError::Conflict);
                }
            }
        }
        let key = &original.request.construction_link.reservation_operation_id;
        if self.final_transactions.get(key).is_some_and(|old| {
            old != &(
                d.final_transaction_digest.clone(),
                d.final_transaction_id.clone(),
            )
        }) {
            return Err(AuthorityError::Conflict);
        }
        Ok(original)
    }
    pub(crate) fn apply_born_dispatch_v1(
        &mut self,
        request: &BornOfflineDispatchRequestV1,
        event: &policy::Event,
        next: &AuthorityHead,
    ) -> Result<BornOfflineDispatchAdmissionV1> {
        let original = self
            .validate_born_dispatch_current_v1(
                request,
                &event.authenticated_certificate_digest,
                event.witness_time_ms,
            )?
            .clone();
        self.fence(
            &request.dispatch.expected_head,
            request.dispatch.writer_epoch,
        )?;
        let session = self
            .require_born_offline_original_session_v1(event.witness_time_ms)?
            .original_writer_session
            .clone();
        if event.writer_session_id
            != self
                .require_born_offline_original_session_v1(event.witness_time_ms)?
                .born_event_writer_session_v1()
        {
            return Err(AuthorityError::SessionRequired);
        }
        let admission = BornOfflineDispatchAdmissionV1 {
            version: 1,
            request: request.clone(),
            request_digest: request.request_digest()?,
            original,
            committed_head: next.clone(),
            admitted_at_ms: event.witness_time_ms,
            original_writer_session: session,
        };
        admission.matches_request(request)?;
        self.final_transactions.insert(
            admission
                .original
                .request
                .construction_link
                .reservation_operation_id
                .clone(),
            (
                request.dispatch.final_transaction_digest.clone(),
                request.dispatch.final_transaction_id.clone(),
            ),
        );
        Ok(admission)
    }
}

impl ReconciledAuthorityHistory {
    pub fn born_offline_dispatch_v1(
        &self,
        operation: &str,
    ) -> Option<&BornOfflineDispatchAdmissionV1> {
        self.born_offline_dispatches
            .iter()
            .find(|r| r.request.dispatch.operation_id == operation)
    }
    pub fn born_offline_dispatch_for_original_v1(
        &self,
        original_operation: &str,
    ) -> Option<&BornOfflineDispatchAdmissionV1> {
        self.born_offline_dispatches
            .iter()
            .filter(|r| r.request.dispatch.reservation_operation_id == original_operation)
            .max_by_key(|r| r.committed_head.sequence)
    }
}

#[cfg(all(test, feature = "pending-birth-foundation", target_os = "linux"))]
#[path = "born_offline_dispatch_v1_tests.rs"]
mod tests;
