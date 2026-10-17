//! Explicit original-owner mTLS transport for one native-approved consumed V3
//! continuation. This never reads, installs, renews or revives a writer MAC key.
use super::*;
use crate::{
    born_offline_admission_v1::*, born_offline_dispatch_v1::*,
    born_offline_enrollment_v1::BornOfflineEnrollmentV1,
    born_offline_owner_continuation_v1::BornOfflineTransportAuthenticationV1,
    born_offline_witness_v1::*,
};
impl AuthorityClient {
    fn check_born_owner_scope_v1(
        &self,
        enrollment: &BornOfflineEnrollmentV1,
    ) -> Result<BornOfflineTransportAuthenticationV1> {
        enrollment.validate()?;
        let origin = enrollment
            .owner_continuation
            .as_ref()
            .ok_or(AuthorityError::Permission)?;
        if enrollment.policy.account_id != self.account
            || enrollment.policy.network_profile_id != self.network
            || enrollment.policy.witness_id != self.witness
            || enrollment.original_policy_digest != self.policy_digest
            || enrollment.owner_certificate_digest != self.tls.client_certificate
            || enrollment.policy.witness_certificate_digest != self.tls.pinned_certificate
        {
            return Err(AuthorityError::Authentication);
        }
        Ok(
            BornOfflineTransportAuthenticationV1::OriginalOwnerContinuationV1 {
                enrollment_digest: enrollment.digest()?,
                continuation_digest: origin.digest()?,
            },
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn submit_born_owner_intent_checked_until_v1(
        &self,
        enrollment: &BornOfflineEnrollmentV1,
        request: BornOfflineReservationRequestV1,
        original_envelope: &[u8],
        export_template: OfflineAdmissionExportPlan,
        deadline: Instant,
        mut current: impl FnMut() -> Result<()>,
    ) -> Result<BornOfflineDeliveryV1> {
        current()?;
        let authentication = self.check_born_owner_scope_v1(enrollment)?;
        enrollment.require_born_construction_scope_v1(&request.construction_link)?;
        if request.enrollment_digest != enrollment.digest()? {
            return Err(AuthorityError::InvalidBinding);
        }
        crate::validate_born_offline_intent_delivery_size_v1(
            &request,
            original_envelope,
            &export_template,
        )?;
        let lookup = BornOfflineDeliveryLookupV1::from_request(&request)?;
        let wire = BornOfflineWitnessRequestV1 {
            request: request.clone(),
            original_envelope_hex: hex::encode(original_envelope),
            export_template: export_template.clone(),
            authentication,
        };
        let response = self.call_with_inner_checked(
            |_| Ok(WireRequest::SubmitBornOfflineIntentV1(Box::new(wire))),
            Some(deadline),
            &mut current,
        )?;
        current()?;
        require_before_caller_deadline(deadline)?;
        let delivery = self.check_born_delivery(response, &lookup)?;
        let mut expected = export_template;
        expected.sequence = delivery.body.delivery.export_plan.sequence;
        let actual = &delivery.body.delivery;
        if actual.export_plan != expected
            || actual.authorization_id != request.reservation.intent.terms.authorization_id
            || actual.admission_expires_at_ms != request.reservation.admission_expires_at_ms
            || actual.reserved_at_ms < request.reservation.requested_at_ms
        {
            return Err(AuthorityError::Authentication);
        }
        Ok(delivery)
    }
    pub fn authorize_born_owner_dispatch_checked_until_v1(
        &self,
        enrollment: &BornOfflineEnrollmentV1,
        request: BornOfflineDispatchRequestV1,
        deadline: Instant,
        mut current: impl FnMut() -> Result<()>,
    ) -> Result<AuthenticatedBornOfflineDispatchV1> {
        current()?;
        request.validate()?;
        let authentication = self.check_born_owner_scope_v1(enrollment)?;
        let origin = enrollment
            .owner_continuation
            .as_ref()
            .ok_or(AuthorityError::Permission)?;
        let d = &request.dispatch;
        if d.account_id != self.account || d.network_profile_id != self.network {
            return Err(AuthorityError::InvalidBinding);
        }
        let started = Instant::now();
        let wall_floor = now_ms()?;
        if wall_floor < d.reviewed_at_ms || wall_floor >= d.admission_expires_at_ms {
            return Err(AuthorityError::Expired);
        }
        let deadline = deadline.min(
            started
                .checked_add(Duration::from_millis(
                    d.admission_expires_at_ms - wall_floor,
                ))
                .ok_or(AuthorityError::Expired)?,
        );
        let mut checked = || {
            current()?;
            let now = now_ms()?;
            if Instant::now() >= deadline || now < wall_floor || now >= d.admission_expires_at_ms {
                return Err(AuthorityError::Expired);
            }
            Ok(())
        };
        let mutation = AuthorityMutation::AuthorizeBornOfflineDispatchV1(Box::new(request.clone()));
        let response = self.call_with_inner_checked(
            |_| {
                Ok(WireRequest::AuthorizeBornOfflineDispatchV1 {
                    request: Box::new(request.clone()),
                    authentication,
                })
            },
            Some(deadline),
            &mut checked,
        )?;
        checked()?;
        let WireResponse::BornOfflineDispatchV1(admission) = response else {
            return Err(AuthorityError::Authentication);
        };
        admission.matches_request(&request)?;
        if admission.original.reserved.witness_id != self.witness
            || admission.original.reserved.witness_policy_digest != self.policy_digest
            || admission.original_writer_session != enrollment.original_writer_session
            || admission.original.request.enrollment_digest != enrollment.digest()?
            || admission
                .original
                .request
                .construction_link
                .reservation_operation_id
                != origin.construction_reservation_operation_id
            || admission
                .original
                .request
                .construction_link
                .consume_operation_id
                != origin.construction_consume_operation_id
        {
            return Err(AuthorityError::Authentication);
        }
        self.check_committed_head(
            &d.expected_head,
            &admission.committed_head,
            mutation,
            admission.admitted_at_ms,
            None,
        )?;
        let authenticated = AuthenticatedBornOfflineDispatchV1 {
            descriptor: *admission,
            certificate: self.tls.pinned_certificate.clone(),
            deadline,
            wall_floor,
        };
        checked()?;
        authenticated.check_current(&request)?;
        Ok(authenticated)
    }
}
