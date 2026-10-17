//! Actual channel-authenticated purpose-distinct exact born dispatch admission.
use super::*;
use crate::born_offline_dispatch_v1::*;
use crate::born_offline_owner_continuation_v1::BornOfflineTransportAuthenticationV1;

/// A descriptor is historical data. Only this private-construction wrapper
/// proves the exact result arrived on this enrolled process's current mTLS call.
/// It cannot be cloned/deserialized and never converts to a legacy permit.
pub struct AuthenticatedBornOfflineDispatchV1 {
    pub(super) descriptor: BornOfflineDispatchAdmissionV1,
    pub(super) certificate: String,
    pub(super) deadline: Instant,
    pub(super) wall_floor: u64,
}
impl AuthenticatedBornOfflineDispatchV1 {
    pub fn descriptor(&self) -> &BornOfflineDispatchAdmissionV1 {
        &self.descriptor
    }
    pub fn authenticated_witness_certificate_digest(&self) -> &str {
        &self.certificate
    }
    pub fn check_current(&self, request: &BornOfflineDispatchRequestV1) -> Result<()> {
        self.descriptor.matches_request(request)?;
        let now = now_ms()?;
        if Instant::now() >= self.deadline
            || now < self.wall_floor
            || now >= request.dispatch.admission_expires_at_ms
        {
            return Err(AuthorityError::Expired);
        }
        Ok(())
    }
}
impl AuthorityClient {
    pub fn authorize_born_offline_dispatch_checked_until_v1(
        &self,
        request: BornOfflineDispatchRequestV1,
        deadline: Instant,
        mut current: impl FnMut() -> Result<()>,
    ) -> Result<AuthenticatedBornOfflineDispatchV1> {
        current()?;
        request.validate()?;
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
            let wall = now_ms()?;
            if Instant::now() >= deadline || wall < wall_floor || wall >= d.admission_expires_at_ms
            {
                return Err(AuthorityError::Expired);
            }
            Ok(())
        };
        let state = super::born_offline_witness_v1::lock_born_session_until(
            &self.session,
            deadline,
            &mut checked,
        )?;
        let session = state
            .as_ref()
            .filter(|s| s.receipt.is_some())
            .ok_or(AuthorityError::SessionRequired)?;
        let mutation = AuthorityMutation::AuthorizeBornOfflineDispatchV1(Box::new(request.clone()));
        let response = self.call_with_inner_checked(
            |exporter| {
                let proof = crate::session::proof(
                    &session.key,
                    (
                        &session.request.session_id,
                        &session.request.disclosure,
                        session.request.writer_epoch,
                    ),
                    exporter,
                    &mutation,
                )?;
                Ok(WireRequest::AuthorizeBornOfflineDispatchV1 {
                    request: Box::new(request.clone()),
                    authentication: BornOfflineTransportAuthenticationV1::OriginalWriterSessionV1 {
                        proof,
                    },
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
            || admission.original_writer_session.disclosure != session.request.disclosure
            || admission.original_writer_session.session_id != session.request.session_id
        {
            return Err(AuthorityError::Authentication);
        }
        self.check_committed_head(
            &d.expected_head,
            &admission.committed_head,
            mutation,
            admission.admitted_at_ms,
            Some(admission.original_writer_session.session_id.clone()),
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
impl AuthorityServer {
    pub(super) fn serve_born_dispatch_v1(
        &self,
        peer: &str,
        exporter: &[u8; 32],
        request: &BornOfflineDispatchRequestV1,
        authentication: &BornOfflineTransportAuthenticationV1,
        deadline: Instant,
    ) -> Result<WireResponse> {
        #[cfg(all(feature = "born-offline-witness-owner", target_os = "linux"))]
        {
            if !self.is_born_offline_server_v1() {
                return Err(AuthorityError::Permission);
            }
            let current = crate::offline_witness_v1::CurrentOfflineWitnessWindowV1::capture(
                request.dispatch.reviewed_at_ms,
                request.dispatch.admission_expires_at_ms,
                deadline,
            )?;
            self.journal
                .commit_born_dispatch_v1(
                    peer,
                    request,
                    authentication,
                    exporter,
                    &self.tls.certificate_digest,
                    &current,
                )
                .map(|a| WireResponse::BornOfflineDispatchV1(Box::new(a)))
        }
        #[cfg(not(all(feature = "born-offline-witness-owner", target_os = "linux")))]
        {
            let _ = (peer, exporter, request, authentication, deadline);
            Err(AuthorityError::Permission)
        }
    }
}
