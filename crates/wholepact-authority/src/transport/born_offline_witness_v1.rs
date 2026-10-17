//! Dedicated actual mTLS bridge for native born offline origins. Neither the
//! legacy configured owner nor the generic mutation endpoint admits this route.
use super::*;
use crate::born_offline_owner_continuation_v1::BornOfflineTransportAuthenticationV1;
use crate::{born_offline_admission_v1::*, born_offline_witness_v1::*};
impl AuthorityClient {
    pub fn submit_born_offline_intent_v1(
        &self,
        request: BornOfflineReservationRequestV1,
        original_envelope: &[u8],
        export_template: OfflineAdmissionExportPlan,
        deadline: Instant,
    ) -> Result<BornOfflineDeliveryV1> {
        self.submit_born_offline_intent_checked_until_v1(
            request,
            original_envelope,
            export_template,
            deadline,
            || Ok(()),
        )
    }
    pub fn submit_born_offline_intent_checked_until_v1(
        &self,
        request: BornOfflineReservationRequestV1,
        original_envelope: &[u8],
        export_template: OfflineAdmissionExportPlan,
        deadline: Instant,
        mut current: impl FnMut() -> Result<()>,
    ) -> Result<BornOfflineDeliveryV1> {
        current()?;
        crate::validate_born_offline_intent_delivery_size_v1(
            &request,
            original_envelope,
            &export_template,
        )?;
        let lookup = BornOfflineDeliveryLookupV1::from_request(&request)?;
        self.check_born_delivery_scope(&lookup)?;
        if original_envelope.is_empty()
            || original_envelope.len() > crate::offline_witness_v1::MAX_ENVELOPE_HEX / 2
        {
            return Err(AuthorityError::Limit);
        }
        let state = lock_born_session_until(&self.session, deadline, &mut current)?;
        let session = state
            .as_ref()
            .filter(|s| s.receipt.is_some())
            .ok_or(AuthorityError::SessionRequired)?;
        let response = self.call_with_inner_checked(
            |exporter| {
                let mut wire = BornOfflineWitnessRequestV1 {
                    request: request.clone(),
                    original_envelope_hex: hex::encode(original_envelope),
                    export_template: export_template.clone(),
                    authentication: BornOfflineTransportAuthenticationV1::OriginalWriterSessionV1 {
                        proof: protocol::WriterSessionProof {
                            session_id: String::new(),
                            tag: String::new(),
                        },
                    },
                };
                let mutation = AuthorityMutation::ReserveBornOfflineV1(Box::new(wire.record()?));
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
                wire.authentication =
                    BornOfflineTransportAuthenticationV1::OriginalWriterSessionV1 { proof };
                Ok(WireRequest::SubmitBornOfflineIntentV1(Box::new(wire)))
            },
            Some(deadline),
            &mut current,
        )?;
        current()?;
        let delivery = self.check_born_delivery(response, &lookup)?;
        let mut expected = export_template;
        expected.sequence = delivery.body.delivery.export_plan.sequence;
        let base = &delivery.body.delivery;
        if base.export_plan != expected
            || base.authorization_id != request.reservation.intent.terms.authorization_id
            || base.admission_expires_at_ms != request.reservation.admission_expires_at_ms
            || base.reserved_at_ms < request.reservation.requested_at_ms
        {
            return Err(AuthorityError::Authentication);
        }
        Ok(delivery)
    }
    pub fn recover_born_offline_delivery_v1(
        &self,
        original: BornOfflineDeliveryLookupV1,
        deadline: Instant,
    ) -> Result<BornOfflineDeliveryV1> {
        self.recover_born_offline_delivery_checked_until_v1(original, deadline, || Ok(()))
    }
    pub fn recover_born_offline_delivery_checked_until_v1(
        &self,
        original: BornOfflineDeliveryLookupV1,
        deadline: Instant,
        mut current: impl FnMut() -> Result<()>,
    ) -> Result<BornOfflineDeliveryV1> {
        current()?;
        self.check_born_delivery_scope(&original)?;
        let response = self.call_with_inner_checked(
            |_| Ok(WireRequest::RecoverBornOfflineDeliveryV1(original.clone())),
            Some(deadline),
            &mut current,
        )?;
        current()?;
        let delivery = self.check_born_delivery(response, &original)?;
        if !delivery.recovered_original() {
            return Err(AuthorityError::Authentication);
        }
        Ok(delivery)
    }
    fn check_born_delivery_scope(&self, original: &BornOfflineDeliveryLookupV1) -> Result<()> {
        original.validate()?;
        if original.original.account_id != self.account
            || original.original.network_profile_id != self.network
        {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
    pub(super) fn check_born_delivery(
        &self,
        response: WireResponse,
        expected: &BornOfflineDeliveryLookupV1,
    ) -> Result<BornOfflineDeliveryV1> {
        let WireResponse::BornOfflineDeliveryV1(body) = response else {
            return Err(AuthorityError::Authentication);
        };
        let ciphertext = body.validate()?;
        if body.origin != *expected
            || body.delivery.witness_id != self.witness
            || body.delivery.witness_account_policy_digest != self.policy_digest
        {
            return Err(AuthorityError::Authentication);
        }
        Ok(BornOfflineDeliveryV1 {
            body: *body,
            ciphertext,
        })
    }
}
impl AuthorityServer {
    /// Opens only an already native-installed original OS-user namespace. This
    /// never creates a key/session/mailbox and cannot adopt an archive or arbitrary
    /// legacy connection. The resulting server has a dedicated read/submit route.
    #[cfg(all(feature = "born-offline-witness-owner", target_os = "linux"))]
    pub fn for_born_offline_witness_v1(
        configuration: crate::BornOfflineWitnessConfigurationV1,
        tls: ServerTls,
    ) -> Result<Self> {
        let owner=crate::born_offline_retry_v1::configured_born_witness::ConfiguredBornOfflineWitnessV1::configure(configuration,&tls.certificate_digest)?;
        Self::from_configured_born_offline_v1(owner, tls)
    }
    #[cfg(all(feature = "born-offline-witness-owner", target_os = "linux"))]
    pub(crate) fn from_configured_born_offline_v1(
        owner: crate::born_offline_retry_v1::configured_born_witness::ConfiguredBornOfflineWitnessV1,
        tls: ServerTls,
    ) -> Result<Self> {
        owner.require_server_certificate(&tls.certificate_digest)?;
        let journal = Arc::clone(&owner.journal);
        let mut server = Self::new(journal, tls);
        server.born_offline_witness = Some(Arc::new(std::sync::Mutex::new(owner)));
        Ok(server)
    }
    pub(super) fn is_born_offline_server_v1(&self) -> bool {
        #[cfg(all(feature = "born-offline-witness-owner", target_os = "linux"))]
        {
            self.born_offline_witness.is_some()
        }
        #[cfg(not(all(feature = "born-offline-witness-owner", target_os = "linux")))]
        {
            false
        }
    }
    pub(super) fn serve_born_offline_intent_v1(
        &self,
        peer: &str,
        exporter: &[u8; 32],
        request: &BornOfflineWitnessRequestV1,
        deadline: Instant,
    ) -> Result<WireResponse> {
        #[cfg(all(feature = "born-offline-witness-owner", target_os = "linux"))]
        {
            let owner = self
                .born_offline_witness
                .as_ref()
                .ok_or(AuthorityError::Permission)?;
            owner
                .lock()
                .map_err(|_| AuthorityError::Storage)?
                .submit(
                    peer,
                    exporter,
                    &self.tls.certificate_digest,
                    request,
                    deadline,
                )
                .map(|body| WireResponse::BornOfflineDeliveryV1(Box::new(body)))
        }
        #[cfg(not(all(feature = "born-offline-witness-owner", target_os = "linux")))]
        {
            let _ = (peer, exporter, request, deadline);
            Err(AuthorityError::Permission)
        }
    }
    pub(super) fn serve_born_offline_recovery_v1(
        &self,
        peer: &str,
        lookup: &BornOfflineDeliveryLookupV1,
        deadline: Instant,
    ) -> Result<WireResponse> {
        #[cfg(all(feature = "born-offline-witness-owner", target_os = "linux"))]
        {
            let owner = self
                .born_offline_witness
                .as_ref()
                .ok_or(AuthorityError::Permission)?;
            owner
                .lock()
                .map_err(|_| AuthorityError::Storage)?
                .recover(peer, lookup, deadline)
                .map(|body| WireResponse::BornOfflineDeliveryV1(Box::new(body)))
        }
        #[cfg(not(all(feature = "born-offline-witness-owner", target_os = "linux")))]
        {
            let _ = (peer, lookup, deadline);
            Err(AuthorityError::Permission)
        }
    }
}

// Waiting on another in-flight request cannot silently outlive cancellation or
// acquire a renewed window. The generic client mutex policy remains unchanged.
pub(super) fn lock_born_session_until<'a, T>(
    mutex: &'a std::sync::Mutex<T>,
    deadline: Instant,
    current: &mut impl FnMut() -> Result<()>,
) -> Result<std::sync::MutexGuard<'a, T>> {
    loop {
        require_before_caller_deadline(deadline)?;
        current()?;
        match mutex.try_lock() {
            Ok(guard) => {
                require_before_caller_deadline(deadline)?;
                current()?;
                require_before_caller_deadline(deadline)?;
                return Ok(guard);
            }
            Err(std::sync::TryLockError::Poisoned(_)) => {
                return Err(AuthorityError::SessionRequired);
            }
            Err(std::sync::TryLockError::WouldBlock) => {
                let remaining = caller_remaining_at(deadline, Instant::now())?;
                std::thread::sleep(remaining.min(Duration::from_millis(5)));
            }
        }
    }
}
#[cfg(test)]
mod cancellation_tests {
    use super::*;
    #[test]
    fn cancellation_during_session_wait_never_acquires_session() {
        let mutex = std::sync::Mutex::new(());
        let _held = mutex.lock().unwrap();
        let mut calls = 0;
        let mut current = || {
            calls += 1;
            if calls >= 2 {
                Err(AuthorityError::Permission)
            } else {
                Ok(())
            }
        };
        assert!(matches!(
            lock_born_session_until(
                &mutex,
                Instant::now() + Duration::from_secs(1),
                &mut current
            ),
            Err(AuthorityError::Permission)
        ));
        assert_eq!(calls, 2);
    }
    #[test]
    fn slow_currentness_callback_cannot_extend_the_session_deadline() {
        let mutex = std::sync::Mutex::new(());
        let deadline = Instant::now() + Duration::from_millis(10);
        let mut calls = 0;
        let mut current = || {
            calls += 1;
            if calls == 2 {
                std::thread::sleep(Duration::from_millis(20));
            }
            Ok(())
        };
        assert!(lock_born_session_until(&mutex, deadline, &mut current).is_err());
        assert!(mutex.try_lock().is_ok());
    }
    #[test]
    fn cancellation_after_session_acquisition_and_expired_deadline_fail_closed() {
        let mutex = std::sync::Mutex::new(());
        let mut calls = 0;
        let mut current = || {
            calls += 1;
            if calls >= 2 {
                Err(AuthorityError::Permission)
            } else {
                Ok(())
            }
        };
        assert!(matches!(
            lock_born_session_until(
                &mutex,
                Instant::now() + Duration::from_secs(1),
                &mut current
            ),
            Err(AuthorityError::Permission)
        ));
        assert!(mutex.try_lock().is_ok());
        assert!(lock_born_session_until(&mutex, Instant::now(), &mut || Ok(())).is_err());
    }
}
