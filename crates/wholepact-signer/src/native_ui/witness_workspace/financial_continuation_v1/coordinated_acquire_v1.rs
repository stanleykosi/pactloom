//! One exact Acquire on the already retained restricted writer client. The
//! exporter request/key exists only inside the maintained transport kernel.
//! No retry, new client, private source audit or action conversion is exposed.
use super::*;
use crate::account::birth::enrollment::roster_v2::financial_source_v1::FinancialOperationSourcePinV1;
use crate::native_peer::PeerProcess;
use wholepact_authority::durable_financial_continuation_v1::AuthenticatedFinancialContinuationHistoryV1;
use wholepact_financial_coordinator_origin::SignerAcquireFinalV1;

pub(in crate::native_ui) enum CoordinatedAcquireFailureV1 {
    KnownNoEffect(Error),
    Uncertain {
        error: Error,
        receipt: Option<wholepact_authority::WriterSessionReceipt>,
    },
}
impl CoordinatedAcquireFailureV1 {
    pub(in crate::native_ui) fn attempted(&self) -> bool {
        matches!(self, Self::Uncertain { .. })
    }
}

fn disclosure_digest(disclosure: &WitnessDisclosureDescriptor) -> Result<String> {
    wholepact_core::proposal::canonical_digest(
        "wholepact:coordinated-original-financial-disclosure:v1",
        disclosure,
    )
    .map_err(|_| Error::InvalidData)
}
impl FinancialWitnessCustodyV1 {
    /// The caller consumes the private Ready owner and Final together and keeps
    /// this SAME client through every returned error until actual joined cleanup.
    /// Method entry is uncertainty, not evidence that a session key was created.
    pub(in crate::native_ui) fn acquire_coordinated_once_v1(
        &self,
        source: &PreparedOriginalFinancialSourceV1,
        owner: &FinancialWitnessCustodyV1,
        host: &PeerProcess,
        history: &AuthenticatedFinancialContinuationHistoryV1,
        pin: &FinancialOperationSourcePinV1,
        final_action: SignerAcquireFinalV1,
    ) -> std::result::Result<
        (wholepact_authority::WriterSessionReceipt, Instant),
        CoordinatedAcquireFailureV1,
    > {
        use CoordinatedAcquireFailureV1::KnownNoEffect;
        let uncertain = |error| CoordinatedAcquireFailureV1::Uncertain {
            error,
            receipt: None,
        };
        let disclosure = owner.client.disclosure_descriptor();
        let check = || -> Result<()> {
            final_action.check_current()?;
            source.check_coordinated_acquire_final_source_pin_v1(
                pin,
                &disclosure,
                &owner.certificate_digest,
                host,
                &final_action,
            )?;
            final_action.check_current()?;
            Ok(())
        };
        check().map_err(KnownNoEffect)?;
        let presentation = final_action.presentation();
        presentation
            .validate()
            .map_err(|_| KnownNoEffect(Error::ReviewMismatch))?;
        let facts = &presentation.facts;
        let request = history.continuation_request();
        let record = history.continuation_record();
        let validate_retained = || -> Result<()> {
            if self.owner
                || !owner.owner
                || self.certificate_digest != facts.writer_certificate_digest
                || owner.certificate_digest != facts.owner_certificate_digest
                || self.client.disclosure_descriptor() != disclosure
                || history.disclosure() != &disclosure
                || pin.continuation_request() != request
                || pin.terms() != &record.terms
                || facts.owner_disclosure_digest != disclosure_digest(&disclosure)?
                || facts.writer_disclosure_digest != facts.owner_disclosure_digest
                || facts.writer_disclosure_json
                    != serde_json::to_string(&disclosure).map_err(|_| Error::InvalidData)?
                || facts.continuation_request_json
                    != serde_json::to_string(request).map_err(|_| Error::InvalidData)?
                || facts.authenticated_history_digest != history.history_digest()
                || facts.authenticated_snapshot_json
                    != serde_json::to_string(history.snapshot()).map_err(|_| Error::InvalidData)?
                || facts.expected_head_sequence != history.snapshot().head.sequence
                || facts.expected_head_digest != history.snapshot().head.digest
                || facts.writer_epoch != history.snapshot().writer_epoch
                || self.certificate_digest != history.snapshot().writer_certificate_digest
                || facts.acquire_operation_id
                    != record
                        .acquire_operation_id(request)
                        .map_err(|_| Error::ReviewMismatch)?
                || facts.terms_digest
                    != record
                        .terms
                        .intent_terms_digest()
                        .map_err(|_| Error::InvalidData)?
                || record.terms.scope.witness != disclosure
                || pin.coordinated_acquire_ready_digest_v1(presentation)?
                    != final_action.acquire_ready_digest()
            {
                return Err(Error::ReviewMismatch);
            }
            history
                .financial_continuation_online_permits_v1(&request.operation_id)
                .map_err(|_| Error::ReviewMismatch)?;
            Ok(())
        };
        validate_retained().map_err(KnownNoEffect)?;
        check().map_err(KnownNoEffect)?;
        let deadline = final_action
            .original_acquire_deadline()
            .min(final_action.original_source_deadline())
            .min(final_action.original_service_deadline());
        // From this exact method-entry boundary onward every error is uncertain.
        // The kernel may retain a key/request or receipt before returning Err.
        let receipt = self
            .client
            .acquire_financial_continuation_writer_v1_checked_until(
                history,
                &request.operation_id,
                deadline,
                || check().map_err(|_| wholepact_authority::AuthorityError::Permission),
            )
            .map_err(|_| uncertain(Error::Uncertain))?;
        // Preserve the actual authenticated receipt even if restriction wins
        // after transport. Receipt custody does not authorize a next action.
        let uncertain = |error| CoordinatedAcquireFailureV1::Uncertain {
            error,
            receipt: Some(receipt.clone()),
        };
        check().map_err(&uncertain)?;
        // The maintained kernel already authenticated the exporter/session and
        // resulting append head. Compare the returned receipt to the immutable
        // recipe again without allocating or exposing a replacement session.
        if receipt.writer_certificate_digest != facts.writer_certificate_digest
            || receipt.writer_epoch != facts.writer_epoch
            || receipt.reconciled_head != history.snapshot().head
            || receipt.reconciled_history_digest != facts.authenticated_history_digest
            || receipt.disclosure != disclosure
            || receipt.acquired_head.sequence
                != facts
                    .expected_head_sequence
                    .checked_add(1)
                    .ok_or_else(|| uncertain(Error::ReviewMismatch))?
            || receipt.expires_at_ms <= receipt.acquired_at_ms
            || receipt.expires_at_ms > record.terms.valid_until_ms
        {
            return Err(uncertain(Error::ReviewMismatch));
        }
        check().map_err(&uncertain)?;
        // Capture once while this consumed Final is still current. Round wall
        // time upward so fractional milliseconds never extend receipt expiry.
        let now = Instant::now();
        let wall = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| uncertain(Error::Locked))?;
        let wall_ms = u64::try_from(wall.as_millis())
            .map_err(|_| uncertain(Error::Locked))?
            .checked_add(u64::from(wall.subsec_nanos() % 1_000_000 != 0))
            .ok_or_else(|| uncertain(Error::Locked))?;
        let remaining = receipt
            .expires_at_ms
            .checked_sub(wall_ms)
            .filter(|n| *n > 0)
            .ok_or_else(|| uncertain(Error::Locked))?;
        let original_writer_session_deadline = now
            .checked_add(std::time::Duration::from_millis(remaining))
            .ok_or_else(|| uncertain(Error::Locked))?
            .min(final_action.original_source_deadline())
            .min(final_action.original_service_deadline());
        check().map_err(&uncertain)?;
        if Instant::now() >= original_writer_session_deadline {
            return Err(uncertain(Error::Locked));
        }
        Ok((receipt, original_writer_session_deadline))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn coordinated_acquire_no_receipt_after_entry_remains_uncertain() {
        let failure = CoordinatedAcquireFailureV1::Uncertain {
            error: Error::Uncertain,
            receipt: None,
        };
        assert!(failure.attempted());
        assert!(matches!(
            failure,
            CoordinatedAcquireFailureV1::Uncertain { receipt: None, .. }
        ));
    }

    #[test]
    fn coordinated_acquire_method_entry_failure_is_not_key_creation_proof() {
        let before = CoordinatedAcquireFailureV1::KnownNoEffect(Error::ReviewMismatch);
        let entered = CoordinatedAcquireFailureV1::Uncertain {
            error: Error::Locked,
            receipt: None,
        };
        assert!(!before.attempted());
        assert!(entered.attempted());
    }
}
