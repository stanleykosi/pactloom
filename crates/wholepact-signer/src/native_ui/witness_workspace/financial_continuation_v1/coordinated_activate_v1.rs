//! Distinct nominal ActivateRead and Activate on the SAME retained clients.
//! No credential reads, client construction, retry or wallet preparation.
use super::*;
use crate::account::birth::enrollment::roster_v2::financial_source_v1::FinancialOperationSourcePinV1;
use crate::native_peer::PeerProcess;
use wholepact_authority::durable_financial_continuation_v1::AuthenticatedFinancialContinuationHistoryV1;
use wholepact_authority::{OwnerControl, OwnerControlRequest, WriterSessionReceipt};
use wholepact_financial_coordinator_origin::{
    SignerActivateArmV1, SignerActivateFinalV1, SignerActivateReadFinalV1,
};

pub(in crate::native_ui) enum CoordinatedActivateFailureV1 {
    KnownNoEffect(Error),
    Uncertain(Error),
    /// An authenticated response is retained even if local revocation wins.
    Authenticated(AccountSnapshot, Error),
}

impl FinancialWitnessCustodyV1 {
    pub(in crate::native_ui) fn read_coordinated_activate_v1(
        &self,
        source: &PreparedOriginalFinancialSourceV1,
        writer: &FinancialWitnessCustodyV1,
        host: &PeerProcess,
        receipt: &WriterSessionReceipt,
        read: &SignerActivateReadFinalV1,
    ) -> Result<(
        AuthenticatedFinancialContinuationHistoryV1,
        OwnerControlRequest,
    )> {
        read.check_current()?;
        let disclosure = self.client.disclosure_descriptor();
        let original = &read.presentation().facts.original;
        if !self.owner
            || writer.owner
            || writer.certificate_digest != receipt.writer_certificate_digest
            || writer.client.disclosure_descriptor() != disclosure
            || receipt.disclosure != disclosure
            || original.acquired.session_id != receipt.session_id
            || original.acquired.acquired_head_sequence != receipt.acquired_head.sequence
            || original.acquired.acquired_head_digest != receipt.acquired_head.digest
        {
            return Err(Error::ReviewMismatch);
        }
        let pin = source.prepare_coordinated_activate_read_source_pin_v1(
            &disclosure,
            &self.certificate_digest,
            host,
            read,
        )?;
        let check = || -> Result<()> {
            read.check_current()?;
            source.check_coordinated_activate_read_source_pin_v1(
                &pin,
                &disclosure,
                &self.certificate_digest,
                host,
                read,
            )?;
            read.check_current()?;
            Ok(())
        };
        check()?;
        let history = self
            .client
            .financial_continuation_history_v1_checked_until(
                &pin.continuation_request().operation_id,
                read.original_read_deadline()
                    .min(read.original_source_deadline())
                    .min(read.original_service_deadline())
                    .min(read.original_writer_session_deadline()),
                || check().map_err(|_| wholepact_authority::AuthorityError::Permission),
            )
            .map_err(|_| Error::Uncertain)?;
        check()?;
        if history.continuation_request() != pin.continuation_request()
            || history.disclosure() != &disclosure
            || history.snapshot().pending_writer_session.as_ref() != Some(receipt)
            || history.snapshot().active_writer_session.is_some()
            || history.snapshot().head != receipt.acquired_head
            || history.snapshot().writer_epoch != receipt.writer_epoch
            || !history.contains_head(&receipt.acquired_head)
            || !history.contains_operation(
                &history
                    .continuation_record()
                    .acquire_operation_id(history.continuation_request())
                    .map_err(|_| Error::ReviewMismatch)?,
            )
            || !history.contains_head(&receipt.reconciled_head)
        {
            return Err(Error::ReviewMismatch);
        }
        history
            .financial_continuation_online_permits_v1(&pin.continuation_request().operation_id)
            .map_err(|_| Error::ReviewMismatch)?;
        let snapshot = history.snapshot();
        let request = OwnerControlRequest {
            operation_id: wholepact_core::proposal::canonical_digest(
                "wholepact:financial-native-activation-operation:v1",
                &(history.continuation_request(), &receipt.session_id),
            )
            .map_err(|_| Error::InvalidData)?,
            account_id: snapshot.account_id.clone(),
            network_profile_id: snapshot.network_profile_id.clone(),
            expected_head: snapshot.head.clone(),
            writer_epoch: snapshot.writer_epoch,
            control: OwnerControl::ActivateWriter {
                session_id: receipt.session_id.clone(),
            },
        };
        check()?;
        Ok((history, request))
    }

    pub(in crate::native_ui) fn prepare_coordinated_activate_pin_v1(
        &self,
        source: &PreparedOriginalFinancialSourceV1,
        writer: &FinancialWitnessCustodyV1,
        host: &PeerProcess,
        history: &AuthenticatedFinancialContinuationHistoryV1,
        request: &OwnerControlRequest,
        receipt: &WriterSessionReceipt,
        arm: &SignerActivateArmV1,
    ) -> Result<FinancialOperationSourcePinV1> {
        arm.check_current()?;
        self.match_coordinated_activation(writer, history, request, receipt, arm.presentation())?;
        let pin = source.prepare_coordinated_activate_source_pin_v1(
            &self.client.disclosure_descriptor(),
            &self.certificate_digest,
            host,
            arm,
        )?;
        if pin.continuation_request() != history.continuation_request()
            || pin.terms() != &history.continuation_record().terms
        {
            return Err(Error::ReviewMismatch);
        }
        arm.check_current()?;
        Ok(pin)
    }

    fn match_coordinated_activation(
        &self,
        writer: &FinancialWitnessCustodyV1,
        history: &AuthenticatedFinancialContinuationHistoryV1,
        request: &OwnerControlRequest,
        receipt: &WriterSessionReceipt,
        presentation: &wholepact_financial_coordinator_origin::SignerActivatePresentationV1,
    ) -> Result<()> {
        presentation.validate()?;
        let f = &presentation.facts;
        if !self.owner
            || writer.owner
            || self.certificate_digest != f.original.owner_certificate_digest
            || writer.certificate_digest != receipt.writer_certificate_digest
            || self.client.disclosure_descriptor() != receipt.disclosure
            || writer.client.disclosure_descriptor() != receipt.disclosure
            || history.disclosure() != &receipt.disclosure
            || history.snapshot().pending_writer_session.as_ref() != Some(receipt)
            || history.snapshot().active_writer_session.is_some()
            || history.snapshot().head != receipt.acquired_head
            || request.expected_head != receipt.acquired_head
            || request.writer_epoch != receipt.writer_epoch
            || request.operation_id
                != wholepact_core::proposal::canonical_digest(
                    "wholepact:financial-native-activation-operation:v1",
                    &(history.continuation_request(), &receipt.session_id),
                )
                .map_err(|_| Error::InvalidData)?
            || request.control
                != (OwnerControl::ActivateWriter {
                    session_id: receipt.session_id.clone(),
                })
            || f.activation_request_json
                != serde_json::to_string(request).map_err(|_| Error::InvalidData)?
            || f.original.continuation_request_json
                != serde_json::to_string(history.continuation_request())
                    .map_err(|_| Error::InvalidData)?
            || f.authenticated_history_digest != history.history_digest()
            || f.authenticated_snapshot_json
                != serde_json::to_string(history.snapshot()).map_err(|_| Error::InvalidData)?
            || f.activation_terms_digest != financial_activation_digest(history, request)?
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }

    pub(in crate::native_ui) fn activate_coordinated_once_v1(
        &self,
        source: &PreparedOriginalFinancialSourceV1,
        writer: &FinancialWitnessCustodyV1,
        host: &PeerProcess,
        history: &AuthenticatedFinancialContinuationHistoryV1,
        request: &OwnerControlRequest,
        receipt: &WriterSessionReceipt,
        pin: &FinancialOperationSourcePinV1,
        final_action: SignerActivateFinalV1,
    ) -> std::result::Result<AccountSnapshot, CoordinatedActivateFailureV1> {
        use CoordinatedActivateFailureV1::*;
        let disclosure = self.client.disclosure_descriptor();
        let check = || -> Result<()> {
            final_action.check_current()?;
            source.check_coordinated_activate_final_source_pin_v1(
                pin,
                &disclosure,
                &self.certificate_digest,
                host,
                &final_action,
            )?;
            final_action.check_current()?;
            Ok(())
        };
        check().map_err(KnownNoEffect)?;
        self.match_coordinated_activation(
            writer,
            history,
            request,
            receipt,
            final_action.presentation(),
        )
        .map_err(KnownNoEffect)?;
        if pin.continuation_request() != history.continuation_request()
            || pin.terms() != &history.continuation_record().terms
        {
            return Err(KnownNoEffect(Error::ReviewMismatch));
        }
        check().map_err(KnownNoEffect)?;
        // Transport entry is a conservative uncertainty boundary; never retry.
        let snapshot = self
            .client
            .activate_financial_continuation_writer_v1_checked_until(
                history,
                &history.continuation_request().operation_id,
                request,
                final_action
                    .original_activate_deadline()
                    .min(final_action.original_source_deadline())
                    .min(final_action.original_service_deadline())
                    .min(final_action.original_writer_session_deadline()),
                || check().map_err(|_| wholepact_authority::AuthorityError::Permission),
            )
            .map_err(|_| Uncertain(Error::Uncertain))?;
        if snapshot.active_writer_session.as_ref() != Some(receipt)
            || snapshot.pending_writer_session.is_some()
            || snapshot.writer_epoch != receipt.writer_epoch
            || Some(snapshot.head.sequence) != receipt.acquired_head.sequence.checked_add(1)
            || snapshot.account_id != request.account_id
            || snapshot.network_profile_id != request.network_profile_id
        {
            return Err(Authenticated(snapshot, Error::ReviewMismatch));
        }
        if let Err(error) = check() {
            return Err(Authenticated(snapshot, error));
        }
        Ok(snapshot)
    }
}
