//! The same retained writer TLS owner serves SignRead and the later reservation.
//! No key/configuration/client getter or substitute native decision is exposed.
use super::*;
use crate::account::birth::enrollment::roster_v2::financial_source_v1::CoordinatedSignReadSourcePinV1;
use crate::native_peer::PeerProcess;
use wholepact_authority::{AuthenticatedWriterSession, WriterSessionReceipt};
use wholepact_authority::durable_financial_continuation_v1::AuthenticatedFinancialContinuationHistoryV1;
use wholepact_financial_coordinator_origin::SignerSignReadFinalV1;

impl FinancialWitnessCustodyV1 {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::native_ui) fn read_coordinated_sign_once_v1(
        &self, source:&PreparedOriginalFinancialSourceV1, host:&PeerProcess,
        activated:&AccountSnapshot, receipt:&WriterSessionReceipt,
        read:&SignerSignReadFinalV1,
    )->Result<(AuthenticatedFinancialContinuationHistoryV1,AuthenticatedWriterSession,CoordinatedSignReadSourcePinV1)> {
        read.check_current()?;
        let p=read.presentation();
        let original=&p.facts.original.activation.facts.original;
        if self.owner || self.certificate_digest!=original.acquired.writer_certificate_digest
            || activated.active_writer_session.as_ref()!=Some(receipt)
            || activated.pending_writer_session.is_some()
            || receipt.session_id!=p.facts.original.activated.session_id
            || activated.head.digest!=p.facts.original.activated.head_digest
            || activated.head.sequence!=p.facts.original.activated.head_sequence
        {return Err(Error::ReviewMismatch);}
        let pin=source.prepare_coordinated_sign_read_pin_v1(host,read)?;
        if self.client.disclosure_descriptor()!=pin.terms().scope.witness
            || self.certificate_digest!=pin.terms().scope.authorization.writer_certificate_digest
        {return Err(Error::ReviewMismatch);}
        let deadline=read.original_read_deadline().min(read.original_source_deadline())
            .min(read.original_service_deadline()).min(read.original_writer_session_deadline());
        let check=||->Result<()>{
            read.check_current()?;
            source.check_coordinated_sign_read_pin_v1(&pin,host,read)?;
            read.check_current()?;
            Ok(())
        };
        check()?;
        // SAME retained writer, not the owner client and not a fresh TLS import.
        let history=self.client.financial_continuation_history_v1_checked_until(
            &pin.continuation_request().operation_id,deadline,
            ||check().map_err(|_|wholepact_authority::AuthorityError::Permission),
        ).map_err(|_|Error::Uncertain)?;
        check()?;
        if history.continuation_request()!=pin.continuation_request()
            || history.disclosure()!=&self.client.disclosure_descriptor()
            || history.snapshot()!=activated
            || !history.contains_head(&activated.head)
        {return Err(Error::ReviewMismatch);}
        history.financial_continuation_online_permits_v1(&pin.continuation_request().operation_id)
            .map_err(|_|Error::ReviewMismatch)?;
        check()?;
        let active=self.client.verify_financial_continuation_session_v1_checked_until(
            &history,&pin.continuation_request().operation_id,deadline,
            ||check().map_err(|_|wholepact_authority::AuthorityError::Permission),
        ).map_err(|_|Error::Uncertain)?;
        check()?;
        if active.receipt()!=receipt || active.snapshot()!=activated
            || active.disclosure()!=history.disclosure() || active.history_digest()!=history.history_digest()
        {return Err(Error::ReviewMismatch);}
        history.require_financial_continuation_session_v1(&pin.continuation_request().operation_id,&active)
            .map_err(|_|Error::ReviewMismatch)?;
        check()?;
        Ok((history,active,pin))
    }
}

impl FinancialWitnessCustodyV1 {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::native_ui) fn sign_coordinated_once_v1(&self,source:&PreparedOriginalFinancialSourceV1,host:&PeerProcess,
        approved:crate::consent_journal::ApprovedCoordinatedFinancialSpendConsentV1,
        history:&AuthenticatedFinancialContinuationHistoryV1,active:&AuthenticatedWriterSession,
        wallet:&mut wholepact_wallet::wallet::protected_sync::ProtectedWalletSync,
        ticket:&wholepact_wallet::wallet::protected_sync::key_use::WalletKeyUseTicket)
        ->std::result::Result<crate::authority_bridge::AuthorizationCommit,crate::authority_bridge::financial_continuation_v1::CoordinatedFinancialSignFailureV1>{
        use crate::authority_bridge::{BridgeError,financial_continuation_v1::{reserve_coordinated_financial_authorization_v1,CoordinatedFinancialSignFailureV1}};
        if self.owner || self.certificate_digest!=approved.presentation().facts.original.activation.facts.original.acquired.writer_certificate_digest
            || self.client.disclosure_descriptor()!=*history.disclosure()
        {return Err(CoordinatedFinancialSignFailureV1::before_result(BridgeError::Permission));}
        reserve_coordinated_financial_authorization_v1(source,host,approved,&self.client,history,active)
            .map_err(CoordinatedFinancialSignFailureV1::before_result)?
            .sign_and_retain(wallet,ticket)
    }
}
