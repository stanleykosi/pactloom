//! Actual SignRead/source join and original account key-use restriction. The
//! source itself is never an action; every entry requires the nominal owner.
use super::*;
use crate::native_peer::PeerProcess;
use crate::consent_journal::{ApprovedCoordinatedFinancialSpendConsentV1, FinancialOperationJournalPinV1, PreparedCoordinatedFinancialSpendV1};
use wholepact_financial_coordinator_origin::SignerSignReadFinalV1;

pub(crate) struct CoordinatedSignReadSourcePinV1 {
    source: String,
    presentation: String,
    journal: FinancialOperationJournalPinV1,
}
impl CoordinatedSignReadSourcePinV1 {
    pub(crate) fn continuation_request(&self) -> &wholepact_authority::OwnerControlRequest { self.journal.continuation_request() }
    pub(crate) fn terms(&self) -> &FinancialContinuationTermsV1 { self.journal.terms() }
}
impl PreparedOriginalFinancialSourceV1 {
    fn check_sign_read(&self, host: &PeerProcess, read: &SignerSignReadFinalV1) -> Result<()> {
        read.check_current()?;
        let p = read.presentation();
        p.validate()?;
        let original = &p.facts.original.activation.facts.original;
        if !matches!(&self.lifetime, OriginalFinancialCustodyLifetimeV1::Coordinated(_))
            || original.source_identity_digest != self.identity
            || original.source_expires_at_ms != self.original_ceiling_ms
            || original.original_host_process_instance != host.instance()
            || read.original_source_deadline() != self.original_deadline
            || Instant::now() >= read.original_read_deadline()
            || Instant::now() >= read.original_writer_session_deadline()
            || Instant::now() >= read.original_service_deadline()
        { return Err(Error::ReviewMismatch); }
        self.check_coordinated_public_custody_v2(host)?;
        read.check_current()?;
        Ok(())
    }
    pub(crate) fn prepare_coordinated_sign_read_pin_v1(&self, host:&PeerProcess, read:&SignerSignReadFinalV1) -> Result<CoordinatedSignReadSourcePinV1> {
        self.check_sign_read(host, read)?;
        let journal = {
            let source = self.financial_binding()?;
            read.check_current()?;
            self.financial_journal()?.prepare_coordinated_sign_read_operation_pin_v1(&source, read)?
        };
        read.check_current()?;
        let original = &read.presentation().facts.original.activation.facts.original;
        if serde_json::to_string(journal.continuation_request()).map_err(|_| Error::InvalidData)? != original.continuation_request_json
            || journal.terms().intent_terms_digest().map_err(|_| Error::InvalidData)? != original.terms_digest
            || journal.terms().valid_until_ms != self.original_ceiling_ms
        { return Err(Error::ReviewMismatch); }
        let pin = CoordinatedSignReadSourcePinV1 { source:self.identity.clone(), presentation:read.presentation().presentation_digest.clone(), journal };
        self.check_coordinated_sign_read_pin_v1(&pin,host,read)?;
        Ok(pin)
    }
    pub(crate) fn check_coordinated_sign_read_pin_v1(&self,pin:&CoordinatedSignReadSourcePinV1,host:&PeerProcess,read:&SignerSignReadFinalV1)->Result<()> {
        self.check_sign_read(host,read)?;
        if pin.source != self.identity || pin.presentation != read.presentation().presentation_digest { return Err(Error::ReviewMismatch); }
        {
            let source=self.financial_binding()?;
            read.check_current()?;
            self.financial_journal()?.check_coordinated_sign_read_operation_pin_v1(&source,&pin.journal,read)?;
        }
        self.check_sign_read(host,read)
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_coordinated_spend_v1(&self,pin:&CoordinatedSignReadSourcePinV1,host:&PeerProcess,read:&SignerSignReadFinalV1,
        fixed:Arc<wholepact_protocol::durable_proposal_v1::VerifiedFixedProposal>,inputs:crate::manifest::ReviewInputs,
        observed_fvk:&orchard::keys::FullViewingKey,
        history:&wholepact_authority::durable_financial_continuation_v1::AuthenticatedFinancialContinuationHistoryV1,
        active:&wholepact_authority::AuthenticatedWriterSession)->Result<PreparedCoordinatedFinancialSpendV1> {
        self.check_coordinated_sign_read_pin_v1(pin,host,read)?;
        read.check_current()?;
        let account=self.retained.account.account();
        let prepared={
            let source=self.financial_binding()?;
            read.check_current()?;
            self.financial_journal()?.prepare_coordinated_financial_spend_v1(&source,read,account,fixed,inputs,observed_fvk,history,active)?
        };
        self.check_coordinated_sign_read_pin_v1(pin,host,read)?;
        Ok(prepared)
    }
    pub(crate) fn check_coordinated_sign_v1(&self,host:&PeerProcess,approved:&ApprovedCoordinatedFinancialSpendConsentV1)->Result<()> {
        approved.check_current()?;
        let p=approved.presentation();
        let original=&p.facts.original.activation.facts.original;
        if !matches!(&self.lifetime,OriginalFinancialCustodyLifetimeV1::Coordinated(_))
            || original.source_identity_digest!=self.identity
            || original.source_expires_at_ms!=self.original_ceiling_ms
            || original.original_host_process_instance!=host.instance()
            || Instant::now()>=self.original_deadline
        {return Err(Error::ReviewMismatch);}
        self.check_coordinated_public_custody_v2(host)?;
        approved.check_current()?;
        Ok(())
    }
    pub(crate) fn coordinated_sign_account_v1(&self,host:&PeerProcess,approved:&ApprovedCoordinatedFinancialSpendConsentV1)->Result<&crate::account::DedicatedAccount>{
        self.check_coordinated_sign_v1(host,approved)?;
        Ok(self.retained.account.account())
    }
    /// Entered key-use currentness only: no mutex, source replay, transaction or
    /// new capability. The original account/directory exclusion is already held.
    pub(crate) fn check_coordinated_sign_key_use_v1(&self,host:&PeerProcess,approved:&ApprovedCoordinatedFinancialSpendConsentV1)->Result<()> {
        approved.check_current()?;
        self.lifetime.check_connected()?;
        host.check_alive()?;
        self.retained.account.directory.check_retained_exclusion_current_v1()?;
        if immutable_file_revisions(&self.retained.account.directory)? != self.immutable {
            return Err(Error::ReviewMismatch);
        }
        let original=&approved.presentation().facts.original.activation.facts.original;
        if original.source_identity_digest!=self.identity || original.original_host_process_instance!=host.instance()
            || Instant::now()>=self.original_deadline {return Err(Error::ReviewMismatch);}
        approved.check_current()?;
        Ok(())
    }
}
