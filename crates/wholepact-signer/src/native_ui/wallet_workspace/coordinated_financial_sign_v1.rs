//! Private child of the actual observed wallet owner. The same controller,
//! exact ticket and mathematical inputs move once into Sign; no reconstruction.
use super::*;
use crate::consent_journal::{ApprovedCoordinatedFinancialSpendConsentV1,PreparedCoordinatedFinancialSpendV1};
use crate::account::birth::enrollment::roster_v2::financial_source_v1::CoordinatedSignReadSourcePinV1;
use crate::authority_bridge::financial_continuation_v1::CoordinatedFinancialSignFailureV1;
use wholepact_authority::{AuthenticatedWriterSession,durable_financial_continuation_v1::AuthenticatedFinancialContinuationHistoryV1};
use wholepact_financial_coordinator_origin::SignerSignReadFinalV1;

pub(in crate::native_ui) struct PreparedCoordinatedSigningWalletV1 {
    wallet: FinancialWalletCustodyV1,
    original: SignerWalletOriginalV1,
    observed: SignerWalletObservedV1,
    original_source: Instant,
    original_service: Instant,
    original_writer: Instant,
}
impl ObservedCoordinatedFinancialWalletV1 {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::native_ui) fn prepare_sign_once_v1(self,source:&Arc<PreparedOriginalFinancialSourceV1>,host:&PeerProcess,
        pin:&CoordinatedSignReadSourcePinV1,read:&SignerSignReadFinalV1,fixed:Arc<wholepact_protocol::durable_proposal_v1::VerifiedFixedProposal>,
        history:&AuthenticatedFinancialContinuationHistoryV1,active:&AuthenticatedWriterSession)
        ->Result<(PreparedCoordinatedSigningWalletV1,PreparedCoordinatedFinancialSpendV1)>{
        read.check_current()?;
        if !Arc::ptr_eq(source,&self.wallet.source)
            || read.presentation().facts.original!=self.original
            || read.presentation().facts.observed!=self.report
            || read.original_source_deadline()!=self.original_source
            || read.original_service_deadline()!=self.original_service
            || read.original_writer_session_deadline()!=self.original_writer
            || self.wallet.ticket.is_none()
        {return Err(Error::ReviewMismatch);}
        self.wallet.identity.check_retained_owner_path().map_err(|_|Error::Verification)?;
        read.check_current()?;
        // Reuse only the actual opaque ticket retained by WalletObserve. Its
        // full observation commitment binds account, FVK, context and inputs.
        let ticket=self.wallet.ticket.as_ref().ok_or(Error::Unavailable)?;
        let evidence=ticket.evidence();
        let c=evidence.context();
        let tuples:Vec<_>=evidence.inputs().iter().map(|i|(i.input_id().to_owned(),hex::encode(i.nullifier()),i.value_zatoshis())).collect();
        let digest=observed_key_digest(
            &self.original.fixed_identity_digest,&self.original.configuration_digest,&self.report.wallet_review_digest,
            evidence.account_id(),&hex::encode(Sha256::digest(evidence.fvk().to_bytes())),
            &(c.tip_height,hex::encode(c.tip_hash_protocol),c.anchor_height,hex::encode(c.anchor_hash_protocol),hex::encode(c.anchor_root)),&tuples)?;
        if digest!=self.report.wallet_observation_digest {return Err(Error::ReviewMismatch);}
        let observed_fvk=evidence.fvk().clone();
        read.check_current()?;
        let prepared=source.prepare_coordinated_spend_v1(pin,host,read,fixed,self.inputs,&observed_fvk,history,active)?;
        read.check_current()?;
        Ok((PreparedCoordinatedSigningWalletV1{wallet:self.wallet,original:self.original,observed:self.report,
            original_source:self.original_source,original_service:self.original_service,original_writer:self.original_writer},prepared))
    }
}
impl PreparedCoordinatedSigningWalletV1 {
    pub(in crate::native_ui) fn sign_once_v1(mut self,writer:&crate::native_ui::witness_workspace::financial_continuation_v1::FinancialWitnessCustodyV1,
        host:&PeerProcess,approved:ApprovedCoordinatedFinancialSpendConsentV1,
        history:&AuthenticatedFinancialContinuationHistoryV1,active:&AuthenticatedWriterSession)
        ->std::result::Result<crate::authority_bridge::AuthorizationCommit,CoordinatedFinancialSignFailureV1>{
        let checks=(||->Result<()>{
            approved.check_current()?;
            if approved.presentation().facts.original!=self.original
                || approved.presentation().facts.observed!=self.observed
                || approved.original_deadlines()!=(self.original_source,self.original_service,self.original_writer)
            {return Err(Error::ReviewMismatch);}
            self.wallet.identity.check_retained_owner_path().map_err(|_|Error::Verification)?;
            approved.check_current()?;
            Ok(())
        })();
        if checks.is_err(){return Err(CoordinatedFinancialSignFailureV1::before_result(crate::authority_bridge::BridgeError::Permission));}
        let Some(ticket)=self.wallet.ticket.take() else {return Err(CoordinatedFinancialSignFailureV1::before_result(crate::authority_bridge::BridgeError::Permission));};
        writer.sign_coordinated_once_v1(&self.wallet.source,host,approved,history,active,&mut self.wallet.controller,&ticket)
    }
}

#[cfg(test)]
mod observed_binding_tests {
    use super::observed_key_digest;
    #[test]
    fn exact_actual_observation_commitment_is_maintained() {
        let context=(30,"tip".into(),20,"anchor".into(),"root".into());
        let inputs=vec![("input".into(),"nullifier".into(),7)];
        let digest=observed_key_digest("fixed","config","review","account","fvk",&context,&inputs).unwrap();
        let maintained=wholepact_core::proposal::canonical_digest("wholepact:coordinated-financial-wallet-observation:v1",
            &("fixed","config","review","account","fvk",&context,&inputs)).unwrap();
        assert_eq!(digest,maintained);
        for changed in 0..5 {
            let mut fields=["fixed","config","review","account","fvk"];
            fields[changed]="foreign";
            assert_ne!(digest,observed_key_digest(fields[0],fields[1],fields[2],fields[3],fields[4],&context,&inputs).unwrap());
        }
        for changed in 0..5 {
            let mut c=context.clone();
            match changed {0=>c.0+=1,1=>c.1="other".into(),2=>c.2+=1,3=>c.3="other".into(),_=>c.4="other".into()}
            assert_ne!(digest,observed_key_digest("fixed","config","review","account","fvk",&c,&inputs).unwrap());
        }
        for changed in 0..3 {
            let mut i=inputs.clone();
            match changed {0=>i[0].0="other".into(),1=>i[0].1="other".into(),_=>i[0].2+=1}
            assert_ne!(digest,observed_key_digest("fixed","config","review","account","fvk",&context,&i).unwrap());
        }
        assert_ne!(digest,observed_key_digest("fixed","config","review","account","fvk",&context,&[]).unwrap());
    }
}
