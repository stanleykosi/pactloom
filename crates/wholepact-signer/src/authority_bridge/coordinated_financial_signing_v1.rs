//! Same-writer one-use SignExact reservation and maintained protected PCZT use.
//! Actual committed results survive postcommit restriction/acknowledgement loss.
use super::*;
use crate::consent_journal::ApprovedCoordinatedFinancialSpendConsentV1;
use crate::native_peer::PeerProcess;
use wholepact_wallet::wallet::protected_sync::{ProtectedWalletSync,key_use::{HeldWalletKeyUse,HeldWalletPermission,WalletKeyUseError,WalletKeyUseScope,WalletKeyUseTicket}};

pub(crate) struct CoordinatedFinancialSignFailureV1 {
    pub(crate) committed: Option<crate::authority_bridge::AuthorizationCommit>,
    pub(crate) error: BridgeError,
}
impl CoordinatedFinancialSignFailureV1 {
    pub(crate) fn before_result(error:BridgeError)->Self{Self{committed:None,error}}
}
pub(crate) struct ReservedCoordinatedFinancialAuthorizationV1<'a>{
    source:&'a PreparedOriginalFinancialSourceV1,
    host:&'a PeerProcess,
    approved:ApprovedCoordinatedFinancialSpendConsentV1,
    request:RetainedAuthorizationRequest,
    permit:AuthenticatedPermit,
}
pub(crate) fn reserve_coordinated_financial_authorization_v1<'a>(
    source:&'a PreparedOriginalFinancialSourceV1,host:&'a PeerProcess,
    approved:ApprovedCoordinatedFinancialSpendConsentV1,client:&AuthorityClient,
    history:&AuthenticatedFinancialContinuationHistoryV1,active:&AuthenticatedWriterSession,
)->Result<ReservedCoordinatedFinancialAuthorizationV1<'a>>{
    source.check_coordinated_sign_v1(host,&approved).map_err(|_|BridgeError::Permission)?;
    let facts=&approved.presentation().facts;
    let binding=approved.record().financial_binding_v1().ok_or(BridgeError::Binding)?;
    if approved.record().terms().receipt.expires_at_ms>active.receipt().expires_at_ms
        || binding.reviewed_head!=history.snapshot().head || binding.disclosure!=*history.disclosure()
        || facts.authenticated_history_digest!=history.history_digest()
        || facts.authenticated_snapshot_json!=serde_json::to_string(history.snapshot()).map_err(|_|BridgeError::Binding)?
        || facts.active_receipt_json!=serde_json::to_string(active.receipt()).map_err(|_|BridgeError::Binding)?
        || client.disclosure_descriptor()!=*history.disclosure()
        || serde_json::to_string(history.continuation_request()).map_err(|_|BridgeError::Binding)?!=facts.original.activation.facts.original.continuation_request_json
    {return Err(BridgeError::Binding);}
    history.require_financial_continuation_session_v1(&history.continuation_request().operation_id,active)?;
    let journal=source.financial_journal().map_err(|_|BridgeError::Permission)?;
    let original=journal.record_coordinated_financial_release_v1(
        &mut *source.financial_binding().map_err(|_|BridgeError::Permission)?,&approved)?;
    let request=request_from_financial_original_v1(&original,history.continuation_record(),approved.fixed().private_proved_pczt_bytes())?;
    journal.retain_coordinated_financial_request_v1(
        &mut *source.financial_binding().map_err(|_|BridgeError::Permission)?,&approved,&request)?;
    // Both conservative release and immutable request COMMIT precede any
    // reservation bytes. The exact same retained client supplies the exporter.
    let expected=request.reservation.request_digest()?;
    let check=||->Result<()>{
        source.check_coordinated_sign_v1(host,&approved).map_err(|_|BridgeError::Permission)?;
        if request.reservation.request_digest()?!=expected{return Err(BridgeError::Binding);}
        approved.check_current()?;
        Ok(())
    };
    check()?;
    let permit=client.reserve_financial_continuation_v1_checked_until(history,active,request.reservation.clone(),approved.original_sign_deadline(),
        ||check().map_err(|_|wholepact_authority::AuthorityError::Permission))?;
    check()?;
    drop(check);
    journal.retain_coordinated_financial_permit_v1(
        &mut *source.financial_binding().map_err(|_|BridgeError::Permission)?,&approved,&permit)?;
    Ok(ReservedCoordinatedFinancialAuthorizationV1{source,host,approved,request,permit})
}
impl ReservedCoordinatedFinancialAuthorizationV1<'_>{
    fn check(&self)->Result<()>{
        self.source.check_coordinated_sign_v1(self.host,&self.approved).map_err(|_|BridgeError::Permission)?;
        self.permit.matches_request(&self.request.reservation)?;
        self.approved.check_current()?;
        Ok(())
    }
    fn key_current(&self)->Result<()>{
        self.source.check_coordinated_sign_key_use_v1(self.host,&self.approved).map_err(|_|BridgeError::Permission)?;
        self.approved.check_current()?;
        Ok(())
    }
    pub(crate) fn sign_and_retain(self,wallet:&mut ProtectedWalletSync,ticket:&WalletKeyUseTicket)
        ->std::result::Result<crate::authority_bridge::AuthorizationCommit,CoordinatedFinancialSignFailureV1>{
        let mut committed=None;
        let result=(||->Result<()>{
            self.check()?;
            let account=self.source.coordinated_sign_account_v1(self.host,&self.approved).map_err(|_|BridgeError::Permission)?;
            // Reuse the verified SAME WalletObserve FVK; deriving it through
            // account.fvk() would derive a SpendingKey before Started/key gate.
            let fvk=self.approved.authenticated_fvk().clone();
            let terms=self.approved.record().terms();
            let policy=terms.wallet_key_use_policy.as_ref().ok_or(BridgeError::Permission)?;
            let permission=CoordinatedWalletPermission{reserved:&self,fvk:&fvk};
            wallet.with_key_use_guard(&permission,ticket,&fvk,policy,terms.transaction_expiry_height,
                |held|self.sign_held(held,account,&fvk,&mut committed))
        })();
        if let Err(error)=result{return Err(CoordinatedFinancialSignFailureV1{committed,error});}
        if let Err(error)=self.approved.finish(){return Err(CoordinatedFinancialSignFailureV1{committed,error:error.into()});}
        committed.ok_or_else(||CoordinatedFinancialSignFailureV1::before_result(BridgeError::Uncertain))
    }
    fn sign_held(&self,wallet:&HeldWalletKeyUse<'_>,account:&crate::account::DedicatedAccount,fvk:&orchard::keys::FullViewingKey,
        committed:&mut Option<crate::authority_bridge::AuthorizationCommit>)->Result<()>{
        self.check()?;
        wallet.check_current()?;
        let(parsed,indices)=signing::verify_exact_signing_material_kernel(self.approved.record(),self.approved.fixed(),self.approved.inputs(),&self.request,wallet,fvk)?;
        self.check()?;
        wallet.check_current()?;
        let journal=self.source.financial_journal().map_err(|_|BridgeError::Permission)?;
        journal.begin_coordinated_financial_key_use_v1(&mut *self.source.financial_binding().map_err(|_|BridgeError::Permission)?,&self.approved,&self.permit)?;
        // Started is durably settled before the key fence can exist. There is
        // deliberately no constructor that resumes from an old Started row.
        let check=||->Result<()>{self.key_current()?;wallet.check_current()?;Ok(())};
        check()?;
        let fence=FinancialKeyUseFenceV1{source:FinancialKeyUseSourceV1::Coordinated{source:self.source,host:self.host,approved:&self.approved},account,check:&check};
        let mut signed=None;
        let mut signing_error=None;
        let admitted=self.approved.execute_key_use(||{
            match signing::sign_exact_result_kernel(self.approved.record(),self.approved.inputs(),&self.request,account,&fence,parsed,&indices,&check){
                Ok(result)=>{signed=Some(result);Ok(())},
                Err(error)=>{signing_error=Some(error);Err(std::io::Error::other("coordinated exact key use failed"))},
            }
        });
        if admitted.is_err(){return Err(signing_error.unwrap_or(BridgeError::Permission));}
        let result=signed.ok_or(BridgeError::Uncertain)?;
        check()?;
        let retained=journal.retain_coordinated_financial_result_v1(
            &mut *self.source.financial_binding().map_err(|_|BridgeError::Permission)?,&self.approved,&self.permit,&result)?;
        // This slot is outside the wallet callback. Its postcheck can deny R but
        // cannot erase knowledge of the actual result commit or permit retry.
        *committed=Some(retained.commit);
        if let Some(error)=retained.after_commit{return Err(error);}
        check()?;
        Ok(())
    }
}
struct CoordinatedWalletPermission<'a,'b>{reserved:&'a ReservedCoordinatedFinancialAuthorizationV1<'b>,fvk:&'a orchard::keys::FullViewingKey}
impl HeldWalletPermission for CoordinatedWalletPermission<'_,'_>{
    fn check_current(&self,scope:&WalletKeyUseScope<'_>)->std::result::Result<(),WalletKeyUseError>{
        self.reserved.key_current().map_err(|_|WalletKeyUseError::Permission)?;
        let t=self.reserved.approved.record().terms();
        if scope.account_id!=t.account_id || scope.authenticated_fvk.to_bytes()!=self.fvk.to_bytes()
            || t.wallet_key_use_policy.as_ref()!=Some(scope.policy)
            || scope.transaction_expiry_height!=t.transaction_expiry_height
            || scope.source.source_id!=scope.policy.source_id || scope.source.endpoint!=scope.policy.endpoint
        {return Err(WalletKeyUseError::Permission);}
        Ok(())
    }
}
