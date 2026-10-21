//! One finite observation after actual SignCommitted. No action or clock issued.
use super::*;
use crate::{SignerFinancialResultSelectorV1, SignerReturnRequestDataV1, SignerSignCommittedV1,
    SignerSignExactPresentationV1, SignerV3PairEndpointV1};

fn require_actual_selector(data:&SignerFinancialResultSelectorV1, exact:&SignerSignExactPresentationV1,
    committed:&SignerSignCommittedV1, endpoint:&SignerV3PairEndpointV1)->Result<()> {
    data.validate()?; committed.validate()?; endpoint.validate()?;
    let request=SignerReturnRequestDataV1::parse_json(&data.request_json)?;
    let original=&exact.facts.original.activation.facts.original;
    let continuation:serde_json::Value=serde_json::from_str(&original.continuation_request_json)
        .map_err(|_|rejected("selector original continuation JSON"))?;
    let scope=continuation.pointer("/control/record/terms/scope")
        .ok_or_else(||rejected("selector original continuation scope"))?;
    let fixed=serde_json::to_value(&request.fixed).map_err(|_|rejected("selector fixed encoding"))?;
    if data.actor!=exact.actor || data.sign_presentation_digest!=exact.presentation_digest
        || committed.sign_presentation_digest!=exact.presentation_digest
        || committed.fixed_identity_digest!=exact.facts.original.fixed_identity_digest
        || data.source_identity_digest!=original.source_identity_digest
        || data.source_identity_digest!=endpoint.source_identity_digest
        || data.actor.signer_process_instance!=endpoint.signer_process_instance
        || data.signer_socket!=endpoint.endpoint_path
        || request.authorization_id!=committed.authorization_id
        || request.original_consent_ref!=committed.original_consent_ref
        || continuation.get("account_id").and_then(|v|v.as_str())!=Some(request.account_id.as_str())
        || scope.pointer("/authorization/fixed")!=Some(&fixed)
        || scope.pointer("/authorization/authorization_id").and_then(|v|v.as_str())!=Some(request.authorization_id.as_str())
    {return Err(rejected("selector replaced actual signed original"));}
    Ok(())
}
impl SignerFinancialWorkflowOriginV1 {
    pub fn report_financial_result_selector(&mut self, request_json:String)->Result<()> {
        self.core.check_action_restrictions()?;
        self.activate.wallet_predecessor()?.0.wallet_bounds()?;
        let (exact,committed)=self.activate.wallet.sign.return_predecessor()?;
        let endpoint=self.v3_entry.pair.endpoint.as_ref().ok_or_else(||rejected("selector before original endpoint"))?;
        let data=SignerFinancialResultSelectorV1 {actor:exact.actor.clone(),
            source_identity_digest:exact.facts.original.activation.facts.original.source_identity_digest.clone(),
            sign_presentation_digest:exact.presentation_digest.clone(), signer_socket:endpoint.endpoint_path.clone(),request_json};
        require_actual_selector(&data,exact,committed,endpoint)?;
        if self.activate.wallet.sign.selector_seen {return Err(rejected("selector already consumed"));}
        // Latch before the one nonblocking send: uncertainty cannot authorize retry.
        self.activate.wallet.sign.selector_seen=true;
        self.send(&Packet::FinancialResultSelector{role:self.target,data})
    }
}
impl CoordinatorFinancialEndpointV1 {
    pub(super) fn receive_financial_result_selector(&mut self,packet:Packet)->Result<CoordinatorFinancialEventV1> {
        let Packet::FinancialResultSelector{role,data}=packet else{return Err(rejected("wrong selector packet"))};
        self.core.check_action_restrictions()?;
        let slot=self.slots[role.index()].as_mut().ok_or_else(||rejected("selector missing source"))?;
        slot.activate.wallet_predecessor()?.0.wallet_bounds()?;
        let (exact,committed)=slot.activate.wallet.sign.return_predecessor()?;
        let endpoint=self.v3_entries[role.index()].pair.endpoint.as_ref().ok_or_else(||rejected("selector missing endpoint"))?;
        if data.actor.signer_role!=role {return Err(rejected("selector role mismatch"));}
        require_actual_selector(&data,exact,committed,endpoint)?;
        if slot.activate.wallet.sign.selector_seen {return Err(rejected("selector replay"));}
        slot.activate.wallet.sign.selector_seen=true;
        Ok(CoordinatorFinancialEventV1::FinancialResultSelector{role,data})
    }
}
impl HostFinancialWorkflowRelayV1 {
    pub(super) fn up_financial_result_selector(&mut self,role:Target,packet:&Packet)->Result<bool> {
        let Packet::FinancialResultSelector{role:actual,data}=packet else{return Err(rejected("wrong relay selector"))};
        if self.restricted||*actual!=role||data.actor.signer_role!=role {return Err(rejected("selector restricted or changed role"));}
        let slot=self.slots[role.index()].as_mut().ok_or_else(||rejected("relay selector missing source"))?;
        let (_,_,service,writer)=slot.activate.wallet_predecessor()?;
        service.check()?; crate::channel::require_time(writer)?;
        let (exact,committed)=slot.activate.wallet.sign.return_predecessor()?;
        let endpoint=self.v3_entries[role.index()].pair.endpoint.as_ref().ok_or_else(||rejected("relay selector missing endpoint"))?;
        require_actual_selector(data,exact,committed,endpoint)?;
        if slot.activate.wallet.sign.selector_seen {return Err(rejected("relay selector replay"));}
        slot.activate.wallet.sign.selector_seen=true;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture()->(SignerFinancialResultSelectorV1,SignerSignExactPresentationV1,SignerSignCommittedV1,SignerV3PairEndpointV1) {
        let read=crate::signer_return_data::tests::read();
        let request=SignerReturnRequestDataV1::parse_json(&read.facts.request_json).unwrap();
        let mut exact=crate::signer_sign_data::tests::exact();
        // Pure data join fixture, not a source/grant/retirement constructor.
        exact.facts.original.activation.facts.original.continuation_request_json=serde_json::json!({
            "account_id":request.account_id,"control":{"record":{"terms":{"scope":{"authorization":{
                "authorization_id":request.authorization_id,"fixed":request.fixed
            }}}}}}).to_string();
        let mut endpoint=crate::signer_v3_pair_data::tests::endpoint();
        endpoint.source_identity_digest=exact.facts.original.activation.facts.original.source_identity_digest.clone();
        endpoint.signer_process_instance=exact.actor.signer_process_instance.clone();
        endpoint.endpoint_digest=endpoint.calculate_endpoint_digest().unwrap();
        let data=SignerFinancialResultSelectorV1 {actor:exact.actor.clone(),source_identity_digest:endpoint.source_identity_digest.clone(),
            sign_presentation_digest:exact.presentation_digest.clone(),signer_socket:endpoint.endpoint_path.clone(),request_json:read.facts.request_json};
        (data,exact,read.facts.signed,endpoint)
    }
    #[test]
    fn actual_selector_preserves_closed_request_and_original_endpoint() {
        let (data,exact,signed,endpoint)=fixture();
        require_actual_selector(&data,&exact,&signed,&endpoint).unwrap();
        let wrapper:serde_json::Value=serde_json::from_str(&data.selector_json().unwrap()).unwrap();
        assert_eq!(wrapper["version"],1);
        assert_eq!(wrapper["signer_socket"],endpoint.endpoint_path);
        assert_eq!(wrapper["request"],serde_json::from_str::<serde_json::Value>(&data.request_json).unwrap());
        assert_eq!(wrapper.as_object().unwrap().len(),3);
    }
    #[test]
    fn selector_cannot_replace_result_source_or_socket() {
        let (data,exact,signed,endpoint)=fixture();
        for field in 0..4 {
            let mut bad=data.clone();
            match field {0=>bad.signer_socket="/tmp/different-original.sock".into(),1=>bad.source_identity_digest="ef".repeat(32),
                2=>bad.sign_presentation_digest="ef".repeat(32),_=>bad.actor.signer_process_instance="ef".repeat(32)}
            assert!(require_actual_selector(&bad,&exact,&signed,&endpoint).is_err());
        }
    }
    #[test]
    fn selector_cannot_replace_fixed_authorization_consent_or_account() {
        let (data,exact,signed,endpoint)=fixture();
        for field in 0..4 {
            let mut request=SignerReturnRequestDataV1::parse_json(&data.request_json).unwrap();
            match field {0=>request.fixed.proposal_digest="ef".repeat(32),1=>request.authorization_id="other-authorization".into(),
                2=>request.original_consent_ref="ef".repeat(32),_=>request.account_id="ef".repeat(32)}
            let mut bad=data.clone();bad.request_json=serde_json::to_string(&request).unwrap();
            assert!(require_actual_selector(&bad,&exact,&signed,&endpoint).is_err());
        }
    }
    #[test]
    fn selector_rejects_unknown_request_fields_and_relative_or_control_paths() {
        let (mut data,_,_,_)=fixture();
        let mut request:serde_json::Value=serde_json::from_str(&data.request_json).unwrap();
        request["signature_bytes"]=serde_json::json!("not-allowed");
        data.request_json=request.to_string();assert!(data.validate().is_err());
        let (mut data,_,_,_)=fixture();
        for path in ["relative.sock","/tmp/line\n.sock"] {data.signer_socket=path.into();assert!(data.validate().is_err());}
    }
}
