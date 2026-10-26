//! One finite observation after actual SignCommitted. No action or clock issued.
use super::*;
use crate::{SignerFinancialResultSelectorV1, SignerReturnRequestDataV1, SignerSignCommittedV1,
    SignerSignExactPresentationV1, SignerV3PairEndpointV1, SignerV3SourceOpenedV1};

fn require_actual_selector(data:&SignerFinancialResultSelectorV1, exact:&SignerSignExactPresentationV1,
    committed:&SignerSignCommittedV1, endpoint:&SignerV3PairEndpointV1, opened:&SignerV3SourceOpenedV1)->Result<()> {
    data.validate()?; committed.validate()?; endpoint.validate()?; opened.validate()?;
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
        // Financial re-entry and original V3 delivery have distinct source
        // identities. Bind each to its own retained authenticated observation.
        || endpoint.source_identity_digest!=opened.source_identity_digest
        || endpoint.entry_presentation_digest!=opened.entry_presentation_digest
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
        require_actual_selector(&data,exact,committed,endpoint,self.v3_entry.original_source_observation()?)?;
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
        require_actual_selector(&data,exact,committed,endpoint,self.v3_entries[role.index()].original_source_observation()?)?;
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
        service.check()?; crate::channel::require_time(writer.min(slot.activate.retained_wall_deadline()?))?;
        let (exact,committed)=slot.activate.wallet.sign.return_predecessor()?;
        let endpoint=self.v3_entries[role.index()].pair.endpoint.as_ref().ok_or_else(||rejected("relay selector missing endpoint"))?;
        require_actual_selector(data,exact,committed,endpoint,self.v3_entries[role.index()].original_source_observation()?)?;
        if slot.activate.wallet.sign.selector_seen {return Err(rejected("relay selector replay"));}
        slot.activate.wallet.sign.selector_seen=true;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture()->(SignerFinancialResultSelectorV1,SignerSignExactPresentationV1,SignerSignCommittedV1,SignerV3PairEndpointV1,SignerV3SourceOpenedV1) {
        let read=crate::signer_return_data::tests::read();
        let request=SignerReturnRequestDataV1::parse_json(&read.facts.request_json).unwrap();
        let mut exact=crate::signer_sign_data::tests::exact();
        // Pure data join fixture, not a source/grant/retirement constructor.
        exact.facts.original.activation.facts.original.continuation_request_json=serde_json::json!({
            "account_id":request.account_id,"control":{"record":{"terms":{"scope":{"authorization":{
                "authorization_id":request.authorization_id,"fixed":request.fixed
            }}}}}}).to_string();
        let mut endpoint=crate::signer_v3_pair_data::tests::endpoint();
        endpoint.signer_process_instance=exact.actor.signer_process_instance.clone();
        endpoint.endpoint_digest=endpoint.calculate_endpoint_digest().unwrap();
        let opened=SignerV3SourceOpenedV1 {entry_presentation_digest:endpoint.entry_presentation_digest.clone(),
            source_identity_digest:endpoint.source_identity_digest.clone()};
        let data=SignerFinancialResultSelectorV1 {actor:exact.actor.clone(),source_identity_digest:exact.facts.original.activation.facts.original.source_identity_digest.clone(),
            sign_presentation_digest:exact.presentation_digest.clone(),signer_socket:endpoint.endpoint_path.clone(),request_json:read.facts.request_json};
        (data,exact,read.facts.signed,endpoint,opened)
    }
    #[test]
    fn actual_selector_preserves_closed_request_and_original_endpoint() {
        let (data,exact,signed,endpoint,opened)=fixture();
        require_actual_selector(&data,&exact,&signed,&endpoint,&opened).unwrap();
        let wrapper:serde_json::Value=serde_json::from_str(&data.selector_json().unwrap()).unwrap();
        assert_eq!(wrapper["version"],1);
        assert_eq!(wrapper["signer_socket"],endpoint.endpoint_path);
        assert_eq!(wrapper["request"],serde_json::from_str::<serde_json::Value>(&data.request_json).unwrap());
        assert_eq!(wrapper.as_object().unwrap().len(),3);
    }
    #[test]
    fn selector_cannot_replace_result_source_or_socket() {
        let (data,exact,signed,endpoint,opened)=fixture();
        for field in 0..4 {
            let mut bad=data.clone();
            match field {0=>bad.signer_socket="/tmp/different-original.sock".into(),1=>bad.source_identity_digest="ef".repeat(32),
                2=>bad.sign_presentation_digest="ef".repeat(32),_=>bad.actor.signer_process_instance="ef".repeat(32)}
            assert!(require_actual_selector(&bad,&exact,&signed,&endpoint,&opened).is_err());
        }
    }
    #[test]
    fn selector_cannot_replace_fixed_authorization_consent_or_account() {
        let (data,exact,signed,endpoint,opened)=fixture();
        for field in 0..4 {
            let mut request=SignerReturnRequestDataV1::parse_json(&data.request_json).unwrap();
            match field {0=>request.fixed.proposal_digest="ef".repeat(32),1=>request.authorization_id="other-authorization".into(),
                2=>request.original_consent_ref="ef".repeat(32),_=>request.account_id="ef".repeat(32)}
            let mut bad=data.clone();bad.request_json=serde_json::to_string(&request).unwrap();
            assert!(require_actual_selector(&bad,&exact,&signed,&endpoint,&opened).is_err());
        }
    }
    #[test]
    fn selector_rejects_unknown_request_fields_and_relative_or_control_paths() {
        let (mut data,_,_,_,_)=fixture();
        let mut request:serde_json::Value=serde_json::from_str(&data.request_json).unwrap();
        request["signature_bytes"]=serde_json::json!("not-allowed");
        data.request_json=request.to_string();assert!(data.validate().is_err());
        let (mut data,_,_,_,_)=fixture();
        for path in ["relative.sock","/tmp/line\n.sock"] {data.signer_socket=path.into();assert!(data.validate().is_err());}
    }

    #[test]
    fn distinct_financial_and_delivery_sources_join_without_relabelling() {
        let (data,exact,signed,endpoint,opened)=fixture();
        // Ordinary metadata only, not produced custody or a native Final.
        // This is the exact former predicate: it rejects the valid two-domain
        // fixture. The old test concealed it by overwriting the V3 identity.
        assert_ne!(data.source_identity_digest,endpoint.source_identity_digest);
        let old_cross_domain_rejection=data.source_identity_digest!=endpoint.source_identity_digest;
        assert!(old_cross_domain_rejection);
        assert_eq!(data.source_identity_digest,exact.facts.original.activation.facts.original.source_identity_digest);
        assert_eq!(endpoint.source_identity_digest,opened.source_identity_digest);
        require_actual_selector(&data,&exact,&signed,&endpoint,&opened).unwrap();
        let mut substituted=data.clone();substituted.source_identity_digest=opened.source_identity_digest.clone();
        assert!(require_actual_selector(&substituted,&exact,&signed,&endpoint,&opened).is_err());
    }

    #[test]
    fn selector_binds_each_original_v3_observation_field_independently() {
        let (data,exact,signed,endpoint,opened)=fixture();
        for field in 0..4 {
            let mut changed_endpoint=endpoint.clone();let mut changed_opened=opened.clone();
            match field {
                0=>changed_opened.source_identity_digest="ef".repeat(32),
                1=>changed_opened.entry_presentation_digest="ef".repeat(32),
                2=>changed_endpoint.source_identity_digest="ef".repeat(32),
                _=>changed_endpoint.entry_presentation_digest="ef".repeat(32),
            }
            // A recomputed valid endpoint digest must not erase retained-source
            // provenance. Both altered objects remain individually valid DTOs.
            changed_endpoint.endpoint_digest=changed_endpoint.calculate_endpoint_digest().unwrap();
            changed_endpoint.validate().unwrap();changed_opened.validate().unwrap();
            assert!(require_actual_selector(&data,&exact,&signed,&changed_endpoint,&changed_opened).is_err());
        }
    }

    #[test]
    fn selector_join_is_bound_to_actual_source_domains_and_retained_callers() {
        let delivery=include_str!("../../wholepact-signer/src/account/birth/enrollment/roster_v2/prepared_delivery_v3/coordinated_source_entry_v1.rs");
        let financial=include_str!("../../wholepact-signer/src/consent_journal/financial_coordinated_public_pin_v2.rs");
        let entry=include_str!("../../wholepact-signer/src/account/birth/enrollment/roster_v2/financial_source_v1/coordinated_source_entry_v1.rs");
        let binding=include_str!("../../wholepact-signer/src/consent_journal/financial_profile_v1.rs");
        assert!(delivery.contains("\"wholepact:coordinated-original-delivery-source:v1\""));
        assert!(delivery.contains("hex::encode(crate::vault::random::<32>()?)"));
        assert!(financial.contains("\"wholepact:original-financial-source:v1\""));
        assert!(financial.contains("&(genesis, &original_rows_digest, random_id()?)"));
        assert!(entry.contains("journal.prepare_coordinated_entry_source_binding_v2(genesis, &admission)?"));
        assert!(entry.contains("let identity = binding.identity_digest().to_owned();"));
        assert!(binding.contains("pub(crate) fn identity_digest(&self) -> &str { &self.source_digest }"));
        let source=include_str!("financial_selector_origin.rs").split("#[cfg(test)]").next().unwrap();
        assert!(source.contains("data.source_identity_digest!=original.source_identity_digest"));
        assert!(!source.contains("data.source_identity_digest!=endpoint.source_identity_digest"));
        for call in [
            "require_actual_selector(&data,exact,committed,endpoint,self.v3_entry.original_source_observation()?)?;",
            "require_actual_selector(&data,exact,committed,endpoint,self.v3_entries[role.index()].original_source_observation()?)?;",
            "require_actual_selector(data,exact,committed,endpoint,self.v3_entries[role.index()].original_source_observation()?)?;",
        ] {assert_eq!(source.matches(call).count(),1);}
        let entries=include_str!("signer_v3_source_entry_origin.rs");
        let accessor="pub(super) fn original_source_observation(&self) -> Result<&SignerV3SourceOpenedV1> {\n        self.observation.as_ref().ok_or_else(|| rejected(\"selector missing original V3 source observation\"))\n    }";
        assert_eq!(entries.matches(accessor).count(),3);
        // Existing currentness/replay gates still precede the unchanged send or
        // accepted observation; this metadata join creates neither permission.
        assert_eq!(source.matches(".selector_seen {return Err(rejected(").count(),3);
        assert_eq!(source.matches("self.core.check_action_restrictions()?;").count(),2);
        assert!(source.contains("if self.restricted||*actual!=role||data.actor.signer_role!=role"));
    }
}
