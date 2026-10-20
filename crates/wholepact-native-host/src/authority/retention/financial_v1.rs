//! Financial-only exact source-A/source-B/union retention approvals.
//! Inert Engine context pins are not consent. No recovery permission is exposed.
use super::*;
use wholepact_protocol::authorization::retention::SignedCandidateContext;

const ROLES: [&str; 3] = ["source A", "source B", "union"];
#[derive(Default)]
struct Approved {
    signed: [Option<SignedRetentionScope>; 3],
    transaction: Option<TransactionRetentionScope>,
    handoff: Option<serde_json::Value>,
}
pub(crate) struct NativeFinancialRetentionConsentV1 {
    contexts: [SignedCandidateContext; 3],
    terminal: Terminal,
    held: Held,
    approved: Mutex<Approved>,
}
pub(crate) struct FrozenNativeFinancialRetentionConsentV1 {
    contexts: [SignedCandidateContext; 3],
    held: Held,
    approved: Approved,
}
fn exact<T: serde::Serialize>(left: &T, right: &T) -> bool {
    match (serde_json::to_value(left), serde_json::to_value(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}
fn role(contexts: &[SignedCandidateContext; 3], scope: &SignedRetentionScope) -> Option<usize> {
    contexts.iter().position(|context| exact(context, &scope.context))
}
fn distinct(contexts: &[SignedCandidateContext; 3]) -> bool {
    !exact(&contexts[0], &contexts[1]) && !exact(&contexts[0], &contexts[2]) && !exact(&contexts[1], &contexts[2])
}
fn copy_signed(scope: &SignedRetentionScope) -> SignedRetentionScope {
    SignedRetentionScope { context: scope.context.clone(), signature_set_digest: scope.signature_set_digest.clone() }
}
fn copy_transaction(scope: &TransactionRetentionScope) -> TransactionRetentionScope {
    TransactionRetentionScope { signed_scope: copy_signed(&scope.signed_scope), signed_result_id: scope.signed_result_id.clone(), signed_request_digest: scope.signed_request_digest.clone(), signed_candidate_digest: scope.signed_candidate_digest.clone() }
}
fn handoff_value(scope: &SubmissionHandoffScope<'_>) -> serde_json::Value {
    serde_json::json!({"retained":scope.retained,"descriptor":scope.descriptor,"backend":scope.backend,"destination_journal_identity":scope.destination_journal_identity})
}
impl Authority {
    pub(crate) fn financial_retention_consent_v1(&self, pinned: &wholepact_engine::FinancialRetentionContextsV1) -> Result<NativeFinancialRetentionConsentV1> {
        let sources=pinned.source_contexts();
        let contexts=[sources[0].clone(),sources[1].clone(),pinned.union_context().clone()];
        if !distinct(&contexts) { return Err(Error::Invalid); }
        for context in &contexts { self.principal(&context.principal_id)?; }
        Ok(NativeFinancialRetentionConsentV1 { contexts, terminal:self.terminal.clone(), held:self.fence.acquire(now()?.checked_add(900).ok_or(Error::Invalid)?)?, approved:Mutex::new(Approved::default()) })
    }
}
impl NativeFinancialRetentionConsentV1 {
    fn confirm(&self, action: &str, role: &str, detail: &impl serde::Serialize) -> bool {
        if self.held.check().is_err() { return false; }
        let Ok(encoded)=serde_json::to_string_pretty(detail) else { return false; };
        self.terminal.confirm(&format!("Approve {action} for this EXACT scope?\nFinancial role: {role}\n{encoded}\nUsable spend signatures or transaction bytes remain in encrypted local journals. This is separate from original signer approval and does not itself authorize network submission. A failed or interrupted operation can leave durable intent; preserve the exact original keys and journals. Scope changes require a new command and approval. Permission ends with this command, lock/revoke or the original 15-minute ceiling; later prompts do not refresh it.")).is_ok() && self.held.check().is_ok()
    }
    pub(crate) fn freeze_for_dispatch(self) -> Result<FrozenNativeFinancialRetentionConsentV1> {
        self.held.check()?;
        let approved=self.approved.into_inner().map_err(|_|Error::Permission)?;
        if approved.signed.iter().any(Option::is_none) || approved.transaction.is_none() || approved.handoff.is_none() { return Err(Error::Permission); }
        self.held.check()?;
        Ok(FrozenNativeFinancialRetentionConsentV1 { contexts:self.contexts, held:self.held, approved })
    }
}
impl SignedRetentionConsent for NativeFinancialRetentionConsentV1 {
    fn permits(&self, scope: &SignedRetentionScope) -> bool {
        if self.held.check().is_err() { return false; }
        let Some(index)=role(&self.contexts,scope) else { return false; };
        let Ok(mut approved)=self.approved.lock() else { return false; };
        if let Some(prior)=&approved.signed[index] { return exact(prior,scope) && self.held.check().is_ok(); }
        if !self.confirm("retain exact usable signatures",ROLES[index],scope) { return false; }
        approved.signed[index]=Some(copy_signed(scope));
        self.held.check().is_ok()
    }
}
impl TransactionRetentionConsent for NativeFinancialRetentionConsentV1 {
    fn permits(&self, scope: &TransactionRetentionScope) -> bool {
        if self.held.check().is_err() || role(&self.contexts,&scope.signed_scope)!=Some(2) { return false; }
        let Ok(mut approved)=self.approved.lock() else { return false; };
        if !approved.signed[2].as_ref().is_some_and(|prior|exact(prior,&scope.signed_scope)) { return false; }
        if let Some(prior)=&approved.transaction { return exact(prior,scope) && self.held.check().is_ok(); }
        if !self.confirm("extract/read and retain exact complete transaction","union",scope) { return false; }
        approved.transaction=Some(copy_transaction(scope));
        self.held.check().is_ok()
    }
}
impl SubmissionHandoffConsent for NativeFinancialRetentionConsentV1 {
    fn permits(&self, scope: &SubmissionHandoffScope<'_>) -> bool {
        if self.held.check().is_err() || role(&self.contexts,&scope.retained.signed_scope)!=Some(2) { return false; }
        let Ok(mut approved)=self.approved.lock() else { return false; };
        if !approved.signed[2].as_ref().is_some_and(|prior|exact(prior,&scope.retained.signed_scope)) || !approved.transaction.as_ref().is_some_and(|prior|exact(prior,scope.retained)) { return false; }
        let detail=handoff_value(scope);
        if let Some(prior)=&approved.handoff { return prior==&detail && self.held.check().is_ok(); }
        if !self.confirm("copy exact retained transaction to the named local submission journal","union",&detail) { return false; }
        approved.handoff=Some(detail);
        self.held.check().is_ok()
    }
}
impl FrozenNativeFinancialRetentionConsentV1 {
    pub(crate) fn valid_until_unix_seconds(&self) -> u64 { self.held.expires }
}
impl SignedRetentionConsent for FrozenNativeFinancialRetentionConsentV1 {
    fn permits(&self, scope: &SignedRetentionScope) -> bool {
        self.held.check().is_ok() && role(&self.contexts,scope).is_some_and(|index|self.approved.signed[index].as_ref().is_some_and(|prior|exact(prior,scope))) && self.held.check().is_ok()
    }
}
impl TransactionRetentionConsent for FrozenNativeFinancialRetentionConsentV1 {
    fn permits(&self, scope: &TransactionRetentionScope) -> bool {
        role(&self.contexts,&scope.signed_scope)==Some(2) && SignedRetentionConsent::permits(self,&scope.signed_scope) && self.approved.transaction.as_ref().is_some_and(|prior|exact(prior,scope)) && self.held.check().is_ok()
    }
}
impl SubmissionHandoffConsent for FrozenNativeFinancialRetentionConsentV1 {
    fn permits(&self, scope: &SubmissionHandoffScope<'_>) -> bool {
        TransactionRetentionConsent::permits(self,scope.retained) && self.approved.handoff.as_ref()==Some(&handoff_value(scope)) && self.held.check().is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn transaction(scope: &SignedRetentionScope) -> TransactionRetentionScope {
        TransactionRetentionScope {signed_scope:copy_signed(scope),signed_result_id:"signed-synthetic".into(),signed_request_digest:"08".repeat(32),signed_candidate_digest:"09".repeat(32)}
    }
    fn fixture() -> (NativeFinancialRetentionConsentV1,[SignedRetentionScope;3]) {
        let base=SignedCandidateContext {principal_id:"synthetic-principal".into(),candidate_id:"synthetic-candidate".into(),proof_job_id:"synthetic-job".into(),checkpoint_scope_digest:"01".repeat(32),proved_artifact_digest:"02".repeat(32),manifest_digest:"03".repeat(32),review_binding:"04".repeat(32),delivery_provenance_digest:"05".repeat(32),account_ids:vec![],local_operator:"synthetic".into(),purpose:"No artifact cache test".into(),retention_policy:"No retention".into()};
        let scopes=std::array::from_fn(|index| {
            let mut context=base.clone();
            context.delivery_provenance_digest=format!("{:064x}",index+1);
            context.account_ids=match index {0=>vec!["source-a".into()],1=>vec!["source-b".into()],_=>vec!["source-a".into(),"source-b".into()]};
            SignedRetentionScope {context,signature_set_digest:format!("{:064x}",index+20)}
        });
        let contexts=std::array::from_fn(|index|scopes[index].context.clone());
        let owner=NativeFinancialRetentionConsentV1 {contexts,terminal:Terminal::disconnected_for_test(),held:Arc::new(Fence::default()).acquire(now().unwrap()+900).unwrap(),approved:Mutex::new(Approved::default())};
        (owner,scopes)
    }
    #[test]
    fn financial_roles_require_exact_full_context_and_independent_approvals() {
        let (owner,scopes)=fixture();
        assert!(distinct(&owner.contexts));
        for (index,scope) in scopes.iter().enumerate() {
            assert_eq!(role(&owner.contexts,scope),Some(index));
            assert!(!SignedRetentionConsent::permits(&owner,scope));
            owner.approved.lock().unwrap().signed[index]=Some(copy_signed(scope));
            assert!(SignedRetentionConsent::permits(&owner,scope));
            let mut changed=copy_signed(scope);changed.signature_set_digest="ff".repeat(32);
            assert!(!SignedRetentionConsent::permits(&owner,&changed));
            changed=copy_signed(scope);changed.context.retention_policy.push_str(" changed");
            assert_eq!(role(&owner.contexts,&changed),None);
            assert!(!SignedRetentionConsent::permits(&owner,&changed));
        }
        assert!(owner.freeze_for_dispatch().is_err());
    }
    #[test]
    fn financial_transaction_is_union_only_and_cache_cannot_refresh_or_widen() {
        let (owner,scopes)=fixture();
        let mut transaction=transaction(&scopes[0]);
        for (index,scope) in scopes.iter().enumerate(){owner.approved.lock().unwrap().signed[index]=Some(copy_signed(scope));}
        transaction.signed_scope=copy_signed(&scopes[0]);
        owner.approved.lock().unwrap().transaction=Some(copy_transaction(&transaction));
        assert!(!TransactionRetentionConsent::permits(&owner,&transaction));
        transaction.signed_scope=copy_signed(&scopes[2]);
        owner.approved.lock().unwrap().transaction=Some(copy_transaction(&transaction));
        assert!(TransactionRetentionConsent::permits(&owner,&transaction));
        let mut changed=copy_transaction(&transaction);changed.signed_request_digest="ff".repeat(32);
        assert!(!TransactionRetentionConsent::permits(&owner,&changed));
        assert!(owner.freeze_for_dispatch().is_err());
        for revoked in [false,true] {
            let (mut owner,scopes)=fixture();owner.approved.lock().unwrap().signed[0]=Some(copy_signed(&scopes[0]));
            if revoked {owner.held.fence.state.lock().unwrap().blocked=true;} else {owner.held.expires=0;}
            assert!(!SignedRetentionConsent::permits(&owner,&scopes[0]));
        }
    }
    #[test]
    fn frozen_financial_retention_requires_all_roles_and_exact_union_handoff() {
        let (owner,scopes)=fixture();
        let tx=transaction(&scopes[2]);
        let descriptor=wholepact_chain::SubmissionDescriptor {operation_id:"synthetic-operation".into(),obligation_id:"synthetic-obligation".into(),proposal_id:"synthetic-proposal".into(),transaction_id:"10".repeat(32),bytes_sha256:"11".repeat(32),expiry_height:100,network:"test".into(),consensus_branch_id:0};
        let backend=wholepact_chain::BackendIdentity {source_id:"synthetic".into(),endpoint:"https://synthetic.invalid".into(),trust_profile:"synthetic only"};
        let scope=SubmissionHandoffScope {retained:&tx,descriptor:&descriptor,backend:&backend,destination_journal_identity:"synthetic-journal"};
        // Cache models only: a disconnected terminal cannot create approval.
        assert!(!SubmissionHandoffConsent::permits(&owner,&scope));
        {
            let mut cache=owner.approved.lock().unwrap();
            for (index,scope) in scopes.iter().enumerate(){cache.signed[index]=Some(copy_signed(scope));}
            cache.transaction=Some(copy_transaction(&tx));cache.handoff=Some(handoff_value(&scope));
        }
        assert!(SubmissionHandoffConsent::permits(&owner,&scope));
        let original_ceiling=owner.held.expires;
        let frozen=owner.freeze_for_dispatch().unwrap();
        assert_eq!(frozen.valid_until_unix_seconds(),original_ceiling);
        for scope in &scopes {assert!(SignedRetentionConsent::permits(&frozen,scope));}
        assert!(TransactionRetentionConsent::permits(&frozen,&tx));
        assert!(SubmissionHandoffConsent::permits(&frozen,&scope));
        let changed=SubmissionHandoffScope {destination_journal_identity:"different",..scope};
        assert!(!SubmissionHandoffConsent::permits(&frozen,&changed));
        let mut changed_backend=backend.clone();changed_backend.endpoint.push_str("/changed");
        let changed=SubmissionHandoffScope {retained:&tx,descriptor:&descriptor,backend:&changed_backend,destination_journal_identity:"synthetic-journal"};
        assert!(!SubmissionHandoffConsent::permits(&frozen,&changed));
        frozen.held.fence.state.lock().unwrap().blocked=true;
        assert!(!TransactionRetentionConsent::permits(&frozen,&tx));
        assert!(!SignedRetentionConsent::permits(&frozen,&scopes[0]));
    }

}
