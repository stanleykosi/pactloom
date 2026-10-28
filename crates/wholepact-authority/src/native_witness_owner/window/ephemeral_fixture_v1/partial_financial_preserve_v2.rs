//! Test-only mixed-state preservation of the actual original installation.
//! The legacy completed-owner descriptor is unchanged and reused, not replaced.
//! No serialized flag, writer receipt, or native decision becomes authority.
use super::*;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PartialOriginalsV2 {
    version: u16,
    purpose: String,
    completed: OwnerControlRequest,
    unfinished_account: String,
    financial_original: Vec<u8>,
    baselines: Vec<PristineAccountBaselineV1>,
}

fn role_ids(completed: &str, unfinished: &str, baselines: &[PristineAccountBaselineV1]) -> Result<()> {
    crate::hash(completed)?;
    crate::hash(unfinished)?;
    let ids: std::collections::BTreeSet<_> = baselines.iter().map(|b| b.account_id.as_str()).collect();
    if completed == unfinished || baselines.len() != 2 || ids.len() != 2
        || ids.contains(completed) || !ids.contains(unfinished)
    { return Err(AuthorityError::InvalidBinding); }
    for baseline in baselines { crate::hash(&baseline.account_id)?; }
    Ok(())
}

fn audited_pristine(
    owner: &mut EphemeralNativeWitnessV1,
    account_id: &str,
    envelope: &[u8],
    selected_roster: bool,
) -> Result<PristineAccountBaselineV1> {
    if envelope.is_empty() || envelope.len() > crate::MAX_FRAME_BYTES { return Err(AuthorityError::Limit); }
    let owner_pin = crate::transport::certificate_digest(&CertificateDer::from(owner.owner_certificate.as_slice()));
    let signed: crate::pending_birth_signature::PendingBirthOwnerSignature =
        serde_json::from_slice(envelope).map_err(|_| AuthorityError::InvalidBinding)?;
    let verified = crate::pending_birth_signature::verify_pending_birth_owner_signature(&signed, &owner_pin)?;
    let journal = crate::witness_locator::open_born_history(owner.original_namespace_input(account_id)?)?;
    let head = {
        let connection = journal.connection.lock().map_err(|_| AuthorityError::Storage)?;
        let ledger = crate::journal::load(connection.connection())?;
        require_pre_v3_original_history(&ledger, selected_roster)?;
        let birth = crate::pending_birth_storage::read(connection.connection(), &ledger.policy)?
            .ok_or(AuthorityError::RecoveryRequired)?;
        if verified.request() != &birth.request
            || verified.certificate_digest() != birth.authenticated_owner_certificate_digest
            || verified.evidence_digest() != birth.owner_approval_evidence_digest
            || ledger.snapshot.account_id != account_id
        { return Err(AuthorityError::CorruptHistory); }
        ledger.snapshot.head
    };
    Ok(PristineAccountBaselineV1 {
        account_id: account_id.into(), head,
        original_signed_birth: String::from_utf8(envelope.to_vec()).map_err(|_| AuthorityError::InvalidBinding)?,
        original_source_commitment: original_source_commitment(&journal)?,
    })
}

fn audited_financial(
    owner: &mut EphemeralNativeWitnessV1,
    account_id: &str,
) -> Result<(OwnerControlRequest, OwnerControlRequest)> {
    let journal = crate::witness_locator::open_born_financial_history_v1(owner.original_namespace_input(account_id)?)?;
    let connection = journal.connection.lock().map_err(|_| AuthorityError::Storage)?;
    let ledger = crate::journal::load_financial_continuation_v1(connection.connection())?;
    if ledger.snapshot.account_id != account_id { return Err(AuthorityError::CorruptHistory); }
    let continuation = ledger.selected_financial_continuation_v1()?.ok_or(AuthorityError::Permission)?.clone();
    let delivery = ledger.selected_durable_delivery_admission_v2()?.ok_or(AuthorityError::Permission)?.clone();
    Ok((continuation, delivery))
}

impl EphemeralNativeWitnessV1 {
    /// Owner order is exact: the first has a completed original continuation;
    /// the second still has its authenticated four-event roster baseline.
    pub fn preserve_partial_financial_originals_v2(mut self, selected: &[String; 2]) -> Result<Vec<u8>> {
        require_selected_original_accounts(&self.durable_delivery.original_signed_births, selected)?;
        require_drained(self.listener.server_handles.load(Ordering::Acquire),
            self.listener.server_join_failed.load(Ordering::Acquire))?;
        if !self.window.can_select() || self.durable_delivery.historical_only {
            return Err(AuthorityError::Permission);
        }
        let (completed, _) = audited_financial(&mut self, &selected[0])?;
        let mut baselines = Vec::new();
        for (account, envelope) in self.durable_delivery.original_signed_births.clone() {
            if account == selected[0] { continue; }
            baselines.push(audited_pristine(&mut self, &account, &envelope, account == selected[1])?);
        }
        role_ids(&completed.account_id, &selected[1], &baselines)?;
        let mut saved = PartialOriginalsV2 { version:2, purpose:"partial-financial-originals-v2".into(),
            completed, unfinished_account:selected[1].clone(), financial_original:Vec::new(), baselines };
        if serde_json::to_vec(&saved).map_err(|_| AuthorityError::InvalidBinding)?.len() > 128 * 1024 {
            return Err(AuthorityError::Limit);
        }
        // This maintained consuming path checks original borrowers, preserves
        // the SAME installation, revokes the owner and releases the old socket.
        saved.financial_original = self.preserve_financial_originals_v1()?;
        let bytes = serde_json::to_vec(&saved).map_err(|_| AuthorityError::InvalidBinding)?;
        if bytes.len() > MAX_PRESERVED_BYTES { return Err(AuthorityError::Limit); }
        Ok(bytes)
    }

    pub fn reopen_partial_financial_originals_v2(bytes: &[u8]) -> Result<EphemeralPartialFinancialWitnessV2> {
        if bytes.is_empty() || bytes.len() > MAX_PRESERVED_BYTES { return Err(AuthorityError::Limit); }
        let saved: PartialOriginalsV2 = serde_json::from_slice(bytes).map_err(|_| AuthorityError::InvalidBinding)?;
        if saved.version != 2 || saved.purpose != "partial-financial-originals-v2" {
            return Err(AuthorityError::InvalidBinding);
        }
        role_ids(&saved.completed.account_id, &saved.unfinished_account, &saved.baselines)?;
        // Legacy reopening authenticates original installation/pins/financial
        // history and leaves every action historical-only. It is unchanged.
        let mut inner = Self::reopen_financial_originals_v1(&saved.financial_original)?;
        let (completed, delivery) = audited_financial(&mut inner, &saved.completed.account_id)?;
        if completed != saved.completed { return Err(AuthorityError::CorruptHistory); }
        for baseline in saved.baselines {
            let actual = audited_pristine(&mut inner, &baseline.account_id,
                baseline.original_signed_birth.as_bytes(), baseline.account_id == saved.unfinished_account)?;
            if serde_json::to_value(&actual).map_err(|_| AuthorityError::InvalidBinding)?
                != serde_json::to_value(&baseline).map_err(|_| AuthorityError::InvalidBinding)?
            { return Err(AuthorityError::CorruptHistory); }
            inner.durable_delivery.original_signed_births.insert(baseline.account_id, baseline.original_signed_birth.into_bytes());
        }
        require_selected_original_accounts(&inner.durable_delivery.original_signed_births,
            &[completed.account_id.clone(), saved.unfinished_account.clone()])?;
        // Actual authenticated original delivery is retained for shared-plan
        // comparison by the ordinary native issuer, never as a new decision.
        inner.durable_delivery.committed.insert(completed.account_id.clone(), delivery);
        Ok(EphemeralPartialFinancialWitnessV2 { inner, completed,
            unfinished_account:saved.unfinished_account, admission_pending:false, continuation_pending:false })
    }
}

/// No Deref, public inner, generic server, grant constructor or unwrapping path.
/// The completed owner is never given an admission or signing service.
pub struct EphemeralPartialFinancialWitnessV2 {
    inner: EphemeralNativeWitnessV1,
    completed: OwnerControlRequest,
    unfinished_account: String,
    admission_pending: bool,
    continuation_pending: bool,
}
// Inert eligibility comparison, not a native owner or permission issuer.
fn require_unfinished_financial_entry_v2(completed:&str, unfinished:&str,
    account:&str, request_account:&str, state:[bool;4])->Result<()> {
    if completed==unfinished || account!=unfinished || request_account!=account
        || state!=[true,false,false,true]
    {return Err(AuthorityError::Permission);}
    Ok(())
}
// Private lexical form scope. The only caller below has just reaudited the
// original exact delivery; native PREPARE and final consent remain unchanged.
// Drop restores historical-only on normal return, refusal and unwinding.
struct UnfinishedFinancialFormV2<'a> { inner:&'a mut EphemeralNativeWitnessV1 }
impl Drop for UnfinishedFinancialFormV2<'_> {
    fn drop(&mut self) {self.inner.durable_delivery.historical_only=true;}
}
impl EphemeralPartialFinancialWitnessV2 {
    /// Same installed credential custody, not a writer grant. Only the exact
    /// still-pristine second account may receive this test-only origin handle.
    pub fn unfinished_origin_v2(&mut self) -> Result<EphemeralWitnessOriginV1> {
        let account = self.unfinished_account.clone();
        let envelope = self.inner.durable_delivery.original_signed_births.get(&account)
            .ok_or(AuthorityError::Permission)?.clone();
        audited_pristine(&mut self.inner, &account, &envelope, true)?;
        self.inner.origin()
    }
    fn unfinished(&self, account: &str) -> Result<()> {
        if account != self.unfinished_account || account == self.completed.account_id {
            return Err(AuthorityError::Permission);
        }
        Ok(())
    }
    pub fn serve_original_delivery_bootstrap_history_v2(&mut self, account: &str) -> Result<EphemeralHistoryServerV1> {
        self.unfinished(account)?;
        let envelope = self.inner.durable_delivery.original_signed_births.get(account).ok_or(AuthorityError::Permission)?.clone();
        audited_pristine(&mut self.inner, account, &envelope, true)?;
        // Temporarily permit only this already-audited account's ordinary
        // source kernel; no shared mutable-capability server is exposed.
        self.inner.durable_delivery.historical_only = false;
        let result = self.inner.serve_original_delivery_bootstrap_history_v2(account);
        self.inner.durable_delivery.historical_only = true;
        result
    }
    pub fn start_exact_durable_delivery_admission_v2(&mut self, account: &str, request: &OwnerControlRequest) -> Result<()> {
        self.unfinished(account)?;
        if request.account_id != account { return Err(AuthorityError::Permission); }
        let envelope = self.inner.durable_delivery.original_signed_births.get(account).ok_or(AuthorityError::Permission)?.clone();
        audited_pristine(&mut self.inner, account, &envelope, true)?;
        self.inner.durable_delivery.historical_only = false;
        let result = self.inner.start_exact_durable_delivery_admission_v2(account, request);
        self.inner.durable_delivery.historical_only = true;
        self.admission_pending = result.is_ok();
        result
    }
    pub fn finish_exact_durable_delivery_admission_v2(&mut self) -> Result<()> {
        if !self.admission_pending { return Err(AuthorityError::Permission); }
        self.admission_pending = false;
        self.inner.finish_exact_durable_delivery_admission_v2()
    }
    pub fn serve_committed_durable_delivery_history_v2(&mut self, operation: &str) -> Result<EphemeralHistoryServerV1> {
        let request = self.inner.durable_delivery.committed.get(&self.unfinished_account).ok_or(AuthorityError::Permission)?;
        if request.operation_id != operation { return Err(AuthorityError::Permission); }
        self.inner.serve_committed_durable_delivery_history_v2(operation)
    }
    pub fn start_exact_financial_continuation_v1(&mut self, account: &str, request: &OwnerControlRequest) -> Result<()> {
        self.unfinished(account)?;
        require_unfinished_financial_entry_v2(&self.completed.account_id,
            &self.unfinished_account,account,&request.account_id,
            [self.inner.durable_delivery.historical_only,self.admission_pending,
             self.continuation_pending,self.inner.financial_continuation.allows_new_exact_continuation_v1(account)])?;
        let original=self.inner.durable_delivery.committed.get(account)
            .ok_or(AuthorityError::Permission)?.clone();
        let OwnerControl::AdmitFinancialContinuationV1 {record}=&request.control else {
            return Err(AuthorityError::Permission);
        };
        record.validate_request(request,&record.terms.scope.witness)?;
        if record.terms.original_delivery_operation_id!=original.operation_id
            || record.terms.original_delivery_request_digest
                !=crate::durable_financial_continuation_v1::original_delivery_request_digest_v1(&original)?
        {return Err(AuthorityError::Conflict);}
        // This is delivery-complete, not pristine and not already financial.
        // Reopen/authenticate the same original namespace; inert retained data
        // cannot substitute for the current journal's exact selected admission.
        let journal=crate::witness_locator::open_born_history(
            self.inner.original_namespace_input(account)?)?;
        journal.require_born_read_current()?;
        {
            let connection=journal.connection.lock().map_err(|_|AuthorityError::Storage)?;
            let ledger=crate::journal::load(connection.connection())?;
            if ledger.snapshot.account_id!=account || ledger.snapshot.head!=request.expected_head
                || ledger.selected_durable_delivery_admission_v2()?!=Some(&original)
                || ledger.selected_financial_continuation_v1()?.is_some()
            {return Err(AuthorityError::CorruptHistory);}
        }
        journal.require_born_read_current()?;
        drop(journal);
        self.inner.durable_delivery.historical_only=false;
        let form=UnfinishedFinancialFormV2 {inner:&mut self.inner};
        let result = form.inner.start_exact_financial_continuation_v1(account, request);
        drop(form);
        self.continuation_pending = result.is_ok();
        result
    }
    pub fn finish_exact_financial_continuation_v1(&mut self) -> Result<()> {
        if !self.continuation_pending { return Err(AuthorityError::Permission); }
        self.continuation_pending = false;
        self.inner.finish_exact_financial_continuation_v1()
    }
    pub fn serve_committed_financial_signing_v1(&mut self, operation: &str) -> Result<EphemeralHistoryServerV1> {
        let (request, _) = audited_financial(&mut self.inner, &self.unfinished_account)?;
        if request.operation_id != operation { return Err(AuthorityError::Permission); }
        self.inner.serve_committed_financial_signing_v1(operation)
    }
    pub fn serve_completed_owner_history_v2(&mut self) -> Result<EphemeralHistoryServerV1> {
        let (request, _) = audited_financial(&mut self.inner, &self.completed.account_id)?;
        if request != self.completed { return Err(AuthorityError::CorruptHistory); }
        self.inner.serve_committed_completed_dispatch_v1(&request.operation_id)
    }
    pub fn serve_exact_completed_history_v2(&mut self, operation: &str) -> Result<EphemeralHistoryServerV1> {
        if operation == self.completed.operation_id { return self.serve_completed_owner_history_v2(); }
        let (request, _) = audited_financial(&mut self.inner, &self.unfinished_account)?;
        if request.operation_id != operation { return Err(AuthorityError::Permission); }
        self.inner.serve_committed_completed_dispatch_v1(operation)
    }
    pub fn serve_committed_completed_dispatch_pair_v1(&mut self) -> Result<EphemeralHistoryServerV1> {
        let (first, _) = audited_financial(&mut self.inner, &self.completed.account_id)?;
        let (second, _) = audited_financial(&mut self.inner, &self.unfinished_account)?;
        if first != self.completed || first.account_id == second.account_id { return Err(AuthorityError::CorruptHistory); }
        self.inner.serve_committed_completed_dispatch_pair_v1()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn partial_preservation_roles_cannot_swap_or_drop_original_accounts() {
        let baseline = |account: String| PristineAccountBaselineV1 {account_id:account,
            head:AuthorityHead {sequence:4,digest:"d".repeat(64)},original_signed_birth:"inert".into(),original_source_commitment:"e".repeat(64)};
        let a = "a".repeat(64); let b = "b".repeat(64); let c = "c".repeat(64);
        let rows = vec![baseline(b.clone()), baseline(c)];
        assert!(role_ids(&a, &b, &rows).is_ok());
        assert!(role_ids(&b, &a, &rows).is_err());
        assert!(role_ids(&a, &a, &rows).is_err());
        assert!(role_ids(&a, &b, &rows[..1]).is_err());
        assert!(role_ids(&a, &"f".repeat(64), &rows).is_err());
        assert!(require_drained(1,false).is_err());
        assert!(require_drained(0,true).is_err());
        // Inert role/state matrix. Only the exact unfinished account in the
        // historical-only idle state can reach the native form scope.
        for bits in 0..16 {
            let state=std::array::from_fn(|i|bits&(1<<i)!=0);
            assert_eq!(require_unfinished_financial_entry_v2(&a,&b,&b,&b,state).is_ok(),bits==9);
            assert!(require_unfinished_financial_entry_v2(&a,&b,&a,&a,state).is_err());
            assert!(require_unfinished_financial_entry_v2(&a,&b,&b,&a,state).is_err());
            assert!(require_unfinished_financial_entry_v2(&a,&a,&a,&a,state).is_err());
        }
        // Cross-layer source contract, not execution of a native authority.
        let source=include_str!("partial_financial_preserve_v2.rs");
        let start=source.split("pub fn start_exact_financial_continuation_v1(").nth(1).unwrap()
            .split("pub fn finish_exact_financial_continuation_v1").next().unwrap();
        let audit=start.find("ledger.selected_durable_delivery_admission_v2()").unwrap();
        let close=start.find("drop(journal);").unwrap();
        let enable=start.find("self.inner.durable_delivery.historical_only=false;").unwrap();
        let call=start.find("form.inner.start_exact_financial_continuation_v1(account, request)").unwrap();
        let restore=start.find("drop(form);").unwrap();
        assert!(audit<close && close<enable && enable<call && call<restore);
        assert!(source.contains("fn drop(&mut self) {self.inner.durable_delivery.historical_only=true;}"));
        let fixture=include_str!("../ephemeral_fixture_v1.rs");
        assert!(fixture.contains("if self.durable_delivery.historical_only"));
        assert!(fixture.contains("![ENROLL, CONTINUE, UNDERSTOOD, AUTHORIZE].contains(&label)"));

    }
}
