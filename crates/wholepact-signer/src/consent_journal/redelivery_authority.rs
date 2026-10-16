//! Child of the native authority module: reuse the exact private decision and
//! held-approval machinery without exposing a generic receipt or approval issuer.
use super::*;

pub struct PreparedResultRedelivery(Pending<ResultRedeliveryRecord>);
pub struct ApprovedResultRedelivery(
    pub(in crate::consent_journal) Approval<ResultRedeliveryRecord>,
);
impl PreparedResultRedelivery {
    pub fn review_digest(&self) -> &str {
        &self.0.review_digest
    }
    pub fn record(&self) -> &ResultRedeliveryRecord {
        &self.0.record
    }
    pub fn display(&self) -> Result<Zeroizing<String>> {
        let _state = self.0.session.read()?;
        let t = self.0.record.terms();
        Ok(Zeroizing::new(format!("EXACT RETAINED AUTHORIZATION REDELIVERY\nNo new transaction will be signed and no exposure is released.\nAccount: {}\nAgreement: {}\nAuthorization: {}\nOriginal consent: {}\nManifest: {}\nOriginal effects: {}\nOriginal maximum debit: {} zatoshis\nOriginal transaction expiry height: {}\nRetained signed result: {}\nExact signature outbox: {}\nNew local recipient (OS process/grant, not publisher attestation): {}\nThis shares the already-produced spend signatures and their exact account/candidate commitments with this new local application process. It does not renew spending permission or change the original consent. Previously released signatures remain usable according to their original transaction constraints.\nExact redelivery decision: {}",t.account_id,t.agreement_id,t.request.authorization_id,t.request.expected_original_consent_ref,t.manifest_digest,t.effects_digest,t.maximum_debit_zatoshis,t.transaction_expiry_height,t.result_digest,t.outbox_digest,serde_json::to_string(&t.recipient).map_err(|_|JournalError::InvalidBinding)?,self.review_digest())))
    }
}
impl SignerConsentSession {
    pub fn prepare_result_redelivery(
        &self,
        journal: &SignerConsentJournal,
        transport: AuthenticatedTransportIdentity,
        request: ResultRedeliveryRequest,
    ) -> Result<PreparedResultRedelivery> {
        request.validate()?;
        self.require_redelivery_transport(&transport)?;
        let lease = journal.acquire_original_authorization(&request.authorization_id, self)?;
        let original = lease.evidence();
        request.matches(original)?;
        let result = journal.bridge_result(&lease).map_err(bridge_error)?;
        let t = original.original_consent().terms();
        if transport.account_id != t.account_id
            || transport.agreement_id != t.agreement_id
            || transport.participant_id != original.enrollment().participant_id()
        {
            return Err(JournalError::InvalidBinding);
        }
        transport.binding.validate_scope(
            &t.account_id,
            &t.agreement_id,
            original.enrollment().participant_id(),
            Some(&t.manifest_digest),
        )?;
        let record = ResultRedeliveryRecord::new(ResultRedeliveryTerms {
            request,
            account_id: t.account_id.clone(),
            principal_id: t.principal_id.clone(),
            agreement_id: t.agreement_id.clone(),
            participant_id: original.enrollment().participant_id().into(),
            manifest_digest: t.manifest_digest.clone(),
            effects_digest: t.effects_digest.clone(),
            maximum_debit_zatoshis: t.maximum_debit_zatoshis,
            transaction_expiry_height: t.transaction_expiry_height,
            result_digest: result.result_digest().into(),
            outbox_digest: result.outbox_digest().into(),
            recipient: transport.binding,
            receipt: self.receipt()?,
        })?;
        record.validate_original(original, &result)?;
        lease.check_current()?;
        Ok(PreparedResultRedelivery(Pending::new(
            record.clone(),
            record.reference.clone(),
            &self.inner,
        )))
    }
    pub fn approve_result_redelivery(
        &self,
        prepared: PreparedResultRedelivery,
        decision: NativeConsentDecision,
    ) -> Result<ApprovedResultRedelivery> {
        Ok(ApprovedResultRedelivery(
            prepared.0.approve(self, decision)?,
        ))
    }
    fn require_redelivery_transport(
        &self,
        transport: &AuthenticatedTransportIdentity,
    ) -> Result<()> {
        let _state = self.inner.read()?;
        if !matches!(
            transport.binding,
            TransportIdentityBinding::LocalProcess { .. }
        ) {
            return Err(JournalError::Permission);
        }
        #[cfg(all(feature = "native-ui", target_os = "linux"))]
        {
            if self.inner.native_origin.as_ref() != Some(&transport.native_origin) {
                return Err(JournalError::Permission);
            }
            if let Some(peer) = &self.inner.native_peer {
                peer.check_current().map_err(|_| JournalError::Permission)?;
                if !peer.scope.authorization_export
                    || !peer.scope.history_read
                    || !crate::authority_bridge::ipc::exact_local_recipient(
                        &transport.binding,
                        peer,
                    )
                {
                    return Err(JournalError::Permission);
                }
            } else {
                #[cfg(not(test))]
                return Err(JournalError::Permission);
            }
        }
        #[cfg(not(all(feature = "native-ui", target_os = "linux")))]
        {
            let _ = transport;
            Err(JournalError::Permission)
        }
        #[cfg(all(feature = "native-ui", target_os = "linux"))]
        Ok(())
    }
}
fn bridge_error(error: crate::authority_bridge::BridgeError) -> JournalError {
    match error {
        crate::authority_bridge::BridgeError::Journal(e) => e,
        crate::authority_bridge::BridgeError::Missing => JournalError::NotFound,
        crate::authority_bridge::BridgeError::Permission => JournalError::Permission,
        crate::authority_bridge::BridgeError::RecoveryRequired => JournalError::RecoveryRequired,
        _ => JournalError::InvalidBinding,
    }
}

#[cfg(test)]
pub(super) fn fixture_approval(
    session: &SignerConsentSession,
    record: ResultRedeliveryRecord,
) -> ApprovedResultRedelivery {
    let prepared = PreparedResultRedelivery(Pending::new(
        record.clone(),
        record.reference.clone(),
        &session.inner,
    ));
    let decision = super::fixture::decision(session, prepared.review_digest());
    session
        .approve_result_redelivery(prepared, decision)
        .unwrap()
}
