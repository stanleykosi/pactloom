//! Foreground dispatch handoff. Client requests never supply financial authority.
use super::*;
use wholepact_engine::{
    native_dispatch_requests::DispatchSource, native_requests::NativeRequestState,
};

impl Host {
    pub(in crate::host) fn native_dispatch_request(&self, status_only: bool) -> Result<()> {
        self.financial_permission(Permission::Coordinate)?;
        self.financial_permission(Permission::Disclose)?;
        self.financial.as_ref().ok_or(Error::Locked)?.inventory()?;
        let agreement = self.terminal.ask("Exact selected agreement ID: ")?;
        self.terminal.json(
            &self
                .engine
                .native_dispatch_requests(self.access()?, &agreement)?,
        )?;
        let id = self
            .terminal
            .ask("Exact original native dispatch request ID: ")?;
        let view = self
            .engine
            .native_dispatch_request(self.access()?, &agreement, &id)?;
        self.terminal.json(&view)?;
        self.terminal.message(&format!("Original submission operation: {}. Preserve its exact request, signature retention key and transaction/submission journals. A provider acknowledgement is historical and does not establish payment; missing records do not prove nobody sent the transaction.\n", view.operation_id))?;
        if status_only {
            if view.state != NativeRequestState::AttemptStarted {
                return Err(Error::Invalid);
            }
            let inspection =
                self.engine
                    .native_dispatch_inspection(self.access()?, &agreement, &id)?;
            if !exact_dispatch_source(&view.source, inspection.source())
                || view.operation_id != inspection.operation_id()
            {
                return Err(Error::Invalid);
            }
            let journal = self.submission.lock().map_err(|_| Error::Storage)?;
            let result = self.authority.with_submission_status_read(
                self.access()?.principal_id.as_str(),
                &view,
                journal.identity(),
                || {
                    Ok(self.engine.inspect_native_dispatch_status(
                        self.access()?,
                        inspection,
                        &journal,
                    )?)
                },
            )?;
            return self.terminal.json(&result);
        }
        if view.state != NativeRequestState::Queued {
            return Err(Error::Invalid);
        }
        self.terminal.confirm("Start this original native dispatch handoff ONCE? This records an uncertain attempt before private work. It does not approve broadcasting. You must separately review the exact transaction and named provider in this native session, and every original signer must independently approve current dispatch. Retain historical submission metadata for this authenticated client under its selected agreement scope? A crash never authorizes replacing or resetting this request.")?;
        let journal_identity = self
            .submission
            .lock()
            .map_err(|_| Error::Storage)?
            .identity()
            .to_owned();
        let attempt = self.engine.mark_native_dispatch_attempt(
            self.access()?,
            &agreement,
            &id,
            &journal_identity,
        )?;
        if !exact_dispatch_source(&view.source, attempt.source())
            || view.operation_id != attempt.operation_id()
            || view.queued_revision.checked_add(1) != Some(attempt.revision())
        {
            return Err(Error::Invalid);
        }
        self.financial_dispatch_request(attempt)
    }
}
fn exact_dispatch_source(a: &DispatchSource, b: &DispatchSource) -> bool {
    a == b
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dispatch_source_does_not_allow_replacement_of_original_transaction_or_receipt() {
        use wholepact_engine::native_settlement_requests::{SettlementSource, SignedObservation};
        let source = DispatchSource {
            transaction_request_id: "original-transaction-request".into(),
            original: SettlementSource {
                intake_request_id: "intake".into(),
                candidate_id: "candidate".into(),
                manifest_digest: "manifest".into(),
                job_id: "job".into(),
                signature_retention_key: "retention".into(),
                proved_artifact_digest: "proof".into(),
                receipt_storage_key: "receipt-key".into(),
                receipt_digest: "receipt".into(),
                scope_digest: "scope".into(),
                coordination_request_digest: "command".into(),
            },
            signed: SignedObservation {
                result_id: "signed".into(),
                request_digest: "signed-request".into(),
                signed_candidate_digest: "signed-digest".into(),
                signatures_complete: true,
            },
            checkpoint_id: "checkpoint".into(),
            transaction_digest: "exact-bytes".into(),
            txid: "transaction-id".into(),
        };
        assert!(exact_dispatch_source(&source, &source));
        let encoded = serde_json::to_value(&source).unwrap();
        for field in encoded.as_object().unwrap().keys() {
            if field == "signed" {
                continue;
            }
            let mut changed = encoded.clone();
            changed[field] = serde_json::json!("changed");
            let other: DispatchSource = serde_json::from_value(changed).unwrap();
            assert!(!exact_dispatch_source(&source, &other), "{field}");
        }
        for field in encoded["signed"].as_object().unwrap().keys() {
            let mut changed = encoded.clone();
            changed["signed"][field] = if field == "signatures_complete" {
                serde_json::json!(false)
            } else {
                serde_json::json!("changed")
            };
            let other: DispatchSource = serde_json::from_value(changed).unwrap();
            assert!(!exact_dispatch_source(&source, &other), "signed.{field}");
        }
    }
}
