//! Foreground request owner. Browser metadata never supplies native authority.
use super::*;
use wholepact_engine::native_requests::NativeRequestState;
use wholepact_engine::native_settlement_requests::{
    NativeSettlementAttempt, NativeSettlementInspection, SettlementRequestKind, SettlementSource,
};

pub(super) enum NativeSettlementDispatch {
    Initial(NativeSettlementAttempt),
    Inspection(NativeSettlementInspection),
}
impl NativeSettlementDispatch {
    pub(super) fn source(&self) -> &SettlementSource {
        match self {
            Self::Initial(v) => v.source(),
            Self::Inspection(v) => v.source(),
        }
    }
    pub(super) fn operation(&self) -> &'static str {
        match self {
            Self::Initial(v) => match v.kind() {
                SettlementRequestKind::SignatureReconcile => "signature-reconcile",
                SettlementRequestKind::TransactionCheckpoint => "transaction-checkpoint",
            },
            Self::Inspection(v) => match v.kind() {
                SettlementRequestKind::SignatureReconcile => "signature-reconcile",
                SettlementRequestKind::TransactionCheckpoint => "transaction-inspect",
            },
        }
    }
}
impl Host {
    pub(in crate::host) fn native_settlement_request(&self, inspect: bool) -> Result<()> {
        self.financial_permission(Permission::Coordinate)?;
        self.financial_permission(Permission::Disclose)?;
        self.financial.as_ref().ok_or(Error::Locked)?.inventory()?;
        let agreement = self.terminal.ask("Exact selected agreement ID: ")?;
        self.terminal.json(
            &self
                .engine
                .native_settlement_requests(self.access()?, &agreement)?,
        )?;
        let id = self
            .terminal
            .ask("Exact original native settlement request ID: ")?;
        let view = self
            .engine
            .native_settlement_request(self.access()?, &agreement, &id)?;
        self.terminal.json(&view)?;
        self.terminal.message(&format!("Original signature retention key: {}. Preserve this and both original private journals. Historical metadata (including any exact transaction ID and digest) will be retained for this authenticated client under its selected agreement scope. It is not current chain validity, signature permission, release authority or payment.\n",view.source.signature_retention_key))?;
        if inspect {
            if view.state != NativeRequestState::AttemptStarted {
                return Err(Error::Invalid);
            }
            self.terminal.confirm(match view.kind {
                SettlementRequestKind::SignatureReconcile => "Reconcile only the original signed intent under fresh native source and privacy decisions? This may finish deterministic assembly of the SAME original signature set after interruption. It never creates a missing intent, new signatures or a transaction. Retain the exact historical result metadata for this client?",
                SettlementRequestKind::TransactionCheckpoint => "Inspect only this original transaction result under fresh native source and privacy decisions? Missing bytes or intent remain unknown/fenced. This path never resets a request, restores a copy or extracts a transaction. Retain exact historical metadata including transaction ID for this client?",
            })?;
            let inspection =
                self.engine
                    .native_settlement_inspection(self.access()?, &agreement, &id)?;
            if !exact_settlement_source(
                &view.source,
                inspection.source(),
                view.kind,
                inspection.kind(),
            ) {
                return Err(Error::Invalid);
            }
            self.financial_settle_request(NativeSettlementDispatch::Inspection(inspection))
        } else {
            if view.state != NativeRequestState::Queued {
                return Err(Error::Invalid);
            }
            self.terminal.confirm("Start this exact native settlement handoff once? Signature reconciliation may finish deterministic assembly of the same original signatures under an existing intent, never generate new signatures. Transaction checkpoint may extract and retain usable transaction bytes after separate exact native consent; it never submits them. A crash can leave a durable unknown result. Preserve all original keys; use inspection rather than a replacement.")?;
            let attempt =
                self.engine
                    .mark_native_settlement_attempt(self.access()?, &agreement, &id)?;
            if !exact_settlement_source(&view.source, attempt.source(), view.kind, attempt.kind())
                || view.queued_revision.checked_add(1) != Some(attempt.revision())
            {
                return Err(Error::Invalid);
            }
            self.financial_settle_request(NativeSettlementDispatch::Initial(attempt))
        }
    }
}
fn exact_settlement_source(
    a: &SettlementSource,
    b: &SettlementSource,
    kind: SettlementRequestKind,
    retained: SettlementRequestKind,
) -> bool {
    a == b && kind == retained
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn settlement_source_binds_original_key_and_all_retained_identity_fields() {
        let source = SettlementSource {
            intake_request_id: "intake".into(),
            candidate_id: "candidate".into(),
            manifest_digest: "manifest".into(),
            job_id: "job".into(),
            signature_retention_key: "original-key".into(),
            proved_artifact_digest: "proof".into(),
            receipt_storage_key: "receipt-index".into(),
            receipt_digest: "receipt".into(),
            scope_digest: "scope".into(),
            coordination_request_digest: "command".into(),
        };
        let kind = SettlementRequestKind::TransactionCheckpoint;
        assert!(exact_settlement_source(&source, &source, kind, kind));
        let encoded = serde_json::to_value(&source).unwrap();
        for field in encoded.as_object().unwrap().keys() {
            let mut changed = encoded.clone();
            changed[field] = serde_json::json!("changed");
            let other: SettlementSource = serde_json::from_value(changed).unwrap();
            assert!(!exact_settlement_source(&source, &other, kind, kind));
        }
        assert!(!exact_settlement_source(
            &source,
            &source,
            kind,
            SettlementRequestKind::SignatureReconcile
        ));
    }
}
