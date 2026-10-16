//! Inert exact handoff requests; all private/native owners remain authoritative.
use super::*;
use wholepact_engine::{
    native_artifact_handoff_requests::ArtifactHandoffKind, native_requests::NativeRequestState,
};
impl Host {
    pub(in crate::host) fn native_artifact_handoff_request(&mut self) -> Result<()> {
        self.financial_permission(Permission::Coordinate)?;
        self.financial_permission(Permission::Disclose)?;
        self.financial.as_ref().ok_or(Error::Locked)?.inventory()?;
        let agreement = self.terminal.ask("Exact selected agreement ID: ")?;
        self.terminal.json(
            &self
                .engine
                .native_artifact_handoff_requests(self.access()?, &agreement)?,
        )?;
        let request = self
            .terminal
            .ask("Exact queued signer-review or signature-intake request ID: ")?;
        let view =
            self.engine
                .native_artifact_handoff_request(self.access()?, &agreement, &request)?;
        self.terminal.json(&view)?;
        self.terminal.message(&format!(
            "Exact original native handoff key: {}. Preserve this unchanged. For signature intake, this is the original signature-set retention key required by signature-reconcile and later transaction-checkpoint; inspect those exact native journals after any missing acknowledgement. An attempted request cannot be rerun.\n",
            view.handoff_key()
        ))?;
        if view.state != NativeRequestState::Queued {
            return Err(Error::Invalid);
        }
        self.terminal.confirm("Hand off this exact original proved artifact to the selected native workflow? Signer review requires every owner's separate native private-data disclosure approval. Signature intake only retains existing authenticated results under fresh owner consent. Endpoint/source selection stays here. This request does not approve signatures or broadcast. Once started, missing acknowledgement remains unknown and this request cannot reset.")?;
        self.financial_permission(Permission::Coordinate)?;
        self.financial_permission(Permission::Disclose)?;
        let attempt = self.engine.mark_native_artifact_handoff_attempt(
            self.access()?,
            &agreement,
            &request,
        )?;
        if !exact_handoff_binding(
            [
                &view.candidate_id,
                &view.job_id,
                &view.manifest_digest,
                &view.receipt_digest,
                &view.receipt_storage_key,
                &view.scope_digest,
                &view.coordination_request_digest,
                &view.proved_artifact_digest,
                &view.handoff_key(),
            ],
            [
                attempt.candidate_id(),
                attempt.job_id(),
                attempt.manifest_digest(),
                attempt.receipt_digest(),
                attempt.receipt_storage_key(),
                attempt.scope_digest(),
                attempt.coordination_request_digest(),
                attempt.proved_artifact_digest(),
                attempt.handoff_key(),
            ],
            view.kind,
            attempt.kind(),
            view.queued_revision.checked_add(1),
            attempt.revision(),
        ) {
            return Err(Error::Invalid);
        }
        match attempt.kind() {
            ArtifactHandoffKind::SignerReview => self.financial_proof_delivery_exact(
                attempt.candidate_id(),
                attempt.job_id(),
                attempt.handoff_key(),
                Some(attempt.proved_artifact_digest()),
            ),
            ArtifactHandoffKind::SignatureIntake => self.financial_settle_exact(
                "signature-retain",
                attempt.candidate_id(),
                attempt.job_id(),
                attempt.handoff_key(),
                Some(attempt.proved_artifact_digest()),
            ),
        }
    }
}
fn exact_handoff_binding(
    a: [&str; 9],
    b: [&str; 9],
    kind: ArtifactHandoffKind,
    retained: ArtifactHandoffKind,
    expected: Option<u64>,
    actual: u64,
) -> bool {
    a == b && kind == retained && expected == Some(actual)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn handoff_dispatch_binds_kind_digest_and_original_identity() {
        let ids = [
            "candidate",
            "job",
            "manifest",
            "receipt",
            "receipt-key",
            "scope",
            "command",
            "proved-digest",
            "handoff-key",
        ];
        let kind = ArtifactHandoffKind::SignerReview;
        assert!(exact_handoff_binding(ids, ids, kind, kind, Some(8), 8));
        for i in 0..9 {
            let mut changed = ids;
            changed[i] = "changed";
            assert!(!exact_handoff_binding(ids, changed, kind, kind, Some(8), 8));
        }
        assert!(!exact_handoff_binding(
            ids,
            ids,
            kind,
            ArtifactHandoffKind::SignatureIntake,
            Some(8),
            8
        ));
        assert!(!exact_handoff_binding(ids, ids, kind, kind, None, 8));
    }
}
