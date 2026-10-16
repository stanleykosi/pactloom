//! Stop-and-drain native metadata handoff. No caller account ID is used as a
//! ledger query; the actual installed signer derives its unlocked account.
use super::*;
use wholepact_engine::native_requests::NativeRequestState;
impl Host {
    pub(in crate::host) fn native_account_inspection_request(
        &self,
        status_only: bool,
    ) -> Result<()> {
        self.coordination_permission(Permission::Read)?;
        let agreement = self.terminal.ask("Exact agreement ID: ")?;
        self.terminal.json(
            &self
                .engine
                .native_account_inspection_requests(self.access()?, &agreement)?,
        )?;
        let id = self
            .terminal
            .ask("Exact original account inspection request ID: ")?;
        let view =
            self.engine
                .native_account_inspection_request(self.access()?, &agreement, &id)?;
        if status_only {
            return self.terminal.json(&view);
        }
        self.financial_permission(Permission::Coordinate)?;
        self.financial_permission(Permission::Disclose)?;
        if view.state != NativeRequestState::Queued {
            return Err(Error::Invalid);
        }
        let (_, candidate) = self
            .engine
            .candidate(self.access()?, &view.request.candidate_id)?;
        let participant = candidate
            .proposal
            .manifest
            .participants
            .iter()
            .find(|p| p.participant_id == view.request.participant_id)
            .ok_or(Error::Invalid)?;
        let client = self
            .signer_review_clients
            .get(&(
                view.request.candidate_id.clone(),
                participant.account_id.clone(),
            ))
            .ok_or(Error::Permission)?;
        self.terminal.json(&view)?;
        self.terminal.confirm("Request ONE exact local account audit from this existing installed signer session? The signer independently reviews the exact metadata disclosure and derives its account from the actual unlocked vault. Save its approved historical authorization, sponsor and automation metadata for this principal and agreement, readable by its workspace/SDK/CLI. No keys, signature bytes, witness/provider contact or financial operation is authorized. Account-wide exposure, balances, settled spending and remaining budgets stay unknown. Starting is durable before IPC; interruption without a committed result remains unknown and cannot run again. Status only returns the original saved result.")?;
        let attempt =
            self.engine
                .mark_native_account_inspection_attempt(self.access()?, &agreement, &id)?;
        let result = client
            .request_owner_inspection(attempt.request())
            .map_err(|_| Error::Permission)?;
        self.financial_permission(Permission::Disclose)?;
        self.terminal
            .json(&self.engine.retain_native_account_inspection(
                self.access()?,
                attempt,
                &result,
            )?)
    }
}
