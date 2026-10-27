//! Explicit durable V2 production entry. Each completed owner is authenticated
//! and intaken before waiting for the next; no stored writer becomes authority.
use super::{Host,
    durable_delivery_admission_v2::{admit_original_financial_borrowed_v2, OriginalDeliveryExportV3},
    durable_financial_commands_v1::{read_selection, continuation_record, require_admitted_selection, ContinuationSelectionV1},
};
use crate::{terminal::Terminal, Error, Result};
use serde::Deserialize;
use std::{collections::BTreeSet, path::{Path, PathBuf}};
use wholepact_signer::authority_bridge::financial_continuation_v1::{
    AuthenticatedFinancialContinuationHistoryV1, DurableFinancialResultRequestV2,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerCommandsV2 { account_id: String, bind_key: String, intake_key: String }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionCommandsV2 { version: u16, owners: [OwnerCommandsV2; 2], completion_key: String }
impl SessionCommandsV2 {
    fn check(&self, expected: &[String]) -> Result<()> {
        if self.version != 2 || expected.len() != 2 { return Err(Error::Invalid); }
        let accounts: BTreeSet<_> = self.owners.iter().map(|v| v.account_id.clone()).collect();
        if accounts != expected.iter().cloned().collect::<BTreeSet<_>>() || accounts.len() != 2 { return Err(Error::Authentication); }
        let mut keys = BTreeSet::new();
        for owner in &self.owners {
            crate::id(&owner.account_id)?;
            for key in [&owner.bind_key, &owner.intake_key] {
                crate::id(key)?;
                if !keys.insert(key) { return Err(Error::Invalid); }
            }
        }
        crate::id(&self.completion_key)?;
        if !keys.insert(&self.completion_key) { return Err(Error::Invalid); }
        Ok(())
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResultSelectionV2 { version: u16, signer_socket: PathBuf, request: DurableFinancialResultRequestV2 }
fn check_result_selection(selection: &ResultSelectionV2, history: &AuthenticatedFinancialContinuationHistoryV1) -> Result<()> {
    let socket = selection.signer_socket.to_str().ok_or(Error::Invalid)?;
    let terms = &history.continuation_record().terms;
    if selection.version != 2 || !selection.signer_socket.is_absolute()
        || socket.len() > 4096 || socket.bytes().any(|b| b.is_ascii_control())
        || selection.request.request.account_id != terms.scope.authorization.identity.account_id
        || selection.request.request.authorization_id != terms.scope.authorization.authorization_id
        || serde_json::to_value(&selection.request.request.fixed)? != serde_json::to_value(&terms.scope.authorization.fixed)?
    { return Err(Error::Authentication); }
    selection.request.validate().map_err(|_| Error::Authentication)
}
fn read_history(host: &Host, workspace: &Path, selected: &ContinuationSelectionV1) -> Result<AuthenticatedFinancialContinuationHistoryV1> {
    let request = selected.original_request();
    continuation_record(selected)?;
    let history = host.read_original_financial_history_v2(workspace, &request.account_id, &request.operation_id)?;
    if history.continuation_request() != request { return Err(Error::Authentication); }
    Ok(history)
}

pub(in crate::host) fn session_v2(
    terminal: Terminal, profile: &Path, workspace: &Path, reconcile_account: Option<&str>,
) -> Result<()> {
    terminal.message("Durable V2 uses the exact original fixed two-owner proposal. It intakes each completed owner before waiting for its counterpart. After restart, completed rows remain historical; unfinished actions need fresh native source, recipient, Read and Return permission. No writer is renewed, no uncertain signing is retried, and no transaction is submitted.\n")?;
    let host = Host::open_workspace_dispatcher_registered_v4(terminal.clone(), profile, workspace, false)?;
    let result = (|| -> Result<()> {
        let initial = host.inspect_original_financial_progress_v2(workspace)?;
        let commands: SessionCommandsV2 = read_selection(&host,
            "Exact ORIGINAL durable V2 command keys JSON {version:2,owners:[{account_id,bind_key,intake_key},{account_id,bind_key,intake_key}],completion_key} (absolute): ")?;
        commands.check(&initial.checkpoint_scope().account_ids)?;
        if reconcile_account.is_some_and(|account|
            !commands.owners.iter().any(|o| o.account_id == account)
                || !initial.intaken_accounts.iter().any(|a| a == account)) {
            // The explicit ACK reconciliation option cannot start admission or
            // signing for an unfinished owner. It only repeats exact delivery.
            return Err(Error::Authentication);
        }
        let mut prior: Option<OriginalDeliveryExportV3> = None;
        for owner in &commands.owners {
            let progress = host.inspect_original_financial_progress_v2(workspace)?;
            commands.check(&progress.checkpoint_scope().account_ids)?;
            let completed = progress.intaken_accounts.iter().any(|a| a == &owner.account_id);
            let bound = progress.bound_accounts.iter().any(|a| a == &owner.account_id);
            if completed && reconcile_account != Some(owner.account_id.as_str()) { continue; }
            if completed && !bound { return Err(Error::Authentication); }
            let exported_before = progress.exported_accounts.iter().any(|a| a == &owner.account_id);
            let selected: ContinuationSelectionV1;
            let fresh_admission = !bound && !exported_before;
            if fresh_admission {
                // Only the audited absence of any prior export permits a new
                // original admission. Missing bind alone is never that proof.
                terminal.message(&format!("Open fresh original-source admission for expected owner {}. Complete only its original continuation admission first; do not acquire/sign before Host retains that authenticated lineage.\n", owner.account_id))?;
                let (exported, admitted) = admit_original_financial_borrowed_v2(&host, workspace, prior.as_ref())?;
                selected = read_selection(&host, "Exact native original continuation selector JSON (absolute): ")?;
                require_admitted_selection(&selected, &admitted)?;
                if selected.original_request().account_id != owner.account_id { return Err(Error::Authentication); }
                prior = Some(exported);
                terminal.message("Finish the existing exact Witness continuation admission, then make its authenticated history available. Keep Sign/Acquire unapproved until the Host binds this lineage.\n")?;
            } else {
                terminal.message("An original export or financial lineage already exists. Reconcile ONLY its exact retained continuation through fresh authenticated history; no admission mutation is resent. Missing or uncertain history remains stopped. A completed result is reopened with fresh Read/Return, never regenerated.\n")?;
                selected = read_selection(&host, "Exact RETAINED original continuation selector JSON (absolute): ")?;
                if selected.original_request().account_id != owner.account_id { return Err(Error::Authentication); }
            }
            let admitted_history = read_history(&host, workspace, &selected)?;
            if !bound {
                host.bind_original_financial_owner_v2(workspace, &owner.bind_key, &admitted_history)?;
            }
            // The binding is durably committed before asking for signing or a
            // result. A crash after Signer commit therefore cannot select the
            // new-admission branch on restart.
            if fresh_admission {
                terminal.message("The exact continuation is now durably bound. Complete this owner's separate current Acquire/Activate/Wallet/Sign reviews once. If signing is uncertain, preserve originals and do not repeat it. Then open its explicit original durable result-only view.\n")?;
            }
            let result: ResultSelectionV2 = read_selection(&host,
                "Exact native durable result V2 selector JSON {version:2,signer_socket,request} (absolute): ")?;
            let history = read_history(&host, workspace, &selected)?;
            check_result_selection(&result, &history)?;
            let receiver = host.prepare_durable_financial_preview_v2(workspace, &result.signer_socket, &result.request, &history)?;
            host.intake_original_financial_result_v2(workspace, &owner.intake_key, receiver, &history)?;
            let after = host.inspect_original_financial_progress_v2(workspace)?;
            if !after.intaken_accounts.iter().any(|a| a == &owner.account_id) { return Err(Error::Authentication); }
            terminal.message("This exact owner result is durably intaken and its protected Return acknowledgement completed. Its old writer is no longer retained as authority while waiting for the counterpart.\n")?;
        }
        let progress = host.inspect_original_financial_progress_v2(workspace)?;
        let expected: BTreeSet<_> = commands.owners.iter().map(|o| o.account_id.clone()).collect();
        if progress.intaken_accounts.iter().cloned().collect::<BTreeSet<_>>() != expected
            || progress.intaken_accounts.len() != 2 { return Err(Error::Authentication); }
        let completed = host.complete_original_financial_transaction_v2(workspace, &commands.completion_key)?;
        let operation = progress.submission_operation_id.as_deref().ok_or(Error::Authentication)?;
        let verified = host.verify_completed_private_financial_summary_v2(workspace, operation)?;
        if verified.checkpoint_id != completed.checkpoint_id
            || verified.transaction_digest != completed.transaction_digest
            || verified.transaction_id != completed.txid {
            return Err(Error::Authentication);
        }
        // Fresh source-owned verification, not a count or remembered UI stage.
        terminal.json(&verified)?;
        terminal.message("Durable V2 completed the exact two-owner retained result union and original transaction checkpoint. This is not network inclusion or payment settlement. No transaction was submitted.\n")
    })();
    if result.is_err() {
        let _ = terminal.message("Durable V2 stopped or has an uncertain effect. Preserve original encrypted journals and SAME command keys. A committed result/receipt is never replaced; Started-only never permits re-signing. A new native permission may authorize exact reconciliation, not renewal of old authority.\n");
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    fn commands() -> SessionCommandsV2 { SessionCommandsV2 { version:2,
        owners:[OwnerCommandsV2 {account_id:"owner-a".into(),bind_key:"bind-a".into(),intake_key:"intake-a".into()},
        OwnerCommandsV2 {account_id:"owner-b".into(),bind_key:"bind-b".into(),intake_key:"intake-b".into()}],completion_key:"complete".into()} }
    fn expected() -> Vec<String> { vec!["owner-a".into(),"owner-b".into()] }
    #[test] fn exact_two_owner_command_keys_are_disjoint_and_profile_specific() {
        assert!(commands().check(&expected()).is_ok());
        let mut wrong=commands();wrong.version=1;assert!(wrong.check(&expected()).is_err());
        let mut wrong=commands();wrong.owners[1].account_id="owner-a".into();assert!(wrong.check(&expected()).is_err());
        let mut wrong=commands();wrong.owners[1].intake_key="bind-a".into();assert!(wrong.check(&expected()).is_err());
        let mut wrong=commands();wrong.completion_key="intake-b".into();assert!(wrong.check(&expected()).is_err());
        assert!(commands().check(&["owner-a".into()]).is_err());
    }
    #[test] fn versioned_command_selector_rejects_unknown_fields() {
        let bytes=br#"{"version":2,"owners":[{"account_id":"owner-a","bind_key":"a","intake_key":"b"},{"account_id":"owner-b","bind_key":"c","intake_key":"d"}],"completion_key":"e","approve":true}"#;
        assert!(wholepact_core::strict_json::parse_typed_json_with_byte_limit::<SessionCommandsV2>(bytes,262144).is_err());
    }
}
