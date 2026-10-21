//! Private structural composition of the existing original financial session.
//! It borrows the caller's one Host and uses only the maintained concrete native
//! handoffs. This does not enable a coordinated runtime or adapt fork custody to
//! an installed provider. CLI prompts remain in the existing command caller.
use super::{
    durable_delivery_admission_v2::OriginalDeliveryExportV3,
    durable_financial_commands_v1::{
        read_histories, require_pair, require_result_selection, select_original_owner_v1,
        ContinuationSelectionV1, ResultSelectionV1, SessionCommandsV1,
    },
    private_financial_v1::CompletedPrivateFinancialSummaryV1,
    Host,
};
use crate::{terminal::Terminal, Error, Result};
use std::{
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use wholepact_signer::authority_bridge::{
    financial_continuation_v1::{
        AuthenticatedFinancialContinuationHistoryV1, PreparedFinancialResultReceiverV1,
    },
    provider::InstalledSignerProvider,
};

/// Checked selection metadata only, never a source, Signer owner, permission or
/// proof of live custody. Only the real two-owner handoff below constructs it;
/// completion still reads fresh original histories and prepares actual peers.
/// The last inert export remains retained through the caller's session scope.
pub(super) struct OriginalFinancialSelectionsV1 {
    selections: [ContinuationSelectionV1; 2],
    results: [ResultSelectionV1; 2],
    _prior_export: Option<OriginalDeliveryExportV3>,
}

pub(super) fn collect_original_owner_selections_v1(
    terminal: &Terminal,
    host: &Host,
    workspace: &Path,
) -> Result<OriginalFinancialSelectionsV1> {
    let mut selections = Vec::with_capacity(2);
    let mut results = Vec::with_capacity(2);
    let mut prior = None;
    for index in 0..2 {
        let (exported, _admitted, selected, result) =
            select_original_owner_v1(terminal, host, workspace, prior.as_ref(), index)?;
        selections.push(selected);
        results.push(result);
        prior = Some(exported);
    }
    let selections: [_; 2] = selections.try_into().map_err(|_| Error::Authentication)?;
    let results: [_; 2] = results.try_into().map_err(|_| Error::Authentication)?;
    require_pair(&selections)?;
    Ok(OriginalFinancialSelectionsV1 {
        selections,
        results,
        _prior_export: prior,
    })
}

fn original_result_deadline(
    history: &AuthenticatedFinancialContinuationHistoryV1,
) -> Result<Instant> {
    // Take the monotonic snapshot first, so computation cannot extend the
    // authenticated absolute ceiling. Native peer approvals remain independent.
    let monotonic = Instant::now();
    let now_ms: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Invalid)?
        .as_millis()
        .try_into()
        .map_err(|_| Error::Invalid)?;
    let terms = &history.continuation_record().terms;
    terms.require_live(now_ms).map_err(|_| Error::Permission)?;
    let remaining = terms
        .valid_until_ms
        .checked_sub(now_ms)
        .ok_or(Error::Permission)?;
    monotonic
        .checked_add(Duration::from_millis(remaining))
        .ok_or(Error::Permission)
}

pub(super) fn complete_original_financial_session_v1(
    host: &Host,
    workspace: &Path,
    commands: &SessionCommandsV1,
    selected: &OriginalFinancialSelectionsV1,
) -> Result<CompletedPrivateFinancialSummaryV1> {
    let histories = read_histories(host, workspace, &selected.selections)?;
    host.bind_original_financial_continuations_v1(
        workspace,
        &commands.bind_key,
        [&histories[0], &histories[1]],
    )?;
    for index in 0..2 {
        require_result_selection(&selected.results[index], histories[index].continuation_record())?;
        let receiver = PreparedFinancialResultReceiverV1::prepare(
            InstalledSignerProvider::load().map_err(|_| Error::Permission)?,
            &selected.results[index].signer_socket,
            &selected.results[index].request,
            original_result_deadline(&histories[index])?,
        ).map_err(|_| Error::Receipt("FINANCIAL_RESULT_PREPARE: original result is unavailable or uncertain; preserve exact operations and journals, never re-sign or replace the selector".into()))?;
        // Maintained intake performs all Host reviews and freezes its gate
        // before receive() starts the independently approved ReturnExact.
        host.intake_original_financial_result_v1(
            workspace,
            &commands.intake_keys[index],
            receiver,
            &histories[index],
        )?;
    }
    let completed =
        host.complete_original_financial_transaction_v1(workspace, &commands.completion_key)?;
    let operation = &histories[0]
        .continuation_record()
        .terms
        .scope
        .delivery
        .submission_operation_id;
    let summary = host.verify_completed_private_financial_summary_v1(workspace, operation)?;
    if summary.checkpoint_id != completed.checkpoint_id
        || summary.transaction_digest != completed.transaction_digest
        || summary.transaction_id != completed.txid
    {
        return Err(Error::Authentication);
    }
    Ok(summary)
}
