//! Foreground production composition, not a new source or permission issuer.
//! UI files select exact retained operations. Only installed native peers,
//! authenticated original Witness history, and the maintained Host methods may
//! supply custody, current consent, result intake, or saved-byte dispatch.
use super::{
    coordinated_session_v1::{
        collect_original_owner_selections_v1, complete_original_financial_session_v1,
    },
    durable_delivery_admission_v2::{admit_original_borrowed_v3, OriginalDeliveryExportV3},
    Host,
};
use crate::{files, terminal::Terminal, Error, Result};
use serde::{de::DeserializeOwned, Deserialize};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};
use wholepact_authority::{
    durable_delivery_scope_v2::{DurableDeliveryPlanV2, DurableDeliveryRouteV2},
    durable_financial_continuation_v1::{
        original_delivery_request_digest_v1, FinancialContinuationRecordV1,
    },
    OwnerControl, OwnerControlRequest,
};
use wholepact_chain::{
    public_read_profile_v1::{PublicReadProfileV1, PublicReadRouteV1},
    ChainAdapter, LightwalletSubmissionBackend, NetworkPolicy, SystemSubmissionClock,
};
use wholepact_signer::authority_bridge::{
    durable_delivery_admission_ipc_v3::DurableDeliveryAdmissionStatusV3,
    financial_continuation_v1::{
        AuthenticatedFinancialContinuationHistoryV1, FinancialResultRequestV1,
    },
};
use zeroize::Zeroizing;

// Matches the deliberately bounded Signer UI handoff. A DTO never grants a
// source, installed-provider trust, native approval, or an expiry extension.
const MAX_SELECTION_BYTES: usize = 262_144;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ContinuationSelectionV1 {
    version: u16,
    continuation: OwnerControlRequest,
}
impl ContinuationSelectionV1 {
    pub(super) fn original_request(&self) -> &OwnerControlRequest { &self.continuation }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ResultSelectionV1 {
    version: u16,
    pub(super) signer_socket: PathBuf,
    pub(super) request: FinancialResultRequestV1,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SessionCommandsV1 {
    version: u16,
    pub(super) bind_key: String,
    pub(super) intake_keys: [String; 2],
    pub(super) completion_key: String,
}
impl SessionCommandsV1 {
    pub(super) fn check(&self) -> Result<()> {
        require_version(self.version)?;
        let mut unique = BTreeSet::new();
        for key in [
            &self.bind_key,
            &self.intake_keys[0],
            &self.intake_keys[1],
            &self.completion_key,
        ] {
            crate::id(key)?;
            if !unique.insert(key) {
                return Err(Error::Invalid);
            }
        }
        Ok(())
    }
}
fn require_version(version: u16) -> Result<()> {
    if version == 1 {
        Ok(())
    } else {
        Err(Error::Invalid)
    }
}
fn parse_selection<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    wholepact_core::strict_json::parse_typed_json_with_byte_limit(bytes, MAX_SELECTION_BYTES)
        .map_err(|_| Error::Invalid)
}
pub(super) fn read_selection<T: DeserializeOwned>(host: &Host, prompt: &str) -> Result<T> {
    let path = host.path(prompt)?;
    let bytes = Zeroizing::new(files::read_artifact(&path, MAX_SELECTION_BYTES)?);
    parse_selection(&bytes)
}
pub(super) fn continuation_record(
    selection: &ContinuationSelectionV1,
) -> Result<&FinancialContinuationRecordV1> {
    require_version(selection.version)?;
    let OwnerControl::AdmitFinancialContinuationV1 { record } = &selection.continuation.control
    else {
        return Err(Error::Authentication);
    };
    record
        .validate_request(&selection.continuation, &record.terms.scope.witness)
        .map_err(|_| Error::Authentication)?;
    Ok(record)
}
pub(super) fn require_admitted_selection(
    selection: &ContinuationSelectionV1,
    admitted: &DurableDeliveryAdmissionStatusV3,
) -> Result<()> {
    let record = continuation_record(selection)?;
    let audit = admitted
        .verified_audit()
        .map_err(|_| Error::Authentication)?;
    let terms = &record.terms;
    if terms.scope != audit.scope
        || terms.original_delivery_operation_id != admitted.request.operation_id
        || terms.original_delivery_request_digest
            != original_delivery_request_digest_v1(&admitted.request)
                .map_err(|_| Error::Authentication)?
        || terms.original_local_intent_digest != admitted.original_local_intent_digest
        || terms.original_recipient_intent_digest != admitted.intent_digest
        || terms.original_recipient_enrollment_ref != audit.original_enrollment_ref
        || terms.original_recipient_manifest_ref != audit.original_accepted_manifest_ref
    {
        return Err(Error::Authentication);
    }
    Ok(())
}
pub(super) fn require_result_selection(
    selection: &ResultSelectionV1,
    record: &FinancialContinuationRecordV1,
) -> Result<()> {
    require_version(selection.version)?;
    // No canonicalization, socket replacement, trust installation or provider
    // fallback. The actual installed peer and exact preview are checked later.
    let socket = selection
        .signer_socket
        .to_str()
        .ok_or(Error::Authentication)?;
    if !selection.signer_socket.is_absolute()
        || socket.len() > 4096
        || socket.bytes().any(|byte| byte.is_ascii_control())
        || selection.request.account_id != record.terms.scope.authorization.identity.account_id
        || selection.request.authorization_id != record.terms.scope.authorization.authorization_id
        || serde_json::to_value(&selection.request.fixed)?
            != serde_json::to_value(&record.terms.scope.authorization.fixed)?
    {
        return Err(Error::Authentication);
    }
    Ok(())
}
pub(super) fn require_pair(selections: &[ContinuationSelectionV1; 2]) -> Result<()> {
    let first = continuation_record(&selections[0])?;
    let second = continuation_record(&selections[1])?;
    if selections[0].continuation.account_id == selections[1].continuation.account_id
        || selections[0].continuation.operation_id == selections[1].continuation.operation_id
        || first.terms.scope.delivery != second.terms.scope.delivery
        || first.terms.scope.authorization.fixed != second.terms.scope.authorization.fixed
    {
        return Err(Error::Authentication);
    }
    Ok(())
}
pub(super) fn read_histories(
    host: &Host,
    workspace: &Path,
    selections: &[ContinuationSelectionV1; 2],
) -> Result<[AuthenticatedFinancialContinuationHistoryV1; 2]> {
    require_pair(selections)?;
    let mut histories = Vec::with_capacity(2);
    for selected in selections {
        let history = host.read_original_financial_history_v1(
            workspace,
            &selected.continuation.account_id,
            &selected.continuation.operation_id,
        )?;
        // Authenticate the ENTIRE exact request, not only user-selected names.
        if history.continuation_request() != &selected.continuation {
            return Err(Error::Authentication);
        }
        histories.push(history);
    }
    histories.try_into().map_err(|_| Error::Authentication)
}

// Concrete CLI handoff only. Keep its prompts and immediate selection checks
// here; the private composition does not accept a replaceable prompt provider.
pub(super) fn select_original_owner_v1(
    terminal: &Terminal,
    host: &Host,
    workspace: &Path,
    prior: Option<&OriginalDeliveryExportV3>,
    index: usize,
) -> Result<(
    OriginalDeliveryExportV3,
    DurableDeliveryAdmissionStatusV3,
    ContinuationSelectionV1,
    ResultSelectionV1,
)> {
    terminal.message(&format!(
        "Select original reviewer {} of 2 for its separate closed V3 admission.\n",
        index + 1
    ))?;
    let (exported, admitted) = admit_original_borrowed_v3(host, workspace, prior)?;
    terminal.message("In this same original Signer, review the fresh original financial continuation. Save its explicit continuation selector before Witness approval. Complete the exact Witness continuation and separate Signer decisions without changing native focus or original deadlines. The Host will not send an owner control request from this file.\n")?;
    let selected: ContinuationSelectionV1 = read_selection(
        host,
        "Exact copied native continuation selector JSON file (absolute): ",
    )?;
    require_admitted_selection(&selected, &admitted)?;
    terminal.message("After this owner's genuine SignExact finishes, save its native result selector while keeping that original Signer alive and focused for ReturnExact. For a shared Witness installation, drain and stop its single-owner service before opening the next owner; never run competing exclusive registry owners.\n")?;
    let result: ResultSelectionV1 = read_selection(
        host,
        "Exact copied native AwaitingReturn result selector JSON file (absolute): ",
    )?;
    require_result_selection(&result, continuation_record(&selected)?)?;
    // Retain the actual admission status in the owner's loop scope, as before.
    Ok((exported, admitted, selected, result))
}

pub(in crate::host) fn session_v1(
    terminal: Terminal,
    profile: &Path,
    workspace: &Path,
) -> Result<()> {
    terminal.message("This foreground session retains the ORIGINAL Host process through both independent owner admissions and protected result intakes. Keep each original Signer alive and focused through its return. Native focus loss aborts that workflow; ordinary sequential windows on one desktop are not a supported workaround. A supported independently focused native arrangement is a prerequisite that still requires runtime qualification. Every Read, Continue, Witness, Admit, Acquire, Activate, Wallet, Sign and Return decision remains separate. This command never auto-approves, renews expiry, resumes an interrupted pre-intake session, or submits a transaction.\n")?;
    // This is the only Host open in the session. In particular, the two V3
    // helpers never reopen a Host or replace the process retained by each peer.
    let host =
        Host::open_workspace_dispatcher_registered_v4(terminal.clone(), profile, workspace, false)?;
    let result = (|| -> Result<()> {
        let commands: SessionCommandsV1 = read_selection(&host,
            "Exact immutable command keys JSON file {version:1,bind_key,intake_keys:[first,second],completion_key} (absolute): ")?;
        commands.check()?;
        let selections = collect_original_owner_selections_v1(&terminal, &host, workspace)?;
        terminal.message("Both owners must now have completed signing and be awaiting protected return. Stop and drain initial Witness services. Serve the exact completed original accounts, using the paired mode only for a genuinely shared installation. The next steps require fresh authenticated history, not the copied selectors.\n")?;
        // A readiness acknowledgement is not a financial permission. Every
        // history/intake/checkpoint action retains its maintained exact review.
        if terminal
            .ask("Type READY when the exact original completed-history service is available: ")?
            .as_str()
            != "READY"
        {
            return Err(Error::Permission);
        }
        let summary =
            complete_original_financial_session_v1(&host, workspace, &commands, &selections)?;
        terminal.json(&summary)?;
        terminal.message("Both protected intakes and the exact original completed transaction checkpoint are retained. No transaction was submitted. Close normally; completed-only inspect or dispatch must reopen these exact originals and cannot sign, extract or repair.\n")
    })();
    if result.is_err() {
        let _ = terminal.message("The original financial session stopped or has an uncertain outcome. Preserve its exact journals, command keys and selectors. Do not restart admission, regenerate signatures, reset operations or infer that an interrupted effect did not happen. Completed-only routes require an actually completed checkpoint.\n");
    }
    // Deliberate drop only after completion or fail-closed exit, never between
    // reviewer admissions, native detaches, continuations or the two intakes.
    drop(host);
    result
}

pub(in crate::host) fn inspect_v1(
    terminal: Terminal,
    profile: &Path,
    workspace: &Path,
) -> Result<()> {
    let host =
        Host::open_workspace_dispatcher_registered_v4(terminal.clone(), profile, workspace, false)?;
    let operation = terminal.ask("Exact retained completed submission operation ID: ")?;
    crate::id(&operation)?;
    // No Signer, Witness mutation, chain adapter, extraction or repair path.
    let summary = host.verify_completed_private_financial_summary_v1(workspace, &operation)?;
    terminal.json(&summary)
}

fn exact_route(actual: &PublicReadRouteV1, expected: &DurableDeliveryRouteV2) -> bool {
    match (actual, expected) {
        (PublicReadRouteV1::Direct, DurableDeliveryRouteV2::Direct {}) => true,
        (
            PublicReadRouteV1::ExistingHttpConnect { origin: actual },
            DurableDeliveryRouteV2::ExistingHttpConnect { origin: expected },
        ) => actual == expected,
        _ => false,
    }
}
fn require_actual_backend(
    actual: &PublicReadProfileV1,
    delivery: &DurableDeliveryPlanV2,
) -> Result<()> {
    if !actual.destination_tls_native_roots
        || !exact_route(&actual.route, &delivery.route)
        || actual.backend.source_id != delivery.provider.source_id
        || actual.backend.endpoint != delivery.provider.endpoint
        || actual.backend.trust_profile != delivery.provider.trust_profile
        || actual.backend.trust_profile != "single_tls_provider_report_not_consensus"
    {
        return Err(Error::Authentication);
    }
    Ok(())
}

pub(in crate::host) fn dispatch_v1(
    terminal: Terminal,
    profile: &Path,
    workspace: &Path,
) -> Result<()> {
    let host =
        Host::open_workspace_dispatcher_registered_v4(terminal.clone(), profile, workspace, false)?;
    let key = terminal.ask("Exact immutable command key for this completed dispatch attempt: ")?;
    crate::id(&key)?;
    let first: ContinuationSelectionV1 = read_selection(
        &host,
        "First exact retained continuation selector JSON file (absolute): ",
    )?;
    let second: ContinuationSelectionV1 = read_selection(
        &host,
        "Second exact retained continuation selector JSON file (absolute): ",
    )?;
    let selections = [first, second];
    require_pair(&selections)?;
    let operation = &continuation_record(&selections[0])?
        .terms
        .scope
        .delivery
        .submission_operation_id;
    // Fail incomplete originals before any remote history or provider contact.
    host.verify_completed_private_financial_summary_v1(workspace, operation)?;
    terminal.message("Read fresh authenticated histories from the exact original Witness accounts. This cannot issue a continuation, repeat signing, extract a transaction, repair custody, or renew owner expiry. A separate final exact Host review is still required for one saved-byte dispatch.\n")?;
    let histories = read_histories(&host, workspace, &selections)?;
    let delivery = &histories[0].continuation_record().terms.scope.delivery;
    // Constructor captures the existing route without making a connection.
    // Use that SAME adapter after comparing both actual original commitments.
    let adapter = ChainAdapter::testnet(
        &delivery.provider.source_id,
        &delivery.provider.endpoint,
        NetworkPolicy::default(),
    )?;
    let actual = adapter.public_read_profile_v1();
    for history in &histories {
        require_actual_backend(&actual, &history.continuation_record().terms.scope.delivery)?;
    }
    let mut backend = LightwalletSubmissionBackend::new(adapter);
    let executor = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| Error::Storage)?;
    // No more command-layer prompts. The maintained composition owns its exact
    // final review, both current admissions, closed gates and retained-byte send.
    let report = executor.block_on(host.dispatch_completed_private_financial_v1(
        workspace,
        &key,
        [&histories[0], &histories[1]],
        &mut backend,
        &SystemSubmissionClock,
    ))?;
    terminal.json(&report)?;
    terminal.message("One exact dispatch attempt returned a durable report, not payment inclusion or settlement. Preserve the same operation, saved bytes, original expiry and full attempt history. An uncertain outcome never permits a replacement payment.\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    const KEYS: &[u8] = br#"{"version":1,"bind_key":"bind-original","intake_keys":["intake-first","intake-second"],"completion_key":"complete-original"}"#;

    #[test]
    fn command_selectors_preserve_explicit_unique_keys() {
        let keys: SessionCommandsV1 = parse_selection(KEYS).unwrap();
        assert!(keys.check().is_ok());
        assert_eq!(keys.bind_key, "bind-original");
        assert_eq!(keys.intake_keys, ["intake-first", "intake-second"]);
        assert_eq!(keys.completion_key, "complete-original");
    }

    #[test]
    fn selector_parser_rejects_duplicate_unknown_trailing_and_oversize_data() {
        for bytes in [
            br#"{"version":1,"version":1,"bind_key":"b","intake_keys":["i1","i2"],"completion_key":"c"}"#.as_slice(),
            br#"{"version":1,"bind_key":"b","intake_keys":["i1","i2"],"completion_key":"c","approve":true}"#.as_slice(),
        ] {
            assert!(parse_selection::<SessionCommandsV1>(bytes).is_err());
        }
        let mut trailing = KEYS.to_vec();
        trailing.extend_from_slice(b"{}");
        assert!(parse_selection::<SessionCommandsV1>(&trailing).is_err());
        assert!(
            parse_selection::<SessionCommandsV1>(&vec![b' '; MAX_SELECTION_BYTES + 1]).is_err()
        );
    }

    #[test]
    fn command_selectors_reject_versions_reused_keys_and_invalid_ids() {
        let mut keys: SessionCommandsV1 = parse_selection(KEYS).unwrap();
        keys.version = 2;
        assert!(keys.check().is_err());
        keys.version = 1;
        keys.intake_keys[1] = keys.intake_keys[0].clone();
        assert!(keys.check().is_err());
        keys.intake_keys[1] = "different".into();
        keys.completion_key = "".into();
        assert!(keys.check().is_err());
    }

    #[test]
    fn command_routes_require_explicit_original_paths() {
        use crate::host::{Args, Command};
        use clap::Parser;
        let session = Args::try_parse_from([
            "host",
            "durable-financial-session-v1",
            "--profile",
            "/original/profile",
            "--workspace",
            "/original/workspace",
        ])
        .unwrap();
        assert!(matches!(
            session.command,
            Command::DurableFinancialSessionV1 { .. }
        ));
        let inspect = Args::try_parse_from([
            "host",
            "durable-financial-inspect-v1",
            "--profile",
            "/original/profile",
            "--workspace",
            "/original/workspace",
        ])
        .unwrap();
        assert!(matches!(
            inspect.command,
            Command::DurableFinancialInspectV1 { .. }
        ));
        let dispatch = Args::try_parse_from([
            "host",
            "durable-financial-dispatch-v1",
            "--profile",
            "/original/profile",
            "--workspace",
            "/original/workspace",
        ])
        .unwrap();
        assert!(matches!(
            dispatch.command,
            Command::DurableFinancialDispatchV1 { .. }
        ));
        for route in [
            "durable-financial-session-v1",
            "durable-financial-inspect-v1",
            "durable-financial-dispatch-v1",
        ] {
            assert!(Args::try_parse_from(["host", route]).is_err());
            assert!(Args::try_parse_from([
                "host",
                route,
                "--profile",
                "/original/profile",
                "--workspace",
                "/original/workspace",
                "--repair"
            ])
            .is_err());
        }
    }

    #[test]
    fn actual_route_must_match_without_normalization_or_fallback() {
        assert!(exact_route(
            &PublicReadRouteV1::Direct,
            &DurableDeliveryRouteV2::Direct {}
        ));
        let actual = PublicReadRouteV1::ExistingHttpConnect {
            origin: "http://127.0.0.1:8080/".into(),
        };
        assert!(exact_route(
            &actual,
            &DurableDeliveryRouteV2::ExistingHttpConnect {
                origin: "http://127.0.0.1:8080/".into()
            }
        ));
        assert!(!exact_route(
            &actual,
            &DurableDeliveryRouteV2::ExistingHttpConnect {
                origin: "http://127.0.0.1:8080".into()
            }
        ));
        assert!(!exact_route(&actual, &DurableDeliveryRouteV2::Direct {}));
        assert!(!exact_route(
            &PublicReadRouteV1::Direct,
            &DurableDeliveryRouteV2::ExistingHttpConnect {
                origin: "http://127.0.0.1:8080/".into()
            }
        ));
    }

    #[test]
    fn wrong_handoff_envelopes_cannot_be_promoted_to_authority() {
        assert!(parse_selection::<ContinuationSelectionV1>(
            br#"{"version":1,"continuation":{},"approved":true}"#
        )
        .is_err());
        assert!(parse_selection::<ResultSelectionV1>(br#"{"version":1,"signer_socket":"/tmp/result","request":{},"deadline_ms":9999999999999}"#).is_err());
        assert!(require_version(0).is_err());
        assert!(require_version(2).is_err());
    }
}
