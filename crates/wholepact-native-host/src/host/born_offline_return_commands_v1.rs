//! Actual foreground caller to original carrier, signer history, return inbox,
//! exact full-roster merge, fresh protected wallets and one-shot dispatch.
//! File values select originals only; no imported field grants authority.
use super::Host;
use crate::{Error, Result, files};
use serde::Deserialize;
use std::{collections::BTreeSet, path::PathBuf};
use wholepact_authority::born_offline_checkpoint_origin_v1::BornOfflineCheckpointExportPlanV1;
use wholepact_signer::{
    authority_bridge::{
        born_history_ipc::BornOriginalHistoryRequestV1, ipc::OriginalHistoryClient,
        provider::InstalledSignerProvider,
    },
    ipc::PairScope,
};
use wholepact_transport::TransportPublicKey;
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BornReturnSelectionV1 {
    version: u16,
    agreement_id: String,
    construction_key: String,
    /// Preserve this SAME exact finalized transaction operation on every retry.
    submission_operation_id: String,
    sources: Vec<BornReturnSourceV1>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BornReturnSourceV1 {
    account_id: String,
    signer_public_key_hex: String,
    original_checkpoint_export_plan: BornOfflineCheckpointExportPlanV1,
    signer_socket: PathBuf,
    history: BornOriginalHistoryRequestV1,
    return_ciphertext_file: PathBuf,
}
impl BornReturnSelectionV1 {
    fn validate(&self) -> Result<()> {
        if self.version != 1
            || !(2..=8).contains(&self.sources.len())
            || !(16..=128).contains(&self.construction_key.len())
            || !self
                .construction_key
                .bytes()
                .all(|b| (33..=126).contains(&b))
        {
            return Err(Error::Invalid);
        }
        crate::id(&self.agreement_id)?;
        crate::id(&self.submission_operation_id)?;
        let mut accounts = BTreeSet::new();
        for source in &self.sources {
            if !accounts.insert(&source.account_id)
                || !source.signer_socket.is_absolute()
                || !source.return_ciphertext_file.is_absolute()
            {
                return Err(Error::Invalid);
            }
            for value in [
                &source.account_id,
                &source.signer_public_key_hex,
                &source.history.expected_original_ref,
                &source.history.expected_born_origin_digest,
            ] {
                hash(value)?;
            }
            crate::id(&source.history.authorization_id)?;
            source
                .original_checkpoint_export_plan
                .validate()
                .map_err(|_| Error::Invalid)?;
        }
        Ok(())
    }
}
impl Host {
    pub(in crate::host) fn born_return_command_v1(&self, dispatch: bool) -> Result<()> {
        self.require_manual_session()?;
        let path=self.path("Protected exact born return selection JSON file (original operation/plan/ciphertext only): ")?;
        self.terminal.confirm(&format!("Read this bounded private selection file for an exact born return {} command. It identifies an ACTUAL existing completed V3/V4 checkpoint,2–8 existing pinned signers, original immutable checkpoint export plans and return ciphertext files. No file field proves consent, history, completion, current inputs or authority. No key or credential is created. Missing originals fail closed, never reconstruct or replace. Separate exact proof-read, local retention, installed-signer native disclosure and (for dispatch) fresh wallet/provider/backend approvals follow.\nFile: {}",if dispatch{"dispatch"}else{"historical-retain"},path.display()))?;
        let bytes = Zeroizing::new(files::read_private(&path, 262_144)?);
        let selection: BornReturnSelectionV1 =
            wholepact_core::parse_typed_json(&bytes).map_err(|_| Error::Invalid)?;
        selection.validate()?;
        let mut owners = Vec::with_capacity(selection.sources.len());
        for source in &selection.sources {
            let peer = TransportPublicKey::from_bytes(
                hex::decode(&source.signer_public_key_hex)
                    .map_err(|_| Error::Invalid)?
                    .try_into()
                    .map_err(|_| Error::Invalid)?,
            )?;
            owners.push(self.prepare_born_offline_checkpoint_carrier_v1(
                &selection.agreement_id,
                &selection.construction_key,
                &source.account_id,
                &peer,
                Some(source.original_checkpoint_export_plan.clone()),
            )?);
        }
        // Missing actual immutable outbox ciphertext cannot be substituted with
        // the imported plan. No sealing, order allocation or file export here.
        let retained = owners
            .iter()
            .map(|o| o.retained_export())
            .collect::<Result<Vec<_>>>()?;
        let mut clients = Vec::with_capacity(selection.sources.len());
        for (source, actual) in selection.sources.iter().zip(&retained) {
            actual.check_current()?;
            let participant = actual
                .original()
                .proposal()
                .manifest()
                .participants
                .iter()
                .find(|p| p.account_id == source.account_id)
                .ok_or(Error::Authentication)?;
            self.terminal.confirm(&format!("Pair ONLY with the independently installed signer at {} for account {} and original born authorization {}. Its separate native window must approve exact historical evidence disclosure and, only if requested later, one exact final transaction dispatch. The Host receives no spending key, writer credential or writer-session secret. No generic online/legacy authorization is requested.",source.signer_socket.display(),source.account_id,source.history.authorization_id))?;
            clients.push(
                OriginalHistoryClient::pair(
                    InstalledSignerProvider::load().map_err(|_| Error::Permission)?,
                    &source.signer_socket,
                    "wholepact-born-return",
                    PairScope {
                        account_id: source.account_id.clone(),
                        agreement_id: selection.agreement_id.clone(),
                        participant_id: participant.participant_id.clone(),
                        manifest_digest: actual.origin().manifest_digest.clone(),
                        history_read: true,
                        authorization_export: false,
                        preconstruction_export: false,
                    },
                )
                .map_err(|_| Error::Permission)?,
            );
            actual.check_current()?;
        }
        let mut histories = Vec::with_capacity(clients.len());
        let original_deadline = retained
            .iter()
            .map(|actual| actual.deadline())
            .min()
            .ok_or(Error::Authentication)?;
        for (client, source) in clients.iter().zip(&selection.sources) {
            histories.push(
                client
                    .acquire_born_original_history_checked_until(
                        &source.history,
                        original_deadline,
                        || {
                            self.require_manual_session().map_err(|_| {
                                wholepact_signer::authority_bridge::BridgeError::Permission
                            })?;
                            retained.iter().try_for_each(|actual| {
                                actual.check_current().map_err(|_| {
                                    wholepact_signer::authority_bridge::BridgeError::Permission
                                })
                            })
                        },
                    )
                    .map_err(|_| Error::Permission)?,
            );
        }
        let mut returns = Vec::with_capacity(clients.len());
        for ((actual, history), source) in retained.iter().zip(&histories).zip(&selection.sources) {
            actual.check_current()?;
            history.check_current().map_err(|_| Error::Permission)?;
            let cipher = files::read_artifact(
                &source.return_ciphertext_file,
                wholepact_transport::MAX_FILE_BYTES,
            )?;
            returns.push(self.retain_born_return_v1(actual, history, cipher)?);
        }
        let merged = self.merge_born_returns_v1(&returns, &selection.submission_operation_id)?;
        if dispatch {
            // Deliberately not async: every wallet DB guard remains held through
            // native/signer/witness checks, exact intent and durable send outcome.
            let result = self.with_born_post_return_inputs_v1(&merged, |held| {
                merged.dispatch_born_current_v1(held, &clients)
            });
            let report=result.map_err(|_|Error::Receipt("born dispatch or admission may already be retained or sent; preserve exact operation and journals, reconcile same bytes, do not replace or clear exposure".into()))?;
            self.terminal.message("One exact born dispatch attempt has a durable local report. This is NOT confirmation/finality/payment proof. Preserve original exposure and observe the same transaction; any retry requires fresh native/current approval and identical bytes.\n")?;
            self.terminal.json(&report)
        } else {
            merged.check_current()?;
            self.terminal.json(&serde_json::json!({"historical_exact_born_transaction_retained":true,"descriptor":merged.verified_submission().descriptor(),"current_inputs_validated":false,"dispatch_authorized":false,"payment_verified":false}))
        }
    }
}
fn hash(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Err(Error::Invalid)
    } else {
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lower_hex_only() {
        assert!(hash(&"01".repeat(32)).is_ok());
        assert!(hash(&"AB".repeat(32)).is_err());
        assert!(hash("actual-private-key-text").is_err());
    }
    #[test]
    fn empty_unknown_or_incomplete_selection_cannot_start() {
        for raw in [b"{}".as_slice(),br#"{"version":1,"agreement_id":"a","construction_key":"1234567890123456","submission_operation_id":"op","sources":[],"trusted":true}"#]{assert!(wholepact_core::parse_typed_json::<BornReturnSelectionV1>(raw).is_err());}
        let s = BornReturnSelectionV1 {
            version: 1,
            agreement_id: "a".into(),
            construction_key: "1234567890123456".into(),
            submission_operation_id: "op".into(),
            sources: vec![],
        };
        assert!(s.validate().is_err());
    }
}
