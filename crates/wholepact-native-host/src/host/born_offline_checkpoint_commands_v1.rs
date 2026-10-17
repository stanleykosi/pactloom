//! Foreground-only routing to the genuine native checkpoint carrier owner.
//! User selections and optional original-plan JSON are inert. This command
//! cannot create a checkpoint, pin a replacement peer, or provision a key.
use super::Host;
use crate::{Error, Result, files};
use std::path::PathBuf;
use wholepact_authority::born_offline_checkpoint_origin_v1::BornOfflineCheckpointExportPlanV1;
use wholepact_transport::TransportPublicKey;
use zeroize::Zeroizing;

const MAX_ORIGINAL_PLAN_BYTES: usize = 16_384;

impl Host {
    pub(in crate::host) fn born_offline_checkpoint_export_v1_command(&self) -> Result<()> {
        self.require_manual_session()?;
        self.terminal.message(
            "This exports or recovers ONLY an actual retained, independently verified V3/V4 completed checkpoint origin. It does not construct or prove a transaction, sign, reserve, validate current inputs, or dispatch. The public common-context V3 construction command remains qualification-gated; missing retained evidence is not permission to create a replacement. The offline signer must already be independently pinned for this exact outgoing born-checkpoint context in this session. No peer pin or key is created here.\n",
        )?;
        let agreement = self.terminal.ask("Exact original agreement ID: ")?;
        crate::id(&agreement)?;
        let key = self
            .terminal
            .ask("Exact original V3/V4 construction key (never a replacement key): ")?;
        if !(16..=128).contains(&key.len()) || !key.bytes().all(|b| (33..=126).contains(&b)) {
            return Err(Error::Invalid);
        }
        let account = self
            .terminal
            .ask("Exact retained account ID (64 lowercase hex): ")?;
        require_hash(&account)?;
        let peer = self.terminal.ask(
            "ALREADY independently pinned offline signer PUBLIC transport key (64 lowercase hex, never a private key): ",
        )?;
        require_hash(&peer)?;
        let peer = TransportPublicKey::from_bytes(
            hex::decode(peer.as_bytes())
                .map_err(|_| Error::Invalid)?
                .try_into()
                .map_err(|_| Error::Invalid)?,
        )?;
        let plan_path = self.terminal.ask(
            "Exact original export-plan JSON file for retry (private file; blank ONLY for the first attempt, never after uncertain output): ",
        )?;
        let original_plan = if plan_path.is_empty() {
            None
        } else {
            let path = PathBuf::from(plan_path.as_str());
            if !path.is_absolute() {
                return Err(Error::Invalid);
            }
            let approval = self.terminal.approve_historical(&format!(
                "Read ONLY this exact private local original export-plan JSON file as inert selection data. It may contain original message/order/times, transport key fingerprints and disclosure purpose. It grants no native consent, checkpoint provenance, peer pin, key use or authority. The actual retained claim, verified proof, existing pinned peer and protected Host outbox will independently authenticate every binding. No file is changed or sent.\nFile: {}",
                path.display(),
            ))?;
            let mut parsed = None;
            approval.effect(&mut || {
                approval.check()?;
                self.require_manual_session()?;
                let bytes = Zeroizing::new(files::read_private(&path, MAX_ORIGINAL_PLAN_BYTES)?);
                parsed = Some(parse_original_plan(&bytes)?);
                self.require_manual_session()?;
                approval.check()
            })?;
            Some(parsed.ok_or(Error::Authentication)?)
        };
        let destination =
            self.path("NEW absolute ciphertext destination (never overwrite an existing file): ")?;
        if !destination.is_absolute() {
            return Err(Error::Invalid);
        }
        let owner = self.prepare_born_offline_checkpoint_carrier_v1(
            &agreement,
            &key,
            &account,
            &peer,
            original_plan,
        )?;
        owner.check_current()?;

        // Display the exact inert retry plan BEFORE any possible durable seal.
        // Use a duplicate of the same TTY inside its one-use effect; calling
        // Terminal::json here would recursively lock the controlling terminal.
        let display = self.terminal.approve_historical(
            "Display the exact inert ORIGINAL checkpoint export-plan JSON once on this controlling terminal before any sealing attempt. Preserve it privately and unchanged if output or acknowledgment is uncertain. This JSON is metadata, not an approval or checkpoint receipt. A retry must use these same original identifiers, times and order; never substitute a new plan or infer that a failed file write means no ciphertext was committed. The separate next carrier review must still approve the actual origin, pinned recipient and create-only output path. No transaction, private proof, viewing key or secret transport key is displayed.",
        )?;
        let output = self.terminal.historical_output()?;
        display.effect(&mut || {
            let check = || {
                display.check()?;
                owner.check_current()?;
                display.check()
            };
            check()?;
            output.json_checked(owner.export_plan(), check)
        })?;
        owner.check_current()?;
        let exported = owner.export_to(&destination)?;
        // The exact private plan was already displayed under its own native
        // decision. Do not log origin/plan/ciphertext identifiers after dropping
        // the source owner, or describe transport output as signer acceptance.
        self.terminal.message(if exported.recovered_original_ciphertext {
            "The identical previously retained checkpoint ciphertext was written to the new local file. Original times were not renewed. This is not external delivery, signer acceptance, current-input validation, transaction authority or dispatch. Preserve the exact original plan and all files.\n"
        } else {
            "Original checkpoint ciphertext was durably retained in the existing protected Host outbox and written to the new local file. This is not external delivery, signer acceptance, current-input validation, transaction authority or dispatch. Preserve the exact original plan and all files.\n"
        })
    }
}

fn require_hash(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::Invalid);
    }
    Ok(())
}
fn parse_original_plan(bytes: &[u8]) -> Result<BornOfflineCheckpointExportPlanV1> {
    if bytes.len() > MAX_ORIGINAL_PLAN_BYTES {
        return Err(Error::Invalid);
    }
    let plan: BornOfflineCheckpointExportPlanV1 =
        wholepact_core::parse_typed_json(bytes).map_err(|_| Error::Invalid)?;
    plan.validate().map_err(|_| Error::Invalid)?;
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inert_plan() -> serde_json::Value {
        serde_json::json!({
            "message_id": "a".repeat(32), "sequence": 1,
            "issued_at_unix_seconds": 1, "expires_at_unix_seconds": 2,
            "purpose": "synthetic original metadata only",
            "persistence_warning": "synthetic recipient may retain metadata",
            "sender_id": format!("born-offline-checkpoint:{}", "b".repeat(64)),
            "recipient_id": format!("born-offline-checkpoint:{}", "c".repeat(64)),
            "sender_key_fingerprint": "b".repeat(64),
            "recipient_key_fingerprint": "c".repeat(64),
        })
    }

    #[test]
    fn inert_plan_parser_rejects_authority_flags_and_changed_wire_shape() {
        let plan = inert_plan();
        assert!(parse_original_plan(&serde_json::to_vec(&plan).unwrap()).is_ok());
        let mut claimed = plan.clone();
        claimed["approved"] = serde_json::json!(true);
        assert!(parse_original_plan(&serde_json::to_vec(&claimed).unwrap()).is_err());
        let wrapped = serde_json::json!({"export_plan": plan});
        assert!(parse_original_plan(&serde_json::to_vec(&wrapped).unwrap()).is_err());
        assert!(parse_original_plan(&vec![b' '; MAX_ORIGINAL_PLAN_BYTES + 1]).is_err());
    }

    #[test]
    fn public_key_selection_is_exact_hex_data_not_a_secret_or_approval() {
        assert!(require_hash(&"a".repeat(64)).is_ok());
        assert!(require_hash(&"A".repeat(64)).is_err());
        assert!(require_hash(&"a".repeat(63)).is_err());
        assert!(require_hash("approved").is_err());
    }
}
