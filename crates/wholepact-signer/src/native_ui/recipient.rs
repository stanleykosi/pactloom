//! Native recipient-owned instruction and finalized-payment workflow. Keys never
//! leave the unlocked signer; every use needs a fresh exact native privacy decision.
use super::{NativeAuthority, NativeAuthorityBinding, NativeDecision};
use crate::{Error, Result, account::AccountVault};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::Read,
    os::unix::fs::OpenOptionsExt,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use wholepact_protocol::recipient_local::{ReceivingInstructions, verify_finalized_payment};
use zeroize::Zeroizing;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstructionRecord {
    instructions: ReceivingInstructions,
    digest: String,
    account_id: String,
    issued_at: u64,
    /// Deliberately owner-issued, not authenticated invoice/legal identity.
    provenance: String,
    observations: Vec<serde_json::Value>,
}
enum Action {
    Issue(ReceivingInstructions),
    Check {
        reference: String,
        bytes: Zeroizing<Vec<u8>>,
    },
}
pub(super) struct PreparedRecipient {
    action: Action,
    source: NativeAuthorityBinding,
    account_id: String,
    digest: String,
    display: String,
    started: Instant,
}
fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| Error::InvalidData)
}
fn records(vault: &AccountVault) -> Result<Vec<InstructionRecord>> {
    let bytes = vault.read_recipient_records()?;
    let records: Vec<InstructionRecord> =
        serde_json::from_slice(&bytes).map_err(|_| Error::InvalidData)?;
    if records.len() > 256 {
        return Err(Error::InvalidData);
    }
    for record in &records {
        if record.account_id != vault.account_id()?
            || record.provenance != "recipient_owner_issued_native_review"
            || record.digest
                != record
                    .instructions
                    .digest()
                    .map_err(|_| Error::Verification)?
            || record.observations.len() > 64
        {
            return Err(Error::Verification);
        }
    }
    Ok(records)
}
impl PreparedRecipient {
    pub(super) fn issue(
        json: &str,
        authority: &NativeAuthority,
        vault: &AccountVault,
    ) -> Result<Self> {
        if json.len() > 16384 {
            return Err(Error::InvalidData);
        }
        let instructions: ReceivingInstructions =
            serde_json::from_str(json).map_err(|_| Error::InvalidData)?;
        instructions.validate().map_err(|_| Error::Verification)?;
        if instructions.valid_until_unix_seconds <= now()? {
            return Err(Error::ReviewMismatch);
        }
        let receiver =
            wholepact_protocol::review::decode_testnet_receiver(&instructions.destination)
                .map_err(|_| Error::Verification)?;
        // This key is derived from the actual unlocked dedicated account, not an
        // import, request field, coordinator record or claimed key fingerprint.
        if vault
            .account()
            .fvk()?
            .scope_for_address(&receiver)
            .is_none()
        {
            return Err(Error::ReviewMismatch);
        }
        let all = records(vault)?;
        if all.len() >= 256
            || all
                .iter()
                .any(|r| r.instructions.reference == instructions.reference)
        {
            return Err(Error::ReviewMismatch);
        }
        let display = format!(
            "ISSUE RECIPIENT RECEIVING INSTRUCTIONS\n{}\n\nThis address belongs to this unlocked account. Approve these exact instructions as recipient owner. Imported text is not authenticated invoice or legal identity evidence. This creates an encrypted local receiving-instruction record using a separate wrapped key. Back up recipient-record-key.wp and recipient-records.wp together with this account. No contributor data is needed. No payment, disclosure to a provider, refund or external acknowledgment is authorized.",
            serde_json::to_string_pretty(&instructions).map_err(|_| Error::InvalidData)?
        );
        Self::prepare(Action::Issue(instructions), display, authority, vault)
    }
    pub(super) fn check(
        reference: &str,
        path: &str,
        authority: &NativeAuthority,
        vault: &AccountVault,
    ) -> Result<Self> {
        let all = records(vault)?;
        let record = all
            .iter()
            .find(|r| r.instructions.reference == reference)
            .ok_or(Error::ReviewMismatch)?;
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        if !file.metadata()?.is_file() || file.metadata()?.len() > 1_048_576 {
            return Err(Error::InvalidData);
        }
        let mut bytes = Zeroizing::new(Vec::new());
        file.by_ref().take(1_048_577).read_to_end(&mut bytes)?;
        if bytes.is_empty() || bytes.len() > 1_048_576 {
            return Err(Error::InvalidData);
        }
        let display = format!(
            "LOCAL RECIPIENT PAYMENT CHECK\nInstruction reference: {}\nInstruction digest: {}\nFinalized transaction bytes SHA256: {}\n{}\n\nUse this recipient account's viewing key LOCALLY for this exact finalized transaction only. The key never leaves this signer. Verify canonical transaction cryptography and exact incoming address, amount and memo. Retain the private result in the encrypted recipient journal. No coordinator journals, contributor identities or private witnesses are requested. No network contact is authorized. Cryptographic validity/decryption is NOT chain inclusion or consensus validity. Commercial validity may have elapsed; only you decide delivery. This does not send an acknowledgment or refund.",
            reference,
            record.digest,
            hex::encode(Sha256::digest(&*bytes)),
            serde_json::to_string_pretty(&record.instructions).map_err(|_| Error::InvalidData)?
        );
        Self::prepare(
            Action::Check {
                reference: reference.into(),
                bytes,
            },
            display,
            authority,
            vault,
        )
    }
    fn prepare(
        action: Action,
        display: String,
        authority: &NativeAuthority,
        vault: &AccountVault,
    ) -> Result<Self> {
        authority.check_current()?;
        let account_id = vault.account_id()?;
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:recipient-native-review:v1",
            &(&account_id, &display, crate::vault::random::<32>()?),
        )
        .map_err(|_| Error::InvalidData)?;
        Ok(Self {
            action,
            source: authority.binding(),
            account_id,
            digest,
            display,
            started: Instant::now(),
        })
    }
    pub(super) fn digest(&self) -> &str {
        &self.digest
    }
    pub(super) fn display(&self) -> String {
        self.display.clone()
    }
    pub(super) fn approve(
        self,
        decision: NativeDecision,
        authority: &NativeAuthority,
        vault: &AccountVault,
    ) -> Result<String> {
        authority.check_current()?;
        self.source.check_current()?;
        if self.source != authority.binding()
            || decision.binding() != &self.source
            || decision.reviewed_digest() != self.digest
            || vault.account_id()? != self.account_id
            || self.started.elapsed() >= Duration::from_secs(120)
        {
            return Err(Error::ReviewMismatch);
        }
        let mut all = records(vault)?;
        let result = match self.action {
            Action::Issue(instructions) => {
                if instructions.valid_until_unix_seconds <= now()?
                    || all.len() >= 256
                    || all
                        .iter()
                        .any(|r| r.instructions.reference == instructions.reference)
                {
                    return Err(Error::ReviewMismatch);
                }
                let digest = instructions.digest().map_err(|_| Error::Verification)?;
                all.push(InstructionRecord {
                    instructions,
                    digest: digest.clone(),
                    account_id: self.account_id,
                    issued_at: now()?,
                    provenance: "recipient_owner_issued_native_review".into(),
                    observations: Vec::new(),
                });
                format!(
                    "Recipient-owned instructions retained: {digest}. No instructions were sent externally."
                )
            }
            Action::Check { reference, bytes } => {
                let record = all
                    .iter_mut()
                    .find(|r| r.instructions.reference == reference)
                    .ok_or(Error::ReviewMismatch)?;
                if record.observations.len() >= 64 {
                    return Err(Error::InvalidData);
                }
                let fvk = vault.account().fvk()?;
                let evidence = verify_finalized_payment(&bytes, &record.instructions, &fvk)
                    .map_err(|_| Error::Verification)?;
                self.source.check_current()?;
                let summary = format!(
                    "Exact incoming output verified locally. Transaction {}. Chain status: NO OBSERVATION. Receiving instructions commercially expired now: {}. No delivery decision, acknowledgment or refund was made.",
                    evidence.transaction_id(),
                    now()? > record.instructions.valid_until_unix_seconds
                );
                record.observations.push(serde_json::json!({"checked_at": now()?, "provenance": "recipient_owned_key_maintained_finalized_transaction_decryption_v1", "chain_status": "no_observation", "evidence": evidence}));
                summary
            }
        };
        self.source.check_current()?;
        let encoded = Zeroizing::new(serde_json::to_vec(&all).map_err(|_| Error::InvalidData)?);
        vault.write_recipient_records(&encoded)?;
        Ok(result)
    }
}

pub(super) mod observation;

/// Explicit private historical projection. It never returns arbitrary observation
/// JSON, raw finalized transactions, keys, or a current confidence assertion.
pub(super) fn historical(vault: &AccountVault, reference: &str) -> Result<Zeroizing<String>> {
    if !vault.account().recovery_required() || reference.is_empty() || reference.len() > 256 {
        return Err(Error::RecoveryRequired);
    }
    let record = records(vault)?
        .into_iter()
        .find(|record| record.instructions.reference == reference)
        .ok_or(Error::InvalidData)?;
    #[derive(Serialize)]
    struct HistoricalRecipient {
        instructions: ReceivingInstructions,
        instruction_digest: String,
        recorded_issue_time_unix_seconds: u64,
        saved_observation_count: usize,
        recovery_required: bool,
        current_chain_confidence: &'static str,
        limitation: &'static str,
    }
    let projection = HistoricalRecipient {
        instructions: record.instructions,
        instruction_digest: record.digest,
        recorded_issue_time_unix_seconds: record.issued_at,
        saved_observation_count: record.observations.len(),
        recovery_required: true,
        current_chain_confidence: "unknown; historical observations are not refreshed",
        limitation: "Private recipient-owned historical instructions only. This is not renewed recipient consent, current chain inclusion, delivery evidence, restored writer authority, or reconciled authorization exposure.",
    };
    Ok(Zeroizing::new(
        serde_json::to_string_pretty(&projection).map_err(|_| Error::InvalidData)?,
    ))
}
