//! Explicitly opt-in, local-only qualification. The only accepted accounts are
//! public deterministic fixture keys. Never use these accounts for real funds.
//! This does NOT establish a production human approval or identity boundary.
use crate::{vault::UnlockedVault, Error, Result};
use orchard::keys::{FullViewingKey, SpendAuthorizingKey, SpendingKey};
use pczt::{roles::signer::Signer, Pczt};
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use wholepact_protocol::{
    review::{verify_review, OutputPurpose},
    synthetic::{policy_for_fixture_pczt, TEST_OWNER_SPENDING_KEY_BYTES},
};
use wholepact_store::{authority::ReleaseIntent, Store};
use zeroize::Zeroizing;

const MAX_PCZT: usize = 1_048_576;
const RESULT_PURPOSE: &[u8] = b"wholepact:synthetic-authorization-result:v1";
const BACKUP_PASSWORD: &[u8] = b"synthetic-local-backup-test-only";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrashAt {
    BeforeIntent,
    AfterIntent,
    AfterSign,
    AfterResult,
    BeforeExport,
}
fn crash(point: Option<CrashAt>, target: CrashAt) {
    if point == Some(target) {
        std::process::exit(86);
    }
}

#[derive(Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    Initialize {
        owner: u8,
        password: String,
    },
    Unlock {
        password: String,
    },
    Lock {},
    CreateBackup {},
    VerifyBackup {},
    Restore {
        encrypted_backup_hex: String,
        password: String,
    },
    Review {
        operation_id: String,
        client_id: String,
        obligation_id: String,
        proposal_id: String,
        pczt_hex: String,
    },
    Approve {
        review_nonce: String,
        review_binding: String,
        client_id: String,
        acknowledge_synthetic_only: bool,
    },
    Reject {
        review_nonce: String,
    },
    Retrieve {
        operation_id: String,
        client_id: String,
    },
    Status {},
}
#[derive(Serialize)]
pub struct ReviewSummary {
    pub qualification_only: bool,
    pub operation_id: String,
    pub client_id: String,
    pub account_id: String,
    pub review_nonce: String,
    pub review_binding: String,
    pub artifact_digest: String,
    pub manifest_digest: String,
    pub effects_digest: String,
    pub maximum_net_debit_zatoshis: String,
    pub fee_share_zatoshis: String,
    pub transaction_fee_zatoshis: String,
    pub recipients: Vec<OutputSummary>,
    pub owned_returns: Vec<OutputSummary>,
    pub expiry_height: u32,
    pub network: &'static str,
    pub match_assurance: &'static str,
    pub chain_validated: bool,
    pub disclosure: &'static str,
}
#[derive(Serialize)]
pub struct OutputSummary {
    pub receiver_hex: String,
    pub amount_zatoshis: String,
}
struct PendingReview {
    operation_id: String,
    client_id: String,
    obligation_id: String,
    proposal_id: String,
    nonce: String,
    binding: String,
    pczt: Zeroizing<Vec<u8>>,
    created: Instant,
}
#[derive(Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct ProtectedResult {
    evidence_kind: String,
    qualification_only: bool,
    chain_validated: bool,
    network: String,
    operation_id: String,
    client_id: String,
    request_digest: String,
    review_binding: String,
    review_nonce: String,
    signed_pczt_hex: String,
}

pub struct Session {
    root: PathBuf,
    vault: Option<UnlockedVault>,
    store: Option<Store>,
    pending: Option<PendingReview>,
    fault: Option<CrashAt>,
}
impl Session {
    pub fn new(root: &Path, fault: Option<CrashAt>) -> Self {
        Self {
            root: root.to_path_buf(),
            vault: None,
            store: None,
            pending: None,
            fault,
        }
    }
    fn vault(&self) -> Result<&UnlockedVault> {
        self.vault.as_ref().ok_or(Error::Locked)
    }
    fn store(&self) -> Result<&Store> {
        self.store.as_ref().ok_or(Error::Locked)
    }
    fn install(&mut self, vault: UnlockedVault, new: bool) -> Result<()> {
        // Missing journal on an existing vault cannot silently bootstrap authority.
        let exists = vault.directory().exists("authority.sqlite")?;
        let store = Store::open(vault.directory().database_path()?)?;
        if new {
            store.initialize_authority_account(&vault.account_id(), 1)?;
        } else if !exists || vault.recovery_required() {
            if store.authority_account(&vault.account_id())?.is_none() {
                store.import_restored_account(&vault.account_id(), 1)?;
            } else {
                store.require_account_recovery(&vault.account_id())?;
            }
        }
        if store.authority_account(&vault.account_id())?.is_none() {
            return Err(Error::RecoveryRequired);
        }
        self.vault = Some(vault);
        self.store = Some(store);
        self.pending = None;
        Ok(())
    }
    pub fn execute(&mut self, command: Command) -> Result<serde_json::Value> {
        match command {
            Command::Initialize { owner, password } => {
                let password = Zeroizing::new(password);
                if self.vault.is_some() || owner > 1 {
                    return Err(Error::InvalidData);
                }
                let vault = UnlockedVault::create_synthetic(
                    &self.root,
                    password.as_bytes(),
                    owner,
                    TEST_OWNER_SPENDING_KEY_BYTES[owner as usize],
                )?;
                self.install(vault, true)?;
                self.status()
            }
            Command::Unlock { password } => {
                let password = Zeroizing::new(password);
                if self.vault.is_some() {
                    return Err(Error::AlreadyOpen);
                }
                let vault = UnlockedVault::unlock(&self.root, password.as_bytes())?;
                self.install(vault, false)?;
                self.status()
            }
            Command::Lock {} => {
                self.pending = None;
                self.store = None;
                self.vault = None;
                self.status()
            }
            Command::CreateBackup {} => {
                let snapshots = self
                    .store()?
                    .account_exposures(&self.vault()?.account_id())?;
                let mut records = Vec::new();
                for exposure in &snapshots {
                    let name = result_filename(&exposure.intent.authorization_id);
                    if self.vault()?.directory().exists(&name)? {
                        // Preserve exact signed result without exposing it in plaintext files.
                        let bytes = self.vault()?.read_protected(
                            &name,
                            &result_domain(&exposure.intent.authorization_id),
                        )?;
                        records.push(
                            serde_json::from_slice::<ProtectedResult>(&bytes)
                                .map_err(|_| Error::InvalidData)?,
                        );
                    }
                }
                #[derive(Serialize)]
                struct BackupJournal<'a> {
                    exposures: &'a [wholepact_store::authority::StoredExposure],
                    results: &'a [ProtectedResult],
                }
                let journal = Zeroizing::new(
                    serde_json::to_vec(&BackupJournal {
                        exposures: &snapshots,
                        results: &records,
                    })
                    .map_err(|_| Error::InvalidData)?,
                );
                self.vault()?.create_backup(&journal, BACKUP_PASSWORD)?;
                Ok(
                    serde_json::json!({"backup_created":true,"verified":false,"freshness_proven":false}),
                )
            }
            Command::VerifyBackup {} => {
                let _ = self
                    .vault
                    .as_mut()
                    .ok_or(Error::Locked)?
                    .verify_backup(BACKUP_PASSWORD)?;
                Ok(serde_json::json!({"backup_integrity_verified":true,"freshness_proven":false}))
            }
            Command::Restore {
                encrypted_backup_hex,
                password,
            } => {
                let password = Zeroizing::new(password);
                if encrypted_backup_hex.len() > 32 * 1024 * 1024 || self.vault.is_some() {
                    return Err(Error::InvalidData);
                }
                let encrypted =
                    hex::decode(encrypted_backup_hex).map_err(|_| Error::InvalidData)?;
                let vault = UnlockedVault::restore(
                    &self.root,
                    &encrypted,
                    BACKUP_PASSWORD,
                    password.as_bytes(),
                )?;
                self.install(vault, false)?;
                self.status()
            }
            Command::Review {
                operation_id,
                client_id,
                obligation_id,
                proposal_id,
                pczt_hex,
            } => {
                if self.pending.is_some() {
                    return Err(Error::ReviewMismatch);
                }
                self.vault()?.require_signing_ready()?;
                for id in [&operation_id, &client_id, &obligation_id, &proposal_id] {
                    validate_id(id)?;
                }
                let account = self
                    .store()?
                    .authority_account(&self.vault()?.account_id())?
                    .ok_or(Error::RecoveryRequired)?;
                if account.recovery_required {
                    return Err(Error::RecoveryRequired);
                }
                if self.store()?.exposure(&operation_id)?.is_some() {
                    return Err(Error::Uncertain);
                }
                let pczt_hex = Zeroizing::new(pczt_hex);
                if pczt_hex.len() > MAX_PCZT * 2 {
                    return Err(Error::InvalidData);
                }
                let bytes = Zeroizing::new(
                    hex::decode(pczt_hex.as_bytes()).map_err(|_| Error::InvalidData)?,
                );
                let policy = policy_for_fixture_pczt(&bytes).map_err(|_| Error::Verification)?;
                let review = verify_review(&bytes, &policy).map_err(|_| Error::Verification)?;
                let owner = self.vault()?.owner_index();
                let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes(
                    *self.vault()?.spending_key_bytes(),
                ))
                .ok_or(Error::Crypto)?;
                if FullViewingKey::from(&sk).to_bytes() != policy.participants[owner].fvk.to_bytes()
                    || policy.participants[owner].account_id != self.vault()?.account_id()
                {
                    return Err(Error::Verification);
                }
                let mut random = [0; 32];
                getrandom::fill(&mut random).map_err(|_| Error::Crypto)?;
                let nonce = hex::encode(random);
                let make_output = |o: &wholepact_protocol::review::OutputPolicy| OutputSummary {
                    receiver_hex: hex::encode(o.receiver.to_raw_address_bytes()),
                    amount_zatoshis: o.value_zatoshis.to_string(),
                };
                let summary = ReviewSummary {
                    qualification_only: true, operation_id: operation_id.clone(), client_id: client_id.clone(), account_id: self.vault()?.account_id(), review_nonce: nonce.clone(), review_binding: review.review_binding().into(), artifact_digest: digest(&bytes), manifest_digest: hex::encode(policy.manifest_digest), effects_digest: review.shielded_sighash().into(), maximum_net_debit_zatoshis: review.net_debits_zatoshis()[owner].to_string(), fee_share_zatoshis: policy.participants[owner].fee_share_zatoshis.to_string(), transaction_fee_zatoshis: review.fee_zatoshis().to_string(),
                    recipients: policy.outputs.iter().filter(|o| matches!(o.purpose, OutputPurpose::Recipient)).map(make_output).collect(),
                    owned_returns: policy.outputs.iter().filter(|o| matches!(o.purpose, OutputPurpose::Return{participant_index} if participant_index==owner)).map(make_output).collect(),
                    expiry_height: policy.expiry_height, network: "testnet NU7 synthetic tree", match_assurance: "fixed contributions only; no identity or sponsor match", chain_validated: false, disclosure: "synthetic private PCZT returned only to this process pipe; no network",
                };
                self.pending = Some(PendingReview {
                    operation_id,
                    client_id,
                    obligation_id,
                    proposal_id,
                    nonce,
                    binding: review.review_binding().into(),
                    pczt: bytes,
                    created: Instant::now(),
                });
                serde_json::to_value(summary).map_err(|_| Error::InvalidData)
            }
            Command::Approve {
                review_nonce,
                review_binding,
                client_id,
                acknowledge_synthetic_only,
            } => {
                let pending = self.pending.take().ok_or(Error::ReviewMismatch)?; // consume even a bad/rejected attempt
                if !acknowledge_synthetic_only
                    || pending.nonce != review_nonce
                    || pending.binding != review_binding
                    || pending.client_id != client_id
                    || pending.created.elapsed() > Duration::from_secs(120)
                {
                    return Err(Error::ReviewMismatch);
                }
                self.vault()?.require_signing_ready()?;
                let policy =
                    policy_for_fixture_pczt(&pending.pczt).map_err(|_| Error::Verification)?;
                let reviewed =
                    verify_review(&pending.pczt, &policy).map_err(|_| Error::Verification)?;
                if reviewed.review_binding() != pending.binding {
                    return Err(Error::ReviewMismatch);
                }
                let owner = self.vault()?.owner_index();
                let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes(
                    *self.vault()?.spending_key_bytes(),
                ))
                .ok_or(Error::Crypto)?;
                if FullViewingKey::from(&sk).to_bytes() != policy.participants[owner].fvk.to_bytes()
                {
                    return Err(Error::Verification);
                }
                let intent = ReleaseIntent {
                    authorization_id: pending.operation_id.clone(),
                    account_id: self.vault()?.account_id(),
                    writer_epoch: 1,
                    obligation_id: pending.obligation_id,
                    proposal_id: pending.proposal_id,
                    manifest_digest: hex::encode(policy.manifest_digest),
                    effects_digest: reviewed.shielded_sighash().into(),
                    artifact_digest: digest(&pending.pczt),
                    maximum_debit: reviewed.net_debits_zatoshis()[owner].to_string(),
                    input_ids: policy
                        .inputs
                        .iter()
                        .filter(|i| i.participant_index == owner)
                        .map(|i| hex::encode(i.nullifier))
                        .collect(),
                    aggregate_budget_limit: policy.participants[owner]
                        .maximum_net_debit_zatoshis
                        .to_string(),
                };
                crash(self.fault, CrashAt::BeforeIntent);
                let consent = Zeroizing::new(serde_json::to_vec(&serde_json::json!({"operation_id":pending.operation_id,"client_id":pending.client_id,"account_id":intent.account_id,"writer_epoch":intent.writer_epoch,"review_nonce":pending.nonce,"review_binding":pending.binding,"manifest_digest":intent.manifest_digest,"artifact_digest":intent.artifact_digest,"effects_digest":intent.effects_digest,"expiry_height":policy.expiry_height})).map_err(|_| Error::InvalidData)?);
                self.vault()?.write_protected(
                    &format!("consent-{}.wp", digest(pending.operation_id.as_bytes())),
                    b"wholepact:synthetic-consent:v1",
                    &consent,
                )?;
                self.store()?.record_authorization_release_intent(&intent)?;
                crash(self.fault, CrashAt::AfterIntent);
                let ask = SpendAuthorizingKey::from(&sk);
                let mut signer =
                    Signer::new(Pczt::parse(&pending.pczt).map_err(|_| Error::Verification)?)
                        .map_err(|_| Error::Verification)?;
                for input in policy
                    .inputs
                    .iter()
                    .filter(|i| i.participant_index == owner)
                {
                    signer
                        .sign_ironwood(UnwrapErr(SysRng), input.action_index, &ask)
                        .map_err(|_| Error::Crypto)?;
                }
                let signed = signer.finish();
                let bytes = Zeroizing::new(
                    pczt::v2::Pczt::try_from(signed)
                        .map_err(|_| Error::Crypto)?
                        .serialize(),
                );
                let rechecked = verify_review(&bytes, &policy).map_err(|_| Error::Verification)?;
                if rechecked.review_binding() != pending.binding {
                    return Err(Error::ReviewMismatch);
                }
                crash(self.fault, CrashAt::AfterSign);
                let result = ProtectedResult {
                    evidence_kind: "synthetic-process-authorization-only".into(),
                    qualification_only: true,
                    chain_validated: false,
                    network: "testnet-NU7-synthetic-tree-expiry140".into(),
                    operation_id: pending.operation_id.clone(),
                    client_id: pending.client_id,
                    request_digest: intent.artifact_digest,
                    review_binding: pending.binding,
                    review_nonce: pending.nonce,
                    signed_pczt_hex: hex::encode(&bytes),
                };
                let encoded =
                    Zeroizing::new(serde_json::to_vec(&result).map_err(|_| Error::InvalidData)?);
                self.vault()?.write_protected(
                    &result_filename(&pending.operation_id),
                    &result_domain(&pending.operation_id),
                    &encoded,
                )?;
                crash(self.fault, CrashAt::AfterResult);
                self.store()?
                    .mark_authorization_released(&pending.operation_id)?;
                crash(self.fault, CrashAt::BeforeExport);
                serde_json::to_value(result).map_err(|_| Error::InvalidData)
            }
            Command::Reject { review_nonce } => {
                let pending = self.pending.take().ok_or(Error::ReviewMismatch)?;
                if pending.nonce != review_nonce {
                    return Err(Error::ReviewMismatch);
                }
                Ok(serde_json::json!({"rejected":true}))
            }
            Command::Retrieve {
                operation_id,
                client_id,
            } => {
                validate_id(&client_id)?;
                validate_id(&operation_id)?;
                let record = self
                    .store()?
                    .exposure(&operation_id)?
                    .ok_or(Error::Uncertain)?;
                if record.intent.account_id != self.vault()?.account_id()
                    || !record.release_intent_recorded
                {
                    return Err(Error::Uncertain);
                }
                let name = result_filename(&operation_id);
                if !self.vault()?.directory().exists(&name)? {
                    return Err(Error::Uncertain);
                }
                // Replay never produces a new signature or clears exposure, even after recovery.
                let bytes = self
                    .vault()?
                    .read_protected(&name, &result_domain(&operation_id))?;
                let result: ProtectedResult =
                    serde_json::from_slice(&bytes).map_err(|_| Error::InvalidData)?;
                if !result.qualification_only
                    || result.chain_validated
                    || result.evidence_kind != "synthetic-process-authorization-only"
                    || result.network != "testnet-NU7-synthetic-tree-expiry140"
                    || result.operation_id != operation_id
                    || result.client_id != client_id
                    || result.request_digest != record.intent.artifact_digest
                {
                    return Err(Error::InvalidData);
                }
                serde_json::to_value(result).map_err(|_| Error::InvalidData)
            }
            Command::Status {} => self.status(),
        }
    }
    fn status(&self) -> Result<serde_json::Value> {
        if let Some(vault) = &self.vault {
            let account = self
                .store()?
                .authority_account(&vault.account_id())?
                .ok_or(Error::RecoveryRequired)?;
            Ok(
                serde_json::json!({"locked":false,"qualification_only":true,"account_id":vault.account_id(),"backup_verified":vault.backup_verified(),"recovery_required":vault.recovery_required()||account.recovery_required,"outstanding_debit_zatoshis":if vault.recovery_required()||account.recovery_required { None } else { Some(self.store()?.outstanding_debit(&vault.account_id())?) },"exposure_completeness_known":!(vault.recovery_required()||account.recovery_required),"exposures":self.store()?.account_exposures(&vault.account_id())?.len(),"automation":false,"live_signing":false}),
            )
        } else {
            Ok(
                serde_json::json!({"locked":true,"qualification_only":true,"automation":false,"live_signing":false}),
            )
        }
    }
}
fn validate_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_:".contains(&b))
    {
        Err(Error::InvalidData)
    } else {
        Ok(())
    }
}
fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn result_filename(operation: &str) -> String {
    format!("result-{}.wp", digest(operation.as_bytes()))
}
fn result_domain(operation: &str) -> Vec<u8> {
    [RESULT_PURPOSE, operation.as_bytes()].concat()
}
