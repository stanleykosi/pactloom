//! Signer-owned maintained viewing-wallet setup, scan, selection and review input.
//! No app-supplied FVK, input-selection flag or context DTO becomes local authority.
//! The only setup constructor consumes an exact signer-native decision. It makes
//! no provider contact until the approved bounded asynchronous scan is requested.
use super::authority::{NativeAuthority, NativeAuthorityBinding, NativeDecision};
use crate::{
    Error, Result,
    account::AccountVault,
    manifest::{AcceptedManifest, LocalSelection, ReviewInputs},
};
use orchard::keys::FullViewingKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    num::NonZeroU32,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use wholepact_core::{OutputAllocation, Proposal};
use wholepact_protocol::{
    construction::{ConstructionContext, InputActionMapping, OutputActionMapping},
    review::{
        InputPolicy, OutputPolicy, OutputPurpose, ParticipantPolicy, ReviewPolicy,
        decode_testnet_receiver,
    },
};
use wholepact_wallet::{
    WalletKeyUseConfidence, WalletKeyUsePolicy,
    wallet::{
        AccountBirthday, AccountUuid, DedicatedTestnetWallet,
        protected_sync::{
            BackendIdentity, ChainAdapter, LocalWalletAccess, NetworkPolicy, ProtectedWalletSync,
            SyncLimits, TreeState, WalletAccessPurpose, account_birthday_from_tree,
            key_use::WalletKeyUseTicket,
        },
    },
};
use zcash_protocol::memo::MemoBytes;

const MAX_SETUP: usize = 32 * 1024;
const MAX_CONTEXT: usize = 2 * 1024 * 1024;
const ACCESS_LIFETIME: Duration = Duration::from_secs(15 * 60);

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SetupAction {
    Create,
    Open,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BirthdayCheckpoint {
    prior_height: u32,
    /// Display-order block hash, as returned by the explicitly chosen source.
    prior_block_hash: String,
    sapling_tree: String,
    orchard_tree: String,
    ironwood_tree: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeWalletSetup {
    schema_version: u32,
    action: SetupAction,
    policy: WalletKeyUsePolicy,
    birthday: Option<BirthdayCheckpoint>,
    maximum_blocks: u32,
}

pub(super) struct PreparedWalletSetup {
    config: NativeWalletSetup,
    source: ChainAdapter,
    birthday: Option<AccountBirthday>,
    account_id: String,
    fvk_digest: String,
    native_origin: NativeAuthorityBinding,
    digest: String,
}
impl PreparedWalletSetup {
    pub(super) fn prepare(
        json: &str,
        vault: &AccountVault,
        authority: &NativeAuthority,
    ) -> Result<Self> {
        authority.check_current()?;
        if vault.account().recovery_required() {
            return Err(Error::RecoveryRequired);
        }
        if json.len() > MAX_SETUP {
            return Err(Error::InvalidData);
        }
        let config: NativeWalletSetup =
            wholepact_core::parse_typed_json(json.as_bytes()).map_err(|_| Error::InvalidData)?;
        if config.schema_version != 1
            || !(1..=1000).contains(&config.maximum_blocks)
            || config.policy.confidence != WalletKeyUseConfidence::TrustedSingleProviderSnapshot
            || !(1..=300).contains(&config.policy.maximum_observation_age_seconds)
            || config.policy.minimum_confirmations == 0
            || config.policy.minimum_expiry_margin_blocks == 0
            || config.policy.source_id.len() > 128
            || config.policy.endpoint.len() > 2048
            || config.policy.endpoint.ends_with('/')
            || (config.action == SetupAction::Create) != config.birthday.is_some()
        {
            return Err(Error::InvalidData);
        }
        // Construction captures the supported existing environment proxy route;
        // it validates TLS configuration but performs no network requests.
        let source = ChainAdapter::testnet(
            &config.policy.source_id,
            &config.policy.endpoint,
            NetworkPolicy {
                observation_ttl: Duration::from_secs(u64::from(
                    config.policy.maximum_observation_age_seconds,
                )),
                ..Default::default()
            },
        )
        .map_err(|_| Error::InvalidData)?;
        let birthday = config
            .birthday
            .as_ref()
            .map(|b| {
                account_birthday_from_tree(TreeState {
                    network: "test".into(),
                    height: u64::from(b.prior_height),
                    hash: b.prior_block_hash.clone(),
                    sapling_tree: b.sapling_tree.clone(),
                    orchard_tree: b.orchard_tree.clone(),
                    ironwood_tree: b.ironwood_tree.clone(),
                    ..Default::default()
                })
                .map_err(|_| Error::InvalidData)
            })
            .transpose()?;
        let account_id = vault.account_id()?;
        let fvk_digest = hex::encode(Sha256::digest(vault.account().fvk()?.to_bytes()));
        let mut hash = Sha256::new();
        hash.update(b"wholepact:native-viewing-wallet-setup:v1\0");
        hash.update(crate::vault::random::<32>()?);
        hash.update(authority.measurement().as_bytes());
        hash.update(account_id.as_bytes());
        hash.update(fvk_digest.as_bytes());
        hash.update(serde_json::to_vec(&config).map_err(|_| Error::InvalidData)?);
        Ok(Self {
            config,
            source,
            birthday,
            account_id,
            fvk_digest,
            native_origin: authority.binding(),
            digest: hex::encode(hash.finalize()),
        })
    }
    pub(super) fn digest(&self) -> &str {
        &self.digest
    }
    pub(super) fn display(&self) -> Result<String> {
        Ok(format!(
            "SET UP SIGNER-OWNED DEDICATED VIEWING WALLET\nAccount: {}\nExact configuration:\n{}\n\nThis explicitly permits importing this signer's dedicated FVK into its private encrypted viewing database (create only), and bounded public-block synchronization plus local note selection for this native session. Grant expires after 15 minutes or native lock/revocation. No spending key leaves the signer, and this is not spending or witness-disclosure approval.\nThe chosen provider and the existing environment proxy can observe IP, timing, public block heights and history ranges. No private viewing key, note or nullifier is sent to the block provider. The existing proxy route is captured at setup; unsupported configurations fail without direct fallback.\nTrust: one explicitly chosen TLS provider, not independent consensus or a global unspentness oracle. Maximum provider tip age is 1200 seconds under the supported network profile. Cache ages only shorten freshness; absent cache metadata does not prove provider refresh. Chain reorganizations, missing mempool conflicts and other-wallet spends remain possible.\nA birthday checkpoint is an explicitly accepted source claim. A wrong or too-late birthday can omit wallet history; import and chain mismatches fail closed. Interrupted or missing wallet storage requires recovery, never silent recreation.",
            self.account_id,
            serde_json::to_string_pretty(&self.config).map_err(|_| Error::InvalidData)?
        ))
    }
    pub(super) fn approve(
        self,
        decision: NativeDecision,
        authority: &NativeAuthority,
        vault: &AccountVault,
    ) -> Result<NativeWalletWorkspace> {
        authority.check_current()?;
        if decision.binding() != &self.native_origin
            || decision.binding() != &authority.binding()
            || decision.reviewed_digest() != self.digest
            || vault.account().recovery_required()
            || vault.account_id()? != self.account_id
            || hex::encode(Sha256::digest(vault.account().fvk()?.to_bytes())) != self.fvk_digest
        {
            return Err(Error::ReviewMismatch);
        }
        let fvk = vault.account().fvk()?;
        let minimum =
            NonZeroU32::new(self.config.policy.minimum_confirmations).ok_or(Error::InvalidData)?;
        let controller = match self.config.action {
            SetupAction::Create => {
                let mut wallet = DedicatedTestnetWallet::from_encrypted_connection(
                    vault.create_viewing_wallet_storage()?,
                )
                .map_err(|_| Error::RecoveryRequired)?;
                wallet
                    .import_dedicated_fvk(&fvk, self.birthday.ok_or(Error::InvalidData)?)
                    .map_err(|_| Error::RecoveryRequired)?;
                ProtectedWalletSync::from_initialized_wallet(wallet, self.source, minimum)
                    .map_err(|_| Error::RecoveryRequired)?
            }
            SetupAction::Open => ProtectedWalletSync::from_encrypted_connection(
                vault.open_viewing_wallet_storage()?,
                self.source,
                minimum,
            )
            .map_err(|_| Error::RecoveryRequired)?,
        };
        controller
            .verify_account_fvk(&fvk)
            .map_err(|_| Error::Verification)?;
        let revocation = NativeWalletRevocation {
            active: Arc::new(AtomicBool::new(true)),
        };
        let access = NativeWalletAccess {
            account: controller.account_uuid(),
            source: controller.status().map_err(|_| Error::Verification)?.source,
            origin: self.native_origin,
            revocation: revocation.clone(),
            approved: Instant::now(),
        };
        Ok(NativeWalletWorkspace {
            controller,
            access,
            fvk,
            account_id: self.account_id,
            policy: self.config.policy,
            maximum_blocks: self.config.maximum_blocks,
            ticket: None,
        })
    }
}

#[derive(Clone)]
pub(super) struct NativeWalletRevocation {
    active: Arc<AtomicBool>,
}
impl NativeWalletRevocation {
    pub(super) fn revoke(&self) {
        self.active.store(false, Ordering::Release);
    }
}
struct NativeWalletAccess {
    account: AccountUuid,
    source: BackendIdentity,
    origin: NativeAuthorityBinding,
    revocation: NativeWalletRevocation,
    approved: Instant,
}
impl NativeWalletAccess {
    fn check(&self) -> Result<()> {
        self.origin.check_current()?;
        if !self.revocation.active.load(Ordering::Acquire)
            || self.approved.elapsed() >= ACCESS_LIFETIME
        {
            return Err(Error::Locked);
        }
        Ok(())
    }
}
impl LocalWalletAccess for NativeWalletAccess {
    fn permits(
        &self,
        account: AccountUuid,
        provider: &BackendIdentity,
        _: WalletAccessPurpose,
    ) -> bool {
        self.check().is_ok() && self.account == account && &self.source == provider
    }
}

pub(super) struct NativeWalletWorkspace {
    controller: ProtectedWalletSync,
    access: NativeWalletAccess,
    fvk: FullViewingKey,
    account_id: String,
    policy: WalletKeyUsePolicy,
    maximum_blocks: u32,
    ticket: Option<WalletKeyUseTicket>,
}
impl NativeWalletWorkspace {
    pub(super) fn check_current(&self) -> Result<()> {
        self.access.check()
    }
    pub(super) fn revoke_handle(&self) -> NativeWalletRevocation {
        self.access.revocation.clone()
    }
    pub(super) fn wallet_mut(&mut self) -> &mut ProtectedWalletSync {
        &mut self.controller
    }
    pub(super) fn take_ticket(&mut self) -> Result<WalletKeyUseTicket> {
        self.access.check()?;
        let ticket = self.ticket.take().ok_or(Error::ReviewMismatch)?;
        ticket
            .validate_policy(&self.policy)
            .map_err(|_| Error::Verification)?;
        Ok(ticket)
    }
    pub(super) fn invalidate_selection(&mut self) {
        self.ticket = None;
        self.controller.invalidate_observation();
    }
    pub(super) async fn synchronize_review(
        &mut self,
        proposal: &Proposal,
        untrusted_context: &[u8],
    ) -> Result<ReviewInputs> {
        // Invalidate first, even when parsing, permission or a new scan fails.
        self.invalidate_selection();
        self.access.check()?;
        let envelope = ContextEnvelope::decode(untrusted_context, proposal)?;
        let own = proposal
            .manifest()
            .participants
            .iter()
            .find(|p| p.account_id == self.account_id)
            .ok_or(Error::Verification)?;
        let debit = own
            .contribution
            .as_zatoshis()
            .checked_add(own.fee_share.as_zatoshis())
            .ok_or(Error::Verification)?;
        self.controller
            .verify_account_fvk(&self.fvk)
            .map_err(|_| Error::Verification)?;
        self.controller
            .synchronize(
                &self.access,
                SyncLimits {
                    maximum_blocks: self.maximum_blocks,
                    anchor_height: Some(envelope.construction_context.anchor_height),
                    deadline: Duration::from_secs(120),
                },
            )
            .await
            .map_err(|_| Error::Verification)?;
        self.access.check()?;
        let selected = self
            .controller
            .select_contribution(&self.access, &self.fvk, &self.account_id, debit, &[])
            .map_err(|_| Error::Verification)?;
        let ticket = selected.key_use_ticket();
        let local = LocalSelection::from_key_use_ticket(&ticket, &self.policy)?;
        let inputs = envelope.into_review(proposal, local, &self.account_id, &self.fvk)?;
        // Imported mappings and policy never replace selected authority. A request
        // that names different valid wallet inputs still fails, rather than silently
        // approving a new selection or modifying the original accepted manifest.
        crate::manifest::reconcile(
            &AcceptedManifest {
                proposal: proposal.clone(),
            },
            &inputs,
            &self.account_id,
            &self.fvk,
        )?;
        self.access.check()?;
        ticket
            .validate_policy(&self.policy)
            .map_err(|_| Error::Verification)?;
        self.ticket = Some(ticket);
        Ok(inputs)
    }
}
impl Drop for NativeWalletWorkspace {
    fn drop(&mut self) {
        self.access.revocation.revoke();
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimedConstructionContext {
    anchor: String,
    anchor_height: u32,
    anchor_block_hash: String,
    target_height: u32,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimedParticipantView {
    account_id: String,
    fvk: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimedInputAction {
    input_id: String,
    account_id: String,
    action_index: usize,
    nullifier: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimedOutputAction {
    output_id: String,
    action_index: usize,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextEnvelope {
    schema_version: u32,
    manifest_digest: String,
    construction_context: ClaimedConstructionContext,
    participant_views: Vec<ClaimedParticipantView>,
    input_actions: Vec<ClaimedInputAction>,
    output_actions: Vec<ClaimedOutputAction>,
}
impl ContextEnvelope {
    fn decode(bytes: &[u8], proposal: &Proposal) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_CONTEXT {
            return Err(Error::InvalidData);
        }
        let value: Self =
            wholepact_core::parse_typed_json(bytes).map_err(|_| Error::InvalidData)?;
        if value.schema_version != 1
            || value.manifest_digest != proposal.manifest_digest()
            || value.participant_views.len() != proposal.manifest().participants.len()
            || value.input_actions.len() != proposal.manifest().inputs.len()
            || value.output_actions.len() != proposal.manifest().outputs.len()
            || value.participant_views.len() > 32
            || value.input_actions.len() > 64
            || value.output_actions.len() > 64
        {
            return Err(Error::Verification);
        }
        Ok(value)
    }
    fn into_review(
        self,
        proposal: &Proposal,
        own_selection: LocalSelection,
        own_account: &str,
        actual_fvk: &FullViewingKey,
    ) -> Result<ReviewInputs> {
        let manifest = proposal.manifest();
        let mut seen_accounts = BTreeSet::new();
        let mut participants = Vec::with_capacity(self.participant_views.len());
        for view in self.participant_views {
            if !seen_accounts.insert(view.account_id.clone()) {
                return Err(Error::Verification);
            }
            let participant = manifest
                .participants
                .iter()
                .find(|p| p.account_id == view.account_id)
                .ok_or(Error::Verification)?;
            let fvk = FullViewingKey::from_bytes(&decode_hex::<96>(&view.fvk)?)
                .ok_or(Error::Verification)?;
            if view.account_id == own_account && fvk.to_bytes() != actual_fvk.to_bytes() {
                return Err(Error::Verification);
            }
            participants.push(ParticipantPolicy {
                account_id: view.account_id,
                fvk,
                contribution_zatoshis: participant.contribution.as_zatoshis(),
                fee_share_zatoshis: participant.fee_share.as_zatoshis(),
                maximum_net_debit_zatoshis: participant.maximum_net_debit.as_zatoshis(),
            });
        }
        let mut input_ids = BTreeSet::new();
        let mut input_indices = BTreeSet::new();
        let mut inputs = Vec::new();
        let mut input_actions = Vec::new();
        for map in self.input_actions {
            if map.action_index >= 128
                || !input_ids.insert(map.input_id.clone())
                || !input_indices.insert(map.action_index)
            {
                return Err(Error::Verification);
            }
            let declared = manifest
                .inputs
                .iter()
                .find(|i| i.input_id == map.input_id && i.account_id == map.account_id)
                .ok_or(Error::Verification)?;
            let participant_index = participants
                .iter()
                .position(|p| p.account_id == map.account_id)
                .ok_or(Error::Verification)?;
            inputs.push(InputPolicy {
                action_index: map.action_index,
                participant_index,
                nullifier: decode_hex(&map.nullifier)?,
                value_zatoshis: declared.amount.as_zatoshis(),
            });
            input_actions.push(InputActionMapping {
                input_id: map.input_id,
                account_id: map.account_id,
                action_index: map.action_index,
            });
        }
        let mut output_ids = BTreeSet::new();
        let mut output_indices = BTreeSet::new();
        let mut outputs = Vec::new();
        let mut output_actions = Vec::new();
        for map in self.output_actions {
            if map.action_index >= 128
                || !output_ids.insert(map.output_id.clone())
                || !output_indices.insert(map.action_index)
            {
                return Err(Error::Verification);
            }
            let declared = manifest
                .outputs
                .iter()
                .find(|o| o.output_id == map.output_id)
                .ok_or(Error::Verification)?;
            let (purpose, memo) = match &declared.allocation {
                OutputAllocation::Recipient { recipient_id } => {
                    let recipient = manifest
                        .agreement
                        .recipients
                        .iter()
                        .find(|r| r.recipient_id == *recipient_id)
                        .ok_or(Error::Verification)?;
                    let memo = recipient
                        .memo
                        .as_ref()
                        .map(|v| MemoBytes::from_bytes(v.as_bytes()))
                        .transpose()
                        .map_err(|_| Error::Verification)?
                        .unwrap_or_else(MemoBytes::empty);
                    (OutputPurpose::Recipient, memo.into_bytes())
                }
                OutputAllocation::Return { account_id, .. } => {
                    let participant_index = participants
                        .iter()
                        .position(|p| p.account_id == *account_id)
                        .ok_or(Error::Verification)?;
                    (
                        OutputPurpose::Return { participant_index },
                        MemoBytes::empty().into_bytes(),
                    )
                }
                OutputAllocation::Charge { .. } => return Err(Error::Verification),
            };
            outputs.push(OutputPolicy {
                action_index: map.action_index,
                receiver: decode_testnet_receiver(&declared.address)
                    .map_err(|_| Error::Verification)?,
                value_zatoshis: declared.amount.as_zatoshis(),
                memo,
                purpose,
            });
            output_actions.push(OutputActionMapping {
                output_id: map.output_id,
                action_index: map.action_index,
            });
        }
        let context = ConstructionContext {
            anchor: decode_hex(&self.construction_context.anchor)?,
            anchor_height: self.construction_context.anchor_height,
            anchor_block_hash: decode_hex(&self.construction_context.anchor_block_hash)?,
            target_height: self.construction_context.target_height,
        };
        Ok(ReviewInputs {
            construction_context: context,
            own_selection,
            input_actions,
            output_actions,
            policy: ReviewPolicy {
                manifest_digest: decode_hex(&self.manifest_digest)?,
                participants,
                inputs,
                outputs,
                exact_fee_zatoshis: manifest.transaction_fee.as_zatoshis(),
                expiry_height: manifest.expiry_height,
                anchor: context.anchor,
            },
        })
    }
}
fn decode_hex<const N: usize>(text: &str) -> Result<[u8; N]> {
    if text.len() != N * 2
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::InvalidData);
    }
    hex::decode(text)
        .map_err(|_| Error::InvalidData)?
        .try_into()
        .map_err(|_| Error::InvalidData)
}

#[cfg(all(test, feature = "synthetic-qualification"))]
mod tests {
    use super::*;
    fn envelope(proposal: &Proposal, inputs: &ReviewInputs) -> serde_json::Value {
        serde_json::json!({
            "schema_version": 1, "manifest_digest": proposal.manifest_digest(),
            "construction_context": {
                "anchor": hex::encode(inputs.construction_context.anchor),
                "anchor_height": inputs.construction_context.anchor_height,
                "anchor_block_hash": hex::encode(inputs.construction_context.anchor_block_hash),
                "target_height": inputs.construction_context.target_height,
            },
            "participant_views": inputs.policy.participants.iter().map(|p| serde_json::json!({"account_id":p.account_id,"fvk":hex::encode(p.fvk.to_bytes())})).collect::<Vec<_>>(),
            "input_actions": inputs.input_actions.iter().map(|m| {
                let i=inputs.policy.inputs.iter().find(|i|i.action_index==m.action_index).unwrap();
                serde_json::json!({"input_id":m.input_id,"account_id":m.account_id,"action_index":m.action_index,"nullifier":hex::encode(i.nullifier)})
            }).collect::<Vec<_>>(),
            "output_actions": inputs.output_actions.iter().map(|m| serde_json::json!({"output_id":m.output_id,"action_index":m.action_index})).collect::<Vec<_>>(),
        })
    }
    #[test]
    fn untrusted_context_reconstructs_only_accepted_terms_and_reconciles_actual_effects() {
        let (accepted, inputs, bytes) = crate::manifest::tests::consent_fixture();
        let claimed = serde_json::to_vec(&envelope(&accepted.proposal, &inputs)).unwrap();
        let fvk = inputs.policy.participants[0].fvk.clone();
        let owner = inputs.policy.participants[0].account_id.clone();
        let parsed = ContextEnvelope::decode(&claimed, &accepted.proposal)
            .unwrap()
            .into_review(&accepted.proposal, inputs.own_selection, &owner, &fvk)
            .unwrap();
        crate::manifest::reconcile(&accepted, &parsed, &owner, &fvk).unwrap();
        wholepact_protocol::review::verify_review(&bytes, &parsed.policy).unwrap();
        assert_eq!(
            parsed.policy.exact_fee_zatoshis,
            accepted.proposal.manifest().transaction_fee.as_zatoshis()
        );
    }
    #[test]
    fn context_flags_extra_fields_duplicate_maps_and_wrong_own_fvk_never_grant_authority() {
        for mutation in 0..4 {
            let (accepted, inputs, _) = crate::manifest::tests::consent_fixture();
            let fvk = inputs.policy.participants[0].fvk.clone();
            let owner = inputs.policy.participants[0].account_id.clone();
            let mut claimed = envelope(&accepted.proposal, &inputs);
            match mutation {
                0 => claimed["verified"] = true.into(),
                1 => claimed["manifest_digest"] = "00".repeat(32).into(),
                2 => claimed["input_actions"][1] = claimed["input_actions"][0].clone(),
                _ => {
                    claimed["participant_views"][0]["fvk"] =
                        claimed["participant_views"][1]["fvk"].clone()
                }
            }
            let outcome =
                ContextEnvelope::decode(&serde_json::to_vec(&claimed).unwrap(), &accepted.proposal)
                    .and_then(|e| {
                        e.into_review(&accepted.proposal, inputs.own_selection, &owner, &fvk)
                    })
                    .and_then(|parsed| {
                        crate::manifest::reconcile(&accepted, &parsed, &owner, &fvk)
                    });
            assert!(outcome.is_err());
        }
    }
    #[test]
    fn unknown_and_oversized_context_fails_before_wallet_contact() {
        let (accepted, _, _) = crate::manifest::tests::consent_fixture();
        assert!(ContextEnvelope::decode(&[], &accepted.proposal).is_err());
        assert!(ContextEnvelope::decode(&vec![b' '; MAX_CONTEXT + 1], &accepted.proposal).is_err());
        assert!(decode_hex::<32>(&"AB".repeat(32)).is_err());
    }
}

#[cfg(feature = "offline-review-foundation")]
mod named_recipient;

#[cfg(feature = "offline-review-foundation")]
pub(super) use named_recipient::NamedRecipientOwnerContext;
