//! One concrete original-to-current-input path. No decoded scope, imported
//! receipt, browser flag or expired construction observation can enter it.
use super::Host;
use crate::host::born_offline_return_owner_v1::RetainedBornMergedTransactionV1;
use crate::{
    Error, Result,
    authority::born_post_return_inputs_v1::{BornPostReturnNativeReadV1, wall_ms},
    financial_inventory::{self, AttachmentRole},
    financial_profile::born_post_return_v1::{
        BornPostReturnWalletProvenanceV1, BornPostReturnWalletV1,
    },
};
use std::{
    cell::Cell,
    collections::{BTreeMap, BTreeSet},
    num::NonZeroU32,
    path::Path,
    time::Instant,
};
use wholepact_chain::{ChainAdapter, ChainContext, NetworkPolicy};
use wholepact_core::manual_roster_inventory_v2::ManualRosterInventoryScopeV2;
use wholepact_protocol::authorization::retention::transaction::submission_handoff::VerifiedRetainedSubmission;
use wholepact_wallet::wallet::protected_sync::born_post_return_inputs_v1::FullViewingKey;
use wholepact_wallet::wallet::protected_sync::born_post_return_inputs_v1::{
    BornPostReturnErrorV1, BornPostReturnInputV1, BornPostReturnReadPermissionV1,
    BornPostReturnWalletReaderV1, BornPostReturnWalletScopeV1, FreshBornPostReturnInputsV1,
};

/// Dispatch-visible current evidence exists ONLY while every exact existing
/// wallet's maintained immediate transaction remains held. Never serializable.
pub(in crate::host) struct HeldBornPostReturnInputsV1<'held> {
    original_submission: &'held VerifiedRetainedSubmission,
    check: &'held dyn Fn() -> Result<()>,
    context: &'held ChainContext,
    read_profile: &'held wholepact_chain::public_read_profile_v1::PublicReadProfileV1,
    digest: &'held str,
    observed_at_ms: u64,
    expires_at_ms: u64,
    deadline: Instant,
}
impl HeldBornPostReturnInputsV1<'_> {
    /// A held scan is usable only with the SAME actual opaque merged predecessor
    /// from which its exact inputs were derived. Equal hashes, economics, tips or
    /// cloned descriptors cannot reconstruct this in-process original identity.
    pub(in crate::host) fn require_original_submission(
        &self,
        original: &RetainedBornMergedTransactionV1<'_, '_, '_>,
    ) -> Result<()> {
        require_same_original_borrow(self.original_submission, original.verified_submission())?;
        self.check_current()?;
        original.check_current_until(self.deadline)
    }

    pub(in crate::host) fn check_current(&self) -> Result<()> {
        (self.check)()
    }
    pub(in crate::host) fn context(&self) -> &ChainContext {
        self.context
    }
    pub(in crate::host) fn read_profile(
        &self,
    ) -> &wholepact_chain::public_read_profile_v1::PublicReadProfileV1 {
        self.read_profile
    }
    pub(in crate::host) fn digest(&self) -> &str {
        self.digest
    }
    pub(in crate::host) fn observed_at_ms(&self) -> u64 {
        self.observed_at_ms
    }
    pub(in crate::host) fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
    /// Only a restriction on existing evidence. No wall-clock conversion or
    /// repeated access can renew the original native/provider observation.
    pub(in crate::host) fn monotonic_deadline(&self) -> Instant {
        self.deadline
    }
}
struct Permission<'a, 'read, 'owner, 'host> {
    host: &'host Host,
    original: &'a RetainedBornMergedTransactionV1<'read, 'owner, 'host>,
    native: &'a BornPostReturnNativeReadV1,
    scope: &'a BornPostReturnWalletScopeV1,
    provenance: &'a BornPostReturnWalletProvenanceV1,
    fvk: &'a FullViewingKey,
    deadline: Cell<Instant>,
}
impl BornPostReturnReadPermissionV1 for Permission<'_, '_, '_, '_> {
    fn scope(&self) -> &BornPostReturnWalletScopeV1 {
        self.scope
    }
    fn authenticated_fvk(&self) -> &FullViewingKey {
        self.fvk
    }
    fn monotonic_deadline(&self) -> Instant {
        self.deadline.get().min(self.native.deadline())
    }
    fn check_current(&self) -> std::result::Result<(), BornPostReturnErrorV1> {
        self.check().map_err(|_| BornPostReturnErrorV1::Permission)
    }
}
impl Permission<'_, '_, '_, '_> {
    fn check(&self) -> Result<()> {
        let deadline = self.deadline.get().min(self.native.deadline());
        if Instant::now() >= deadline {
            return Err(Error::Permission);
        }
        self.original.check_current_until(deadline)?;
        self.native.check(&self.host.authority)?;
        let primary = self.host.financial.as_ref().ok_or(Error::Locked)?;
        financial_inventory::manual::require_born_post_return_wallet_binding_v1(
            &self.host.directory,
            &self.host.secrets,
            primary,
            self.provenance,
            &self.scope.import_scope.inventory.attachment,
        )?;
        if self
            .provenance
            .wallet_origin_digest(&self.host.secrets.profile())?
            != self.scope.wallet_origin_digest
        {
            return Err(Error::Authentication);
        }
        self.original
            .original()
            .check_current(self.host.access()?)
            .map_err(|_| Error::Permission)
    }
}
impl Host {
    pub(in crate::host) fn with_born_post_return_inputs_v1<R>(
        &self,
        original: &RetainedBornMergedTransactionV1<'_, '_, '_>,
        callback: impl FnOnce(&HeldBornPostReturnInputsV1<'_>) -> Result<R>,
    ) -> Result<R> {
        original.check_current()?;
        let claim = original.original().claim();
        let primary = self.financial.as_ref().ok_or(Error::Locked)?;
        primary.check_current_journals()?;
        if !(2..=8).contains(&claim.consumed.len()) {
            return Err(Error::Invalid);
        }
        let descriptors = claim
            .consumed
            .iter()
            .map(|c| {
                &c.request
                    .plan
                    .retained
                    .selection
                    .scope
                    .selection
                    .inventory
                    .attachment
            })
            .collect::<Vec<_>>();
        let prior=self.terminal.approve_historical(&format!(
            "Open ONLY these already registered existing participant wallet journals for one fresh born post-return input observation. This reads private exact account/FVK/import history, retains bounded public scan progress locally, and holds the original file identities. It creates no wallet/account, imports no key, signs nothing and sends no transaction. A second exact native review will name actual wallet DB origins, exact original inputs, final transaction and provider before network/scan use.\nOriginal retained transaction: {}\nOriginal registered dependencies: {}",original.verified_submission().descriptor().transaction_id,serde_json::to_string_pretty(&descriptors)?))?;
        original.check_current()?;
        let mut passwords = Vec::new();
        for consumed in &claim.consumed {
            prior.check()?;
            original.check_current()?;
            let inventory = &consumed
                .request
                .plan
                .retained
                .selection
                .scope
                .selection
                .inventory;
            let path = Path::new(&inventory.attachment.selected.canonical_directory);
            if !financial_inventory::known_entry_before_open(
                &self.directory,
                &self.secrets,
                path,
                AttachmentRole::ParticipantWallet,
                Some(&inventory.enrollment.identity.account_id),
            )? {
                return Err(Error::Authentication);
            }
            let password = self.terminal.secret(&format!(
                "Existing participant wallet passphrase for account {} at {}: ",
                inventory.enrollment.identity.account_id,
                path.display()
            ))?;
            passwords.push(password);
        }
        // A single one-use native effect owns every exact existing-file open.
        // No prompt or network wait occurs under the terminal mutex. Passwords
        // stay zeroizing and are dropped before the separate scan disclosure.
        let mut wallets = Vec::new();
        prior.effect(&mut || {
            if passwords.len() != claim.consumed.len() {
                return Err(Error::Invalid);
            }
            for (consumed, password) in claim.consumed.iter().zip(&passwords) {
                prior.check()?;
                original.check_current()?;
                let inventory = &consumed
                    .request
                    .plan
                    .retained
                    .selection
                    .scope
                    .selection
                    .inventory;
                let path = Path::new(&inventory.attachment.selected.canonical_directory);
                if !financial_inventory::known_entry_before_open(
                    &self.directory,
                    &self.secrets,
                    path,
                    AttachmentRole::ParticipantWallet,
                    Some(&inventory.enrollment.identity.account_id),
                )? {
                    return Err(Error::Authentication);
                }
                let source = ChainAdapter::testnet(
                    &inventory.provider.source_id,
                    &inventory.provider.endpoint,
                    NetworkPolicy::default(),
                )?;
                let wallet = BornPostReturnWalletV1::open_existing(
                    path,
                    &self.secrets.profile(),
                    password.as_bytes(),
                    source,
                    NonZeroU32::new(inventory.minimum_confirmations).ok_or(Error::Invalid)?,
                )?;
                financial_inventory::manual::require_born_post_return_wallet_binding_v1(
                    &self.directory,
                    &self.secrets,
                    primary,
                    &wallet.provenance,
                    &inventory.attachment,
                )?;
                prior.check()?;
                original.check_current()?;
                wallets.push(wallet);
            }
            Ok(())
        })?;
        drop(passwords);
        let scopes = derive_scopes(self, original, &wallets)?;
        let native = BornPostReturnNativeReadV1::review(
            &self.authority,
            &prior,
            &claim.principal_id,
            &scopes,
            || original.check_current(),
        )?;
        let mut readers = Vec::new();
        let mut permissions = Vec::new();
        for (wallet, scope) in wallets.iter_mut().zip(&scopes) {
            let participants = &original.original().checkpoint().policy().participants;
            let fvk = &participants
                .iter()
                .find(|p| {
                    p.account_id == scope.import_scope.inventory.enrollment.identity.account_id
                })
                .ok_or(Error::Authentication)?
                .fvk;
            readers.push(&mut wallet.reader);
            permissions.push(Permission {
                host: self,
                original,
                native: &native,
                scope,
                provenance: &wallet.provenance,
                fvk,
                deadline: Cell::new(native.deadline()),
            });
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| Error::Invalid)?;
        let mut fresh = Vec::new();
        // Strict shared 60-second native bound is rechecked for each scan. No
        // stale result is renewed while later owners complete. Different tips
        // refuse below; neither a timeout nor partial scan admits dispatch.
        for (reader, permission) in readers.iter_mut().zip(&permissions) {
            permission.check()?;
            fresh.push(
                runtime
                    .block_on(reader.observe_born_post_return_inputs_v1(permission))
                    .map_err(|_| Error::Permission)?,
            );
        }
        let first = fresh.first().ok_or(Error::Invalid)?;
        let context = first.observation();
        let read_profile = &scopes.first().ok_or(Error::Invalid)?.provider_read_profile;
        if scopes
            .iter()
            .any(|s| &s.provider_read_profile != read_profile)
        {
            return Err(Error::Authentication);
        }
        for observation in &fresh {
            observation.check_current().map_err(|_| Error::Permission)?;
            if observation.observation().tip() != context.tip()
                || observation.observation().source() != context.source()
                || observation.observation().network() != context.network()
                || observation.observation().branch_id() != context.branch_id()
            {
                return Err(Error::Authentication);
            }
        }
        let observed_at_ms = fresh
            .iter()
            .map(|f| f.observed_at_ms())
            .min()
            .ok_or(Error::Invalid)?;
        let expires_at_ms = fresh
            .iter()
            .map(|f| f.expires_at_ms())
            .min()
            .ok_or(Error::Invalid)?;
        let deadline = fresh
            .iter()
            .map(|f| f.monotonic_deadline())
            .min()
            .ok_or(Error::Invalid)?
            .min(native.deadline());
        // Tighten every subsequent wallet/native/history check to the SAME
        // immutable earliest cutoff before taking any wallet transaction lock.
        // This can only shorten the native lifetime and never renews evidence.
        for permission in &permissions {
            permission
                .deadline
                .set(permission.deadline.get().min(deadline));
        }
        if expires_at_ms <= observed_at_ms || expires_at_ms - observed_at_ms > 60_000 {
            return Err(Error::Permission);
        }
        let digests = fresh.iter().map(|f| f.digest()).collect::<Vec<_>>();
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:born-post-return-all-wallets:v1",
            &(
                &scopes,
                &digests,
                native.review_digest(),
                context,
                observed_at_ms,
                expires_at_ms,
            ),
        )
        .map_err(|_| Error::Invalid)?;
        let mut slots = readers.into_iter().zip(&fresh).collect::<Vec<_>>();
        let root = || {
            original.check_current_until(deadline)?;
            native.check(&self.authority)?;
            for permission in &permissions {
                permission.check()?;
            }
            Ok(())
        };
        let facts = AggregateFacts {
            original_submission: original.verified_submission(),
            context,
            read_profile,
            digest: &digest,
            observed_at_ms,
            expires_at_ms,
            deadline,
        };
        hold_all(&mut slots, &root, &facts, &mut Some(callback))
    }
}
struct AggregateFacts<'a> {
    original_submission: &'a VerifiedRetainedSubmission,
    context: &'a ChainContext,
    read_profile: &'a wholepact_chain::public_read_profile_v1::PublicReadProfileV1,
    digest: &'a str,
    observed_at_ms: u64,
    expires_at_ms: u64,
    deadline: Instant,
}
fn hold_all<R, F>(
    slots: &mut [(
        &mut BornPostReturnWalletReaderV1,
        &FreshBornPostReturnInputsV1<'_>,
    )],
    prior: &dyn Fn() -> Result<()>,
    facts: &AggregateFacts<'_>,
    callback: &mut Option<F>,
) -> Result<R>
where
    F: FnOnce(&HeldBornPostReturnInputsV1<'_>) -> Result<R>,
{
    prior()?;
    for (_, fresh) in slots.iter() {
        fresh.check_current().map_err(|_| Error::Permission)?;
    }
    let Some(((reader, fresh), rest)) = slots.split_first_mut() else {
        let held = HeldBornPostReturnInputsV1 {
            original_submission: facts.original_submission,
            check: prior,
            context: facts.context,
            read_profile: facts.read_profile,
            digest: facts.digest,
            observed_at_ms: facts.observed_at_ms,
            expires_at_ms: facts.expires_at_ms,
            deadline: facts.deadline,
        };
        held.check_current()?;
        let result = callback.take().ok_or(Error::Invalid)?(&held)?;
        held.check_current()?;
        return Ok(result);
    };
    reader.with_born_post_return_inputs_v1(fresh, |held| {
        let check = || {
            prior()?;
            held.check_current().map_err(|_| Error::Permission)
        };
        check()?;
        let result = hold_all(rest, &check, facts, callback)?;
        check()?;
        Ok(result)
    })
}
impl From<BornPostReturnErrorV1> for Error {
    fn from(_: BornPostReturnErrorV1) -> Self {
        Error::Permission
    }
}
fn decode(s: &str) -> Result<[u8; 32]> {
    hex::decode(s)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or(Error::Invalid)
}
fn derive_scopes(
    host: &Host,
    original: &RetainedBornMergedTransactionV1<'_, '_, '_>,
    wallets: &[BornPostReturnWalletV1],
) -> Result<Vec<BornPostReturnWalletScopeV1>> {
    original.check_current()?;
    let old = original.original();
    let claim = old.claim();
    let checkpoint = old.checkpoint();
    let descriptor = original.verified_submission().descriptor();
    let first = &claim.consumed.first().ok_or(Error::Invalid)?.request.plan;
    let common = &first.common_context;
    if descriptor.expiry_height != common.expiry_height
        || descriptor.network != "testnet"
        || descriptor.consensus_branch_id != wholepact_chain::NU7_BRANCH_ID
    {
        return Err(Error::Authentication);
    }
    let binding = wholepact_core::proposal::canonical_digest(
        "wholepact:born-post-return-original:v1",
        &(
            claim.request_digest().map_err(|_| Error::Invalid)?,
            old.receipt(),
            checkpoint.summary(),
            descriptor,
            original.verified_submission().signed_request_digest(),
            original.verified_submission().signed_candidate_digest(),
        ),
    )
    .map_err(|_| Error::Invalid)?;
    let mut all_inputs = Vec::new();
    let mut by_account = BTreeMap::new();
    let mut ancestry = BTreeMap::new();
    for consumed in &claim.consumed {
        let plan = &consumed.request.plan;
        if plan.common_context != *common {
            return Err(Error::Authentication);
        }
        let account = &plan.enrollment().identity.account_id;
        let owner_index = checkpoint
            .policy()
            .participants
            .iter()
            .position(|p| &p.account_id == account)
            .ok_or(Error::Authentication)?;
        let mut own = Vec::new();
        for input in plan.selected_inputs() {
            let nullifier = decode(&input.nullifier)?;
            let found = checkpoint
                .policy()
                .inputs
                .iter()
                .filter(|i| {
                    i.participant_index == owner_index
                        && i.nullifier == nullifier
                        && i.value_zatoshis == input.value_zatoshis
                })
                .collect::<Vec<_>>();
            if found.len() != 1 {
                return Err(Error::Authentication);
            }
            own.push(BornPostReturnInputV1 {
                input_id: input.input_id.clone(),
                nullifier: input.nullifier.clone(),
                value_zatoshis: input.value_zatoshis,
                action_index: found[0].action_index,
            });
        }
        own.sort_by_key(|i| i.action_index);
        all_inputs.extend(own.clone());
        if by_account.insert(account.clone(), own).is_some() {
            return Err(Error::Authentication);
        }
        let c = &plan.retained.selection_context;
        let hash = decode(&c.tip_hash_protocol)?;
        if ancestry
            .insert(c.tip_height, hash)
            .is_some_and(|old| old != hash)
        {
            return Err(Error::Authentication);
        }
    }
    all_inputs.sort_by_key(|i| i.action_index);
    if all_inputs.len() != checkpoint.policy().inputs.len()
        || all_inputs
            .iter()
            .map(|i| i.action_index)
            .collect::<BTreeSet<_>>()
            .len()
            != all_inputs.len()
    {
        return Err(Error::Authentication);
    }
    let expires = wall_ms()?.checked_add(60_000).ok_or(Error::Invalid)?;
    let minimum_margin = common.read_profile.minimum_expiry_margin_blocks;
    let max_tip = common
        .reference_tip_height
        .checked_add(1000)
        .ok_or(Error::Invalid)?
        .min(
            common
                .expiry_height
                .checked_sub(minimum_margin)
                .ok_or(Error::Invalid)?,
        );
    let mut scopes = Vec::new();
    for (consumed, wallet) in claim.consumed.iter().zip(wallets) {
        let plan = &consumed.request.plan;
        let selection = &plan.retained.selection.scope;
        let scope = BornPostReturnWalletScopeV1 {
            checkpoint_binding_digest: binding.clone(),
            final_transaction_digest: descriptor.bytes_sha256.clone(),
            final_transaction_id: descriptor.transaction_id.clone(),
            final_effects_digest: checkpoint.summary().effects_commitment.clone(),
            transaction_expiry_height: descriptor.expiry_height,
            all_inputs: all_inputs.clone(),
            own_inputs: by_account
                .remove(&plan.enrollment().identity.account_id)
                .ok_or(Error::Authentication)?,
            import_scope: ManualRosterInventoryScopeV2 {
                version: 2,
                inventory: selection.selection.inventory.clone(),
                provenance: selection.provenance.clone(),
            },
            provider_read_profile: wallet.reader.provider_read_profile(),
            wallet_origin_digest: wallet
                .provenance
                .wallet_origin_digest(&host.secrets.profile())?,
            anchor_height: common.anchor_height,
            anchor_hash: decode(&common.anchor_hash_protocol)?,
            anchor_root: decode(&common.anchor_root)?,
            original_ancestry: ancestry.iter().map(|(h, b)| (*h, *b)).collect(),
            maximum_tip_height: max_tip,
            minimum_confirmations: common.read_profile.minimum_confirmations,
            minimum_expiry_margin_blocks: minimum_margin,
            maximum_scan_runtime_ms: 30_000,
            native_observation_expires_at_ms: expires.min(plan.enrollment().scope.expires_at_ms),
        };
        scope.validate().map_err(|_| Error::Invalid)?;
        scopes.push(scope);
    }
    original.check_current()?;
    Ok(scopes)
}

// Pointer identity is restriction-only. Production instantiates this private
// predicate exclusively with the actual opaque verified submission type. Tests
// can prove same-value substitution refusal using inert metadata, never owners.
fn require_same_original_borrow<T>(original: &T, requested: &T) -> Result<()> {
    if std::ptr::eq(original, requested) {
        Ok(())
    } else {
        Err(Error::Authentication)
    }
}

#[cfg(test)]
mod held_original_identity_tests {
    use super::require_same_original_borrow;
    use wholepact_chain::SubmissionDescriptor;
    fn inert_economic_metadata() -> (u64, SubmissionDescriptor) {
        (
            4_465_052,
            SubmissionDescriptor {
                operation_id: "same-test-operation".into(),
                obligation_id: "same-test-obligation".into(),
                proposal_id: "same-test-proposal".into(),
                transaction_id: "11".repeat(32),
                bytes_sha256: "22".repeat(32),
                expiry_height: 4_465_083,
                network: "testnet".into(),
                consensus_branch_id: 0x77190ad9,
            },
        )
    }
    #[test]
    fn held_original_identity_rejects_distinct_same_tip_same_economic_value() {
        let original = inert_economic_metadata();
        let distinct = original.clone();
        assert_eq!(original, distinct);
        assert!(require_same_original_borrow(&original, &distinct).is_err());
        assert!(require_same_original_borrow(&distinct, &original).is_err());
    }
    #[test]
    fn held_original_identity_accepts_only_the_same_actual_borrow() {
        let original = inert_economic_metadata();
        let borrowed = &original;
        assert!(require_same_original_borrow(&original, borrowed).is_ok());
        assert!(require_same_original_borrow(borrowed, &original).is_ok());
        // This is predicate coverage only, not a native/verified owner fixture.
    }
}
