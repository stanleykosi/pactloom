//! Exact per-owner recapture under a genuine fresh non-spending lease.
//! This restrictive adapter does not activate the private Host coordinator.
//! Public restrictions are data, NOT authenticated historical provenance.
//! Only the Engine's private original-intake owner can supply that historical
//! join; neither this DTO nor the deny-only callback can issue signer authority.
use super::{
    hash, AuthenticatedDurableConstructionDisclosureV1, BridgeError,
    DurableConstructionCaptureRequestV1, DurableConstructionRequestV1, DurableConstructionScopeV1,
    HistoricalConstructionMaterialV1, OriginalHistoryClient, Result,
};
use orchard::keys::{FullViewingKey, Scope};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use wholepact_core::{manual_construction::PreconstructionScope, OutputAllocation};
use wholepact_protocol::{
    durable_proposal_v1::canonical_durable_account_id, review::encode_testnet_receiver,
};
use wholepact_wallet::wallet::protected_sync::{
    durable_exact_selection_v1::DurableExactSelectionExpectationV1, BackendIdentity,
};

/// Additional exact data restrictions, never a source/consent capability. The
/// private coordinator must derive ALL fields from its protected original intake
/// and explicitly approved new common anchor, not an incoming projection DTO.
#[derive(Clone)]
pub struct DurableExactCaptureRestrictionsV1 {
    pub expected: DurableExactSelectionExpectationV1,
    /// Retained actual internal index-zero receiver, including when the final
    /// proposal has no return output. It is independently checked against FVK.
    pub original_own_return_receiver: String,
}
impl DurableExactCaptureRestrictionsV1 {
    fn require_matches(
        &self,
        scope: &DurableConstructionScopeV1,
        current: &PreconstructionScope,
        provider: &BackendIdentity,
        actual_fvk: &FullViewingKey,
    ) -> Result<()> {
        let proposal = scope.validate().map_err(|_| BridgeError::Binding)?;
        let expected = &self.expected;
        let original = &expected.original_context;
        let anchor = &expected.construction_anchor;
        if expected.provider != *provider
            || provider.source_id != current.provider.source_id
            || provider.endpoint != current.provider.endpoint
            || provider.trust_profile != current.provider.trust_profile
            || scope.account_id != canonical_durable_account_id(actual_fvk)
            || anchor.height != current.anchor_height
            || anchor.height < original.anchor_height
            || original.anchor_height == 0
            || original.anchor_height > original.tip_height
            || original.tip_height >= proposal.manifest().expiry_height
            || anchor.height >= proposal.manifest().expiry_height
            || (anchor.height == original.anchor_height
                && (anchor.block_hash_protocol != original.anchor_hash_protocol
                    || anchor.root != original.anchor_root))
            || self.original_own_return_receiver
                != encode_testnet_receiver(&actual_fvk.address_at(0u32, Scope::Internal))
            || expected.inputs.is_empty()
            || expected.inputs.len() > 32
            || expected
                .inputs
                .windows(2)
                .any(|w| w[0].input_id >= w[1].input_id)
            || expected.inputs.iter().any(|i| i.commitment.is_none())
        {
            return Err(BridgeError::Binding);
        }
        let own_inputs = proposal
            .manifest()
            .inputs
            .iter()
            .filter(|i| i.account_id == scope.account_id)
            .collect::<Vec<_>>();
        if own_inputs.len() != expected.inputs.len()
            || own_inputs.iter().any(|i| {
                i.participant_id != scope.participant_id
                    || !expected.inputs.iter().any(|e| {
                        e.input_id == i.input_id && e.value_zatoshis == i.amount.as_zatoshis()
                    })
            })
        {
            return Err(BridgeError::Binding);
        }
        let mut total = 0u64;
        for input in &expected.inputs {
            input.outpoint().map_err(|_| BridgeError::Binding)?;
            total = total
                .checked_add(input.value_zatoshis)
                .ok_or(BridgeError::Binding)?;
        }
        wholepact_core::Amount::from_zatoshis(total).map_err(|_| BridgeError::Binding)?;
        let debit = proposal
            .accounting()
            .participant_net_debits
            .get(&scope.participant_id)
            .ok_or(BridgeError::Binding)?
            .as_zatoshis();
        let change = total.checked_sub(debit).ok_or(BridgeError::Binding)?;
        let returns = proposal
            .manifest()
            .outputs
            .iter()
            .filter(|o| {
                matches!(&o.allocation, OutputAllocation::Return { account_id, .. }
                if account_id == &scope.account_id)
            })
            .collect::<Vec<_>>();
        if (change == 0 && !returns.is_empty())
            || (change > 0
                && (returns.len() != 1
                    || returns[0].amount.as_zatoshis() != change
                    || returns[0].address != self.original_own_return_receiver))
        {
            return Err(BridgeError::Binding);
        }
        Ok(())
    }
}

fn require_use(
    scope: &DurableConstructionScopeV1,
    current_retained_source: &(dyn Fn() -> bool + Sync),
) -> Result<()> {
    if !current_retained_source() {
        return Err(BridgeError::Permission);
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| BridgeError::Permission)?
        .as_secs();
    scope
        .check_valid_at(now)
        .map_err(|_| BridgeError::Permission)?;
    if !current_retained_source() {
        return Err(BridgeError::Permission);
    }
    Ok(())
}

impl OriginalHistoryClient {
    /// Capture only the exact retained IDs/values/commitments at the separately
    /// approved new pre-proof anchor. No generic selector or fallback exists.
    ///
    /// `current_retained_source` is only an additional denial gate. The exclusive
    /// Engine coordinator must check its original authenticated receipt, frozen
    /// candidate, both metadata purposes/privacy/deadlines, cancellation and
    /// actual encrypted intake destination on every call. It must not depend on
    /// the consumed old lease or extend any original validity window.
    ///
    /// The actual live lease independently authorizes FVK import/private reads.
    /// Its acknowledged Finish precedes the NEW native material disclosure.
    /// Failure may leave an already-imported wallet or approved immutable signer
    /// outbox. In particular, denial after dispatch cannot retract disclosure.
    /// Preserve the exact operation ID/history and do not automatically retry
    /// with a new operation, refund old exposure or claim secure erasure.
    #[allow(clippy::too_many_arguments)]
    pub async fn capture_exact_and_request_durable_construction_v1(
        &self,
        original: super::super::preconstruction_ipc::SignerPreconstructionLease<'_>,
        destination: wholepact_storage_security::EncryptedConnection,
        source: wholepact_chain::ChainAdapter,
        request: DurableConstructionCaptureRequestV1,
        restrictions: DurableExactCaptureRestrictionsV1,
        current_retained_source: &(dyn Fn() -> bool + Sync),
    ) -> Result<(
        wholepact_wallet::wallet::protected_sync::ProtectedWalletSync,
        AuthenticatedDurableConstructionDisclosureV1,
    )> {
        use wholepact_wallet::wallet::{
            protected_sync::{
                account_birthday_from_tree, BackendIdentity, LocalWalletAccess,
                ProtectedWalletSync, SyncLimits, TreeState, WalletAccessPurpose,
            },
            AccountUuid, DedicatedTestnetWallet,
        };
        crate::review::validate_label(&request.operation_id).map_err(|_| BridgeError::Binding)?;
        hash(&request.enrollment_ref)?;
        hash(&request.accepted_manifest_ref)?;
        let proposal = request.scope.validate().map_err(|_| BridgeError::Binding)?;
        require_use(&request.scope, current_retained_source)?;
        original.check_current()?;
        let old = original.scope();
        old.validate().map_err(|_| BridgeError::Binding)?;
        if original.sponsor_policy().is_some()
            || original.sponsor_budget()?.is_some()
            || request.scope.version != 2
            || request.scope.proposal.artifact_digest.is_some()
            || request.scope.proposal.effects_commitment.is_some()
            || request.scope.proposal != old.proposal
            || request.scope.account_id != old.account_id
            || request.scope.participant_id != old.participant_id
            || request.scope.privacy_domain != old.privacy_domain
            || request.scope.constructor.principal_id != old.principal_id
            || request.scope.prover.principal_id != old.principal_id
            || request.scope.protected_destination != old.operator_destination
            || request.scope.minimum_confirmations != old.minimum_confirmations
            || request.scope.maximum_scan_blocks != old.maximum_blocks
            || source.identity().source_id != old.provider.source_id
            || source.identity().endpoint != old.provider.endpoint
            || source.identity().trust_profile != old.provider.trust_profile
            || !matches!(
                proposal.manifest().agreement.fee_policy,
                wholepact_core::FeePolicy::ProRata
            )
            || proposal
                .manifest()
                .participants
                .iter()
                .any(|p| !p.charges.is_empty())
            || !proposal.manifest().agreement.extensions.is_empty()
            || proposal
                .manifest()
                .inputs
                .iter()
                .any(|i| i.ownership_evidence_ref.is_some())
            || proposal
                .manifest()
                .outputs
                .iter()
                .any(|o| match &o.allocation {
                    wholepact_core::OutputAllocation::Charge { .. } => true,
                    wholepact_core::OutputAllocation::Return {
                        ownership_evidence_ref,
                        ..
                    } => ownership_evidence_ref.is_some(),
                    wholepact_core::OutputAllocation::Recipient { .. } => false,
                })
        {
            return Err(BridgeError::Binding);
        }
        restrictions.require_matches(&request.scope, old, source.identity(), original.fvk())?;
        require_use(&request.scope, current_retained_source)?;
        let actual_recipient = self.durable_construction_recipient_v1(&old.principal_id)?;
        if request.scope.constructor != actual_recipient || request.scope.prover != actual_recipient
        {
            return Err(BridgeError::Binding);
        }
        // Join the approved path to the actual authenticated SQLite main handle,
        // not to a caller string or a reconstructed account lookup.
        let identity = destination
            .database_identity()
            .map_err(|_| BridgeError::Binding)?;
        identity
            .check_current(destination.connection())
            .map_err(|_| BridgeError::Binding)?;
        if destination.connection().path() != Some(old.wallet_destination.as_str())
            || std::fs::canonicalize(&old.wallet_destination).map_err(|_| BridgeError::Binding)?
                != std::path::Path::new(&old.wallet_destination)
            || destination
                .connection()
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
                    [],
                    |r| r.get::<_, i64>(0),
                )
                .map_err(|_| BridgeError::Binding)?
                != 0
        {
            return Err(BridgeError::Binding);
        }
        identity
            .check_current(destination.connection())
            .map_err(|_| BridgeError::Binding)?;
        let birthday = &old.birthday;
        let birthday = account_birthday_from_tree(TreeState {
            network: "test".into(),
            height: u64::from(birthday.prior_height),
            hash: birthday.prior_block_hash.clone(),
            sapling_tree: birthday.sapling_tree.clone(),
            orchard_tree: birthday.orchard_tree.clone(),
            ironwood_tree: birthday.ironwood_tree.clone(),
            ..Default::default()
        })
        .map_err(|_| BridgeError::Binding)?;
        require_use(&request.scope, current_retained_source)?;
        original.check_current()?;
        let mut wallet = DedicatedTestnetWallet::from_encrypted_connection(destination)
            .map_err(|_| BridgeError::Binding)?;
        // Schema initialization/migrations can take time. Recheck the real
        // disclosure immediately before the first viewing-key write, not merely
        // before opening the maintained wallet. Failure after import is uncertain
        // persistence, never erasure or permission to reuse the old grant.
        require_use(&request.scope, current_retained_source)?;
        original.check_current()?;
        identity
            .check_retained_owner_path()
            .map_err(|_| BridgeError::Binding)?;
        require_use(&request.scope, current_retained_source)?;
        let account = wallet
            .import_dedicated_fvk(original.fvk(), birthday)
            .map_err(|_| BridgeError::Binding)?;
        identity
            .check_retained_owner_path()
            .map_err(|_| BridgeError::Binding)?;
        require_use(&request.scope, current_retained_source)?;
        original.check_current()?;
        let mut sync = ProtectedWalletSync::from_initialized_wallet(
            wallet,
            source,
            std::num::NonZeroU32::new(old.minimum_confirmations).ok_or(BridgeError::Binding)?,
        )
        .map_err(|_| BridgeError::Binding)?;
        struct InitialCaptureAccess<'a, 'b> {
            original: &'a super::super::preconstruction_ipc::SignerPreconstructionLease<'b>,
            account: AccountUuid,
            identity: &'a wholepact_storage_security::DatabaseFileIdentity,
            scope: &'a DurableConstructionScopeV1,
            current_retained_source: &'a (dyn Fn() -> bool + Sync),
        }
        impl LocalWalletAccess for InitialCaptureAccess<'_, '_> {
            fn permits(
                &self,
                account: AccountUuid,
                provider: &BackendIdentity,
                _: WalletAccessPurpose,
            ) -> bool {
                let expected = &self.original.scope().provider;
                require_use(self.scope, self.current_retained_source).is_ok()
                    && self.account == account
                    && provider.source_id == expected.source_id
                    && provider.endpoint == expected.endpoint
                    && provider.trust_profile == expected.trust_profile
                    && self.identity.check_retained_owner_path().is_ok()
                    && self.original.check_current().is_ok()
                    && require_use(self.scope, self.current_retained_source).is_ok()
            }
        }
        let access = InitialCaptureAccess {
            original: &original,
            account,
            identity: &identity,
            scope: &request.scope,
            current_retained_source,
        };
        require_use(&request.scope, current_retained_source)?;
        sync.verify_account_fvk(original.fvk())
            .map_err(|_| BridgeError::Binding)?;
        sync.synchronize(
            &access,
            SyncLimits {
                maximum_blocks: old.maximum_blocks,
                anchor_height: Some(old.anchor_height),
                deadline: Duration::from_secs(120),
            },
        )
        .await
        .map_err(|_| BridgeError::Permission)?;
        require_use(&request.scope, current_retained_source)?;
        original.check_current()?;
        let debit = proposal
            .accounting()
            .participant_net_debits
            .get(&old.participant_id)
            .ok_or(BridgeError::Binding)?
            .as_zatoshis();
        if debit > old.maximum_net_debit_zatoshis {
            return Err(BridgeError::Binding);
        }
        let selected = sync
            .select_exact_durable_contribution_v1(
                &access,
                original.fvk(),
                &request.scope,
                &restrictions.expected,
            )
            .map_err(|_| BridgeError::Permission)?;
        require_use(&request.scope, current_retained_source)?;
        let material = HistoricalConstructionMaterialV1::capture(&selected, &sync)
            .map_err(|_| BridgeError::Binding)?;
        material
            .validate_for(&request.scope)
            .map_err(|_| BridgeError::Binding)?;
        require_use(&request.scope, current_retained_source)?;
        original.check_current()?;
        identity
            .check_retained_owner_path()
            .map_err(|_| BridgeError::Binding)?;
        // Finish the original owner's lease before another human review. Its
        // retained journal read fence must not overlap the new native decision.
        // Captured bytes remain data; only that separate exact decision can
        // approve their durable retention. No original grant is reconstructed.
        drop(selected);
        drop(access);
        original.finish()?;
        // This gate owns only the retained Engine source, never the released lease.
        require_use(&request.scope, current_retained_source)?;
        let disclosure = self.request_durable_construction_v1(&DurableConstructionRequestV1 {
            operation_id: request.operation_id,
            enrollment_ref: request.enrollment_ref,
            accepted_manifest_ref: request.accepted_manifest_ref,
            scope: request.scope,
            material,
        })?;
        // A denial here cannot retract a signer outbox committed during the
        // bounded native exchange. Preserve the exact operation locator.
        require_use(
            &disclosure.outbox().request().scope,
            current_retained_source,
        )?;
        identity
            .check_retained_owner_path()
            .map_err(|_| BridgeError::Binding)?;
        Ok((sync, disclosure))
    }
}

#[cfg(all(test, feature = "synthetic-qualification"))]
#[path = "exact_capture_v1_tests.rs"]
mod tests;
