//! Candidate-free discovery from the actual signer-local maintained wallet.
//! Only private metadata is projected. No FVK, note plaintext, witness, native
//! approval, key-use ticket or fresh spendability claim leaves this adapter.
use super::*;
use crate::account::birth::enrollment::roster_v2::durable_entry_v1::FreshDurableBornEntryV1;
use crate::ipc::durable_input_projection_v1::AuthenticatedInputProjectionPeerV1;
use wholepact_core::durable_input_projection_v1::{
    DurableInputProjectionV1, DurableProjectedInputV1, DurableProjectionContextV1,
};
use wholepact_signer_origin::durable_input_projection_v1::DurableInputProjectionRequestV1;

fn now_seconds() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::Locked)?
        .as_secs())
}

/// Mandatory restriction-only conjunction of the independently approved wallet
/// setup, original born source, exact projection intent and genuine nominal
/// peer. No host callback, bool, ordinary pairing or data-only scope can replace
/// any member. Source helpers must not reacquire journal authority fences.
struct ProjectionWalletAccessV1<'a> {
    native: &'a NativeWalletAccess,
    source: &'a FreshDurableBornEntryV1,
    peer: &'a AuthenticatedInputProjectionPeerV1,
    request: &'a DurableInputProjectionRequestV1,
    account_id: &'a str,
    fvk: &'a FullViewingKey,
    policy: &'a WalletKeyUsePolicy,
}
impl ProjectionWalletAccessV1<'_> {
    fn check(&self) -> Result<()> {
        self.native.check()?;
        self.native
            .durable_source
            .as_ref()
            .ok_or(Error::Unavailable)?
            .require_source(self.source)?;
        self.peer.check_current()?;
        self.peer.require_request(self.request)?;
        self.request
            .require_valid_at(now_seconds()?)
            .map_err(|_| Error::Locked)?;
        self.source
            .require_input_projection_intent_v1(&self.request.intent)?;
        let intent = &self.request.intent;
        if self.native.origin != self.source.native_binding()
            || self.peer.native_origin() != &self.native.origin
            || self.account_id != intent.account_id
            || self.source.account().account_id()? != self.account_id
            || self.source.account().fvk()?.to_bytes() != self.fvk.to_bytes()
            || wholepact_protocol::durable_proposal_v1::canonical_durable_account_id(self.fvk)
                != self.account_id
            || self.native.source.source_id != intent.provider.source_id
            || self.native.source.endpoint != intent.provider.endpoint
            || self.native.source.trust_profile != intent.provider.trust_profile
            || self.policy.source_id != intent.provider.source_id
            || self.policy.endpoint != intent.provider.endpoint
            || self.policy.confidence != WalletKeyUseConfidence::TrustedSingleProviderSnapshot
            || self.policy.minimum_confirmations < intent.minimum_confirmations
        {
            return Err(Error::ReviewMismatch);
        }
        self.native.check()
    }
}
impl LocalWalletAccess for ProjectionWalletAccessV1<'_> {
    fn permits(
        &self,
        account: AccountUuid,
        provider: &BackendIdentity,
        purpose: WalletAccessPurpose,
    ) -> bool {
        self.native.permits(account, provider, purpose) && self.check().is_ok()
    }
}

/// Exact historical capture provenance, not approval to disclose and not a
/// current observation after the capture ends. Only the maintained method below
/// constructs this non-serializable type. The issuer must independently obtain
/// a genuine native disclosure decision and commit its immutable outbox before
/// exposing even the metadata returned by projection().
pub(in crate::native_ui) struct CapturedDurableInputProjectionV1 {
    source: Arc<FreshDurableBornEntryV1>,
    peer: AuthenticatedInputProjectionPeerV1,
    origin: NativeAuthorityBinding,
    wallet_revocation: NativeWalletRevocation,
    wallet_approved: Instant,
    request_digest: String,
    account_id: String,
    fvk_digest: String,
    projection: DurableInputProjectionV1,
}
impl CapturedDurableInputProjectionV1 {
    fn check_wallet_permission(&self) -> Result<()> {
        // The same approval clock and revocation instance, never capture-time
        // renewal. Metadata remains historical even while this permission lives.
        if !self.wallet_revocation.active.load(Ordering::Acquire)
            || self.wallet_approved.elapsed() >= ACCESS_LIFETIME
        {
            return Err(Error::Locked);
        }
        Ok(())
    }
    pub(in crate::native_ui) fn projection(&self) -> &DurableInputProjectionV1 {
        &self.projection
    }
    pub(in crate::native_ui) fn require_origin(
        &self,
        source: &Arc<FreshDurableBornEntryV1>,
        peer: &AuthenticatedInputProjectionPeerV1,
        request: &DurableInputProjectionRequestV1,
    ) -> Result<()> {
        self.check_wallet_permission()?;
        source.check_original_source_current()?;
        self.peer.require_same_grant(peer)?;
        peer.require_request(request)?;
        request
            .require_valid_at(now_seconds()?)
            .map_err(|_| Error::Locked)?;
        source.require_input_projection_intent_v1(&request.intent)?;
        if !Arc::ptr_eq(&self.source, source)
            || self.origin != source.native_binding()
            || peer.native_origin() != &self.origin
            || request.digest().map_err(|_| Error::ReviewMismatch)? != self.request_digest
            || self.projection.intent != request.intent
            || request.intent.account_id != self.account_id
            || source.account().account_id()? != self.account_id
            || hex::encode(Sha256::digest(source.account().fvk()?.to_bytes())) != self.fvk_digest
        {
            return Err(Error::ReviewMismatch);
        }
        self.projection
            .validate()
            .map_err(|_| Error::Verification)?;
        self.origin.check_current()?;
        peer.check_current()?;
        self.check_wallet_permission()
    }
}

impl NativeWalletWorkspace {
    /// Borrowing preserves this same workspace and already committed bounded
    /// scan batches on every Err or cancelled future. A runtime worker must
    /// return (workspace, result) even when result is Err; it must never silently
    /// drop/recreate the cache to retry. Explicit owner loss still revokes it.
    pub(in crate::native_ui) async fn synchronize_input_projection_v1(
        &mut self,
        request: &DurableInputProjectionRequestV1,
        source: Arc<FreshDurableBornEntryV1>,
        peer: &AuthenticatedInputProjectionPeerV1,
    ) -> Result<CapturedDurableInputProjectionV1> {
        self.invalidate_selection();
        let access = ProjectionWalletAccessV1 {
            native: &self.access,
            source: &source,
            peer,
            request,
            account_id: &self.account_id,
            fvk: &self.fvk,
            policy: &self.policy,
        };
        access.check()?;
        // Actual native-created cache identity, current account and provider
        // are checked BEFORE any source contact. The complete birthday came
        // only from the separate actual native ephemeral-wallet setup.
        self.controller
            .verify_account_fvk(&self.fvk)
            .map_err(|_| Error::Verification)?;
        access.check()?;
        let deadline = peer
            .deadline()
            .min(self.access.origin.bounded_deadline()?)
            .min(
                self.access
                    .approved
                    .checked_add(ACCESS_LIFETIME)
                    .ok_or(Error::Locked)?,
            )
            .min(Instant::now() + Duration::from_secs(120));
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(Error::Locked)?;
        if remaining.is_zero() {
            return Err(Error::Locked);
        }
        self.controller
            .synchronize(
                &access,
                SyncLimits {
                    maximum_blocks: self.maximum_blocks.min(request.intent.maximum_scan_blocks),
                    anchor_height: Some(request.intent.anchor_height),
                    deadline: remaining,
                },
            )
            .await
            .map_err(|_| Error::Verification)?;
        access.check()?;
        let debit = request
            .intent
            .maximum_selection_debit()
            .map_err(|_| Error::InvalidData)?;
        let selected = self
            .controller
            .select_contribution(
                &access,
                &self.fvk,
                &self.account_id,
                debit.as_zatoshis(),
                &[],
            )
            .map_err(|_| Error::Verification)?;
        selected.check_current().map_err(|_| Error::Verification)?;
        access.check()?;
        let contribution = selected.selection();
        let context = contribution.context();
        if contribution.account_id() != self.account_id
            || contribution.fvk().to_bytes() != self.fvk.to_bytes()
            || contribution.requested_debit_zatoshis() != debit.as_zatoshis()
            || context.anchor_height != request.intent.anchor_height
            || contribution.change_address()
                != self.fvk.address_at(0u32, orchard::keys::Scope::Internal)
        {
            return Err(Error::Verification);
        }
        let mut inputs = contribution
            .notes()
            .iter()
            .map(|note| {
                Ok(DurableProjectedInputV1 {
                    input_id: note.input_id.clone(),
                    value: wholepact_core::Amount::from_zatoshis(note.note.value().inner())
                        .map_err(|_| Error::Verification)?,
                    commitment: hex::encode(
                        orchard::note::ExtractedNoteCommitment::from(note.note.commitment())
                            .to_bytes(),
                    ),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        inputs.sort_by(|a, b| a.input_id.cmp(&b.input_id));
        let projection = DurableInputProjectionV1 {
            version: 1,
            intent: request.intent.clone(),
            inputs,
            selected_total: wholepact_core::Amount::from_zatoshis(contribution.selected_zatoshis())
                .map_err(|_| Error::Verification)?,
            own_return_receiver: wholepact_protocol::review::encode_testnet_receiver(
                &contribution.change_address(),
            ),
            // Context hashes are protocol-order bytes; input IDs independently
            // use the maintained canonical display-order transaction ID format.
            context: DurableProjectionContextV1 {
                tip_height: context.tip_height,
                tip_hash: hex::encode(context.tip_hash_protocol),
                anchor_height: context.anchor_height,
                anchor_hash: hex::encode(context.anchor_hash_protocol),
                anchor_root: hex::encode(context.anchor_root),
            },
            captured_at_unix_seconds: now_seconds()?,
        };
        projection.validate().map_err(|_| Error::Verification)?;
        selected.check_current().map_err(|_| Error::Verification)?;
        access.check()?;
        let captured = CapturedDurableInputProjectionV1 {
            source: source.clone(),
            peer: peer.clone(),
            origin: self.access.origin.clone(),
            wallet_revocation: self.access.revocation.clone(),
            wallet_approved: self.access.approved,
            request_digest: request.digest().map_err(|_| Error::Verification)?,
            account_id: self.account_id.clone(),
            fvk_digest: hex::encode(Sha256::digest(self.fvk.to_bytes())),
            projection,
        };
        captured.require_origin(&source, peer, request)?;
        // selected (including FVK/notes/witnesses) stays local and is dropped;
        // no key_use_ticket or construction material is emitted by this path.
        Ok(captured)
    }
}
