//! Fresh wallet context for an already fixed, fully mathematically reviewed
//! proposal. Nothing here changes its anchor, inputs, expiry, policy or proof.
use super::*;
use crate::account::birth::enrollment::roster_v2::durable_entry_v1::FreshDurableBornEntryV1;
use crate::ipc::AuthenticatedPeer;
use crate::native_ui::durable_proposal_v1::VerifiedDurableEconomicsV1;

/// Restriction-only conjunction. None of these data checks can replace the
/// independently approved native wallet/provider access below. The actual
/// imported source and peer, not a caller-supplied consent flag, are borrowed
/// through every maintained scanner/ticket permission check.
struct CurrentDurableReviewAccessV1<'a> {
    native: &'a NativeWalletAccess,
    source: &'a FreshDurableBornEntryV1,
    peer: &'a AuthenticatedPeer,
    fixed: &'a VerifiedDurableEconomicsV1,
    account_id: &'a str,
}
impl CurrentDurableReviewAccessV1<'_> {
    fn check(&self) -> Result<()> {
        self.native.check()?;
        // This fixed born path requires the actual purpose-specific workspace
        // and its retained database identity, never an ordinary wallet fallback.
        self.native
            .durable_source
            .as_ref()
            .ok_or(Error::Unavailable)?
            .require_source(self.source)?;
        // No journal authority-fence acquisition here. Financial authorization
        // separately reuses its actual held lease at the specialized boundary.
        self.source.check_original_source_current()?;
        self.peer.check_current()?;
        let manifest = self.fixed.proposal().manifest();
        if self.native.origin != self.source.native_binding()
            || self.peer.native_origin != self.native.origin
            || self.source.account().account_id()? != self.account_id
            || self.peer.scope.account_id != self.account_id
            || self.peer.scope.agreement_id != manifest.agreement.agreement_id
            || self.peer.scope.manifest_digest != self.fixed.proposal().manifest_digest()
            || !manifest.participants.iter().any(|participant| {
                participant.account_id == self.account_id
                    && participant.participant_id == self.peer.scope.participant_id
            })
        {
            return Err(Error::ReviewMismatch);
        }
        let time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Error::Locked)?
            .as_secs();
        for participant in &self.fixed.verified().private_review_policy().participants {
            let (_, scope) = self.fixed.original_for_account(&participant.account_id)?;
            scope.check_valid_at(time).map_err(|_| Error::Locked)?;
        }
        self.native.check()
    }
}
impl LocalWalletAccess for CurrentDurableReviewAccessV1<'_> {
    fn permits(
        &self,
        account: AccountUuid,
        provider: &BackendIdentity,
        purpose: WalletAccessPurpose,
    ) -> bool {
        self.native.permits(account, provider, purpose) && self.check().is_ok()
    }
}

impl NativeWalletWorkspace {
    pub(in crate::native_ui) async fn synchronize_durable_review_v1(
        &mut self,
        fixed: &VerifiedDurableEconomicsV1,
        source: &FreshDurableBornEntryV1,
        peer: &AuthenticatedPeer,
    ) -> Result<ReviewInputs> {
        self.invalidate_selection();
        let access = CurrentDurableReviewAccessV1 {
            native: &self.access,
            source,
            peer,
            fixed,
            account_id: &self.account_id,
        };
        access.check()?;
        let proposal = fixed.proposal();
        let immutable = fixed.fixed_context();
        let own_policy = fixed
            .verified()
            .private_review_policy()
            .participants
            .iter()
            .find(|p| p.account_id == self.account_id)
            .ok_or(Error::Verification)?;
        if own_policy.fvk.to_bytes() != self.fvk.to_bytes() {
            return Err(Error::Verification);
        }
        let (original_material, original_scope) = fixed.original_for_account(&self.account_id)?;
        // No material use or remote synchronization against a substituted
        // provider, account, birthday or protected database is permitted.
        self.controller
            .validate_durable_material_source_v1(original_material, original_scope, &self.fvk)
            .map_err(|_| Error::Verification)?;
        self.controller
            .synchronize(
                &access,
                SyncLimits {
                    maximum_blocks: self.maximum_blocks.min(original_scope.maximum_scan_blocks),
                    anchor_height: Some(immutable.anchor_height),
                    deadline: Duration::from_secs(120),
                },
            )
            .await
            .map_err(|_| Error::Verification)?;
        access.check()?;
        let ticket = self
            .controller
            .exact_durable_review_ticket_v1(
                original_material,
                original_scope,
                &access,
                &self.fvk,
                &self.policy,
            )
            .map_err(|_| Error::Verification)?;
        let local = LocalSelection::from_key_use_ticket(&ticket, &self.policy)?;
        let mut context = immutable;
        // Only this contemporaneous review-context field advances. Old native
        // receipts never become current and the proved transaction is untouched.
        context.target_height = local
            .context
            .tip_height
            .checked_add(1)
            .ok_or(Error::Verification)?;
        let inputs = ReviewInputs {
            construction_context: context,
            policy: fixed.verified().private_review_policy().clone(),
            input_actions: fixed.input_actions().to_vec(),
            output_actions: fixed.output_actions().to_vec(),
            own_selection: local,
        };
        crate::manifest::reconcile(
            &AcceptedManifest {
                proposal: proposal.clone(),
            },
            &inputs,
            &self.account_id,
            &self.fvk,
        )?;
        fixed
            .verified()
            .verify_action_mappings(&inputs.input_actions, &inputs.output_actions)
            .map_err(|_| Error::Verification)?;
        access.check()?;
        ticket
            .validate_policy(&self.policy)
            .map_err(|_| Error::Verification)?;
        access.check()?;
        self.ticket = Some(ticket);
        Ok(inputs)
    }
}
