//! Fresh wallet context for an already fixed, fully mathematically reviewed
//! proposal. Nothing here changes its anchor, inputs, expiry, policy or proof.
use super::*;
use crate::native_ui::durable_proposal_v1::VerifiedDurableEconomicsV1;

impl NativeWalletWorkspace {
    pub(in crate::native_ui) async fn synchronize_durable_review_v1(
        &mut self,
        fixed: &VerifiedDurableEconomicsV1,
    ) -> Result<ReviewInputs> {
        self.invalidate_selection();
        self.access.check()?;
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
                &self.access,
                SyncLimits {
                    maximum_blocks: self.maximum_blocks.min(original_scope.maximum_scan_blocks),
                    anchor_height: Some(immutable.anchor_height),
                    deadline: Duration::from_secs(120),
                },
            )
            .await
            .map_err(|_| Error::Verification)?;
        self.access.check()?;
        let ticket = self
            .controller
            .exact_durable_review_ticket_v1(
                original_material,
                original_scope,
                &self.access,
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
        self.access.check()?;
        ticket
            .validate_policy(&self.policy)
            .map_err(|_| Error::Verification)?;
        self.ticket = Some(ticket);
        Ok(inputs)
    }
}
