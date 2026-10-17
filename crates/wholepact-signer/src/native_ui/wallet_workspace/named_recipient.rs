//! Own-only expectations from the actual retained wallet selection. The result is
//! an inspection input, never enrollment, native consent or spending authority.
use super::*;
use crate::consent_journal::{SignerConsentJournal, SignerConsentSession};
use wholepact_protocol::own_effects::OwnEffectsPolicy;

/// Borrowed genuine runtime owners. Every binding is rechecked below; this is
/// neither serializable nor an approval token.
pub(in crate::native_ui) struct NamedRecipientOwnerContext<'a> {
    pub journal: &'a Arc<SignerConsentJournal>,
    pub session: &'a Arc<SignerConsentSession>,
    pub enrollment_ref: &'a str,
    pub manifest_ref: &'a str,
    pub vault: &'a Arc<AccountVault>,
    pub authority: &'a NativeAuthority,
    #[cfg(feature = "pending-birth-owner-signing")]
    pub born: Option<(&'a crate::account::birth::enrollment::roster_v2::inventory::common_context_reentry_v1::named_recipient::ConsumedBornNamedSourceV1, &'a super::super::PendingAccountNativeAuthority)>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnInputAction {
    input_id: String,
    account_id: String,
    action_index: usize,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnContextEnvelope {
    schema_version: u32,
    manifest_digest: String,
    construction_context: ClaimedConstructionContext,
    input_actions: Vec<OwnInputAction>,
    output_actions: Vec<ClaimedOutputAction>,
}
impl OwnContextEnvelope {
    fn decode(bytes: &[u8], proposal: &Proposal) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_CONTEXT {
            return Err(Error::InvalidData);
        }
        let value: Self =
            wholepact_core::parse_typed_json(bytes).map_err(|_| Error::InvalidData)?;
        if value.schema_version != 1
            || value.manifest_digest != proposal.manifest_digest()
            || value.input_actions.len() != proposal.manifest().inputs.len()
            || value.output_actions.len() != proposal.manifest().outputs.len()
            || value.input_actions.len() > 64
            || value.output_actions.len() > 64
            || value.input_actions.iter().any(|m| m.action_index >= 128)
            || value.output_actions.iter().any(|m| m.action_index >= 128)
        {
            return Err(Error::Verification);
        }
        Ok(value)
    }
    fn context(&self) -> Result<ConstructionContext> {
        Ok(ConstructionContext {
            anchor: decode_hex(&self.construction_context.anchor)?,
            anchor_height: self.construction_context.anchor_height,
            anchor_block_hash: decode_hex(&self.construction_context.anchor_block_hash)?,
            target_height: self.construction_context.target_height,
        })
    }
    fn inputs(&self) -> Vec<InputActionMapping> {
        self.input_actions
            .iter()
            .map(|m| InputActionMapping {
                input_id: m.input_id.clone(),
                account_id: m.account_id.clone(),
                action_index: m.action_index,
            })
            .collect()
    }
    fn outputs(&self) -> Vec<OutputActionMapping> {
        self.output_actions
            .iter()
            .map(|m| OutputActionMapping {
                output_id: m.output_id.clone(),
                action_index: m.action_index,
            })
            .collect()
    }
}

impl NativeWalletWorkspace {
    /// Uses the already separately native-approved bounded wallet access. No peer
    /// viewing data is accepted. A different newly selected input set is refused
    /// by the retained manifest reconciliation, never silently substituted.
    pub(in crate::native_ui) async fn synchronize_named_recipient_policy(
        &mut self,
        owner: &NamedRecipientOwnerContext<'_>,
        untrusted_context: &[u8],
    ) -> Result<OwnEffectsPolicy> {
        self.invalidate_selection();
        self.access.check()?;
        owner.authority.check_current()?;
        let proposal = {
            let records = owner
                .journal
                .acquire_preconstruction_records(
                    owner.enrollment_ref,
                    owner.manifest_ref,
                    owner.session,
                )
                .map_err(|_| Error::ReviewMismatch)?;
            records
                .require_native_origin(&owner.authority.binding())
                .map_err(|_| Error::ReviewMismatch)?;
            let proposal = Proposal::validate(records.manifest().proposal_input().clone())
                .map_err(|_| Error::Verification)?;
            if owner.vault.account_id()? != self.account_id
                || records.enrollment().account_id() != self.account_id
                || records.enrollment().account_fvk_digest()
                    != hex::encode(Sha256::digest(self.fvk.to_bytes()))
                || self.fvk.to_bytes() != owner.vault.account().fvk()?.to_bytes()
                || proposal.manifest_digest() != records.manifest().manifest_digest()
                || proposal.proposal_digest() != records.manifest().proposal_digest()
            {
                return Err(Error::ReviewMismatch);
            }
            proposal
        }; // Do not retain a journal fence across provider work.
        let envelope = OwnContextEnvelope::decode(untrusted_context, &proposal)?;
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
        owner.authority.check_current()?;
        self.access.check()?;
        let selected = self
            .controller
            .select_contribution(&self.access, &self.fvk, &self.account_id, debit, &[])
            .map_err(|_| Error::Verification)?;
        self.ticket = Some(selected.key_use_ticket());
        let result = self.named_recipient_policy_from_retained_selection(owner, untrusted_context);
        if result.is_err() {
            self.invalidate_selection();
        }
        result
    }
    pub(in crate::native_ui) fn named_recipient_policy_from_retained_selection(
        &self,
        owner: &NamedRecipientOwnerContext<'_>,
        untrusted_context: &[u8],
    ) -> Result<OwnEffectsPolicy> {
        let NamedRecipientOwnerContext {
            journal,
            session,
            enrollment_ref,
            manifest_ref,
            vault,
            authority,
            ..
        } = owner;
        self.access.check()?;
        authority.check_current()?;
        let records = journal
            .acquire_preconstruction_records(enrollment_ref, manifest_ref, session)
            .map_err(|_| Error::ReviewMismatch)?;
        records
            .require_native_origin(&authority.binding())
            .map_err(|_| Error::ReviewMismatch)?;
        let account_id = vault.account_id()?;
        let fvk = vault.account().fvk()?;
        if vault.account().recovery_required()
            || self.account_id != account_id
            || self.fvk.to_bytes() != fvk.to_bytes()
            || records.enrollment().account_id() != account_id
            || records.enrollment().account_fvk_digest()
                != hex::encode(Sha256::digest(fvk.to_bytes()))
        {
            return Err(Error::ReviewMismatch);
        }
        let proposal = Proposal::validate(records.manifest().proposal_input().clone())
            .map_err(|_| Error::Verification)?;
        if proposal.manifest_digest() != records.manifest().manifest_digest()
            || proposal.proposal_digest() != records.manifest().proposal_digest()
            || proposal.manifest().agreement.agreement_id != records.enrollment().agreement_id()
        {
            return Err(Error::ReviewMismatch);
        }
        let envelope = OwnContextEnvelope::decode(untrusted_context, &proposal)?;
        let context = envelope.context()?;
        let input_actions = envelope.inputs();
        let output_actions = envelope.outputs();
        let ticket = self.ticket.as_ref().ok_or(Error::ReviewMismatch)?;
        let selected = LocalSelection::from_key_use_ticket(ticket, &self.policy)?;
        let policy = crate::manifest::named_own_policy::derive_selected_own_policy(
            &AcceptedManifest { proposal },
            &selected,
            vault.account(),
            &context,
            &input_actions,
            &output_actions,
        )?;
        ticket
            .validate_policy(&self.policy)
            .map_err(|_| Error::Verification)?;
        records.check_current().map_err(|_| Error::ReviewMismatch)?;
        authority.check_current()?;
        self.access.check()?;
        Ok(policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn context() -> serde_json::Value {
        serde_json::json!({
            "schema_version":1,"manifest_digest":"00".repeat(32),
            "construction_context":{"anchor":"00".repeat(32),"anchor_height":1,
                "anchor_block_hash":"11".repeat(32),"target_height":3},
            "input_actions":[{"input_id":"input-one","account_id":"account-one","action_index":0}],
            "output_actions":[{"output_id":"output-one","action_index":0}]
        })
    }
    #[test]
    fn own_only_context_refuses_peer_viewing_and_imported_nullifier_fields() {
        let bytes = serde_json::to_vec(&context()).unwrap();
        let parsed: OwnContextEnvelope = wholepact_core::parse_typed_json(&bytes).unwrap();
        assert_eq!(parsed.inputs()[0].input_id, "input-one");
        let mut peer = context();
        peer["participant_views"] = serde_json::json!([]);
        assert!(
            wholepact_core::parse_typed_json::<OwnContextEnvelope>(
                &serde_json::to_vec(&peer).unwrap()
            )
            .is_err()
        );
        let mut imported = context();
        imported["input_actions"][0]["nullifier"] = serde_json::json!("22".repeat(32));
        assert!(
            wholepact_core::parse_typed_json::<OwnContextEnvelope>(
                &serde_json::to_vec(&imported).unwrap()
            )
            .is_err()
        );
    }
}

#[cfg(feature = "pending-birth-owner-signing")]
impl NamedRecipientOwnerContext<'_> {
    pub(in crate::native_ui) fn born_own_policy(&self, context: &[u8]) -> Result<OwnEffectsPolicy> {
        let (actual, owner) = self.born.ok_or(Error::Unavailable)?;
        actual.check(owner)?;
        let proposal = actual
            .construction()
            .reservation
            .request
            .construction
            .plan
            .validate()
            .map_err(|_| Error::Verification)?;
        let envelope = OwnContextEnvelope::decode(context, &proposal)?;
        crate::manifest::named_own_policy::derive_born_consumed_own_policy(
            actual,
            owner,
            &envelope.context()?,
            &envelope.inputs(),
            &envelope.outputs(),
        )
    }
}
