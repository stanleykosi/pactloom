//! One ordinary selection on the same completed original V3 source. It permits
//! no credentials, private configuration reads, financial Entry or Read itself.
use super::*;
use crate::{
    SignerFinancialSetupSelectionV1, SignerV3AuditedV1, SignerV3OwnerSetupSelectionV1,
    SignerV3ReceivedV1,
};
fn matches_completed(
    s: &SignerFinancialSetupSelectionV1,
    a: &SignerV3AuditedV1,
    r: &SignerV3ReceivedV1,
    account: &str,
) -> bool {
    s.source_identity_digest == a.source_identity_digest
        && s.audit_presentation_digest == a.audit_presentation_digest
        && s.recipient_intent_digest == a.recipient_intent_digest
        && s.recipient_intent_digest == r.recipient_intent_digest
        && s.fixed_identity_digest == r.fixed_identity_digest
        && SignerV3OwnerSetupSelectionV1::parse_json(&s.writer_setup_json)
            .is_ok_and(|v| v.account_id == account)
}
impl CoordinatorFinancialEndpointV1 {
    pub fn try_select_financial_setup(
        &mut self,
        role: Target,
        writer_setup_json: String,
        wallet_setup_json: String,
    ) -> Result<FinancialSendProgressV1> {
        let i = role.index();
        let s = &mut self.v3_entries[i];
        if s.financial_setup.is_some()
            || self.slots[i].is_some()
            || self.core.phase.phase(i) != V3_HELD
        {
            return Err(rejected("financial setup selection repeated/reordered"));
        }
        let a = s
            .audit
            .result
            .as_ref()
            .ok_or_else(|| rejected("financial selection before actual Audit"))?;
        if !s.audit.reported {
            return Err(rejected("financial selection before actual Audit report"));
        }
        let (_, r) = s.delivery.admission_wire()?;
        let entry = s
            .entry
            .as_ref()
            .ok_or_else(|| rejected("financial selection missing original Entry"))?;
        entry.check_custody()?;
        let selection = SignerFinancialSetupSelectionV1 {
            source_identity_digest: a.source_identity_digest.clone(),
            audit_presentation_digest: a.audit_presentation_digest.clone(),
            recipient_intent_digest: a.recipient_intent_digest.clone(),
            fixed_identity_digest: r.fixed_identity_digest.clone(),
            writer_setup_json,
            wallet_setup_json,
            selection_nonce: state::nonce()?,
        };
        selection.validate()?;
        if !matches_completed(&selection, a, r, &entry.wire.presentation.facts.account_id) {
            return Err(rejected(
                "financial selection changed actual completed source",
            ));
        }
        let deadline = entry.original_source;
        s.financial_setup = Some(selection.clone());
        if self.core.phase.source_send_restricted(i, V3_HELD)? {
            return Ok(FinancialSendProgressV1::Restricted);
        }
        self.send_positive(
            &Packet::FinancialSetupSelection { role, selection },
            deadline,
        )
    }
}
impl SignerFinancialWorkflowOriginV1 {
    pub(in crate::financial_workflow_origin) fn receive_financial_setup(
        &mut self,
        p: Packet,
    ) -> Result<SignerFinancialWorkflowRequestV1> {
        let Packet::FinancialSetupSelection { role, selection } = p else {
            return Err(rejected("wrong financial selection event"));
        };
        selection.validate()?;
        self.core.check_action_restrictions()?;
        let s = &mut self.v3_entry;
        if role != self.target
            || s.financial_setup.is_some()
            || self.start.is_some()
            || self.core.phase.phase(role.index()) != V3_HELD
        {
            return Err(rejected("financial selection repeated/reordered"));
        }
        let a = s
            .audit
            .result
            .as_ref()
            .ok_or_else(|| rejected("financial selection before actual Audit"))?;
        let (_, r) = s.delivery.admission_wire()?;
        let entry = s
            .entry
            .as_ref()
            .ok_or_else(|| rejected("financial selection missing original Entry"))?;
        entry.check_custody()?;
        if !s.audit.reported
            || !matches_completed(&selection, a, r, &entry.wire.presentation.facts.account_id)
        {
            return Err(rejected(
                "financial selection actual completed source mismatch",
            ));
        }
        s.financial_setup = Some(selection.clone());
        Ok(SignerFinancialWorkflowRequestV1::FinancialSetupSelection { selection })
    }
}
impl HostFinancialWorkflowRelayV1 {
    pub(in crate::financial_workflow_origin) fn down_financial_setup(
        &mut self,
        p: &Packet,
    ) -> Result<()> {
        if self.restricted {
            return Err(rejected("financial selection after R"));
        }
        let Packet::FinancialSetupSelection { role, selection } = p else {
            return Err(rejected("wrong financial selection relay"));
        };
        selection.validate()?;
        let s = &mut self.v3_entries[role.index()];
        if s.financial_setup.is_some()
            || self.slots[role.index()].is_some()
            || s.phase != V3_HELD
            || !s.audit.reported
        {
            return Err(rejected("financial selection relay repeated/reordered"));
        }
        let a = s
            .audit
            .result
            .as_ref()
            .ok_or_else(|| rejected("financial selection relay before actual Audit"))?;
        let (_, r) = s.delivery.admission_wire()?;
        let entry = s
            .offer
            .as_ref()
            .ok_or_else(|| rejected("financial selection relay original Entry missing"))?;
        if !matches_completed(selection, a, r, &entry.presentation.facts.account_id) {
            return Err(rejected(
                "financial selection relay actual completed source mismatch",
            ));
        }
        self.clocks.restrict_received(
            PROFILE,
            entry.presentation.source_ceiling_ms,
            self.clocks.supervision(),
            Instant::now(),
        )?;
        let wall = state::wall_ms()?;
        if wall < s.last_wall || wall >= entry.presentation.facts.source_expires_at_ms {
            return Err(rejected("financial selection original source expired"));
        }
        s.last_wall = wall;
        s.financial_setup = Some(selection.clone());
        Ok(())
    }
}
