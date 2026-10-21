//! A fresh owner-history/local-preparation Read, not custody reinterpreted as authority.
use super::delivery::PrepareReadBinding;
use super::*;
use crate::signer_v3_audit_data::*;
use crate::{SignerV3PrepareReadPresentationV1, SignerV3ReceivedV1};
#[derive(Default)]
pub(super) struct AuditSlot {
    pub(super) binding: Option<Arc<AuditBinding>>,
    pub(super) wire: Option<SignerV3AuditPresentationV1>,
    pub(super) result: Option<SignerV3AuditedV1>,
    pub(super) phase: u8,
    pub(super) reported: bool,
}
pub(super) struct AuditBinding {
    completed: AtomicBool,
    pub(super) owner: Arc<PrepareReadBinding>,
    pub(super) p: SignerV3AuditPresentationV1,
    pub(super) deadline: Instant,
    last_wall: AtomicU64,
}
impl AuditBinding {
    fn new(owner: Arc<PrepareReadBinding>, p: SignerV3AuditPresentationV1) -> Result<Arc<Self>> {
        p.validate()?;
        owner.custody_bounds()?;
        let now = Instant::now();
        let deadline = owner
            .pair
            .entry
            .clocks
            .restrict_received(
                PROFILE,
                p.review_ceiling_ms,
                owner.service_deadline.min(owner.material_deadline),
                now,
            )?
            .min(wall_ceiling(
                now,
                state::wall_ms()?,
                p.facts.reviewed_at_ms,
                p.facts.expires_at_ms,
            )?);
        let b = Arc::new(Self {
            completed: AtomicBool::new(false),
            owner,
            p,
            deadline,
            last_wall: AtomicU64::new(state::wall_ms()?),
        });
        b.bounds()?;
        Ok(b)
    }
    pub(super) fn bounds(&self) -> Result<()> {
        self.owner.custody_bounds()?;
        let wall = state::wall_ms()?;
        let old = self.last_wall.fetch_max(wall, Ordering::AcqRel);
        if wall < old
            || wall < self.p.facts.reviewed_at_ms
            || wall >= self.p.facts.expires_at_ms
            || Instant::now() >= self.deadline
        {
            return Err(rejected("original fresh Audit expired"));
        }
        Ok(())
    }
    fn current(&self, phase: u8) -> Result<()> {
        self.bounds()?;
        self.owner.pair.entry.core.check_action_restrictions()?;
        if self
            .owner
            .pair
            .entry
            .core
            .phase
            .phase(self.owner.pair.entry.slot())
            != phase
        {
            return Err(rejected("Audit consumed or reordered"));
        }
        Ok(())
    }
}
pub struct SignerV3AuditTicketV1 {
    binding: Arc<AuditBinding>,
    consumed: bool,
}
impl SignerV3AuditTicketV1 {
    pub fn presentation(&self) -> &SignerV3AuditPresentationV1 {
        &self.binding.p
    }
    pub fn check_current(&self) -> Result<()> {
        self.binding.current(158)
    }
}
impl Drop for SignerV3AuditTicketV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.owner.pair.entry.core.phase.revoke();
        }
    }
}
pub struct SignerV3AuditOutboundV1 {
    binding: Arc<AuditBinding>,
    consumed: bool,
}
impl Drop for SignerV3AuditOutboundV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.owner.pair.entry.core.phase.revoke();
        }
    }
}
pub struct SignerV3AuditFinalV1 {
    binding: Arc<AuditBinding>,
    consumed: bool,
}
impl SignerV3AuditFinalV1 {
    pub fn original_entry_presentation(&self) -> &SignerV3SourceEntryPresentationV1 {
        &self.binding.owner.pair.entry.wire.presentation
    }
    pub fn source_identity_digest(&self) -> &str {
        &self.binding.p.facts.received.source_identity_digest
    }
    pub fn recipient_intent_digest(&self) -> &str {
        &self.binding.p.facts.received.recipient_intent_digest
    }

    pub fn original_channel_expires_at_ms(&self) -> u64 {
        self.binding.owner.pair.p.facts.channel_expires_at_ms
    }

    pub fn presentation(&self) -> &SignerV3AuditPresentationV1 {
        &self.binding.p
    }
    pub fn facts(&self) -> &SignerV3AuditFactsV1 {
        &self.binding.p.facts
    }
    pub fn check_current(&self) -> Result<()> {
        self.binding.current(159)
    }
    pub fn original_read_deadline(&self) -> Instant {
        self.binding.deadline
    }
    pub fn original_source_deadline(&self) -> Instant {
        self.binding.owner.pair.entry.original_source
    }
    pub fn original_channel_deadline(&self) -> Instant {
        self.binding.owner.pair.channel_deadline
    }
    pub fn original_service_deadline(&self) -> Instant {
        self.binding.owner.service_deadline
    }
    pub fn original_material_deadline(&self) -> Instant {
        self.binding.owner.material_deadline
    }
    pub fn finish_audit(mut self) -> Result<SignerV3CompletedLifetimeV1> {
        self.check_current()?;
        self.binding.owner.pair.entry.core.phase.step(
            self.binding.owner.pair.entry.slot(),
            159,
            160,
        )?;
        self.consumed = true;
        Ok(SignerV3CompletedLifetimeV1 {
            binding: Arc::clone(&self.binding),
        })
    }
}
impl Drop for SignerV3AuditFinalV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.owner.pair.entry.core.phase.revoke();
        }
    }
}
fn matches_original(
    p: &SignerV3AuditPresentationV1,
    read: &SignerV3PrepareReadPresentationV1,
    received: &SignerV3ReceivedV1,
    admitted: &crate::SignerV3AdmittedV1,
    admission: &crate::SignerV3AdmitPresentationV1,
) -> bool {
    p.facts.admitted == *admitted
        && p.facts.operation_id == admission.facts.read.operation_id
        && p.actor == read.actor
        && p.facts.received == *received
        && p.facts.owner_selection_digest == read.facts.owner_selection_digest
        && p.facts.owner_certificate_digest == read.facts.owner_certificate_digest
        && p.facts.disclosure_digest == read.facts.disclosure_digest
        && p.source_ceiling_ms == read.source_ceiling_ms
        && p.service_ceiling_ms == read.service_ceiling_ms
        && p.material_ceiling_ms == read.material_ceiling_ms
        && p.facts.source_expires_at_ms == read.facts.source_expires_at_ms
        && p.facts.service_expires_at_ms == read.facts.service_expires_at_ms
        && p.facts.material_expires_at_ms == read.facts.material_expires_at_ms
        && p.facts.reviewed_at_ms >= read.facts.reviewed_at_ms
}
fn matches_result(d: &SignerV3AuditedV1, p: &SignerV3AuditPresentationV1) -> bool {
    d.validate().is_ok()
        && d.audit_presentation_digest == p.presentation_digest
        && d.admit_presentation_digest == p.facts.admitted.admit_presentation_digest
        && d.source_identity_digest == p.facts.received.source_identity_digest
        && d.owner_service_digest == p.facts.received.owner_service_digest
        && d.recipient_intent_digest == p.facts.received.recipient_intent_digest
        && d.local_record_digest == p.facts.admitted.local_record_digest
        && d.admission_request_digest == p.facts.admitted.admission_request_digest
        && d.operation_id == p.facts.operation_id
}

impl SignerFinancialWorkflowOriginV1 {
    pub fn offer_v3_audit(
        &mut self,
        facts: SignerV3AuditFactsV1,
        original_read: Instant,
    ) -> Result<SignerV3AuditPresentationV1> {
        self.core.check_action_restrictions()?;
        facts.validate()?;
        let s = &mut self.v3_entry;
        let (owner, received) = s.delivery.admission_predecessor()?;
        let admitted = s
            .admission
            .result
            .as_ref()
            .ok_or_else(|| rejected("Audit before actual retained local admission"))?;
        let admission = s
            .admission
            .wire
            .as_ref()
            .ok_or_else(|| rejected("Audit missing original admission"))?;
        if !s.admission.reported {
            return Err(rejected("Audit before retained admission report"));
        }
        owner.custody_bounds()?;
        if s.audit.binding.is_some()
            || original_read > owner.service_deadline
            || original_read > owner.material_deadline
            || original_read > Instant::now() + Duration::from_secs(120)
        {
            return Err(rejected("Audit one original window"));
        }
        let mut p = SignerV3AuditPresentationV1 {
            actor: owner.p.actor.clone(),
            facts,
            notice: crate::signer_v3_audit_data::NOTICE.into(),
            challenge: state::nonce()?,
            source_ceiling_ms: owner.p.source_ceiling_ms,
            service_ceiling_ms: owner.p.service_ceiling_ms,
            material_ceiling_ms: owner.p.material_ceiling_ms,
            review_ceiling_ms: self.clocks.restrictive_offset(
                original_read,
                owner.service_deadline.min(owner.material_deadline),
            )?,
            presentation_digest: String::new(),
        };
        p.presentation_digest = p.calculate_presentation_digest()?;
        if !matches_original(&p, &owner.p, received, admitted, admission) {
            return Err(rejected("Audit original received owner mismatch"));
        }
        let mut b = AuditBinding::new(Arc::clone(owner), p.clone())?;
        Arc::get_mut(&mut b)
            .ok_or_else(|| rejected("new Audit binding shared"))?
            .deadline = original_read;
        b.bounds()?;
        self.core.phase.step(self.target.index(), 157, 158)?;
        s.audit.binding = Some(b);
        s.audit.wire = Some(p.clone());
        s.audit.phase = 158;
        self.send(&Packet::V3AuditDisplay {
            presentation: p.clone(),
        })?;
        Ok(p)
    }
    pub fn report_v3_audited(&mut self, data: SignerV3AuditedV1) -> Result<()> {
        data.validate()?;
        let slot = &mut self.v3_entry.audit;
        let b = slot
            .binding
            .as_ref()
            .ok_or_else(|| rejected("Audit result without review"))?;
        if slot.reported
            || slot.phase != 159
            || self.core.phase.phase(self.target.index()) != 160
            || !matches_result(&data, &b.p)
        {
            return Err(rejected("Audit result replay/mismatch"));
        }
        self.core
            .phase
            .observe_v3_audited_complete(self.target.index())?;
        b.completed.store(true, Ordering::Release);
        slot.result = Some(data.clone());
        slot.reported = true;
        slot.phase = V3_HELD;
        self.send(&Packet::V3Audited {
            role: self.target,
            data,
        })
    }
    pub(in crate::financial_workflow_origin) fn receive_v3_audit(
        &mut self,
        p: Packet,
    ) -> Result<SignerFinancialWorkflowRequestV1> {
        let Packet::V3AuditFinal {
            role,
            presentation_digest,
        } = p
        else {
            return Err(rejected("wrong Audit request"));
        };
        let slot = &mut self.v3_entry.audit;
        let b = slot
            .binding
            .as_ref()
            .ok_or_else(|| rejected("Audit Final unsolicited"))?;
        if role != self.target
            || slot.phase != 158
            || presentation_digest != b.p.presentation_digest
        {
            return Err(rejected("Audit Final replay/mismatch"));
        }
        b.current(158)?;
        self.core.phase.step(role.index(), 158, 159)?;
        slot.phase = 159;
        Ok(SignerFinancialWorkflowRequestV1::V3Audit {
            final_action: SignerV3AuditFinalV1 {
                binding: Arc::clone(b),
                consumed: false,
            },
        })
    }
}
impl CoordinatorFinancialNativeV1 {
    pub fn admit_v3_audit(
        &self,
        mut ticket: SignerV3AuditTicketV1,
    ) -> Result<SignerV3AuditOutboundV1> {
        if !Arc::ptr_eq(&self.core, &ticket.binding.owner.pair.entry.core) {
            self.revoke();
            return Err(rejected("Audit foreign native Core"));
        }
        ticket.check_current()?;
        self.core
            .phase
            .step(ticket.binding.owner.pair.entry.slot(), 158, 159)?;
        ticket.consumed = true;
        Ok(SignerV3AuditOutboundV1 {
            binding: Arc::clone(&ticket.binding),
            consumed: false,
        })
    }
}
impl CoordinatorFinancialEndpointV1 {
    pub fn try_send_v3_audit(
        &mut self,
        mut out: SignerV3AuditOutboundV1,
    ) -> Result<FinancialSendProgressV1> {
        let b = Arc::clone(&out.binding);
        let i = b.owner.pair.entry.slot();
        let result = (|| {
            let slot = &self.v3_entries[i].audit;
            if !Arc::ptr_eq(&self.core, &b.owner.pair.entry.core)
                || slot.phase != 158
                || slot.binding.as_ref().is_none_or(|v| !Arc::ptr_eq(v, &b))
            {
                return Err(rejected("Audit outbound foreign/reused"));
            }
            b.bounds()?;
            if self.core.phase.source_send_restricted(i, 159)? {
                return Ok(FinancialSendProgressV1::Restricted);
            }
            let r = self.send_positive(
                &Packet::V3AuditFinal {
                    role: b.p.actor.signer_role,
                    presentation_digest: b.p.presentation_digest.clone(),
                },
                b.deadline,
            )?;
            if r == FinancialSendProgressV1::Sent {
                self.v3_entries[i].audit.phase = 159;
            }
            Ok(r)
        })();
        out.consumed = true;
        if result.is_err() {
            self.core.phase.revoke();
        }
        result
    }
    pub(in crate::financial_workflow_origin) fn receive_v3_audit_event(
        &mut self,
        p: Packet,
    ) -> Result<CoordinatorFinancialEventV1> {
        let role = p.target()?.ok_or_else(|| rejected("Audit role"))?;
        let i = role.index();
        let s = &mut self.v3_entries[i];
        let (owner, received) = s.delivery.admission_predecessor()?;
        let admitted = s
            .admission
            .result
            .as_ref()
            .ok_or_else(|| rejected("Audit before actual retained local admission"))?;
        let admission = s
            .admission
            .wire
            .as_ref()
            .ok_or_else(|| rejected("Audit missing original admission"))?;
        if !s.admission.reported {
            return Err(rejected("Audit before retained admission report"));
        }
        match p {
            Packet::V3AuditDisplay { presentation } => {
                if s.audit.binding.is_some()
                    || !matches_original(&presentation, &owner.p, received, admitted, admission)
                {
                    return Err(rejected("Audit display predecessor"));
                }
                let b = AuditBinding::new(Arc::clone(owner), presentation.clone())?;
                s.audit.wire = Some(presentation);
                s.audit.binding = Some(Arc::clone(&b));
                s.audit.phase = 158;
                if !received_workflow_progress(&self.core.phase, i, 157, 158)? {
                    return Ok(CoordinatorFinancialEventV1::Restricted(role));
                }
                Ok(CoordinatorFinancialEventV1::V3AuditDisplay(
                    SignerV3AuditTicketV1 {
                        binding: b,
                        consumed: false,
                    },
                ))
            }
            Packet::V3Audited { data, .. } => {
                data.validate()?;
                let slot = &mut s.audit;
                let b = slot
                    .binding
                    .as_ref()
                    .ok_or_else(|| rejected("Audit result before review"))?;
                if slot.reported || slot.phase != 159 || !matches_result(&data, &b.p) {
                    return Err(rejected("Audit actual result replay/mismatch"));
                }
                slot.result = Some(data.clone());
                slot.reported = true;
                slot.phase = 160;
                if received_workflow_progress(&self.core.phase, i, 159, 160)? {
                    received_workflow_progress(&self.core.phase, i, 160, V3_HELD)?;
                }
                Ok(CoordinatorFinancialEventV1::V3Audited { role, data })
            }
            _ => Err(rejected("wrong Audit event")),
        }
    }
}
fn relay_clock(
    p: &SignerV3AuditPresentationV1,
    clocks: FullWorkflowClocksV1,
    last: &mut u64,
) -> Result<()> {
    for cap in [
        p.review_ceiling_ms,
        p.service_ceiling_ms,
        p.material_ceiling_ms,
        p.source_ceiling_ms,
    ] {
        clocks.restrict_received(PROFILE, cap, clocks.supervision(), Instant::now())?;
    }
    let wall = state::wall_ms()?;
    if wall < *last || wall < p.facts.reviewed_at_ms || wall >= p.facts.expires_at_ms {
        return Err(rejected("Audit relay original clock"));
    }
    *last = wall;
    Ok(())
}
impl HostFinancialWorkflowRelayV1 {
    pub(in crate::financial_workflow_origin) fn down_v3_audit(&mut self, p: &Packet) -> Result<()> {
        if self.restricted {
            return Err(rejected("Audit relay after R"));
        }
        let Packet::V3AuditFinal {
            role,
            presentation_digest,
        } = p
        else {
            return Err(rejected("wrong Audit relay request"));
        };
        let s = &mut self.v3_entries[role.index()];
        let slot = &mut s.audit;
        let p = slot
            .wire
            .as_ref()
            .ok_or_else(|| rejected("Audit relay Final before review"))?;
        if slot.phase != 158 || presentation_digest != &p.presentation_digest {
            return Err(rejected("Audit relay Final mismatch/replay"));
        }
        relay_clock(p, self.clocks, &mut s.pair.last_wall)?;
        slot.phase = 159;
        Ok(())
    }
    pub(in crate::financial_workflow_origin) fn up_v3_audit(
        &mut self,
        role: Target,
        p: &Packet,
    ) -> Result<bool> {
        let s = &mut self.v3_entries[role.index()];
        let (read, received) = s.delivery.admission_wire()?;
        let admitted = s
            .admission
            .result
            .as_ref()
            .ok_or_else(|| rejected("Audit relay before retained admission"))?;
        let admission = s
            .admission
            .wire
            .as_ref()
            .ok_or_else(|| rejected("Audit relay missing admission"))?;
        if !s.admission.reported {
            return Err(rejected("Audit relay before actual report"));
        }
        match p {
            Packet::V3AuditDisplay { presentation } => {
                presentation.validate()?;
                if s.audit.wire.is_some()
                    || !matches_original(presentation, read, received, admitted, admission)
                {
                    return Err(rejected("Audit relay display predecessor"));
                }
                if !self.restricted {
                    relay_clock(presentation, self.clocks, &mut s.pair.last_wall)?;
                }
                s.audit.wire = Some(presentation.clone());
                s.audit.phase = 158;
                Ok(!self.restricted)
            }
            Packet::V3Audited { data, .. } => {
                data.validate()?;
                let slot = &mut s.audit;
                let p = slot
                    .wire
                    .as_ref()
                    .ok_or_else(|| rejected("Audit relay result before review"))?;
                if slot.reported || slot.phase != 159 || !matches_result(data, p) {
                    return Err(rejected("Audit relay result replay/mismatch"));
                }
                slot.result = Some(data.clone());
                slot.phase = V3_HELD;
                s.phase = V3_HELD;
                slot.reported = true;
                Ok(true)
            }
            _ => Err(rejected("wrong Audit relay event")),
        }
    }
}

/// Restriction-only handle to actual verified V3 custody. It is not a financial
/// grant and cannot construct source ownership from result data.
pub struct SignerV3CompletedLifetimeV1 {
    binding: Arc<AuditBinding>,
}
impl SignerV3CompletedLifetimeV1 {
    pub fn pair_grant_id(&self) -> &str {
        &self.binding.owner.p.facts.pair_grant_id
    }
    pub fn pair_channel_digest(&self) -> &str {
        &self.binding.owner.p.facts.pair_channel_digest
    }
    pub fn pair_presentation_digest(&self) -> &str {
        &self.binding.owner.pair.p.presentation_digest
    }

    pub fn original_channel_expires_at_ms(&self) -> u64 {
        self.binding.owner.pair.p.facts.channel_expires_at_ms
    }

    pub fn check_current(&self) -> Result<()> {
        if !self.binding.completed.load(Ordering::Acquire) {
            return Err(rejected("V3 completion has not been actually reported"));
        }
        self.binding.owner.custody_bounds()?;
        self.binding
            .owner
            .pair
            .entry
            .core
            .check_action_restrictions()
    }
    pub fn audit_presentation_digest(&self) -> &str {
        &self.binding.p.presentation_digest
    }
    pub fn source_identity_digest(&self) -> &str {
        &self.binding.p.facts.received.source_identity_digest
    }
    pub fn original_source_deadline(&self) -> Instant {
        self.binding.owner.pair.entry.original_source
    }
    pub fn original_channel_deadline(&self) -> Instant {
        self.binding.owner.pair.channel_deadline
    }
    pub fn original_service_deadline(&self) -> Instant {
        self.binding.owner.service_deadline
    }
    pub fn original_material_deadline(&self) -> Instant {
        self.binding.owner.material_deadline
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn audit_matches_original_verified_payload_and_retained_unknown_without_claiming_success() {
        let p = crate::signer_v3_audit_data::tests::presentation();
        let r = crate::signer_v3_delivery_data::tests::read();
        let a = crate::signer_v3_admission_data::tests::presentation();
        assert!(matches_original(
            &p,
            &r,
            &p.facts.received,
            &p.facts.admitted,
            &a
        ));
        let mut q = p.clone();
        q.facts.operation_id.push('x');
        assert!(!matches_original(
            &q,
            &r,
            &p.facts.received,
            &p.facts.admitted,
            &a
        ));
    }
    #[test]
    fn actual_audit_result_requires_exact_local_record_and_operation() {
        let p = crate::signer_v3_audit_data::tests::presentation();
        let mut d = crate::signer_v3_audit_data::tests::audited();
        assert!(matches_result(&d, &p));
        d.local_record_digest = "ff".repeat(32);
        assert!(!matches_result(&d, &p));
    }
    #[test]
    fn no_initial_or_intermediate_phase_can_claim_completed_v3() {
        for old in 0..=159 {
            let p = state::Phases::new();
            p.step(0, 0, old).unwrap();
            assert!(p.observe_v3_audited_complete(0).is_err());
        }
        let p = state::Phases::new();
        p.step(0, 0, 160).unwrap();
        p.revoke();
        p.observe_v3_audited_complete(0).unwrap();
        assert_eq!(p.phase(0), V3_HELD);
        assert!(p.revoked());
        assert!(p.step(0, V3_HELD, ENTRY_PREPARING).is_err());
        assert!(p.observe_v3_audited_complete(0).is_err());
    }
    #[test]
    fn completion_does_not_cross_quiescence() {
        let p = state::Phases::new();
        p.step(1, 0, 160).unwrap();
        p.begin_quiescence(p.snapshot()).unwrap();
        assert!(p.observe_v3_audited_complete(1).is_err());
    }
}
