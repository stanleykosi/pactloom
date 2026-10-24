//! A fresh owner-history/local-preparation Read, not custody reinterpreted as authority.
use super::delivery::PrepareReadBinding;
use super::*;
use crate::signer_v3_admit_read_data::*;
use crate::{SignerV3PrepareReadPresentationV1, SignerV3ReceivedV1};
#[derive(Default)]
pub(super) struct AdmitReadSlot {
    pub(super) binding: Option<Arc<AdmitReadBinding>>,
    pub(super) wire: Option<SignerV3AdmitReadPresentationV1>,
    pub(super) result: Option<SignerV3AdmitReadRetainedV1>,
    pub(super) phase: u8,
    pub(super) reported: bool,
}
pub(super) struct AdmitReadBinding {
    pub(super) owner: Arc<PrepareReadBinding>,
    pub(super) p: SignerV3AdmitReadPresentationV1,
    pub(super) deadline: Instant,
    last_wall: AtomicU64,
}
impl AdmitReadBinding {
    fn new(
        owner: Arc<PrepareReadBinding>,
        p: SignerV3AdmitReadPresentationV1,
    ) -> Result<Arc<Self>> {
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
            return Err(rejected("original fresh AdmitRead expired"));
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
            return Err(rejected("AdmitRead consumed or reordered"));
        }
        Ok(())
    }
}
pub struct SignerV3AdmitReadTicketV1 {
    binding: Arc<AdmitReadBinding>,
    consumed: bool,
}
impl SignerV3AdmitReadTicketV1 {
    pub fn presentation(&self) -> &SignerV3AdmitReadPresentationV1 {
        &self.binding.p
    }
    pub fn check_current(&self) -> Result<()> {
        self.binding.current(150)
    }
}
impl Drop for SignerV3AdmitReadTicketV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.owner.pair.entry.core.phase.revoke();
        }
    }
}
pub struct SignerV3AdmitReadOutboundV1 {
    binding: Arc<AdmitReadBinding>,
    consumed: bool,
}
impl Drop for SignerV3AdmitReadOutboundV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.owner.pair.entry.core.phase.revoke();
        }
    }
}
pub struct SignerV3AdmitReadFinalV1 {
    binding: Arc<AdmitReadBinding>,
    consumed: bool,
}
impl SignerV3AdmitReadFinalV1 {
    pub fn original_channel_expires_at_ms(&self) -> u64 {
        self.binding.owner.pair.p.facts.channel_expires_at_ms
    }

    pub fn presentation(&self) -> &SignerV3AdmitReadPresentationV1 {
        &self.binding.p
    }
    pub fn facts(&self) -> &SignerV3AdmitReadFactsV1 {
        &self.binding.p.facts
    }
    pub fn check_current(&self) -> Result<()> {
        self.binding.current(151)
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
    /// Semantic failure reporting only. An unconditional owned-worker error
    /// already exists. Advance the same restrictive close before the original
    /// automatic drops, so IPC-first cleanup cannot erase the latched error.
    /// This is not a success/permission API and performs no additional check.
    #[cfg(wholepact_financial_rendered_host_semantic_ci)]
    pub fn financial_ci_close_for_failed_admit_read_v1(&self) {
        self.binding.owner.pair.entry.core.close_with_failure_observation();
    }
    pub fn finish_read(mut self) -> Result<()> {
        let current = self.check_current();
        #[cfg(wholepact_financial_rendered_host_semantic_ci)]
        if let Err(error) = &current {
            crate::financial_ci_actor_diagnostics::driver(
                crate::financial_ci_actor_diagnostics::DriverStage::AdmitReadFinishCurrent,
                crate::financial_ci_actor_diagnostics::classify_io(error.kind()));
            self.financial_ci_close_for_failed_admit_read_v1();
        }
        current?;
        let transition = self.binding.owner.pair.entry.core.phase.step(
            self.binding.owner.pair.entry.slot(),
            151,
            152,
        );
        #[cfg(wholepact_financial_rendered_host_semantic_ci)]
        if let Err(error) = &transition {
            crate::financial_ci_actor_diagnostics::driver(
                crate::financial_ci_actor_diagnostics::DriverStage::AdmitReadFinishPhase,
                crate::financial_ci_actor_diagnostics::classify_io(error.kind()));
            self.financial_ci_close_for_failed_admit_read_v1();
        }
        transition?;
        self.consumed = true;
        Ok(())
    }
}
impl Drop for SignerV3AdmitReadFinalV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.owner.pair.entry.core.phase.revoke();
        }
    }
}
fn matches_original(
    p: &SignerV3AdmitReadPresentationV1,
    read: &SignerV3PrepareReadPresentationV1,
    received: &SignerV3ReceivedV1,
) -> bool {
    p.actor == read.actor
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
fn matches_result(d: &SignerV3AdmitReadRetainedV1, p: &SignerV3AdmitReadPresentationV1) -> bool {
    d.validate().is_ok()
        && d.admit_read_presentation_digest == p.presentation_digest
        && d.source_identity_digest == p.facts.received.source_identity_digest
        && d.owner_service_digest == p.facts.received.owner_service_digest
        && d.recipient_intent_digest == p.facts.received.recipient_intent_digest
}
impl SignerFinancialWorkflowOriginV1 {
    pub fn offer_v3_admit_read(
        &mut self,
        facts: SignerV3AdmitReadFactsV1,
        original_read: Instant,
    ) -> Result<SignerV3AdmitReadPresentationV1> {
        self.core.check_action_restrictions()?;
        facts.validate()?;
        let s = &mut self.v3_entry;
        let (owner, received) = s.delivery.admission_predecessor()?;
        owner.custody_bounds()?;
        if s.admit_read.binding.is_some()
            || original_read > owner.service_deadline
            || original_read > owner.material_deadline
            || original_read > Instant::now() + Duration::from_secs(120)
        {
            return Err(rejected("AdmitRead one original window"));
        }
        let mut p = SignerV3AdmitReadPresentationV1 {
            actor: owner.p.actor.clone(),
            facts,
            notice: crate::signer_v3_admit_read_data::NOTICE.into(),
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
        if !matches_original(&p, &owner.p, received) {
            return Err(rejected("AdmitRead original received owner mismatch"));
        }
        let mut b = AdmitReadBinding::new(Arc::clone(owner), p.clone())?;
        Arc::get_mut(&mut b)
            .ok_or_else(|| rejected("new AdmitRead binding shared"))?
            .deadline = original_read;
        b.bounds()?;
        self.core.phase.step(self.target.index(), 149, 150)?;
        s.admit_read.binding = Some(b);
        s.admit_read.wire = Some(p.clone());
        s.admit_read.phase = 150;
        self.send(&Packet::V3AdmitReadDisplay {
            presentation: p.clone(),
        })?;
        Ok(p)
    }
    pub fn report_v3_admit_read_retained(
        &mut self,
        data: SignerV3AdmitReadRetainedV1,
    ) -> Result<()> {
        data.validate()?;
        let slot = &mut self.v3_entry.admit_read;
        let b = slot
            .binding
            .as_ref()
            .ok_or_else(|| rejected("AdmitRead result without review"))?;
        if slot.reported
            || slot.phase != 151
            || self.core.phase.phase(self.target.index()) != 152
            || !matches_result(&data, &b.p)
        {
            return Err(rejected("AdmitRead result replay/mismatch"));
        }
        slot.result = Some(data.clone());
        slot.reported = true;
        slot.phase = 152;
        self.send(&Packet::V3AdmitReadRetained {
            role: self.target,
            data,
        })
    }
    pub(in crate::financial_workflow_origin) fn receive_v3_admit_read(
        &mut self,
        p: Packet,
    ) -> Result<SignerFinancialWorkflowRequestV1> {
        let Packet::V3AdmitReadFinal {
            role,
            presentation_digest,
        } = p
        else {
            return Err(rejected("wrong AdmitRead request"));
        };
        let slot = &mut self.v3_entry.admit_read;
        let b = slot
            .binding
            .as_ref()
            .ok_or_else(|| rejected("AdmitRead Final unsolicited"))?;
        if role != self.target
            || slot.phase != 150
            || presentation_digest != b.p.presentation_digest
        {
            return Err(rejected("AdmitRead Final replay/mismatch"));
        }
        b.current(150)?;
        self.core.phase.step(role.index(), 150, 151)?;
        slot.phase = 151;
        Ok(SignerFinancialWorkflowRequestV1::V3AdmitRead {
            final_action: SignerV3AdmitReadFinalV1 {
                binding: Arc::clone(b),
                consumed: false,
            },
        })
    }
}
impl CoordinatorFinancialNativeV1 {
    pub fn admit_v3_admit_read(
        &self,
        mut ticket: SignerV3AdmitReadTicketV1,
    ) -> Result<SignerV3AdmitReadOutboundV1> {
        if !Arc::ptr_eq(&self.core, &ticket.binding.owner.pair.entry.core) {
            self.revoke();
            return Err(rejected("AdmitRead foreign native Core"));
        }
        ticket.check_current()?;
        self.core
            .phase
            .step(ticket.binding.owner.pair.entry.slot(), 150, 151)?;
        ticket.consumed = true;
        Ok(SignerV3AdmitReadOutboundV1 {
            binding: Arc::clone(&ticket.binding),
            consumed: false,
        })
    }
}
impl CoordinatorFinancialEndpointV1 {
    pub fn try_send_v3_admit_read(
        &mut self,
        mut out: SignerV3AdmitReadOutboundV1,
    ) -> Result<FinancialSendProgressV1> {
        let b = Arc::clone(&out.binding);
        let i = b.owner.pair.entry.slot();
        let result = (|| {
            let slot = &self.v3_entries[i].admit_read;
            if !Arc::ptr_eq(&self.core, &b.owner.pair.entry.core)
                || slot.phase != 150
                || slot.binding.as_ref().is_none_or(|v| !Arc::ptr_eq(v, &b))
            {
                return Err(rejected("AdmitRead outbound foreign/reused"));
            }
            b.bounds()?;
            if self.core.phase.source_send_restricted(i, 151)? {
                return Ok(FinancialSendProgressV1::Restricted);
            }
            let r = self.send_positive(
                &Packet::V3AdmitReadFinal {
                    role: b.p.actor.signer_role,
                    presentation_digest: b.p.presentation_digest.clone(),
                },
                b.deadline,
            )?;
            if r == FinancialSendProgressV1::Sent {
                self.v3_entries[i].admit_read.phase = 151;
            }
            Ok(r)
        })();
        out.consumed = true;
        if result.is_err() {
            self.core.phase.revoke();
        }
        result
    }
    pub(in crate::financial_workflow_origin) fn receive_v3_admit_read_event(
        &mut self,
        p: Packet,
    ) -> Result<CoordinatorFinancialEventV1> {
        let role = p.target()?.ok_or_else(|| rejected("AdmitRead role"))?;
        let i = role.index();
        let s = &mut self.v3_entries[i];
        let (owner, received) = s.delivery.admission_predecessor()?;
        match p {
            Packet::V3AdmitReadDisplay { presentation } => {
                if s.admit_read.binding.is_some()
                    || !matches_original(&presentation, &owner.p, received)
                {
                    return Err(rejected("AdmitRead display predecessor"));
                }
                let b = AdmitReadBinding::new(Arc::clone(owner), presentation.clone())?;
                s.admit_read.wire = Some(presentation);
                s.admit_read.binding = Some(Arc::clone(&b));
                s.admit_read.phase = 150;
                if !received_workflow_progress(&self.core.phase, i, 149, 150)? {
                    return Ok(CoordinatorFinancialEventV1::Restricted(role));
                }
                Ok(CoordinatorFinancialEventV1::V3AdmitReadDisplay(
                    SignerV3AdmitReadTicketV1 {
                        binding: b,
                        consumed: false,
                    },
                ))
            }
            Packet::V3AdmitReadRetained { data, .. } => {
                data.validate()?;
                let slot = &mut s.admit_read;
                let b = slot
                    .binding
                    .as_ref()
                    .ok_or_else(|| rejected("AdmitRead result before review"))?;
                if slot.reported || slot.phase != 151 || !matches_result(&data, &b.p) {
                    return Err(rejected("AdmitRead actual result replay/mismatch"));
                }
                slot.result = Some(data.clone());
                slot.reported = true;
                slot.phase = 152;
                received_workflow_progress(&self.core.phase, i, 151, 152)?;
                Ok(CoordinatorFinancialEventV1::V3AdmitReadRetained { role, data })
            }
            _ => Err(rejected("wrong AdmitRead event")),
        }
    }
}
fn relay_clock(
    p: &SignerV3AdmitReadPresentationV1,
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
        return Err(rejected("AdmitRead relay original clock"));
    }
    *last = wall;
    Ok(())
}
impl HostFinancialWorkflowRelayV1 {
    pub(in crate::financial_workflow_origin) fn down_v3_admit_read(
        &mut self,
        p: &Packet,
    ) -> Result<()> {
        if self.restricted {
            return Err(rejected("AdmitRead relay after R"));
        }
        let Packet::V3AdmitReadFinal {
            role,
            presentation_digest,
        } = p
        else {
            return Err(rejected("wrong AdmitRead relay request"));
        };
        let s = &mut self.v3_entries[role.index()];
        let slot = &mut s.admit_read;
        let p = slot
            .wire
            .as_ref()
            .ok_or_else(|| rejected("AdmitRead relay Final before review"))?;
        if slot.phase != 150 || presentation_digest != &p.presentation_digest {
            return Err(rejected("AdmitRead relay Final mismatch/replay"));
        }
        relay_clock(p, self.clocks, &mut s.pair.last_wall)?;
        slot.phase = 151;
        Ok(())
    }
    pub(in crate::financial_workflow_origin) fn up_v3_admit_read(
        &mut self,
        role: Target,
        p: &Packet,
    ) -> Result<bool> {
        let s = &mut self.v3_entries[role.index()];
        let (read, received) = s.delivery.admission_wire()?;
        match p {
            Packet::V3AdmitReadDisplay { presentation } => {
                presentation.validate()?;
                if s.admit_read.wire.is_some() || !matches_original(presentation, read, received) {
                    return Err(rejected("AdmitRead relay display predecessor"));
                }
                if !self.restricted {
                    relay_clock(presentation, self.clocks, &mut s.pair.last_wall)?;
                }
                s.admit_read.wire = Some(presentation.clone());
                s.admit_read.phase = 150;
                Ok(!self.restricted)
            }
            Packet::V3AdmitReadRetained { data, .. } => {
                data.validate()?;
                let slot = &mut s.admit_read;
                let p = slot
                    .wire
                    .as_ref()
                    .ok_or_else(|| rejected("AdmitRead relay result before review"))?;
                if slot.reported || slot.phase != 151 || !matches_result(data, p) {
                    return Err(rejected("AdmitRead relay result replay/mismatch"));
                }
                slot.result = Some(data.clone());
                slot.phase = 152;
                slot.reported = true;
                Ok(true)
            }
            _ => Err(rejected("wrong AdmitRead relay event")),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retained_preparation_binds_same_verified_payload_and_local_client() {
        let p = crate::signer_v3_admit_read_data::tests::presentation();
        let mut d = crate::signer_v3_admit_read_data::tests::retained();
        assert!(matches_result(&d, &p));
        d.owner_service_digest = "ff".repeat(32);
        assert!(!matches_result(&d, &p));
    }
    #[test]
    fn fresh_history_cannot_relabel_original_service_or_received_intent() {
        let p = crate::signer_v3_admit_read_data::tests::presentation();
        let r = crate::signer_v3_delivery_data::tests::read();
        assert!(matches_original(&p, &r, &p.facts.received));
        let mut q = p.clone();
        q.service_ceiling_ms += 1;
        assert!(!matches_original(&q, &r, &p.facts.received));
        let mut q = p.clone();
        q.facts.received.recipient_intent_digest = "ff".repeat(32);
        assert!(!matches_original(&q, &r, &p.facts.received));
    }
}
