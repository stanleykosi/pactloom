//! Fresh pairing on the actual original-fork source. No native grant conversion.
use super::*;
use crate::signer_v3_pair_data::*;
pub(super) const PAIR_REVIEW: u8 = 128;
pub(super) const PAIR_ADMITTED: u8 = 129;
pub(super) const PAIR_ISSUED: u8 = 130;
pub(super) const PAIRED: u8 = 131;
#[derive(Default)]
pub(super) struct PairSlot {
    pub endpoint: Option<SignerV3PairEndpointV1>,
    pub(super) binding: Option<Arc<PairBinding>>,
    pub(super) wire: Option<SignerV3PairPresentationV1>,
    pub(super) result: Option<SignerV3PairedV1>,
    phase: u8,
    pub(super) last_wall: u64,
}
pub(super) struct PairBinding {
    pub(super) entry: Arc<V3EntryReviewed>,
    pub(super) p: SignerV3PairPresentationV1,
    deadline: Instant,
    pub(super) channel_deadline: Instant,
    last_wall: AtomicU64,
}
impl PairBinding {
    fn new(entry: Arc<V3EntryReviewed>, p: SignerV3PairPresentationV1) -> Result<Arc<Self>> {
        p.validate()?;
        let now = Instant::now();
        let channel_deadline = entry
            .clocks
            .restrict_received(PROFILE, p.channel_ceiling_ms, entry.original_source, now)?
            .min(wall_ceiling(
                now,
                state::wall_ms()?,
                p.facts.reviewed_at_ms,
                p.facts.channel_expires_at_ms,
            )?);
        let deadline = entry
            .clocks
            .restrict_received(PROFILE, p.pair_ceiling_ms, channel_deadline, now)?
            .min(wall_ceiling(
                now,
                state::wall_ms()?,
                p.facts.reviewed_at_ms,
                p.facts.expires_at_ms,
            )?);
        if p.source_ceiling_ms != entry.wire.presentation.source_ceiling_ms
            || p.actor != entry.wire.presentation.actor
        {
            return Err(rejected("Pair original actor/source clock"));
        }
        let x = Arc::new(Self {
            entry,
            p,
            deadline,
            channel_deadline,
            last_wall: AtomicU64::new(state::wall_ms()?),
        });
        x.bounds()?;
        Ok(x)
    }
    pub(super) fn channel_bounds(&self) -> Result<()> {
        self.entry.check_custody()?;
        let wall = state::wall_ms()?;
        let old = self.last_wall.fetch_max(wall, Ordering::AcqRel);
        if wall < old
            || wall < self.p.facts.reviewed_at_ms
            || wall >= self.p.facts.channel_expires_at_ms
            || Instant::now() >= self.channel_deadline
        {
            return Err(rejected("Pair original channel expired"));
        }
        Ok(())
    }
    fn bounds(&self) -> Result<()> {
        self.channel_bounds()?;
        let wall = state::wall_ms()?;
        let old = self.last_wall.fetch_max(wall, Ordering::AcqRel);
        if wall < old
            || wall < self.p.facts.reviewed_at_ms
            || wall >= self.p.facts.expires_at_ms
            || Instant::now() >= self.deadline
        {
            return Err(rejected("Pair original action expired"));
        }
        Ok(())
    }
    fn current(&self, phase: u8) -> Result<()> {
        self.bounds()?;
        self.entry.core.check_action_restrictions()?;
        if self.entry.core.phase.phase(self.entry.slot()) != phase {
            return Err(rejected("Pair purpose consumed"));
        }
        Ok(())
    }
}
pub struct SignerV3PairTicketV1 {
    binding: Arc<PairBinding>,
    consumed: bool,
}
impl SignerV3PairTicketV1 {
    pub fn presentation(&self) -> &SignerV3PairPresentationV1 {
        &self.binding.p
    }
    pub fn check_current(&self) -> Result<()> {
        self.binding.current(PAIR_REVIEW)
    }
}
impl Drop for SignerV3PairTicketV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.entry.core.phase.revoke();
        }
    }
}
pub struct SignerV3PairOutboundV1 {
    binding: Arc<PairBinding>,
    consumed: bool,
}
impl Drop for SignerV3PairOutboundV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.entry.core.phase.revoke();
        }
    }
}
pub struct SignerV3PairFinalV1 {
    binding: Arc<PairBinding>,
    consumed: bool,
}
impl SignerV3PairFinalV1 {
    pub fn facts(&self) -> &SignerV3PairFactsV1 {
        &self.binding.p.facts
    }
    pub fn presentation(&self) -> &SignerV3PairPresentationV1 {
        &self.binding.p
    }
    pub fn check_current(&self) -> Result<()> {
        self.binding.current(PAIR_ADMITTED)
    }
    pub fn original_source_deadline(&self) -> Instant {
        self.binding.entry.original_source
    }
    pub fn original_channel_deadline(&self) -> Instant {
        self.binding.channel_deadline
    }
    pub fn original_pair_deadline(&self) -> Instant {
        self.binding.deadline
    }
    pub fn into_pair_lifetime(mut self) -> Result<SignerV3PairLifetimeV1> {
        self.check_current()?;
        self.binding.entry.core.phase.step(
            self.binding.entry.slot(),
            PAIR_ADMITTED,
            PAIR_ISSUED,
        )?;
        self.consumed = true;
        Ok(SignerV3PairLifetimeV1 {
            binding: Arc::clone(&self.binding),
        })
    }
}
impl Drop for SignerV3PairFinalV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.entry.core.phase.revoke();
        }
    }
}
pub struct SignerV3PairLifetimeV1 {
    binding: Arc<PairBinding>,
}
impl SignerV3PairLifetimeV1 {
    pub fn check_current(&self) -> Result<()> {
        self.binding.channel_bounds()?;
        self.binding.entry.core.check_action_restrictions()
    }
}
fn endpoint_matches(
    e: &SignerV3PairEndpointV1,
    opened: &SignerV3SourceOpenedV1,
    p: &SignerV3SourceEntryPresentationV1,
) -> bool {
    e.entry_presentation_digest == opened.entry_presentation_digest
        && e.source_identity_digest == opened.source_identity_digest
        && e.signer_process_instance == p.actor.signer_process_instance
        && e.source_expires_at_ms == p.facts.source_expires_at_ms
}
fn facts_match(
    p: &SignerV3PairPresentationV1,
    e: &SignerV3PairEndpointV1,
    entry: &SignerV3SourceEntryPresentationV1,
) -> bool {
    p.facts.matches_endpoint(e)
        && p.actor == entry.actor
        && p.facts.original_host_process_instance == entry.facts.original_host_process_instance
        && p.source_ceiling_ms == entry.source_ceiling_ms
}
impl SignerFinancialWorkflowOriginV1 {
    pub fn publish_v3_pair_endpoint(
        &mut self,
        endpoint_path: String,
    ) -> Result<SignerV3PairEndpointV1> {
        self.core.check_action_restrictions()?;
        let s = &mut self.v3_entry;
        let entry = s
            .entry
            .as_ref()
            .ok_or_else(|| rejected("Pair endpoint before Entry"))?;
        entry.check_custody()?;
        if !s.opened
            || s.terminal
            || s.pair.endpoint.is_some()
            || self.core.phase.phase(self.target.index()) != V3_OPENED
        {
            return Err(rejected("Pair endpoint one original source"));
        }
        let opened = s
            .observation
            .as_ref()
            .ok_or_else(|| rejected("Pair endpoint before actual opened report"))?;
        let p = &entry.wire.presentation;
        let provider = digest(
            b"wholepact:original-fork-coordinated-provider:v1\0",
            &(&p.actor, opened, &endpoint_path),
        )?;
        let mut e = SignerV3PairEndpointV1 {
            entry_presentation_digest: opened.entry_presentation_digest.clone(),
            source_identity_digest: opened.source_identity_digest.clone(),
            endpoint_path,
            endpoint_digest: String::new(),
            signer_process_instance: self.instance.clone(),
            coordinated_provider_reference: provider,
            source_expires_at_ms: p.facts.source_expires_at_ms,
        };
        e.endpoint_digest = e.calculate_endpoint_digest()?;
        e.validate()?;
        s.pair.endpoint = Some(e.clone());
        self.send(&Packet::V3PairEndpoint {
            role: self.target,
            data: e.clone(),
        })?;
        Ok(e)
    }
    pub fn offer_v3_pair(
        &mut self,
        facts: SignerV3PairFactsV1,
        original_pair: Instant,
        original_channel: Instant,
    ) -> Result<SignerV3PairPresentationV1> {
        self.core.check_action_restrictions()?;
        facts.validate()?;
        let (uid, pid) = self
            .leaf
            .as_ref()
            .ok_or_else(|| rejected("Pair original custody"))?
            .origin
            .original_host_identity()?;
        if facts.original_host_uid != uid || facts.original_host_pid != pid {
            return Err(rejected("Pair original H kernel identity"));
        }
        let s = &mut self.v3_entry;
        let entry = s
            .entry
            .as_ref()
            .ok_or_else(|| rejected("Pair missing Entry"))?;
        entry.check_custody()?;
        let endpoint = s
            .pair
            .endpoint
            .as_ref()
            .ok_or_else(|| rejected("Pair missing endpoint"))?;
        if s.pair.binding.is_some()
            || s.terminal
            || !facts.matches_endpoint(endpoint)
            || facts.original_host_process_instance
                != entry.wire.presentation.facts.original_host_process_instance
            || original_pair > original_channel
            || original_channel > entry.original_source
            || original_channel > Instant::now() + Duration::from_secs(900)
            || original_pair > Instant::now() + Duration::from_secs(120)
        {
            return Err(rejected("Pair selected source/clock"));
        }
        let mut p = SignerV3PairPresentationV1 {
            actor: entry.wire.presentation.actor.clone(),
            facts,
            notice: crate::signer_v3_pair_data::NOTICE.into(),
            challenge: state::nonce()?,
            source_ceiling_ms: entry.wire.presentation.source_ceiling_ms,
            pair_ceiling_ms: self
                .clocks
                .restrictive_offset(original_pair, original_channel)?,
            channel_ceiling_ms: self
                .clocks
                .restrictive_offset(original_channel, entry.original_source)?,
            presentation_digest: String::new(),
        };
        p.presentation_digest = p.calculate_presentation_digest()?;
        let b = PairBinding::new(Arc::clone(entry), p.clone())?;
        self.core
            .phase
            .step(self.target.index(), V3_OPENED, PAIR_REVIEW)?;
        s.pair.binding = Some(b);
        s.pair.phase = PAIR_REVIEW;
        self.send(&Packet::V3PairDisplay {
            presentation: p.clone(),
        })?;
        Ok(p)
    }
    pub fn report_v3_pair_authenticated(&mut self, data: SignerV3PairedV1) -> Result<()> {
        data.validate()?;
        let s = &mut self.v3_entry;
        let b = s
            .pair
            .binding
            .as_ref()
            .ok_or_else(|| rejected("Pair result without review"))?;
        if s.pair.phase != PAIR_ADMITTED
            || self.core.phase.phase(self.target.index()) != PAIR_ISSUED
        {
            return Err(rejected("Pair result without consumed actual Final"));
        }
        b.channel_bounds()?;
        if !result_matches(&data, &b.p) {
            return Err(rejected("Pair authenticated result changed"));
        }
        s.pair.result = Some(data.clone());
        self.core
            .phase
            .step(self.target.index(), PAIR_ISSUED, PAIRED)?;
        s.pair.phase = PAIRED;
        self.send(&Packet::V3Paired {
            role: self.target,
            data,
        })
    }
    pub(in crate::financial_workflow_origin) fn receive_v3_pair(
        &mut self,
        p: Packet,
    ) -> Result<SignerFinancialWorkflowRequestV1> {
        match p {
            Packet::V3PairFinal {
                role,
                presentation_digest,
            } => {
                let s = &mut self.v3_entry;
                let b = s
                    .pair
                    .binding
                    .as_ref()
                    .ok_or_else(|| rejected("Pair Final unsolicited"))?;
                if role != self.target
                    || s.pair.phase != PAIR_REVIEW
                    || presentation_digest != b.p.presentation_digest
                {
                    return Err(rejected("Pair Final exact one-shot binding"));
                }
                b.current(PAIR_REVIEW)?;
                self.core
                    .phase
                    .step(role.index(), PAIR_REVIEW, PAIR_ADMITTED)?;
                s.pair.phase = PAIR_ADMITTED;
                Ok(SignerFinancialWorkflowRequestV1::V3Pair {
                    final_action: SignerV3PairFinalV1 {
                        binding: Arc::clone(b),
                        consumed: false,
                    },
                })
            }
            _ => Err(rejected("wrong Pair request")),
        }
    }
}
impl CoordinatorFinancialNativeV1 {
    pub fn admit_v3_pair(
        &self,
        mut ticket: SignerV3PairTicketV1,
    ) -> Result<SignerV3PairOutboundV1> {
        let b = &ticket.binding;
        if !Arc::ptr_eq(&self.core, &b.entry.core) {
            self.revoke();
            return Err(rejected("Pair foreign native Core"));
        }
        ticket.check_current()?;
        self.core
            .phase
            .step(b.entry.slot(), PAIR_REVIEW, PAIR_ADMITTED)?;
        ticket.consumed = true;
        Ok(SignerV3PairOutboundV1 {
            binding: Arc::clone(b),
            consumed: false,
        })
    }
}
impl CoordinatorFinancialEndpointV1 {
    pub fn send_v3_pair(&mut self, out: SignerV3PairOutboundV1) -> Result<()> {
        self.try_send_v3_pair(out)?.require_sent()
    }
    pub fn try_send_v3_pair(
        &mut self,
        mut out: SignerV3PairOutboundV1,
    ) -> Result<FinancialSendProgressV1> {
        let b = Arc::clone(&out.binding);
        let i = b.entry.slot();
        let result = (|| {
            if !Arc::ptr_eq(&self.core, &b.entry.core)
                || self.v3_entries[i].pair.phase != PAIR_REVIEW
                || self.v3_entries[i]
                    .pair
                    .binding
                    .as_ref()
                    .is_none_or(|old| !Arc::ptr_eq(old, &b))
            {
                return Err(rejected("Pair outbound foreign/reused"));
            }
            b.bounds()?;
            if self.core.phase.source_send_restricted(i, PAIR_ADMITTED)? {
                return Ok(FinancialSendProgressV1::Restricted);
            }
            let r = self.send_positive(
                &Packet::V3PairFinal {
                    role: b.p.actor.signer_role,
                    presentation_digest: b.p.presentation_digest.clone(),
                },
                b.deadline,
            )?;
            if r == FinancialSendProgressV1::Sent {
                self.v3_entries[i].pair.phase = PAIR_ADMITTED;
            }
            Ok(r)
        })();
        out.consumed = true;
        if result.is_err() {
            self.core.phase.revoke();
        }
        result
    }
    pub(in crate::financial_workflow_origin) fn receive_v3_pair_event(
        &mut self,
        p: Packet,
    ) -> Result<CoordinatorFinancialEventV1> {
        let role = p.target()?.ok_or_else(|| rejected("Pair role"))?;
        let i = role.index();
        let s = &mut self.v3_entries[i];
        let entry = s
            .entry
            .as_ref()
            .ok_or_else(|| rejected("Pair before Entry"))?;
        if !s.opened || s.terminal {
            return Err(rejected("Pair source not opened"));
        }
        match p {
            Packet::V3PairEndpoint { data, .. } => {
                data.validate()?;
                entry.check_custody()?;
                if s.pair.endpoint.is_some()
                    || !endpoint_matches(
                        &data,
                        s.observation
                            .as_ref()
                            .ok_or_else(|| rejected("Pair observation"))?,
                        &entry.wire.presentation,
                    )
                {
                    return Err(rejected("Pair endpoint changed"));
                }
                s.pair.endpoint = Some(data.clone());
                Ok(CoordinatorFinancialEventV1::V3PairEndpoint { role, data })
            }
            Packet::V3PairDisplay { presentation } => {
                let endpoint = s
                    .pair
                    .endpoint
                    .as_ref()
                    .ok_or_else(|| rejected("Pair display before endpoint"))?;
                if s.pair.binding.is_some()
                    || !facts_match(&presentation, endpoint, &entry.wire.presentation)
                {
                    return Err(rejected("Pair display binding"));
                }
                let b = PairBinding::new(Arc::clone(entry), presentation)?;
                s.pair.binding = Some(Arc::clone(&b));
                s.pair.phase = PAIR_REVIEW;
                if !received_workflow_progress(&self.core.phase, i, V3_OPENED, PAIR_REVIEW)? {
                    return Ok(CoordinatorFinancialEventV1::Restricted(role));
                }
                Ok(CoordinatorFinancialEventV1::V3PairDisplay(
                    SignerV3PairTicketV1 {
                        binding: b,
                        consumed: false,
                    },
                ))
            }
            Packet::V3Paired { data, .. } => {
                let b = s
                    .pair
                    .binding
                    .as_ref()
                    .ok_or_else(|| rejected("Pair result before display"))?;
                if s.pair.phase != PAIR_ADMITTED || !result_matches(&data, &b.p) {
                    return Err(rejected("Pair result mismatch/replay"));
                }
                s.pair.result = Some(data.clone());
                s.pair.phase = PAIRED;
                received_workflow_progress(&self.core.phase, i, PAIR_ADMITTED, PAIRED)?;
                Ok(CoordinatorFinancialEventV1::V3Paired { role, data })
            }
            _ => Err(rejected("wrong Pair event")),
        }
    }
}
impl HostFinancialWorkflowRelayV1 {
    pub(in crate::financial_workflow_origin) fn down_v3_pair(&mut self, p: &Packet) -> Result<()> {
        if self.restricted {
            return Err(rejected("Pair after R"));
        }
        let role = p.target()?.ok_or_else(|| rejected("Pair role"))?;
        let s = &mut self.v3_entries[role.index()];
        let wire = s
            .pair
            .wire
            .as_ref()
            .ok_or_else(|| rejected("Pair Final before display"))?;
        match p {
            Packet::V3PairFinal {
                presentation_digest,
                ..
            } => {
                if s.pair.phase != PAIR_REVIEW || presentation_digest != &wire.presentation_digest {
                    return Err(rejected("Pair relay Final mismatch/replay"));
                }
                pair_relay_current(wire, self.clocks, &mut s.pair.last_wall)?;
                s.pair.phase = PAIR_ADMITTED;
                Ok(())
            }
            _ => Err(rejected("wrong Pair relay command")),
        }
    }
    pub(in crate::financial_workflow_origin) fn up_v3_pair(
        &mut self,
        role: Target,
        p: &Packet,
    ) -> Result<bool> {
        let s = &mut self.v3_entries[role.index()];
        let entry = s
            .offer
            .as_ref()
            .ok_or_else(|| rejected("Pair relay before Entry"))?;
        if !s.opened || s.terminal {
            return Err(rejected("Pair relay source not opened"));
        }
        match p {
            Packet::V3PairEndpoint { data, .. } => {
                data.validate()?;
                self.clocks.restrict_received(
                    PROFILE,
                    entry.presentation.source_ceiling_ms,
                    self.clocks.supervision(),
                    Instant::now(),
                )?;
                if state::wall_ms()? >= data.source_expires_at_ms {
                    return Err(rejected("Pair endpoint source expired"));
                }
                if s.pair.endpoint.is_some()
                    || !endpoint_matches(
                        data,
                        s.observation
                            .as_ref()
                            .ok_or_else(|| rejected("Pair relay opened observation"))?,
                        &entry.presentation,
                    )
                {
                    return Err(rejected("Pair relay endpoint changed"));
                }
                s.pair.endpoint = Some(data.clone());
                if !self.restricted {
                    self.lifecycle
                        .publish_v3_pair_endpoint(role, data.clone())?;
                }
                Ok(!self.restricted)
            }
            Packet::V3PairDisplay { presentation } => {
                presentation.validate()?;
                let endpoint = s
                    .pair
                    .endpoint
                    .as_ref()
                    .ok_or_else(|| rejected("Pair relay endpoint missing"))?;
                if s.pair.wire.is_some()
                    || !facts_match(presentation, endpoint, &entry.presentation)
                {
                    return Err(rejected("Pair relay display original binding"));
                }
                if !self.restricted {
                    pair_relay_current(presentation, self.clocks, &mut s.pair.last_wall)?;
                }
                s.pair.wire = Some(presentation.clone());
                s.pair.phase = PAIR_REVIEW;
                Ok(!self.restricted)
            }
            Packet::V3Paired { data, .. } => {
                let wire = s
                    .pair
                    .wire
                    .as_ref()
                    .ok_or_else(|| rejected("Pair relay result before display"))?;
                if s.pair.phase != PAIR_ADMITTED || !result_matches(data, wire) {
                    return Err(rejected("Pair relay result mismatch/replay"));
                }
                s.pair.result = Some(data.clone());
                s.pair.phase = PAIRED;
                Ok(true)
            }
            _ => Err(rejected("wrong Pair relay event")),
        }
    }
}
fn pair_relay_current(
    p: &SignerV3PairPresentationV1,
    clocks: FullWorkflowClocksV1,
    last: &mut u64,
) -> Result<()> {
    for bound in [p.source_ceiling_ms, p.pair_ceiling_ms, p.channel_ceiling_ms] {
        clocks.restrict_received(PROFILE, bound, clocks.supervision(), Instant::now())?;
    }
    let wall = state::wall_ms()?;
    if wall < *last
        || wall < p.facts.reviewed_at_ms
        || wall >= p.facts.expires_at_ms
        || wall >= p.facts.source_expires_at_ms
    {
        return Err(rejected("Pair relay clock elapsed"));
    }
    *last = wall;
    Ok(())
}

fn result_matches(d: &SignerV3PairedV1, p: &SignerV3PairPresentationV1) -> bool {
    d.validate().is_ok()
        && d.presentation_digest == p.presentation_digest
        && d.source_identity_digest == p.facts.source_identity_digest
        && d.original_host_process_instance == p.facts.original_host_process_instance
        && d.generation == p.facts.generation
        && d.channel_digest == p.facts.pairing_review_digest
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pairing_issuance_is_not_authentication_or_completion() {
        let phases = Phases::new();
        phases.step(0, 0, V3_OPENED).unwrap();
        phases.step(0, V3_OPENED, PAIR_REVIEW).unwrap();
        phases.step(0, PAIR_REVIEW, PAIR_ADMITTED).unwrap();
        phases.step(0, PAIR_ADMITTED, PAIR_ISSUED).unwrap();
        assert_ne!(phases.phase(0), PAIRED);
        assert_ne!(phases.phase(0), V3_HELD);
        phases.step(0, PAIR_ISSUED, PAIRED).unwrap();
        assert!(phases.step(0, PAIR_ISSUED, PAIRED).is_err());
        assert_ne!(phases.phase(0), V3_HELD);
    }
    #[test]
    fn pairing_restriction_prevents_issuance_and_authentication() {
        for phase in [PAIR_ADMITTED, PAIR_ISSUED] {
            let p = Phases::new();
            p.step(0, 0, phase).unwrap();
            p.revoke();
            assert!(p.step(0, phase, PAIRED).is_err());
        }
    }
    #[test]
    fn authenticated_observation_matches_original_channel_review() {
        let p = crate::signer_v3_pair_data::tests::presentation();
        let mut d = SignerV3PairedV1 {
            presentation_digest: p.presentation_digest.clone(),
            source_identity_digest: p.facts.source_identity_digest.clone(),
            original_host_process_instance: p.facts.original_host_process_instance.clone(),
            grant_id: "ab".repeat(32),
            key_digest: "bc".repeat(32),
            channel_digest: p.facts.pairing_review_digest.clone(),
            generation: 1,
        };
        assert!(result_matches(&d, &p));
        d.source_identity_digest = "ef".repeat(32);
        assert!(!result_matches(&d, &p));
    }
}
