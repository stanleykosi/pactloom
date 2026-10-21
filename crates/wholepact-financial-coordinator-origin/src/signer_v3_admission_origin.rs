//! Conditional READY and separate native Final for the exact retained V3 admission.
use super::admit_read::AdmitReadBinding;
use super::*;
use crate::signer_v3_admission_data::*;
use crate::{SignerV3AdmitReadPresentationV1, SignerV3AdmitReadRetainedV1};
#[derive(Default)]
pub(super) struct AdmissionSlot {
    pub(super) binding: Option<Arc<AdmissionBinding>>,
    pub(super) wire: Option<SignerV3AdmitPresentationV1>,
    ready: Option<Arc<AdmissionReady>>,
    ready_wire: Option<(SignerV3AdmitReadyV1, String)>,
    pub(super) result: Option<SignerV3AdmittedV1>,
    pub(super) phase: u8,
    pub(super) reported: bool,
}
pub(super) struct AdmissionBinding {
    pub(super) read: Arc<AdmitReadBinding>,
    pub(super) p: SignerV3AdmitPresentationV1,
    pub(super) deadline: Instant,
    last_wall: AtomicU64,
}
impl AdmissionBinding {
    fn new(read: Arc<AdmitReadBinding>, p: SignerV3AdmitPresentationV1) -> Result<Arc<Self>> {
        p.validate()?;
        read.bounds()?;
        let now = Instant::now();
        let deadline = read
            .owner
            .pair
            .entry
            .clocks
            .restrict_received(PROFILE, p.review_ceiling_ms, read.deadline, now)?
            .min(wall_ceiling(
                now,
                state::wall_ms()?,
                p.facts.reviewed_at_ms,
                p.facts.expires_at_ms,
            )?);
        let b = Arc::new(Self {
            read,
            p,
            deadline,
            last_wall: AtomicU64::new(state::wall_ms()?),
        });
        b.bounds()?;
        Ok(b)
    }
    fn core(&self) -> &Arc<Core> {
        &self.read.owner.pair.entry.core
    }
    fn slot(&self) -> usize {
        self.read.owner.pair.entry.slot()
    }
    fn bounds(&self) -> Result<()> {
        self.read.bounds()?;
        let wall = state::wall_ms()?;
        let old = self.last_wall.fetch_max(wall, Ordering::AcqRel);
        if wall < old
            || wall < self.p.facts.reviewed_at_ms
            || wall >= self.p.facts.expires_at_ms
            || Instant::now() >= self.deadline
        {
            return Err(rejected("original admission window expired"));
        }
        Ok(())
    }
    fn current(&self, phase: u8) -> Result<()> {
        self.bounds()?;
        self.core().check_action_restrictions()?;
        if self.core().phase.phase(self.slot()) != phase {
            return Err(rejected("admission purpose consumed/reordered"));
        }
        Ok(())
    }
}
struct AdmissionReady {
    binding: Arc<AdmissionBinding>,
    data: SignerV3AdmitReadyV1,
    challenge: String,
}
pub struct SignerV3AdmitTicketV1 {
    binding: Arc<AdmissionBinding>,
    consumed: bool,
}
impl SignerV3AdmitTicketV1 {
    pub fn presentation(&self) -> &SignerV3AdmitPresentationV1 {
        &self.binding.p
    }
    pub fn check_current(&self) -> Result<()> {
        self.binding.current(153)
    }
}
impl Drop for SignerV3AdmitTicketV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.core().phase.revoke();
        }
    }
}
pub struct SignerV3AdmitArmOutboundV1 {
    binding: Arc<AdmissionBinding>,
    consumed: bool,
}
impl Drop for SignerV3AdmitArmOutboundV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.core().phase.revoke();
        }
    }
}
pub struct SignerV3AdmitArmV1 {
    binding: Arc<AdmissionBinding>,
    consumed: bool,
}
impl SignerV3AdmitArmV1 {
    pub fn original_channel_expires_at_ms(&self) -> u64 {
        self.binding.read.owner.pair.p.facts.channel_expires_at_ms
    }

    pub fn presentation(&self) -> &SignerV3AdmitPresentationV1 {
        &self.binding.p
    }
    pub fn facts(&self) -> &SignerV3AdmitFactsV1 {
        &self.binding.p.facts
    }
    pub fn check_current(&self) -> Result<()> {
        self.binding.current(154)
    }
    pub fn original_admit_deadline(&self) -> Instant {
        self.binding.deadline
    }
    pub fn original_source_deadline(&self) -> Instant {
        self.binding.read.owner.pair.entry.original_source
    }
    pub fn original_service_deadline(&self) -> Instant {
        self.binding.read.owner.service_deadline
    }
}
impl Drop for SignerV3AdmitArmV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.core().phase.revoke();
        }
    }
}
pub struct SignerV3AdmitReadyTicketV1 {
    ready: Arc<AdmissionReady>,
    consumed: bool,
}
impl SignerV3AdmitReadyTicketV1 {
    pub fn presentation(&self) -> &SignerV3AdmitPresentationV1 {
        &self.ready.binding.p
    }
    pub fn ready(&self) -> &SignerV3AdmitReadyV1 {
        &self.ready.data
    }
    pub fn check_current(&self) -> Result<()> {
        self.ready.binding.current(155)
    }
}
impl Drop for SignerV3AdmitReadyTicketV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.ready.binding.core().phase.revoke();
        }
    }
}
pub struct SignerV3AdmitFinalOutboundV1 {
    ready: Arc<AdmissionReady>,
    consumed: bool,
}
impl Drop for SignerV3AdmitFinalOutboundV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.ready.binding.core().phase.revoke();
        }
    }
}
pub struct SignerV3AdmitFinalV1 {
    ready: Arc<AdmissionReady>,
    effect: AtomicU8,
    consumed: bool,
}
impl SignerV3AdmitFinalV1 {
    pub fn original_channel_expires_at_ms(&self) -> u64 {
        self.ready
            .binding
            .read
            .owner
            .pair
            .p
            .facts
            .channel_expires_at_ms
    }

    pub fn presentation(&self) -> &SignerV3AdmitPresentationV1 {
        &self.ready.binding.p
    }
    pub fn facts(&self) -> &SignerV3AdmitFactsV1 {
        &self.ready.binding.p.facts
    }
    pub fn ready(&self) -> &SignerV3AdmitReadyV1 {
        &self.ready.data
    }
    pub fn check_current(&self) -> Result<()> {
        self.ready.binding.current(156)
    }
    pub fn original_admit_deadline(&self) -> Instant {
        self.ready.binding.deadline
    }
    pub fn original_read_deadline(&self) -> Instant {
        self.ready.binding.read.deadline
    }
    pub fn original_source_deadline(&self) -> Instant {
        self.ready.binding.read.owner.pair.entry.original_source
    }
    pub fn original_channel_deadline(&self) -> Instant {
        self.ready.binding.read.owner.pair.channel_deadline
    }
    pub fn original_service_deadline(&self) -> Instant {
        self.ready.binding.read.owner.service_deadline
    }
    pub fn original_material_deadline(&self) -> Instant {
        self.ready.binding.read.owner.material_deadline
    }
    /// Trusted pinned-S callsite: hold all local locks first, then MOVE the entire
    /// owned SQL transaction into this synchronous exact-purpose closure. Drop,
    /// rollback or commit must finish before this gate returns. No socket I/O here.
    pub fn execute_admission_publication(
        &self,
        publication: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        self.check_current()?;
        self.effect
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| {
                self.ready.binding.core().phase.revoke();
                rejected("admission publication one-use")
            })?;
        let core = self.ready.binding.core();
        let mut attempt = AdmissionEffectAttempt {
            core,
            effect: &self.effect,
            settled: false,
        };
        let restriction = core
            .signer_restriction
            .as_ref()
            .ok_or_else(|| rejected("admission missing original shared restriction"))?;
        restriction.execute_journal_publication(|| {
            self.check_current()?;
            publication()
        })?;
        self.effect.store(2, Ordering::Release);
        attempt.settled = true;
        Ok(())
    }
    /// Observe only a locally retained record after the separately checked remote
    /// send settled Controlled or Unknown. R is preserved, never turned into retry.
    pub fn finish_admission(mut self) -> Result<()> {
        let b = &self.ready.binding;
        let core = b.core();
        if self.effect.load(Ordering::Acquire) != 2
            || unsafe { libc::getpid() } != core.owner_pid
            || unsafe { libc::geteuid() } != core.owner_uid
            || core.phase.phase(b.slot()) != 156
        {
            return Err(rejected(
                "admission finish lacks original completed local publication",
            ));
        }
        core.phase.observe_v3_admission_published(b.slot())?;
        self.consumed = true;
        Ok(())
    }
}
impl Drop for SignerV3AdmitFinalV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.ready.binding.core().phase.revoke();
        }
    }
}
struct AdmissionEffectAttempt<'a> {
    core: &'a Core,
    effect: &'a AtomicU8,
    settled: bool,
}
impl Drop for AdmissionEffectAttempt<'_> {
    fn drop(&mut self) {
        if !self.settled {
            self.effect.store(3, Ordering::Release);
            self.core.phase.revoke();
        }
    }
}
fn matches_read(
    p: &SignerV3AdmitPresentationV1,
    read: &SignerV3AdmitReadPresentationV1,
    result: &SignerV3AdmitReadRetainedV1,
) -> bool {
    p.actor == read.actor
        && p.facts.read == *result
        && p.source_ceiling_ms == read.source_ceiling_ms
        && p.service_ceiling_ms == read.service_ceiling_ms
        && p.material_ceiling_ms == read.material_ceiling_ms
        && p.review_ceiling_ms <= read.review_ceiling_ms
        && p.facts.source_expires_at_ms == read.facts.source_expires_at_ms
        && p.facts.service_expires_at_ms == read.facts.service_expires_at_ms
        && p.facts.material_expires_at_ms == read.facts.material_expires_at_ms
        && p.facts.expires_at_ms <= read.facts.expires_at_ms
        && p.facts.reviewed_at_ms >= read.facts.reviewed_at_ms
}
fn matches_ready(d: &SignerV3AdmitReadyV1, p: &SignerV3AdmitPresentationV1) -> bool {
    d.validate().is_ok()
        && d.admit_presentation_digest == p.presentation_digest
        && d.admission_request_digest == p.facts.read.admission_request_digest
        && d.admission_review_digest == p.facts.read.admission_review_digest
        && d.owner_service_digest == p.facts.read.owner_service_digest
        && d.expected_head_sequence == p.facts.read.expected_head_sequence
        && d.expected_head_digest == p.facts.read.expected_head_digest
        && d.operation_id == p.facts.read.operation_id
}
fn matches_result(d: &SignerV3AdmittedV1, p: &SignerV3AdmitPresentationV1) -> bool {
    d.validate().is_ok()
        && d.admit_presentation_digest == p.presentation_digest
        && d.admission_request_digest == p.facts.read.admission_request_digest
        && d.admission_review_digest == p.facts.read.admission_review_digest
        && d.owner_service_digest == p.facts.read.owner_service_digest
}
impl SignerFinancialWorkflowOriginV1 {
    pub fn offer_v3_admit(
        &mut self,
        facts: SignerV3AdmitFactsV1,
        original_admit: Instant,
    ) -> Result<SignerV3AdmitPresentationV1> {
        self.core.check_action_restrictions()?;
        facts.validate()?;
        let s = &mut self.v3_entry;
        let read = s
            .admit_read
            .binding
            .as_ref()
            .ok_or_else(|| rejected("admission before fresh Read"))?;
        let result = s
            .admit_read
            .result
            .as_ref()
            .ok_or_else(|| rejected("admission before actual prepared request"))?;
        read.bounds()?;
        if !s.admit_read.reported
            || s.admission.binding.is_some()
            || original_admit > read.deadline
            || original_admit > Instant::now() + Duration::from_secs(120)
        {
            return Err(rejected("admission original exact window"));
        }
        let mut p = SignerV3AdmitPresentationV1 {
            actor: read.p.actor.clone(),
            facts,
            notice: crate::signer_v3_admission_data::NOTICE.into(),
            challenge: state::nonce()?,
            source_ceiling_ms: read.p.source_ceiling_ms,
            service_ceiling_ms: read.p.service_ceiling_ms,
            material_ceiling_ms: read.p.material_ceiling_ms,
            review_ceiling_ms: self
                .clocks
                .restrictive_offset(original_admit, read.deadline)?,
            presentation_digest: String::new(),
        };
        p.presentation_digest = p.calculate_presentation_digest()?;
        if !matches_read(&p, &read.p, result) {
            return Err(rejected("admission exact local candidate mismatch"));
        }
        let mut b = AdmissionBinding::new(Arc::clone(read), p.clone())?;
        Arc::get_mut(&mut b)
            .ok_or_else(|| rejected("new admission binding shared"))?
            .deadline = original_admit;
        b.bounds()?;
        self.core.phase.step(self.target.index(), 152, 153)?;
        s.admission.binding = Some(b);
        s.admission.wire = Some(p.clone());
        s.admission.phase = 153;
        self.send(&Packet::V3AdmitDisplay {
            presentation: p.clone(),
        })?;
        Ok(p)
    }
    pub fn send_v3_admit_ready(
        &mut self,
        mut arm: SignerV3AdmitArmV1,
        data: SignerV3AdmitReadyV1,
    ) -> Result<()> {
        let slot = &mut self.v3_entry.admission;
        let b = slot
            .binding
            .as_ref()
            .ok_or_else(|| rejected("admission READY before review"))?;
        if slot.phase != 154
            || slot.ready.is_some()
            || !Arc::ptr_eq(b, &arm.binding)
            || !matches_ready(&data, &b.p)
        {
            return Err(rejected("admission actual READY mismatch/replay"));
        }
        arm.check_current()?;
        let challenge = state::nonce()?;
        let ready = Arc::new(AdmissionReady {
            binding: Arc::clone(b),
            data: data.clone(),
            challenge: challenge.clone(),
        });
        self.core.phase.step(self.target.index(), 154, 155)?;
        slot.ready = Some(ready);
        slot.ready_wire = Some((data.clone(), challenge.clone()));
        slot.phase = 155;
        arm.consumed = true;
        self.send(&Packet::V3AdmitReady {
            role: self.target,
            data,
            ready_challenge: challenge,
        })
    }
    pub fn report_v3_admitted(&mut self, data: SignerV3AdmittedV1) -> Result<()> {
        data.validate()?;
        let slot = &mut self.v3_entry.admission;
        let b = slot
            .binding
            .as_ref()
            .ok_or_else(|| rejected("admission result before offer"))?;
        if slot.reported
            || slot.phase != 156
            || self.core.phase.phase(self.target.index()) != 157
            || !matches_result(&data, &b.p)
        {
            return Err(rejected("admission retained result replay/mismatch"));
        }
        slot.result = Some(data.clone());
        slot.reported = true;
        slot.phase = 157;
        self.send(&Packet::V3Admitted {
            role: self.target,
            data,
        })
    }
    pub(in crate::financial_workflow_origin) fn receive_v3_admission(
        &mut self,
        p: Packet,
    ) -> Result<SignerFinancialWorkflowRequestV1> {
        let role = p.target()?.ok_or_else(|| rejected("admission role"))?;
        if role != self.target {
            return Err(rejected("admission wrong original role"));
        }
        let slot = &mut self.v3_entry.admission;
        let b = slot
            .binding
            .as_ref()
            .ok_or_else(|| rejected("admission command before review"))?;
        match p {
            Packet::V3AdmitArm {
                presentation_digest,
                ..
            } => {
                if slot.phase != 153 || presentation_digest != b.p.presentation_digest {
                    return Err(rejected("admission Arm mismatch/replay"));
                }
                b.current(153)?;
                self.core.phase.step(role.index(), 153, 154)?;
                slot.phase = 154;
                Ok(SignerFinancialWorkflowRequestV1::V3AdmitArm {
                    arm: SignerV3AdmitArmV1 {
                        binding: Arc::clone(b),
                        consumed: false,
                    },
                })
            }
            Packet::V3AdmitFinal {
                presentation_digest,
                ready_challenge,
                authenticated_ready_digest,
                ..
            } => {
                let ready = slot
                    .ready
                    .as_ref()
                    .ok_or_else(|| rejected("admission Final before actual READY"))?;
                if slot.phase != 155
                    || presentation_digest != b.p.presentation_digest
                    || ready_challenge != ready.challenge
                    || authenticated_ready_digest != ready.data.authenticated_ready_digest
                {
                    return Err(rejected("admission Final exact READY mismatch/replay"));
                }
                b.current(155)?;
                self.core.phase.step(role.index(), 155, 156)?;
                slot.phase = 156;
                Ok(SignerFinancialWorkflowRequestV1::V3AdmitFinal {
                    final_action: SignerV3AdmitFinalV1 {
                        ready: Arc::clone(ready),
                        effect: AtomicU8::new(0),
                        consumed: false,
                    },
                })
            }
            _ => Err(rejected("wrong admission command")),
        }
    }
}
impl CoordinatorFinancialNativeV1 {
    pub fn arm_v3_admit(
        &self,
        mut ticket: SignerV3AdmitTicketV1,
    ) -> Result<SignerV3AdmitArmOutboundV1> {
        if !Arc::ptr_eq(&self.core, ticket.binding.core()) {
            self.revoke();
            return Err(rejected("foreign admission native Core"));
        }
        ticket.check_current()?;
        self.core.phase.step(ticket.binding.slot(), 153, 154)?;
        ticket.consumed = true;
        Ok(SignerV3AdmitArmOutboundV1 {
            binding: Arc::clone(&ticket.binding),
            consumed: false,
        })
    }
    pub fn admit_v3_admit(
        &self,
        mut ticket: SignerV3AdmitReadyTicketV1,
    ) -> Result<SignerV3AdmitFinalOutboundV1> {
        let b = &ticket.ready.binding;
        if !Arc::ptr_eq(&self.core, b.core()) {
            self.revoke();
            return Err(rejected("foreign admission READY native Core"));
        }
        ticket.check_current()?;
        self.core.phase.step(b.slot(), 155, 156)?;
        ticket.consumed = true;
        Ok(SignerV3AdmitFinalOutboundV1 {
            ready: Arc::clone(&ticket.ready),
            consumed: false,
        })
    }
}
impl CoordinatorFinancialEndpointV1 {
    pub fn try_send_v3_admit_arm(
        &mut self,
        mut out: SignerV3AdmitArmOutboundV1,
    ) -> Result<FinancialSendProgressV1> {
        let b = Arc::clone(&out.binding);
        let i = b.slot();
        let result = (|| {
            let slot = &self.v3_entries[i].admission;
            if !Arc::ptr_eq(&self.core, b.core())
                || slot.phase != 153
                || slot.binding.as_ref().is_none_or(|v| !Arc::ptr_eq(v, &b))
            {
                return Err(rejected("admission outbound Arm foreign/reused"));
            }
            b.bounds()?;
            if self.core.phase.source_send_restricted(i, 154)? {
                return Ok(FinancialSendProgressV1::Restricted);
            }
            let r = self.send_positive(
                &Packet::V3AdmitArm {
                    role: b.p.actor.signer_role,
                    presentation_digest: b.p.presentation_digest.clone(),
                },
                b.deadline,
            )?;
            if r == FinancialSendProgressV1::Sent {
                self.v3_entries[i].admission.phase = 154;
            }
            Ok(r)
        })();
        out.consumed = true;
        if result.is_err() {
            self.core.phase.revoke();
        }
        result
    }
    pub fn try_send_v3_admit_final(
        &mut self,
        mut out: SignerV3AdmitFinalOutboundV1,
    ) -> Result<FinancialSendProgressV1> {
        let ready = Arc::clone(&out.ready);
        let b = &ready.binding;
        let i = b.slot();
        let result = (|| {
            let slot = &self.v3_entries[i].admission;
            if !Arc::ptr_eq(&self.core, b.core())
                || slot.phase != 155
                || slot.ready.as_ref().is_none_or(|v| !Arc::ptr_eq(v, &ready))
            {
                return Err(rejected("admission outbound Final foreign/reused"));
            }
            b.bounds()?;
            if self.core.phase.source_send_restricted(i, 156)? {
                return Ok(FinancialSendProgressV1::Restricted);
            }
            let r = self.send_positive(
                &Packet::V3AdmitFinal {
                    role: b.p.actor.signer_role,
                    presentation_digest: b.p.presentation_digest.clone(),
                    ready_challenge: ready.challenge.clone(),
                    authenticated_ready_digest: ready.data.authenticated_ready_digest.clone(),
                },
                b.deadline,
            )?;
            if r == FinancialSendProgressV1::Sent {
                self.v3_entries[i].admission.phase = 156;
            }
            Ok(r)
        })();
        out.consumed = true;
        if result.is_err() {
            self.core.phase.revoke();
        }
        result
    }
    pub(in crate::financial_workflow_origin) fn receive_v3_admission_event(
        &mut self,
        p: Packet,
    ) -> Result<CoordinatorFinancialEventV1> {
        let role = p
            .target()?
            .ok_or_else(|| rejected("admission event role"))?;
        let i = role.index();
        let s = &mut self.v3_entries[i];
        let read = s
            .admit_read
            .binding
            .as_ref()
            .ok_or_else(|| rejected("admission event before fresh Read"))?;
        let result = s
            .admit_read
            .result
            .as_ref()
            .ok_or_else(|| rejected("admission event before actual prepared request"))?;
        if !s.admit_read.reported {
            return Err(rejected("admission event before retained Read result"));
        }
        match p {
            Packet::V3AdmitDisplay { presentation } => {
                if s.admission.binding.is_some() || !matches_read(&presentation, &read.p, result) {
                    return Err(rejected("admission display original candidate mismatch"));
                }
                let b = AdmissionBinding::new(Arc::clone(read), presentation.clone())?;
                s.admission.binding = Some(Arc::clone(&b));
                s.admission.wire = Some(presentation);
                s.admission.phase = 153;
                if !received_workflow_progress(&self.core.phase, i, 152, 153)? {
                    return Ok(CoordinatorFinancialEventV1::Restricted(role));
                }
                Ok(CoordinatorFinancialEventV1::V3AdmitDisplay(
                    SignerV3AdmitTicketV1 {
                        binding: b,
                        consumed: false,
                    },
                ))
            }
            Packet::V3AdmitReady {
                data,
                ready_challenge,
                ..
            } => {
                let slot = &mut s.admission;
                let b = slot
                    .binding
                    .as_ref()
                    .ok_or_else(|| rejected("admission READY before offer"))?;
                if slot.phase != 154
                    || slot.ready.is_some()
                    || !state::hash(&ready_challenge)
                    || !matches_ready(&data, &b.p)
                {
                    return Err(rejected("admission READY exact candidate mismatch/replay"));
                }
                b.bounds()?;
                let ready = Arc::new(AdmissionReady {
                    binding: Arc::clone(b),
                    data: data.clone(),
                    challenge: ready_challenge.clone(),
                });
                slot.ready = Some(Arc::clone(&ready));
                slot.ready_wire = Some((data, ready_challenge));
                slot.phase = 155;
                if !received_workflow_progress(&self.core.phase, i, 154, 155)? {
                    return Ok(CoordinatorFinancialEventV1::Restricted(role));
                }
                Ok(CoordinatorFinancialEventV1::V3AdmitReady(
                    SignerV3AdmitReadyTicketV1 {
                        ready,
                        consumed: false,
                    },
                ))
            }
            Packet::V3Admitted { data, .. } => {
                data.validate()?;
                let slot = &mut s.admission;
                let b = slot
                    .binding
                    .as_ref()
                    .ok_or_else(|| rejected("admission result before offer"))?;
                if slot.phase != 156 || slot.reported || !matches_result(&data, &b.p) {
                    return Err(rejected("admission actual retained result mismatch/replay"));
                }
                slot.result = Some(data.clone());
                slot.phase = 157;
                slot.reported = true;
                received_workflow_progress(&self.core.phase, i, 156, 157)?;
                Ok(CoordinatorFinancialEventV1::V3Admitted { role, data })
            }
            _ => Err(rejected("wrong admission event")),
        }
    }
}
fn relay_clock(
    p: &SignerV3AdmitPresentationV1,
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
        return Err(rejected("admission original relay window"));
    }
    *last = wall;
    Ok(())
}
impl HostFinancialWorkflowRelayV1 {
    pub(in crate::financial_workflow_origin) fn down_v3_admission(
        &mut self,
        p: &Packet,
    ) -> Result<()> {
        if self.restricted {
            return Err(rejected("admission relay after R"));
        }
        let role = p
            .target()?
            .ok_or_else(|| rejected("admission relay role"))?;
        let s = &mut self.v3_entries[role.index()];
        let slot = &mut s.admission;
        let wire = slot
            .wire
            .as_ref()
            .ok_or_else(|| rejected("admission relay command before offer"))?;
        relay_clock(wire, self.clocks, &mut s.pair.last_wall)?;
        match p {
            Packet::V3AdmitArm {
                presentation_digest,
                ..
            } => {
                if slot.phase != 153 || presentation_digest != &wire.presentation_digest {
                    return Err(rejected("admission relay Arm mismatch/replay"));
                }
                slot.phase = 154;
                Ok(())
            }
            Packet::V3AdmitFinal {
                presentation_digest,
                ready_challenge,
                authenticated_ready_digest,
                ..
            } => {
                let (ready, challenge) = slot
                    .ready_wire
                    .as_ref()
                    .ok_or_else(|| rejected("admission relay Final before actual READY"))?;
                if slot.phase != 155
                    || presentation_digest != &wire.presentation_digest
                    || ready_challenge != challenge
                    || authenticated_ready_digest != &ready.authenticated_ready_digest
                {
                    return Err(rejected(
                        "admission relay Final exact READY mismatch/replay",
                    ));
                }
                slot.phase = 156;
                Ok(())
            }
            _ => Err(rejected("wrong admission relay command")),
        }
    }
    pub(in crate::financial_workflow_origin) fn up_v3_admission(
        &mut self,
        role: Target,
        p: &Packet,
    ) -> Result<bool> {
        let s = &mut self.v3_entries[role.index()];
        let read = s
            .admit_read
            .wire
            .as_ref()
            .ok_or_else(|| rejected("admission relay before fresh Read"))?;
        let result = s
            .admit_read
            .result
            .as_ref()
            .ok_or_else(|| rejected("admission relay before prepared candidate"))?;
        if !s.admit_read.reported {
            return Err(rejected("admission relay before actual Read report"));
        }
        match p {
            Packet::V3AdmitDisplay { presentation } => {
                presentation.validate()?;
                if s.admission.wire.is_some() || !matches_read(presentation, read, result) {
                    return Err(rejected("admission relay original candidate mismatch"));
                }
                if !self.restricted {
                    relay_clock(presentation, self.clocks, &mut s.pair.last_wall)?;
                }
                s.admission.wire = Some(presentation.clone());
                s.admission.phase = 153;
                Ok(!self.restricted)
            }
            Packet::V3AdmitReady {
                data,
                ready_challenge,
                ..
            } => {
                data.validate()?;
                let slot = &mut s.admission;
                let wire = slot
                    .wire
                    .as_ref()
                    .ok_or_else(|| rejected("admission relay READY before offer"))?;
                if slot.phase != 154
                    || slot.ready_wire.is_some()
                    || !state::hash(ready_challenge)
                    || !matches_ready(data, wire)
                {
                    return Err(rejected("admission relay READY mismatch/replay"));
                }
                if !self.restricted {
                    relay_clock(wire, self.clocks, &mut s.pair.last_wall)?;
                }
                slot.ready_wire = Some((data.clone(), ready_challenge.clone()));
                slot.phase = 155;
                Ok(!self.restricted)
            }
            Packet::V3Admitted { data, .. } => {
                data.validate()?;
                let slot = &mut s.admission;
                let wire = slot
                    .wire
                    .as_ref()
                    .ok_or_else(|| rejected("admission relay result before offer"))?;
                if slot.reported || slot.phase != 156 || !matches_result(data, wire) {
                    return Err(rejected("admission relay retained result mismatch/replay"));
                }
                slot.result = Some(data.clone());
                slot.phase = 157;
                slot.reported = true;
                Ok(true)
            }
            _ => Err(rejected("wrong admission relay event")),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_ready_binds_same_request_head_service_and_operation() {
        let p = crate::signer_v3_admission_data::tests::presentation();
        let mut d = crate::signer_v3_admission_data::tests::ready();
        assert!(matches_ready(&d, &p));
        d.expected_head_sequence += 1;
        assert!(!matches_ready(&d, &p));
        d.expected_head_sequence -= 1;
        d.owner_service_digest = "ff".repeat(32);
        assert!(!matches_ready(&d, &p));
    }
    #[test]
    fn admission_cannot_extend_fresh_read_or_replace_immutable_candidate() {
        let p = crate::signer_v3_admission_data::tests::presentation();
        let r = crate::signer_v3_admit_read_data::tests::presentation();
        let d = crate::signer_v3_admit_read_data::tests::retained();
        assert!(matches_read(&p, &r, &d));
        let mut q = p.clone();
        q.facts.expires_at_ms += 1;
        assert!(!matches_read(&q, &r, &d));
        let mut q = p;
        q.facts.read.admission_request_digest = "ff".repeat(32);
        assert!(!matches_read(&q, &r, &d));
    }
    #[test]
    fn retained_unknown_survives_r_but_is_not_completed_v3() {
        let p = crate::signer_v3_admission_data::tests::presentation();
        let d = crate::signer_v3_admission_data::tests::admitted();
        assert!(matches_result(&d, &p));
        let state = state::Phases::new();
        state.step(0, 0, 156).unwrap();
        state.revoke();
        state.observe_v3_admission_published(0).unwrap();
        assert!(state.revoked());
        assert_eq!(state.phase(0), 157);
        assert_ne!(state.phase(0), V3_HELD);
        assert!(state.step(0, 157, 158).is_err());
        assert!(state.observe_v3_admission_published(0).is_err());
    }
}
