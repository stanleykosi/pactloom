//! Exact historical outbox Read, followed by distinct fresh local redisclosure.
use super::pair::PairBinding;
use super::*;
use crate::signer_v3_pair_data::{SignerV3PairPresentationV1, SignerV3PairedV1};
use crate::signer_v3_redisclosure_data::*;
use crate::SignerV3CurrentDisclosureV1;
#[derive(Default)]
pub(super) struct RedisclosureSlots {
    redisclosure_read: RedisclosureReadSlot,
    redisclose: RediscloseSlot,
}

const REDISCLOSURE_READ_REVIEW: u8 = 138;
const REDISCLOSURE_READ_ADMITTED: u8 = 139;
const REDISCLOSURE_READ_DONE: u8 = 140;
#[derive(Default)]
struct RedisclosureReadSlot {
    prepared: Option<SignerV3RedisclosurePreparedV1>,
    binding: Option<Arc<RedisclosureReadBinding>>,
    wire: Option<SignerV3RedisclosureReadPresentationV1>,
    phase: u8,
    reported: bool,
}
struct RedisclosureReadBinding {
    pair: Arc<PairBinding>,
    p: SignerV3RedisclosureReadPresentationV1,
    deadline: Instant,
    last_wall: AtomicU64,
}
impl RedisclosureReadBinding {
    fn new(pair: Arc<PairBinding>, p: SignerV3RedisclosureReadPresentationV1) -> Result<Arc<Self>> {
        p.validate()?;
        pair.channel_bounds()?;
        let now = Instant::now();
        let deadline = pair
            .entry
            .clocks
            .restrict_received(PROFILE, p.review_ceiling_ms, pair.channel_deadline, now)?
            .min(wall_ceiling(
                now,
                state::wall_ms()?,
                p.facts.reviewed_at_ms,
                p.facts.expires_at_ms,
            )?);
        let b = Arc::new(Self {
            pair,
            p,
            deadline,
            last_wall: AtomicU64::new(state::wall_ms()?),
        });
        b.bounds()?;
        Ok(b)
    }
    fn bounds(&self) -> Result<()> {
        self.pair.channel_bounds()?;
        let wall = state::wall_ms()?;
        let old = self.last_wall.fetch_max(wall, Ordering::AcqRel);
        if wall < old
            || wall < self.p.facts.reviewed_at_ms
            || wall >= self.p.facts.expires_at_ms
            || Instant::now() >= self.deadline
        {
            return Err(rejected("redisclosure review expired"));
        }
        Ok(())
    }
    fn current(&self, phase: u8) -> Result<()> {
        self.bounds()?;
        self.pair.entry.core.check_action_restrictions()?;
        if self.pair.entry.core.phase.phase(self.pair.entry.slot()) != phase {
            return Err(rejected("redisclosure purpose consumed"));
        }
        Ok(())
    }
}
pub struct SignerV3RedisclosureReadTicketV1 {
    binding: Arc<RedisclosureReadBinding>,
    consumed: bool,
}
impl SignerV3RedisclosureReadTicketV1 {
    pub fn presentation(&self) -> &SignerV3RedisclosureReadPresentationV1 {
        &self.binding.p
    }
    pub fn check_current(&self) -> Result<()> {
        self.binding.current(138)
    }
}
impl Drop for SignerV3RedisclosureReadTicketV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.pair.entry.core.phase.revoke();
        }
    }
}
pub struct SignerV3RedisclosureReadOutboundV1 {
    binding: Arc<RedisclosureReadBinding>,
    consumed: bool,
}
impl Drop for SignerV3RedisclosureReadOutboundV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.pair.entry.core.phase.revoke();
        }
    }
}
pub struct SignerV3RedisclosureReadFinalV1 {
    binding: Arc<RedisclosureReadBinding>,
    consumed: bool,
}
impl SignerV3RedisclosureReadFinalV1 {
    pub fn presentation(&self) -> &SignerV3RedisclosureReadPresentationV1 {
        &self.binding.p
    }
    pub fn facts(&self) -> &SignerV3RedisclosureReadFactsV1 {
        &self.binding.p.facts
    }
    pub fn original_review_deadline(&self) -> Instant {
        self.binding.deadline
    }
    pub fn original_source_deadline(&self) -> Instant {
        self.binding.pair.entry.original_source
    }
    pub fn check_current(&self) -> Result<()> {
        self.binding.current(139)
    }
    pub fn original_read_deadline(&self) -> Instant {
        self.binding.deadline
    }
    pub fn finish_read(mut self) -> Result<()> {
        self.check_current()?;
        self.binding
            .pair
            .entry
            .core
            .phase
            .step(self.binding.pair.entry.slot(), 139, 140)?;
        self.consumed = true;
        Ok(())
    }
}
impl Drop for SignerV3RedisclosureReadFinalV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.pair.entry.core.phase.revoke();
        }
    }
}
fn redisclosure_read_matches(
    p: &SignerV3RedisclosureReadPresentationV1,
    entry: &SignerV3SourceEntryPresentationV1,
    pair: &SignerV3PairPresentationV1,
    result: &SignerV3PairedV1,
    current: &SignerV3CurrentDisclosureV1,
    prepared: Option<&SignerV3RedisclosurePreparedV1>,
) -> bool {
    let f = &p.facts;
    p.actor == entry.actor
        && p.source_ceiling_ms == entry.source_ceiling_ms
        && p.review_ceiling_ms <= pair.channel_ceiling_ms
        && f.entry_presentation_digest == current.entry_presentation_digest
        && f.source_identity_digest == current.source_identity_digest
        && f.current_enrollment_ref == current.current_enrollment_ref
        && f.current_manifest_ref == current.current_manifest_ref
        && f.coordinated_session_id == current.coordinated_session_id
        && f.pair_grant_id == result.grant_id
        && f.pair_key_digest == result.key_digest
        && f.pair_channel_digest == result.channel_digest
        && f.pair_generation == result.generation
        && f.source_expires_at_ms == entry.facts.source_expires_at_ms
        && f.expires_at_ms <= pair.facts.channel_expires_at_ms
        && f.reviewed_at_ms >= pair.facts.reviewed_at_ms
}

impl SignerFinancialWorkflowOriginV1 {
    pub fn offer_v3_redisclosure_read(
        &mut self,
        facts: SignerV3RedisclosureReadFactsV1,
        original_review: Instant,
    ) -> Result<SignerV3RedisclosureReadPresentationV1> {
        self.core.check_action_restrictions()?;
        facts.validate()?;
        let s = &mut self.v3_entry;
        let pair = s
            .pair
            .binding
            .as_ref()
            .ok_or_else(|| rejected("redisclosure before Pair"))?;
        pair.channel_bounds()?;
        let result = s
            .pair
            .result
            .as_ref()
            .ok_or_else(|| rejected("redisclosure before possession proof"))?;
        let current = s.receipts.current_disclosure(&pair.p, result)?;
        if s.redisclosure.redisclosure_read.binding.is_some()
            || original_review > pair.channel_deadline
            || original_review > Instant::now() + Duration::from_secs(120)
        {
            return Err(rejected("redisclosure one exact window"));
        }
        let mut p = SignerV3RedisclosureReadPresentationV1 {
            actor: pair.p.actor.clone(),
            facts,
            notice: REDISCLOSURE_READ_NOTICE.into(),
            challenge: state::nonce()?,
            source_ceiling_ms: pair.p.source_ceiling_ms,
            review_ceiling_ms: self
                .clocks
                .restrictive_offset(original_review, pair.channel_deadline)?,
            presentation_digest: String::new(),
        };
        p.presentation_digest = p.calculate_presentation_digest()?;
        if !redisclosure_read_matches(
            &p,
            &pair.entry.wire.presentation,
            &pair.p,
            result,
            &current,
            s.redisclosure.redisclosure_read.prepared.as_ref(),
        ) {
            return Err(rejected("redisclosure original record/Pair predecessor"));
        }
        let binding = RedisclosureReadBinding::new(Arc::clone(pair), p.clone())?;
        self.core.phase.step(self.target.index(), 137, 138)?;
        s.redisclosure.redisclosure_read.binding = Some(binding);
        s.redisclosure.redisclosure_read.wire = Some(p.clone());
        s.redisclosure.redisclosure_read.phase = 138;
        self.send(&Packet::V3RedisclosureReadDisplay {
            presentation: p.clone(),
        })?;
        Ok(p)
    }
    pub fn report_v3_redisclosure_prepared(
        &mut self,
        data: SignerV3RedisclosurePreparedV1,
    ) -> Result<()> {
        data.validate()?;
        let slot = &mut self.v3_entry.redisclosure.redisclosure_read;
        let b = slot
            .binding
            .as_ref()
            .ok_or_else(|| rejected("redisclosure report before offer"))?;
        if slot.reported
            || slot.phase != 139
            || self.core.phase.phase(self.target.index()) != 140
            || !prepared_matches(&data, &b.p)
        {
            return Err(rejected("redisclosure actual result binding/replay"));
        }
        slot.prepared = Some(data.clone());
        slot.reported = true;
        slot.phase = 140;
        self.send(&Packet::V3RedisclosurePrepared {
            role: self.target,
            data,
        })
    }
}
impl CoordinatorFinancialNativeV1 {
    pub fn admit_v3_redisclosure_read(
        &self,
        mut ticket: SignerV3RedisclosureReadTicketV1,
    ) -> Result<SignerV3RedisclosureReadOutboundV1> {
        if !Arc::ptr_eq(&self.core, &ticket.binding.pair.entry.core) {
            self.revoke();
            return Err(rejected("redisclosure foreign native Core"));
        }
        ticket.check_current()?;
        self.core
            .phase
            .step(ticket.binding.pair.entry.slot(), 138, 139)?;
        ticket.consumed = true;
        Ok(SignerV3RedisclosureReadOutboundV1 {
            binding: Arc::clone(&ticket.binding),
            consumed: false,
        })
    }
}
impl CoordinatorFinancialEndpointV1 {
    pub fn send_v3_redisclosure_read(
        &mut self,
        out: SignerV3RedisclosureReadOutboundV1,
    ) -> Result<()> {
        self.try_send_v3_redisclosure_read(out)?.require_sent()
    }
    pub fn try_send_v3_redisclosure_read(
        &mut self,
        mut out: SignerV3RedisclosureReadOutboundV1,
    ) -> Result<FinancialSendProgressV1> {
        let b = Arc::clone(&out.binding);
        let i = b.pair.entry.slot();
        let r = (|| {
            let slot = &self.v3_entries[i].redisclosure.redisclosure_read;
            if !Arc::ptr_eq(&self.core, &b.pair.entry.core)
                || slot.phase != 138
                || slot
                    .binding
                    .as_ref()
                    .is_none_or(|old| !Arc::ptr_eq(old, &b))
            {
                return Err(rejected("redisclosure outbound foreign/reused"));
            }
            b.bounds()?;
            if self.core.phase.source_send_restricted(i, 139)? {
                return Ok(FinancialSendProgressV1::Restricted);
            }
            let r = self.send_positive(
                &Packet::V3RedisclosureReadFinal {
                    role: b.p.actor.signer_role,
                    presentation_digest: b.p.presentation_digest.clone(),
                },
                b.deadline,
            )?;
            if r == FinancialSendProgressV1::Sent {
                self.v3_entries[i].redisclosure.redisclosure_read.phase = 139;
            }
            Ok(r)
        })();
        out.consumed = true;
        if r.is_err() {
            self.core.phase.revoke();
        }
        r
    }
}

const REDISCLOSE_REVIEW: u8 = 141;
const REDISCLOSE_ADMITTED: u8 = 142;
const REDISCLOSE_DONE: u8 = 143;
#[derive(Default)]
struct RediscloseSlot {
    result: Option<SignerV3RedisclosedV1>,
    binding: Option<Arc<RediscloseBinding>>,
    wire: Option<SignerV3RedisclosePresentationV1>,
    phase: u8,
    reported: bool,
}
struct RediscloseBinding {
    pair: Arc<PairBinding>,
    p: SignerV3RedisclosePresentationV1,
    deadline: Instant,
    last_wall: AtomicU64,
}
impl RediscloseBinding {
    fn new(pair: Arc<PairBinding>, p: SignerV3RedisclosePresentationV1) -> Result<Arc<Self>> {
        p.validate()?;
        pair.channel_bounds()?;
        let now = Instant::now();
        let deadline = pair
            .entry
            .clocks
            .restrict_received(PROFILE, p.review_ceiling_ms, pair.channel_deadline, now)?
            .min(wall_ceiling(
                now,
                state::wall_ms()?,
                p.facts.reviewed_at_ms,
                p.facts.expires_at_ms,
            )?);
        let b = Arc::new(Self {
            pair,
            p,
            deadline,
            last_wall: AtomicU64::new(state::wall_ms()?),
        });
        b.bounds()?;
        Ok(b)
    }
    fn bounds(&self) -> Result<()> {
        self.pair.channel_bounds()?;
        let wall = state::wall_ms()?;
        let old = self.last_wall.fetch_max(wall, Ordering::AcqRel);
        if wall < old
            || wall < self.p.facts.reviewed_at_ms
            || wall >= self.p.facts.expires_at_ms
            || Instant::now() >= self.deadline
        {
            return Err(rejected("redisclosure review expired"));
        }
        Ok(())
    }
    fn current(&self, phase: u8) -> Result<()> {
        self.bounds()?;
        self.pair.entry.core.check_action_restrictions()?;
        if self.pair.entry.core.phase.phase(self.pair.entry.slot()) != phase {
            return Err(rejected("redisclosure purpose consumed"));
        }
        Ok(())
    }
}
pub struct SignerV3RediscloseTicketV1 {
    binding: Arc<RediscloseBinding>,
    consumed: bool,
}
impl SignerV3RediscloseTicketV1 {
    pub fn presentation(&self) -> &SignerV3RedisclosePresentationV1 {
        &self.binding.p
    }
    pub fn check_current(&self) -> Result<()> {
        self.binding.current(141)
    }
}
impl Drop for SignerV3RediscloseTicketV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.pair.entry.core.phase.revoke();
        }
    }
}
pub struct SignerV3RediscloseOutboundV1 {
    binding: Arc<RediscloseBinding>,
    consumed: bool,
}
impl Drop for SignerV3RediscloseOutboundV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.pair.entry.core.phase.revoke();
        }
    }
}
pub struct SignerV3RediscloseFinalV1 {
    effect: AtomicU8,
    binding: Arc<RediscloseBinding>,
    consumed: bool,
}
impl SignerV3RediscloseFinalV1 {
    pub fn presentation(&self) -> &SignerV3RedisclosePresentationV1 {
        &self.binding.p
    }
    pub fn facts(&self) -> &SignerV3RediscloseFactsV1 {
        &self.binding.p.facts
    }
    pub fn original_export_deadline(&self) -> Instant {
        self.binding.deadline
    }
    pub fn original_review_deadline(&self) -> Instant {
        self.binding.deadline
    }
    pub fn original_source_deadline(&self) -> Instant {
        self.binding.pair.entry.original_source
    }
    pub fn check_current(&self) -> Result<()> {
        self.binding.current(142)
    }
    /// Invoke only under actual validated source/SQL locks. Move the entire
    /// owned transaction into this closure: commit, rollback and destruction
    /// must finish before it returns. No await, enqueue, or escaping guard.
    pub fn execute_redisclosure_publication(
        &self,
        publication: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        self.check_current()?;
        self.effect
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| {
                self.binding.pair.entry.core.phase.revoke();
                rejected("redisclosure publication is one-use")
            })?;
        let core = &self.binding.pair.entry.core;
        let mut attempt = RedisclosureEffectAttempt {
            core,
            effect: &self.effect,
            settled: false,
        };
        let restriction = core
            .signer_restriction
            .as_ref()
            .ok_or_else(|| rejected("receipt missing original shared restriction"))?;
        restriction.execute_journal_publication(|| {
            self.check_current()?;
            publication()
        })?;
        self.effect.store(2, Ordering::Release);
        attempt.settled = true;
        Ok(())
    }
    pub fn finish_export(mut self) -> Result<()> {
        let core = &self.binding.pair.entry.core;
        if self.effect.load(Ordering::Acquire) != 2
            || unsafe { libc::getpid() } != core.owner_pid
            || unsafe { libc::geteuid() } != core.owner_uid
            || core.phase.phase(self.binding.pair.entry.slot()) != 142
        {
            return Err(rejected(
                "redisclosure finish lacks completed original publication",
            ));
        }
        core.phase
            .observe_v3_redisclosure_published(self.binding.pair.entry.slot())?;
        self.consumed = true;
        Ok(())
    }
}
impl Drop for SignerV3RediscloseFinalV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.pair.entry.core.phase.revoke();
        }
    }
}
fn redisclose_matches(
    p: &SignerV3RedisclosePresentationV1,
    entry: &SignerV3SourceEntryPresentationV1,
    pair: &SignerV3PairPresentationV1,
    result: &SignerV3PairedV1,
    current: &SignerV3CurrentDisclosureV1,
    prepared: Option<&SignerV3RedisclosurePreparedV1>,
) -> bool {
    let f = &p.facts;
    p.actor == entry.actor
        && p.source_ceiling_ms == entry.source_ceiling_ms
        && p.review_ceiling_ms <= pair.channel_ceiling_ms
        && f.entry_presentation_digest == current.entry_presentation_digest
        && f.source_identity_digest == current.source_identity_digest
        && f.current_enrollment_ref == current.current_enrollment_ref
        && f.current_manifest_ref == current.current_manifest_ref
        && f.coordinated_session_id == current.coordinated_session_id
        && f.pair_grant_id == result.grant_id
        && f.pair_key_digest == result.key_digest
        && f.pair_channel_digest == result.channel_digest
        && f.pair_generation == result.generation
        && f.source_expires_at_ms == entry.facts.source_expires_at_ms
        && f.expires_at_ms <= pair.facts.channel_expires_at_ms
        && f.reviewed_at_ms >= pair.facts.reviewed_at_ms
        && prepared.is_some_and(|old| old == &f.prepared)
}

impl SignerFinancialWorkflowOriginV1 {
    pub fn offer_v3_redisclose(
        &mut self,
        facts: SignerV3RediscloseFactsV1,
        original_review: Instant,
    ) -> Result<SignerV3RedisclosePresentationV1> {
        self.core.check_action_restrictions()?;
        facts.validate()?;
        let s = &mut self.v3_entry;
        let pair = s
            .pair
            .binding
            .as_ref()
            .ok_or_else(|| rejected("redisclosure before Pair"))?;
        pair.channel_bounds()?;
        let result = s
            .pair
            .result
            .as_ref()
            .ok_or_else(|| rejected("redisclosure before possession proof"))?;
        let current = s.receipts.current_disclosure(&pair.p, result)?;
        if s.redisclosure.redisclose.binding.is_some()
            || original_review > pair.channel_deadline
            || original_review > Instant::now() + Duration::from_secs(120)
        {
            return Err(rejected("redisclosure one exact window"));
        }
        let mut p = SignerV3RedisclosePresentationV1 {
            actor: pair.p.actor.clone(),
            facts,
            notice: REDISCLOSE_NOTICE.into(),
            challenge: state::nonce()?,
            source_ceiling_ms: pair.p.source_ceiling_ms,
            review_ceiling_ms: self
                .clocks
                .restrictive_offset(original_review, pair.channel_deadline)?,
            presentation_digest: String::new(),
        };
        p.presentation_digest = p.calculate_presentation_digest()?;
        if !redisclose_matches(
            &p,
            &pair.entry.wire.presentation,
            &pair.p,
            result,
            &current,
            s.redisclosure.redisclosure_read.prepared.as_ref(),
        ) || !s.redisclosure.redisclosure_read.reported
        {
            return Err(rejected("redisclosure original record/Pair predecessor"));
        }
        let binding = RediscloseBinding::new(Arc::clone(pair), p.clone())?;
        self.core.phase.step(self.target.index(), 140, 141)?;
        s.redisclosure.redisclose.binding = Some(binding);
        s.redisclosure.redisclose.wire = Some(p.clone());
        s.redisclosure.redisclose.phase = 141;
        self.send(&Packet::V3RediscloseDisplay {
            presentation: p.clone(),
        })?;
        Ok(p)
    }
    pub fn report_v3_redisclosed(&mut self, data: SignerV3RedisclosedV1) -> Result<()> {
        data.validate()?;
        let slot = &mut self.v3_entry.redisclosure.redisclose;
        let b = slot
            .binding
            .as_ref()
            .ok_or_else(|| rejected("redisclosure report before offer"))?;
        if slot.reported
            || slot.phase != 142
            || self.core.phase.phase(self.target.index()) != 143
            || !redisclosed_matches(&data, &b.p)
        {
            return Err(rejected("redisclosure actual result binding/replay"));
        }
        slot.result = Some(data.clone());
        slot.reported = true;
        slot.phase = 143;
        self.send(&Packet::V3Redisclosed {
            role: self.target,
            data,
        })
    }
}
impl CoordinatorFinancialNativeV1 {
    pub fn admit_v3_redisclose(
        &self,
        mut ticket: SignerV3RediscloseTicketV1,
    ) -> Result<SignerV3RediscloseOutboundV1> {
        if !Arc::ptr_eq(&self.core, &ticket.binding.pair.entry.core) {
            self.revoke();
            return Err(rejected("redisclosure foreign native Core"));
        }
        ticket.check_current()?;
        self.core
            .phase
            .step(ticket.binding.pair.entry.slot(), 141, 142)?;
        ticket.consumed = true;
        Ok(SignerV3RediscloseOutboundV1 {
            binding: Arc::clone(&ticket.binding),
            consumed: false,
        })
    }
}
impl CoordinatorFinancialEndpointV1 {
    pub fn send_v3_redisclose(&mut self, out: SignerV3RediscloseOutboundV1) -> Result<()> {
        self.try_send_v3_redisclose(out)?.require_sent()
    }
    pub fn try_send_v3_redisclose(
        &mut self,
        mut out: SignerV3RediscloseOutboundV1,
    ) -> Result<FinancialSendProgressV1> {
        let b = Arc::clone(&out.binding);
        let i = b.pair.entry.slot();
        let r = (|| {
            let slot = &self.v3_entries[i].redisclosure.redisclose;
            if !Arc::ptr_eq(&self.core, &b.pair.entry.core)
                || slot.phase != 141
                || slot
                    .binding
                    .as_ref()
                    .is_none_or(|old| !Arc::ptr_eq(old, &b))
            {
                return Err(rejected("redisclosure outbound foreign/reused"));
            }
            b.bounds()?;
            if self.core.phase.source_send_restricted(i, 142)? {
                return Ok(FinancialSendProgressV1::Restricted);
            }
            let r = self.send_positive(
                &Packet::V3RediscloseFinal {
                    role: b.p.actor.signer_role,
                    presentation_digest: b.p.presentation_digest.clone(),
                },
                b.deadline,
            )?;
            if r == FinancialSendProgressV1::Sent {
                self.v3_entries[i].redisclosure.redisclose.phase = 142;
            }
            Ok(r)
        })();
        out.consumed = true;
        if r.is_err() {
            self.core.phase.revoke();
        }
        r
    }
}
impl SignerFinancialWorkflowOriginV1 {
    pub(in crate::financial_workflow_origin) fn receive_v3_redisclosure(
        &mut self,
        p: Packet,
    ) -> Result<SignerFinancialWorkflowRequestV1> {
        match p {
            Packet::V3RedisclosureReadFinal {
                role,
                presentation_digest,
            } => {
                let slot = &mut self.v3_entry.redisclosure.redisclosure_read;
                let b = slot
                    .binding
                    .as_ref()
                    .ok_or_else(|| rejected("redisclosure Final unsolicited"))?;
                if role != self.target
                    || slot.phase != 138
                    || presentation_digest != b.p.presentation_digest
                {
                    return Err(rejected("redisclosure Final mismatch/replay"));
                }
                b.current(138)?;
                self.core.phase.step(role.index(), 138, 139)?;
                slot.phase = 139;
                Ok(SignerFinancialWorkflowRequestV1::V3RedisclosureRead {
                    final_action: SignerV3RedisclosureReadFinalV1 {
                        binding: Arc::clone(b),
                        consumed: false,
                    },
                })
            }
            Packet::V3RediscloseFinal {
                role,
                presentation_digest,
            } => {
                let slot = &mut self.v3_entry.redisclosure.redisclose;
                let b = slot
                    .binding
                    .as_ref()
                    .ok_or_else(|| rejected("redisclosure Final unsolicited"))?;
                if role != self.target
                    || slot.phase != 141
                    || presentation_digest != b.p.presentation_digest
                {
                    return Err(rejected("redisclosure Final mismatch/replay"));
                }
                b.current(141)?;
                self.core.phase.step(role.index(), 141, 142)?;
                slot.phase = 142;
                Ok(SignerFinancialWorkflowRequestV1::V3Redisclose {
                    final_action: SignerV3RediscloseFinalV1 {
                        effect: AtomicU8::new(0),
                        binding: Arc::clone(b),
                        consumed: false,
                    },
                })
            }
            _ => Err(rejected("wrong redisclosure request")),
        }
    }
}
impl CoordinatorFinancialEndpointV1 {
    pub(in crate::financial_workflow_origin) fn receive_v3_redisclosure_event(
        &mut self,
        p: Packet,
    ) -> Result<CoordinatorFinancialEventV1> {
        let role = p.target()?.ok_or_else(|| rejected("receipt role"))?;
        let i = role.index();
        let s = &mut self.v3_entries[i];
        let pair = s
            .pair
            .binding
            .as_ref()
            .ok_or_else(|| rejected("receipt event before Pair"))?;
        let result = s
            .pair
            .result
            .as_ref()
            .ok_or_else(|| rejected("receipt event before possession proof"))?;
        let current = s.receipts.current_disclosure(&pair.p, result)?;
        match p {
            Packet::V3RedisclosureReadDisplay { presentation } => {
                let slot = &s.redisclosure.redisclosure_read;
                if slot.binding.is_some()
                    || !redisclosure_read_matches(
                        &presentation,
                        &pair.entry.wire.presentation,
                        &pair.p,
                        result,
                        &current,
                        s.redisclosure.redisclosure_read.prepared.as_ref(),
                    )
                {
                    return Err(rejected("redisclosure display predecessor"));
                }
                let b = RedisclosureReadBinding::new(Arc::clone(pair), presentation.clone())?;
                s.redisclosure.redisclosure_read.wire = Some(presentation);
                s.redisclosure.redisclosure_read.binding = Some(Arc::clone(&b));
                s.redisclosure.redisclosure_read.phase = 138;
                if !received_workflow_progress(&self.core.phase, i, 137, 138)? {
                    return Ok(CoordinatorFinancialEventV1::Restricted(role));
                }
                Ok(CoordinatorFinancialEventV1::V3RedisclosureReadDisplay(
                    SignerV3RedisclosureReadTicketV1 {
                        binding: b,
                        consumed: false,
                    },
                ))
            }
            Packet::V3RedisclosurePrepared { data, .. } => {
                data.validate()?;
                let slot = &mut s.redisclosure.redisclosure_read;
                let b = slot
                    .binding
                    .as_ref()
                    .ok_or_else(|| rejected("receipt result without review"))?;
                if slot.reported || slot.phase != 139 || !prepared_matches(&data, &b.p) {
                    return Err(rejected("receipt result binding/replay"));
                }
                slot.prepared = Some(data.clone());
                slot.phase = 140;
                slot.reported = true;
                received_workflow_progress(&self.core.phase, i, 139, 140)?;
                Ok(CoordinatorFinancialEventV1::V3RedisclosurePrepared { role, data })
            }
            Packet::V3RediscloseDisplay { presentation } => {
                let slot = &s.redisclosure.redisclose;
                if slot.binding.is_some()
                    || !redisclose_matches(
                        &presentation,
                        &pair.entry.wire.presentation,
                        &pair.p,
                        result,
                        &current,
                        s.redisclosure.redisclosure_read.prepared.as_ref(),
                    )
                    || !s.redisclosure.redisclosure_read.reported
                {
                    return Err(rejected("redisclosure display predecessor"));
                }
                let b = RediscloseBinding::new(Arc::clone(pair), presentation.clone())?;
                s.redisclosure.redisclose.wire = Some(presentation);
                s.redisclosure.redisclose.binding = Some(Arc::clone(&b));
                s.redisclosure.redisclose.phase = 141;
                if !received_workflow_progress(&self.core.phase, i, 140, 141)? {
                    return Ok(CoordinatorFinancialEventV1::Restricted(role));
                }
                Ok(CoordinatorFinancialEventV1::V3RediscloseDisplay(
                    SignerV3RediscloseTicketV1 {
                        binding: b,
                        consumed: false,
                    },
                ))
            }
            Packet::V3Redisclosed { data, .. } => {
                data.validate()?;
                let slot = &mut s.redisclosure.redisclose;
                let b = slot
                    .binding
                    .as_ref()
                    .ok_or_else(|| rejected("receipt result without review"))?;
                if slot.reported || slot.phase != 142 || !redisclosed_matches(&data, &b.p) {
                    return Err(rejected("receipt result binding/replay"));
                }
                slot.result = Some(data.clone());
                slot.phase = 143;
                slot.reported = true;
                received_workflow_progress(&self.core.phase, i, 142, 143)?;
                Ok(CoordinatorFinancialEventV1::V3Redisclosed { role, data })
            }
            _ => Err(rejected("wrong redisclosure event")),
        }
    }
}
impl HostFinancialWorkflowRelayV1 {
    pub(in crate::financial_workflow_origin) fn down_v3_redisclosure(
        &mut self,
        p: &Packet,
    ) -> Result<()> {
        if self.restricted {
            return Err(rejected("receipt command after R"));
        }
        let role = p.target()?.ok_or_else(|| rejected("receipt role"))?;
        let s = &mut self.v3_entries[role.index()];
        let pair = s
            .pair
            .wire
            .as_ref()
            .ok_or_else(|| rejected("receipt relay before Pair"))?;
        match p {
            Packet::V3RedisclosureReadFinal {
                presentation_digest,
                ..
            } => {
                let slot = &mut s.redisclosure.redisclosure_read;
                let p = slot
                    .wire
                    .as_ref()
                    .ok_or_else(|| rejected("receipt relay Final before display"))?;
                if slot.phase != 138 || presentation_digest != &p.presentation_digest {
                    return Err(rejected("receipt relay Final mismatch/replay"));
                }
                redisclosure_relay_clock(
                    p.review_ceiling_ms,
                    p.facts.reviewed_at_ms,
                    p.facts.expires_at_ms,
                    pair,
                    self.clocks,
                    &mut s.pair.last_wall,
                )?;
                slot.phase = 139;
                Ok(())
            }
            Packet::V3RediscloseFinal {
                presentation_digest,
                ..
            } => {
                let slot = &mut s.redisclosure.redisclose;
                let p = slot
                    .wire
                    .as_ref()
                    .ok_or_else(|| rejected("receipt relay Final before display"))?;
                if slot.phase != 141 || presentation_digest != &p.presentation_digest {
                    return Err(rejected("receipt relay Final mismatch/replay"));
                }
                redisclosure_relay_clock(
                    p.review_ceiling_ms,
                    p.facts.reviewed_at_ms,
                    p.facts.expires_at_ms,
                    pair,
                    self.clocks,
                    &mut s.pair.last_wall,
                )?;
                slot.phase = 142;
                Ok(())
            }
            _ => Err(rejected("wrong redisclosure relay command")),
        }
    }
    pub(in crate::financial_workflow_origin) fn up_v3_redisclosure(
        &mut self,
        role: Target,
        p: &Packet,
    ) -> Result<bool> {
        let s = &mut self.v3_entries[role.index()];
        let entry = s
            .offer
            .as_ref()
            .ok_or_else(|| rejected("receipt relay before Entry"))?;
        let pair = s
            .pair
            .wire
            .as_ref()
            .ok_or_else(|| rejected("receipt relay before Pair"))?;
        let result = s
            .pair
            .result
            .as_ref()
            .ok_or_else(|| rejected("receipt relay before possession proof"))?;
        let current = s.receipts.current_disclosure(pair, result)?;
        match p {
            Packet::V3RedisclosureReadDisplay { presentation } => {
                presentation.validate()?;
                if s.redisclosure.redisclosure_read.wire.is_some()
                    || !redisclosure_read_matches(
                        presentation,
                        &entry.presentation,
                        pair,
                        result,
                        &current,
                        s.redisclosure.redisclosure_read.prepared.as_ref(),
                    )
                {
                    return Err(rejected("receipt relay display predecessor"));
                }
                if !self.restricted {
                    redisclosure_relay_clock(
                        presentation.review_ceiling_ms,
                        presentation.facts.reviewed_at_ms,
                        presentation.facts.expires_at_ms,
                        pair,
                        self.clocks,
                        &mut s.pair.last_wall,
                    )?;
                }
                s.redisclosure.redisclosure_read.wire = Some(presentation.clone());
                s.redisclosure.redisclosure_read.phase = 138;
                Ok(!self.restricted)
            }
            Packet::V3RedisclosurePrepared { data, .. } => {
                data.validate()?;
                let slot = &mut s.redisclosure.redisclosure_read;
                let p = slot
                    .wire
                    .as_ref()
                    .ok_or_else(|| rejected("receipt relay result before display"))?;
                if slot.reported || slot.phase != 139 || !prepared_matches(data, p) {
                    return Err(rejected("receipt relay result mismatch/replay"));
                }
                slot.prepared = Some(data.clone());
                slot.reported = true;
                slot.phase = 140;
                Ok(true)
            }
            Packet::V3RediscloseDisplay { presentation } => {
                presentation.validate()?;
                if s.redisclosure.redisclose.wire.is_some()
                    || !redisclose_matches(
                        presentation,
                        &entry.presentation,
                        pair,
                        result,
                        &current,
                        s.redisclosure.redisclosure_read.prepared.as_ref(),
                    )
                    || !s.redisclosure.redisclosure_read.reported
                {
                    return Err(rejected("receipt relay display predecessor"));
                }
                if !self.restricted {
                    redisclosure_relay_clock(
                        presentation.review_ceiling_ms,
                        presentation.facts.reviewed_at_ms,
                        presentation.facts.expires_at_ms,
                        pair,
                        self.clocks,
                        &mut s.pair.last_wall,
                    )?;
                }
                s.redisclosure.redisclose.wire = Some(presentation.clone());
                s.redisclosure.redisclose.phase = 141;
                Ok(!self.restricted)
            }
            Packet::V3Redisclosed { data, .. } => {
                data.validate()?;
                let slot = &mut s.redisclosure.redisclose;
                let p = slot
                    .wire
                    .as_ref()
                    .ok_or_else(|| rejected("receipt relay result before display"))?;
                if slot.reported || slot.phase != 142 || !redisclosed_matches(data, p) {
                    return Err(rejected("receipt relay result mismatch/replay"));
                }
                slot.result = Some(data.clone());
                slot.reported = true;
                slot.phase = 143;
                Ok(true)
            }
            _ => Err(rejected("wrong redisclosure relay event")),
        }
    }
}
fn redisclosure_relay_clock(
    review: u64,
    start: u64,
    end: u64,
    pair: &SignerV3PairPresentationV1,
    clocks: FullWorkflowClocksV1,
    last: &mut u64,
) -> Result<()> {
    for bound in [review, pair.channel_ceiling_ms, pair.source_ceiling_ms] {
        clocks.restrict_received(PROFILE, bound, clocks.supervision(), Instant::now())?;
    }
    let wall = state::wall_ms()?;
    if wall < *last || wall < start || wall >= end || wall >= pair.facts.channel_expires_at_ms {
        return Err(rejected("redisclosure original relay window"));
    }
    *last = wall;
    Ok(())
}
// Pinned-S implementation boundary: this gate proves exclusive entry and the
// closure result, not physical SQL execution. Only the reviewed source kernel
// may invoke it, with an owned transaction moved into the synchronous closure.
struct RedisclosureEffectAttempt<'a> {
    core: &'a Core,
    effect: &'a AtomicU8,
    settled: bool,
}
impl Drop for RedisclosureEffectAttempt<'_> {
    fn drop(&mut self) {
        if !self.settled {
            self.effect.store(3, Ordering::Release);
            self.core.phase.revoke();
        }
    }
}

fn prepared_matches(
    d: &SignerV3RedisclosurePreparedV1,
    p: &SignerV3RedisclosureReadPresentationV1,
) -> bool {
    d.validate().is_ok()
        && d.read_presentation_digest == p.presentation_digest
        && d.source_identity_digest == p.facts.source_identity_digest
        && d.current_enrollment_ref == p.facts.current_enrollment_ref
        && d.current_manifest_ref == p.facts.current_manifest_ref
        && d.coordinated_session_id == p.facts.coordinated_session_id
}
fn redisclosed_matches(d: &SignerV3RedisclosedV1, p: &SignerV3RedisclosePresentationV1) -> bool {
    d.validate().is_ok()
        && d.presentation_digest == p.presentation_digest
        && d.request_digest == p.facts.prepared.next_request_digest
        && d.outbox_reference != p.facts.prepared.original_outbox_reference
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_prepared_read_observation_binds_all_current_records() {
        let r = crate::signer_v3_redisclosure_data::tests::read();
        let mut p = crate::signer_v3_redisclosure_data::tests::prepared();
        assert!(prepared_matches(&p, &r));
        p.current_enrollment_ref = "ff".repeat(32);
        assert!(!prepared_matches(&p, &r));
    }
    #[test]
    fn completed_export_cannot_substitute_historical_outbox_or_request() {
        let p = crate::signer_v3_redisclosure_data::tests::export();
        let mut d = SignerV3RedisclosedV1 {
            presentation_digest: p.presentation_digest.clone(),
            outbox_reference: "11".repeat(32),
            request_digest: p.facts.prepared.next_request_digest.clone(),
        };
        assert!(redisclosed_matches(&d, &p));
        d.outbox_reference = p.facts.prepared.original_outbox_reference.clone();
        assert!(!redisclosed_matches(&d, &p));
    }
    #[test]
    fn entered_export_completion_preserves_r_without_preparation_authority() {
        let p = Phases::new();
        p.step(0, 0, 142).unwrap();
        p.revoke();
        p.observe_v3_redisclosure_published(0).unwrap();
        assert_eq!(p.phase(0), 143);
        assert!(p.revoked());
        assert!(p.step(0, 143, 144).is_err());
        assert!(p.observe_v3_redisclosure_published(0).is_err());
        assert_ne!(p.phase(0), V3_HELD);
    }
}

impl RedisclosureSlots {
    pub(super) fn actual_export(&self) -> Result<&SignerV3RedisclosedV1> {
        if !self.redisclose.reported {
            return Err(rejected("preparation before actual new export"));
        }
        self.redisclose
            .result
            .as_ref()
            .ok_or_else(|| rejected("actual export observation missing"))
    }
}
